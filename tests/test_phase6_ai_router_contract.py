import importlib.util
import os
from pathlib import Path
import sys
import types
import unittest


REPO_ROOT = os.path.dirname(os.path.dirname(__file__))


def _load_router_module():
    module_path = os.path.join(REPO_ROOT, 'utils', 'ai', 'router.py')
    spec = importlib.util.spec_from_file_location('phase6_ai_router', module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class Phase6AIRouterContractTestCase(unittest.TestCase):
    def _load_ioc_runtime_module(self, module_name: str, relative_path: str, invoke_json):
        fake_utils = types.ModuleType('utils')
        fake_utils.__path__ = [os.path.join(REPO_ROOT, 'utils')]
        fake_ai = types.ModuleType('utils.ai')
        fake_ai.__path__ = []
        fake_router = types.ModuleType('utils.ai.router')
        fake_router.invoke_json = invoke_json

        previous_modules = {
            name: sys.modules.get(name)
            for name in ('utils', 'utils.ai', 'utils.ai.router')
        }
        sys.modules['utils'] = fake_utils
        sys.modules['utils.ai'] = fake_ai
        sys.modules['utils.ai.router'] = fake_router

        try:
            module_path = os.path.join(REPO_ROOT, 'utils', relative_path)
            spec = importlib.util.spec_from_file_location(module_name, module_path)
            module = importlib.util.module_from_spec(spec)
            assert spec.loader is not None
            spec.loader.exec_module(module)
        finally:
            for name, previous in previous_modules.items():
                if previous is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = previous

        return module

    def test_normalize_usage_maps_cache_and_token_fields(self):
        router = _load_router_module()

        normalized = router._normalize_usage(
            {
                'prompt_tokens': 120,
                'completion_tokens': 30,
                'total_tokens': 150,
                'prompt_tokens_details': {'cached_tokens': 80},
            }
        )

        self.assertEqual(normalized['input_tokens'], 120)
        self.assertEqual(normalized['output_tokens'], 30)
        self.assertEqual(normalized['cache_read_input_tokens'], 80)
        self.assertEqual(normalized['stable_prefix_cache_hits'], 1)

    def test_invoke_text_routes_through_shared_provider_and_records_metrics(self):
        router = _load_router_module()

        fake_utils = types.ModuleType('utils')
        fake_utils.__path__ = []
        fake_provider_module = types.ModuleType('utils.ai_providers')

        class FakeProvider:
            model = 'casescope-report'

            def provider_type(self):
                return 'local'

            def get_provider_display(self):
                return 'Local casescope-report'

            def generate(self, **kwargs):
                return {
                    'success': True,
                    'response': f"echo:{kwargs['prompt']}",
                    'usage': {
                        'input_tokens': 50,
                        'output_tokens': 25,
                        'cache_creation_input_tokens': 50,
                    },
                }

        fake_provider_module.get_llm_provider = (
            lambda model_override=None, function=None: FakeProvider()
        )

        previous_utils = sys.modules.get('utils')
        previous_ai_providers = sys.modules.get('utils.ai_providers')
        sys.modules['utils'] = fake_utils
        sys.modules['utils.ai_providers'] = fake_provider_module
        try:
            result = router.invoke_text(
                function='report',
                prompt='hello',
                system='system',
                temperature=0.3,
                max_tokens=200,
            )
        finally:
            if previous_utils is not None:
                sys.modules['utils'] = previous_utils
            else:
                sys.modules.pop('utils', None)
            if previous_ai_providers is not None:
                sys.modules['utils.ai_providers'] = previous_ai_providers
            else:
                sys.modules.pop('utils.ai_providers', None)

        self.assertTrue(result['success'])
        self.assertEqual(result['response'], 'echo:hello')
        self.assertEqual(result['runtime']['function'], 'report')
        self.assertEqual(result['runtime']['provider_type'], 'local')
        self.assertEqual(result['runtime']['metrics']['cache_creation_input_tokens'], 50)
        snapshot = router.get_ai_runtime_metrics()
        self.assertGreaterEqual(snapshot['by_function']['report']['calls'], 1)

    def test_invoke_json_can_use_explicit_provider_instance(self):
        router = _load_router_module()

        class FakeProvider:
            model = 'casescope-review'

            def provider_type(self):
                return 'local'

            def get_provider_display(self):
                return 'Local casescope-review'

            def generate_json(self, **kwargs):
                return {
                    'success': True,
                    'data': {'ok': True, 'prompt': kwargs['prompt']},
                    'usage': {'input_tokens': 20, 'output_tokens': 10},
                }

        result = router.invoke_json(
            function='case_review',
            prompt='repair',
            system='system',
            provider=FakeProvider(),
        )

        self.assertTrue(result['success'])
        self.assertEqual(result['data']['prompt'], 'repair')
        self.assertEqual(result['runtime']['provider_type'], 'local')

    def test_ioc_gemma_json_prompts_start_with_no_think(self):
        router = _load_router_module()
        captured = {}

        class FakeProvider:
            model = 'gemma3:12b'

            def provider_type(self):
                return 'local'

            def get_provider_display(self):
                return 'Local gemma3:12b'

            def generate_json(self, **kwargs):
                captured.update(kwargs)
                return {
                    'success': True,
                    'data': {'ok': True},
                    'usage': {'input_tokens': 20, 'output_tokens': 10},
                }

        result = router.invoke_json(
            function='ioc_extraction',
            prompt='Extract IOCs',
            system='System rules',
            provider=FakeProvider(),
        )

        self.assertTrue(result['success'])
        self.assertTrue(captured['prompt'].startswith('/no_think\nExtract IOCs'))
        self.assertTrue(captured['system'].startswith('/no_think\nSystem rules'))

    def test_stream_chat_records_runtime_metrics_on_terminal_chunk(self):
        router = _load_router_module()

        class FakeProvider:
            model = 'casescope-chat'

            def provider_type(self):
                return 'local'

            def get_provider_display(self):
                return 'Local casescope-chat'

            def stream_chat(self, **kwargs):
                yield {
                    'message': {'role': 'assistant', 'content': 'partial'},
                    'done': False,
                }
                yield {
                    'message': {'role': 'assistant', 'content': ''},
                    'done': True,
                    'usage': {'input_tokens': 12, 'output_tokens': 4},
                }

        chunks = list(
            router.stream_chat(
                function='chat_runtime',
                messages=[{'role': 'user', 'content': 'hello'}],
                provider=FakeProvider(),
            )
        )

        self.assertEqual(len(chunks), 2)
        self.assertNotIn('runtime', chunks[0])
        self.assertEqual(chunks[-1]['runtime']['mode'], 'stream_chat')
        self.assertEqual(chunks[-1]['runtime']['provider_type'], 'local')
        snapshot = router.get_ai_runtime_metrics()
        self.assertGreaterEqual(snapshot['by_function']['chat_runtime']['calls'], 1)

    def test_ioc_substages_route_through_shared_invoke_json(self):
        semantic_calls = []

        def semantic_invoke_json(**kwargs):
            semantic_calls.append(kwargs)
            return {'success': True, 'data': {'domains': ['bad.example']}}

        semantic_module = self._load_ioc_runtime_module(
            'phase6_semantic_ioc_extractor',
            'semantic_ioc_extractor.py',
            semantic_invoke_json,
        )
        semantic_module.build_semantic_task_plan = lambda *_args, **_kwargs: [
            {
                'task_name': 'semantic_network',
                'section_names': ['Network'],
                'prompt_template': '{0}',
                'sections': [{'name': 'Network', 'body': 'bad.example beacon'}],
            }
        ]
        semantic_module._report_normalizer.chunk_report_for_ai_with_metadata = (
            lambda text, _max_chars: [
                {'text': text, 'chunk_index': 1, 'chunk_count': 1}
            ]
        )

        semantic_result = semantic_module.run_semantic_stage(
            provider='provider',
            report_text='Network\n------------\nbad.example beacon',
            deterministic_extraction={'iocs': {}},
            max_chunk_chars=2000,
            max_response_tokens=400,
            validate_result=lambda _result: None,
            prepare_payload=lambda _provider, data, **_kwargs: (data, {}),
            filter_payload_for_task=lambda _task, payload: payload,
            normalize_extraction=lambda payload, _report: {'payload': payload},
        )

        self.assertEqual(len(semantic_calls), 1)
        self.assertEqual(semantic_calls[0]['function'], 'ioc_extraction')
        self.assertEqual(
            semantic_result['normalized_results'][0]['payload'],
            {'domains': ['bad.example']},
        )

        audit_calls = []

        def audit_invoke_json(**kwargs):
            audit_calls.append(kwargs)
            return {
                'success': True,
                'data': {'additions': [], 'corrections': [], 'drops': []},
            }

        audit_module = self._load_ioc_runtime_module(
            'phase6_ioc_audit',
            'ioc_audit.py',
            audit_invoke_json,
        )
        audit_module._report_normalizer.chunk_report_for_ai_with_metadata = (
            lambda _text, _max_chars: [
                {
                    'text': 'Observed bad.example beacon',
                    'sections': ['Network'],
                    'chunk_index': 1,
                    'chunk_count': 1,
                }
            ]
        )
        audit_module.select_chunk_candidates = (
            lambda _extraction, _text: [{'type': 'domain', 'value': 'bad.example'}]
        )
        audit_module.validate_audit_delta = (
            lambda _data, **_kwargs: (
                {'additions': [], 'corrections': [], 'drops': []},
                {'rejected': []},
            )
        )
        audit_module.apply_audit_deltas = (
            lambda extraction, deltas: {'original': extraction, 'delta_count': len(deltas)}
        )

        audit_result = audit_module.run_audit_stage(
            provider='provider',
            report_text='Observed bad.example beacon',
            deterministic_extraction={'iocs': {'domains': ['bad.example']}},
            max_chunk_chars=2000,
            max_response_tokens=400,
            validate_result=lambda _result: None,
        )

        self.assertEqual(len(audit_calls), 1)
        self.assertEqual(audit_calls[0]['function'], 'ioc_extraction')
        self.assertEqual(audit_result['reviewed_chunks'], 1)
        self.assertEqual(audit_result['candidate_count'], 1)

    def test_cloud_case_content_requires_privacy_context(self):
        router = _load_router_module()

        class PrivacyContextRequiredError(RuntimeError):
            pass

        fake_privacy = types.ModuleType('utils.privacy_aliases')

        def sanitize_for_ai_egress(value, *, context, provider):
            if context is None and provider.provider_type() != 'local':
                raise PrivacyContextRequiredError('privacy context required')
            return types.SimpleNamespace(value=value, metadata={'enabled': bool(context), 'aliases_applied': 0})

        fake_privacy.sanitize_for_ai_egress = sanitize_for_ai_egress
        previous_privacy = sys.modules.get('utils.privacy_aliases')
        sys.modules['utils.privacy_aliases'] = fake_privacy

        class CloudProvider:
            model = 'cloud-model'

            def provider_type(self):
                return 'openai'

            def get_provider_display(self):
                return 'OpenAI cloud-model'

            def generate(self, **_kwargs):
                return {'success': True, 'response': 'ok'}

        try:
            with self.assertRaises(PrivacyContextRequiredError):
                router.invoke_text(function='report', prompt='raw user', provider=CloudProvider())
        finally:
            if previous_privacy is None:
                sys.modules.pop('utils.privacy_aliases', None)
            else:
                sys.modules['utils.privacy_aliases'] = previous_privacy

    def test_router_sanitizes_before_fake_cloud_provider_receives_prompt(self):
        router = _load_router_module()
        captured = {}
        raw_identifier = 'alice@client.example'

        fake_privacy = types.ModuleType('utils.privacy_aliases')

        def sanitize_for_ai_egress(value, *, context, provider):
            self.assertIsNotNone(context)
            if isinstance(value, str):
                value = value.replace(raw_identifier, 'EMAIL_0001')
            return types.SimpleNamespace(
                value=value,
                metadata={'enabled': True, 'aliases_applied': 1, 'entity_categories': ['EMAIL']},
            )

        fake_privacy.sanitize_for_ai_egress = sanitize_for_ai_egress
        previous_privacy = sys.modules.get('utils.privacy_aliases')
        sys.modules['utils.privacy_aliases'] = fake_privacy

        class CloudProvider:
            model = 'cloud-model'

            def provider_type(self):
                return 'openai'

            def get_provider_display(self):
                return 'OpenAI cloud-model'

            def generate(self, **kwargs):
                captured.update(kwargs)
                return {'success': True, 'response': 'EMAIL_0001 logged in'}

        try:
            result = router.invoke_text(
                function='report',
                prompt=f'Investigate {raw_identifier}',
                provider=CloudProvider(),
                privacy_context=types.SimpleNamespace(case_id=146, content_scope='case_content'),
            )
        finally:
            if previous_privacy is None:
                sys.modules.pop('utils.privacy_aliases', None)
            else:
                sys.modules['utils.privacy_aliases'] = previous_privacy

        self.assertTrue(result['success'])
        self.assertNotIn(raw_identifier, captured['prompt'])
        self.assertIn('EMAIL_0001', captured['prompt'])
        self.assertTrue(result['privacy']['enabled'])

    def test_privacy_extractor_detects_quoted_bare_hostnames(self):
        from utils.privacy_aliases import extract_alias_candidates_from_text

        candidates = extract_alias_candidates_from_text(
            'Installed on host "BDALENE" before the host by an unauthorized party.'
        )
        host_values = {
            candidate.original_value
            for key, candidate in candidates.items()
            if key.entity_type == 'HOSTNAME'
        }

        self.assertIn('BDALENE', host_values)
        self.assertNotIn('by', {value.lower() for value in host_values})

    def test_ioc_enhancement_rehydrates_ai_output_before_staging(self):
        source = Path(REPO_ROOT, 'tasks', 'celery_tasks.py').read_text()

        self.assertIn('from utils.privacy_aliases import rehydrate_for_display', source)
        self.assertIn('ai_extraction_for_review = rehydrate_for_display(case.id, ai_extraction)', source)
        self.assertIn('extraction=ai_extraction_for_review,', source)

    def test_ioc_enhancement_rehydrates_legacy_staged_candidates(self):
        model_source = Path(REPO_ROOT, 'models', 'ioc_enhancement.py').read_text()
        route_source = Path(REPO_ROOT, 'routes', 'iocs.py').read_text()

        self.assertIn('display_candidates = rehydrate_for_display(self.case_id, candidates)', model_source)
        self.assertIn('selected_for_save = rehydrate_for_display(case.id, selected)', route_source)
        self.assertIn('iocs_data=selected_for_save,', route_source)


if __name__ == '__main__':
    unittest.main()
