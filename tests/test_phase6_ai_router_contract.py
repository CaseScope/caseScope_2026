import importlib.util
import os
import sys
import types
import unittest
from pathlib import Path


REPO_ROOT = os.path.dirname(os.path.dirname(__file__))


def _load_router_module():
    module_path = os.path.join(REPO_ROOT, 'utils', 'ai', 'router.py')
    spec = importlib.util.spec_from_file_location('phase6_ai_router', module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class Phase6AIRouterContractTestCase(unittest.TestCase):
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

    def test_ioc_substages_route_through_shared_invoke_json(self):
        semantic_source = Path(
            os.path.join(REPO_ROOT, 'utils', 'semantic_ioc_extractor.py')
        ).read_text(encoding='utf-8')
        audit_source = Path(
            os.path.join(REPO_ROOT, 'utils', 'ioc_audit.py')
        ).read_text(encoding='utf-8')

        self.assertIn('from utils.ai.router import invoke_json', semantic_source)
        self.assertIn('ai_result = invoke_json(', semantic_source)
        self.assertNotIn('provider.generate_json(', semantic_source)
        self.assertIn('from utils.ai.router import invoke_json', audit_source)
        self.assertIn('ai_result = invoke_json(', audit_source)
        self.assertNotIn('provider.generate_json(', audit_source)


if __name__ == '__main__':
    unittest.main()
