import importlib.util
import os
import sys
import types
import unittest


REPO_ROOT = os.path.dirname(os.path.dirname(__file__))


class IOCHuntressExtractorRegressionTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fake_utils = types.ModuleType('utils')
        fake_utils.__path__ = []
        fake_ai_training = types.ModuleType('utils.ai_training')
        fake_ai_training.build_role_system_prompt = (
            lambda route_name, extra_instructions='': extra_instructions
        )

        cls._previous_utils = sys.modules.get('utils')
        cls._previous_ai_training = sys.modules.get('utils.ai_training')
        sys.modules['utils'] = fake_utils
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

            if cls._previous_ai_training is not None:
                sys.modules['utils.ai_training'] = cls._previous_ai_training
            else:
                sys.modules.pop('utils.ai_training', None)

    def _read_report(self, name):
        report_path = os.path.join(REPO_ROOT, 'example_reports', 'huntress', name)
        with open(report_path, 'r', encoding='utf-8') as handle:
            return handle.read()

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

    def test_regex_extractor_defangs_huntress_urls_and_domains_from_sample_reports(self):
        extractor = self.extractor_module.RegexIOCExtractor()

        report50 = extractor.extract(self._read_report('report50.txt'))
        urls = {item['value'] for item in report50['iocs']['urls']}
        domains = {item['value'] for item in report50['iocs']['domains']}

        self.assertIn('https://teuehebaji.de/ture.html', urls)
        self.assertIn('yoc736.ikhelp.top', domains)

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
        fake_ai_training = types.ModuleType('utils.ai_training')
        fake_ai_training.build_role_system_prompt = (
            lambda route_name, extra_instructions='': extra_instructions
        )

        previous_utils = sys.modules.get('utils')
        previous_ai_training = sys.modules.get('utils.ai_training')
        sys.modules['utils'] = fake_utils
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

    def test_prepare_ai_extraction_payload_reviews_semantic_task_field_leakage_and_invalid_hash(self):
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

        self.assertTrue(meta['review_applied'])
        self.assertEqual(len(review_calls), 1)
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
            all(failure['error'] == "finish_reason was 'length'" for failure in result['task_failures'])
        )
        self.assertFalse(review_calls)

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
                'task_failures': [{'task': 'semantic_residual_review', 'chunk': 2, 'error': 'simulated chunk failure'}],
                'task_provenance': [{'task': 'semantic_users_and_accounts', 'sections': ['Overview'], 'chunk': 1, 'chunk_count': 2}],
                'schema_reviews': 0,
                'planned_tasks': ['semantic_users_and_accounts', 'semantic_residual_review'],
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

    def test_semantic_task_plan_includes_residual_pass_for_unmapped_sections(self):
        build_plan = self.extractor_module._semantic_stage.build_semantic_task_plan
        report = (
            "Overview\n--------\n"
            "Analyst prose without direct process keywords.\n\n"
            "Odd Vendor Section\n------------------\n"
            "Novel field: remote blob identifier abc123\n"
        )

        tasks = build_plan(report, {'iocs': {}, 'extraction_summary': {}})

        task_names = [task['task_name'] for task in tasks]
        self.assertIn('semantic_residual_review', task_names)

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

        filtered = self.extractor_module._filter_semantic_payload_for_task(
            'semantic_process_relationships',
            payload,
        )

        self.assertEqual(filtered['affected_users'], [])
        self.assertEqual(len(filtered['process_iocs']['commands']), 1)
        self.assertEqual(filtered['authentication_iocs']['compromised_users'], [])

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
            {'username': 'maria.lopez', 'sid': ''},
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

        class FakeProvider:
            model = 'fake-audit-model'

            @staticmethod
            def get_batch_config():
                return {'context_window': 16384, 'max_tokens': 4000}

        def fake_audit_stage(_provider, _report_text, deterministic_extraction, **_kwargs):
            audited = {
                'extraction_summary': dict(deterministic_extraction.get('extraction_summary', {})),
                'iocs': dict(deterministic_extraction.get('iocs', {})),
                'raw_artifacts': dict(deterministic_extraction.get('raw_artifacts', {})),
            }
            audited['iocs']['domains'] = [{'value': 'audit-added.example', 'context': 'audit addition'}]
            return {
                'audited_extraction': audited,
                'validated_deltas': [],
                'task_failures': [],
                'task_provenance': [{'chunk': 'chunk-01', 'sections': ['Overview']}],
                'planned_tasks': ['chunk-01'],
                'reviewed_chunks': 1,
                'candidate_count': 2,
                'rejected_delta_count': 0,
                'schema_reviews': 0,
            }

        self.extractor_module._audit_stage.run_audit_stage = fake_audit_stage
        try:
            extraction, used_ai = self.extractor_module.run_ioc_pipeline_with_provider(
                'Domain: audit-added.example',
                FakeProvider(),
                pipeline_mode='audit',
                model_name='fake-audit-model',
            )
        finally:
            self.extractor_module._audit_stage.run_audit_stage = original_audit_runner

        self.assertTrue(used_ai)
        self.assertEqual(extraction['extraction_summary']['method'], 'deterministic_plus_audit')
        self.assertEqual(extraction['extraction_summary']['model'], 'fake-audit-model')
        self.assertEqual(extraction['extraction_summary']['audit_chunk_count'], 1)
        self.assertTrue(
            any(item['value'] == 'audit-added.example' for item in extraction['iocs']['domains'])
        )


if __name__ == '__main__':
    unittest.main()
