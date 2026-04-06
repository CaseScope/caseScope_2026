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

    def test_extract_iocs_with_ai_marks_partial_chunk_failure_as_degraded(self):
        original_chunker = self.extractor_module._chunk_report_for_ai_with_metadata
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

        self.extractor_module._chunk_report_for_ai_with_metadata = lambda *_args, **_kwargs: [
            {
                'text': 'chunk one',
                'sections': ['Overview'],
                'overlap_applied': False,
                'chunk_index': 1,
                'chunk_count': 2,
            },
            {
                'text': 'chunk two',
                'sections': ['Late Evidence'],
                'overlap_applied': True,
                'chunk_index': 2,
                'chunk_count': 2,
            },
        ]
        sys.modules['utils.feature_availability'] = fake_feature_module
        sys.modules['utils.ai_providers'] = fake_provider_module

        try:
            extraction, used_ai = self.extractor_module.extract_iocs_with_ai('evil.example')
        finally:
            self.extractor_module._chunk_report_for_ai_with_metadata = original_chunker
            if previous_feature_module is not None:
                sys.modules['utils.feature_availability'] = previous_feature_module
            else:
                sys.modules.pop('utils.feature_availability', None)
            if previous_provider_module is not None:
                sys.modules['utils.ai_providers'] = previous_provider_module
            else:
                sys.modules.pop('utils.ai_providers', None)

        self.assertTrue(used_ai)
        self.assertEqual(extraction['extraction_summary']['method'], 'ai_plus_regex_degraded')
        self.assertTrue(extraction['extraction_summary']['ai_degraded'])
        self.assertEqual(extraction['extraction_summary']['ai_chunk_failures'], [2])
        self.assertEqual(extraction['extraction_summary']['ai_chunk_successes'], 1)
        self.assertIn('HOST-A', extraction['iocs']['hostnames'])

    def test_resolve_ai_chunk_config_scales_up_for_large_context_models(self):
        resolve_config = self.extractor_module._resolve_ai_chunk_config

        local_config = resolve_config({'context_window': 16384, 'max_tokens': 4000})
        large_config = resolve_config({'context_window': 128000, 'max_tokens': 4096})

        self.assertGreater(large_config['max_chunk_chars'], local_config['max_chunk_chars'])
        self.assertEqual(local_config['max_response_tokens'], 4000)

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


if __name__ == '__main__':
    unittest.main()
