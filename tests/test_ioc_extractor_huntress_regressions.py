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
