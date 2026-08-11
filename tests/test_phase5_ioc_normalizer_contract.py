import importlib.util
import os
import unittest


REPO_ROOT = os.path.dirname(os.path.dirname(__file__))


def _load_module(name: str, relative_path: str):
    module_path = os.path.join(REPO_ROOT, relative_path)
    spec = importlib.util.spec_from_file_location(name, module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


ioc_normalizer = _load_module(
    'phase5_ioc_normalizer',
    os.path.join('utils', 'ioc_normalizer.py'),
)
ioc_schema = _load_module(
    'phase5_ioc_schema',
    os.path.join('utils', 'ioc_schema.py'),
)


class Phase5IOCNormalizerContractTestCase(unittest.TestCase):
    def test_defang_and_file_name_helpers_are_shared(self):
        self.assertEqual(
            ioc_normalizer._defang_text('hxxps://evil[.]example/path'),
            'https://evil.example/path',
        )
        self.assertEqual(
            ioc_normalizer._normalize_ai_file_name(
                'payload.exe (Quarantined by Microsoft Defender)'
            ),
            'payload.exe',
        )

    def test_normalize_ai_extraction_preserves_additive_guardrails(self):
        normalized = ioc_normalizer._normalize_ai_extraction(
            {
                'affected_hosts': ['HOST-A'],
                'affected_users': [{'username': 'alice', 'sid': 'S-1-5-21-1'}],
                'network_iocs': {
                    'ipv4': [{'value': '10[.]0[.]0[.]5'}],
                    'ipv6': [],
                    'domains': [],
                    'urls': [{'value': 'http://evil.example/path'}],
                    'cloudflare_tunnels': [],
                },
                'file_iocs': {
                    'hashes': [],
                    'file_paths': [{'value': r'C:\Temp\payload.exe'}],
                    'file_names': [],
                },
                'process_iocs': {'commands': [], 'services': [], 'scheduled_tasks': []},
                'persistence_iocs': {'registry': [], 'credential_theft_indicators': []},
                'authentication_iocs': {
                    'compromised_users': [{'username': 'alice'}],
                    'created_users': [],
                    'passwords_observed': [],
                },
                'vulnerability_iocs': {'cves': [], 'webshells': []},
                'raw_artifacts': {},
            },
            report_text='Observed user alice on HOST-A contacting http://evil.example/path',
        )

        self.assertEqual(normalized['iocs']['ip_addresses'][0]['value'], '10.0.0.5')
        self.assertEqual(normalized['iocs']['file_names'], ['payload.exe'])
        self.assertEqual(normalized['iocs']['domains'][0]['value'], 'evil.example')
        self.assertTrue(
            any(user.get('value') == 'alice' for user in normalized['iocs']['users'])
        )

    def test_semantic_affected_user_exact_provenance_survives_records(self):
        evidence_ref = {
            'source_section': 'Affected Users',
            'canonical_section': 'identity',
            'evidence': 'Account ACMATCORP\\CPalmero was involved in the observed execution.',
        }
        normalized = ioc_normalizer._normalize_ai_extraction(
            {
                'affected_users': [
                    {
                        'username': 'ACMATCORP\\CPalmero',
                        'sid': None,
                        'evidence': evidence_ref['evidence'],
                        'evidence_source_section': 'Affected Users',
                        'canonical_section': 'identity',
                        'evidence_classes': ['identity'],
                        'evidence_refs': [evidence_ref],
                    }
                ],
                'network_iocs': {'ipv4': [], 'ipv6': [], 'domains': [], 'urls': [], 'cloudflare_tunnels': []},
                'file_iocs': {'hashes': [], 'file_paths': [], 'file_names': []},
                'process_iocs': {'commands': [], 'services': [], 'scheduled_tasks': []},
                'persistence_iocs': {'registry': [], 'credential_theft_indicators': []},
                'authentication_iocs': {'compromised_users': [], 'created_users': [], 'passwords_observed': []},
                'vulnerability_iocs': {'cves': [], 'webshells': []},
                'raw_artifacts': {},
                'extraction_summary': {'semantic_sections': ['Executive Summary', 'Affected Users']},
            },
            report_text=evidence_ref['evidence'],
        )
        records = ioc_schema.records_from_extraction(
            normalized,
            source='semantic',
            trust_tier=ioc_schema.TRUST_HIGH,
        )

        user_record = next(record for record in records if record['ioc_type'] == 'Username')
        self.assertEqual(user_record['evidence_source_section'], 'Affected Users')
        self.assertEqual(user_record['canonical_section'], 'identity')
        self.assertEqual(user_record['evidence_refs'][0]['source_section'], 'Affected Users')

    def test_identity_and_password_provenance_survives_normalization_and_records(self):
        user_evidence = 'The attacker authenticated successfully using account ACMATCORP\\CPalmero.'
        password_evidence = 'Password Spring2026! was explicitly observed for ACMATCORP\\CPalmero.'
        created_evidence = 'Attacker created account svc-backup with observed password TempP@ss1.'
        normalized = ioc_normalizer._normalize_ai_extraction(
            {
                'network_iocs': {'ipv4': [], 'ipv6': [], 'domains': [], 'urls': [], 'cloudflare_tunnels': []},
                'file_iocs': {'hashes': [], 'file_paths': [], 'file_names': []},
                'process_iocs': {'commands': [], 'services': [], 'scheduled_tasks': []},
                'persistence_iocs': {'registry': [], 'credential_theft_indicators': []},
                'authentication_iocs': {
                    'compromised_users': [
                        {
                            'username': 'ACMATCORP\\CPalmero',
                            'sid': None,
                            'evidence': user_evidence,
                            'evidence_source_section': 'Affected Users',
                            'canonical_section': 'identity',
                            'evidence_refs': [{'source_section': 'Affected Users', 'canonical_section': 'identity', 'evidence': user_evidence}],
                        }
                    ],
                    'created_users': [
                        {
                            'username': 'svc-backup',
                            'sid': None,
                            'password': 'TempP@ss1',
                            'evidence': created_evidence,
                            'evidence_origin': 'reported_finding',
                            'evidence_source_section': 'Account Creation',
                            'canonical_section': 'identity',
                            'evidence_refs': [{'source_section': 'Account Creation', 'canonical_section': 'identity', 'evidence': created_evidence}],
                        }
                    ],
                    'passwords_observed': [
                        {
                            'username': 'ACMATCORP\\CPalmero',
                            'password': 'Spring2026!',
                            'evidence': password_evidence,
                            'evidence_origin': 'reported_finding',
                            'evidence_source_section': 'Credential Evidence',
                            'canonical_section': 'identity',
                            'evidence_refs': [{'source_section': 'Credential Evidence', 'canonical_section': 'identity', 'evidence': password_evidence}],
                        }
                    ],
                },
                'vulnerability_iocs': {'cves': [], 'webshells': []},
                'raw_artifacts': {},
                'extraction_summary': {'semantic_sections': ['Executive Summary', 'Affected Users', 'Credential Evidence']},
            },
            report_text=f'{user_evidence} {password_evidence} {created_evidence}',
        )
        records = ioc_schema.records_from_extraction(
            normalized,
            source='semantic',
            trust_tier=ioc_schema.TRUST_HIGH,
        )
        records_by_value = {(record['ioc_type'], record['value']): record for record in records}

        self.assertEqual(
            records_by_value[('Username', 'ACMATCORP\\CPalmero')]['evidence_refs'][0]['source_section'],
            'Affected Users',
        )
        self.assertEqual(
            records_by_value[('Password', 'Spring2026!')]['evidence_source_section'],
            'Credential Evidence',
        )
        self.assertEqual(
            records_by_value[('Password', 'Spring2026!')]['evidence_refs'][0]['source_section'],
            'Credential Evidence',
        )
        self.assertEqual(
            records_by_value[('Username', 'svc-backup')]['evidence_source_section'],
            'Account Creation',
        )
        self.assertEqual(
            records_by_value[('Password', 'TempP@ss1')]['evidence_refs'][0]['source_section'],
            'Account Creation',
        )

    def test_identity_record_with_multiple_refs_keeps_refs_without_single_section_guess(self):
        records = ioc_schema.records_from_extraction(
            {
                'extraction_summary': {'semantic_sections': ['Executive Summary', 'Affected Users']},
                'iocs': {
                    'users': [
                        {
                            'value': 'ACMATCORP\\CPalmero',
                            'username': 'ACMATCORP\\CPalmero',
                            'evidence': 'ACMATCORP\\CPalmero was observed.',
                            'evidence_refs': [
                                {'source_section': 'Executive Summary', 'canonical_section': 'summary', 'evidence': 'ACMATCORP\\CPalmero was observed.'},
                                {'source_section': 'Affected Users', 'canonical_section': 'identity', 'evidence': 'ACMATCORP\\CPalmero was observed.'},
                            ],
                        }
                    ],
                },
            },
            source='semantic',
            trust_tier=ioc_schema.TRUST_HIGH,
        )

        user_record = next(record for record in records if record['ioc_type'] == 'Username')
        self.assertEqual(user_record['evidence_source_section'], '')
        self.assertEqual(
            [ref['source_section'] for ref in user_record['evidence_refs']],
            ['Executive Summary', 'Affected Users'],
        )

    def test_summary_only_affected_user_does_not_get_section_guess(self):
        records = ioc_schema.records_from_extraction(
            {
                'extraction_summary': {
                    'semantic_sections': ['Executive Summary', 'Affected Users'],
                    'affected_users': [{'username': 'ACMATCORP\\CPalmero', 'sid': None}],
                },
                'iocs': {},
            },
            source='semantic',
            trust_tier=ioc_schema.TRUST_HIGH,
        )

        user_record = next(record for record in records if record['field'] == 'affected_users')
        self.assertEqual(user_record['evidence_source_section'], '')

    def test_command_only_scheduled_task_survives_without_fabricated_name_or_path(self):
        normalized = ioc_normalizer._normalize_ai_extraction(
            {
                'network_iocs': {'ipv4': [], 'ipv6': [], 'domains': [], 'urls': [], 'cloudflare_tunnels': []},
                'file_iocs': {'hashes': [], 'file_paths': [], 'file_names': []},
                'process_iocs': {
                    'commands': [],
                    'services': [],
                    'scheduled_tasks': [
                        {
                            'name': None,
                            'path': None,
                            'command': 'pythonw.exe run.pyw',
                            'action': None,
                            'evidence': 'Scheduled task executed pythonw.exe run.pyw.',
                            'evidence_origin': 'reported_finding',
                        }
                    ],
                },
                'persistence_iocs': {'registry': [], 'credential_theft_indicators': []},
                'authentication_iocs': {'compromised_users': [], 'created_users': [], 'passwords_observed': []},
                'vulnerability_iocs': {'cves': [], 'webshells': []},
                'raw_artifacts': {},
            },
            report_text='Scheduled task executed pythonw.exe run.pyw.',
        )

        self.assertEqual(len(normalized['iocs']['scheduled_tasks']), 1)
        task = normalized['iocs']['scheduled_tasks'][0]
        self.assertIsNone(task['name'])
        self.assertIsNone(task['path'])
        self.assertEqual(task['command'], 'pythonw.exe run.pyw')
        self.assertTrue(
            any(command['value'] == 'pythonw.exe run.pyw' for command in normalized['iocs']['commands'])
        )


if __name__ == '__main__':
    unittest.main()
