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


if __name__ == '__main__':
    unittest.main()
