import importlib.util
import os
import sys
import types
import unittest


REPO_ROOT = os.path.dirname(os.path.dirname(__file__))


class _FakeDB:
    Model = object

    @staticmethod
    def Column(*_args, **_kwargs):
        return None

    @staticmethod
    def String(*_args, **_kwargs):
        return None

    @staticmethod
    def Integer(*_args, **_kwargs):
        return None

    @staticmethod
    def DateTime(*_args, **_kwargs):
        return None

    @staticmethod
    def Text(*_args, **_kwargs):
        return None

    @staticmethod
    def Boolean(*_args, **_kwargs):
        return None

    @staticmethod
    def JSON(*_args, **_kwargs):
        return None

    @staticmethod
    def ForeignKey(*_args, **_kwargs):
        return None

    @staticmethod
    def relationship(*_args, **_kwargs):
        return None

    @staticmethod
    def backref(*_args, **_kwargs):
        return None

    @staticmethod
    def UniqueConstraint(*_args, **_kwargs):
        return None


class IOCModelCaseScopeTestCase(unittest.TestCase):
    def test_link_to_case_only_matches_owned_case(self):
        database_module = types.ModuleType('models.database')
        database_module.db = _FakeDB()
        sys.modules['models.database'] = database_module

        module_path = os.path.join(REPO_ROOT, 'models', 'ioc.py')
        spec = importlib.util.spec_from_file_location('ioc_model_under_test', module_path)
        ioc_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ioc_module)

        ioc = ioc_module.IOC()
        ioc.case_id = 7

        self.assertTrue(ioc.link_to_case(7))
        self.assertFalse(ioc.link_to_case(8))

    def test_normalize_value_lowercases_file_names(self):
        database_module = types.ModuleType('models.database')
        database_module.db = _FakeDB()
        sys.modules['models.database'] = database_module

        module_path = os.path.join(REPO_ROOT, 'models', 'ioc.py')
        spec = importlib.util.spec_from_file_location('ioc_model_under_test', module_path)
        ioc_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ioc_module)

        normalized = ioc_module.IOC.normalize_value('RunMe.EXE', 'File Name')
        self.assertEqual(normalized, 'runme.exe')


class IOCExtractorCaseScopeTestCase(unittest.TestCase):
    def setUp(self):
        class FakeExistingIOC:
            def __init__(self, ioc_id, notes='notes', match_type='token'):
                self.id = ioc_id
                self.notes = notes
                self._match_type = match_type

            def get_effective_match_type(self):
                return self._match_type

        self.fake_existing_ioc = FakeExistingIOC(101)
        self.fake_command_ioc = FakeExistingIOC(202, match_type='substring')

        class FakeIOC:
            calls = []

            @staticmethod
            def find_by_value(value, ioc_type, case_id=None):
                FakeIOC.calls.append((value, ioc_type, case_id))
                if value == 'evil.example' and ioc_type == 'Domain' and case_id == 42:
                    return self.fake_existing_ioc
                if value == 'cmd.exe' and ioc_type == 'Command Line' and case_id == 42:
                    return self.fake_command_ioc
                return None

        fake_ioc_module = types.ModuleType('models.ioc')
        fake_ioc_module.IOC = FakeIOC
        fake_ioc_module.detect_match_type = lambda value, ioc_type: 'token'
        fake_ioc_module.get_match_type_recommendation = (
            lambda value, ioc_type: {'reason': f'{ioc_type} recommendation'}
        )
        fake_ioc_module.get_category_for_type = lambda ioc_type: 'File'
        sys.modules['models.ioc'] = fake_ioc_module

        fake_database_module = types.ModuleType('models.database')
        fake_database_module.db = object()
        sys.modules['models.database'] = fake_database_module

        class FakeKnownSystem:
            @staticmethod
            def find_by_hostname_or_alias(hostname, case_id=None):
                return None, None

        fake_known_system_module = types.ModuleType('models.known_system')
        fake_known_system_module.KnownSystem = FakeKnownSystem
        sys.modules['models.known_system'] = fake_known_system_module

        class FakeKnownUser:
            @staticmethod
            def find_by_username_sid_alias_or_email(username=None, sid=None, case_id=None):
                return None, None

            @staticmethod
            def normalize_username(username):
                return username, ''

        fake_known_user_module = types.ModuleType('models.known_user')
        fake_known_user_module.KnownUser = FakeKnownUser
        sys.modules['models.known_user'] = fake_known_user_module

        module_path = os.path.join(REPO_ROOT, 'utils', 'ioc_extractor.py')
        spec = importlib.util.spec_from_file_location('ioc_extractor_under_test', module_path)
        self.extractor_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.extractor_module)
        self.fake_ioc_cls = FakeIOC

    def test_create_ioc_entry_scopes_lookup_to_case(self):
        entry = self.extractor_module._create_ioc_entry(
            value='evil.example',
            ioc_type='Domain',
            category='Network',
            context='seen in DNS logs',
            case_id=42,
        )

        self.assertEqual(self.fake_ioc_cls.calls, [('evil.example', 'Domain', 42)])
        self.assertEqual(entry['existing_ioc_id'], 101)
        self.assertTrue(entry['already_linked'])
        self.assertFalse(entry['is_new'])

    def test_type_aware_entry_uses_case_scoped_command_lookup(self):
        entry = self.extractor_module._create_ioc_entry_with_type_awareness(
            primary_value='cmd.exe',
            primary_type='Command Line',
            aliases=['cmd.exe /c whoami'],
            original_type='Command Line',
            category='Process',
            context='seen in process tree',
            case_id=42,
        )

        self.assertEqual(
            self.fake_ioc_cls.calls,
            [
                ('cmd.exe', 'File Name', 42),
                ('cmd.exe', 'Command Line', 42),
            ],
        )
        self.assertEqual(entry['existing_ioc_id'], 202)
        self.assertTrue(entry['already_linked'])
        self.assertTrue(entry['merge_into_existing'])

    def test_normalize_ai_extraction_cleans_network_hash_and_user_fields(self):
        normalized = self.extractor_module._normalize_ai_extraction(
            {
                'affected_hosts': ['ATN74122'],
                'network_iocs': {
                    'ipv4': [{'value': '192[.]168[.]1[.]142'}],
                    'ipv6': [],
                    'domains': [
                        {'value': 'ssastatements-helper[.]top'},
                        {'value': 'tabinc.huntress.io'},
                    ],
                    'urls': [
                        {'value': 'https://tabinc.huntress.io/org/105204/infection_reports/1920466'}
                    ],
                    'cloudflare_tunnels': [],
                },
                'file_iocs': {
                    'hashes': [{'value': 'File is no longer on disk.', 'type': 'sha256'}],
                    'file_paths': [],
                    'file_names': [r'C:\Windows\System32\msiexec.exe'],
                },
                'authentication_iocs': {
                    'compromised_users': [
                        {'username': 'sues', 'sid': 'S-1-5-21-123'}
                    ],
                    'created_users': [],
                    'passwords_observed': [],
                },
            }
        )

        self.assertEqual(
            normalized['iocs']['ip_addresses'][0]['value'],
            '192.168.1.142',
        )
        self.assertEqual(
            [item['value'] for item in normalized['iocs']['domains']],
            ['ssastatements-helper.top'],
        )
        self.assertEqual(normalized['iocs']['urls'], [])
        self.assertEqual(normalized['iocs']['hashes'], [])
        self.assertEqual(normalized['iocs']['file_names'], ['msiexec.exe'])
        self.assertEqual(normalized['iocs']['users'][0]['value'], 'sues')
        self.assertEqual(normalized['iocs']['users'][0]['sid'], 'S-1-5-21-123')
        self.assertEqual(normalized['iocs']['hostnames'], ['ATN74122'])

    def test_regex_extractor_keeps_windows_paths_with_spaces(self):
        extractor = self.extractor_module.RegexIOCExtractor()
        report = (
            'Parent Process: C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\n'
            'Command: "C:\\Windows\\System32\\msiexec.exe" /i '
            '"C:\\Users\\sues\\Downloads\\mySSAstatement2026.msi"\n'
        )

        file_paths = [
            item['value']
            for item in extractor.extract(report)['iocs']['file_paths']
        ]

        self.assertIn(
            r'C:\Program Files\Google\Chrome\Application\chrome.exe',
            file_paths,
        )
        self.assertIn(r'C:\Windows\System32\msiexec.exe', file_paths)
        self.assertIn(r'C:\Users\sues\Downloads\mySSAstatement2026.msi', file_paths)
        self.assertNotIn(r'C:\Program', file_paths)

    def test_process_extraction_keeps_command_ioc_when_file_path_seen_first(self):
        processed = self.extractor_module.process_extraction_for_import(
            extraction={
                'iocs': {
                    'file_paths': [
                        {'value': r'C:\Windows\System32\msiexec.exe', 'context': '', 'action': ''}
                    ],
                    'commands': [
                        {
                            'value': '"C:\\Windows\\System32\\msiexec.exe" /i "C:\\Users\\sues\\Downloads\\mySSAstatement2026.msi"',
                            'executable': r'C:\Windows\System32\msiexec.exe',
                            'parent': r'C:\Program Files\Google\Chrome\Application\chrome.exe',
                            'user': 'sues',
                            'context': '',
                        }
                    ],
                },
                'extraction_summary': {},
            },
            case_id=42,
            username='tester',
        )

        iocs_to_import = processed['iocs_to_import']
        self.assertTrue(
            any(
                entry['ioc_type'] == 'File Name' and entry['value'] == 'msiexec.exe'
                for entry in iocs_to_import
            )
        )
        self.assertTrue(
            any(
                entry['ioc_type'] == 'Command Line' and entry['value'] == 'msiexec.exe'
                for entry in iocs_to_import
            )
        )


if __name__ == '__main__':
    unittest.main()
