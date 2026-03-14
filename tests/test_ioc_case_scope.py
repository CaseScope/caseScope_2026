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
        sys.modules['models.ioc'] = fake_ioc_module

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


if __name__ == '__main__':
    unittest.main()
