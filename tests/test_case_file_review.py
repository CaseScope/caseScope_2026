import os
import sys
import types
import importlib.util
import unittest

os.environ.setdefault('SECRET_KEY', 'test-secret')


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
    def BigInteger(*_args, **_kwargs):
        return None

    @staticmethod
    def Boolean(*_args, **_kwargs):
        return None

    @staticmethod
    def DateTime(*_args, **_kwargs):
        return None

    @staticmethod
    def Text(*_args, **_kwargs):
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


database_module = types.ModuleType('models.database')
database_module.db = _FakeDB()
sys.modules['models.database'] = database_module

module_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models', 'case_file.py')
spec = importlib.util.spec_from_file_location('case_file_under_test', module_path)
case_file_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(case_file_module)
CaseFile = case_file_module.CaseFile


class CaseFileReviewStatusTestCase(unittest.TestCase):
    def test_expected_sidecar_is_retained_only(self):
        review = CaseFile.derive_review_status(
            filename='NTUSER.DAT.LOG1',
            status='done',
            ingestion_status='no_parser',
            is_archive=False,
            retention_state='retained',
        )

        self.assertEqual(review['code'], 'retained_only')
        self.assertEqual(review['label'], 'Retained Only')

    def test_non_sidecar_no_parser_is_unsupported(self):
        review = CaseFile.derive_review_status(
            filename='hosts',
            status='done',
            ingestion_status='no_parser',
            is_archive=False,
            retention_state='retained',
        )

        self.assertEqual(review['code'], 'unsupported')

    def test_archive_records_are_labeled_archived(self):
        review = CaseFile.derive_review_status(
            filename='ATN82406.zip',
            status='done',
            ingestion_status='no_parser',
            is_archive=True,
            retention_state='archived',
        )

        self.assertEqual(review['code'], 'archived')
        self.assertEqual(review['label'], 'Archived ZIP')

    def test_duplicate_records_are_labeled_duplicate_retained(self):
        review = CaseFile.derive_review_status(
            filename='History',
            status='duplicate',
            ingestion_status='not_done',
            is_archive=False,
            retention_state='duplicate_retained',
        )

        self.assertEqual(review['code'], 'duplicate_retained')


if __name__ == '__main__':
    unittest.main()
