import importlib.util
import os
import unittest


REPO_ROOT = os.path.dirname(os.path.dirname(__file__))


class MitreAttackSyncTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        module_path = os.path.join(REPO_ROOT, 'utils', 'mitre_attack_sync.py')
        spec = importlib.util.spec_from_file_location('mitre_attack_sync_under_test', module_path)
        cls.module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(cls.module)

    def test_credential_dump_query_builds_valid_event_id_list(self):
        syncer = self.module.MitreAttackSync()

        query = syncer._generate_credential_dump_query('T1003', [], [])

        self.assertIn("event_id IN ('4656', '4663', '10')", query)
        self.assertNotIn('("', query)


if __name__ == '__main__':
    unittest.main()
