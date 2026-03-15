import importlib.util
import os
import sys
import types
import unittest


os.environ.setdefault('SECRET_KEY', 'test-secret')

REPO_ROOT = os.path.dirname(os.path.dirname(__file__))
utils_package = types.ModuleType('utils')
clickhouse_module = types.ModuleType('utils.clickhouse')
clickhouse_module.get_fresh_client = lambda: None
utils_package.clickhouse = clickhouse_module
sys.modules.setdefault('utils', utils_package)
sys.modules['utils.clickhouse'] = clickhouse_module

module_path = os.path.join(REPO_ROOT, 'utils', 'ioc_artifact_tagger.py')
spec = importlib.util.spec_from_file_location('ioc_artifact_tagger_under_test', module_path)
ioc_tagger = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ioc_tagger)


class IOCArtifactTaggerTestCase(unittest.TestCase):
    def test_command_line_matching_searches_raw_json_and_search_blob(self):
        clause = ioc_tagger.build_ioc_match_clause(
            'Get-AppxPackage *WindowsMaps* | Remove-AppxPackage',
            'Command Line',
            'substring',
        )

        self.assertIn('lower(raw_json)', clause)
        self.assertIn('lower(search_blob)', clause)
        self.assertIn('get-appxpackage', clause.lower())

    def test_file_path_matching_searches_raw_json_and_search_blob(self):
        clause = ioc_tagger.build_ioc_match_clause(
            r'C:\Windows\example.inf',
            'File Path',
            'substring',
        )

        self.assertIn('lower(raw_json)', clause)
        self.assertIn('lower(search_blob)', clause)
        self.assertIn('windows', clause.lower())
        self.assertIn('example.inf', clause.lower())


if __name__ == '__main__':
    unittest.main()
