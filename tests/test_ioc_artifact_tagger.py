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
clickhouse_module.get_client = lambda: None
clickhouse_module.clickhouse_string_literal = lambda value: f"'{value}'"
clickhouse_module.run_events_update = lambda assignments_sql, where_sql, *, client=None, wait=True: client.command(
    f"ALTER TABLE events UPDATE {assignments_sql} WHERE {where_sql} SETTINGS mutations_sync = 1"
)
utils_package.clickhouse = clickhouse_module
sys.modules.setdefault('utils', utils_package)
sys.modules['utils.clickhouse'] = clickhouse_module

selector_path = os.path.join(REPO_ROOT, 'utils', 'event_selector.py')
selector_spec = importlib.util.spec_from_file_location('utils.event_selector', selector_path)
selector_module = importlib.util.module_from_spec(selector_spec)
selector_spec.loader.exec_module(selector_module)
utils_package.event_selector = selector_module
sys.modules['utils.event_selector'] = selector_module

ioc_state_path = os.path.join(REPO_ROOT, 'utils', 'event_ioc_state.py')
ioc_state_spec = importlib.util.spec_from_file_location('utils.event_ioc_state', ioc_state_path)
ioc_state_module = importlib.util.module_from_spec(ioc_state_spec)
ioc_state_spec.loader.exec_module(ioc_state_module)
utils_package.event_ioc_state = ioc_state_module
sys.modules['utils.event_ioc_state'] = ioc_state_module

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

    def test_mark_events_stores_canonical_ioc_identity(self):
        queries = []
        commands = []
        class FakeClient:
            def query(self, sql, parameters=None):
                queries.append(sql)
                return types.SimpleNamespace(result_rows=[(2,)])

            def command(self, sql, parameters=None):
                commands.append(sql)

        models_package = sys.modules.setdefault('models', types.ModuleType('models'))
        ioc_module = types.ModuleType('models.ioc')
        ioc_module.detect_match_type = lambda _value, _ioc_type: 'substring'
        sys.modules['models.ioc'] = ioc_module
        models_package.ioc = ioc_module

        original_get_fresh_client = ioc_tagger.get_fresh_client
        try:
            ioc_tagger.get_fresh_client = lambda: FakeClient()
            updated = ioc_tagger.mark_events_with_ioc_type(
                7,
                'evil.example',
                'Domain',
                match_type='substring',
                scan_version='scan-123',
            )
        finally:
            ioc_tagger.get_fresh_client = original_get_fresh_client

        self.assertEqual(updated, 2)
        self.assertIn("SELECT count() FROM events", queries[0])
        self.assertIn("ALTER TABLE events UPDATE", commands[-1])
        self.assertIn("arrayDistinct(arrayConcat(ioc_types, ['Domain']))", commands[-1])
        self.assertIn("case_id = 7", commands[-1])


if __name__ == '__main__':
    unittest.main()
