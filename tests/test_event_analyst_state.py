import importlib.util
import os
import sys
import types
import unittest
from contextlib import contextmanager


os.environ.setdefault("SECRET_KEY", "test-secret")

REPO_ROOT = os.path.dirname(os.path.dirname(__file__))

@contextmanager
def _load_module_under_test():
    original_utils = sys.modules.get("utils")
    original_clickhouse = sys.modules.get("utils.clickhouse")
    original_event_selector = sys.modules.get("utils.event_selector")

    utils_package = types.ModuleType("utils")
    clickhouse_module = types.ModuleType("utils.clickhouse")
    clickhouse_module.get_client = lambda: None
    utils_package.clickhouse = clickhouse_module
    sys.modules["utils"] = utils_package
    sys.modules["utils.clickhouse"] = clickhouse_module

    selector_path = os.path.join(REPO_ROOT, "utils", "event_selector.py")
    selector_spec = importlib.util.spec_from_file_location("utils.event_selector", selector_path)
    selector_module = importlib.util.module_from_spec(selector_spec)
    selector_spec.loader.exec_module(selector_module)
    utils_package.event_selector = selector_module
    sys.modules["utils.event_selector"] = selector_module

    try:
        module_path = os.path.join(REPO_ROOT, "utils", "event_analyst_state.py")
        spec = importlib.util.spec_from_file_location("event_analyst_state_under_test", module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        yield module
    finally:
        if original_utils is None:
            sys.modules.pop("utils", None)
        else:
            sys.modules["utils"] = original_utils
        if original_clickhouse is None:
            sys.modules.pop("utils.clickhouse", None)
        else:
            sys.modules["utils.clickhouse"] = original_clickhouse
        if original_event_selector is None:
            sys.modules.pop("utils.event_selector", None)
        else:
            sys.modules["utils.event_selector"] = original_event_selector


class EventAnalystStateTestCase(unittest.TestCase):
    def test_build_event_selector_key_prefers_record_then_timestamp_then_event_id(self):
        with _load_module_under_test() as event_analyst_state:
            self.assertEqual(
                event_analyst_state.build_event_selector_key(
                    event_id="4624",
                    record_id=99,
                    source_file="Security.evtx",
                    source_host="HOST1",
                ),
                "record:99|file:Security.evtx|host:HOST1",
            )
            self.assertEqual(
                event_analyst_state.build_event_selector_key(
                    event_id="4104",
                    timestamp="2026-04-21 12:00:00",
                    source_host="HOST2",
                    artifact_type="Windows Event Logs",
                    source_file="Windows PowerShell.evtx",
                ),
                "ts:2026-04-21 12:00:00|host:HOST2|artifact:Windows Event Logs|event:4104|file:Windows PowerShell.evtx",
            )
            self.assertEqual(
                event_analyst_state.build_event_selector_key(event_id="4624"),
                "event_id:4624",
            )
            self.assertEqual(
                event_analyst_state.build_event_selector_key(
                    event_id="-",
                    timestamp="2026-04-21 12:00:00",
                    source_host="-",
                    artifact_type="-",
                    source_file="-",
                ),
                "ts:2026-04-21 12:00:00|host:|artifact:|event:|file:",
            )

    def test_upsert_event_analyst_state_rows_creates_table_and_inserts_rows(self):
        commands = []
        inserts = []

        class FakeClient:
            def command(self, sql):
                commands.append(sql)

            def insert(self, table, rows, column_names=None):
                inserts.append((table, rows, column_names))

        client = FakeClient()
        with _load_module_under_test() as event_analyst_state:
            updated = event_analyst_state.upsert_event_analyst_state_rows(
                7,
                [
                    {
                        "selector_key": "event_id:4624",
                        "analyst_tagged": True,
                        "analyst_tags": ["credential-access", " credential-access ", ""],
                        "analyst_notes": "Important event",
                    }
                ],
                updated_by="tester",
                client=client,
            )

            self.assertEqual(updated, 1)
            self.assertTrue(any("CREATE TABLE IF NOT EXISTS event_analyst_state" in sql for sql in commands))
            self.assertEqual(inserts[0][0], "event_analyst_state")
            self.assertEqual(inserts[0][1][0][0], 7)
            self.assertEqual(inserts[0][1][0][1], "event_id:4624")
            self.assertEqual(inserts[0][1][0][3], ["credential-access", "credential-access"])
            self.assertEqual(inserts[0][1][0][4], "Important event")

    def test_build_event_selector_sql_uses_record_priority_and_minute_token(self):
        with _load_module_under_test() as event_analyst_state:
            sql = event_analyst_state.build_event_selector_sql("e")
            self.assertIn("record:", sql)
            self.assertIn("%Y-%m-%d %H:%i:%S", sql)
            self.assertLess(sql.index("record:"), sql.index("event_id:"))
            self.assertIn(",\n            ''\n        )", sql)


if __name__ == "__main__":
    unittest.main()
