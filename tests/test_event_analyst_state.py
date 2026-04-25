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
    clickhouse_module.clickhouse_bool_literal = lambda value: "true" if value else "false"
    clickhouse_module.clickhouse_nullable_string_literal = lambda value: "NULL" if value is None else f"'{value}'"
    clickhouse_module.clickhouse_string_array_literal = lambda values: "[" + ", ".join(f"'{value}'" for value in values) + "]"
    clickhouse_module.clickhouse_string_literal = lambda value: f"'{value}'"
    clickhouse_module.run_events_update = lambda assignments_sql, where_sql, *, client=None, wait=True: client.command(
        f"ALTER TABLE events UPDATE {assignments_sql} WHERE {where_sql}"
        f"{' SETTINGS mutations_sync = 1' if wait else ''}"
    )
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

    def test_upsert_event_analyst_state_rows_updates_events_table(self):
        commands = []

        class FakeClient:
            def command(self, sql):
                commands.append(sql)

        client = FakeClient()
        with _load_module_under_test() as event_analyst_state:
            updated = event_analyst_state.upsert_event_analyst_state_rows(
                7,
                [
                    {
                        "selector_key": "event_id:4624",
                        "artifact_type": "evtx",
                        "analyst_tagged": True,
                        "analyst_tags": ["credential-access", " credential-access ", ""],
                        "analyst_notes": "Important event",
                    }
                ],
                updated_by="tester",
                client=client,
            )

            self.assertEqual(updated, 1)
            self.assertEqual(len(commands), 1)
            self.assertIn("ALTER TABLE events UPDATE", commands[0])
            self.assertIn("analyst_tagged = true", commands[0])
            self.assertIn("analyst_tags = ['credential-access', 'credential-access']", commands[0])
            self.assertIn("analyst_notes = 'Important event'", commands[0])
            self.assertIn("case_id = 7", commands[0])
            self.assertIn("artifact_type = 'evtx'", commands[0])
            self.assertIn("selector_key", commands[0])
            self.assertNotIn("mutations_sync", commands[0])

    def test_upsert_event_analyst_state_rows_groups_by_artifact_type(self):
        commands = []

        class FakeClient:
            def command(self, sql):
                commands.append(sql)

        client = FakeClient()
        with _load_module_under_test() as event_analyst_state:
            updated = event_analyst_state.upsert_event_analyst_state_rows(
                7,
                [
                    {
                        "selector_key": "event_id:4624",
                        "artifact_type": "evtx",
                        "analyst_tagged": True,
                    },
                    {
                        "selector_key": "ts:2026-04-21 12:00:00|host:HOST2|artifact:registry|event:|file:SOFTWARE",
                        "artifact_type": "registry",
                        "analyst_tagged": True,
                    },
                ],
                updated_by="tester",
                client=client,
            )

            self.assertEqual(updated, 2)
            self.assertEqual(len(commands), 2)
            self.assertTrue(any("artifact_type = 'evtx'" in command for command in commands))
            self.assertTrue(any("artifact_type = 'registry'" in command for command in commands))

    def test_build_analyst_projection_reads_direct_events_columns(self):
        with _load_module_under_test() as event_analyst_state:
            projection = event_analyst_state.build_analyst_projection("e")
            self.assertEqual(projection["join_sql"], "")
            self.assertEqual(projection["tagged_sql"], "e.analyst_tagged")
            self.assertEqual(projection["tags_sql"], "e.analyst_tags")
            self.assertEqual(projection["notes_sql"], "e.analyst_notes")


if __name__ == "__main__":
    unittest.main()
