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
    clickhouse_module.clickhouse_string_array_literal = lambda values: (
        "[" + ", ".join(f"'{value}'" for value in values) + "]"
    )
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
        module_path = os.path.join(REPO_ROOT, "utils", "event_noise_state.py")
        spec = importlib.util.spec_from_file_location("event_noise_state_under_test", module_path)
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


class EventNoiseStateTestCase(unittest.TestCase):
    def test_upsert_manual_noise_state_rows_prunes_by_artifact_type(self):
        commands = []

        class FakeClient:
            def command(self, sql):
                commands.append(sql)

        client = FakeClient()
        with _load_module_under_test() as event_noise_state:
            updated = event_noise_state.upsert_manual_noise_state_rows(
                7,
                [
                    {
                        "selector_key": "event_id:4624",
                        "artifact_type": "evtx",
                        "noise_matched": True,
                        "noise_rules": [],
                    }
                ],
                updated_by="tester",
                client=client,
            )

            self.assertEqual(updated, 1)
            self.assertEqual(len(commands), 1)
            self.assertIn("noise_matched = true", commands[0])
            self.assertIn("case_id = 7", commands[0])
            self.assertIn("artifact_type = 'evtx'", commands[0])
            self.assertIn("selector_key", commands[0])
            self.assertNotIn("mutations_sync", commands[0])

    def test_upsert_manual_noise_state_rows_groups_by_artifact_type(self):
        commands = []

        class FakeClient:
            def command(self, sql):
                commands.append(sql)

        client = FakeClient()
        with _load_module_under_test() as event_noise_state:
            updated = event_noise_state.upsert_manual_noise_state_rows(
                7,
                [
                    {
                        "selector_key": "event_id:4624",
                        "artifact_type": "evtx",
                        "noise_matched": True,
                        "noise_rules": [],
                    },
                    {
                        "selector_key": "ts:2026-04-21 12:00:00|host:HOST2|artifact:registry|event:|file:SOFTWARE",
                        "artifact_type": "registry",
                        "noise_matched": True,
                        "noise_rules": [],
                    },
                ],
                updated_by="tester",
                client=client,
            )

            self.assertEqual(updated, 2)
            self.assertEqual(len(commands), 2)
            self.assertTrue(any("artifact_type = 'evtx'" in command for command in commands))
            self.assertTrue(any("artifact_type = 'registry'" in command for command in commands))


if __name__ == "__main__":
    unittest.main()
