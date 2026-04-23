import importlib.util
import os
import unittest
from pathlib import Path


os.environ.setdefault("SECRET_KEY", "test-secret")

REPO_ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = REPO_ROOT / "utils" / "event_selector.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("event_selector_under_test", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class EventSelectorTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.event_selector = _load_module()

    def test_build_event_selector_sql_defaults_to_selector_key_column(self):
        qualified_sql = self.event_selector.build_event_selector_sql("e")
        unqualified_sql = self.event_selector.build_event_selector_sql("")
        forced_raw_sql = self.event_selector.build_event_selector_sql(
            "e",
            source=self.event_selector.SelectorKeySource.RAW_EXPRESSION,
        )
        self.assertEqual(qualified_sql, "e.selector_key")
        self.assertEqual(unqualified_sql, "selector_key")
        self.assertIn("multiIf(", forced_raw_sql)

    def test_raw_selector_expression_matches_python_builder_for_fixtures(self):
        try:
            from utils.clickhouse import get_client

            client = get_client()
            if client is None:
                self.skipTest("ClickHouse unavailable for selector parity test")
        except Exception as exc:
            self.skipTest(f"ClickHouse unavailable for selector parity test: {exc}")

        expression = self.event_selector._raw_selector_expression("t")
        fixtures = [
            {
                "event_id": "4624",
                "record_id": 99,
                "source_file": "Security.evtx",
                "source_host": "HOST1",
                "artifact_type": "",
                "timestamp": None,
            },
            {
                "event_id": "4104",
                "record_id": 0,
                "source_file": "Windows PowerShell.evtx",
                "source_host": "HOST2",
                "artifact_type": "Windows Event Logs",
                "timestamp": "2026-04-21 12:00:00",
            },
            {
                "event_id": "4624",
                "record_id": 0,
                "source_file": "",
                "source_host": "",
                "artifact_type": "",
                "timestamp": None,
            },
            {
                "event_id": "-",
                "record_id": 0,
                "source_file": "-",
                "source_host": "-",
                "artifact_type": "-",
                "timestamp": "2026-04-21 12:00:00",
            },
        ]

        for fixture in fixtures:
            expected = self.event_selector.build_event_selector_key(
                event_id=fixture["event_id"],
                record_id=fixture["record_id"],
                source_file=fixture["source_file"],
                source_host=fixture["source_host"],
                timestamp=fixture["timestamp"] or "",
                artifact_type=fixture["artifact_type"],
            )
            result = client.query(self._build_fixture_query(expression, fixture))
            actual = result.result_rows[0][0] if result.result_rows else None
            self.assertEqual(actual, expected)

    @staticmethod
    def _sql_string(value: str) -> str:
        escaped = str(value).replace("\\", "\\\\").replace("'", "\\'")
        return f"'{escaped}'"

    @classmethod
    def _build_fixture_query(cls, expression: str, fixture: dict) -> str:
        timestamp_sql = (
            f"toDateTime({cls._sql_string(fixture['timestamp'])})"
            if fixture["timestamp"]
            else "CAST(NULL, 'Nullable(DateTime)')"
        )
        return f"""
            SELECT {expression} AS selector_key
            FROM (
                SELECT
                    {cls._sql_string(fixture['event_id'])} AS event_id,
                    toUInt64({int(fixture['record_id'])}) AS record_id,
                    {cls._sql_string(fixture['source_file'])} AS source_file,
                    {cls._sql_string(fixture['source_host'])} AS source_host,
                    {cls._sql_string(fixture['artifact_type'])} AS artifact_type,
                    {timestamp_sql} AS timestamp,
                    CAST(NULL, 'Nullable(DateTime)') AS timestamp_utc
            ) AS t
        """


if __name__ == "__main__":
    unittest.main()
