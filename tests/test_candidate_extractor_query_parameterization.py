import importlib.util
import sys
import types
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_module(name: str, relative_path: str):
    module_path = REPO_ROOT / relative_path
    spec = importlib.util.spec_from_file_location(name, module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


utils_pkg = sys.modules.setdefault("utils", types.ModuleType("utils"))
utils_pkg.__path__ = [str(REPO_ROOT / "utils")]

clickhouse_stub = types.ModuleType("utils.clickhouse")
clickhouse_stub.clickhouse_bool_literal = lambda value: "true" if value else "false"
clickhouse_stub.clickhouse_nullable_string_literal = lambda value: "NULL" if value is None else repr(value)
clickhouse_stub.clickhouse_string_array_literal = lambda values: "[" + ",".join(repr(v) for v in values) + "]"
clickhouse_stub.clickhouse_string_literal = lambda value: repr(value)
clickhouse_stub.get_client = lambda: None
clickhouse_stub.get_fresh_client = lambda: None
clickhouse_stub.run_events_update = lambda *args, **kwargs: None
sys.modules["utils.clickhouse"] = clickhouse_stub
utils_pkg.clickhouse = clickhouse_stub

models_pkg = sys.modules.setdefault("models", types.ModuleType("models"))
database_stub = types.ModuleType("models.database")
database_stub.db = object()
sys.modules["models.database"] = database_stub
models_pkg.database = database_stub

candidate_extractor = _load_module(
    "candidate_extractor_query_parameterization_module",
    Path("utils") / "candidate_extractor.py",
)


class _FakeClient:
    def __init__(self, rows=None):
        self.last_query = None
        self.last_parameters = None
        self.rows = rows or []

    def query(self, query, parameters=None):
        self.last_query = query
        self.last_parameters = parameters or {}
        return types.SimpleNamespace(result_rows=self.rows)


class CandidateExtractorQueryParameterizationTestCase(unittest.TestCase):
    def test_extract_events_uses_parameters_for_event_ids_time_and_like_fragments(self):
        fake_client = _FakeClient()
        extractor = object.__new__(candidate_extractor.CandidateExtractor)
        extractor.case_id = 7
        extractor.analysis_id = "analysis-1"
        extractor.client = fake_client
        extractor.exclude_noise = True
        extractor._stats = {"queries_run": 0, "events_extracted": 0, "events_stored": 0}

        extractor._extract_events(
            event_ids=["4624"],
            conditions={
                "4624": {
                    "auth_package": ["NTLM%' OR 1=1 --"],
                    "command_line_contains_any": ["whoami_%"],
                    "target_image": ["lsass.exe"],
                }
            },
            role="anchor",
            time_filter=(
                ["COALESCE(timestamp_utc, timestamp) >= parseDateTimeBestEffort({time_start:String})"],
                {"time_start": "2026-04-20 10:00:00"},
            ),
            limit=25,
        )

        self.assertIn("case_id = {case_id:UInt32}", fake_client.last_query)
        self.assertIn("event_id IN {event_ids:Array(String)}", fake_client.last_query)
        self.assertIn("NOT (noise_matched = true)", fake_client.last_query)
        self.assertIn("LIMIT {limit:UInt32}", fake_client.last_query)
        self.assertNotIn("case_id = 7", fake_client.last_query)
        self.assertNotIn("OR 1=1", fake_client.last_query)
        self.assertNotIn("whoami_%", fake_client.last_query)
        self.assertNotIn("lsass.exe", fake_client.last_query)
        self.assertEqual(fake_client.last_parameters["case_id"], 7)
        self.assertEqual(fake_client.last_parameters["event_ids"], ["4624"])
        self.assertEqual(fake_client.last_parameters["limit"], 25)
        self.assertEqual(fake_client.last_parameters["time_start"], "2026-04-20 10:00:00")
        self.assertTrue(
            any(value == "%NTLM\\%' OR 1=1 --%" for value in fake_client.last_parameters.values())
        )
        self.assertTrue(
            any(value == "%whoami\\_\\%%" for value in fake_client.last_parameters.values())
        )
        self.assertTrue(
            any(value == "%lsass.exe" for value in fake_client.last_parameters.values())
        )

    def test_extract_events_can_include_noise_for_detection_scoring(self):
        fake_client = _FakeClient()
        extractor = object.__new__(candidate_extractor.CandidateExtractor)
        extractor.case_id = 7
        extractor.analysis_id = "analysis-1"
        extractor.client = fake_client
        extractor.exclude_noise = False
        extractor._stats = {"queries_run": 0, "events_extracted": 0, "events_stored": 0}

        extractor._extract_events(
            event_ids=["4624"],
            conditions={},
            role="anchor",
            limit=25,
        )

        self.assertIn("case_id = {case_id:UInt32}", fake_client.last_query)
        self.assertIn("event_id IN {event_ids:Array(String)}", fake_client.last_query)
        self.assertNotIn("NOT (noise_matched = true)", fake_client.last_query)
        self.assertIn("noise_matched", fake_client.last_query)
        self.assertIn("noise_rules", fake_client.last_query)

    def test_noise_tagged_anchor_is_returned_when_detection_includes_noise(self):
        fake_client = _FakeClient(rows=[(
            "event-uuid",
            "2026-06-04 20:00:00",
            "4624",
            "HOST-A",
            "alice",
            "Security",
            "3",
            "proc.exe",
            "cmd.exe",
            "10.0.0.1",
            "HOST-B",
            "",
            "0",
            "NtLmSsp",
            "NTLM",
            "alice",
            "alice",
            "summary",
            "source.exe",
            "target.exe",
            "parent.exe",
            "Microsoft-Windows-Security-Auditing",
            True,
            ["Expected VPN logon"],
        )])
        extractor = object.__new__(candidate_extractor.CandidateExtractor)
        extractor.case_id = 7
        extractor.analysis_id = "analysis-1"
        extractor.client = fake_client
        extractor.exclude_noise = False
        extractor._stats = {"queries_run": 0, "events_extracted": 0, "events_stored": 0}

        events = extractor._extract_events(
            event_ids=["4624"],
            conditions={},
            role="anchor",
            limit=25,
        )

        self.assertEqual(len(events), 1)
        self.assertTrue(events[0]["noise_matched"])
        self.assertEqual(events[0]["noise_rules"], ["Expected VPN logon"])
        self.assertNotIn("NOT (noise_matched = true)", fake_client.last_query)

    def test_build_condition_clauses_parameterizes_channel_and_provider(self):
        extractor = object.__new__(candidate_extractor.CandidateExtractor)

        clauses, params = extractor._build_condition_clauses({
            "104": {
                "channel": "System",
                "provider": "Microsoft-Windows-Eventlog",
            }
        })

        query_fragment = " ".join(clauses)
        self.assertIn("channel = {generic_value_", query_fragment)
        self.assertIn("provider = {generic_value_", query_fragment)
        self.assertNotIn("Microsoft-Windows-Eventlog", query_fragment)
        self.assertIn("System", params.values())
        self.assertIn("Microsoft-Windows-Eventlog", params.values())


if __name__ == "__main__":
    unittest.main()
