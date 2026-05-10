import os
import unittest
from datetime import datetime
from unittest.mock import patch

os.environ.setdefault('SECRET_KEY', 'test-secret')

import routes.hunting_query_helpers as hunting_query_helpers
import tasks.rag_tasks as rag_tasks
import utils.chat_tools as chat_tools
import utils.ioc_artifact_tagger as ioc_artifact_tagger


class _FakeResult:
    def __init__(self, rows):
        self.result_rows = rows


class _FakeClient:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def query(self, query, parameters=None):
        self.calls.append((query, parameters))
        return _FakeResult(self.rows)


class QueryHardeningRegressionTestCase(unittest.TestCase):
    def test_query_events_uses_bound_parameters(self):
        client = _FakeClient([
            (
                '2026-01-01 00:00:00',
                '4624',
                'host-a',
                'alice',
                'Security',
                'Rule',
                'high',
                'cmd.exe',
                'cmd /c whoami',
                '1.2.3.4',
                '5.6.7.8',
                3,
                'remote-a',
                'workstation-a',
                'NTLM',
                'NtLmSsp',
                'summary',
            )
        ])
        malicious_host = "srv' OR 1=1 --"

        with patch.object(chat_tools, 'get_fresh_client', return_value=client):
            result = chat_tools.query_events(
                case_id=7,
                host=malicious_host,
                search_text="powershell % _",
                severity='high',
            )

        self.assertEqual(result['event_count'], 1)
        query, params = client.calls[0]
        self.assertIn('{host:String}', query)
        self.assertIn('{search_text:String}', query)
        self.assertNotIn(malicious_host, query)
        self.assertEqual(params['host'], malicious_host)
        self.assertEqual(params['search_text'], "powershell % _")

    def test_sigma_severity_filter_only_uses_allowlisted_levels(self):
        condition = hunting_query_helpers._build_sigma_alert_condition("high,critical,drop-table")

        self.assertIn("lower(rule_level) IN", condition)
        self.assertNotIn('DROP TABLE', condition)
        self.assertNotIn('drop-table', condition)
        self.assertIn("'critical'", condition)
        self.assertIn("'high'", condition)

    def test_hunting_type_filter_uses_placeholders(self):
        params = {}
        malicious_types = "evtx,foo') OR 1=1 --"

        condition = hunting_query_helpers.build_hunting_type_filter(malicious_types, params)

        self.assertIn("artifact_type IN", condition)
        self.assertNotIn("OR 1=1", condition)
        self.assertEqual(params["artifact_type_0"], "evtx")
        self.assertEqual(params["artifact_type_1"], "foo') OR 1=1 --")

    def test_hunting_type_filter_keeps_etl_trace_legacy_alias(self):
        params = {}

        condition = hunting_query_helpers.build_hunting_type_filter("etl_trace", params)

        self.assertIn("artifact_type IN", condition)
        self.assertEqual(params["artifact_type_0"], "etl_trace")
        self.assertEqual(params["artifact_type_1"], "windows_etl")
        self.assertEqual(params["artifact_type_2"], "windows_etl_event")

    def test_windows_etl_description_is_not_source_path(self):
        description = hunting_query_helpers.build_event_description(
            "windows_etl",
            "",
            "windows_etl",
            "",
            "",
            "",
            "/opt/casescope/staging/case/ExplorerStartupLog.etl",
            "ExplorerStartupLog.etl /opt/casescope/staging/case/ExplorerStartupLog.etl",
        )

        self.assertIn("Windows ETL trace file metadata preserved", description)
        self.assertNotEqual(description, "/opt/casescope/staging/case/ExplorerStartupLog.etl")

    def test_windows_etl_event_description_uses_provider(self):
        description = hunting_query_helpers.build_event_description(
            "windows_etl_event",
            "",
            "Microsoft-Windows-TestProvider",
            "",
            "",
            "",
            "/opt/casescope/staging/case/ExplorerStartupLog.etl",
            "windows_etl_event Microsoft-Windows-TestProvider",
        )

        self.assertEqual(description, "ETL event from provider Microsoft-Windows-TestProvider")

    def test_hunting_alert_filter_rejects_unknown_mode(self):
        with self.assertRaises(ValueError):
            hunting_query_helpers._build_hunting_alert_type_filter(
                "maybe",
                "",
                "",
                "",
                "",
            )

    def test_hunting_time_filter_rejects_inverted_custom_range(self):
        params = {}

        with self.assertRaises(ValueError):
            hunting_query_helpers.build_hunting_time_filter(
                client=_FakeClient([(datetime(2026, 1, 5, 0, 0, 0),)]),
                case_id=7,
                case_tz="UTC",
                time_range="custom",
                time_start="2026-01-05T10:00",
                time_end="2026-01-05T09:00",
                params=params,
            )

    def test_hunting_search_clause_handles_mixed_group_or(self):
        params = {}

        clause = hunting_query_helpers.build_hunting_search_clause("(eventid:4625)|host:dc1", params)

        self.assertIn(" OR ", clause)
        self.assertIn("4625", params.values())
        self.assertIn("%dc1%", params.values())

    def test_time_filter_clause_rejects_unsupported_sql(self):
        valid = "COALESCE(timestamp_utc, timestamp) >= '2026-01-01 00:00:00'"
        self.assertEqual(rag_tasks._build_time_filter_clause(valid), f" AND {valid}")

        with self.assertRaises(ValueError):
            rag_tasks._build_time_filter_clause("1=1; DROP TABLE events")

    def test_unsafe_regex_falls_back_to_substring_match(self):
        clause = ioc_artifact_tagger.build_regex_match_clause('(?=evil)')

        self.assertIn('LIKE', clause)
        self.assertNotIn("match(lower(", clause)


if __name__ == '__main__':
    unittest.main()
