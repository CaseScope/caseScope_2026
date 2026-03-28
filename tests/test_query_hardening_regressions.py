import os
import unittest
from unittest.mock import patch

os.environ.setdefault('SECRET_KEY', 'test-secret')

import routes.api as api_routes
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
            ('2026-01-01 00:00:00', '4624', 'host-a', 'alice', 'Security', 'Rule', 'high', 'cmd.exe', 'cmd /c whoami', '1.2.3.4', '5.6.7.8', 3)
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
        condition = api_routes._build_sigma_alert_condition("high,critical,drop-table")

        self.assertIn("lower(rule_level) IN", condition)
        self.assertNotIn('DROP TABLE', condition)
        self.assertNotIn('drop-table', condition)
        self.assertIn("'critical'", condition)
        self.assertIn("'high'", condition)

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
