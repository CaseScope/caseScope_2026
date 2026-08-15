import logging
import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from parsers.registry import BatchProcessor
from utils.ingest_metrics import (
    diagnostic_counts_enabled,
    emit_metric,
    estimate_rows_bytes,
    sanitize_fields,
    timed_stage,
)


class IngestMetricsTestCase(unittest.TestCase):
    def test_sanitize_fields_omits_sensitive_evidence_values(self):
        sanitized = sanitize_fields({
            "case_id": 12,
            "raw_json": '{"secret": true}',
            "search_blob": "sensitive command",
            "duration_ms": 1.23456,
        })

        self.assertEqual(sanitized, {"case_id": 12, "duration_ms": 1.235})

    def test_estimate_rows_bytes_counts_strings_without_retaining_values(self):
        self.assertEqual(estimate_rows_bytes([(1, "abcd", None), ("xy",)]), 14)

    def test_diagnostic_counts_env_gate(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(diagnostic_counts_enabled())

        with patch.dict(os.environ, {"DATABASE_FLOW_DIAGNOSTIC_COUNTS": "true"}, clear=True):
            self.assertTrue(diagnostic_counts_enabled())

    def test_timed_stage_emits_sanitized_metric(self):
        logger = logging.getLogger("casescope.database_flow.ingest")
        with self.assertLogs(logger, level="INFO") as captured:
            with timed_stage("unit_stage", case_id=4, raw_json="secret") as metric:
                metric["events_inserted"] = 2

        output = "\n".join(captured.output)
        self.assertIn("database_flow_phase0a_metric", output)
        self.assertIn("unit_stage", output)
        self.assertIn("events_inserted", output)
        self.assertNotIn("secret", output)

    def test_emit_metric_sanitizes_direct_calls(self):
        logger = logging.getLogger("casescope.database_flow.ingest")
        with self.assertLogs(logger, level="INFO") as captured:
            emit_metric("direct", file_path="/sensitive/path.evtx", case_id=7)

        output = "\n".join(captured.output)
        self.assertIn("direct", output)
        self.assertIn("case_id", output)
        self.assertNotIn("/sensitive/path.evtx", output)

    def test_alias_candidate_counts_support_alias_candidate_shape(self):
        candidates = {
            ("HOSTNAME", "host-a"): SimpleNamespace(seen_count=3),
            ("USERNAME", "user-a"): SimpleNamespace(seen_count=2),
        }

        self.assertEqual(BatchProcessor._alias_candidate_counts(candidates), (5, 2))


if __name__ == "__main__":
    unittest.main()
