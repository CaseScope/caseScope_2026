import unittest
from datetime import datetime
from types import SimpleNamespace

from utils.graph_query import EVIDENCE_EVENT_COLUMNS, GraphNotFoundError
from utils.investigation_context import InvestigationContextError, InvestigationContextService


def evidence_key(char):
    return "erk:v2:" + (char * 64)


def event_row(**overrides):
    base = {
        "timestamp": "2026-01-01 12:00:00",
        "timestamp_utc": "2026-01-01 12:00:00",
        "selector_key": "selector-1",
        "artifact_type": "evtx",
        "source_file": "Security.evtx",
        "source_path": "/evidence/Security.evtx",
        "source_host": "HOST-A",
        "event_id": "4688",
        "channel": "Security",
        "provider": "Microsoft-Windows-Security-Auditing",
        "record_id": 1,
        "level": "info",
        "username": "Administrator",
        "domain": "",
        "sid": "",
        "logon_type": 2,
        "logon_id": "",
        "process_name": "cmd.exe",
        "process_path": r"C:\Windows\System32\cmd.exe",
        "process_id": 1234,
        "parent_process": "",
        "parent_pid": 0,
        "command_line": "cmd.exe",
        "target_path": "",
        "file_hash_md5": "",
        "file_hash_sha1": "",
        "file_hash_sha256": "",
        "file_size": 0,
        "src_ip": "",
        "dst_ip": "",
        "src_port": 0,
        "dst_port": 0,
        "reg_key": "",
        "reg_value": "",
        "reg_data": "",
        "raw_json": "{}",
        "extra_fields": "{}",
        "search_blob": "",
        "parser_version": "test",
        "evidence_record_key": evidence_key("a"),
        "evidence_identity_version": "v2",
        "evidence_identity_quality": "exact",
    }
    base.update(overrides)
    return tuple(base[name] for name in EVIDENCE_EVENT_COLUMNS)


class QueueClickHouse:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def query(self, sql, parameters=None):
        self.calls.append((sql, parameters or {}))
        rows = self.responses.pop(0) if self.responses else []
        return SimpleNamespace(column_names=list(EVIDENCE_EVENT_COLUMNS), result_rows=rows)


class InvestigationContextServiceTestCase(unittest.TestCase):
    def test_exact_erk_anchor_dedupes_physical_rows_and_uses_inclusive_boundaries(self):
        anchor = event_row(evidence_record_key=evidence_key("a"))
        context = [
            event_row(evidence_record_key=evidence_key("a")),
            event_row(evidence_record_key=evidence_key("a"), selector_key="selector-duplicate"),
            event_row(evidence_record_key=evidence_key("b"), timestamp_utc="2026-01-01 12:00:30"),
        ]
        client = QueueClickHouse([[anchor, anchor], context])

        result = InvestigationContextService(client=client).context(1, anchor_erk=evidence_key("a"), window="30s")

        self.assertTrue(result["anchor"]["duplicates_detected"])
        self.assertEqual([row["evidence_record_key"] for row in result["records"]], [evidence_key("a"), evidence_key("b")])
        self.assertEqual(result["time_boundary"], "inclusive: anchor_time - window <= timestamp <= anchor_time + window")
        params = client.calls[1][1]
        self.assertEqual(params["time_start"], "2026-01-01 11:59:30.000")
        self.assertEqual(params["time_end"], "2026-01-01 12:00:30.000")

    def test_malformed_and_non_v2_erk_rejected(self):
        service = InvestigationContextService(client=QueueClickHouse([]))
        for key in ("bad", "erk:v1:" + ("a" * 64)):
            with self.assertRaises(InvestigationContextError):
                service.context(1, anchor_erk=key)

    def test_cross_case_erk_absence_is_not_found(self):
        with self.assertRaises(GraphNotFoundError):
            InvestigationContextService(client=QueueClickHouse([[]])).context(2, anchor_erk=evidence_key("a"))

    def test_pagination_hard_limit_and_cursor(self):
        anchor = event_row(evidence_record_key=evidence_key("a"))
        rows = [
            event_row(evidence_record_key=evidence_key("a")),
            event_row(evidence_record_key=evidence_key("b")),
            event_row(evidence_record_key=evidence_key("c")),
        ]
        first = InvestigationContextService(client=QueueClickHouse([[anchor], rows])).context(1, anchor_erk=evidence_key("a"), limit=2)
        self.assertTrue(first["truncated"])
        self.assertTrue(first["next_cursor"])
        second_client = QueueClickHouse([[anchor], [rows[-1]]])
        second = InvestigationContextService(client=second_client).context(1, anchor_erk=evidence_key("a"), limit=5000, cursor=first["next_cursor"])
        self.assertEqual(second["limit"], 500)
        self.assertIn("cursor_ts", second_client.calls[1][1])

    def test_same_user_bare_username_is_host_scoped_and_ambiguous(self):
        anchor = event_row(username="Administrator", domain="", sid="", source_host="HOST-A")
        result = InvestigationContextService(client=QueueClickHouse([[anchor], [anchor]])).context(
            1,
            anchor_erk=evidence_key("a"),
            mode="same_user",
        )
        self.assertEqual(result["identity_resolution"]["status"], "ambiguous")
        self.assertIn("host-scoped", result["identity_resolution"]["warning"])

    def test_logon_session_is_host_scoped(self):
        anchor = event_row(logon_id="0x3e7")
        client = QueueClickHouse([[anchor], [anchor]])
        result = InvestigationContextService(client=client).context(1, anchor_erk=evidence_key("a"), mode="logon_session")
        sql, params = client.calls[1]
        self.assertEqual(result["identity_resolution"]["basis"], "host-scoped logon_id")
        self.assertIn("source_host = {filter_0:String}", sql)
        self.assertEqual(params["filter_0"], "HOST-A")
        self.assertEqual(params["filter_1"], "0x3e7")

    def test_process_lifetime_bounds_before_pid_reuse(self):
        anchor = event_row(evidence_record_key=evidence_key("a"), process_id=1234, timestamp_utc="2026-01-01 12:00:00")
        next_start = [("2026-01-01 13:00:00",)]
        no_termination = []
        rows = [anchor]
        client = QueueClickHouse([[anchor], next_start, no_termination, rows])

        result = InvestigationContextService(client=client).context(1, anchor_erk=evidence_key("a"), mode="process_lifetime")

        self.assertEqual(result["identity_resolution"]["status"], "partial")
        self.assertEqual(client.calls[3][1]["time_end"], "2026-01-01 13:00:00.000")


if __name__ == "__main__":
    unittest.main()
