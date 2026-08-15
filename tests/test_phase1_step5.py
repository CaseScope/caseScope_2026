"""Focused Phase 1 Step 5 tests for typed hot-field promotion.

Run with:

    /opt/casescope/venv/bin/python -m unittest tests.test_phase1_step5

Do not use production-bound full unittest discovery.
"""

from __future__ import annotations

import json
import os
import unittest
from datetime import datetime

os.environ.setdefault("SECRET_KEY", "phase1-step5-test-secret")

from migrations.add_event_key_length_column import add_key_length_column
from migrations.add_events_table import EVENTS_COLUMN_DEFINITIONS
from parsers.base import BaseParser, ParsedEvent
from parsers.evtx_parser import EvtxECmdParser
from utils.candidate_extractor import CandidateExtractor


class _QueryResult:
    def __init__(self, rows=None):
        self.result_rows = list(rows or [])


class _FakeMigrationClient:
    def __init__(self):
        self.columns = set()
        self.commands = []

    def query(self, sql, parameters=None):
        params = parameters or {}
        if "FROM system.columns" in sql:
            return _QueryResult([(1 if params.get("column_name") in self.columns else 0,)])
        return _QueryResult([])

    def command(self, sql):
        self.commands.append(sql)
        if "ADD COLUMN IF NOT EXISTS key_length" in sql:
            self.columns.add("key_length")


def _new_evtx_parser():
    parser = object.__new__(EvtxECmdParser)
    BaseParser.__init__(parser, case_id=1, source_host="HOST1", case_file_id=55, case_tz="UTC")
    return parser


def _evtx_event(key_length):
    event_data = {
        "Data": [
            {"@Name": "TargetUserName", "#text": "alice"},
            {"@Name": "TargetDomainName", "#text": "CORP"},
            {"@Name": "TargetUserSid", "#text": "S-1-5-21-1-2-3-1001"},
            {"@Name": "LogonType", "#text": "3"},
            {"@Name": "AuthenticationPackageName", "#text": "NTLM"},
            {"@Name": "KeyLength", "#text": str(key_length)},
        ]
    }
    return {
        "TimeCreated": "2026-03-14T12:00:00.123Z",
        "EventId": 4624,
        "Channel": "Security",
        "Computer": "HOST1",
        "EventRecordId": "77",
        "Provider": "Microsoft-Windows-Security-Auditing",
        "Payload": json.dumps({"EventData": event_data}),
    }


class KeyLengthSchemaTestCase(unittest.TestCase):
    def test_schema_and_insert_order_include_key_length_once(self):
        columns = ParsedEvent.clickhouse_columns()
        self.assertEqual(columns.count("key_length"), 1)
        self.assertIn("key_length", EVENTS_COLUMN_DEFINITIONS)
        self.assertEqual(EVENTS_COLUMN_DEFINITIONS["key_length"], "Nullable(UInt16)")
        self.assertEqual(columns.index("key_length"), columns.index("logon_process") + 1)

        event = ParsedEvent(
            case_id=1,
            artifact_type="evtx",
            timestamp=datetime(2026, 1, 1),
            source_file="Security.evtx",
            key_length=0,
        )
        row = event.to_clickhouse_row()
        self.assertEqual(row[columns.index("key_length")], 0)

    def test_uint16_guard_keeps_malformed_values_nullable(self):
        columns = ParsedEvent.clickhouse_columns()
        event = ParsedEvent(
            case_id=1,
            artifact_type="evtx",
            timestamp=datetime(2026, 1, 1),
            source_file="Security.evtx",
            key_length=70000,
        )
        self.assertIsNone(event.to_clickhouse_row()[columns.index("key_length")])


class EvtxKeyLengthNormalizationTestCase(unittest.TestCase):
    def test_evtx_transform_promotes_key_length_without_changing_legacy_payloads(self):
        parsed = _new_evtx_parser()._transform_evtxecmd_event(
            event=_evtx_event(0),
            file_path="/tmp/Security.evtx",
            source_file="Security.evtx",
            detections={},
        )
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.key_length, 0)
        self.assertIn("KeyLength:0", parsed.search_blob)
        self.assertEqual(json.loads(parsed.raw_json)["EventData"]["KeyLength"], "0")

        columns = ParsedEvent.clickhouse_columns()
        row = parsed.to_clickhouse_row()
        self.assertEqual(row[columns.index("key_length")], 0)
        serialized_extra = json.loads(row[columns.index("extra_fields")])
        self.assertNotIn("key_length", serialized_extra.get("field_provenance", {}))
        self.assertTrue(parsed.evidence_record_key.startswith("erk:v2:"))

    def test_evtx_transform_preserves_malformed_key_length_in_raw_json_only(self):
        parsed = _new_evtx_parser()._transform_evtxecmd_event(
            event=_evtx_event("not-a-number"),
            file_path="/tmp/Security.evtx",
            source_file="Security.evtx",
            detections={},
        )
        self.assertIsNotNone(parsed)
        self.assertIsNone(parsed.key_length)
        self.assertIn("KeyLength:not-a-number", parsed.search_blob)
        self.assertEqual(json.loads(parsed.raw_json)["EventData"]["KeyLength"], "not-a-number")

    def test_key_length_is_not_part_of_evidence_identity(self):
        base = ParsedEvent(
            case_id=1,
            artifact_type="evtx",
            timestamp=datetime(2026, 1, 1),
            timestamp_utc=datetime(2026, 1, 1),
            source_file="Security.evtx",
            source_host="HOST1",
            event_id="4624",
            key_length=None,
        )
        promoted = ParsedEvent(
            case_id=1,
            artifact_type="evtx",
            timestamp=datetime(2026, 1, 1),
            timestamp_utc=datetime(2026, 1, 1),
            source_file="Security.evtx",
            source_host="HOST1",
            event_id="4624",
            key_length=0,
        )
        base.to_clickhouse_row()
        promoted.to_clickhouse_row()
        self.assertEqual(base.evidence_record_key, promoted.evidence_record_key)


class CandidateExtractorFallbackTestCase(unittest.TestCase):
    def test_key_length_condition_uses_typed_column_with_historical_fallback(self):
        extractor = object.__new__(CandidateExtractor)
        clauses, params = extractor._build_condition_clauses({"4624": {"key_length": "0"}})
        sql = " ".join(clauses[0].split())
        self.assertIn("key_length = {key_length_typed_3:UInt16}", sql)
        self.assertIn("key_length IS NULL", sql)
        self.assertIn("JSONExtractString(raw_json, 'EventData', 'KeyLength')", sql)
        self.assertIn("if(", sql)
        self.assertEqual(params["key_length_legacy_2"], "0")
        self.assertEqual(params["key_length_typed_3"], 0)

    def test_malformed_key_length_condition_keeps_legacy_only(self):
        extractor = object.__new__(CandidateExtractor)
        clauses, params = extractor._build_condition_clauses({"4624": {"key_length": "bad"}})
        sql = " ".join(clauses[0].split())
        self.assertNotIn("key_length =", sql)
        self.assertIn("key_length IS NULL", sql)
        self.assertEqual(params["key_length_legacy_2"], "bad")


class KeyLengthMigrationTestCase(unittest.TestCase):
    def test_add_key_length_column_is_idempotent_and_does_not_backfill(self):
        client = _FakeMigrationClient()
        first = add_key_length_column(client)
        second = add_key_length_column(client)
        self.assertTrue(first["success"])
        self.assertTrue(first["changed"])
        self.assertFalse(first["backfill_performed"])
        self.assertFalse(second["changed"])
        self.assertEqual(len(client.commands), 2)
        self.assertTrue(all("ADD COLUMN IF NOT EXISTS key_length Nullable(UInt16)" in sql for sql in client.commands))


if __name__ == "__main__":
    unittest.main()
