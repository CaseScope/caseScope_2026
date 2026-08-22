"""Focused Phase 1 Step 1 tests. Run with:

    /opt/casescope/venv/bin/python -m unittest tests.test_phase1_step1

Do not use production-bound full unittest discovery.
"""
from __future__ import annotations

import inspect
import json
import os
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault("SECRET_KEY", "phase1-step1-test-secret")

from migrations.reset_events_wide_part_settings import (
    RESET_SETTING_SQL,
    events_has_forced_wide_settings,
    reset_events_forced_wide_part_settings,
)
from parsers.base import BaseParser, ParsedEvent
from parsers.evtx_parser import EvtxECmdParser, _evtx_json_loads
from parsers.registry import BatchProcessor
from utils.clickhouse import delete_file_events
from utils.ingest_fence import install_memory_backend, reset_fence_backend
from utils.privacy_aliases import (
    PRIVACY_ENTITY_TYPES_BY_LEVEL,
    PRIVACY_LEVEL_CMMC_CUI,
    SCANNED_TEXT_FIELDS,
    _alias_scope_filter_sql,
    _merge_candidate_maps,
    _scan_distinct_field,
    _validate_generation_scope,
    canonical_alias_identity_set,
    extract_alias_candidates_from_event_rows,
)


def setUpModule():
    install_memory_backend()


def tearDownModule():
    reset_fence_backend()


class _QueryResult:
    def __init__(self, rows=None):
        self.result_rows = list(rows or [])


class _FakeClickHouse:
    def __init__(self, *, events_rows=None, buffer_rows=None, fail_probe=None, engine_full=""):
        self.commands = []
        self.queries = []
        self.events_rows = list(events_rows or [])
        self.buffer_rows = buffer_rows
        self.fail_probe = fail_probe
        self.engine_full = engine_full
        self.fail_buffer_mutation = False

    def query(self, sql, parameters=None):
        self.queries.append((sql, parameters or {}))
        if self.fail_probe:
            raise RuntimeError(self.fail_probe)
        text = " ".join(sql.split())
        if "SELECT currentDatabase()" in text:
            return _QueryResult([("phase1_step1_test",)])
        if "SELECT engine_full" in text:
            return _QueryResult([(self.engine_full,)])
        if "FROM system.tables" in text and "events_buffer" in text:
            return _QueryResult([(1,)])
        if "FROM system.tables" in text:
            return _QueryResult([(1,)])
        if "FROM events_buffer" in text and "LIMIT 1" in text:
            if self.buffer_rows is None:
                return _QueryResult([])
            return _QueryResult(self.buffer_rows)
        if "FROM events" in text and "LIMIT 1" in text:
            return _QueryResult(self.events_rows)
        if "GROUP BY value" in text:
            return _QueryResult([])
        return _QueryResult([])

    def command(self, sql):
        if self.fail_buffer_mutation and "events_buffer" in sql:
            raise RuntimeError("Table engine Buffer doesn't support mutations")
        self.commands.append(sql)


def _sample_rows():
    ts = datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    return [
        {
            "timestamp_utc": ts,
            "username": "jsmith",
            "domain": "CORP",
            "source_host": "FIN-WKS0142",
            "remote_host": "",
            "workstation_name": "FIN-WKS0142",
            "src_ip": "10.0.0.8",
            "dst_ip": None,
            "command_line": r"C:\Users\jsmith\app.exe",
            "process_path": r"C:\Users\jsmith\app.exe",
            "parent_process": "",
            "target_path": "",
            "source_path": r"C:\Windows\System32\winevt\Logs\Security.evtx",
            "reg_data": "",
            "payload_data1": "jsmith",
            "payload_data2": "",
            "payload_data3": "",
            "payload_data4": "",
            "payload_data5": "",
            "payload_data6": "",
            "raw_json": '{"TargetUserName":"secret-should-not-scan","IpAddress":"8.8.8.8"}',
        },
        {
            "timestamp_utc": ts,
            "username": "jsmith",
            "domain": "CORP",
            "source_host": "FIN-WKS0142",
            "remote_host": "dc01.corp.local",
            "workstation_name": "",
            "src_ip": "10.0.0.8",
            "dst_ip": "10.0.0.1",
            "command_line": r"C:\Users\jsmith\app.exe",
            "process_path": r"C:\Users\jsmith\app.exe",
            "parent_process": "",
            "target_path": "",
            "source_path": r"C:\Windows\System32\winevt\Logs\Security.evtx",
            "reg_data": "",
            "payload_data1": "jsmith",
            "payload_data2": "",
            "payload_data3": "",
            "payload_data4": "",
            "payload_data5": "",
            "payload_data6": "",
            "raw_json": '{"TargetUserName":"secret-should-not-scan"}',
        },
    ]


def _distinct_scan_from_rows(rows, *, allowed_types):
    """Apply the same per-column DISTINCT extractors used by the CH scanner."""
    from utils.privacy_aliases import (
        _add_domain,
        _add_host,
        _add_username,
        _candidate_is_vaultable,
        _extract_text_entities,
        _ip_type,
        _normalize,
        _clean,
        AliasCandidate,
        AliasKey,
    )

    candidates = {}
    field_extractors = {
        "username": _add_username,
        "domain": _add_domain,
        "source_host": _add_host,
        "remote_host": _add_host,
        "workstation_name": _add_host,
    }
    for field_name, extractor in field_extractors.items():
        values = {}
        for row in rows:
            value = row.get(field_name)
            if value in (None, ""):
                continue
            values.setdefault(value, 0)
            values[value] += 1
        for value, seen_count in values.items():
            temp = {}
            extractor(temp, value, field_name, None)
            for key, candidate in temp.items():
                if not _candidate_is_vaultable(candidate, allowed_types):
                    continue
                candidate.seen_count = seen_count
                _merge_candidate_maps(candidates, {key: candidate})
    for field_name in SCANNED_TEXT_FIELDS:
        values = {}
        for row in rows:
            value = row.get(field_name)
            if value in (None, ""):
                continue
            values.setdefault(value, 0)
            values[value] += 1
        for value, seen_count in values.items():
            temp = {}
            _extract_text_entities(temp, value, field_name, None, None)
            for key, candidate in list(temp.items()):
                if not _candidate_is_vaultable(candidate, allowed_types):
                    temp.pop(key, None)
                    continue
                candidate.seen_count = seen_count
            _merge_candidate_maps(candidates, temp)
    for field_name in ("src_ip", "dst_ip"):
        values = {}
        for row in rows:
            value = row.get(field_name)
            if value in (None, ""):
                continue
            values.setdefault(value, 0)
            values[value] += 1
        for value, seen_count in values.items():
            entity_type = _ip_type(value, client_public_ips=None)
            if entity_type and entity_type in allowed_types:
                key = AliasKey(entity_type, _normalize(entity_type, value))
                candidate = AliasCandidate(
                    entity_type=entity_type,
                    original_value=_clean(value),
                    normalized_value=key.normalized_value,
                    seen_count=seen_count,
                )
                candidate.source_fields.add(field_name)
                _merge_candidate_maps(candidates, {key: candidate})
    return candidates


class AliasHotPathTests(unittest.TestCase):
    def test_add_event_does_not_extract_aliases(self):
        source = inspect.getsource(BatchProcessor.add_event)
        self.assertNotIn("extract_alias_candidates_from_event_rows", source)
        self.assertNotIn("_extract_text_entities", source)

        client = SimpleNamespace(inserts=[])

        def insert(table, batch, column_names=None, settings=None, **kwargs):
            client.inserts.append((table, list(batch), column_names))

        client.insert = insert
        processor = BatchProcessor(client, batch_size=10, use_buffer=False)
        with patch(
            "utils.privacy_aliases.extract_alias_candidates_from_event_rows",
            side_effect=AssertionError("per-event alias extraction must not run"),
        ):
            processor.add_event(SimpleNamespace(to_clickhouse_row=lambda: ("row",)))
        self.assertEqual(processor._batch, [("row",)])

    def test_scope_sql_is_independent_per_field_and_file_scoped(self):
        sql, params = _alias_scope_filter_sql(case_file_id=99, generation=None)
        self.assertIn("case_file_id = {case_file_id:UInt32}", sql)
        self.assertEqual(params, {"case_file_id": 99})
        fake = _FakeClickHouse()
        _scan_distinct_field(
            client=fake,
            case_id=7,
            field_name="username",
            extractor=lambda *args, **kwargs: None,
            client_public_ips=set(),
            candidates={},
            table_name="events",
            scope_sql=sql,
            scope_params=params,
        )
        query_sql = fake.queries[-1][0]
        self.assertIn("GROUP BY value", query_sql)
        self.assertNotIn("username, source_host", query_sql)
        self.assertIn("case_file_id = {case_file_id:UInt32}", query_sql)
        self.assertNotIn("SELECT DISTINCT username, source_host", query_sql)

    def test_generation_none_is_accepted_nonzero_is_rejected(self):
        _validate_generation_scope(None)
        with self.assertRaises(ValueError):
            _validate_generation_scope(1)

    def test_scoped_alias_semantic_parity_with_per_event_path(self):
        rows = _sample_rows()
        allowed = set(PRIVACY_ENTITY_TYPES_BY_LEVEL[PRIVACY_LEVEL_CMMC_CUI])
        scanned_rows = [{**row, "raw_json": ""} for row in rows]
        old = extract_alias_candidates_from_event_rows(scanned_rows)
        new = _distinct_scan_from_rows(rows, allowed_types=allowed)
        old_keys = canonical_alias_identity_set(old, allowed_types=allowed)
        new_keys = canonical_alias_identity_set(new, allowed_types=allowed)
        missing = old_keys - new_keys
        self.assertFalse(missing, f"missing protected aliases: {sorted(missing)}")
        self.assertEqual(old_keys, new_keys)
        self.assertTrue(all("secret-should-not-scan" not in key[1] for key in new_keys))


class OrjsonParityTests(unittest.TestCase):
    def test_malformed_json_raises_json_decode_error(self):
        with self.assertRaises(json.JSONDecodeError):
            _evtx_json_loads("{not-json")

    def test_bytes_and_str_and_unicode_round_trip(self):
        payload = {"Computer": "HÔTE-1", "EventId": 1, "note": "café"}
        encoded = json.dumps(payload, ensure_ascii=False)
        self.assertEqual(_evtx_json_loads(encoded), payload)
        self.assertEqual(_evtx_json_loads(encoded.encode("utf-8")), payload)

    def test_nan_infinity_fallback_matches_stdlib(self):
        raw = '{"n": NaN, "i": Infinity}'
        decoded = _evtx_json_loads(raw)
        stdlib = json.loads(raw)
        self.assertEqual(str(decoded["n"]), str(stdlib["n"]))
        self.assertEqual(str(decoded["i"]), str(stdlib["i"]))

    def test_duplicate_keys_last_wins(self):
        raw = '{"EventId": 1, "EventId": 4624}'
        self.assertEqual(_evtx_json_loads(raw)["EventId"], json.loads(raw)["EventId"])

    def test_normalized_event_and_erk_parity(self):
        parser = object.__new__(EvtxECmdParser)
        BaseParser.__init__(parser, case_id=1, source_host="HOST1", case_file_id=55, case_tz="UTC")
        payload = {
            "EventData": {
                "Data": [
                    {"@Name": "IpAddress", "#text": "10.0.0.9"},
                    {"@Name": "TargetUserName", "#text": "alice"},
                    {"@Name": "TargetDomainName", "#text": "CORP"},
                    {"@Name": "TargetUserSid", "#text": "S-1-5-21-1-2-3-1001"},
                ]
            }
        }
        event = {
            "TimeCreated": "2026-03-14T12:00:00.123Z",
            "EventId": 4624,
            "Channel": "Security",
            "Computer": "HOST1",
            "EventRecordId": "77",
            "RecordNumber": "77",
            "Provider": "Microsoft-Windows-Security-Auditing",
            "Level": "Info",
            "UserName": "alice",
            "Payload": json.dumps(payload),
            "PayloadData1": "alice",
        }
        parsed_orjson = parser._transform_evtxecmd_event(
            event=_evtx_json_loads(json.dumps(event)),
            file_path="/tmp/Security.evtx",
            source_file="Security.evtx",
            detections={},
        )
        parsed_json = parser._transform_evtxecmd_event(
            event=json.loads(json.dumps(event)),
            file_path="/tmp/Security.evtx",
            source_file="Security.evtx",
            detections={},
        )
        self.assertIsNotNone(parsed_orjson)
        self.assertIsNotNone(parsed_json)
        parsed_orjson.to_clickhouse_row()
        parsed_json.to_clickhouse_row()
        self.assertEqual(parsed_orjson.evidence_record_key, parsed_json.evidence_record_key)
        self.assertTrue(parsed_orjson.evidence_record_key.startswith("erk:"))
        skip = {"raw_json", "extra_fields"}
        for column in ParsedEvent.clickhouse_columns():
            if column in skip:
                continue
            self.assertEqual(
                getattr(parsed_orjson, column),
                getattr(parsed_json, column),
                column,
            )
        self.assertEqual(json.loads(parsed_orjson.raw_json), json.loads(parsed_json.raw_json))
        self.assertEqual(json.loads(parsed_orjson.extra_fields), json.loads(parsed_json.extra_fields))
        self.assertEqual(parsed_orjson.event_id, "4624")
        self.assertEqual(parsed_orjson.source_host, parsed_json.source_host)
        self.assertEqual(parsed_orjson.search_blob, parsed_json.search_blob)


class SemanticParityHelperTests(unittest.TestCase):
    def _load_parity(self):
        import importlib.util
        from pathlib import Path

        path = Path(__file__).resolve().parents[1] / "scripts" / "phase1_step1_semantic_parity.py"
        spec = importlib.util.spec_from_file_location("phase1_step1_semantic_parity", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_json_key_order_is_semantically_equal(self):
        parity = self._load_parity()
        left = '{"b": 1, "a": {"y": 2, "x": 3}}'
        right = '{"a": {"x": 3, "y": 2}, "b": 1}'
        self.assertTrue(parity.json_semantic_equal(left, right))
        row_a = {"evidence_record_key": "erk:1", "raw_json": left, "username": "alice", "indexed_at": "now"}
        row_b = {"evidence_record_key": "erk:1", "raw_json": right, "username": "alice", "indexed_at": "later"}
        self.assertEqual(parity.canonical_event_row(row_a), parity.canonical_event_row(row_b))

    def test_erk_set_and_field_difference_detection(self):
        import tempfile
        from pathlib import Path

        parity = self._load_parity()
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base.jsonl"
            step = Path(tmp) / "step.jsonl"
            base.write_text(
                json.dumps({"evidence_record_key": "erk:a", "username": "alice", "raw_json": '{"k":1}'})
                + "\n"
                + json.dumps({"evidence_record_key": "erk:b", "username": "bob", "raw_json": '{"k":2}'})
                + "\n"
            )
            step.write_text(
                json.dumps({"evidence_record_key": "erk:a", "username": "alice", "raw_json": '{"k": 1}'})
                + "\n"
                + json.dumps({"evidence_record_key": "erk:c", "username": "carol", "raw_json": '{"k":3}'})
                + "\n"
            )
            result = parity.compare_event_dumps(base, step)
        self.assertEqual(result["erk_set_difference_A_minus_B"], 1)
        self.assertEqual(result["erk_set_difference_B_minus_A"], 1)
        self.assertEqual(result["missing_erks_sample"], ["erk:b"])
        self.assertEqual(result["extra_erks_sample"], ["erk:c"])
        self.assertEqual(result["rows_with_deterministic_field_difference"], 0)

    def test_alias_identity_ignores_generated_alias_strings(self):
        parity = self._load_parity()
        baseline = {
            "privacy_level_effective": "cmmc_cui",
            "alias_path": "per_event_extract",
            "alias_extract": {
                "baseline_style_candidate_count_with_raw_json": 3,
                "baseline_style_candidate_count_raw_json_excluded": 2,
                "step1_scanned_candidate_count": None,
            },
            "vault": {
                "identities": [
                    {"entity_type": "USERNAME", "normalized_value": "alice"},
                    {"entity_type": "HOSTNAME", "normalized_value": "host1"},
                ],
                "identities_all_types": [
                    {"entity_type": "USERNAME", "normalized_value": "alice"},
                    {"entity_type": "HOSTNAME", "normalized_value": "host1"},
                    {"entity_type": "URL", "normalized_value": "http://x"},
                ],
            },
            "aliases_rows": [
                {
                    "entity_type": "USERNAME",
                    "normalized_value": "alice",
                    "original_value": "ALICE",
                    "alias_value": "USERNAME_0001",
                }
            ],
            "per_source_contracted_raw_json_excluded": {
                "Security.evtx": {
                    "channels": ["Security"],
                    "identities": [{"entity_type": "USERNAME", "normalized_value": "alice"}],
                }
            },
        }
        step1 = {
            "privacy_level_effective": "cmmc_cui",
            "alias_path": "scoped_populate",
            "alias_extract": {
                "baseline_style_candidate_count_with_raw_json": 2,
                "baseline_style_candidate_count_raw_json_excluded": 2,
                "step1_scanned_candidate_count": 2,
            },
            "vault": {
                "identities": [
                    {"entity_type": "HOSTNAME", "normalized_value": "host1"},
                    {"entity_type": "USERNAME", "normalized_value": "alice"},
                ],
                "identities_all_types": [
                    {"entity_type": "HOSTNAME", "normalized_value": "host1"},
                    {"entity_type": "USERNAME", "normalized_value": "alice"},
                ],
            },
            "aliases_rows": [
                {
                    "entity_type": "USERNAME",
                    "normalized_value": "alice",
                    "original_value": "ALICE",
                    "alias_value": "USERNAME_0099",
                }
            ],
            "per_source_contracted_raw_json_excluded": {
                "Security.evtx": {
                    "channels": ["Security"],
                    "identities": [{"entity_type": "USERNAME", "normalized_value": "alice"}],
                }
            },
        }
        result = parity.compare_alias_dumps(baseline, step1)
        self.assertTrue(result["protected_identity_set_parity"])
        self.assertEqual(result["normalization_mismatch_count"], 0)
        self.assertTrue(result["per_source_contracted"]["Security.evtx"]["parity"])


class DeleteExistenceProbeTests(unittest.TestCase):
    def test_zero_row_source_skips_alter_delete(self):
        client = _FakeClickHouse(events_rows=[], buffer_rows=[])
        self.assertTrue(delete_file_events(42, wait=True, client=client))
        self.assertEqual(client.commands, [])
        probe_sql = " ".join(client.queries[0][0].split())
        self.assertIn("SELECT 1 FROM events WHERE case_file_id = {case_file_id:UInt32} LIMIT 1", probe_sql)

    def test_existing_rows_execute_current_delete_path(self):
        client = _FakeClickHouse(events_rows=[(1,)])
        self.assertTrue(delete_file_events(99, wait=False, client=client))
        self.assertEqual(
            client.commands,
            [
                "ALTER TABLE events DELETE WHERE case_file_id = 99",
                "ALTER TABLE events_buffer DELETE WHERE case_file_id = 99",
            ],
        )

    def test_probe_failure_fails_safe_and_deletes(self):
        client = _FakeClickHouse(fail_probe="connection reset")
        self.assertTrue(delete_file_events(7, wait=False, client=client))
        self.assertEqual(
            client.commands,
            [
                "ALTER TABLE events DELETE WHERE case_file_id = 7",
                "ALTER TABLE events_buffer DELETE WHERE case_file_id = 7",
            ],
        )


class WidePartMigrationTests(unittest.TestCase):
    def test_detects_forced_zero_override(self):
        self.assertTrue(
            events_has_forced_wide_settings(
                "MergeTree SETTINGS index_granularity = 8192, min_bytes_for_wide_part = 0, min_rows_for_wide_part = 0"
            )
        )
        self.assertFalse(
            events_has_forced_wide_settings("MergeTree SETTINGS index_granularity = 8192")
        )

    def test_refuses_production_without_flag(self):
        client = _FakeClickHouse()

        def query(sql, parameters=None):
            if "currentDatabase" in sql:
                return _QueryResult([("casescope",)])
            return _QueryResult([(1,)])

        client.query = query
        with self.assertRaises(RuntimeError):
            reset_events_forced_wide_part_settings(client, allow_production=False)

    def test_reset_is_idempotent(self):
        client = _FakeClickHouse(
            engine_full="MergeTree SETTINGS index_granularity = 8192, min_bytes_for_wide_part = 0, min_rows_for_wide_part = 0"
        )
        first = reset_events_forced_wide_part_settings(client, allow_production=True)
        self.assertEqual(first["sql"], RESET_SETTING_SQL)
        self.assertTrue(first["changed"])
        self.assertEqual(client.commands, [RESET_SETTING_SQL])
        client.engine_full = "MergeTree SETTINGS index_granularity = 8192"
        second = reset_events_forced_wide_part_settings(client, allow_production=True)
        self.assertFalse(second["changed"])
        self.assertIsNone(second["sql"])
        self.assertEqual(client.commands, [RESET_SETTING_SQL])


if __name__ == "__main__":
    unittest.main()
