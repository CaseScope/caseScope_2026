from __future__ import annotations

import hashlib
import json
import os
import struct
import unittest
from datetime import datetime, timezone
import uuid

os.environ.setdefault("SECRET_KEY", "phase1b-tranche-a-test-secret")

from migrations.add_phase1b_event_protocol_columns import (  # noqa: E402
    PHASE1B_EVENT_PROTOCOL_COLUMNS,
    protocol_column_ddl,
)
from migrations.add_phase1b_control_plane_tables import migrate as pg_control_plane_migrate  # noqa: E402
from migrations import add_events_table  # noqa: E402
from models.database_flow import (  # noqa: E402
    CapabilityWatermarkStatus,
    CaseCapabilitySourceState,
    EvidenceGenerationState,
    EvidenceSourceGeneration,
    IngestBatch,
    IngestBatchState,
    SourceRefType,
)
from parsers.base import ParsedEvent  # noqa: E402
from utils.ingest_identity import (  # noqa: E402
    BATCHING_CONTRACT_VERSION,
    PARSER_PROVENANCE_ALLOWED_FIELDS,
    ROW_HASH_ALLOWED_FIELDS,
    batch_content_hash,
    batch_content_hash_for_ordinals,
    canonical_ingest_batch_identity,
    canonical_ingest_row_payload,
    canonical_source_locator,
    deterministic_ingest_batch_id,
    ingest_row_hash,
    validate_uint32_ordinal,
    validate_zero_based_manifest_ordinals,
)


def _json_hash(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


class Phase1BDeterministicBatchIdentityTests(unittest.TestCase):
    def test_batch_id_is_stable_and_excludes_attempt_id(self):
        kwargs = {
            "case_id": 42,
            "source_ref_type": SourceRefType.CASE_FILE,
            "source_ref_id": 123,
            "source_generation": 1,
            "batch_ordinal": 7,
        }
        first = deterministic_ingest_batch_id(**kwargs)
        second = deterministic_ingest_batch_id(**kwargs)
        self.assertEqual(first, second)
        self.assertTrue(first.startswith(f"{BATCHING_CONTRACT_VERSION}:"))
        self.assertNotIn(str(uuid.uuid4()), first)

        with_attempt_a = deterministic_ingest_batch_id(**kwargs)
        with_attempt_b = deterministic_ingest_batch_id(**kwargs)
        self.assertEqual(with_attempt_a, with_attempt_b)

    def test_batch_id_changes_when_identity_inputs_change(self):
        base = {
            "case_id": 42,
            "source_ref_type": SourceRefType.CASE_FILE,
            "source_ref_id": 123,
            "source_generation": 1,
            "batch_ordinal": 7,
        }
        baseline = deterministic_ingest_batch_id(**base)
        for field, value in {
            "case_id": 43,
            "source_ref_type": SourceRefType.MEMORY_JOB,
            "source_ref_id": 124,
            "source_generation": 2,
            "batch_ordinal": 8,
        }.items():
            changed = dict(base)
            changed[field] = value
            self.assertNotEqual(baseline, deterministic_ingest_batch_id(**changed))

    def test_batch_id_uses_locked_canonical_input(self):
        canonical = canonical_ingest_batch_identity(
            case_id=42,
            source_ref_type=SourceRefType.CASE_FILE,
            source_ref_id=123,
            source_generation=1,
            batch_ordinal=7,
        )
        self.assertEqual(
            canonical,
            {
                "batching_contract_version": "ingest-batch:v1",
                "case_id": 42,
                "source_ref_type": "CASE_FILE",
                "source_ref_id": "123",
                "source_generation": 1,
                "batch_ordinal": 7,
            },
        )
        self.assertEqual(
            deterministic_ingest_batch_id(
                case_id=42,
                source_ref_type=SourceRefType.CASE_FILE,
                source_ref_id=123,
                source_generation=1,
                batch_ordinal=7,
            ),
            f"ingest-batch:v1:{_json_hash(canonical)}",
        )


class Phase1BOrdinalTests(unittest.TestCase):
    def test_ingest_row_ordinal_is_zero_based_uint32(self):
        self.assertEqual(validate_uint32_ordinal(0), 0)
        self.assertEqual(validate_uint32_ordinal(2**32 - 1), 2**32 - 1)
        with self.assertRaises(ValueError):
            validate_uint32_ordinal(-1)
        with self.assertRaises(ValueError):
            validate_uint32_ordinal(2**32)
        with self.assertRaises(ValueError):
            validate_uint32_ordinal(True)

    def test_manifest_ordinals_reject_duplicates_and_gaps(self):
        self.assertEqual(validate_zero_based_manifest_ordinals([0, 1, 2]), (0, 1, 2))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            validate_zero_based_manifest_ordinals([0, 1, 1])
        with self.assertRaisesRegex(ValueError, "zero-based"):
            validate_zero_based_manifest_ordinals([1, 2, 3])
        with self.assertRaisesRegex(ValueError, "zero-based"):
            validate_zero_based_manifest_ordinals([0, 2])


class Phase1BRowHashTests(unittest.TestCase):
    def _event(self, **overrides):
        event = {
            "case_id": 42,
            "artifact_type": "evtx",
            "timestamp": datetime(2026, 1, 2, 3, 4, 5, 987654, tzinfo=timezone.utc),
            "timestamp_utc": datetime(2026, 1, 2, 3, 4, 5, 987654, tzinfo=timezone.utc),
            "timestamp_source_tz": "UTC",
            "source_file": "Security.evtx",
            "source_path": "/evidence/Security.evtx",
            "source_host": "HOST1",
            "case_file_id": 123,
            "source_ref_type": "CASE_FILE",
            "source_ref_id": "123",
            "source_generation": 1,
            "ingest_batch_id": "ingest-batch:v1:" + ("1" * 64),
            "ingest_row_ordinal": 0,
            "event_id": "4688",
            "channel": "Security",
            "provider": "Microsoft-Windows-Security-Auditing",
            "record_id": 777,
            "level": "Information",
            "username": "alice",
            "domain": "EXAMPLE",
            "sid": "S-1-5-21",
            "process_name": "cmd.exe",
            "process_id": 4242,
            "command_line": "cmd.exe /c whoami",
            "mitre_tactics": ["execution"],
            "mitre_tags": ["attack.t1059"],
            "mitre_attack_ids": ["T1059"],
            "mitre_attack_tactics": ["execution"],
            "mitre_attack_sources": ["hayabusa"],
            "mitre_mapping_max_confidence": 90,
            "raw_json": '{"b":2,"a":1}',
            "search_blob": "cmd whoami",
            "parser_version": "parser-1",
            "parser_provenance": {
                "parser_version": "parser-1",
                "native_record_id_authoritative": True,
                "source_record_identifier_authoritative": True,
                "source_record_identifier_type": "record_id",
                "source_record_identifier_value": "777",
                "task_id": "excluded-task",
            },
            "extra_fields": '{"nondeterministic":true}',
            "indexed_at": datetime.now(timezone.utc),
            "selector_key": "excluded-selector",
            "ingest_attempt_id": str(uuid.uuid4()),
            "analyst_notes": "excluded analyst overlay",
        }
        event.update(overrides)
        return event

    def test_row_hash_is_stable_and_matches_fixture(self):
        event = self._event()
        self.assertEqual(ingest_row_hash(event), ingest_row_hash(dict(reversed(list(event.items())))))
        self.assertEqual(ingest_row_hash(event), _json_hash(canonical_ingest_row_payload(event)))

    def test_row_hash_changes_for_allowed_evidence_changes(self):
        baseline = ingest_row_hash(self._event())
        self.assertNotEqual(baseline, ingest_row_hash(self._event(command_line="cmd.exe /c hostname")))
        self.assertNotEqual(baseline, ingest_row_hash(self._event(raw_json='{"a":1,"b":3}')))
        self.assertNotEqual(baseline, ingest_row_hash(self._event(ingest_batch_id="ingest-batch:v1:" + ("2" * 64))))
        self.assertNotEqual(baseline, ingest_row_hash(self._event(ingest_row_ordinal=1)))

    def test_row_hash_ignores_excluded_fields(self):
        baseline = ingest_row_hash(self._event())
        self.assertEqual(
            baseline,
            ingest_row_hash(
                self._event(
                    indexed_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
                    selector_key="different",
                    ingest_attempt_id=str(uuid.uuid4()),
                    analyst_notes="different overlay",
                    extra_fields='{"changed":true}',
                    task_id="different-task",
                )
            ),
        )

    def test_raw_json_and_datetime_canonicalization(self):
        self.assertEqual(
            ingest_row_hash(self._event(raw_json='{"a":1,"b":2}')),
            ingest_row_hash(self._event(raw_json='{"b":2,"a":1}')),
        )
        payload = canonical_ingest_row_payload(self._event(raw_json="{invalid"))
        self.assertEqual(payload["raw_json"], {"$raw_text": "{invalid"})
        self.assertEqual(payload["timestamp_utc"], "2026-01-02T03:04:05.987Z")

    def test_parser_provenance_allowlist_only(self):
        payload = canonical_ingest_row_payload(self._event())
        self.assertEqual(
            payload["parser_provenance"],
            {
                "parser_version": "parser-1",
                "native_record_id_authoritative": True,
                "source_record_identifier_authoritative": True,
                "source_record_identifier_type": "record_id",
                "source_record_identifier_value": "777",
            },
        )

    def test_row_hash_allowlist_matches_locked_contract(self):
        self.assertEqual(
            tuple(ROW_HASH_ALLOWED_FIELDS),
            (
                "case_id",
                "artifact_type",
                "source_ref_type",
                "source_ref_id",
                "source_generation",
                "ingest_batch_id",
                "ingest_row_ordinal",
                "source_file",
                "source_path",
                "source_host",
                "case_file_id",
                "timestamp",
                "timestamp_utc",
                "timestamp_source_tz",
                "event_id",
                "channel",
                "provider",
                "record_id",
                "level",
                "username",
                "domain",
                "sid",
                "logon_type",
                "logon_id",
                "remote_host",
                "workstation_name",
                "auth_package",
                "logon_process",
                "elevated_token",
                "process_name",
                "process_path",
                "process_id",
                "parent_process",
                "parent_pid",
                "command_line",
                "thread_id",
                "executable_info",
                "payload_data1",
                "payload_data2",
                "payload_data3",
                "payload_data4",
                "payload_data5",
                "payload_data6",
                "target_path",
                "file_hash_md5",
                "file_hash_sha1",
                "file_hash_sha256",
                "file_size",
                "src_ip",
                "dst_ip",
                "src_port",
                "dst_port",
                "reg_key",
                "reg_value",
                "reg_data",
                "rule_title",
                "rule_level",
                "rule_file",
                "mitre_tactics",
                "mitre_tags",
                "mitre_attack_ids",
                "mitre_attack_tactics",
                "mitre_attack_sources",
                "mitre_mapping_max_confidence",
                "raw_json",
                "search_blob",
                "evidence_record_key",
                "evidence_identity_version",
                "evidence_identity_quality",
            ),
        )
        self.assertEqual(
            tuple(PARSER_PROVENANCE_ALLOWED_FIELDS),
            (
                "parser_version",
                "native_record_id_authoritative",
                "source_record_identifier_authoritative",
                "source_record_identifier_type",
                "source_record_identifier_value",
            ),
        )


class Phase1BBatchContentHashTests(unittest.TestCase):
    VECTOR_HASHES = [
        "3c831eb5a23962a50dbffc0d4f37facd0f1171844d08d1a5cc93a04426f02393",
        "0f719b1f3a428a4dd53c61b3bdc5c2ec279c2e6139f160b3bbb8df8e7efdead8",
        "4568437f50f4fba02636d5b089556984a0544019977a130c7fdc2fce24bb4fa0",
    ]
    VECTOR_EXPECTED = "b2960860c1669f5121172af32fd2411eecedf998b5582514284ec7580ac2a8f1"

    def _independent_binary_hash(self, row_hashes):
        version_bytes = b"ingest-batch:v1"
        payload = bytes([len(version_bytes)]) + version_bytes + b"\x00"
        for ordinal, row_hash in enumerate(row_hashes):
            payload += b"\x01" + bytes([32]) + bytes.fromhex(row_hash) + struct.pack(">I", ordinal)
        return hashlib.sha256(payload).hexdigest()

    def test_batch_content_hash_matches_locked_binary_vector(self):
        self.assertEqual(self._independent_binary_hash(self.VECTOR_HASHES), self.VECTOR_EXPECTED)
        self.assertEqual(batch_content_hash(self.VECTOR_HASHES), self.VECTOR_EXPECTED)

    def test_batch_content_hash_changes_for_order_ordinal_version_and_hash(self):
        hashes = list(self.VECTOR_HASHES)
        baseline = batch_content_hash(hashes)
        self.assertEqual(baseline, batch_content_hash(hashes))
        with self.assertRaisesRegex(ValueError, "zero-based"):
            batch_content_hash_for_ordinals([(2, hashes[2]), (1, hashes[1]), (0, hashes[0])])
        self.assertNotEqual(baseline, batch_content_hash(["a" * 64, "b" * 64, "d" * 64]))
        with self.assertRaisesRegex(ValueError, "exactly ingest-batch:v1"):
            batch_content_hash(hashes, batching_contract_version="ingest-batch:v2")
        with self.assertRaisesRegex(ValueError, "zero-based"):
            batch_content_hash_for_ordinals([(0, hashes[0]), (2, hashes[2])])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            batch_content_hash_for_ordinals([(0, "a" * 64), (0, "b" * 64)])

    def test_empty_batch_has_explicit_binary_header_hash(self):
        version_bytes = b"ingest-batch:v1"
        payload = bytes([len(version_bytes)]) + version_bytes + b"\x00"
        self.assertEqual(batch_content_hash([]), hashlib.sha256(payload).hexdigest())

    def test_batch_content_hash_rejects_malformed_manifest_input(self):
        h0, h1, h2 = self.VECTOR_HASHES
        invalid_manifests = [
            ([(1, h0)], "zero-based"),
            ([(0, h0), (2, h2)], "zero-based"),
            ([(0, h0), (1, h1), (1, h2)], "duplicate"),
            ([(1, h1), (0, h0)], "zero-based"),
            ([(0, h0), (2**32, h1)], "UInt32"),
            ([(-1, h0)], "UInt32"),
        ]
        for manifest, message in invalid_manifests:
            with self.subTest(manifest=manifest):
                with self.assertRaisesRegex(ValueError, message):
                    batch_content_hash_for_ordinals(manifest)

        invalid_hashes = [
            h0[:-1],
            h0 + "0",
            h0.upper(),
            "z" * 64,
            bytes.fromhex(h0),
        ]
        for row_hash in invalid_hashes:
            with self.subTest(row_hash=row_hash):
                with self.assertRaises(ValueError):
                    batch_content_hash([row_hash])


class Phase1BModelAndMigrationTests(unittest.TestCase):
    def test_control_plane_model_constraints_are_declared(self):
        generation_columns = {column.name for column in EvidenceSourceGeneration.__table__.columns}
        self.assertIn("visibility_state", generation_columns)
        self.assertIn("parser_version", generation_columns)
        self.assertIn("batching_contract_version", generation_columns)
        self.assertIn("configured_batch_size", generation_columns)

        batch_columns = {column.name for column in IngestBatch.__table__.columns}
        self.assertIn("expected_ingest_row_hashes", batch_columns)
        self.assertIn("first_source_locator", batch_columns)
        self.assertIn("last_source_locator", batch_columns)

        state_columns = {column.name for column in CaseCapabilitySourceState.__table__.columns}
        self.assertIn("contiguous_batch_ordinal", state_columns)
        self.assertIn("highest_completed_batch_ordinal", state_columns)
        self.assertIn("completed_batch_ordinals", state_columns)

        unique_constraints = {
            constraint.name
            for table in (
                EvidenceSourceGeneration.__table__,
                IngestBatch.__table__,
                CaseCapabilitySourceState.__table__,
            )
            for constraint in table.constraints
        }
        self.assertIn("uq_evidence_source_generation_identity", unique_constraints)
        self.assertIn("uq_ingest_batch_generation_ordinal", unique_constraints)
        self.assertIn("uq_case_capability_source_state_identity", unique_constraints)

    def test_allowed_states_and_source_types_cover_locked_contract(self):
        self.assertEqual(
            EvidenceGenerationState.all(),
            ["BUILDING_INITIAL", "BUILDING_REPLACEMENT", "ACTIVE", "SUPERSEDED", "INVALIDATED", "FAILED"],
        )
        self.assertEqual(IngestBatchState.all(), ["STAGED", "DURABLE"])
        self.assertIn("CONTIGUOUS_READY", CapabilityWatermarkStatus.all())
        self.assertEqual(
            {SourceRefType.CASE_FILE, SourceRefType.MEMORY_JOB, SourceRefType.PCAP_FILE},
            {"CASE_FILE", "MEMORY_JOB", "PCAP_FILE"},
        )

    def test_clickhouse_protocol_columns_are_nullable_defaults_and_inactive(self):
        for column in (
            "source_ref_type",
            "source_ref_id",
            "source_generation",
            "ingest_batch_id",
            "ingest_row_ordinal",
            "ingest_row_hash",
            "ingest_attempt_id",
        ):
            self.assertIn(column, add_events_table.EVENTS_COLUMN_DEFINITIONS)
            self.assertIn("Nullable", PHASE1B_EVENT_PROTOCOL_COLUMNS[column])
            self.assertIn("DEFAULT NULL", PHASE1B_EVENT_PROTOCOL_COLUMNS[column])
            self.assertNotIn(column, ParsedEvent.clickhouse_columns())

    def test_clickhouse_protocol_migration_is_additive_only(self):
        ddl = "\n".join(protocol_column_ddl())
        ddl_upper = ddl.upper()
        self.assertIn("ALTER TABLE events ADD COLUMN IF NOT EXISTS", ddl)
        forbidden = ["ALTER TABLE events UPDATE", "OPTIMIZE TABLE events FINAL", "INSERT SELECT", "RENAME TABLE"]
        for token in forbidden:
            self.assertNotIn(token.upper(), ddl_upper)

    def test_postgres_control_plane_migration_imports_models(self):
        self.assertTrue(callable(pg_control_plane_migrate))


class Phase1BSourceLocatorTests(unittest.TestCase):
    def test_source_locator_priority(self):
        locator = canonical_source_locator(
            parser_source_id="parser:1",
            native_record_id=99,
            byte_offset=20,
            deterministic_ordinal=0,
        )
        self.assertEqual(locator.canonical(), {"type": "parser_source_id", "value": "parser:1"})
        self.assertEqual(
            canonical_source_locator(native_record_id=99, deterministic_ordinal=0).canonical(),
            {"type": "native_record_id", "value": "99"},
        )
        self.assertEqual(
            canonical_source_locator(deterministic_ordinal=0).canonical(),
            {"type": "deterministic_ordinal", "value": "0"},
        )


if __name__ == "__main__":
    unittest.main()
