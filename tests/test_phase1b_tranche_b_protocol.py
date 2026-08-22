from __future__ import annotations

import os
import inspect
import unittest
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime
from types import SimpleNamespace

os.environ.setdefault("SECRET_KEY", "phase1b-tranche-b-test-secret")

from flask import Flask
from sqlalchemy.exc import IntegrityError

from models.case import Case
from models.case_file import CaseFile
from models.client import Client
from models.database import db
from models.database_flow import (
    EvidenceGenerationState,
    EvidenceSourceGeneration,
    IngestAttempt,
    IngestBatch,
    IngestBatchState,
    SourceRefType,
)
from models.graph_saved_view import GraphSavedView  # noqa: F401 - resolves graph/thread mapper relationships
from models.investigation_thread import InvestigationThread  # noqa: F401 - resolves graph/thread mapper relationships
from parsers.base import BaseParser, ParsedEvent
from utils.ingest_fence import install_memory_backend, reset_fence_backend
from utils.manifest_protocol import (
    PROTOCOL_CLICKHOUSE_COLUMNS,
    BatchVerificationResult,
    FrozenGenerationMismatch,
    GenerationAllocationError,
    ManifestEligibilityError,
    ManifestMismatchError,
    ManifestParserContract,
    allocate_case_file_initial_generation,
    batch_became_durable,
    construct_managed_batches,
    contract_from_parser,
    create_ingest_attempt,
    finish_ingest_attempt,
    handle_failed_verification,
    insert_managed_batch,
    mark_batch_durable,
    parser_manifest_eligible,
    project_generation_control_state,
    purge_ingest_batch_rows,
    reserve_staged_batch,
    update_generation_ingest_accounting,
    verify_ingest_batch,
)


class _FakeResult:
    def __init__(self, rows):
        self.result_rows = rows


class _FakeClickHouseClient:
    def __init__(self, *, fail_insert_after_store=False, fail_projection=False):
        self.events = []
        self.inserts = []
        self.commands = []
        self.fail_insert_after_store = fail_insert_after_store
        self.fail_projection = fail_projection

    def insert(self, table, rows, column_names=None, settings=None, **kwargs):
        rows = list(rows)
        column_names = list(column_names or [])
        self.inserts.append((table, rows, column_names))
        if table == "events":
            for row in rows:
                self.events.append(dict(zip(column_names, row)))
            if self.fail_insert_after_store:
                raise TimeoutError("client timeout after ClickHouse accepted rows")
        elif self.fail_projection:
            raise RuntimeError("projection insert failed")

    def query(self, sql, parameters=None):
        ingest_batch_id = (parameters or {}).get("id")
        grouped = {}
        for row in self.events:
            if row.get("ingest_batch_id") != ingest_batch_id:
                continue
            key = (row.get("ingest_row_ordinal"), row.get("ingest_row_hash"))
            grouped[key] = grouped.get(key, 0) + 1
        rows = [
            (ordinal, row_hash, physical_copies, 1)
            for (ordinal, row_hash), physical_copies in sorted(grouped.items())
        ]
        return _FakeResult(rows)

    def command(self, sql):
        self.commands.append(sql)
        if "DELETE WHERE ingest_batch_id" in sql:
            target = sql.rsplit("=", 1)[-1].strip().strip("'")
            self.events = [row for row in self.events if row.get("ingest_batch_id") != target]


class _IneligibleParser(BaseParser):
    @property
    def artifact_type(self):
        return "fixture"

    def can_parse(self, _file_path):
        return True

    def parse(self, _file_path):
        return iter(())


class _EligibleParser(_IneligibleParser):
    supports_manifest_protocol = True
    manifest_ordering_contract = "test:fixture-order:v1"


class Phase1BTrancheBProtocolTestCase(unittest.TestCase):
    def setUp(self):
        install_memory_backend()
        self.app = Flask(__name__)
        self.app.config.update(
            SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            SECRET_KEY="phase1b-tranche-b-test",
        )
        db.init_app(self.app)
        self.ctx = self.app.app_context()
        self.ctx.push()
        for table in (
            Client.__table__,
            Case.__table__,
            CaseFile.__table__,
            EvidenceSourceGeneration.__table__,
            IngestAttempt.__table__,
            IngestBatch.__table__,
        ):
            table.create(db.engine, checkfirst=True)
        self.case = Case(uuid="case-1", name="Case 1", company="Example", created_by="tester")
        db.session.add(self.case)
        db.session.flush()
        self.case_file = CaseFile(
            case_uuid=self.case.uuid,
            filename="fixture.log",
            original_filename="fixture.log",
            file_path="/tmp/fixture.log",
            file_size=123,
            sha256_hash="a" * 64,
            uploaded_by="tester",
        )
        db.session.add(self.case_file)
        db.session.commit()
        self.contract = ManifestParserContract(
            parser_version="fixture-parser:v1",
            normalization_version="fixture-normalization:v1",
            configured_batch_size=2,
            ordering_contract="test:fixture-order:v1",
            producer_version="casescope-test",
            manifest_eligible=True,
        )

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()
        reset_fence_backend()

    def _event(self, record_id, command_line=None):
        return ParsedEvent(
            case_id=self.case.id,
            artifact_type="fixture",
            timestamp=datetime(2026, 1, 1, 0, 0, record_id),
            timestamp_utc=datetime(2026, 1, 1, 0, 0, record_id),
            timestamp_source_tz="UTC",
            source_file="fixture.log",
            source_path="/tmp/fixture.log",
            source_host="HOST1",
            case_file_id=self.case_file.id,
            event_id=str(1000 + record_id),
            record_id=record_id,
            command_line=command_line or f"row {record_id}",
            raw_json=f'{{"record_id":{record_id}}}',
            search_blob=f"row {record_id}",
            parser_version="fixture-parser:v1",
            native_record_id_authoritative=True,
        )

    def _generation_attempt_batches(self, events=None):
        generation = allocate_case_file_initial_generation(
            session=db.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        attempt = create_ingest_attempt(session=db.session, generation=generation)
        events = events or [self._event(1), self._event(2), self._event(3)]
        batches = construct_managed_batches(generation=generation, attempt=attempt, events=events)
        return generation, attempt, batches

    def test_parser_eligibility_requires_global_flag_and_parser_contract(self):
        config_off = SimpleNamespace(PHASE1B_MANIFEST_PROTOCOL_ENABLED=False)
        config_on = SimpleNamespace(PHASE1B_MANIFEST_PROTOCOL_ENABLED=True)
        self.assertFalse(parser_manifest_eligible(_EligibleParser(1), config_off))
        self.assertFalse(parser_manifest_eligible(_IneligibleParser(1), config_on))
        self.assertTrue(parser_manifest_eligible(_EligibleParser(1), config_on))
        with self.assertRaises(ManifestEligibilityError):
            contract_from_parser(
                _IneligibleParser(1),
                configured_batch_size=2,
                normalization_version="norm:v1",
                config=config_on,
            )

    def test_generation_allocation_first_generation_and_retry_reuse(self):
        generation = allocate_case_file_initial_generation(
            session=db.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        db.session.commit()
        self.assertEqual(generation.source_ref_type, SourceRefType.CASE_FILE)
        self.assertEqual(generation.source_ref_id, str(self.case_file.id))
        self.assertEqual(generation.source_generation, 1)
        self.assertEqual(generation.visibility_state, EvidenceGenerationState.BUILDING_INITIAL)

        reused = allocate_case_file_initial_generation(
            session=db.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        self.assertEqual(reused.id, generation.id)

    def test_generation_constraints_allow_replacement_shape_but_reject_duplicate_open_building(self):
        active = EvidenceSourceGeneration(
            case_id=self.case.id,
            source_ref_type=SourceRefType.CASE_FILE,
            source_ref_id=str(self.case_file.id),
            source_generation=1,
            visibility_state=EvidenceGenerationState.ACTIVE,
            parser_version="p",
            normalization_version="n",
            batching_contract_version="ingest-batch:v1",
            configured_batch_size=2,
            ordering_contract="test:fixture-order:v1",
        )
        replacement = EvidenceSourceGeneration(
            case_id=self.case.id,
            source_ref_type=SourceRefType.CASE_FILE,
            source_ref_id=str(self.case_file.id),
            source_generation=2,
            visibility_state=EvidenceGenerationState.BUILDING_REPLACEMENT,
            parser_version="p",
            normalization_version="n",
            batching_contract_version="ingest-batch:v1",
            configured_batch_size=2,
            ordering_contract="test:fixture-order:v1",
        )
        db.session.add_all([active, replacement])
        db.session.commit()

        duplicate_building = EvidenceSourceGeneration(
            case_id=self.case.id,
            source_ref_type=SourceRefType.CASE_FILE,
            source_ref_id=str(self.case_file.id),
            source_generation=3,
            visibility_state=EvidenceGenerationState.BUILDING_INITIAL,
            parser_version="p",
            normalization_version="n",
            batching_contract_version="ingest-batch:v1",
            configured_batch_size=2,
            ordering_contract="test:fixture-order:v1",
        )
        db.session.add(duplicate_building)
        with self.assertRaises(IntegrityError):
            db.session.commit()
        db.session.rollback()

    def test_allocation_stops_on_active_or_frozen_config_mismatch(self):
        generation = allocate_case_file_initial_generation(
            session=db.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        generation.parser_version = "fixture-parser:v2"
        db.session.commit()
        with self.assertRaises(FrozenGenerationMismatch):
            allocate_case_file_initial_generation(
                session=db.session,
                case_id=self.case.id,
                case_file_id=self.case_file.id,
                contract=self.contract,
            )

        generation.visibility_state = EvidenceGenerationState.ACTIVE
        generation.parser_version = self.contract.parser_version
        db.session.commit()
        with self.assertRaises(GenerationAllocationError):
            allocate_case_file_initial_generation(
                session=db.session,
                case_id=self.case.id,
                case_file_id=self.case_file.id,
                contract=self.contract,
            )

    def test_retry_attempt_has_new_uuid_but_same_generation_batches_hashes(self):
        generation = allocate_case_file_initial_generation(
            session=db.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        events_a = [self._event(1), self._event(2), self._event(3)]
        attempt_a = create_ingest_attempt(session=db.session, generation=generation)
        batches_a = construct_managed_batches(generation=generation, attempt=attempt_a, events=events_a)
        attempt_b = create_ingest_attempt(session=db.session, generation=generation)
        events_b = [self._event(1), self._event(2), self._event(3)]
        batches_b = construct_managed_batches(generation=generation, attempt=attempt_b, events=events_b)
        self.assertNotEqual(attempt_a.ingest_attempt_id, attempt_b.ingest_attempt_id)
        self.assertEqual([b.ingest_batch_id for b in batches_a], [b.ingest_batch_id for b in batches_b])
        self.assertEqual([b.row_hashes for b in batches_a], [b.row_hashes for b in batches_b])
        self.assertEqual([b.batch_content_hash for b in batches_a], [b.batch_content_hash for b in batches_b])

    def test_staged_reservation_idempotent_and_conflict_rejected(self):
        _generation, _attempt, batches = self._generation_attempt_batches()
        batch = reserve_staged_batch(session=db.session, manifest=batches[0])
        db.session.commit()
        reused = reserve_staged_batch(session=db.session, manifest=batches[0])
        self.assertEqual(reused.id, batch.id)
        changed = replace(batches[0], row_hashes=("b" * 64,) + batches[0].row_hashes[1:])
        with self.assertRaises(ManifestMismatchError):
            reserve_staged_batch(session=db.session, manifest=changed)

    def test_protocol_insert_populates_metadata_columns(self):
        _generation, _attempt, batches = self._generation_attempt_batches()
        client = _FakeClickHouseClient()
        insert_managed_batch(client, batches[0])
        table, rows, columns = client.inserts[0]
        self.assertEqual(table, "events")
        self.assertEqual(columns, list(PROTOCOL_CLICKHOUSE_COLUMNS))
        row = dict(zip(columns, rows[0]))
        self.assertEqual(row["source_ref_type"], "CASE_FILE")
        self.assertEqual(row["source_ref_id"], str(self.case_file.id))
        self.assertEqual(row["source_generation"], 1)
        self.assertEqual(row["ingest_row_ordinal"], 0)
        self.assertRegex(row["ingest_row_hash"], r"^[0-9a-f]{64}$")
        self.assertEqual(row["ingest_attempt_id"], batches[0].ingest_attempt_id)

    def test_verifier_outcomes(self):
        _generation, _attempt, batches = self._generation_attempt_batches()
        batch = batches[0]

        absent = verify_ingest_batch(_FakeClickHouseClient(), batch)
        self.assertEqual((absent.outcome, absent.success), ("absent", False))

        exact_client = _FakeClickHouseClient()
        insert_managed_batch(exact_client, batch)
        exact = verify_ingest_batch(exact_client, batch)
        self.assertEqual((exact.outcome, exact.success), ("exact", True))

        partial_client = _FakeClickHouseClient()
        partial_client.insert("events", batch.clickhouse_rows[:1], column_names=list(PROTOCOL_CLICKHOUSE_COLUMNS))
        self.assertEqual(verify_ingest_batch(partial_client, batch).outcome, "partial")

        extra_client = _FakeClickHouseClient()
        insert_managed_batch(extra_client, batch)
        extra = dict(extra_client.events[0])
        extra["ingest_row_ordinal"] = 99
        extra_client.events.append(extra)
        self.assertEqual(verify_ingest_batch(extra_client, batch).outcome, "extra_ordinal")

        dup_same = _FakeClickHouseClient()
        insert_managed_batch(dup_same, batch)
        dup_same.events.append(dict(dup_same.events[0]))
        self.assertEqual(verify_ingest_batch(dup_same, batch).outcome, "duplicate_identical")

        dup_diff = _FakeClickHouseClient()
        insert_managed_batch(dup_diff, batch)
        conflict = dict(dup_diff.events[0])
        conflict["ingest_row_hash"] = "f" * 64
        dup_diff.events.append(conflict)
        self.assertEqual(verify_ingest_batch(dup_diff, batch).outcome, "duplicate_different")

        mismatch = _FakeClickHouseClient()
        insert_managed_batch(mismatch, batch)
        mismatch.events[0]["ingest_row_hash"] = "e" * 64
        self.assertEqual(verify_ingest_batch(mismatch, batch).outcome, "hash_mismatch")

        aggregate = _FakeClickHouseClient()
        insert_managed_batch(aggregate, batch)
        wrong_aggregate = replace(batch, batch_content_hash="d" * 64)
        self.assertEqual(verify_ingest_batch(aggregate, wrong_aggregate).outcome, "aggregate_mismatch")

    def test_failed_verification_purges_only_batch_id(self):
        _generation, _attempt, batches = self._generation_attempt_batches()
        client = _FakeClickHouseClient()
        insert_managed_batch(client, batches[0])
        verification = BatchVerificationResult("partial", False)
        handle_failed_verification(clickhouse_client=client, verification=verification, manifest=batches[0])
        self.assertIn("ingest_batch_id", client.commands[0])
        self.assertNotIn("case_file_id", client.commands[0])

    def test_durable_transition_idempotent_generation_not_active_and_projection_replay(self):
        generation, attempt, batches = self._generation_attempt_batches()
        batch_row = reserve_staged_batch(session=db.session, manifest=batches[0])
        client = _FakeClickHouseClient()
        insert_managed_batch(client, batches[0])
        verification = verify_ingest_batch(client, batches[0])
        mark_batch_durable(session=db.session, batch=batch_row, verification=verification)
        first_version = batch_row.state_version
        mark_batch_durable(session=db.session, batch=batch_row, verification=verification)
        update_generation_ingest_accounting(session=db.session, generation=generation, expected_rows=3)
        self.assertEqual(batch_row.state, IngestBatchState.DURABLE)
        self.assertEqual(batch_row.state_version, first_version)
        self.assertEqual(generation.visibility_state, EvidenceGenerationState.BUILDING_INITIAL)
        self.assertEqual(generation.landed_rows, 2)

        failing_projection = _FakeClickHouseClient(fail_projection=True)
        with self.assertRaises(RuntimeError):
            project_generation_control_state(failing_projection, db.session, generation)
        replay = _FakeClickHouseClient()
        project_generation_control_state(replay, db.session, generation)
        tables = [insert[0] for insert in replay.inserts]
        self.assertIn("visible_evidence_generations", tables)
        self.assertIn("durable_ingest_batches", tables)
        self.assertIsNone(batch_became_durable(batch_row))
        finish_ingest_attempt(db.session, attempt, status="SUCCEEDED")
        self.assertEqual(attempt.status, "SUCCEEDED")

    def test_crash_boundaries_keep_locked_recovery_state(self):
        generation = allocate_case_file_initial_generation(
            session=db.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        db.session.commit()
        self.assertEqual(IngestAttempt.query.count(), 0)

        attempt = create_ingest_attempt(session=db.session, generation=generation)
        db.session.commit()
        self.assertEqual(IngestBatch.query.count(), 0)

        batches = construct_managed_batches(generation=generation, attempt=attempt, events=[self._event(1), self._event(2)])
        staged = reserve_staged_batch(session=db.session, manifest=batches[0])
        db.session.commit()
        self.assertEqual(staged.state, IngestBatchState.STAGED)
        self.assertEqual(verify_ingest_batch(_FakeClickHouseClient(), batches[0]).outcome, "absent")

        timeout_client = _FakeClickHouseClient(fail_insert_after_store=True)
        with self.assertRaises(TimeoutError):
            insert_managed_batch(timeout_client, batches[0])
        verification = verify_ingest_batch(timeout_client, batches[0])
        self.assertTrue(verification.success)
        mark_batch_durable(session=db.session, batch=staged, verification=verification)
        db.session.commit()
        self.assertEqual(staged.state, IngestBatchState.DURABLE)

    def test_legacy_path_default_off_and_managed_code_does_not_schedule_derivations(self):
        config = SimpleNamespace(PHASE1B_MANIFEST_PROTOCOL_ENABLED=False)
        self.assertFalse(parser_manifest_eligible(_EligibleParser(1), config))
        import utils.manifest_protocol as manifest_protocol

        source = inspect.getsource(manifest_protocol)
        self.assertNotIn("populate_case_privacy_aliases", source)
        self.assertNotIn("materialize_events_for_case", source)
        self.assertNotIn("case_indexing_complete_task", source)

    def test_tranche_b_clickhouse_ddl_is_additive_control_tables_only(self):
        from migrations.add_phase1b_tranche_b_manifest_protocol import clickhouse_control_table_ddl

        ddl = "\n".join(clickhouse_control_table_ddl()).upper()
        self.assertIn("CREATE TABLE IF NOT EXISTS VISIBLE_EVIDENCE_GENERATIONS", ddl)
        self.assertIn("CREATE TABLE IF NOT EXISTS DURABLE_INGEST_BATCHES", ddl)
        self.assertNotIn("ALTER TABLE EVENTS UPDATE", ddl)
        self.assertNotIn("OPTIMIZE TABLE EVENTS FINAL", ddl)
        self.assertNotIn("INSERT INTO EVENTS SELECT", ddl)
        self.assertNotIn("RENAME TABLE EVENTS", ddl)


if __name__ == "__main__":
    unittest.main()
