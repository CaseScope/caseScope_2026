from __future__ import annotations

import os
import threading
import time
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

os.environ.setdefault("SECRET_KEY", "phase1b-d2-test-secret")

import clickhouse_connect
from flask import Flask
from sqlalchemy import create_engine, text
from sqlalchemy.orm import scoped_session, sessionmaker

from config import Config
from migrations.add_events_table import EVENTS_COLUMN_DEFINITIONS
from models.case import Case
from models.case_file import CaseFile, IngestProtocolOrigin
from models.client import Client
from models.database import db
from models.database_flow import (
    CaseCapabilitySourceState,
    EvidenceGenerationAudit,
    EvidenceGenerationState,
    EvidenceSourceGeneration,
    IngestAttempt,
    IngestBatch,
    IngestBatchReconciliationAudit,
    IngestBatchState,
)
from models.graph_saved_view import GraphSavedView
from models.investigation_thread import InvestigationThread
from parsers.base import BaseParser, ParsedEvent
from utils.ingest_fence import install_memory_backend, reset_fence_backend
from utils.manifest_protocol import (
    PROTOCOL_CLICKHOUSE_COLUMNS,
    ManifestParserContract,
    activate_initial_generation,
    allocate_case_file_initial_generation,
    allocate_case_file_replacement_generation,
    batch_content_hash,
    construct_managed_batch,
    create_ingest_attempt,
    declare_generation_ingest_complete,
    finish_ingest_attempt,
    insert_managed_batch,
    mark_batch_durable,
    reserve_staged_batch,
    update_generation_ingest_accounting,
    verify_ingest_batch,
)
from utils.staged_batch_reconciler import (
    classify_batch,
    discover_stale_staged_batch_ids,
    inspect_batch,
    reconcile_staged_batch,
)


PG_URL = os.environ.get("PHASE1B_PG_TEST_DATABASE_URL")
CH_DB = os.environ.get("PHASE1B_CH_TEST_DATABASE")

_MAPPER_RELATIONSHIP_IMPORTS = (GraphSavedView, InvestigationThread)

POSTGRES_INDEX_DDL = [
    """
    CREATE UNIQUE INDEX IF NOT EXISTS uq_evidence_source_generation_open_building
    ON evidence_source_generations (case_id, source_ref_type, source_ref_id)
    WHERE visibility_state IN ('BUILDING_INITIAL', 'BUILDING_REPLACEMENT')
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS uq_evidence_source_generation_active
    ON evidence_source_generations (case_id, source_ref_type, source_ref_id)
    WHERE visibility_state = 'ACTIVE'
    """,
]

CLICKHOUSE_CONTROL_TABLE_DDL = [
    """
    CREATE TABLE IF NOT EXISTS visible_evidence_generations (
        case_id UInt32,
        source_ref_type String,
        source_ref_id String,
        source_generation UInt32,
        visibility_state LowCardinality(String),
        state_version UInt64,
        publishable UInt8,
        updated_at DateTime64(3) DEFAULT now64(3)
    )
    ENGINE = ReplacingMergeTree(state_version)
    ORDER BY (case_id, source_ref_type, source_ref_id, source_generation)
    SETTINGS index_granularity = 8192
    """,
    """
    CREATE TABLE IF NOT EXISTS durable_ingest_batches (
        ingest_batch_id String,
        case_id UInt32,
        source_ref_type String,
        source_ref_id String,
        source_generation UInt32,
        batch_ordinal UInt32,
        expected_row_count UInt64,
        batch_content_hash String,
        state LowCardinality(String),
        state_version UInt64,
        durable_at Nullable(DateTime64(3)),
        updated_at DateTime64(3) DEFAULT now64(3)
    )
    ENGINE = ReplacingMergeTree(state_version)
    ORDER BY ingest_batch_id
    SETTINGS index_granularity = 8192
    """,
]


class _D2Parser(BaseParser):
    supports_manifest_protocol = True
    manifest_ordering_contract = "d2:fixture-order:v1"
    VERSION = "1.0.0"

    def __init__(self, *args, events=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._events = list(events or [])

    @property
    def artifact_type(self):
        return "d2_fixture"

    def can_parse(self, _file_path):
        return True

    def parse(self, _file_path):
        return iter(self._events)

    def manifest_producer_version(self):
        return "d2-parser:v1"


@unittest.skipUnless(PG_URL and CH_DB, "PHASE1B_PG_TEST_DATABASE_URL and PHASE1B_CH_TEST_DATABASE are required")
class Phase1BD2RealPGCHTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        install_memory_backend()
        cls._old_flag = getattr(Config, "PHASE1B_MANIFEST_PROTOCOL_ENABLED", False)
        cls._old_batch_size = getattr(Config, "PHASE1B_MANIFEST_BATCH_SIZE", None)
        Config.PHASE1B_MANIFEST_PROTOCOL_ENABLED = True
        Config.PHASE1B_MANIFEST_BATCH_SIZE = 2
        cls.app = Flask(__name__)
        cls.app.config.update(
            SQLALCHEMY_DATABASE_URI=PG_URL,
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            SECRET_KEY="phase1b-d2-real",
        )
        db.init_app(cls.app)
        cls.ctx = cls.app.app_context()
        cls.ctx.push()
        cls.engine = create_engine(PG_URL)
        cls.Session = scoped_session(sessionmaker(bind=cls.engine))
        with cls.engine.begin() as conn:
            conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            conn.execute(text("CREATE SCHEMA public"))
        for table in (
            Client.__table__,
            Case.__table__,
            CaseFile.__table__,
            EvidenceSourceGeneration.__table__,
            EvidenceGenerationAudit.__table__,
            IngestAttempt.__table__,
            IngestBatch.__table__,
            IngestBatchReconciliationAudit.__table__,
            CaseCapabilitySourceState.__table__,
        ):
            table.create(cls.engine, checkfirst=True)
        with cls.engine.begin() as conn:
            for ddl in POSTGRES_INDEX_DDL:
                conn.execute(text(ddl))
        cls.ch = clickhouse_connect.get_client(
            host=os.environ.get("CLICKHOUSE_HOST", "localhost"),
            port=int(os.environ.get("CLICKHOUSE_PORT", 8123)),
            username=os.environ.get("CLICKHOUSE_USER", "default"),
            password=os.environ.get("CLICKHOUSE_PASSWORD", ""),
            database=CH_DB,
            autogenerate_session_id=False,
        )
        cls._create_events_table()
        for ddl in CLICKHOUSE_CONTROL_TABLE_DDL:
            cls.ch.command(ddl)

    @classmethod
    def tearDownClass(cls):
        cls.ch.command("DROP TABLE IF EXISTS events")
        cls.ch.command("DROP TABLE IF EXISTS visible_evidence_generations")
        cls.ch.command("DROP TABLE IF EXISTS durable_ingest_batches")
        cls.ch.close()
        cls.Session.remove()
        with cls.engine.begin() as conn:
            conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            conn.execute(text("CREATE SCHEMA public"))
        cls.engine.dispose()
        cls.ctx.pop()
        Config.PHASE1B_MANIFEST_PROTOCOL_ENABLED = cls._old_flag
        if cls._old_batch_size is None:
            try:
                delattr(Config, "PHASE1B_MANIFEST_BATCH_SIZE")
            except AttributeError:
                pass
        else:
            Config.PHASE1B_MANIFEST_BATCH_SIZE = cls._old_batch_size
        reset_fence_backend()

    @classmethod
    def _create_events_table(cls):
        columns = ",\n".join(
            f"    {name} {definition}"
            for name, definition in EVENTS_COLUMN_DEFINITIONS.items()
        )
        cls.ch.command(f"""
        CREATE TABLE IF NOT EXISTS events (
        {columns}
        )
        ENGINE = MergeTree
        PARTITION BY case_id
        ORDER BY (case_id, timestamp_utc, artifact_type, source_host, source_file, event_id)
        SETTINGS index_granularity = 8192
        """)

    def setUp(self):
        self.ch.command("TRUNCATE TABLE events")
        self.ch.command("TRUNCATE TABLE visible_evidence_generations")
        self.ch.command("TRUNCATE TABLE durable_ingest_batches")
        self.session = self.Session()
        self.session.query(IngestBatchReconciliationAudit).delete()
        self.session.query(IngestBatch).delete()
        self.session.query(IngestAttempt).delete()
        self.session.query(EvidenceGenerationAudit).delete()
        self.session.query(EvidenceSourceGeneration).delete()
        self.session.query(CaseFile).delete()
        self.session.query(Case).delete()
        self.session.query(Client).delete()
        self.session.commit()
        self.client = Client(name="D2 Real", code=f"D2R{time.time_ns() % 100000}", created_by="tester")
        self.case = Case(uuid=f"d2-real-{time.time_ns()}", name="D2 Real", company="Example", client=self.client, created_by="tester")
        self.case_file = CaseFile(
            case_uuid=self.case.uuid,
            filename="d2-real.log",
            original_filename="d2-real.log",
            file_path="/tmp/d2-real.log",
            file_size=1,
            sha256_hash="4" * 64,
            uploaded_by="tester",
            ingest_protocol_origin=IngestProtocolOrigin.NOT_STARTED,
        )
        self.session.add_all([self.client, self.case, self.case_file])
        self.session.commit()
        parser = _D2Parser(case_id=self.case.id, case_file_id=self.case_file.id)
        self.contract = ManifestParserContract(
            parser_version=parser.parser_version,
            normalization_version="normalization:v1",
            configured_batch_size=2,
            ordering_contract="d2:fixture-order:v1",
            producer_version="d2-parser:v1",
            manifest_eligible=True,
        )

    def tearDown(self):
        self.session.close()
        self.Session.remove()

    def _event(self, generation_number, record_id, *, case_file_id=None):
        return ParsedEvent(
            case_id=self.case.id,
            artifact_type="d2_fixture",
            timestamp=datetime(2026, 1, 1) + timedelta(seconds=record_id),
            timestamp_utc=datetime(2026, 1, 1) + timedelta(seconds=record_id),
            timestamp_source_tz="UTC",
            source_file="d2-real.log",
            source_path="/tmp/d2-real.log",
            source_host="D2HOST",
            case_file_id=case_file_id or self.case_file.id,
            event_id=f"{generation_number}-{record_id}",
            record_id=record_id,
            command_line=f"generation {generation_number} record {record_id}",
            raw_json=f'{{"generation":{generation_number},"record_id":{record_id}}}',
            search_blob=f"generation {generation_number} record {record_id}",
            parser_version="D2Parser-1.0.0",
            native_record_id_authoritative=True,
        )

    def _initial_generation(self, *, state=EvidenceGenerationState.BUILDING_INITIAL):
        generation = allocate_case_file_initial_generation(
            session=self.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        generation.visibility_state = state
        self.session.commit()
        return generation

    def _staged_batch(self, generation, events, *, batch_ordinal=0, terminal_attempt=True):
        attempt = create_ingest_attempt(session=self.session, generation=generation)
        manifest = construct_managed_batch(
            generation=generation,
            attempt=attempt,
            events=events,
            batch_ordinal=batch_ordinal,
        )
        batch = reserve_staged_batch(session=self.session, manifest=manifest)
        if terminal_attempt:
            finish_ingest_attempt(self.session, attempt, status="FAILED", error="simulated stale producer")
        self.session.commit()
        return attempt, manifest, batch

    def _insert_rows(self, rows):
        self.ch.insert("events", list(rows), column_names=list(PROTOCOL_CLICKHOUSE_COLUMNS))

    def _row_count(self, ingest_batch_id):
        result = self.ch.query(
            "SELECT count() FROM events WHERE ingest_batch_id = {id:String}",
            parameters={"id": ingest_batch_id},
        )
        return int(result.result_rows[0][0])

    def _schedule_recorder(self):
        scheduled = []

        def schedule(ingest_batch_id, recovery_attempt_id):
            scheduled.append((ingest_batch_id, recovery_attempt_id))
            return f"retry-{len(scheduled)}"

        return scheduled, schedule

    def test_live_writer_is_not_reconciled_until_attempt_lease_expires(self):
        generation = self._initial_generation()
        attempt, manifest, batch = self._staged_batch(
            generation,
            [self._event(1, 1), self._event(1, 2)],
            terminal_attempt=False,
        )
        attempt.lease_expires_at = datetime.utcnow() + timedelta(hours=1)
        self.session.commit()

        result = reconcile_staged_batch(
            session=self.session,
            clickhouse_client=self.ch,
            ingest_batch_id=manifest.ingest_batch_id,
        )
        self.assertEqual(result.action_taken, "skipped_not_stale")
        self.assertEqual(self._row_count(manifest.ingest_batch_id), 0)
        self.assertEqual(self.session.get(IngestBatch, batch.id).state, IngestBatchState.STAGED)

        attempt.lease_expires_at = datetime.utcnow() - timedelta(seconds=1)
        self.session.commit()
        scheduled, schedule = self._schedule_recorder()
        result = reconcile_staged_batch(
            session=self.session,
            clickhouse_client=self.ch,
            ingest_batch_id=manifest.ingest_batch_id,
            retry_scheduler=schedule,
        )
        self.assertEqual(result.classification, "absent")
        self.assertEqual(result.action_taken, "retry_same_batch")
        self.assertEqual(scheduled, [(manifest.ingest_batch_id, result.recovery_attempt_id)])
        self.assertEqual(self.session.get(IngestBatch, batch.id).ingest_batch_id, manifest.ingest_batch_id)

    def test_exact_staged_clickhouse_rows_promote_to_durable_without_reinsert(self):
        generation = self._initial_generation()
        _attempt, manifest, batch = self._staged_batch(generation, [self._event(1, 1), self._event(1, 2)])
        self._insert_rows(manifest.clickhouse_rows)

        result = reconcile_staged_batch(session=self.session, clickhouse_client=self.ch, ingest_batch_id=manifest.ingest_batch_id)

        self.assertEqual(result.action_taken, "mark_durable")
        self.assertEqual(result.classification, "exact")
        self.assertEqual(self.session.get(IngestBatch, batch.id).state, IngestBatchState.DURABLE)
        self.assertEqual(self._row_count(manifest.ingest_batch_id), manifest.row_count)

    def test_partial_batch_purges_only_target_and_retries_same_identity(self):
        generation = self._initial_generation()
        _attempt_a, manifest_a, batch_a = self._staged_batch(generation, [self._event(1, 1), self._event(1, 2)], batch_ordinal=0)
        attempt_b = create_ingest_attempt(session=self.session, generation=generation)
        manifest_b = construct_managed_batch(generation=generation, attempt=attempt_b, events=[self._event(1, 3), self._event(1, 4)], batch_ordinal=1)
        batch_b = reserve_staged_batch(session=self.session, manifest=manifest_b)
        self._insert_rows(manifest_a.clickhouse_rows[:1])
        insert_managed_batch(self.ch, manifest_b)
        mark_batch_durable(session=self.session, batch=batch_b, verification=verify_ingest_batch(self.ch, manifest_b))
        finish_ingest_attempt(self.session, attempt_b, status="SUCCEEDED")
        self.session.commit()

        scheduled, schedule = self._schedule_recorder()
        with patch("utils.clickhouse.delete_file_events", side_effect=AssertionError("broad file delete called")):
            with patch("utils.clickhouse.delete_case_events", side_effect=AssertionError("broad case delete called")):
                result = reconcile_staged_batch(
                    session=self.session,
                    clickhouse_client=self.ch,
                    ingest_batch_id=manifest_a.ingest_batch_id,
                    retry_scheduler=schedule,
                )

        self.assertEqual(result.action_taken, "purged_and_retry_same_batch")
        self.assertEqual(result.classification, "partial")
        self.assertEqual(self._row_count(manifest_a.ingest_batch_id), 0)
        self.assertEqual(self._row_count(manifest_b.ingest_batch_id), manifest_b.row_count)
        self.assertEqual(self.session.get(IngestBatch, batch_a.id).state, IngestBatchState.STAGED)
        self.assertEqual(scheduled, [(manifest_a.ingest_batch_id, result.recovery_attempt_id)])

    def test_duplicate_identical_collapsed_proof_promotes_without_purge(self):
        generation = self._initial_generation()
        _attempt, manifest, batch = self._staged_batch(generation, [self._event(1, 1), self._event(1, 2)])
        self._insert_rows(manifest.clickhouse_rows)
        self._insert_rows(manifest.clickhouse_rows)

        result = reconcile_staged_batch(session=self.session, clickhouse_client=self.ch, ingest_batch_id=manifest.ingest_batch_id)

        self.assertEqual(result.classification, "duplicate_identical")
        self.assertEqual(result.action_taken, "mark_durable")
        self.assertEqual(self.session.get(IngestBatch, batch.id).state, IngestBatchState.DURABLE)
        self.assertEqual(self._row_count(manifest.ingest_batch_id), manifest.row_count * 2)

    def _assert_fail_closed_scenario(self, scenario, mutate):
        generation = self._initial_generation()
        _attempt, manifest, batch = self._staged_batch(generation, [self._event(1, 1), self._event(1, 2)])
        mutate(manifest, batch)

        result = reconcile_staged_batch(session=self.session, clickhouse_client=self.ch, ingest_batch_id=manifest.ingest_batch_id)

        self.assertEqual(result.action_taken, "fail_closed")
        self.assertEqual(result.classification, scenario)
        self.assertEqual(self.session.get(IngestBatch, batch.id).state, IngestBatchState.STAGED)
        self.assertIsNone(result.recovery_attempt_id)

    def test_duplicate_different_fails_closed(self):
        def mutate(manifest, _batch):
            self._insert_rows(manifest.clickhouse_rows)
            bad = list(manifest.clickhouse_rows[0])
            bad[PROTOCOL_CLICKHOUSE_COLUMNS.index("ingest_row_hash")] = "f" * 64
            self._insert_rows([tuple(bad)])

        self._assert_fail_closed_scenario("duplicate_different", mutate)

    def test_hash_mismatch_fails_closed(self):
        def mutate(manifest, _batch):
            rows = [list(row) for row in manifest.clickhouse_rows]
            rows[0][PROTOCOL_CLICKHOUSE_COLUMNS.index("ingest_row_hash")] = "e" * 64
            self._insert_rows(tuple(tuple(row) for row in rows))

        self._assert_fail_closed_scenario("hash_mismatch", mutate)

    def test_extra_ordinal_fails_closed_without_automatic_retry(self):
        def mutate(manifest, _batch):
            self._insert_rows(manifest.clickhouse_rows)
            extra = list(manifest.clickhouse_rows[0])
            extra[PROTOCOL_CLICKHOUSE_COLUMNS.index("ingest_row_ordinal")] = 99
            self._insert_rows([tuple(extra)])

        self._assert_fail_closed_scenario("extra_ordinal", mutate)

    def test_aggregate_hash_mismatch_fails_closed(self):
        def mutate(manifest, batch):
            self._insert_rows(manifest.clickhouse_rows)
            batch.batch_content_hash = batch_content_hash(["a" * 64, "b" * 64])
            self.session.commit()

        self._assert_fail_closed_scenario("aggregate_mismatch", mutate)

    def test_purge_crash_recovery_requires_next_pass_to_reinspect_and_prove_zero(self):
        generation = self._initial_generation()
        _attempt, manifest, batch = self._staged_batch(generation, [self._event(1, 1), self._event(1, 2)])
        self._insert_rows(manifest.clickhouse_rows[:1])

        def purge_then_crash(clickhouse_client, ingest_batch_id):
            from utils.manifest_protocol import purge_ingest_batch_rows

            purge_ingest_batch_rows(clickhouse_client, ingest_batch_id)
            raise RuntimeError("crash after purge")

        with patch("utils.staged_batch_reconciler.purge_ingest_batch_rows", side_effect=purge_then_crash):
            with self.assertRaises(RuntimeError):
                reconcile_staged_batch(session=self.session, clickhouse_client=self.ch, ingest_batch_id=manifest.ingest_batch_id)

        self.session.rollback()
        batch = self.session.get(IngestBatch, batch.id)
        batch.reconcile_lease_expires_at = datetime.utcnow() - timedelta(seconds=1)
        self.session.commit()
        scheduled, schedule = self._schedule_recorder()
        result = reconcile_staged_batch(
            session=self.session,
            clickhouse_client=self.ch,
            ingest_batch_id=manifest.ingest_batch_id,
            retry_scheduler=schedule,
        )
        self.assertEqual(self._row_count(manifest.ingest_batch_id), 0)
        self.assertEqual(result.classification, "absent")
        self.assertEqual(result.action_taken, "retry_same_batch")
        self.assertEqual(len(scheduled), 1)

    def test_replacement_recovery_does_not_delete_or_publish_prior_active_generation(self):
        initial = self._initial_generation()
        attempt_n = create_ingest_attempt(session=self.session, generation=initial)
        manifest_n = construct_managed_batch(generation=initial, attempt=attempt_n, events=[self._event(1, 1), self._event(1, 2)], batch_ordinal=0)
        batch_n = reserve_staged_batch(session=self.session, manifest=manifest_n)
        insert_managed_batch(self.ch, manifest_n)
        mark_batch_durable(session=self.session, batch=batch_n, verification=verify_ingest_batch(self.ch, manifest_n))
        update_generation_ingest_accounting(session=self.session, generation=initial)
        declare_generation_ingest_complete(session=self.session, generation=initial, expected_rows=2, final_batch_ordinal=0)
        activate_initial_generation(session=self.session, generation=initial)
        finish_ingest_attempt(self.session, attempt_n, status="SUCCEEDED")
        self.session.commit()

        replacement = allocate_case_file_replacement_generation(
            session=self.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        _attempt_r, manifest_r, _batch_r = self._staged_batch(replacement, [self._event(2, 1), self._event(2, 2)])
        self._insert_rows(manifest_r.clickhouse_rows[:1])

        with patch("utils.clickhouse.delete_file_events", side_effect=AssertionError("broad file delete called")):
            with patch("utils.clickhouse.delete_case_events", side_effect=AssertionError("broad case delete called")):
                result = reconcile_staged_batch(session=self.session, clickhouse_client=self.ch, ingest_batch_id=manifest_r.ingest_batch_id)

        self.assertEqual(result.action_taken, "purged_and_retry_same_batch")
        self.session.refresh(initial)
        self.session.refresh(replacement)
        self.assertEqual(initial.visibility_state, EvidenceGenerationState.ACTIVE)
        self.assertEqual(replacement.visibility_state, EvidenceGenerationState.BUILDING_REPLACEMENT)
        self.assertEqual(self._row_count(manifest_n.ingest_batch_id), manifest_n.row_count)

    def test_active_generation_staged_batch_is_invariant_violation_not_repaired(self):
        generation = self._initial_generation(state=EvidenceGenerationState.ACTIVE)
        _attempt, manifest, batch = self._staged_batch(generation, [self._event(1, 1), self._event(1, 2)])
        self._insert_rows(manifest.clickhouse_rows)

        result = reconcile_staged_batch(session=self.session, clickhouse_client=self.ch, ingest_batch_id=manifest.ingest_batch_id)

        self.assertEqual(result.action_taken, "fail_closed")
        self.assertEqual(result.classification, "active_generation_invariant_violation")
        self.assertEqual(self.session.get(IngestBatch, batch.id).state, IngestBatchState.STAGED)

    def test_real_pg_concurrent_reconcilers_only_one_owner_marks_durable(self):
        generation = self._initial_generation()
        _attempt, manifest, _batch = self._staged_batch(generation, [self._event(1, 1), self._event(1, 2)])
        self._insert_rows(manifest.clickhouse_rows)
        barrier = threading.Barrier(2)
        results = []
        errors = []

        def worker(label):
            session = self.Session()
            try:
                barrier.wait(timeout=10)
                result = reconcile_staged_batch(
                    session=session,
                    clickhouse_client=self.ch,
                    ingest_batch_id=manifest.ingest_batch_id,
                    owner=label,
                )
                results.append(result.action_taken)
            except Exception as exc:
                errors.append(exc)
                session.rollback()
            finally:
                session.close()

        threads = [threading.Thread(target=worker, args=(label,)) for label in ("reconciler-a", "reconciler-b")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=20)

        self.assertEqual(errors, [])
        self.assertEqual(results.count("mark_durable"), 1)
        self.assertIn("skipped_not_stale", results)
        self.session.expire_all()
        self.assertEqual(
            self.session.query(IngestBatch).filter_by(ingest_batch_id=manifest.ingest_batch_id).one().state,
            IngestBatchState.DURABLE,
        )

    def test_discovery_is_bounded_and_uses_stale_eligibility(self):
        generation = self._initial_generation()
        old_ids = []
        for record_id in range(1, 6):
            attempt, manifest, _batch = self._staged_batch(
                generation,
                [self._event(1, record_id * 10), self._event(1, record_id * 10 + 1)],
                batch_ordinal=record_id - 1,
                terminal_attempt=False,
            )
            attempt.lease_expires_at = datetime.utcnow() - timedelta(seconds=1)
            old_ids.append(manifest.ingest_batch_id)
        self.session.commit()

        found = discover_stale_staged_batch_ids(session=self.session, limit=3)
        self.assertEqual(tuple(old_ids[:3]), found)

    def test_classifier_precedence_prefers_conflict_over_missing(self):
        generation = self._initial_generation()
        _attempt, manifest, batch = self._staged_batch(generation, [self._event(1, 1), self._event(1, 2)])
        bad = list(manifest.clickhouse_rows[0])
        bad[PROTOCOL_CLICKHOUSE_COLUMNS.index("ingest_row_hash")] = "d" * 64
        self._insert_rows([manifest.clickhouse_rows[0], tuple(bad)])

        classification = classify_batch(batch, inspect_batch(self.ch, manifest.ingest_batch_id))

        self.assertEqual(classification.classification, "duplicate_different")
        self.assertEqual(classification.missing_ordinals, (1,))


if __name__ == "__main__":
    unittest.main()
