from __future__ import annotations

import os
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

os.environ.setdefault("SECRET_KEY", "phase1b-e1-test-secret")

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
    CapabilityName,
    CapabilityWatermarkStatus,
    CaseCapabilityBatchCompletion,
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
from models.privacy_alias import PrivacyAlias, PrivacyAliasCounter
from parsers.base import BaseParser, ParsedEvent
from parsers.log_parsers import IISLogParser
from utils.capability_watermarks import (
    CAPABILITY_INVENTORY,
    LOCKED_CAPABILITY_NAMES,
    PRIVACY_ALIASES_V1,
    compute_contiguous_prefix,
    incremental_row_local_enabled,
    is_current_source_capability_covered,
    is_source_capability_covered,
    mark_capability_failed,
    record_capability_batch_completion,
    record_zero_event_capability_completion,
    verify_capability_batch_coverage,
    verify_capability_erk_coverage,
)
from utils.ingest_fence import install_memory_backend, reset_fence_backend
from utils.manifest_protocol import (
    PROTOCOL_CLICKHOUSE_COLUMNS,
    ManifestParserContract,
    activate_initial_generation,
    activate_replacement_generation,
    allocate_case_file_initial_generation,
    allocate_case_file_replacement_generation,
    construct_managed_batch,
    create_ingest_attempt,
    declare_generation_ingest_complete,
    invalidate_source_generation,
    mark_batch_durable,
    reserve_staged_batch,
    verify_ingest_batch,
)
from utils.row_local_derivations import derive_privacy_aliases_for_durable_batch
from utils.staged_batch_reconciler import reconcile_staged_batch


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


class _E1Parser(BaseParser):
    supports_manifest_protocol = True
    manifest_ordering_contract = "e1:fixture-order:v1"
    VERSION = "1.0.0"

    def __init__(self, *args, events=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._events = list(events or [])

    @property
    def artifact_type(self):
        return "e1_fixture"

    def can_parse(self, _file_path):
        return True

    def parse(self, _file_path):
        return iter(self._events)

    def manifest_producer_version(self):
        return "e1-parser:v1"


class Phase1BE1ContractUnitTestCase(unittest.TestCase):
    def test_locked_capability_names_and_inventory(self):
        self.assertEqual(
            tuple(LOCKED_CAPABILITY_NAMES),
            (
                "privacy_aliases",
                "ioc_matches",
                "mitre_matches",
                "graph_extraction",
                "known_principal_discovery",
                "behavioral_profile_contribution",
                "pattern_detection",
                "event_embeddings",
            ),
        )
        self.assertEqual(set(CAPABILITY_INVENTORY), set(LOCKED_CAPABILITY_NAMES))
        self.assertTrue(CAPABILITY_INVENTORY["privacy_aliases"]["e1_migrated"])
        for name, spec in CAPABILITY_INVENTORY.items():
            if name != "privacy_aliases":
                self.assertFalse(spec["e1_migrated"], name)
                self.assertFalse(spec["batch_local_completion"], name)

    def test_contiguous_prefix_has_holes_and_late_fill(self):
        self.assertIsNone(compute_contiguous_prefix([1, 3, 4]))
        self.assertEqual(compute_contiguous_prefix([0, 1, 3, 4]), 1)
        self.assertEqual(compute_contiguous_prefix([0, 1, 2, 3, 4]), 4)

    def test_incremental_flag_defaults_off(self):
        self.assertFalse(incremental_row_local_enabled(Config))


@unittest.skipUnless(PG_URL, "PHASE1B_PG_TEST_DATABASE_URL is required")
class Phase1BE1RealPGTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        install_memory_backend()
        cls._old_flag = getattr(Config, "PHASE1B_MANIFEST_PROTOCOL_ENABLED", False)
        cls._old_incremental = getattr(Config, "PHASE1B_INCREMENTAL_ROW_LOCAL_DERIVATIONS_ENABLED", False)
        cls._old_batch_size = getattr(Config, "PHASE1B_MANIFEST_BATCH_SIZE", None)
        Config.PHASE1B_MANIFEST_PROTOCOL_ENABLED = True
        Config.PHASE1B_INCREMENTAL_ROW_LOCAL_DERIVATIONS_ENABLED = False
        Config.PHASE1B_MANIFEST_BATCH_SIZE = 2
        cls.app = Flask(__name__)
        cls.app.config.update(
            SQLALCHEMY_DATABASE_URI=PG_URL,
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            SECRET_KEY="phase1b-e1-real",
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
            CaseCapabilityBatchCompletion.__table__,
        ):
            table.create(cls.engine, checkfirst=True)
        with cls.engine.begin() as conn:
            for ddl in POSTGRES_INDEX_DDL:
                conn.execute(text(ddl))

    @classmethod
    def tearDownClass(cls):
        cls.Session.remove()
        with cls.engine.begin() as conn:
            conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            conn.execute(text("CREATE SCHEMA public"))
        cls.engine.dispose()
        cls.ctx.pop()
        Config.PHASE1B_MANIFEST_PROTOCOL_ENABLED = cls._old_flag
        Config.PHASE1B_INCREMENTAL_ROW_LOCAL_DERIVATIONS_ENABLED = cls._old_incremental
        if cls._old_batch_size is None:
            try:
                delattr(Config, "PHASE1B_MANIFEST_BATCH_SIZE")
            except AttributeError:
                pass
        else:
            Config.PHASE1B_MANIFEST_BATCH_SIZE = cls._old_batch_size
        reset_fence_backend()

    def setUp(self):
        self.session = self.Session()
        self.session.query(CaseCapabilityBatchCompletion).delete()
        self.session.query(CaseCapabilitySourceState).delete()
        self.session.query(IngestBatchReconciliationAudit).delete()
        self.session.query(IngestBatch).delete()
        self.session.query(IngestAttempt).delete()
        self.session.query(EvidenceGenerationAudit).delete()
        self.session.query(EvidenceSourceGeneration).delete()
        self.session.query(CaseFile).delete()
        self.session.query(Case).delete()
        self.session.query(Client).delete()
        self.session.commit()
        self.client = Client(name="E1 Real", code=f"E1R{time.time_ns() % 100000}", created_by="tester")
        self.case = Case(uuid=f"e1-real-{time.time_ns()}", name="E1 Real", company="Example", client=self.client, created_by="tester")
        self.case_file = CaseFile(
            case_uuid=self.case.uuid,
            filename="e1-real.log",
            original_filename="e1-real.log",
            file_path="/tmp/e1-real.log",
            file_size=1,
            sha256_hash="5" * 64,
            uploaded_by="tester",
            ingest_protocol_origin=IngestProtocolOrigin.NOT_STARTED,
        )
        self.session.add_all([self.client, self.case, self.case_file])
        self.session.commit()
        parser = _E1Parser(case_id=self.case.id, case_file_id=self.case_file.id)
        self.contract = ManifestParserContract(
            parser_version=parser.parser_version,
            normalization_version="normalization:v1",
            configured_batch_size=2,
            ordering_contract="e1:fixture-order:v1",
            producer_version="e1-parser:v1",
            manifest_eligible=True,
        )

    def tearDown(self):
        self.session.close()
        self.Session.remove()

    def _event(self, generation_number, record_id):
        return ParsedEvent(
            case_id=self.case.id,
            artifact_type="e1_fixture",
            timestamp=datetime(2026, 1, 1) + timedelta(seconds=record_id),
            timestamp_utc=datetime(2026, 1, 1) + timedelta(seconds=record_id),
            timestamp_source_tz="UTC",
            source_file="e1-real.log",
            source_path="/tmp/e1-real.log",
            source_host="E1HOST",
            case_file_id=self.case_file.id,
            event_id=f"{generation_number}-{record_id}",
            record_id=record_id,
            username=f"user{record_id}",
            command_line=f"generation {generation_number} record {record_id}",
            raw_json=f'{{"generation":{generation_number},"record_id":{record_id}}}',
            search_blob=f"generation {generation_number} record {record_id} user{record_id}",
            parser_version="E1Parser-1.0.0",
            native_record_id_authoritative=True,
        )

    def _generation(self, *, state=EvidenceGenerationState.BUILDING_INITIAL):
        generation = allocate_case_file_initial_generation(
            session=self.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        generation.visibility_state = state
        self.session.commit()
        return generation

    def _durable_batch(self, generation, events, *, batch_ordinal=0, durable=True):
        attempt = create_ingest_attempt(session=self.session, generation=generation)
        manifest = construct_managed_batch(
            generation=generation,
            attempt=attempt,
            events=events,
            batch_ordinal=batch_ordinal,
        )
        batch = reserve_staged_batch(session=self.session, manifest=manifest)
        if durable:
            batch.state = IngestBatchState.DURABLE
            batch.durable_at = datetime.utcnow()
        self.session.commit()
        return batch

    def _complete(self, batch, *, version=PRIVACY_ALIASES_V1, capability=CapabilityName.PRIVACY_ALIASES):
        generation = batch.generation
        return record_capability_batch_completion(
            session=self.session,
            case_id=generation.case_id,
            capability=capability,
            source_ref_type=generation.source_ref_type,
            source_ref_id=generation.source_ref_id,
            source_generation=generation.source_generation,
            derivation_version=version,
            ingest_batch_id=batch.ingest_batch_id,
        )

    def _identity(self, generation, *, version=PRIVACY_ALIASES_V1):
        return {
            "case_id": generation.case_id,
            "capability": CapabilityName.PRIVACY_ALIASES,
            "source_ref_type": generation.source_ref_type,
            "source_ref_id": generation.source_ref_id,
            "source_generation": generation.source_generation,
            "derivation_version": version,
        }

    def test_unique_identity_and_json_is_not_authority(self):
        generation = self._generation()
        batch = self._durable_batch(generation, [self._event(1, 1), self._event(1, 2)])
        first = self._complete(batch)
        second = self._complete(batch)
        self.assertEqual(first.id, second.id)
        self.assertEqual(first.state_version, second.state_version)
        self.assertEqual(self.session.query(CaseCapabilityBatchCompletion).count(), 1)
        self.assertEqual(first.completed_batch_ordinals, [])
        self.assertEqual(first.contiguous_batch_ordinal, 0)

    def test_staged_batch_cannot_advance_watermark(self):
        generation = self._generation()
        batch = self._durable_batch(generation, [self._event(1, 1), self._event(1, 2)], durable=False)
        from utils.capability_watermarks import CapabilityWatermarkError
        with self.assertRaises(CapabilityWatermarkError):
            self._complete(batch)
        self.assertEqual(self.session.query(CaseCapabilityBatchCompletion).count(), 0)
        self.assertEqual(self.session.query(CaseCapabilitySourceState).count(), 0)

    def test_out_of_order_and_late_hole(self):
        generation = self._generation()
        batches = [
            self._durable_batch(generation, [self._event(1, idx * 2 + 1), self._event(1, idx * 2 + 2)], batch_ordinal=idx)
            for idx in range(5)
        ]
        self._complete(batches[0])
        self._complete(batches[1])
        self._complete(batches[3])
        watermark = self._complete(batches[4])
        self.assertEqual(watermark.contiguous_batch_ordinal, 1)
        self.assertEqual(watermark.status, CapabilityWatermarkStatus.CONTIGUOUS_READY)
        self.assertEqual(watermark.highest_completed_batch_ordinal, 4)
        watermark = self._complete(batches[2])
        self.assertEqual(watermark.contiguous_batch_ordinal, 4)
        declare_generation_ingest_complete(
            session=self.session,
            generation=generation,
            expected_rows=10,
            final_batch_ordinal=4,
        )
        watermark = self._complete(batches[2])
        self.assertEqual(watermark.status, CapabilityWatermarkStatus.COMPLETE)

    def test_zero_event_complete_without_fake_batch(self):
        generation = self._generation()
        declare_generation_ingest_complete(
            session=self.session,
            generation=generation,
            expected_rows=0,
            final_batch_ordinal=None,
        )
        watermark = record_zero_event_capability_completion(
            session=self.session,
            generation=generation,
            capability=CapabilityName.PRIVACY_ALIASES,
            derivation_version=PRIVACY_ALIASES_V1,
        )
        self.assertEqual(watermark.status, CapabilityWatermarkStatus.COMPLETE)
        self.assertIsNone(watermark.contiguous_batch_ordinal)
        self.assertEqual(self.session.query(IngestBatch).count(), 0)
        covered = is_source_capability_covered(self.session, **self._identity(generation))
        self.assertTrue(covered.covered)

    def test_derivation_version_isolation(self):
        generation = self._generation()
        batch = self._durable_batch(generation, [self._event(1, 1), self._event(1, 2)])
        declare_generation_ingest_complete(session=self.session, generation=generation, expected_rows=2, final_batch_ordinal=0)
        self._complete(batch, version=PRIVACY_ALIASES_V1)
        v1 = is_source_capability_covered(self.session, **self._identity(generation, version=PRIVACY_ALIASES_V1))
        v2 = is_source_capability_covered(self.session, **self._identity(generation, version="privacy-aliases:v2"))
        self.assertTrue(v1.covered)
        self.assertFalse(v2.covered)
        self.assertEqual(v2.status, CapabilityWatermarkStatus.NOT_STARTED)

    def test_generation_isolation_and_replacement_default_authority(self):
        initial = self._generation()
        batch_n = self._durable_batch(initial, [self._event(1, 1), self._event(1, 2)])
        declare_generation_ingest_complete(session=self.session, generation=initial, expected_rows=2, final_batch_ordinal=0)
        self._complete(batch_n)
        activate_initial_generation(session=self.session, generation=initial)
        self.session.commit()

        replacement = allocate_case_file_replacement_generation(
            session=self.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        batch_r = self._durable_batch(replacement, [self._event(2, 1), self._event(2, 2)])
        self._complete(batch_r)
        current = is_current_source_capability_covered(
            self.session,
            case_id=self.case.id,
            capability=CapabilityName.PRIVACY_ALIASES,
            source_ref_type=initial.source_ref_type,
            source_ref_id=initial.source_ref_id,
            derivation_version=PRIVACY_ALIASES_V1,
        )
        self.assertTrue(current.covered)
        self.assertEqual(current.source_generation, 1)
        explicit_r = is_source_capability_covered(self.session, **self._identity(replacement))
        self.assertFalse(explicit_r.covered)
        self.assertEqual(explicit_r.contiguous_batch_ordinal, 0)

        declare_generation_ingest_complete(session=self.session, generation=replacement, expected_rows=2, final_batch_ordinal=0)
        activate_replacement_generation(session=self.session, replacement=replacement)
        self.session.commit()
        after = is_current_source_capability_covered(
            self.session,
            case_id=self.case.id,
            capability=CapabilityName.PRIVACY_ALIASES,
            source_ref_type=initial.source_ref_type,
            source_ref_id=initial.source_ref_id,
            derivation_version=PRIVACY_ALIASES_V1,
        )
        self.assertTrue(after.covered)
        self.assertEqual(after.source_generation, 2)
        superseded = is_source_capability_covered(self.session, **self._identity(initial))
        self.assertFalse(superseded.covered)

    def test_replacement_incomplete_after_activation_does_not_fall_back(self):
        initial = self._generation()
        batch_n = self._durable_batch(initial, [self._event(1, 1), self._event(1, 2)])
        declare_generation_ingest_complete(session=self.session, generation=initial, expected_rows=2, final_batch_ordinal=0)
        self._complete(batch_n)
        activate_initial_generation(session=self.session, generation=initial)
        replacement = allocate_case_file_replacement_generation(
            session=self.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        self._durable_batch(replacement, [self._event(2, 1), self._event(2, 2)], batch_ordinal=0)
        self._durable_batch(replacement, [self._event(2, 3), self._event(2, 4)], batch_ordinal=1)
        declare_generation_ingest_complete(session=self.session, generation=replacement, expected_rows=4, final_batch_ordinal=1)
        activate_replacement_generation(session=self.session, replacement=replacement)
        self.session.commit()
        after = is_current_source_capability_covered(
            self.session,
            case_id=self.case.id,
            capability=CapabilityName.PRIVACY_ALIASES,
            source_ref_type=initial.source_ref_type,
            source_ref_id=initial.source_ref_id,
            derivation_version=PRIVACY_ALIASES_V1,
        )
        self.assertFalse(after.covered)
        self.assertEqual(after.source_generation, 2)

    def test_invalidation_withdraws_gates_without_deleting_history(self):
        generation = self._generation()
        batch = self._durable_batch(generation, [self._event(1, 1), self._event(1, 2)])
        declare_generation_ingest_complete(session=self.session, generation=generation, expected_rows=2, final_batch_ordinal=0)
        self._complete(batch)
        invalidate_source_generation(session=self.session, generation=generation, actor="tester", reason="e1 invalidation")
        self.session.commit()
        covered = is_source_capability_covered(self.session, **self._identity(generation))
        self.assertFalse(covered.covered)
        self.assertEqual(covered.status, CapabilityWatermarkStatus.INVALIDATED)
        self.assertEqual(self.session.query(CaseCapabilityBatchCompletion).count(), 1)
        current = is_current_source_capability_covered(
            self.session,
            case_id=self.case.id,
            capability=CapabilityName.PRIVACY_ALIASES,
            source_ref_type=generation.source_ref_type,
            source_ref_id=generation.source_ref_id,
            derivation_version=PRIVACY_ALIASES_V1,
        )
        self.assertFalse(current.covered)

    def test_failed_status_does_not_gate(self):
        generation = self._generation()
        batch = self._durable_batch(generation, [self._event(1, 1), self._event(1, 2)])
        self._complete(batch)
        mark_capability_failed(session=self.session, **self._identity(generation), reason="e1 fail")
        covered = is_source_capability_covered(
            self.session,
            **self._identity(generation),
            required_batch_ordinal=0,
        )
        self.assertFalse(covered.covered)
        self.assertEqual(covered.status, CapabilityWatermarkStatus.FAILED)

    def test_exact_batch_set_coverage(self):
        generation = self._generation()
        first = self._durable_batch(generation, [self._event(1, 1), self._event(1, 2)], batch_ordinal=0)
        second = self._durable_batch(generation, [self._event(1, 3), self._event(1, 4)], batch_ordinal=1)
        self._complete(first)
        missing = verify_capability_batch_coverage(
            self.session,
            capability=CapabilityName.PRIVACY_ALIASES,
            derivation_version=PRIVACY_ALIASES_V1,
            batch_ids=[first.ingest_batch_id, second.ingest_batch_id],
        )
        self.assertFalse(missing.covered)
        self.assertEqual(missing.missing_batch_ids, (second.ingest_batch_id,))
        self._complete(second)
        covered = verify_capability_batch_coverage(
            self.session,
            capability=CapabilityName.PRIVACY_ALIASES,
            derivation_version=PRIVACY_ALIASES_V1,
            batch_ids=[first.ingest_batch_id, second.ingest_batch_id],
        )
        self.assertTrue(covered.covered)

    def test_activation_requirements_remain_empty(self):
        from utils.manifest_protocol import _declared_activation_requirements
        generation = self._generation()
        self.assertEqual(_declared_activation_requirements(generation), ())

    def test_flag_off_does_not_queue_from_durable_transition(self):
        generation = self._generation()
        attempt = create_ingest_attempt(session=self.session, generation=generation)
        manifest = construct_managed_batch(
            generation=generation,
            attempt=attempt,
            events=[self._event(1, 1), self._event(1, 2)],
            batch_ordinal=0,
        )
        batch = reserve_staged_batch(session=self.session, manifest=manifest)
        with patch("tasks.celery_tasks.derive_row_local_capability_batch_task.delay") as queued:
            mark_batch_durable(
                session=self.session,
                batch=batch,
                verification=type("V", (), {"success": True, "outcome": "exact"})(),
            )
            queued.assert_not_called()
        self.assertEqual(self.session.query(CaseCapabilityBatchCompletion).count(), 0)

    def test_concurrent_workers_converge_without_regression(self):
        generation = self._generation()
        batches = [
            self._durable_batch(generation, [self._event(1, idx * 2 + 1), self._event(1, idx * 2 + 2)], batch_ordinal=idx)
            for idx in range(5)
        ]
        self.session.commit()
        barrier = threading.Barrier(3)
        errors = []

        def worker(ordinal):
            session = self.Session()
            try:
                barrier.wait(timeout=10)
                record_capability_batch_completion(
                    session=session,
                    case_id=generation.case_id,
                    capability=CapabilityName.PRIVACY_ALIASES,
                    source_ref_type=generation.source_ref_type,
                    source_ref_id=generation.source_ref_id,
                    source_generation=generation.source_generation,
                    derivation_version=PRIVACY_ALIASES_V1,
                    ingest_batch_id=batches[ordinal].ingest_batch_id,
                )
                session.commit()
            except Exception as exc:
                errors.append(exc)
                session.rollback()
            finally:
                session.close()

        threads = [threading.Thread(target=worker, args=(ordinal,)) for ordinal in (4, 2, 3)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=20)
        self.assertEqual(errors, [])
        self.session.expire_all()
        watermark = self._complete(batches[0])
        self.assertEqual(watermark.contiguous_batch_ordinal, 0)
        watermark = self._complete(batches[1])
        self.assertEqual(watermark.contiguous_batch_ordinal, 4)
        self.assertEqual(self.session.query(CaseCapabilityBatchCompletion).count(), 5)
        self.assertGreaterEqual(watermark.contiguous_batch_ordinal, 0)

    def test_performance_bounded_prefix_walk(self):
        generation = self._generation()
        batches = [
            self._durable_batch(generation, [self._event(1, idx * 2 + 1), self._event(1, idx * 2 + 2)], batch_ordinal=idx)
            for idx in range(20)
        ]
        started = time.perf_counter()
        for batch in batches:
            self._complete(batch)
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        watermark = self.session.query(CaseCapabilitySourceState).one()
        self.assertEqual(watermark.contiguous_batch_ordinal, 19)
        self.assertLess(elapsed_ms, 15000)
        self.assertEqual(self.session.query(CaseCapabilityBatchCompletion).count(), 20)
        self.assertEqual(watermark.completed_batch_ordinals, [])
        self.assertLess(elapsed_ms / 20, 1000)


@unittest.skipUnless(PG_URL and CH_DB, "PHASE1B_PG_TEST_DATABASE_URL and PHASE1B_CH_TEST_DATABASE are required")
class Phase1BE1RealPGCHTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        install_memory_backend()
        cls._old_flag = getattr(Config, "PHASE1B_MANIFEST_PROTOCOL_ENABLED", False)
        cls._old_incremental = getattr(Config, "PHASE1B_INCREMENTAL_ROW_LOCAL_DERIVATIONS_ENABLED", False)
        cls._old_batch_size = getattr(Config, "PHASE1B_MANIFEST_BATCH_SIZE", None)
        Config.PHASE1B_MANIFEST_PROTOCOL_ENABLED = True
        Config.PHASE1B_INCREMENTAL_ROW_LOCAL_DERIVATIONS_ENABLED = False
        Config.PHASE1B_MANIFEST_BATCH_SIZE = 4
        cls.app = Flask(__name__)
        cls.app.config.update(
            SQLALCHEMY_DATABASE_URI=PG_URL,
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            SECRET_KEY="phase1b-e1-ch",
        )
        db.init_app(cls.app)
        cls.ctx = cls.app.app_context()
        cls.ctx.push()
        with db.engine.begin() as conn:
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
            CaseCapabilityBatchCompletion.__table__,
            PrivacyAlias.__table__,
            PrivacyAliasCounter.__table__,
        ):
            table.create(db.engine, checkfirst=True)
        with db.engine.begin() as conn:
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
        columns = ",\n".join(f"    {name} {definition}" for name, definition in EVENTS_COLUMN_DEFINITIONS.items())
        cls.ch.command(f"""
        CREATE TABLE IF NOT EXISTS events (
        {columns}
        )
        ENGINE = MergeTree
        PARTITION BY case_id
        ORDER BY (case_id, timestamp_utc, artifact_type, source_host, source_file, event_id)
        SETTINGS index_granularity = 8192
        """)
        for ddl in CLICKHOUSE_CONTROL_TABLE_DDL:
            cls.ch.command(ddl)

    @classmethod
    def tearDownClass(cls):
        cls.ch.command("DROP TABLE IF EXISTS events")
        cls.ch.command("DROP TABLE IF EXISTS visible_evidence_generations")
        cls.ch.command("DROP TABLE IF EXISTS durable_ingest_batches")
        cls.ch.close()
        with db.engine.begin() as conn:
            conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            conn.execute(text("CREATE SCHEMA public"))
        cls.ctx.pop()
        Config.PHASE1B_MANIFEST_PROTOCOL_ENABLED = cls._old_flag
        Config.PHASE1B_INCREMENTAL_ROW_LOCAL_DERIVATIONS_ENABLED = cls._old_incremental
        if cls._old_batch_size is None:
            try:
                delattr(Config, "PHASE1B_MANIFEST_BATCH_SIZE")
            except AttributeError:
                pass
        else:
            Config.PHASE1B_MANIFEST_BATCH_SIZE = cls._old_batch_size
        reset_fence_backend()

    def setUp(self):
        self.ch.command("TRUNCATE TABLE events")
        self.ch.command("TRUNCATE TABLE visible_evidence_generations")
        self.ch.command("TRUNCATE TABLE durable_ingest_batches")
        PrivacyAlias.query.delete()
        PrivacyAliasCounter.query.delete()
        CaseCapabilityBatchCompletion.query.delete()
        CaseCapabilitySourceState.query.delete()
        IngestBatchReconciliationAudit.query.delete()
        IngestBatch.query.delete()
        IngestAttempt.query.delete()
        EvidenceGenerationAudit.query.delete()
        EvidenceSourceGeneration.query.delete()
        CaseFile.query.delete()
        Case.query.delete()
        Client.query.delete()
        db.session.commit()
        self.client = Client(name="E1 CH", code=f"E1C{time.time_ns() % 100000}", created_by="tester")
        self.case = Case(uuid=f"e1-ch-{time.time_ns()}", name="E1 CH", company="Example", client=self.client, created_by="tester")
        self.tempdir = tempfile.TemporaryDirectory()
        iis_path = os.path.join(self.tempdir.name, "u_ex260101.log")
        lines = [
            "#Software: Microsoft Internet Information Services",
            "#Version: 1.0",
            "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status",
        ]
        for idx in range(11):
            query = f"id={idx}&q=alpha" if idx % 2 else "-"
            username = f"user{idx}" if idx % 3 else "-"
            lines.append(
                f"2026-01-01 00:00:{idx:02d} 10.0.0.10 GET /path/{idx} {query} 443 {username} 192.0.2.{idx + 1} Agent{idx} 200"
            )
        with open(iis_path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
        self.case_file = CaseFile(
            case_uuid=self.case.uuid,
            filename="u_ex260101.log",
            original_filename="u_ex260101.log",
            file_path=iis_path,
            file_size=1,
            sha256_hash="6" * 64,
            uploaded_by="tester",
            ingest_protocol_origin=IngestProtocolOrigin.NOT_STARTED,
        )
        db.session.add_all([self.client, self.case, self.case_file])
        db.session.commit()
        parser = IISLogParser(case_id=self.case.id, case_file_id=self.case_file.id)
        self.events = list(parser.parse(iis_path))
        self.contract = ManifestParserContract(
            parser_version=parser.parser_version,
            normalization_version="normalization:v1",
            configured_batch_size=4,
            ordering_contract=parser.manifest_ordering_contract,
            producer_version=parser.parser_version,
            manifest_eligible=True,
        )

    def tearDown(self):
        db.session.remove()
        self.tempdir.cleanup()

    def _generation(self):
        generation = allocate_case_file_initial_generation(
            session=db.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        db.session.commit()
        return generation

    def _ingest_batch(self, generation, events, *, batch_ordinal, durable=True):
        attempt = create_ingest_attempt(session=db.session, generation=generation)
        manifest = construct_managed_batch(
            generation=generation,
            attempt=attempt,
            events=events,
            batch_ordinal=batch_ordinal,
        )
        batch = reserve_staged_batch(session=db.session, manifest=manifest)
        db.session.commit()
        self.ch.insert("events", list(manifest.clickhouse_rows), column_names=list(PROTOCOL_CLICKHOUSE_COLUMNS))
        if durable:
            mark_batch_durable(session=db.session, batch=batch, verification=verify_ingest_batch(self.ch, manifest))
            db.session.commit()
        return batch, manifest

    def test_iis_row_local_privacy_watermark_and_erk_coverage(self):
        generation = self._generation()
        slices = [self.events[0:4], self.events[4:8], self.events[8:11]]
        batch0, manifest0 = self._ingest_batch(generation, slices[0], batch_ordinal=0)
        batch1, _manifest1 = self._ingest_batch(generation, slices[1], batch_ordinal=1)
        batch2, _manifest2 = self._ingest_batch(generation, slices[2], batch_ordinal=2)

        result0 = derive_privacy_aliases_for_durable_batch(
            session=db.session,
            ingest_batch_id=batch0.ingest_batch_id,
            privacy_level="basic",
            clickhouse_client=self.ch,
        )
        db.session.commit()
        self.assertEqual(result0["contiguous_batch_ordinal"], 0)
        aliases_after_0 = PrivacyAlias.query.filter_by(case_id=self.case.id).count()
        self.assertGreater(aliases_after_0, 0)

        result2 = derive_privacy_aliases_for_durable_batch(
            session=db.session,
            ingest_batch_id=batch2.ingest_batch_id,
            privacy_level="basic",
            clickhouse_client=self.ch,
        )
        db.session.commit()
        self.assertEqual(result2["contiguous_batch_ordinal"], 0)

        result1 = derive_privacy_aliases_for_durable_batch(
            session=db.session,
            ingest_batch_id=batch1.ingest_batch_id,
            privacy_level="basic",
            clickhouse_client=self.ch,
        )
        db.session.commit()
        self.assertEqual(result1["contiguous_batch_ordinal"], 2)
        aliases_after_all = PrivacyAlias.query.filter_by(case_id=self.case.id).count()
        self.assertGreaterEqual(aliases_after_all, aliases_after_0)

        retry = derive_privacy_aliases_for_durable_batch(
            session=db.session,
            ingest_batch_id=batch0.ingest_batch_id,
            privacy_level="basic",
            clickhouse_client=self.ch,
        )
        db.session.commit()
        self.assertEqual(retry["contiguous_batch_ordinal"], 2)
        self.assertEqual(PrivacyAlias.query.filter_by(case_id=self.case.id).count(), aliases_after_all)
        self.assertEqual(CaseCapabilityBatchCompletion.query.count(), 3)
        self.assertEqual(retry["state_version"], result1["state_version"])

        erks = [event.evidence_record_key for event in slices[0] if event.evidence_record_key]
        self.assertTrue(erks)
        erk_coverage = verify_capability_erk_coverage(
            db.session,
            self.ch,
            case_id=self.case.id,
            capability=CapabilityName.PRIVACY_ALIASES,
            derivation_version=PRIVACY_ALIASES_V1,
            evidence_record_keys=erks,
        )
        self.assertTrue(erk_coverage.covered)
        batch_coverage = verify_capability_batch_coverage(
            db.session,
            capability=CapabilityName.PRIVACY_ALIASES,
            derivation_version=PRIVACY_ALIASES_V1,
            batch_ids=[manifest0.ingest_batch_id],
        )
        self.assertTrue(batch_coverage.covered)

    def test_d2_does_not_mark_capability_complete_then_late_hole_advances(self):
        generation = self._generation()
        slices = [self.events[0:4], self.events[4:8], self.events[8:11]]
        batch0, _m0 = self._ingest_batch(generation, slices[0], batch_ordinal=0)
        batch1, manifest1 = self._ingest_batch(generation, slices[1], batch_ordinal=1, durable=False)
        batch2, _m2 = self._ingest_batch(generation, slices[2], batch_ordinal=2)
        derive_privacy_aliases_for_durable_batch(
            session=db.session,
            ingest_batch_id=batch0.ingest_batch_id,
            privacy_level="basic",
            clickhouse_client=self.ch,
        )
        derive_privacy_aliases_for_durable_batch(
            session=db.session,
            ingest_batch_id=batch2.ingest_batch_id,
            privacy_level="basic",
            clickhouse_client=self.ch,
        )
        db.session.commit()
        watermark = CaseCapabilitySourceState.query.one()
        self.assertEqual(watermark.contiguous_batch_ordinal, 0)
        self.assertEqual(CaseCapabilityBatchCompletion.query.count(), 2)

        finish_attempt = IngestAttempt.query.filter_by(ingest_attempt_id=batch1.ingest_attempt_id).one()
        finish_attempt.status = "FAILED"
        finish_attempt.lease_expires_at = datetime.utcnow() - timedelta(seconds=1)
        db.session.commit()
        result = reconcile_staged_batch(session=db.session, clickhouse_client=self.ch, ingest_batch_id=manifest1.ingest_batch_id)
        self.assertEqual(result.action_taken, "mark_durable")
        db.session.expire_all()
        self.assertEqual(db.session.get(IngestBatch, batch1.id).state, IngestBatchState.DURABLE)
        self.assertEqual(CaseCapabilityBatchCompletion.query.count(), 2)
        self.assertEqual(CaseCapabilitySourceState.query.one().contiguous_batch_ordinal, 0)

        derive_privacy_aliases_for_durable_batch(
            session=db.session,
            ingest_batch_id=batch1.ingest_batch_id,
            privacy_level="basic",
            clickhouse_client=self.ch,
        )
        db.session.commit()
        self.assertEqual(CaseCapabilitySourceState.query.one().contiguous_batch_ordinal, 2)
