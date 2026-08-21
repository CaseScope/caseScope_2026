from __future__ import annotations

import os
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

os.environ.setdefault("SECRET_KEY", "phase1b-f1-test-secret")

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
    CaseCompletionReconciliationAudit,
    CaseIngestComposition,
    EvidenceGenerationAudit,
    EvidenceGenerationState,
    EvidenceSourceGeneration,
    IngestAttempt,
    IngestBatch,
    IngestBatchReconciliationAudit,
    IngestBatchState,
    ReconciliationAssessment,
)
from models.graph import GraphProjectionState
from models.graph_saved_view import GraphSavedView
from models.investigation_thread import InvestigationThread
from models.privacy_alias import PrivacyAlias, PrivacyAliasCounter
from parsers.base import BaseParser, ParsedEvent
from parsers.log_parsers import IISLogParser
from utils.capability_watermarks import (
    CAPABILITY_INVENTORY,
    LOCKED_CAPABILITY_NAMES,
    PRIVACY_ALIASES_V1,
    record_capability_batch_completion,
)
from sqlalchemy.exc import OperationalError, ProgrammingError
from utils.completion_reconciler import (
    COMPLETION_DERIVATION_INVENTORY,
    CompletionCompositionUnknown,
    ReconciliationHooks,
    classify_case_ingest_composition,
    completion_derivation_inventory,
    managed_destructive_completion_forbidden,
    maybe_schedule_case_completion_reconciliation,
    reconcile_case_completion,
    resolve_case_completion_route,
)
from utils.event_deduplication import (
    ManagedEvidenceAuthorityUnavailable,
    ManagedEvidenceDedupForbidden,
    case_has_managed_source_generations,
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


class _F1Parser(BaseParser):
    supports_manifest_protocol = True
    manifest_ordering_contract = "f1:fixture-order:v1"
    VERSION = "1.0.0"

    def __init__(self, *args, events=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._events = list(events or [])

    @property
    def artifact_type(self):
        return "f1_fixture"

    def can_parse(self, _file_path):
        return True

    def parse(self, _file_path):
        return iter(self._events)

    def manifest_producer_version(self):
        return "f1-parser:v1"


class Phase1BF1ContractUnitTestCase(unittest.TestCase):
    def test_derivation_inventory_covers_locked_capabilities(self):
        inventory = {item["name"] for item in completion_derivation_inventory()}
        self.assertIn("privacy_aliases", inventory)
        self.assertIn("ioc_matches", inventory)
        self.assertIn("mitre_matches", inventory)
        self.assertIn("graph_extraction", inventory)
        self.assertIn("known_user_discovery", inventory)
        self.assertIn("known_system_discovery", inventory)
        self.assertIn("behavioral_profiles", inventory)
        self.assertIn("pattern_detection", inventory)
        self.assertIn("event_embeddings", inventory)
        privacy = next(item for item in COMPLETION_DERIVATION_INVENTORY if item["name"] == "privacy_aliases")
        self.assertTrue(privacy["capability_watermark_migration"])
        self.assertTrue(privacy["f1_can_inspect_completion"])
        for item in COMPLETION_DERIVATION_INVENTORY:
            if item["name"] != "privacy_aliases":
                self.assertFalse(item["capability_watermark_migration"], item["name"])

    def test_unmigrated_capabilities_remain_not_e1(self):
        self.assertEqual(set(CAPABILITY_INVENTORY), set(LOCKED_CAPABILITY_NAMES))
        self.assertTrue(CAPABILITY_INVENTORY["privacy_aliases"]["e1_migrated"])
        for name, spec in CAPABILITY_INVENTORY.items():
            if name != "privacy_aliases":
                self.assertFalse(spec["e1_migrated"], name)

    def test_managed_destructive_completion_forbidden(self):
        self.assertFalse(managed_destructive_completion_forbidden(CaseIngestComposition.LEGACY_ONLY))
        self.assertTrue(managed_destructive_completion_forbidden(CaseIngestComposition.MANAGED_ONLY))
        self.assertTrue(managed_destructive_completion_forbidden(CaseIngestComposition.MIXED))

    def test_schedule_is_disabled_under_pytest_unless_forced(self):
        calls = []
        result = maybe_schedule_case_completion_reconciliation(
            case_id=1,
            case_uuid="abc",
            reason="batch_durable",
            scheduler=lambda *args: calls.append(args) or "task-1",
        )
        self.assertIsNone(result)
        self.assertEqual(calls, [])
        result = maybe_schedule_case_completion_reconciliation(
            case_id=1,
            case_uuid="abc",
            reason="batch_durable",
            force=True,
            scheduler=lambda *args: calls.append(args) or "task-1",
        )
        self.assertEqual(result, "task-1")
        self.assertEqual(calls, [(1, "abc", "batch_durable")])


@unittest.skipUnless(PG_URL, "PHASE1B_PG_TEST_DATABASE_URL is required")
class Phase1BF1RealPGTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        install_memory_backend()
        cls.app = Flask(__name__)
        cls.app.config.update(
            SQLALCHEMY_DATABASE_URI=PG_URL,
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            SECRET_KEY="phase1b-f1-real",
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
            CaseCompletionReconciliationAudit.__table__,
            GraphProjectionState.__table__,
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
        reset_fence_backend()

    def setUp(self):
        self.session = self.Session()
        self.session.query(CaseCompletionReconciliationAudit).delete()
        self.session.query(GraphProjectionState).delete()
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
        self.client = Client(name="F1 Real", code=f"F1R{time.time_ns() % 100000}", created_by="tester")
        self.case = Case(uuid=f"f1-real-{time.time_ns()}", name="F1 Real", company="Example", client=self.client, created_by="tester")
        self.case_file = CaseFile(
            case_uuid=self.case.uuid,
            filename="f1-real.log",
            original_filename="f1-real.log",
            file_path="/tmp/f1-real.log",
            file_size=1,
            sha256_hash="7" * 64,
            uploaded_by="tester",
            ingest_protocol_origin=IngestProtocolOrigin.NOT_STARTED,
        )
        self.session.add_all([self.client, self.case, self.case_file])
        self.session.commit()
        parser = _F1Parser(case_id=self.case.id, case_file_id=self.case_file.id)
        self.contract = ManifestParserContract(
            parser_version=parser.parser_version,
            normalization_version="normalization:v1",
            configured_batch_size=2,
            ordering_contract="f1:fixture-order:v1",
            producer_version="f1-parser:v1",
            manifest_eligible=True,
        )
        self.privacy_calls = []
        self.d2_calls = []

    def tearDown(self):
        self.session.close()
        self.Session.remove()

    def _event(self, generation_number, record_id):
        return ParsedEvent(
            case_id=self.case.id,
            artifact_type="f1_fixture",
            timestamp=datetime(2026, 1, 1) + timedelta(seconds=record_id),
            timestamp_utc=datetime(2026, 1, 1) + timedelta(seconds=record_id),
            timestamp_source_tz="UTC",
            source_file="f1-real.log",
            source_path="/tmp/f1-real.log",
            source_host="F1HOST",
            case_file_id=self.case_file.id,
            event_id=f"{generation_number}-{record_id}",
            record_id=record_id,
            username=f"user{record_id}",
            command_line=f"generation {generation_number} record {record_id}",
            raw_json=f'{{"generation":{generation_number},"record_id":{record_id}}}',
            search_blob=f"generation {generation_number} record {record_id} user{record_id}",
            parser_version="F1Parser-1.0.0",
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
        else:
            attempt.status = "FAILED"
            attempt.finished_at = datetime.utcnow()
            attempt.lease_expires_at = datetime.utcnow() - timedelta(seconds=1)
        self.session.commit()
        return batch

    def _complete_privacy(self, batch):
        generation = batch.generation
        return record_capability_batch_completion(
            session=self.session,
            case_id=generation.case_id,
            capability=CapabilityName.PRIVACY_ALIASES,
            source_ref_type=generation.source_ref_type,
            source_ref_id=generation.source_ref_id,
            source_generation=generation.source_generation,
            derivation_version=PRIVACY_ALIASES_V1,
            ingest_batch_id=batch.ingest_batch_id,
        )

    def _hooks(self, **overrides):
        def privacy(_session, ingest_batch_id):
            self.privacy_calls.append(ingest_batch_id)

        def d2(ingest_batch_id):
            self.d2_calls.append(ingest_batch_id)

        kwargs = {
            "privacy_executor": privacy,
            "d2_invoker": d2,
        }
        kwargs.update(overrides)
        return ReconciliationHooks(**kwargs)

    def _reconcile(self, **overrides):
        return reconcile_case_completion(
            session=self.session,
            case_id=self.case.id,
            case_uuid=self.case.uuid,
            trigger_reason=overrides.pop("trigger_reason", "test"),
            hooks=overrides.pop("hooks", None) or self._hooks(),
            **overrides,
        )

    def test_legacy_only_preserves_route_and_does_not_queue_privacy(self):
        self.session.query(EvidenceSourceGeneration).delete()
        self.case_file.ingest_protocol_origin = IngestProtocolOrigin.LEGACY_OR_UNKNOWN
        self.session.commit()
        composition = classify_case_ingest_composition(
            self.session, case_id=self.case.id, case_uuid=self.case.uuid
        )
        self.assertEqual(composition, CaseIngestComposition.LEGACY_ONLY)
        result = self._reconcile()
        self.assertEqual(result.composition, CaseIngestComposition.LEGACY_ONLY)
        self.assertEqual(self.privacy_calls, [])
        self.assertEqual(self.d2_calls, [])
        self.assertFalse(managed_destructive_completion_forbidden(result.composition))

    def test_managed_only_missing_privacy_is_queued_and_completed_is_not(self):
        generation = self._generation()
        batch0 = self._durable_batch(generation, [self._event(1, 1), self._event(1, 2)], batch_ordinal=0)
        batch1 = self._durable_batch(generation, [self._event(1, 3), self._event(1, 4)], batch_ordinal=1)
        self._complete_privacy(batch0)
        self.session.commit()
        result = self._reconcile()
        self.assertEqual(result.composition, CaseIngestComposition.MANAGED_ONLY)
        self.assertEqual(self.privacy_calls, [batch1.ingest_batch_id])
        self.assertNotIn(batch0.ingest_batch_id, self.privacy_calls)
        self.assertEqual(result.assessment, ReconciliationAssessment.WORK_QUEUED)
        self.assertTrue(any(item["kind"] == "privacy_aliases" for item in result.work_queued))
        self.assertIsNotNone(result.audit_id)

    def test_staged_batch_hands_off_to_d2_not_privacy(self):
        generation = self._generation()
        durable = self._durable_batch(generation, [self._event(1, 1), self._event(1, 2)], batch_ordinal=0)
        staged = self._durable_batch(
            generation, [self._event(1, 3), self._event(1, 4)], batch_ordinal=1, durable=False
        )
        self._complete_privacy(durable)
        self.session.commit()
        result = self._reconcile()
        self.assertEqual(self.privacy_calls, [])
        self.assertEqual(self.d2_calls, [staged.ingest_batch_id])
        self.assertTrue(any(item["ingest_batch_id"] == staged.ingest_batch_id for item in result.d2_gaps))
        self.assertIn(result.assessment, {
            ReconciliationAssessment.WORK_QUEUED,
            ReconciliationAssessment.INCOMPLETE_INGEST,
        })

    def test_building_initial_progressive_and_active_current(self):
        generation = self._generation()
        batch0 = self._durable_batch(generation, [self._event(1, 1), self._event(1, 2)], batch_ordinal=0)
        result = self._reconcile()
        self.assertEqual(generation.visibility_state, EvidenceGenerationState.BUILDING_INITIAL)
        self.assertEqual(self.privacy_calls, [batch0.ingest_batch_id])
        self.assertEqual(result.readiness["sources"][0]["publishable"], True)
        self._complete_privacy(batch0)
        declare_generation_ingest_complete(
            session=self.session,
            generation=generation,
            expected_rows=2,
            final_batch_ordinal=0,
        )
        activate_initial_generation(session=self.session, generation=generation)
        self.session.commit()
        self.privacy_calls.clear()
        result = self._reconcile()
        self.assertEqual(self.privacy_calls, [])
        self.assertEqual(
            self.session.get(EvidenceSourceGeneration, generation.id).visibility_state,
            EvidenceGenerationState.ACTIVE,
        )
        self.assertEqual(result.readiness["sources"][0]["is_default_authority"], True)

    def test_building_replacement_hidden_from_default_and_zero_event(self):
        initial = self._generation()
        batch_n = self._durable_batch(initial, [self._event(1, 1), self._event(1, 2)])
        self._complete_privacy(batch_n)
        declare_generation_ingest_complete(session=self.session, generation=initial, expected_rows=2, final_batch_ordinal=0)
        activate_initial_generation(session=self.session, generation=initial)
        self.session.commit()
        replacement = allocate_case_file_replacement_generation(
            session=self.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        batch_r = self._durable_batch(replacement, [self._event(2, 1), self._event(2, 2)])
        result = self._reconcile()
        self.assertEqual(self.privacy_calls, [batch_r.ingest_batch_id])
        replacement_ready = next(
            row for row in result.readiness["sources"] if row["source_generation"] == replacement.source_generation
        )
        active_ready = next(
            row for row in result.readiness["sources"] if row["source_generation"] == initial.source_generation
        )
        self.assertFalse(replacement_ready["is_default_authority"])
        self.assertFalse(replacement_ready["publishable"])
        self.assertTrue(active_ready["is_default_authority"])

        zero_file = CaseFile(
            case_uuid=self.case.uuid,
            filename="empty.log",
            original_filename="empty.log",
            file_path="/tmp/empty.log",
            file_size=1,
            sha256_hash="8" * 64,
            uploaded_by="tester",
            ingest_protocol_origin=IngestProtocolOrigin.NOT_STARTED,
        )
        self.session.add(zero_file)
        self.session.commit()
        zero_gen = allocate_case_file_initial_generation(
            session=self.session,
            case_id=self.case.id,
            case_file_id=zero_file.id,
            contract=self.contract,
        )
        declare_generation_ingest_complete(
            session=self.session,
            generation=zero_gen,
            expected_rows=0,
            final_batch_ordinal=None,
        )
        self.session.commit()
        before_batches = self.session.query(IngestBatch).count()
        result = self._reconcile()
        self.assertEqual(self.session.query(IngestBatch).count(), before_batches)
        watermark = (
            self.session.query(CaseCapabilitySourceState)
            .filter_by(source_ref_id=str(zero_file.id), capability=CapabilityName.PRIVACY_ALIASES)
            .one()
        )
        self.assertEqual(watermark.status, CapabilityWatermarkStatus.COMPLETE)
        self.assertIsNone(watermark.contiguous_batch_ordinal)

    def test_invalidated_failed_not_requeued(self):
        generation = self._generation()
        self._durable_batch(generation, [self._event(1, 1), self._event(1, 2)])
        invalidate_source_generation(session=self.session, generation=generation, reason="f1-test")
        self.session.commit()
        result = self._reconcile()
        self.assertEqual(self.privacy_calls, [])
        self.assertTrue(any(item.get("action") == "skip_terminal" for item in result.derivations_checked))

    def test_replacement_activation_race_revalidates_authority(self):
        initial = self._generation()
        batch_n = self._durable_batch(initial, [self._event(1, 1), self._event(1, 2)])
        self._complete_privacy(batch_n)
        declare_generation_ingest_complete(session=self.session, generation=initial, expected_rows=2, final_batch_ordinal=0)
        activate_initial_generation(session=self.session, generation=initial)
        replacement = allocate_case_file_replacement_generation(
            session=self.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        self._durable_batch(replacement, [self._event(2, 1), self._event(2, 2)])
        declare_generation_ingest_complete(
            session=self.session, generation=replacement, expected_rows=2, final_batch_ordinal=0
        )
        self.session.commit()

        def activate_during_privacy(session, ingest_batch_id):
            activate_replacement_generation(session=session, replacement=replacement)
            self.privacy_calls.append(ingest_batch_id)

        result = reconcile_case_completion(
            session=self.session,
            case_id=self.case.id,
            case_uuid=self.case.uuid,
            trigger_reason="replacement_race",
            hooks=self._hooks(privacy_executor=activate_during_privacy),
        )
        self.assertTrue(result.authority_changed or result.assessment == ReconciliationAssessment.BLOCKED)
        self.assertTrue(
            any(item.get("kind") == "authority_changed" for item in result.unresolved_conflicts)
            or result.authority_changed
        )
        self.assertEqual(
            self.session.get(EvidenceSourceGeneration, replacement.id).visibility_state,
            EvidenceGenerationState.ACTIVE,
        )
        later = self._reconcile()
        default_sources = [row for row in later.readiness["sources"] if row["is_default_authority"]]
        self.assertEqual(len(default_sources), 1)
        self.assertEqual(default_sources[0]["source_generation"], replacement.source_generation)

    def test_active_staged_is_blocked_not_silently_fixed(self):
        generation = self._generation(state=EvidenceGenerationState.ACTIVE)
        generation.completed_at = datetime.utcnow()
        generation.expected_rows = 2
        generation.final_batch_ordinal = 0
        staged = self._durable_batch(generation, [self._event(1, 1), self._event(1, 2)], durable=False)
        self.session.commit()
        result = self._reconcile()
        self.assertEqual(result.assessment, ReconciliationAssessment.BLOCKED)
        self.assertEqual(self.d2_calls, [])
        self.assertTrue(any(item["kind"] == "active_generation_staged_batch" for item in result.unresolved_conflicts))
        self.assertEqual(self.session.get(IngestBatch, staged.id).state, IngestBatchState.STAGED)

    def test_redis_loss_and_idempotent_repeat(self):
        generation = self._generation()
        batch0 = self._durable_batch(generation, [self._event(1, 1), self._event(1, 2)], batch_ordinal=0)
        batch1 = self._durable_batch(generation, [self._event(1, 3), self._event(1, 4)], batch_ordinal=1)
        self._complete_privacy(batch0)
        self._complete_privacy(batch1)
        declare_generation_ingest_complete(session=self.session, generation=generation, expected_rows=4, final_batch_ordinal=1)
        activate_initial_generation(session=self.session, generation=generation)
        self.session.add(
            GraphProjectionState(
                case_id=self.case.id,
                case_uuid=self.case.uuid,
                status="completed",
                mode="ingest",
            )
        )
        self.session.commit()
        with patch("utils.progress.get_redis_client", side_effect=RuntimeError("redis gone")):
            first = self._reconcile(trigger_reason="redis_loss")
            second = self._reconcile(trigger_reason="redis_loss_repeat")
            third = self._reconcile(trigger_reason="redis_loss_repeat2")
        self.assertEqual(first.privacy_calls if hasattr(first, "privacy_calls") else self.privacy_calls, [])
        self.assertEqual(self.privacy_calls, [])
        self.assertEqual(self.d2_calls, [])
        self.assertEqual(first.assessment, ReconciliationAssessment.RECONCILED)
        self.assertEqual(second.assessment, ReconciliationAssessment.RECONCILED)
        self.assertEqual(third.assessment, ReconciliationAssessment.RECONCILED)
        self.assertEqual(first.batch_counts["durable"], 2)
        self.assertFalse(any(item["kind"] == "privacy_aliases" for item in second.work_queued))
        self.assertGreaterEqual(self.session.query(CaseCompletionReconciliationAudit).count(), 3)
        self.assertLess(first.metrics["pg_rows_loaded"], 1000)

    def test_concurrent_reconciliation_converges(self):
        generation = self._generation()
        self._durable_batch(generation, [self._event(1, 1), self._event(1, 2)])
        self.session.commit()
        errors = []
        queued = []

        def worker():
            session = self.Session()
            try:
                def privacy(current_session, ingest_batch_id):
                    record_capability_batch_completion(
                        session=current_session,
                        case_id=self.case.id,
                        capability=CapabilityName.PRIVACY_ALIASES,
                        source_ref_type=generation.source_ref_type,
                        source_ref_id=generation.source_ref_id,
                        source_generation=generation.source_generation,
                        derivation_version=PRIVACY_ALIASES_V1,
                        ingest_batch_id=ingest_batch_id,
                    )
                    queued.append(ingest_batch_id)

                reconcile_case_completion(
                    session=session,
                    case_id=self.case.id,
                    case_uuid=self.case.uuid,
                    trigger_reason="concurrent",
                    hooks=ReconciliationHooks(privacy_executor=privacy),
                )
            except Exception as exc:
                errors.append(exc)
            finally:
                session.close()

        threads = [threading.Thread(target=worker), threading.Thread(target=worker)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(self.session.query(CaseCapabilityBatchCompletion).count(), 1)
        self.assertGreaterEqual(self.session.query(CaseCompletionReconciliationAudit).count(), 2)

    def test_mixed_case_refuses_case_wide_dedup(self):
        generation = self._generation()
        self._durable_batch(generation, [self._event(1, 1), self._event(1, 2)])
        legacy = CaseFile(
            case_uuid=self.case.uuid,
            filename="legacy.evtx",
            original_filename="legacy.evtx",
            file_path="/tmp/legacy.evtx",
            file_size=1,
            sha256_hash="9" * 64,
            uploaded_by="tester",
            ingest_protocol_origin=IngestProtocolOrigin.LEGACY_OR_UNKNOWN,
        )
        self.session.add(legacy)
        self.session.commit()
        composition = resolve_case_completion_route(
            self.session, case_id=self.case.id, case_uuid=self.case.uuid
        )
        self.assertEqual(composition, CaseIngestComposition.MIXED)
        self.assertTrue(managed_destructive_completion_forbidden(composition))
        db.session.remove()
        self.assertTrue(case_has_managed_source_generations(self.case.id))
        from utils.event_deduplication import deduplicate_case_events
        with self.assertRaises(ManagedEvidenceDedupForbidden):
            deduplicate_case_events(case_id=self.case.id, case_uuid=self.case.uuid)
        result = self._reconcile()
        self.assertEqual(result.composition, CaseIngestComposition.MIXED)

    def test_new_source_during_reconciliation_does_not_latch_complete(self):
        generation = self._generation()
        self._durable_batch(generation, [self._event(1, 1), self._event(1, 2)])
        self.session.commit()
        extra_file = CaseFile(
            case_uuid=self.case.uuid,
            filename="late.log",
            original_filename="late.log",
            file_path="/tmp/late.log",
            file_size=1,
            sha256_hash="a" * 64,
            uploaded_by="tester",
            ingest_protocol_origin=IngestProtocolOrigin.NOT_STARTED,
        )
        self.session.add(extra_file)
        self.session.commit()

        def privacy_and_add(session, ingest_batch_id):
            allocate_case_file_initial_generation(
                session=session,
                case_id=self.case.id,
                case_file_id=extra_file.id,
                contract=self.contract,
            )

        result = reconcile_case_completion(
            session=self.session,
            case_id=self.case.id,
            case_uuid=self.case.uuid,
            trigger_reason="new_source_race",
            hooks=self._hooks(privacy_executor=privacy_and_add),
        )
        self.assertNotIn(result.assessment, {ReconciliationAssessment.RECONCILED})
        later = self._reconcile()
        self.assertEqual(later.batch_counts["generations"], 2)
        self.assertIsNone(later.readiness.get("case_ready"))

    def _failing_query(self, target_model, exc):
        original = self.session.query

        def _query(model, *args, **kwargs):
            if model is target_model:
                raise exc
            return original(model, *args, **kwargs)

        return _query

    def test_classification_pg_failure_is_not_legacy_only(self):
        self._generation()
        self.session.commit()
        with patch.object(
            self.session,
            "query",
            side_effect=self._failing_query(
                EvidenceSourceGeneration,
                OperationalError("SELECT", {}, Exception("pg down")),
            ),
        ):
            with self.assertRaises(CompletionCompositionUnknown):
                resolve_case_completion_route(
                    self.session, case_id=self.case.id, case_uuid=self.case.uuid
                )

    def test_casefile_query_failure_fails_closed(self):
        self._generation()
        self.session.commit()
        with patch.object(
            self.session,
            "query",
            side_effect=self._failing_query(
                CaseFile,
                OperationalError("SELECT", {}, Exception("case_files down")),
            ),
        ):
            with self.assertRaises(CompletionCompositionUnknown) as raised:
                classify_case_ingest_composition(
                    self.session, case_id=self.case.id, case_uuid=self.case.uuid
                )
        self.assertNotEqual(raised.exception.args[0], CaseIngestComposition.MANAGED_ONLY)
        self.assertNotEqual(raised.exception.args[0], CaseIngestComposition.LEGACY_ONLY)

    def test_missing_generation_table_is_not_legacy(self):
        self._generation()
        self.session.commit()
        case_id = int(self.case.id)
        case_uuid = str(self.case.uuid)
        self.session.close()
        with self.engine.begin() as conn:
            conn.execute(text("ALTER TABLE evidence_source_generations RENAME TO evidence_source_generations_hidden"))
        try:
            session = self.Session()
            try:
                with self.assertRaises(CompletionCompositionUnknown):
                    resolve_case_completion_route(
                        session, case_id=case_id, case_uuid=case_uuid
                    )
            finally:
                session.close()
            db.session.remove()
            with self.assertRaises(ManagedEvidenceAuthorityUnavailable):
                case_has_managed_source_generations(case_id)
        finally:
            with self.engine.begin() as conn:
                conn.execute(text(
                    "ALTER TABLE IF EXISTS evidence_source_generations_hidden "
                    "RENAME TO evidence_source_generations"
                ))
            db.session.remove()

    def test_proven_legacy_only_route_remains_available(self):
        self.session.query(EvidenceSourceGeneration).delete()
        self.case_file.ingest_protocol_origin = IngestProtocolOrigin.LEGACY_OR_UNKNOWN
        self.session.commit()
        composition = resolve_case_completion_route(
            self.session, case_id=self.case.id, case_uuid=self.case.uuid
        )
        self.assertEqual(composition, CaseIngestComposition.LEGACY_ONLY)
        self.assertFalse(managed_destructive_completion_forbidden(composition))
        db.session.remove()
        self.assertFalse(case_has_managed_source_generations(self.case.id))

    def test_proven_managed_only_route_is_durable(self):
        self._generation()
        self.session.commit()
        composition = resolve_case_completion_route(
            self.session, case_id=self.case.id, case_uuid=self.case.uuid
        )
        self.assertEqual(composition, CaseIngestComposition.MANAGED_ONLY)
        self.assertTrue(managed_destructive_completion_forbidden(composition))

    def test_redis_complete_cannot_override_pg_authority_failure(self):
        self._generation()
        self.session.commit()
        with patch("utils.progress.get_redis_client") as redis_factory:
            redis_factory.return_value.get.return_value = "complete"
            with patch.object(
                self.session,
                "query",
                side_effect=self._failing_query(
                    EvidenceSourceGeneration,
                    OperationalError("SELECT", {}, Exception("pg down")),
                ),
            ):
                with self.assertRaises(CompletionCompositionUnknown):
                    resolve_case_completion_route(
                        self.session, case_id=self.case.id, case_uuid=self.case.uuid
                    )


@unittest.skipUnless(PG_URL and CH_DB, "PHASE1B_PG_TEST_DATABASE_URL and PHASE1B_CH_TEST_DATABASE are required")
class Phase1BF1RealPGCHTestCase(unittest.TestCase):
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
            SECRET_KEY="phase1b-f1-ch",
        )
        db.init_app(cls.app)
        cls.ctx = cls.app.app_context()
        cls.ctx.push()
        db.session.remove()
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
            CaseCompletionReconciliationAudit.__table__,
            PrivacyAlias.__table__,
            PrivacyAliasCounter.__table__,
            GraphProjectionState.__table__,
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
        GraphProjectionState.query.delete()
        CaseCompletionReconciliationAudit.query.delete()
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
        self.client = Client(name="F1 CH", code=f"F1C{time.time_ns() % 100000}", created_by="tester")
        self.case = Case(uuid=f"f1-ch-{time.time_ns()}", name="F1 CH", company="Example", client=self.client, created_by="tester")
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
            sha256_hash="b" * 64,
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
        self.privacy_calls = []
        self.d2_calls = []

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
        else:
            attempt.status = "FAILED"
            attempt.finished_at = datetime.utcnow()
            attempt.lease_expires_at = datetime.utcnow() - timedelta(seconds=1)
            db.session.commit()
        return batch, manifest

    def _hooks(self):
        def privacy(session, ingest_batch_id):
            self.privacy_calls.append(ingest_batch_id)
            derive_privacy_aliases_for_durable_batch(
                session=session,
                ingest_batch_id=ingest_batch_id,
                privacy_level="basic",
                clickhouse_client=self.ch,
            )

        def d2(ingest_batch_id):
            self.d2_calls.append(ingest_batch_id)
            reconcile_staged_batch(
                session=db.session,
                clickhouse_client=self.ch,
                ingest_batch_id=ingest_batch_id,
            )

        return ReconciliationHooks(privacy_executor=privacy, d2_invoker=d2)

    def test_iis_three_batch_reconciliation_pilot(self):
        generation = self._generation()
        slices = [self.events[0:4], self.events[4:8], self.events[8:11]]
        batch0, _m0 = self._ingest_batch(generation, slices[0], batch_ordinal=0)
        batch1, _m1 = self._ingest_batch(generation, slices[1], batch_ordinal=1)
        batch2, _m2 = self._ingest_batch(generation, slices[2], batch_ordinal=2, durable=False)
        derive_privacy_aliases_for_durable_batch(
            session=db.session,
            ingest_batch_id=batch0.ingest_batch_id,
            privacy_level="basic",
            clickhouse_client=self.ch,
        )
        db.session.commit()
        before_aliases = PrivacyAlias.query.filter_by(case_id=self.case.id).count()
        started = time.perf_counter()
        result = reconcile_case_completion(
            session=db.session,
            case_id=self.case.id,
            case_uuid=self.case.uuid,
            trigger_reason="iis_pilot",
            hooks=self._hooks(),
        )
        duration_ms = (time.perf_counter() - started) * 1000.0
        self.assertEqual(self.privacy_calls, [batch1.ingest_batch_id])
        self.assertEqual(self.d2_calls, [batch2.ingest_batch_id])
        self.assertEqual(db.session.get(IngestBatch, batch2.id).state, IngestBatchState.DURABLE)
        self.assertGreaterEqual(PrivacyAlias.query.filter_by(case_id=self.case.id).count(), before_aliases)
        self.assertEqual(CaseCapabilityBatchCompletion.query.count(), 2)
        self.assertNotEqual(result.assessment, ReconciliationAssessment.RECONCILED)
        self.assertIsNone(result.readiness.get("ready"))
        self.assertLess(duration_ms, 15000)
        self.assertLess(result.metrics["pg_rows_loaded"], 100)

        self.privacy_calls.clear()
        self.d2_calls.clear()
        reconcile_case_completion(
            session=db.session,
            case_id=self.case.id,
            case_uuid=self.case.uuid,
            trigger_reason="iis_pilot_after_d2",
            hooks=self._hooks(),
        )
        self.assertEqual(self.privacy_calls, [batch2.ingest_batch_id])
        self.assertEqual(self.d2_calls, [])
        self.assertEqual(CaseCapabilityBatchCompletion.query.count(), 3)

        self.privacy_calls.clear()
        result3 = reconcile_case_completion(
            session=db.session,
            case_id=self.case.id,
            case_uuid=self.case.uuid,
            trigger_reason="iis_pilot_idempotent",
            hooks=self._hooks(),
        )
        self.assertEqual(self.privacy_calls, [])
        self.assertEqual(self.d2_calls, [])
        self.assertEqual(CaseCapabilityBatchCompletion.query.count(), 3)
        self.assertFalse(any(item["kind"] == "privacy_aliases" for item in result3.work_queued))

    def test_old_generation_evidence_survives_reconciliation(self):
        generation = self._generation()
        slices = [self.events[0:4], self.events[4:8]]
        batch0, _m0 = self._ingest_batch(generation, slices[0], batch_ordinal=0)
        derive_privacy_aliases_for_durable_batch(
            session=db.session,
            ingest_batch_id=batch0.ingest_batch_id,
            privacy_level="basic",
            clickhouse_client=self.ch,
        )
        declare_generation_ingest_complete(session=db.session, generation=generation, expected_rows=4, final_batch_ordinal=0)
        activate_initial_generation(session=db.session, generation=generation)
        db.session.commit()
        before = self.ch.query(
            "SELECT count() FROM events WHERE case_id = {case_id:UInt32} AND source_generation = 1",
            parameters={"case_id": self.case.id},
        ).result_rows[0][0]
        self.assertGreater(before, 0)
        reconcile_case_completion(
            session=db.session,
            case_id=self.case.id,
            case_uuid=self.case.uuid,
            trigger_reason="survival",
            hooks=self._hooks(),
        )
        after = self.ch.query(
            "SELECT count() FROM events WHERE case_id = {case_id:UInt32} AND source_generation = 1",
            parameters={"case_id": self.case.id},
        ).result_rows[0][0]
        self.assertEqual(before, after)

    def test_managed_completion_task_skips_legacy_destructive_paths(self):
        generation = self._generation()
        batch0, _m0 = self._ingest_batch(generation, self.events[0:4], batch_ordinal=0)
        derive_privacy_aliases_for_durable_batch(
            session=db.session,
            ingest_batch_id=batch0.ingest_batch_id,
            privacy_level="basic",
            clickhouse_client=self.ch,
        )
        db.session.commit()

        def raise_if_called(*_args, **_kwargs):
            raise AssertionError("legacy destructive completion path invoked")

        from tasks import celery_tasks as celery_mod

        with patch.object(celery_mod, "get_flask_app", return_value=self.app), \
             patch.object(celery_mod, "exclusive_ingest_fence", raise_if_called), \
             patch("utils.event_deduplication.deduplicate_case_events", raise_if_called), \
             patch("utils.progress.clear_progress"), \
             patch("utils.completion_reconciler.default_production_hooks", return_value=ReconciliationHooks()), \
             patch.object(celery_mod, "_build_case_ingest_summary", return_value={}):
            result = celery_mod._run_durable_completion_reconciliation(
                self.case.id,
                self.case.uuid,
                trigger_reason="tripwire",
            )
        self.assertTrue(result["legacy_destructive_skipped"])
        self.assertEqual(result["route"], CaseIngestComposition.MANAGED_ONLY)
        self.assertEqual(result["buffer_flush_status"], "not_required_managed")

    def _insert_json_log_duplicates(self):
        ts = datetime(2026, 1, 1, 0, 0, 0)
        earlier = datetime(2026, 1, 1, 0, 0, 1)
        later = datetime(2026, 1, 1, 0, 0, 2)
        self.ch.insert(
            "events",
            [
                [self.case.id, "json_log", ts, ts, "dup.log", "e-dup", earlier],
                [self.case.id, "json_log", ts, ts, "dup.log", "e-dup", later],
            ],
            column_names=[
                "case_id",
                "artifact_type",
                "timestamp",
                "timestamp_utc",
                "source_file",
                "event_id",
                "indexed_at",
            ],
        )

    def test_direct_dedup_legacy_still_operates(self):
        self.case_file.ingest_protocol_origin = IngestProtocolOrigin.LEGACY_OR_UNKNOWN
        db.session.commit()
        self._insert_json_log_duplicates()
        from utils.event_deduplication import deduplicate_case_events
        with patch("utils.clickhouse.get_fresh_client", return_value=self.ch):
            result = deduplicate_case_events(
                case_id=self.case.id,
                case_uuid=self.case.uuid,
                track_progress=False,
                allow_managed_evidence=False,
            )
        self.assertTrue(result["success"])
        remaining = self.ch.query(
            "SELECT count() FROM events WHERE case_id = {case_id:UInt32}",
            parameters={"case_id": self.case.id},
        ).result_rows[0][0]
        self.assertEqual(remaining, 1)

    def test_direct_dedup_managed_is_blocked(self):
        self._generation()
        self._insert_json_log_duplicates()
        before = self.ch.query(
            "SELECT count() FROM events WHERE case_id = {case_id:UInt32}",
            parameters={"case_id": self.case.id},
        ).result_rows[0][0]
        capturing = _CapturingClickHouse()
        from utils.event_deduplication import deduplicate_case_events
        with patch("utils.clickhouse.get_fresh_client", return_value=capturing):
            with self.assertRaises(ManagedEvidenceDedupForbidden):
                deduplicate_case_events(
                    case_id=self.case.id,
                    case_uuid=self.case.uuid,
                    track_progress=False,
                    allow_managed_evidence=False,
                )
        self.assertEqual(capturing.commands, [])
        after = self.ch.query(
            "SELECT count() FROM events WHERE case_id = {case_id:UInt32}",
            parameters={"case_id": self.case.id},
        ).result_rows[0][0]
        self.assertEqual(before, after)

    def test_mixed_case_authority_unavailable_cannot_mutate(self):
        generation = self._generation()
        self._ingest_batch(generation, self.events[0:4], batch_ordinal=0)
        legacy = CaseFile(
            case_uuid=self.case.uuid,
            filename="legacy-closure.evtx",
            original_filename="legacy-closure.evtx",
            file_path="/tmp/legacy-closure.evtx",
            file_size=1,
            sha256_hash="c" * 64,
            uploaded_by="tester",
            ingest_protocol_origin=IngestProtocolOrigin.LEGACY_OR_UNKNOWN,
        )
        db.session.add(legacy)
        db.session.commit()
        composition = resolve_case_completion_route(
            db.session, case_id=self.case.id, case_uuid=self.case.uuid
        )
        self.assertEqual(composition, CaseIngestComposition.MIXED)
        capturing = _CapturingClickHouse()
        from utils.event_deduplication import deduplicate_case_events
        with patch("models.database.db.session.query", side_effect=OperationalError("SELECT", {}, Exception("pg down"))), \
             patch("utils.clickhouse.get_fresh_client", return_value=capturing):
            with self.assertRaises(ManagedEvidenceAuthorityUnavailable):
                deduplicate_case_events(
                    case_id=self.case.id,
                    case_uuid=self.case.uuid,
                    track_progress=False,
                    allow_managed_evidence=False,
                )
        self.assertEqual(capturing.commands, [])
        surviving = self.ch.query(
            "SELECT count() FROM events WHERE case_id = {case_id:UInt32} AND source_generation = 1",
            parameters={"case_id": self.case.id},
        ).result_rows[0][0]
        self.assertGreater(surviving, 0)

    def test_completion_task_pg_failure_does_not_enter_old_tail(self):
        from tasks import celery_tasks as celery_mod

        self._generation()
        db.session.commit()
        invoked = []
        with patch.object(celery_mod, "get_flask_app", return_value=self.app), \
             patch.object(
                 celery_mod,
                 "exclusive_ingest_fence",
                 _raise_if_called("exclusive_ingest_fence", invoked),
             ), \
             patch(
                 "utils.event_deduplication.deduplicate_case_events",
                 _raise_if_called("deduplicate_case_events", invoked),
             ), \
             patch(
                 "utils.known_systems_discovery.discover_known_systems",
                 _raise_if_called("discover_known_systems", invoked),
             ), \
             patch(
                 "utils.known_users_discovery.discover_known_users",
                 _raise_if_called("discover_known_users", invoked),
             ), \
             patch.object(
                 celery_mod,
                 "_queue_post_ingest_mitre_mapping",
                 _raise_if_called("mitre_tail", invoked),
             ), \
             patch.object(
                 celery_mod,
                 "_queue_auto_event_embedding",
                 _raise_if_called("embed_tail", invoked),
             ), \
             patch.object(celery_mod.case_indexing_complete_task, "apply_async"), \
             patch("utils.progress.clear_progress"), \
             patch(
                 "utils.completion_reconciler.resolve_case_completion_route",
                 side_effect=CompletionCompositionUnknown("pg down"),
             ):
            result = celery_mod.case_indexing_complete_task.run(self.case.id, self.case.uuid)
        self.assertEqual(result["status"], "deferred")
        self.assertEqual(result["reason"], "completion_composition_unknown")
        self.assertEqual(invoked, [])


class Phase1BF1RoutingUnitTestCase(unittest.TestCase):
    def test_case_indexing_complete_routes_managed_before_legacy_tail(self):
        from tasks import celery_tasks as celery_mod

        class DummyTask:
            def delay(self, **kwargs):
                return None

        with patch.object(celery_mod, "get_flask_app") as app_factory, \
             patch("utils.completion_reconciler.resolve_case_completion_route", return_value=CaseIngestComposition.MANAGED_ONLY), \
             patch.object(celery_mod, "_run_durable_completion_reconciliation", return_value={"routed": True}) as durable, \
             patch.object(celery_mod, "exclusive_ingest_fence") as fence:
            app_factory.return_value.app_context.return_value = MagicMock()
            # Bind a dummy self
            result = celery_mod.case_indexing_complete_task.run(9, "uuid-f1")
            self.assertEqual(result, {"routed": True})
            durable.assert_called_once()
            fence.assert_not_called()


class _CapturingClickHouse:
    def __init__(self):
        self.commands = []
        self.queries = []

    def command(self, sql, *args, **kwargs):
        self.commands.append(sql)
        raise AssertionError(f"unexpected ClickHouse command: {sql}")

    def query(self, sql, parameters=None, **kwargs):
        self.queries.append((sql, parameters))
        raise AssertionError(f"unexpected ClickHouse query: {sql}")


def _raise_if_called(name, bucket):
    def _inner(*_args, **_kwargs):
        bucket.append(name)
        raise AssertionError(f"{name} invoked during fail-closed completion")
    return _inner


class Phase1BF1ClosureUnitTestCase(unittest.TestCase):
    def test_classification_failure_before_legacy_tail(self):
        from tasks import celery_tasks as celery_mod

        invoked = []
        queued = []

        def capture_async(*_args, **kwargs):
            queued.append(kwargs)
            return None

        with patch.object(celery_mod, "get_flask_app") as app_factory, \
             patch(
                 "utils.completion_reconciler.resolve_case_completion_route",
                 side_effect=CompletionCompositionUnknown("pg down"),
             ), \
             patch.object(celery_mod, "exclusive_ingest_fence", _raise_if_called("exclusive_ingest_fence", invoked)), \
             patch("utils.event_deduplication.deduplicate_case_events", _raise_if_called("deduplicate_case_events", invoked)), \
             patch("utils.known_systems_discovery.discover_known_systems", _raise_if_called("discover_known_systems", invoked)), \
             patch("utils.known_users_discovery.discover_known_users", _raise_if_called("discover_known_users", invoked)), \
             patch.object(celery_mod, "_queue_post_ingest_mitre_mapping", _raise_if_called("mitre_tail", invoked)), \
             patch.object(celery_mod, "_queue_auto_event_embedding", _raise_if_called("embed_tail", invoked)), \
             patch.object(celery_mod, "materialize_case_graph_task") as graph_task, \
             patch.object(celery_mod.case_indexing_complete_task, "apply_async", capture_async), \
             patch.object(celery_mod.case_indexing_complete_task, "update_state"), \
             patch("utils.progress.clear_progress", _raise_if_called("clear_progress", invoked)):
            graph_task.apply_async.side_effect = _raise_if_called("graph_tail", invoked)
            app_factory.return_value.app_context.return_value = MagicMock()
            result = celery_mod.case_indexing_complete_task.run(9, "uuid-f1-closure")

        self.assertEqual(result["status"], "deferred")
        self.assertEqual(result["reason"], "completion_composition_unknown")
        self.assertTrue(result["legacy_destructive_skipped"])
        self.assertEqual(invoked, [])
        self.assertEqual(len(queued), 1)
        self.assertEqual(queued[0]["kwargs"]["_classification_retry_count"], 1)
        self.assertEqual(queued[0]["countdown"], 1)

    def test_classification_retry_exhaustion_still_skips_legacy_tail(self):
        from tasks import celery_tasks as celery_mod

        invoked = []
        with patch.object(celery_mod, "get_flask_app") as app_factory, \
             patch(
                 "utils.completion_reconciler.resolve_case_completion_route",
                 side_effect=CompletionCompositionUnknown("pg down"),
             ), \
             patch.object(celery_mod, "exclusive_ingest_fence", _raise_if_called("exclusive_ingest_fence", invoked)), \
             patch("utils.event_deduplication.deduplicate_case_events", _raise_if_called("deduplicate_case_events", invoked)), \
             patch.object(celery_mod.case_indexing_complete_task, "apply_async", _raise_if_called("apply_async", invoked)):
            app_factory.return_value.app_context.return_value = MagicMock()
            with self.assertRaises(CompletionCompositionUnknown):
                celery_mod.case_indexing_complete_task.run(
                    9,
                    "uuid-f1-closure",
                    _classification_retry_count=10,
                )
        self.assertEqual(invoked, [])

    def _assert_probe_failure_blocks_dedup(self, exc):
        capturing = _CapturingClickHouse()
        with patch("models.database.db.session.query", side_effect=exc), \
             patch("utils.clickhouse.get_fresh_client", return_value=capturing) as fresh:
            with self.assertRaises(ManagedEvidenceAuthorityUnavailable):
                from utils.event_deduplication import deduplicate_case_events
                deduplicate_case_events(
                    case_id=7,
                    case_uuid="uuid-f1-probe",
                    track_progress=False,
                    allow_managed_evidence=False,
                )
            fresh.assert_not_called()
        self.assertEqual(capturing.commands, [])

    def test_generation_probe_operational_error_blocks_dedup(self):
        self._assert_probe_failure_blocks_dedup(
            OperationalError("SELECT", {}, Exception("pg operational"))
        )

    def test_generation_probe_programming_error_blocks_dedup(self):
        self._assert_probe_failure_blocks_dedup(
            ProgrammingError("SELECT", {}, Exception("relation does not exist"))
        )

    def test_generation_probe_generic_failure_blocks_dedup(self):
        self._assert_probe_failure_blocks_dedup(RuntimeError("unexpected query failure"))


class Phase1BF1GraphSchedulerKwargsTest(unittest.TestCase):
    def test_production_graph_scheduler_supplies_case_id_in_kwargs(self):
        from utils.completion_reconciler import default_production_hooks

        with patch("tasks.celery_tasks.materialize_case_graph_task") as graph_task:
            hooks = default_production_hooks(case_id=3, case_uuid="a580e5ce-4bb2-4912-b34b-8b63b4cf80cd")
            hooks.graph_scheduler()

        graph_task.apply_async.assert_called_once()
        kwargs = graph_task.apply_async.call_args.kwargs["kwargs"]
        self.assertEqual(kwargs["case_id"], 3)
        self.assertEqual(kwargs["case_uuid"], "a580e5ce-4bb2-4912-b34b-8b63b4cf80cd")
        self.assertEqual(kwargs["mode"], "ingest")
        self.assertNotIn("args", graph_task.apply_async.call_args.kwargs)
