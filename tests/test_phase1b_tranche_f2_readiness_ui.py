"""Phase 1B Tranche F2 readiness UI: PG DTO/API, Case Files strip, Hunt coverage note."""
from __future__ import annotations

import ast
import json
import os
import tempfile
import time
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault("SECRET_KEY", "phase1b-f2-ui-secret")

from flask import Flask
from flask_login import FlaskLoginClient, LoginManager, UserMixin
from sqlalchemy import event, text

from config import Config
from models.case import Case
from models.case_file import CaseFile, IngestProtocolOrigin
from models.client import Client
from models.database import db
from models.database_flow import (
    CapabilityName,
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
from parsers.base import BaseParser, ParsedEvent
from parsers.log_parsers import IISLogParser
from routes.case_files import case_files_bp, get_case_readiness, repair_case_completion
from routes.hunting import hunting_bp
from utils.capability_watermarks import (
    PRIVACY_ALIASES_V1,
    record_capability_batch_completion,
    record_zero_event_capability_completion,
)
from utils.case_readiness import (
    AUTHORIZES_AI_EGRESS,
    READINESS_CLICKHOUSE_CALLS,
    REPLACEMENT_HUNT_NOTE,
    UNAVAILABLE_HUNT_NOTE,
    build_case_readiness_dto,
)
from utils.completion_reconciler import (
    CompletionCompositionUnknown,
    _generation_state_fingerprint,
    _is_default_authority,
    classify_case_ingest_composition,
    default_generation_ids_from_rows,
    snapshot_case_completion_authority,
)
from utils.ingest_fence import install_memory_backend, reset_fence_backend
from utils.manifest_protocol import (
    ManifestParserContract,
    activate_initial_generation,
    activate_replacement_generation,
    allocate_case_file_initial_generation,
    allocate_case_file_replacement_generation,
    construct_managed_batch,
    create_ingest_attempt,
    declare_generation_ingest_complete,
    fail_generation_terminal,
    insert_managed_batch,
    invalidate_source_generation,
    mark_batch_durable,
    project_generation_control_state,
    reserve_staged_batch,
    update_generation_ingest_accounting,
    verify_ingest_batch,
)


PG_URL = os.environ.get("PHASE1B_PG_TEST_DATABASE_URL")
CH_DB = os.environ.get("PHASE1B_CH_TEST_DATABASE")
REPO = Path("/opt/casescope")

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


class _F2User(UserMixin):
    id = 1
    username = "f2-ui"
    permission_level = "analyst"
    allowed_case_ids = None

    def get_id(self):
        return "1"

    def can_access_case(self, case_id):
        if self.allowed_case_ids is None:
            return True
        return int(case_id) in {int(value) for value in self.allowed_case_ids}


class _F2Parser(BaseParser):
    supports_manifest_protocol = True
    manifest_ordering_contract = "f2-ui:fixture-order:v1"
    VERSION = "1.0.0"

    def __init__(self, *args, events=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._events = list(events or [])

    @property
    def artifact_type(self):
        return "f2_ui_fixture"

    def can_parse(self, _file_path):
        return True

    def parse(self, _file_path):
        return iter(self._events)

    def manifest_producer_version(self):
        return "f2-ui-parser:v1"


class Phase1BF2ReadinessUnitTestCase(unittest.TestCase):
    def test_default_generation_ids_match_resolver_semantics(self):
        active = SimpleNamespace(
            id=10,
            source_ref_type="CASE_FILE",
            source_ref_id="1",
            visibility_state=EvidenceGenerationState.ACTIVE,
        )
        replacement = SimpleNamespace(
            id=11,
            source_ref_type="CASE_FILE",
            source_ref_id="1",
            visibility_state=EvidenceGenerationState.BUILDING_REPLACEMENT,
        )
        initial = SimpleNamespace(
            id=20,
            source_ref_type="CASE_FILE",
            source_ref_id="2",
            visibility_state=EvidenceGenerationState.BUILDING_INITIAL,
        )
        ids = default_generation_ids_from_rows([active, replacement, initial])
        self.assertEqual(ids, {10, 20})
        self.assertNotIn(11, ids)

    def test_case_readiness_module_does_not_query_clickhouse(self):
        source = (REPO / "utils/case_readiness.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.append(node.module)
        self.assertNotIn("utils.clickhouse", imported)
        self.assertNotIn("clickhouse_connect", imported)
        self.assertNotIn("count_events", source)
        self.assertEqual(READINESS_CLICKHOUSE_CALLS, 0)
        self.assertFalse(AUTHORIZES_AI_EGRESS)

    def test_f2_dto_is_not_an_ai_authorization_gate(self):
        for relative in ("utils/ai/router.py", "utils/ai_privacy_freeze.py"):
            source = (REPO / relative).read_text(encoding="utf-8")
            tree = ast.parse(source)
            imported_modules = []
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    imported_modules.append(node.module)
                elif isinstance(node, ast.Import):
                    imported_modules.extend(alias.name for alias in node.names)
            self.assertNotIn("utils.case_readiness", imported_modules, relative)
            self.assertNotIn("build_case_readiness_dto", source, relative)
            self.assertNotIn("get_case_readiness", source, relative)

    def test_readiness_route_is_authenticated(self):
        self.assertTrue(hasattr(get_case_readiness, "__wrapped__"))
        self.assertTrue(hasattr(repair_case_completion, "__wrapped__"))


class Phase1BF2ReadinessTemplateTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.case_files = (REPO / "static/templates/case_files.html").read_text(encoding="utf-8")
        cls.hunting = (REPO / "static/templates/case_hunting.html").read_text(encoding="utf-8")
        cls.events = (REPO / "static/templates/hunting/tab_events.html").read_text(encoding="utf-8")
        cls.css = (REPO / "static/css/main.css").read_text(encoding="utf-8")

    def test_case_files_strip_uses_four_text_dimensions_and_shared_api(self):
        self.assertIn('id="readiness-strip"', self.case_files)
        self.assertIn(">Evidence<", self.case_files)
        self.assertIn(">Privacy<", self.case_files)
        self.assertIn(">Reconciliation<", self.case_files)
        self.assertIn(">Live Activity<", self.case_files)
        self.assertIn("/api/case/readiness/", self.case_files)
        self.assertIn("role=\"status\"", self.case_files)
        self.assertIn("aria-label=\"Resume completion repair\"", self.case_files)
        self.assertIn('type="button"', self.case_files)
        self.assertIn("readiness-strip", self.css)
        self.assertIn("loadReadiness", self.case_files)

    def test_hunt_coverage_note_uses_same_api_and_does_not_disable_search(self):
        self.assertIn('id="hunt-coverage-note"', self.events)
        self.assertIn("/api/case/readiness/", self.hunting)
        self.assertIn("function loadHuntCoverageNote", self.hunting)
        self.assertIn("searchInput.disabled = false", self.hunting)
        self.assertIn("searchBtn.disabled = false", self.hunting)
        self.assertIn('id="events-search"', self.events)
        self.assertNotIn("events-search-btn\" disabled", self.events)
        self.assertIn("build_hunting_publication_bridge", (REPO / "routes/hunting.py").read_text(encoding="utf-8"))


@unittest.skipUnless(PG_URL, "PHASE1B_PG_TEST_DATABASE_URL is required")
class Phase1BF2ReadinessRealPGTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        install_memory_backend()
        cls.app = Flask(__name__)
        cls.app.config.update(
            SQLALCHEMY_DATABASE_URI=PG_URL,
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            SECRET_KEY="phase1b-f2-ui-pg",
            LOGIN_DISABLED=False,
        )
        db.init_app(cls.app)
        login_manager = LoginManager()
        login_manager.session_protection = None
        login_manager.init_app(cls.app)
        login_manager.user_loader(lambda _user_id: _F2User())
        cls.app.test_client_class = FlaskLoginClient
        cls.app.register_blueprint(case_files_bp)
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
            CaseCompletionReconciliationAudit.__table__,
        ):
            table.create(db.engine, checkfirst=True)
        with db.engine.begin() as conn:
            for ddl in POSTGRES_INDEX_DDL:
                conn.execute(text(ddl))

    @classmethod
    def tearDownClass(cls):
        with db.engine.begin() as conn:
            conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            conn.execute(text("CREATE SCHEMA public"))
        cls.ctx.pop()
        reset_fence_backend()

    def setUp(self):
        from flask import g
        g.pop("_login_user", None)
        db.session.rollback()
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
        self.client_row = Client(name="F2 UI", code=f"F2U{time.time_ns() % 100000}", created_by="tester")
        self.case = Case(
            uuid=f"f2-ui-{time.time_ns()}",
            name="F2 UI",
            company="Example",
            client=self.client_row,
            created_by="tester",
        )
        self.case_file = CaseFile(
            case_uuid=self.case.uuid,
            filename="f2-ui.log",
            original_filename="f2-ui.log",
            file_path="/tmp/f2-ui.log",
            file_size=1,
            sha256_hash="a" * 64,
            uploaded_by="tester",
            ingest_protocol_origin=IngestProtocolOrigin.NOT_STARTED,
        )
        db.session.add_all([self.client_row, self.case, self.case_file])
        db.session.commit()
        parser = _F2Parser(case_id=self.case.id, case_file_id=self.case_file.id)
        self.contract = ManifestParserContract(
            parser_version=parser.parser_version,
            normalization_version="normalization:v1",
            configured_batch_size=2,
            ordering_contract="f2-ui:fixture-order:v1",
            producer_version="f2-ui-parser:v1",
            manifest_eligible=True,
        )

    def tearDown(self):
        _F2User.allowed_case_ids = None
        db.session.rollback()
        db.session.remove()

    def _event(self, record_id, generation_number=1):
        return ParsedEvent(
            case_id=self.case.id,
            artifact_type="f2_ui_fixture",
            timestamp=datetime(2026, 1, 1) + timedelta(seconds=record_id),
            timestamp_utc=datetime(2026, 1, 1) + timedelta(seconds=record_id),
            timestamp_source_tz="UTC",
            source_file="f2-ui.log",
            source_path="/tmp/f2-ui.log",
            source_host="F2HOST",
            case_file_id=self.case_file.id,
            event_id=f"{generation_number}-{record_id}",
            record_id=record_id,
            username=f"user{record_id}",
            command_line=f"record {record_id}",
            raw_json=f'{{"record_id":{record_id}}}',
            search_blob=f"record {record_id} user{record_id}",
            parser_version="F2UIParser-1.0.0",
            native_record_id_authoritative=True,
        )

    def _generation(self, case_file=None, *, state=EvidenceGenerationState.BUILDING_INITIAL):
        generation = allocate_case_file_initial_generation(
            session=db.session,
            case_id=self.case.id,
            case_file_id=(case_file or self.case_file).id,
            contract=self.contract,
        )
        generation.visibility_state = state
        db.session.commit()
        return generation

    def _durable_batch(self, generation, events, *, batch_ordinal=0, durable=True):
        attempt = create_ingest_attempt(session=db.session, generation=generation)
        manifest = construct_managed_batch(
            generation=generation,
            attempt=attempt,
            events=events,
            batch_ordinal=batch_ordinal,
        )
        batch = reserve_staged_batch(session=db.session, manifest=manifest)
        if durable:
            batch.state = IngestBatchState.DURABLE
            batch.durable_at = datetime.utcnow()
        db.session.commit()
        return batch

    def _complete_privacy(self, batch):
        generation = batch.generation
        return record_capability_batch_completion(
            session=db.session,
            case_id=generation.case_id,
            capability=CapabilityName.PRIVACY_ALIASES,
            source_ref_type=generation.source_ref_type,
            source_ref_id=generation.source_ref_id,
            source_generation=generation.source_generation,
            derivation_version=PRIVACY_ALIASES_V1,
            ingest_batch_id=batch.ingest_batch_id,
        )

    def _dto(self, **kwargs):
        kwargs.setdefault("redis_available", True)
        kwargs.setdefault("redis_progress", None)
        kwargs.setdefault("redis_calls", 0)
        return build_case_readiness_dto(
            db.session,
            case_id=self.case.id,
            case_uuid=self.case.uuid,
            **kwargs,
        )

    def _client(self):
        from flask import g
        g.pop("_login_user", None)
        return self.app.test_client(user=_F2User(), fresh_login=True)

    def _api(self, case_uuid=None):
        client = self._client()
        with patch("utils.clickhouse.get_client") as get_client, patch("utils.clickhouse.count_events") as count_events:
            response = client.get(f"/api/case/readiness/{case_uuid or self.case.uuid}")
        self.assertFalse(get_client.called)
        self.assertFalse(count_events.called)
        return response

    def _durable_dims(self, dto):
        dims = dto["dimensions"]
        return {
            "evidence": {key: dims["evidence"][key] for key in ("code", "label", "detail", "final_percent", "published_durable_batches", "expanding", "replacement_in_progress")},
            "privacy": {key: dims["privacy"][key] for key in ("code", "label", "contiguous_batch_ordinal", "authorizes_ai_egress", "informational_only")},
            "reconciliation": {key: dims["reconciliation"][key] for key in ("code", "label", "audit_current")},
        }

    def test_building_initial_before_durable_and_with_published_batches(self):
        generation = self._generation()
        before = self._dto()
        self.assertEqual(before["composition"], CaseIngestComposition.MANAGED_ONLY)
        self.assertEqual(before["authority"], "postgresql")
        self.assertIsNone(before["dimensions"]["evidence"]["final_percent"])
        self.assertTrue(before["dimensions"]["evidence"]["expanding"])
        self.assertEqual(before["dimensions"]["evidence"]["published_durable_batches"], 0)
        self.assertEqual(before["metrics"]["clickhouse_calls"], 0)
        self.assertTrue(before["hunt_coverage"]["search_enabled"])

        self._durable_batch(generation, [self._event(1), self._event(2)], batch_ordinal=0)
        self._durable_batch(generation, [self._event(3), self._event(4)], batch_ordinal=1)
        self._durable_batch(generation, [self._event(5), self._event(6)], batch_ordinal=2)
        after = self._dto()
        evidence = after["dimensions"]["evidence"]
        self.assertEqual(evidence["code"], "expanding")
        self.assertEqual(evidence["published_durable_batches"], 3)
        self.assertIsNone(evidence["final_percent"])
        self.assertIn("still expanding", evidence["detail"])
        self.assertIn("3 published", evidence["detail"])
        self.assertTrue(after["hunt_coverage"]["show"])
        self.assertEqual(after["hunt_coverage"]["note_kind"], "expanding")
        self.assertIn("currently published evidence", after["hunt_coverage"]["text"])
        self.assertFalse(after["completion"]["repair_available"])

    def test_active_does_not_imply_analysis_complete(self):
        generation = self._generation()
        batch = self._durable_batch(generation, [self._event(1), self._event(2)])
        self._complete_privacy(batch)
        declare_generation_ingest_complete(
            session=db.session, generation=generation, expected_rows=2, final_batch_ordinal=0
        )
        activate_initial_generation(session=db.session, generation=generation)
        db.session.commit()
        dto = self._dto()
        self.assertEqual(dto["dimensions"]["evidence"]["code"], "published")
        self.assertFalse(dto["dimensions"]["evidence"]["expanding"])
        self.assertIn("not analysis completion", dto["dimensions"]["evidence"]["detail"])
        self.assertFalse(dto["hunt_coverage"]["show"])
        self.assertNotIn("ioc_matches", json.dumps(dto["dimensions"]))

    def test_replacement_does_not_make_current_active_look_partial(self):
        initial = self._generation()
        batch = self._durable_batch(initial, [self._event(1), self._event(2)])
        self._complete_privacy(batch)
        declare_generation_ingest_complete(
            session=db.session, generation=initial, expected_rows=2, final_batch_ordinal=0
        )
        activate_initial_generation(session=db.session, generation=initial)
        db.session.commit()
        replacement = allocate_case_file_replacement_generation(
            session=db.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        db.session.commit()
        self._durable_batch(replacement, [self._event(3, 2), self._event(4, 2)])
        dto = self._dto()
        evidence = dto["dimensions"]["evidence"]
        self.assertEqual(evidence["code"], "published_with_replacement")
        self.assertTrue(evidence["replacement_in_progress"])
        self.assertFalse(evidence["expanding"])
        self.assertNotIn("partial", evidence["detail"].lower())
        self.assertIn("Replacement processing", evidence["detail"])
        self.assertEqual(dto["hunt_coverage"]["note_kind"], "replacement_background")
        self.assertEqual(dto["hunt_coverage"]["text"], REPLACEMENT_HUNT_NOTE)
        self.assertEqual(dto["dimensions"]["privacy"]["code"], "complete")
        self.assertTrue(dto["dimensions"]["privacy"]["replacement_incomplete"])

        declare_generation_ingest_complete(
            session=db.session, generation=replacement, expected_rows=2, final_batch_ordinal=0
        )
        repl_batch = (
            db.session.query(IngestBatch).filter_by(generation_id=replacement.id).one()
        )
        self._complete_privacy(repl_batch)
        activate_replacement_generation(
            session=db.session, replacement=replacement, actor="f2-ui"
        )
        db.session.commit()
        after = self._dto()
        self.assertEqual(after["dimensions"]["evidence"]["code"], "published")
        self.assertFalse(after["dimensions"]["evidence"]["replacement_in_progress"])
        snapshot = snapshot_case_completion_authority(
            db.session, case_id=self.case.id, case_uuid=self.case.uuid
        )
        active = [
            row for row in snapshot["generations"]
            if row.visibility_state == EvidenceGenerationState.ACTIVE
        ]
        self.assertEqual(len(active), 1)
        self.assertEqual(int(active[0].id), int(replacement.id))

    def test_privacy_hole_is_contiguous_prefix_and_informational(self):
        generation = self._generation()
        batch0 = self._durable_batch(generation, [self._event(1), self._event(2)], batch_ordinal=0)
        self._durable_batch(generation, [self._event(3), self._event(4)], batch_ordinal=1)
        batch2 = self._durable_batch(generation, [self._event(5), self._event(6)], batch_ordinal=2)
        self._complete_privacy(batch0)
        self._complete_privacy(batch2)
        db.session.commit()
        dto = self._dto()
        privacy = dto["dimensions"]["privacy"]
        self.assertEqual(privacy["contiguous_batch_ordinal"], 0)
        self.assertEqual(privacy["code"], "contiguous")
        self.assertIn("batch 0", privacy["detail"])
        self.assertNotIn("batch 2", privacy["detail"])
        self.assertTrue(privacy["informational_only"])
        self.assertFalse(privacy["authorizes_ai_egress"])

    def test_zero_event_source_is_not_missing_batch(self):
        generation = self._generation()
        declare_generation_ingest_complete(
            session=db.session, generation=generation, expected_rows=0, final_batch_ordinal=None
        )
        record_zero_event_capability_completion(
            session=db.session,
            generation=generation,
            capability=CapabilityName.PRIVACY_ALIASES,
            derivation_version=PRIVACY_ALIASES_V1,
        )
        activate_initial_generation(session=db.session, generation=generation)
        db.session.commit()
        dto = self._dto()
        self.assertNotIn("0/1", json.dumps(dto))
        self.assertNotIn("missing batch", json.dumps(dto).lower())
        self.assertEqual(dto["dimensions"]["privacy"]["code"], "complete")
        self.assertEqual(dto["dimensions"]["evidence"]["code"], "published")

    def test_failed_incomplete_source(self):
        generation = self._generation()
        self._durable_batch(generation, [self._event(1), self._event(2)])
        fail_generation_terminal(session=db.session, generation=generation, reason="f2-ui-fail")
        db.session.commit()
        dto = self._dto()
        self.assertEqual(dto["dimensions"]["evidence"]["code"], "failed")
        self.assertEqual(dto["dimensions"]["reconciliation"]["code"], ReconciliationAssessment.FAILED)

    def test_legacy_only_and_mixed_are_qualitative(self):
        self.case_file.ingest_protocol_origin = IngestProtocolOrigin.LEGACY_OR_UNKNOWN
        db.session.commit()
        legacy = self._dto()
        self.assertEqual(legacy["composition"], CaseIngestComposition.LEGACY_ONLY)
        self.assertEqual(legacy["dimensions"]["evidence"]["code"], "legacy")
        self.assertIsNone(legacy["dimensions"]["evidence"]["final_percent"])
        self.assertEqual(legacy["completion"]["repair_route"], "legacy")
        self.assertFalse(legacy["completion"]["repair_available"])

        managed_file = CaseFile(
            case_uuid=self.case.uuid,
            filename="managed.log",
            original_filename="managed.log",
            file_path="/tmp/managed.log",
            file_size=1,
            sha256_hash="e" * 64,
            uploaded_by="tester",
            ingest_protocol_origin=IngestProtocolOrigin.NOT_STARTED,
        )
        db.session.add(managed_file)
        db.session.commit()
        generation = self._generation(managed_file)
        self._durable_batch(generation, [self._event(1), self._event(2)])
        mixed = self._dto()
        self.assertEqual(mixed["composition"], CaseIngestComposition.MIXED)
        self.assertEqual(mixed["dimensions"]["evidence"]["code"], "mixed")
        self.assertIsNone(mixed["dimensions"]["evidence"]["final_percent"])
        self.assertIn("untracked", mixed["dimensions"]["evidence"]["detail"].lower())
        self.assertEqual(mixed["hunt_coverage"]["note_kind"], "expanding")
        self.assertEqual(mixed["completion"]["repair_route"], "f1")

    def test_new_source_and_new_durable_batch_invalidate_stale_reconciled_audit(self):
        generation = self._generation()
        batch = self._durable_batch(generation, [self._event(1), self._event(2)])
        self._complete_privacy(batch)
        declare_generation_ingest_complete(
            session=db.session, generation=generation, expected_rows=2, final_batch_ordinal=0
        )
        activate_initial_generation(session=db.session, generation=generation)
        db.session.commit()
        snapshot = snapshot_case_completion_authority(
            db.session, case_id=self.case.id, case_uuid=self.case.uuid
        )
        counts = {
            "staged": 0,
            "durable": 1,
            "generations": 1,
        }
        audit = CaseCompletionReconciliationAudit(
            case_id=self.case.id,
            case_uuid=self.case.uuid,
            trigger_reason="test",
            composition=CaseIngestComposition.MANAGED_ONLY,
            assessment=ReconciliationAssessment.RECONCILED,
            generations_inspected=[],
            batch_counts=counts,
            d2_gaps=[],
            capability_gaps=[],
            derivations_checked=[],
            work_queued=[],
            unresolved_conflicts=[],
            deferred=[],
            errors=[],
            metrics={"generation_fingerprint": [list(item) for item in _generation_state_fingerprint(snapshot)]},
        )
        db.session.add(audit)
        db.session.commit()
        current = self._dto()
        self.assertTrue(current["dimensions"]["reconciliation"]["audit_current"])
        self.assertEqual(current["dimensions"]["reconciliation"]["code"], ReconciliationAssessment.RECONCILED)

        self._durable_batch(generation, [self._event(3), self._event(4)], batch_ordinal=1)
        after_batch = self._dto()
        self.assertFalse(after_batch["dimensions"]["reconciliation"]["audit_current"])
        self.assertNotEqual(
            after_batch["dimensions"]["reconciliation"]["code"],
            ReconciliationAssessment.RECONCILED,
        )

        extra = CaseFile(
            case_uuid=self.case.uuid,
            filename="second.log",
            original_filename="second.log",
            file_path="/tmp/second.log",
            file_size=1,
            sha256_hash="c" * 64,
            uploaded_by="tester",
            ingest_protocol_origin=IngestProtocolOrigin.NOT_STARTED,
        )
        db.session.add(extra)
        db.session.commit()
        self._generation(extra)
        after_source = self._dto()
        self.assertFalse(after_source["dimensions"]["reconciliation"]["audit_current"])
        self.assertEqual(
            after_source["dimensions"]["reconciliation"]["code"],
            ReconciliationAssessment.INCOMPLETE_INGEST,
        )
        self.assertTrue(after_source["dimensions"]["evidence"]["expanding"])

    def test_invalidation_withdraws_stale_readiness(self):
        generation = self._generation()
        batch = self._durable_batch(generation, [self._event(1), self._event(2)])
        self._complete_privacy(batch)
        declare_generation_ingest_complete(
            session=db.session, generation=generation, expected_rows=2, final_batch_ordinal=0
        )
        activate_initial_generation(session=db.session, generation=generation)
        db.session.commit()
        before = self._dto()
        self.assertEqual(before["dimensions"]["evidence"]["code"], "published")
        invalidate_source_generation(session=db.session, generation=generation, reason="f2-ui-invalidate")
        db.session.commit()
        after = self._dto()
        self.assertEqual(after["dimensions"]["evidence"]["code"], "withdrawn")
        self.assertNotEqual(after["dimensions"]["privacy"]["code"], "complete")

    def test_pg_failure_is_unavailable_not_legacy_or_ready(self):
        generation = self._generation()
        self._durable_batch(generation, [self._event(1), self._event(2)])
        with patch(
            "utils.case_readiness.snapshot_case_completion_authority",
            side_effect=CompletionCompositionUnknown("forced"),
        ):
            dto = self._dto(redis_available=True, redis_progress={"status": "processing", "current_item": "x"})
        self.assertFalse(dto["authority_available"])
        self.assertEqual(dto["composition"], "unknown")
        self.assertEqual(dto["dimensions"]["evidence"]["code"], "unavailable")
        self.assertEqual(dto["dimensions"]["privacy"]["code"], "unavailable")
        self.assertEqual(dto["dimensions"]["reconciliation"]["code"], "unavailable")
        self.assertNotEqual(dto["composition"], CaseIngestComposition.LEGACY_ONLY)
        self.assertIsNone(dto["dimensions"]["evidence"]["final_percent"])
        self.assertTrue(dto["completion"]["fail_closed"])
        self.assertFalse(dto["completion"]["repair_available"])
        self.assertEqual(dto["hunt_coverage"]["text"], UNAVAILABLE_HUNT_NOTE)
        self.assertTrue(dto["hunt_coverage"]["search_enabled"])
        self.assertEqual(dto["dimensions"]["live_activity"]["code"], "processing")

    def test_redis_loss_does_not_change_durable_dimensions(self):
        generation = self._generation()
        self._durable_batch(generation, [self._event(1), self._event(2)])
        with_redis = self._dto(
            redis_available=True,
            redis_progress={"status": "processing", "current_item": "file.log", "files": {"completed": 1, "total": 4}},
            redis_calls=2,
        )
        without_redis = self._dto(redis_available=False, redis_progress=None, redis_calls=1)
        self.assertEqual(self._durable_dims(with_redis), self._durable_dims(without_redis))
        self.assertEqual(with_redis["dimensions"]["live_activity"]["code"], "processing")
        self.assertEqual(without_redis["dimensions"]["live_activity"]["code"], "unavailable")
        self.assertFalse(without_redis["dimensions"]["live_activity"]["available"])

    def test_api_is_case_scoped_authenticated_and_clickhouse_free(self):
        generation = self._generation()
        self._durable_batch(generation, [self._event(1), self._event(2)])
        anonymous = self.app.test_client().get(f"/api/case/readiness/{self.case.uuid}")
        self.assertIn(anonymous.status_code, {302, 401})
        response = self._api()
        payload = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(payload["authority_available"])
        self.assertEqual(payload["metrics"]["clickhouse_calls"], 0)
        other = Case(
            uuid=f"f2-ui-other-{time.time_ns()}",
            name="Other",
            company="Example",
            client=self.client_row,
            created_by="tester",
        )
        db.session.add(other)
        db.session.commit()
        _F2User.allowed_case_ids = {self.case.id}
        denied = self._api(other.uuid)
        self.assertEqual(denied.status_code, 403)
        _F2User.allowed_case_ids = None

    def test_repair_routes_fail_closed_on_unknown_and_use_f1_for_managed(self):
        generation = self._generation()
        self._durable_batch(generation, [self._event(1), self._event(2)])
        self.case_file.status = "done"
        db.session.commit()
        client = self._client()
        with patch(
            "utils.completion_reconciler.classify_case_ingest_composition",
            side_effect=CompletionCompositionUnknown("forced"),
        ), patch("utils.progress.clear_completion_trigger") as clear, patch(
            "tasks.celery_tasks.case_indexing_complete_task.delay"
        ) as delay:
            denied = client.post(f"/api/files/repair-completion/{self.case.uuid}")
        self.assertEqual(denied.status_code, 409)
        self.assertFalse(denied.get_json()["success"])
        self.assertEqual(denied.get_json()["composition"], "unknown")
        clear.assert_not_called()
        delay.assert_not_called()

        with patch("tasks.celery_tasks.case_indexing_complete_task.delay") as delay, patch(
            "utils.progress.clear_completion_trigger"
        ) as clear, patch("utils.progress.set_phase"), patch(
            "utils.progress.get_progress", return_value={}
        ):
            delay.return_value = SimpleNamespace(id="task-f1")
            ok = client.post(f"/api/files/repair-completion/{self.case.uuid}")
        self.assertEqual(ok.status_code, 200)
        self.assertEqual(ok.get_json()["repair_route"], "f1")
        self.assertEqual(ok.get_json()["composition"], CaseIngestComposition.MANAGED_ONLY)
        clear.assert_not_called()
        delay.assert_called_once()

    def test_default_ids_match_per_row_resolver_and_classify_reuse(self):
        initial = self._generation()
        batch = self._durable_batch(initial, [self._event(1), self._event(2)])
        self._complete_privacy(batch)
        declare_generation_ingest_complete(
            session=db.session, generation=initial, expected_rows=2, final_batch_ordinal=0
        )
        activate_initial_generation(session=db.session, generation=initial)
        db.session.commit()
        allocate_case_file_replacement_generation(
            session=db.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        db.session.commit()
        snapshot = snapshot_case_completion_authority(
            db.session, case_id=self.case.id, case_uuid=self.case.uuid
        )
        in_memory = default_generation_ids_from_rows(snapshot["generations"])
        per_row = {
            int(row.id)
            for row in snapshot["generations"]
            if _is_default_authority(db.session, row)
        }
        self.assertEqual(in_memory, per_row)
        reused = classify_case_ingest_composition(
            db.session,
            case_id=self.case.id,
            case_uuid=self.case.uuid,
            generations=snapshot["generations"],
        )
        queried = classify_case_ingest_composition(
            db.session, case_id=self.case.id, case_uuid=self.case.uuid
        )
        self.assertEqual(reused, queried)

    def test_representative_polling_is_bounded_and_clickhouse_free(self):
        files = [self.case_file]
        for idx in range(3):
            extra = CaseFile(
                case_uuid=self.case.uuid,
                filename=f"src-{idx}.log",
                original_filename=f"src-{idx}.log",
                file_path=f"/tmp/src-{idx}.log",
                file_size=1,
                sha256_hash=str(idx + 1) * 64,
                uploaded_by="tester",
                ingest_protocol_origin=IngestProtocolOrigin.NOT_STARTED,
            )
            db.session.add(extra)
            db.session.commit()
            files.append(extra)
        for case_file in files:
            generation = allocate_case_file_initial_generation(
                session=db.session,
                case_id=self.case.id,
                case_file_id=case_file.id,
                contract=self.contract,
            )
            db.session.commit()
            for ordinal in range(3):
                rec = ordinal * 2 + 1
                self._durable_batch(
                    generation,
                    [self._event(rec, case_file.id), self._event(rec + 1, case_file.id)],
                    batch_ordinal=ordinal,
                )
        statements = []

        def _count(_conn, _cursor, statement, _parameters, _context, _executemany):
            statements.append(statement)

        event.listen(db.engine, "before_cursor_execute", _count)
        try:
            started = time.perf_counter()
            response = self._api()
            elapsed_ms = (time.perf_counter() - started) * 1000.0
        finally:
            event.remove(db.engine, "before_cursor_execute", _count)
        payload = response.get_json()
        body = json.dumps(payload)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["metrics"]["clickhouse_calls"], 0)
        self.assertGreaterEqual(len(statements), 1)
        self.assertLessEqual(len(statements), 20)
        self.assertLess(payload["metrics"]["pg_rows_loaded"], 80)
        self.assertLess(elapsed_ms, 2000)
        self.assertLess(len(body), 8000)
        self.assertEqual(payload["dimensions"]["evidence"]["published_durable_batches"], 12)
        self.assertIsNone(payload["dimensions"]["evidence"]["final_percent"])
        self._perf = {
            "pg_statements": len(statements),
            "pg_rows_loaded": payload["metrics"]["pg_rows_loaded"],
            "redis_calls": payload["metrics"]["redis_calls"],
            "clickhouse_calls": payload["metrics"]["clickhouse_calls"],
            "latency_ms": elapsed_ms,
            "payload_bytes": len(body),
        }
        print("F2_READINESS_PERF", json.dumps(self._perf))


@unittest.skipUnless(PG_URL and CH_DB, "PHASE1B_PG_TEST_DATABASE_URL and PHASE1B_CH_TEST_DATABASE are required")
class Phase1BF2SearchDuringIngestE2ETestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        install_memory_backend()
        cls._old_flag = getattr(Config, "PHASE1B_MANIFEST_PROTOCOL_ENABLED", False)
        cls._old_batch_size = getattr(Config, "PHASE1B_MANIFEST_BATCH_SIZE", None)
        Config.PHASE1B_MANIFEST_PROTOCOL_ENABLED = True
        Config.PHASE1B_MANIFEST_BATCH_SIZE = 4
        cls.app = Flask(__name__)
        cls.app.config.update(
            SQLALCHEMY_DATABASE_URI=PG_URL,
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            SECRET_KEY="phase1b-f2-ui-e2e",
            LOGIN_DISABLED=False,
        )
        db.init_app(cls.app)
        login_manager = LoginManager()
        login_manager.session_protection = None
        login_manager.init_app(cls.app)
        login_manager.user_loader(lambda _user_id: _F2User())
        cls.app.test_client_class = FlaskLoginClient
        cls.app.register_blueprint(hunting_bp)
        cls.app.register_blueprint(case_files_bp)
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
            CaseCompletionReconciliationAudit.__table__,
        ):
            table.create(db.engine, checkfirst=True)
        with db.engine.begin() as conn:
            for ddl in POSTGRES_INDEX_DDL:
                conn.execute(text(ddl))
        import clickhouse_connect
        from migrations.add_events_table import EVENTS_COLUMN_DEFINITIONS
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
        for ddl in [
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
        ]:
            cls.ch.command(ddl)

    @classmethod
    def tearDownClass(cls):
        cls.ch.command("DROP TABLE IF EXISTS events")
        cls.ch.command("DROP TABLE IF EXISTS visible_evidence_generations")
        cls.ch.command("DROP TABLE IF EXISTS durable_ingest_batches")
        cls.ch.command("DROP TABLE IF EXISTS event_mitre_matches")
        cls.ch.close()
        with db.engine.begin() as conn:
            conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            conn.execute(text("CREATE SCHEMA public"))
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

    def setUp(self):
        self.ch.command("TRUNCATE TABLE events")
        self.ch.command("TRUNCATE TABLE visible_evidence_generations")
        self.ch.command("TRUNCATE TABLE durable_ingest_batches")
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
        self.client_row = Client(name="F2 E2E", code=f"F2E{time.time_ns() % 100000}", created_by="tester")
        self.case = Case(
            uuid=f"f2-e2e-{time.time_ns()}",
            name="F2 E2E",
            company="Example",
            client=self.client_row,
            created_by="tester",
        )
        self.tempdir = tempfile.TemporaryDirectory()
        iis_path = os.path.join(self.tempdir.name, "u_ex260101.log")
        lines = [
            "#Software: Microsoft Internet Information Services",
            "#Version: 1.0",
            "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status",
        ]
        for idx in range(8):
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
            sha256_hash="d" * 64,
            uploaded_by="tester",
            ingest_protocol_origin=IngestProtocolOrigin.NOT_STARTED,
        )
        db.session.add_all([self.client_row, self.case, self.case_file])
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

    def _client(self):
        from flask import g
        g.pop("_login_user", None)
        return self.app.test_client(user=_F2User(), fresh_login=True)

    def _hunt(self, flask_client):
        with patch("utils.clickhouse.get_client", return_value=self.ch):
            response = flask_client.get(f"/api/hunting/events/{self.case.id}")
        payload = response.get_json() or {}
        self.assertEqual(response.status_code, 200, msg=payload)
        return payload

    def _readiness(self, flask_client):
        response = flask_client.get(f"/api/case/readiness/{self.case.uuid}")
        payload = response.get_json() or {}
        self.assertEqual(response.status_code, 200, msg=payload)
        return payload

    def _ingest_slice(self, generation, events, *, batch_ordinal):
        attempt = create_ingest_attempt(session=db.session, generation=generation)
        manifest = construct_managed_batch(
            generation=generation,
            attempt=attempt,
            events=events,
            batch_ordinal=batch_ordinal,
        )
        batch = reserve_staged_batch(session=db.session, manifest=manifest)
        db.session.commit()
        insert_managed_batch(self.ch, manifest)
        mark_batch_durable(
            session=db.session,
            batch=batch,
            verification=verify_ingest_batch(self.ch, manifest),
        )
        update_generation_ingest_accounting(session=db.session, generation=generation)
        db.session.commit()
        project_generation_control_state(self.ch, db.session, generation)
        return batch

    def test_search_during_ingest_coverage_note_and_enabled_controls(self):
        events_tab = (REPO / "static/templates/hunting/tab_events.html").read_text(encoding="utf-8")
        hunting = (REPO / "static/templates/case_hunting.html").read_text(encoding="utf-8")
        self.assertIn('id="hunt-coverage-note"', events_tab)
        self.assertIn("/api/case/readiness/", hunting)
        self.assertIn("searchInput.disabled = false", hunting)

        flask_client = self._client()
        generation = allocate_case_file_initial_generation(
            session=db.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        db.session.commit()
        first = self.events[0:4]
        second = self.events[4:8]
        self._ingest_slice(generation, first, batch_ordinal=0)
        hunt = self._hunt(flask_client)
        readiness = self._readiness(flask_client)
        self.assertEqual(hunt["total"], 4)
        self.assertTrue(readiness["hunt_coverage"]["show"])
        self.assertIn("currently published evidence", readiness["hunt_coverage"]["text"])
        self.assertTrue(readiness["hunt_coverage"]["search_enabled"])
        self.assertTrue(readiness["dimensions"]["evidence"]["expanding"])
        self.assertIsNone(generation.completed_at)

        self._ingest_slice(generation, second, batch_ordinal=1)
        hunt = self._hunt(flask_client)
        self.assertEqual(hunt["total"], 8)

        declare_generation_ingest_complete(
            session=db.session,
            generation=generation,
            expected_rows=len(self.events),
            final_batch_ordinal=1,
        )
        activate_initial_generation(session=db.session, generation=generation, actor="f2-ui")
        db.session.commit()
        project_generation_control_state(self.ch, db.session, generation)
        hunt = self._hunt(flask_client)
        readiness = self._readiness(flask_client)
        self.assertEqual(hunt["total"], 8)
        self.assertFalse(readiness["dimensions"]["evidence"]["expanding"])
        self.assertFalse(readiness["hunt_coverage"]["show"])
        self.assertTrue(readiness["hunt_coverage"]["search_enabled"])
        self.assertNotEqual(readiness["hunt_coverage"]["note_kind"], "expanding")
