"""Phase 1B EXIT blocker-closure proofs: lifecycle, Hunt scale, no-later-phase."""
from __future__ import annotations

import json
import os
import statistics
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("SECRET_KEY", "phase1b-exit-blocker-secret")

import clickhouse_connect
from flask import Flask
from flask_login import FlaskLoginClient, LoginManager, UserMixin
from sqlalchemy import text

from config import Config
from migrations.add_events_table import EVENTS_COLUMN_DEFINITIONS
from models.case import Case
from models.case_file import CaseFile, IngestProtocolOrigin
from models.client import Client
from models.graph import GraphProjectionState
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
from parsers.log_parsers import IISLogParser
from routes.case_files import case_files_bp
from routes.hunting import hunting_bp
from routes.hunting_query_helpers import build_hunting_publication_bridge
from utils.capability_watermarks import PRIVACY_ALIASES_V1, record_capability_batch_completion
from utils.case_readiness import PENDING_RECONCILIATION, build_case_readiness_dto
from utils.completion_reconciler import (
    CompletionCompositionUnknown,
    ReconciliationHooks,
    reconcile_case_completion,
)
from utils.ingest_fence import install_memory_backend, reset_fence_backend
from utils.manifest_protocol import (
    DURABLE_INGEST_BATCHES_COLUMNS,
    ManifestParserContract,
    VISIBLE_EVIDENCE_GENERATIONS_COLUMNS,
    activate_initial_generation,
    activate_replacement_generation,
    allocate_case_file_initial_generation,
    allocate_case_file_replacement_generation,
    construct_managed_batch,
    create_ingest_attempt,
    declare_generation_ingest_complete,
    insert_managed_batch,
    invalidate_source_generation,
    mark_batch_durable,
    project_generation_authority_swap,
    project_generation_control_state,
    reserve_staged_batch,
    update_generation_ingest_accounting,
    verify_ingest_batch,
)


PG_URL = os.environ.get("PHASE1B_PG_TEST_DATABASE_URL")
CH_DB = os.environ.get("PHASE1B_CH_TEST_DATABASE")
REPO = Path("/opt/casescope")
ARTIFACT_DIR = REPO / "docs" / "database_flow_phase1b"

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


class _ExitUser(UserMixin):
    id = 1
    username = "phase1b-exit"
    permission_level = "analyst"

    def get_id(self):
        return "1"

    def can_access_case(self, _case_id):
        return True


def _percentile(values, pct):
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return round(ordered[0], 3)
    rank = (len(ordered) - 1) * (pct / 100.0)
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    weight = rank - low
    return round(ordered[low] * (1.0 - weight) + ordered[high] * weight, 3)


def _query_with_stats(client, sql, parameters=None):
    started = time.perf_counter()
    result = client.query(sql, parameters=parameters or {})
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    summary = result.summary or {}
    return {
        "elapsed_ms": round(elapsed_ms, 3),
        "read_rows": int(summary.get("read_rows") or 0),
        "read_bytes": int(summary.get("read_bytes") or 0),
        "result_rows": int(summary.get("result_rows") or len(result.result_rows or [])),
        "rows": list(result.result_rows or []),
        "summary": dict(summary),
    }


class Phase1BExitNoLaterPhaseTestCase(unittest.TestCase):
    def test_closure_does_not_start_later_phases(self):
        changed = [
            REPO / "utils/case_readiness.py",
            REPO / "routes/hunting_query_helpers.py",
            REPO / "routes/hunting.py",
        ]
        forbidden_uses = (
            "FROM events_current",
            "INTO events_current",
            "TABLE events_current",
            "FROM event_observations_current",
            "TABLE event_observations_current",
            "CREATE TABLE lek",
        )
        for path in changed:
            if not path.exists():
                continue
            text_source = path.read_text(encoding="utf-8")
            lowered = text_source.lower()
            for token in forbidden_uses:
                self.assertNotIn(token.lower(), lowered, path.name)
        hunt = (REPO / "routes/hunting.py").read_text(encoding="utf-8")
        self.assertIn("build_hunting_publication_bridge", hunt)
        self.assertNotIn("FROM events_current", hunt)


@unittest.skipUnless(PG_URL and CH_DB, "PHASE1B_PG_TEST_DATABASE_URL and PHASE1B_CH_TEST_DATABASE are required")
class Phase1BExitLifecycleAndScaleTestCase(unittest.TestCase):
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
            SECRET_KEY="phase1b-exit-blocker",
            LOGIN_DISABLED=False,
        )
        db.init_app(cls.app)
        login_manager = LoginManager()
        login_manager.session_protection = None
        login_manager.init_app(cls.app)
        login_manager.user_loader(lambda _user_id: _ExitUser())
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
        cls.ch.command("""
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
        """)
        cls.ch.command("""
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
        """)

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
        GraphProjectionState.query.delete()
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
        self.client_row = Client(name="Exit", code=f"EX{time.time_ns() % 100000}", created_by="tester")
        self.case = Case(
            uuid=f"exit-{time.time_ns()}",
            name="Exit",
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
        self.timings = {}

    def tearDown(self):
        db.session.remove()
        self.tempdir.cleanup()

    def _client(self):
        from flask import g
        g.pop("_login_user", None)
        return self.app.test_client(user=_ExitUser(), fresh_login=True)

    def _hunt(self, flask_client):
        with patch("utils.clickhouse.get_client", return_value=self.ch):
            response = flask_client.get(f"/api/hunting/events/{self.case.id}")
        payload = response.get_json() or {}
        self.assertEqual(response.status_code, 200, msg=payload)
        return payload

    def _readiness(self, **kwargs):
        kwargs.setdefault("redis_available", True)
        kwargs.setdefault("redis_progress", None)
        kwargs.setdefault("redis_calls", 0)
        return build_case_readiness_dto(
            db.session,
            case_id=self.case.id,
            case_uuid=self.case.uuid,
            **kwargs,
        )

    def _complete_privacy(self, batch):
        generation = batch.generation
        started = time.perf_counter()
        watermark = record_capability_batch_completion(
            session=db.session,
            case_id=generation.case_id,
            capability=CapabilityName.PRIVACY_ALIASES,
            source_ref_type=generation.source_ref_type,
            source_ref_id=generation.source_ref_id,
            source_generation=generation.source_generation,
            derivation_version=PRIVACY_ALIASES_V1,
            ingest_batch_id=batch.ingest_batch_id,
        )
        self.timings.setdefault("privacy_ms", []).append(round((time.perf_counter() - started) * 1000.0, 3))
        return watermark

    def _ingest_slice(self, generation, events, *, batch_ordinal, durable=True):
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
        verification = verify_ingest_batch(self.ch, manifest)
        if durable:
            mark_batch_durable(session=db.session, batch=batch, verification=verification)
            update_generation_ingest_accounting(session=db.session, generation=generation)
            db.session.commit()
            project_generation_control_state(self.ch, db.session, generation)
        return db.session.get(IngestBatch, batch.id), verification

    def test_required_exit_lifecycle_proof(self):
        flask_client = self._client()
        started = time.perf_counter()
        generation = allocate_case_file_initial_generation(
            session=db.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        db.session.commit()
        self.assertEqual(generation.visibility_state, EvidenceGenerationState.BUILDING_INITIAL)

        first = self.events[0:4]
        second = self.events[4:8]
        batch0, verification0 = self._ingest_slice(generation, first, batch_ordinal=0, durable=False)
        hunt = self._hunt(flask_client)
        self.assertEqual(hunt["total"], 0)
        self.assertEqual(batch0.state, IngestBatchState.STAGED)

        first_searchable_started = time.perf_counter()
        mark_batch_durable(session=db.session, batch=batch0, verification=verification0)
        update_generation_ingest_accounting(session=db.session, generation=generation)
        db.session.commit()
        project_generation_control_state(self.ch, db.session, generation)
        hunt = self._hunt(flask_client)
        hunt = self._hunt(flask_client)
        self.timings["time_to_first_searchable_ms"] = round((time.perf_counter() - first_searchable_started) * 1000.0, 3)
        self.timings["first_durable_to_hunt_ms"] = self.timings["time_to_first_searchable_ms"]
        self.assertEqual(hunt["total"], 4)
        readiness = self._readiness()
        self.assertTrue(readiness["hunt_coverage"]["search_enabled"])
        self.assertNotEqual(readiness["dimensions"]["evidence"]["label"], "Published")
        watermark = self._complete_privacy(batch0)
        self.assertEqual(watermark.contiguous_batch_ordinal, 0)

        batch1, _verification1 = self._ingest_slice(generation, second, batch_ordinal=1, durable=True)
        hunt = self._hunt(flask_client)
        self.assertEqual(hunt["total"], 8)
        self._complete_privacy(batch1)
        declare_generation_ingest_complete(
            session=db.session,
            generation=generation,
            expected_rows=len(self.events),
            final_batch_ordinal=1,
        )
        db.session.commit()
        pre = self._readiness()
        self.assertEqual(pre["dimensions"]["evidence"]["code"], "finalizing")
        self.assertNotEqual(pre["dimensions"]["evidence"]["label"], "Published")
        self.assertTrue(pre["hunt_coverage"]["search_enabled"])

        activate_initial_generation(session=db.session, generation=generation, actor="exit")
        db.session.commit()
        project_generation_control_state(self.ch, db.session, generation)
        CaseCompletionReconciliationAudit.query.delete()
        db.session.commit()
        db.session.add(
            GraphProjectionState(
                case_id=self.case.id,
                case_uuid=self.case.uuid,
                status="completed",
                mode="ingest",
            )
        )
        db.session.commit()
        after_active = self._readiness()
        self.assertEqual(after_active["dimensions"]["evidence"]["code"], "published")
        self.assertNotEqual(
            after_active["dimensions"]["reconciliation"]["code"],
            ReconciliationAssessment.RECONCILED,
        )
        self.assertEqual(after_active["dimensions"]["reconciliation"]["code"], PENDING_RECONCILIATION)
        recon_started = time.perf_counter()
        result = reconcile_case_completion(
            session=db.session,
            case_id=self.case.id,
            case_uuid=self.case.uuid,
            trigger_reason="exit_lifecycle",
            hooks=ReconciliationHooks(),
        )
        self.timings["completion_reconciliation_ms"] = round((time.perf_counter() - recon_started) * 1000.0, 3)
        self.assertEqual(result.assessment, ReconciliationAssessment.RECONCILED)
        current = self._readiness()
        self.assertEqual(current["dimensions"]["reconciliation"]["code"], ReconciliationAssessment.RECONCILED)
        self.assertEqual(current["dimensions"]["reconciliation"]["label"], "Current")

        replacement = allocate_case_file_replacement_generation(
            session=db.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        db.session.commit()
        self._ingest_slice(replacement, first, batch_ordinal=0, durable=True)
        hunt = self._hunt(flask_client)
        self.assertEqual(hunt["total"], 8)
        with_replacement = self._readiness()
        self.assertEqual(with_replacement["dimensions"]["evidence"]["code"], "published_with_replacement")
        self.assertEqual(with_replacement["dimensions"]["privacy"]["code"], "complete")
        self.assertTrue(with_replacement["dimensions"]["privacy"]["replacement_incomplete"])
        self.assertTrue(with_replacement["hunt_coverage"]["search_enabled"])

        repl_batch = (
            db.session.query(IngestBatch).filter_by(generation_id=replacement.id).one()
        )
        self._complete_privacy(repl_batch)
        declare_generation_ingest_complete(
            session=db.session, generation=replacement, expected_rows=4, final_batch_ordinal=0
        )
        activate_replacement_generation(session=db.session, replacement=replacement, actor="exit")
        db.session.commit()
        project_generation_authority_swap(
            self.ch, db.session, prior_generation=generation, new_generation=replacement
        )
        db.session.refresh(generation)
        db.session.refresh(replacement)
        self.assertEqual(generation.visibility_state, EvidenceGenerationState.SUPERSEDED)
        self.assertEqual(replacement.visibility_state, EvidenceGenerationState.ACTIVE)
        hunt = self._hunt(flask_client)
        self.assertEqual(hunt["total"], 4)
        stale = self._readiness()
        self.assertFalse(stale["dimensions"]["reconciliation"]["audit_current"])
        self.assertNotEqual(stale["dimensions"]["reconciliation"]["code"], ReconciliationAssessment.RECONCILED)

        result2 = reconcile_case_completion(
            session=db.session,
            case_id=self.case.id,
            case_uuid=self.case.uuid,
            trigger_reason="exit_lifecycle_n_plus_1",
            hooks=ReconciliationHooks(),
        )
        self.assertEqual(result2.assessment, ReconciliationAssessment.RECONCILED)
        refreshed = self._readiness()
        self.assertEqual(refreshed["dimensions"]["reconciliation"]["code"], ReconciliationAssessment.RECONCILED)

        with_redis = self._readiness(
            redis_available=True,
            redis_progress={"status": "processing", "current_item": "file.log"},
            redis_calls=2,
        )
        without_redis = self._readiness(redis_available=False, redis_progress=None, redis_calls=1)
        for name in ("evidence", "privacy", "reconciliation"):
            self.assertEqual(with_redis["dimensions"][name]["code"], without_redis["dimensions"][name]["code"])
        self.assertEqual(without_redis["dimensions"]["live_activity"]["code"], "unavailable")

        invalidate_source_generation(session=db.session, generation=replacement, reason="exit-invalidate")
        invalidate_source_generation(session=db.session, generation=generation, reason="exit-invalidate-prior")
        db.session.commit()
        withdrawn = self._readiness()
        self.assertEqual(withdrawn["dimensions"]["evidence"]["code"], "withdrawn")
        self.assertEqual(withdrawn["dimensions"]["privacy"]["code"], "withdrawn")
        self.assertFalse(withdrawn["dimensions"]["privacy"]["authorizes_ai_egress"])

        with patch(
            "utils.case_readiness.snapshot_case_completion_authority",
            side_effect=CompletionCompositionUnknown("forced"),
        ):
            failed = self._readiness(redis_available=True, redis_progress={"status": "processing"})
        self.assertEqual(failed["composition"], "unknown")
        self.assertEqual(failed["dimensions"]["evidence"]["code"], "unavailable")
        self.assertNotEqual(failed["composition"], CaseIngestComposition.LEGACY_ONLY)
        self.assertTrue(failed["hunt_coverage"]["search_enabled"])
        self.timings["lifecycle_wall_ms"] = round((time.perf_counter() - started) * 1000.0, 3)
        print("PHASE1B_EXIT_LIFECYCLE", json.dumps(self.timings))

    def test_hunt_publication_bridge_control_plane_scale(self):
        generation = allocate_case_file_initial_generation(
            session=db.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        db.session.commit()
        self._ingest_slice(generation, self.events[0:4], batch_ordinal=0, durable=True)
        declare_generation_ingest_complete(
            session=db.session, generation=generation, expected_rows=4, final_batch_ordinal=0
        )
        activate_initial_generation(session=db.session, generation=generation, actor="exit-scale")
        db.session.commit()
        project_generation_control_state(self.ch, db.session, generation)

        now = datetime.now(timezone.utc).replace(tzinfo=None)
        veg_rows = []
        dib_rows = []
        extra_cases = 40
        sources_per_case = 10
        batches_per_source = 12
        for case_offset in range(extra_cases):
            case_id = 900000 + case_offset
            for source_offset in range(sources_per_case):
                source_id = str(1000 + source_offset)
                veg_rows.append((
                    case_id,
                    "CASE_FILE",
                    source_id,
                    1,
                    "ACTIVE",
                    1,
                    1,
                    now,
                ))
                for ordinal in range(batches_per_source):
                    dib_rows.append((
                        f"scale-{case_id}-{source_id}-{ordinal}",
                        case_id,
                        "CASE_FILE",
                        source_id,
                        1,
                        ordinal,
                        8,
                        "0" * 64,
                        "DURABLE",
                        1,
                        now,
                        now,
                    ))
        self.ch.insert("visible_evidence_generations", veg_rows, column_names=list(VISIBLE_EVIDENCE_GENERATIONS_COLUMNS))
        self.ch.insert("durable_ingest_batches", dib_rows, column_names=list(DURABLE_INGEST_BATCHES_COLUMNS))

        unscoped = build_hunting_publication_bridge(alias="e")
        scoped = build_hunting_publication_bridge(alias="e", case_id_param="{case_id:UInt32}")
        count_unscoped = f"""
            SELECT count()
            FROM events AS e
            {unscoped["join_sql"]}
            WHERE e.case_id = {{case_id:UInt32}}{unscoped["where_sql"]}
        """
        page_unscoped = f"""
            SELECT e.search_blob
            FROM events AS e
            {unscoped["join_sql"]}
            WHERE e.case_id = {{case_id:UInt32}}{unscoped["where_sql"]}
            ORDER BY COALESCE(e.timestamp_utc, e.timestamp) DESC
            LIMIT 50
        """
        count_scoped = f"""
            SELECT count()
            FROM events AS e
            {scoped["join_sql"]}
            WHERE e.case_id = {{case_id:UInt32}}{scoped["where_sql"]}
        """
        page_scoped = f"""
            SELECT e.search_blob
            FROM events AS e
            {scoped["join_sql"]}
            WHERE e.case_id = {{case_id:UInt32}}{scoped["where_sql"]}
            ORDER BY COALESCE(e.timestamp_utc, e.timestamp) DESC
            LIMIT 50
        """
        params = {"case_id": self.case.id}
        samples = 40
        unscoped_count = []
        unscoped_page = []
        scoped_count = []
        scoped_page = []
        for _ in range(samples):
            unscoped_count.append(_query_with_stats(self.ch, count_unscoped, params))
            unscoped_page.append(_query_with_stats(self.ch, page_unscoped, params))
            scoped_count.append(_query_with_stats(self.ch, count_scoped, params))
            scoped_page.append(_query_with_stats(self.ch, page_scoped, params))

        def _pack(rows, key):
            values = [item[key] for item in rows]
            return {
                "p50": _percentile(values, 50),
                "p95": _percentile(values, 95),
                "p99": _percentile(values, 99),
                "mean": round(statistics.mean(values), 3),
                "max": round(max(values), 3),
                "samples": len(values),
            }

        explain_unscoped = self.ch.query(f"EXPLAIN indexes = 1\n{count_unscoped}", parameters=params)
        explain_scoped = self.ch.query(f"EXPLAIN indexes = 1\n{count_scoped}", parameters=params)
        last_unscoped = unscoped_count[-1]
        last_scoped = scoped_count[-1]
        read_row_ratio = None
        if last_scoped["read_rows"]:
            read_row_ratio = round(last_unscoped["read_rows"] / max(last_scoped["read_rows"], 1), 3)
        unscoped_p95 = _percentile([row["elapsed_ms"] for row in unscoped_count], 95) or 0
        scoped_p95 = _percentile([row["elapsed_ms"] for row in scoped_count], 95) or 0.001
        material = bool(
            (last_unscoped["read_rows"] >= 1000 and (read_row_ratio or 0) >= 5)
            or (unscoped_p95 >= 20 and unscoped_p95 >= 1.25 * scoped_p95)
        )
        artifact = {
            "control_plane_population": {
                "extra_cases": extra_cases,
                "sources_per_case": sources_per_case,
                "batches_per_source": batches_per_source,
                "visible_evidence_generations": extra_cases * sources_per_case + 1,
                "durable_ingest_batches": extra_cases * sources_per_case * batches_per_source + 1,
            },
            "unscoped": {
                "count_ms": _pack(unscoped_count, "elapsed_ms"),
                "page_ms": _pack(unscoped_page, "elapsed_ms"),
                "count_read_rows": _pack(unscoped_count, "read_rows"),
                "count_read_bytes": _pack(unscoped_count, "read_bytes"),
                "last_summary": last_unscoped["summary"],
                "explain": [str(row[0]) for row in (explain_unscoped.result_rows or [])],
            },
            "case_scoped": {
                "count_ms": _pack(scoped_count, "elapsed_ms"),
                "page_ms": _pack(scoped_page, "elapsed_ms"),
                "count_read_rows": _pack(scoped_count, "read_rows"),
                "count_read_bytes": _pack(scoped_count, "read_bytes"),
                "last_summary": last_scoped["summary"],
                "explain": [str(row[0]) for row in (explain_scoped.result_rows or [])],
            },
            "read_row_ratio_unscoped_over_scoped": read_row_ratio,
            "material_unscoped_overhead": material,
            "bridge_still_events_table": True,
            "events_current": False,
        }
        ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
        (ARTIFACT_DIR / "phase1b_exit_hunt_bridge_scale.json").write_text(
            json.dumps(artifact, indent=2) + "\n",
            encoding="utf-8",
        )
        print("PHASE1B_EXIT_HUNT_SCALE", json.dumps({
            "material_unscoped_overhead": material,
            "unscoped_count_p95": artifact["unscoped"]["count_ms"]["p95"],
            "scoped_count_p95": artifact["case_scoped"]["count_ms"]["p95"],
            "read_row_ratio": read_row_ratio,
        }))
        flask_client = self._client()
        hunt = self._hunt(flask_client)
        self.assertEqual(hunt["total"], 4)
        self.assertTrue(self._readiness()["hunt_coverage"]["search_enabled"])
        self.assertNotIn("FROM events_current", count_unscoped)
        self.assertNotIn("event_observations_current", count_unscoped)
        self._scale_artifact = artifact


if __name__ == "__main__":
    unittest.main()
