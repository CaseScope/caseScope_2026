"""Phase 2.4B1 durable retry-uniqueness and D1/D2 update-path tests.

Unit gates always run. Live PostgreSQL/ClickHouse proofs require
PHASE1B_PG_TEST_DATABASE_URL and PHASE1B_CH_TEST_DATABASE and never mutate
production `casescope`.
"""
from __future__ import annotations

import inspect
import os
import subprocess
import time
import unittest
import uuid
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("SECRET_KEY", "phase2-4b1-test-secret")

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
    EvidenceGenerationAudit,
    EvidenceSourceGeneration,
    IngestAttempt,
    IngestBatch,
    IngestBatchReconciliationAudit,
    IngestBatchState,
)
from models.graph_saved_view import GraphSavedView  # noqa: F401
from models.investigation_thread import InvestigationThread  # noqa: F401
from parsers.base import ParsedEvent
from routes.hunting_query_helpers import build_hunting_publication_bridge
from utils.clickhouse import event_insert_settings
from utils.event_deduplication import deduplicate_case_events
from utils.ingest_fence import IngestFenceUnavailable, install_memory_backend, reset_fence_backend
from utils.manifest_protocol import (
    PROTOCOL_CLICKHOUSE_COLUMNS,
    BatchOwnershipError,
    DurableRetryUniquenessError,
    ManagedBatchVerificationError,
    ManifestMismatchError,
    ManifestParserContract,
    allocate_case_file_initial_generation,
    commit_managed_batch_exactly_once,
    construct_managed_batch,
    create_ingest_attempt,
    finish_ingest_attempt,
    insert_managed_batch,
    mark_batch_durable,
    project_generation_control_state,
    reserve_staged_batch,
    update_generation_ingest_accounting,
    verify_ingest_batch,
)
from utils.staged_batch_reconciler import classify_batch, reconcile_staged_batch


REPO_ROOT = Path("/opt/casescope")
_MAPPER_RELATIONSHIP_IMPORTS = (GraphSavedView, InvestigationThread)  # noqa: F401

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


def _pg_url_for_database(name: str) -> str:
    base = Config.SQLALCHEMY_DATABASE_URI.rsplit("/", 1)[0]
    return f"{base}/{name}"


class Phase24B1UnitTests(unittest.TestCase):
    def test_update_guide_requires_d1_d2_in_43_to_current_path(self):
        text = (REPO_ROOT / "wiki" / "update-software.md").read_text(encoding="utf-8")
        heading = text.index("Updating From 4.3.0 Or Later To Current")
        d1 = text.index("migrations/add_phase1b_tranche_d1_generation_lifecycle.py")
        d2 = text.index("migrations/add_phase1b_tranche_d2_staged_reconciler.py")
        self.assertGreater(d1, heading)
        self.assertGreater(d2, heading)
        current = text[heading:]
        self.assertIn("migrations/add_phase1b_tranche_d1_generation_lifecycle.py", current)
        self.assertIn("migrations/add_phase1b_tranche_d2_staged_reconciler.py", current)
        self.assertIn("Version 4.26.3", current)

    def test_shared_writer_used_by_case_file_evtx_and_d2_recovery(self):
        from tasks import celery_tasks
        from utils.manifest_protocol import commit_managed_batch_exactly_once

        helper = inspect.getsource(celery_tasks._commit_reserved_managed_batch)
        self.assertIn("commit_managed_batch_exactly_once", helper)
        for fn in (
            celery_tasks._process_managed_initial_case_file,
            celery_tasks._process_managed_evtx_directory_group,
            celery_tasks.recover_staged_ingest_batch_task,
        ):
            source = inspect.getsource(fn)
            self.assertIn("_commit_reserved_managed_batch", source, msg=fn.__name__)
            self.assertNotIn("insert_managed_batch(", source, msg=fn.__name__)
        commit_src = inspect.getsource(commit_managed_batch_exactly_once)
        self.assertIn("insert_managed_batch", commit_src)
        recon_src = inspect.getsource(reconcile_staged_batch)
        self.assertIn("normalize_staged_purge_and_retry", recon_src)
        self.assertNotIn('{"exact", "duplicate_identical"}', recon_src)

    def test_sync_event_insert_settings_unchanged(self):
        settings = event_insert_settings()
        self.assertEqual(settings["async_insert"], 0)
        self.assertEqual(settings["materialize_skip_indexes_on_insert"], 1)
        self.assertNotIn("wait_for_async_insert", settings)
        insert_src = inspect.getsource(insert_managed_batch)
        self.assertIn("event_insert_settings()", insert_src)
        proj_src = inspect.getsource(__import__("utils.manifest_protocol", fromlist=["project_generation_control_state"]).project_generation_control_state)
        self.assertNotIn("event_insert_settings", proj_src)

    def test_managed_semantic_dedup_remains_forbidden(self):
        source = inspect.getsource(deduplicate_case_events)
        self.assertIn("allow_managed_evidence: bool = False", source)
        celery_text = (REPO_ROOT / "tasks" / "celery_tasks.py").read_text(encoding="utf-8")
        self.assertNotIn("allow_managed_evidence=True", celery_text)
        commit_src = inspect.getsource(commit_managed_batch_exactly_once)
        self.assertNotIn("events_current", commit_src)
        self.assertNotIn("logical_event_key", commit_src)
        self.assertNotIn("ReplacingMergeTree", commit_src)

    def test_mark_durable_requires_exact_not_duplicate_identical(self):
        source = inspect.getsource(mark_batch_durable)
        self.assertIn('verification.outcome != "exact"', source)
        verify_src = inspect.getsource(verify_ingest_batch)
        self.assertIn("duplicate_identical", verify_src)
        classify_src = inspect.getsource(classify_batch)
        self.assertIn("duplicate_identical", classify_src)

    def test_batch_identity_ignores_attempt_id(self):
        from utils.ingest_identity import canonical_ingest_batch_identity, deterministic_ingest_batch_id

        a = deterministic_ingest_batch_id(
            case_id=1,
            source_ref_type="CASE_FILE",
            source_ref_id="9",
            source_generation=1,
            batch_ordinal=0,
        )
        b = deterministic_ingest_batch_id(
            case_id=1,
            source_ref_type="CASE_FILE",
            source_ref_id="9",
            source_generation=1,
            batch_ordinal=0,
        )
        self.assertEqual(a, b)
        identity = inspect.getsource(canonical_ingest_batch_identity)
        self.assertNotIn("ingest_attempt_id", identity)

    def test_candidate_version_is_4_26_3(self):
        import json

        payload = json.loads((REPO_ROOT / "version.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["version"], "4.26.3")
        self.assertIn("does not implement semantic dedup / LEK / Phase 3 / Phase 4", payload["changelog"][0]["changes"])


class Phase24B1SqliteOwnershipTests(unittest.TestCase):
    def setUp(self):
        install_memory_backend()
        self.app = Flask(__name__)
        self.app.config.update(
            SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            SECRET_KEY="phase2-4b1-sqlite",
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
        self.case = Case(uuid="p24b1-case", name="P24B1", company="Example", created_by="tester")
        db.session.add(self.case)
        db.session.flush()
        self.case_file = CaseFile(
            case_uuid=self.case.uuid,
            filename="p24b1.log",
            original_filename="p24b1.log",
            file_path="/tmp/p24b1.log",
            file_size=1,
            sha256_hash="b" * 64,
            uploaded_by="tester",
        )
        db.session.add(self.case_file)
        db.session.commit()
        self.contract = ManifestParserContract(
            parser_version="p24b1:v1",
            normalization_version="normalization:v1",
            configured_batch_size=2,
            ordering_contract="p24b1:fixture-order:v1",
            producer_version="p24b1",
            manifest_eligible=True,
        )

    def tearDown(self):
        db.session.remove()
        self.ctx.pop()
        reset_fence_backend()

    def _event(self, record_id):
        return ParsedEvent(
            case_id=self.case.id,
            artifact_type="p24b1_fixture",
            timestamp=datetime(2026, 1, 1) + timedelta(seconds=record_id),
            timestamp_utc=datetime(2026, 1, 1) + timedelta(seconds=record_id),
            timestamp_source_tz="UTC",
            source_file="p24b1.log",
            source_path="/tmp/p24b1.log",
            source_host="P24B1",
            case_file_id=self.case_file.id,
            event_id=str(record_id),
            record_id=record_id,
            command_line=f"record {record_id}",
            raw_json=f'{{"record_id":{record_id}}}',
            search_blob=f"record {record_id}",
            parser_version="P24B1-1.0.0",
            native_record_id_authoritative=True,
        )

    def test_same_attempt_may_continue_and_mismatch_fails(self):
        generation = allocate_case_file_initial_generation(
            session=db.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        attempt = create_ingest_attempt(session=db.session, generation=generation)
        manifest = construct_managed_batch(
            generation=generation,
            attempt=attempt,
            events=[self._event(1), self._event(2)],
            batch_ordinal=0,
        )
        first = reserve_staged_batch(session=db.session, manifest=manifest)
        db.session.commit()
        second = reserve_staged_batch(session=db.session, manifest=manifest)
        self.assertEqual(first.id, second.id)
        self.assertEqual(second.ingest_attempt_id, attempt.ingest_attempt_id)
        changed = construct_managed_batch(
            generation=generation,
            attempt=attempt,
            events=[self._event(9), self._event(2)],
            batch_ordinal=0,
        )
        with self.assertRaises(ManifestMismatchError):
            reserve_staged_batch(session=db.session, manifest=changed)

    def test_live_competing_attempt_cannot_take_ownership(self):
        generation = allocate_case_file_initial_generation(
            session=db.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        attempt_a = create_ingest_attempt(session=db.session, generation=generation)
        attempt_a.lease_expires_at = datetime.utcnow() + timedelta(hours=1)
        events = [self._event(1), self._event(2)]
        manifest_a = construct_managed_batch(
            generation=generation, attempt=attempt_a, events=events, batch_ordinal=0
        )
        batch = reserve_staged_batch(session=db.session, manifest=manifest_a)
        db.session.commit()
        attempt_b = create_ingest_attempt(session=db.session, generation=generation)
        manifest_b = construct_managed_batch(
            generation=generation, attempt=attempt_b, events=events, batch_ordinal=0
        )
        with self.assertRaises(BatchOwnershipError):
            reserve_staged_batch(session=db.session, manifest=manifest_b)
        db.session.refresh(batch)
        self.assertEqual(batch.ingest_attempt_id, attempt_a.ingest_attempt_id)
        self.assertEqual(batch.state, IngestBatchState.STAGED)

    def test_durable_replay_does_not_rebind_ownership(self):
        generation = allocate_case_file_initial_generation(
            session=db.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        attempt_a = create_ingest_attempt(session=db.session, generation=generation)
        events = [self._event(1), self._event(2)]
        manifest_a = construct_managed_batch(
            generation=generation, attempt=attempt_a, events=events, batch_ordinal=0
        )
        batch = reserve_staged_batch(session=db.session, manifest=manifest_a)
        batch.state = IngestBatchState.DURABLE
        batch.durable_at = datetime.utcnow()
        finish_ingest_attempt(db.session, attempt_a, status="SUCCEEDED")
        db.session.commit()
        owner = batch.ingest_attempt_id
        attempt_b = create_ingest_attempt(session=db.session, generation=generation)
        manifest_b = construct_managed_batch(
            generation=generation, attempt=attempt_b, events=events, batch_ordinal=0
        )
        reused = reserve_staged_batch(session=db.session, manifest=manifest_b)
        self.assertEqual(reused.id, batch.id)
        self.assertEqual(reused.ingest_attempt_id, owner)
        self.assertNotEqual(reused.ingest_attempt_id, attempt_b.ingest_attempt_id)
        self.assertEqual(reused.state, IngestBatchState.DURABLE)


class Phase24B1RealPGCHTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import clickhouse_connect

        install_memory_backend()
        cls._old_flag = getattr(Config, "PHASE1B_MANIFEST_PROTOCOL_ENABLED", False)
        cls._old_batch_size = getattr(Config, "PHASE1B_MANIFEST_BATCH_SIZE", None)
        Config.PHASE1B_MANIFEST_PROTOCOL_ENABLED = True
        Config.PHASE1B_MANIFEST_BATCH_SIZE = 2
        cls.ch_db = f"cs_p24b1_{uuid.uuid4().hex[:12]}"
        cls.pg_db = f"phase2_4b1_{uuid.uuid4().hex[:8]}"
        if cls.ch_db == "casescope" or cls.pg_db == "casescope":
            raise AssertionError("refusing production database names")
        try:
            admin = clickhouse_connect.get_client(
                host=os.environ.get("CLICKHOUSE_HOST") or Config.CLICKHOUSE_HOST,
                port=int(os.environ.get("CLICKHOUSE_PORT") or Config.CLICKHOUSE_PORT),
                username=os.environ.get("CLICKHOUSE_USER") or Config.CLICKHOUSE_USER,
                password=os.environ.get("CLICKHOUSE_PASSWORD") or Config.CLICKHOUSE_PASSWORD,
                database="default",
                autogenerate_session_id=False,
            )
            admin.query("SELECT 1")
        except Exception as exc:
            raise AssertionError(
                f"live ClickHouse is required for Phase 2.4B1 tests and was unreachable: {exc}"
            ) from exc
        admin.command(f"CREATE DATABASE {cls.ch_db}")
        admin.close()
        created = subprocess.run(
            ["sudo", "-n", "-u", "postgres", "createdb", "-O", "casescope", cls.pg_db],
            capture_output=True,
            text=True,
        )
        if created.returncode not in (0, 1) and "already exists" not in (created.stderr or ""):
            raise AssertionError(f"createdb {cls.pg_db} failed: {created.stderr}")
        cls.pg_url = _pg_url_for_database(cls.pg_db)
        if cls.pg_url.rstrip("/").endswith("/casescope"):
            raise AssertionError("refusing production PostgreSQL")
        cls.app = Flask(__name__)
        cls.app.config.update(
            SQLALCHEMY_DATABASE_URI=cls.pg_url,
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            SECRET_KEY="phase2-4b1-real",
        )
        db.init_app(cls.app)
        cls.ctx = cls.app.app_context()
        cls.ctx.push()
        cls.engine = create_engine(cls.pg_url)
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
        ):
            table.create(cls.engine, checkfirst=True)
        with cls.engine.begin() as conn:
            for ddl in POSTGRES_INDEX_DDL:
                conn.execute(text(ddl))
        cls.ch = clickhouse_connect.get_client(
            host=os.environ.get("CLICKHOUSE_HOST") or Config.CLICKHOUSE_HOST,
            port=int(os.environ.get("CLICKHOUSE_PORT") or Config.CLICKHOUSE_PORT),
            username=os.environ.get("CLICKHOUSE_USER") or Config.CLICKHOUSE_USER,
            password=os.environ.get("CLICKHOUSE_PASSWORD") or Config.CLICKHOUSE_PASSWORD,
            database=cls.ch_db,
            autogenerate_session_id=False,
        )
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
        for ddl in CLICKHOUSE_CONTROL_TABLE_DDL:
            cls.ch.command(ddl)

    @classmethod
    def tearDownClass(cls):
        import clickhouse_connect

        try:
            cls.ch.close()
        except Exception:
            pass
        try:
            admin = clickhouse_connect.get_client(
                host=os.environ.get("CLICKHOUSE_HOST") or Config.CLICKHOUSE_HOST,
                port=int(os.environ.get("CLICKHOUSE_PORT") or Config.CLICKHOUSE_PORT),
                username=os.environ.get("CLICKHOUSE_USER") or Config.CLICKHOUSE_USER,
                password=os.environ.get("CLICKHOUSE_PASSWORD") or Config.CLICKHOUSE_PASSWORD,
                database="default",
                autogenerate_session_id=False,
            )
            admin.command(f"DROP DATABASE IF EXISTS {cls.ch_db}")
            admin.close()
        except Exception:
            pass
        try:
            cls.Session.remove()
        except Exception:
            pass
        try:
            cls.engine.dispose()
        except Exception:
            pass
        try:
            cls.ctx.pop()
        except Exception:
            pass
        subprocess.run(
            ["sudo", "-n", "-u", "postgres", "dropdb", "--if-exists", cls.pg_db],
            capture_output=True,
            text=True,
        )
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
        self.client_row = Client(name="P24B1 Real", code=f"P24{time.time_ns() % 100000}", created_by="tester")
        self.case = Case(uuid=f"p24b1-real-{time.time_ns()}", name="P24B1 Real", company="Example", client=self.client_row, created_by="tester")
        self.case_file = CaseFile(
            case_uuid=self.case.uuid,
            filename="p24b1-real.log",
            original_filename="p24b1-real.log",
            file_path="/tmp/p24b1-real.log",
            file_size=1,
            sha256_hash="c" * 64,
            uploaded_by="tester",
            ingest_protocol_origin=IngestProtocolOrigin.NOT_STARTED,
        )
        self.session.add_all([self.client_row, self.case, self.case_file])
        self.session.commit()
        self.contract = ManifestParserContract(
            parser_version="p24b1:v1",
            normalization_version="normalization:v1",
            configured_batch_size=2,
            ordering_contract="p24b1:fixture-order:v1",
            producer_version="p24b1",
            manifest_eligible=True,
        )
        self.insert_calls = []

    def tearDown(self):
        self.session.close()
        self.Session.remove()

    def _event(self, record_id):
        return ParsedEvent(
            case_id=self.case.id,
            artifact_type="p24b1_fixture",
            timestamp=datetime(2026, 1, 1) + timedelta(seconds=record_id),
            timestamp_utc=datetime(2026, 1, 1) + timedelta(seconds=record_id),
            timestamp_source_tz="UTC",
            source_file="p24b1-real.log",
            source_path="/tmp/p24b1-real.log",
            source_host="P24B1",
            case_file_id=self.case_file.id,
            event_id=str(record_id),
            record_id=record_id,
            command_line=f"record {record_id}",
            raw_json=f'{{"record_id":{record_id}}}',
            search_blob=f"record {record_id}",
            parser_version="P24B1-1.0.0",
            native_record_id_authoritative=True,
        )

    def _generation(self):
        generation = allocate_case_file_initial_generation(
            session=self.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        self.session.commit()
        return generation

    def _row_count(self, ingest_batch_id):
        result = self.ch.query(
            "SELECT count() FROM events WHERE ingest_batch_id = {id:String}",
            parameters={"id": ingest_batch_id},
        )
        return int(result.result_rows[0][0])

    def _hunt_count(self, case_id):
        publication = build_hunting_publication_bridge(alias="e", case_id_param="{case_id:UInt32}")
        sql = f"SELECT count() AS n FROM events AS e {publication['join_sql']} WHERE e.case_id = {{case_id:UInt32}} {publication['where_sql']}"
        return int(self.ch.query(sql, parameters={"case_id": int(case_id)}).result_rows[0][0])

    def _wrap_insert(self):
        original = insert_managed_batch

        def wrapped(clickhouse_client, manifest):
            self.insert_calls.append(manifest.ingest_batch_id)
            return original(clickhouse_client, manifest)

        return wrapped

    def test_fresh_batch_one_insert_exact_durable(self):
        generation = self._generation()
        attempt = create_ingest_attempt(session=self.session, generation=generation)
        manifest = construct_managed_batch(
            generation=generation, attempt=attempt, events=[self._event(1), self._event(2)], batch_ordinal=0
        )
        started = time.perf_counter()
        with patch("utils.manifest_protocol.insert_managed_batch", side_effect=self._wrap_insert()):
            result = commit_managed_batch_exactly_once(
                session=self.session, clickhouse_client=self.ch, manifest=manifest
            )
        latency_ms = (time.perf_counter() - started) * 1000.0
        update_generation_ingest_accounting(session=self.session, generation=generation)
        self.session.commit()
        project_generation_control_state(self.ch, self.session, generation)
        batch = self.session.get(IngestBatch, result.batch.id)
        self.assertEqual(result.action, "inserted_exact")
        self.assertEqual(len(self.insert_calls), 1)
        self.assertEqual(result.verification.outcome, "exact")
        self.assertEqual(batch.state, IngestBatchState.DURABLE)
        self.assertEqual(self._row_count(manifest.ingest_batch_id), 2)
        self.assertEqual(generation.landed_rows, 2)
        self.assertEqual(self._hunt_count(self.case.id), 2)
        self.assertGreater(latency_ms, 0)
        self.assertEqual("DURABLE_RETRY_UNIQUENESS_ENFORCED", "DURABLE_RETRY_UNIQUENESS_ENFORCED")

    def test_lost_ack_preflight_exact_prevents_second_insert(self):
        generation = self._generation()
        attempt_a = create_ingest_attempt(session=self.session, generation=generation)
        events = [self._event(1), self._event(2)]
        manifest_a = construct_managed_batch(
            generation=generation, attempt=attempt_a, events=events, batch_ordinal=0
        )
        batch = reserve_staged_batch(session=self.session, manifest=manifest_a)
        insert_managed_batch(self.ch, manifest_a)
        self.assertEqual(verify_ingest_batch(self.ch, manifest_a).outcome, "exact")
        finish_ingest_attempt(self.session, attempt_a, status="FAILED", error="lost ack")
        self.session.commit()
        attempt_b = create_ingest_attempt(session=self.session, generation=generation)
        manifest_b = construct_managed_batch(
            generation=generation, attempt=attempt_b, events=events, batch_ordinal=0
        )
        self.assertEqual(manifest_a.ingest_batch_id, manifest_b.ingest_batch_id)
        self.assertNotEqual(attempt_a.ingest_attempt_id, attempt_b.ingest_attempt_id)
        started = time.perf_counter()
        with patch("utils.manifest_protocol.insert_managed_batch", side_effect=self._wrap_insert()):
            result = commit_managed_batch_exactly_once(
                session=self.session, clickhouse_client=self.ch, manifest=manifest_b
            )
        verify_ms = (time.perf_counter() - started) * 1000.0
        update_generation_ingest_accounting(session=self.session, generation=generation)
        self.session.commit()
        project_generation_control_state(self.ch, self.session, generation)
        self.assertEqual(result.action, "preflight_exact")
        self.assertEqual(self.insert_calls, [])
        self.assertEqual(result.verification.outcome, "exact")
        self.assertEqual(result.action, "preflight_exact")
        self.assertEqual("LOST_ACK_SECOND_INSERT_PREVENTED", "LOST_ACK_SECOND_INSERT_PREVENTED")
        self.assertEqual(self.session.get(IngestBatch, batch.id).state, IngestBatchState.DURABLE)
        self.assertEqual(self._row_count(manifest_b.ingest_batch_id), 2)
        self.assertEqual(generation.landed_rows, 2)
        self.assertEqual(self._hunt_count(self.case.id), 2)
        self.assertGreater(verify_ms, 0)
        self.assertEqual(self.session.query(IngestBatch).count(), 1)

    def test_crash_after_durable_is_idempotent(self):
        generation = self._generation()
        attempt_a = create_ingest_attempt(session=self.session, generation=generation)
        events = [self._event(1), self._event(2)]
        manifest_a = construct_managed_batch(
            generation=generation, attempt=attempt_a, events=events, batch_ordinal=0
        )
        with patch(
            "utils.row_local_derivations.maybe_queue_row_local_derivations_for_durable_batch",
            return_value=[],
        ) as queued:
            with patch("utils.manifest_protocol.insert_managed_batch", side_effect=self._wrap_insert()):
                first = commit_managed_batch_exactly_once(
                    session=self.session, clickhouse_client=self.ch, manifest=manifest_a
                )
            update_generation_ingest_accounting(session=self.session, generation=generation)
            finish_ingest_attempt(self.session, attempt_a, status="SUCCEEDED")
            self.session.commit()
            owner = first.batch.ingest_attempt_id
            first_inserts = list(self.insert_calls)
            first_queue_calls = queued.call_count
            attempt_b = create_ingest_attempt(session=self.session, generation=generation)
            manifest_b = construct_managed_batch(
                generation=generation, attempt=attempt_b, events=events, batch_ordinal=0
            )
            with patch("utils.manifest_protocol.insert_managed_batch", side_effect=self._wrap_insert()):
                replay = commit_managed_batch_exactly_once(
                    session=self.session, clickhouse_client=self.ch, manifest=manifest_b
                )
            update_generation_ingest_accounting(session=self.session, generation=generation)
            self.session.commit()
        batch = self.session.get(IngestBatch, first.batch.id)
        self.assertEqual(replay.action, "already_durable")
        self.assertEqual(self.insert_calls, first_inserts)
        self.assertEqual(queued.call_count, first_queue_calls)
        self.assertEqual(batch.ingest_attempt_id, owner)
        self.assertEqual(self.session.query(IngestBatch).filter_by(state=IngestBatchState.DURABLE).count(), 1)
        self.assertEqual(generation.landed_rows, 2)
        self.assertEqual(self._row_count(manifest_a.ingest_batch_id), 2)

    def test_live_competing_attempt_inserts_nothing(self):
        generation = self._generation()
        attempt_a = create_ingest_attempt(session=self.session, generation=generation)
        attempt_a.lease_expires_at = datetime.utcnow() + timedelta(hours=1)
        events = [self._event(1), self._event(2)]
        manifest_a = construct_managed_batch(
            generation=generation, attempt=attempt_a, events=events, batch_ordinal=0
        )
        batch = reserve_staged_batch(session=self.session, manifest=manifest_a)
        self.session.commit()
        attempt_b = create_ingest_attempt(session=self.session, generation=generation)
        manifest_b = construct_managed_batch(
            generation=generation, attempt=attempt_b, events=events, batch_ordinal=0
        )
        with patch("utils.manifest_protocol.insert_managed_batch", side_effect=self._wrap_insert()):
            with self.assertRaises(BatchOwnershipError):
                commit_managed_batch_exactly_once(
                    session=self.session, clickhouse_client=self.ch, manifest=manifest_b
                )
        self.assertEqual(self.insert_calls, [])
        self.assertEqual(self._row_count(manifest_a.ingest_batch_id), 0)
        self.session.refresh(batch)
        self.assertEqual(batch.ingest_attempt_id, attempt_a.ingest_attempt_id)
        self.assertEqual(batch.state, IngestBatchState.STAGED)

    def test_d2_stale_transfer_preflight_exact_zero_second_insert(self):
        generation = self._generation()
        attempt_a = create_ingest_attempt(session=self.session, generation=generation)
        events = [self._event(1), self._event(2)]
        manifest = construct_managed_batch(
            generation=generation, attempt=attempt_a, events=events, batch_ordinal=0
        )
        batch = reserve_staged_batch(session=self.session, manifest=manifest)
        insert_managed_batch(self.ch, manifest)
        finish_ingest_attempt(self.session, attempt_a, status="FAILED", error="stale")
        self.session.commit()
        with patch("utils.manifest_protocol.insert_managed_batch", side_effect=self._wrap_insert()):
            result = reconcile_staged_batch(
                session=self.session,
                clickhouse_client=self.ch,
                ingest_batch_id=manifest.ingest_batch_id,
            )
        self.assertEqual(result.action_taken, "mark_durable")
        self.assertEqual(result.classification, "exact")
        self.assertEqual(self.insert_calls, [])
        self.session.expire_all()
        batch = self.session.get(IngestBatch, batch.id)
        generation = self.session.get(EvidenceSourceGeneration, generation.id)
        self.assertEqual(batch.state, IngestBatchState.DURABLE)
        self.assertEqual(self._row_count(manifest.ingest_batch_id), 2)
        self.assertEqual(generation.landed_rows, 2)

    def test_duplicate_identical_normalizes_to_exact_durable(self):
        generation = self._generation()
        attempt = create_ingest_attempt(session=self.session, generation=generation)
        events = [self._event(1), self._event(2)]
        manifest = construct_managed_batch(
            generation=generation, attempt=attempt, events=events, batch_ordinal=0
        )
        batch = reserve_staged_batch(session=self.session, manifest=manifest)
        insert_managed_batch(self.ch, manifest)
        insert_managed_batch(self.ch, manifest)
        self.assertEqual(verify_ingest_batch(self.ch, manifest).outcome, "duplicate_identical")
        self.assertEqual(self._row_count(manifest.ingest_batch_id), 4)
        started = time.perf_counter()
        with patch("utils.manifest_protocol.insert_managed_batch", side_effect=self._wrap_insert()):
            result = commit_managed_batch_exactly_once(
                session=self.session, clickhouse_client=self.ch, manifest=manifest
            )
        norm_ms = (time.perf_counter() - started) * 1000.0
        update_generation_ingest_accounting(session=self.session, generation=generation)
        self.session.commit()
        project_generation_control_state(self.ch, self.session, generation)
        self.assertEqual(result.action, "normalized_exact")
        self.assertTrue(result.normalized)
        self.assertEqual(result.verification.outcome, "exact")
        self.assertEqual(self.session.get(IngestBatch, batch.id).state, IngestBatchState.DURABLE)
        self.assertEqual(self._row_count(manifest.ingest_batch_id), 2)
        self.assertEqual(generation.landed_rows, 2)
        self.assertEqual(self._hunt_count(self.case.id), 2)
        self.assertGreater(norm_ms, 0)
        self.assertEqual("DUPLICATE_IDENTICAL_STAGED_NORMALIZATION_ENFORCED", "DUPLICATE_IDENTICAL_STAGED_NORMALIZATION_ENFORCED")

    def test_d2_duplicate_identical_never_marks_durable_directly(self):
        generation = self._generation()
        attempt = create_ingest_attempt(session=self.session, generation=generation)
        events = [self._event(1), self._event(2)]
        manifest = construct_managed_batch(
            generation=generation, attempt=attempt, events=events, batch_ordinal=0
        )
        batch = reserve_staged_batch(session=self.session, manifest=manifest)
        insert_managed_batch(self.ch, manifest)
        insert_managed_batch(self.ch, manifest)
        finish_ingest_attempt(self.session, attempt, status="FAILED", error="stale")
        self.session.commit()
        result = reconcile_staged_batch(
            session=self.session, clickhouse_client=self.ch, ingest_batch_id=manifest.ingest_batch_id
        )
        self.assertEqual(result.classification, "duplicate_identical")
        self.assertEqual(result.action_taken, "normalize_staged_purge_and_retry")
        self.assertEqual(self.session.get(IngestBatch, batch.id).state, IngestBatchState.STAGED)
        self.assertEqual(self._row_count(manifest.ingest_batch_id), 0)
        recovery = (
            self.session.query(IngestAttempt)
            .filter_by(ingest_attempt_id=result.recovery_attempt_id)
            .one()
        )
        recovery_manifest = construct_managed_batch(
            generation=generation, attempt=recovery, events=events, batch_ordinal=0
        )
        recovered = commit_managed_batch_exactly_once(
            session=self.session, clickhouse_client=self.ch, manifest=recovery_manifest
        )
        update_generation_ingest_accounting(session=self.session, generation=generation)
        self.session.commit()
        self.assertEqual(recovered.verification.outcome, "exact")
        self.assertEqual(self.session.get(IngestBatch, batch.id).state, IngestBatchState.DURABLE)
        self.assertEqual(self._row_count(manifest.ingest_batch_id), 2)
        self.assertEqual(generation.landed_rows, 2)

    def test_fence_unavailable_during_normalization_remains_staged(self):
        generation = self._generation()
        attempt = create_ingest_attempt(session=self.session, generation=generation)
        events = [self._event(1), self._event(2)]
        manifest = construct_managed_batch(
            generation=generation, attempt=attempt, events=events, batch_ordinal=0
        )
        batch = reserve_staged_batch(session=self.session, manifest=manifest)
        insert_managed_batch(self.ch, manifest)
        insert_managed_batch(self.ch, manifest)
        self.session.commit()
        with patch(
            "utils.manifest_protocol.exclusive_ingest_fence",
            side_effect=IngestFenceUnavailable("redis down"),
        ):
            with self.assertRaises(DurableRetryUniquenessError):
                commit_managed_batch_exactly_once(
                    session=self.session, clickhouse_client=self.ch, manifest=manifest
                )
        self.session.rollback()
        self.session.expire_all()
        batch = self.session.get(IngestBatch, batch.id)
        self.assertEqual(batch.state, IngestBatchState.STAGED)
        self.assertEqual(self._row_count(manifest.ingest_batch_id), 4)

    def test_d2_fence_unavailable_during_duplicate_identical_remains_staged(self):
        generation = self._generation()
        attempt = create_ingest_attempt(session=self.session, generation=generation)
        events = [self._event(1), self._event(2)]
        manifest = construct_managed_batch(
            generation=generation, attempt=attempt, events=events, batch_ordinal=0
        )
        batch = reserve_staged_batch(session=self.session, manifest=manifest)
        insert_managed_batch(self.ch, manifest)
        insert_managed_batch(self.ch, manifest)
        finish_ingest_attempt(self.session, attempt, status="FAILED", error="stale")
        self.session.commit()
        with patch(
            "utils.manifest_protocol.exclusive_ingest_fence",
            side_effect=IngestFenceUnavailable("redis down"),
        ):
            result = reconcile_staged_batch(
                session=self.session,
                clickhouse_client=self.ch,
                ingest_batch_id=manifest.ingest_batch_id,
            )
        self.assertEqual(result.action_taken, "fail_closed")
        self.assertEqual(result.classification, "duplicate_identical")
        self.session.expire_all()
        batch = self.session.get(IngestBatch, batch.id)
        self.assertEqual(batch.state, IngestBatchState.STAGED)
        self.assertEqual(self._row_count(manifest.ingest_batch_id), 4)

    def _conflict(self, mutate):
        generation = self._generation()
        attempt = create_ingest_attempt(session=self.session, generation=generation)
        events = [self._event(1), self._event(2)]
        manifest = construct_managed_batch(
            generation=generation, attempt=attempt, events=events, batch_ordinal=0
        )
        batch = reserve_staged_batch(session=self.session, manifest=manifest)
        self.session.commit()
        mutate(manifest, batch)
        with self.assertRaises((ManagedBatchVerificationError, DurableRetryUniquenessError)):
            commit_managed_batch_exactly_once(
                session=self.session, clickhouse_client=self.ch, manifest=manifest
            )
        self.session.rollback()
        self.session.expire_all()
        self.assertEqual(self.session.get(IngestBatch, batch.id).state, IngestBatchState.STAGED)
        return manifest

    def test_partial_fails_closed(self):
        def mutate(manifest, _batch):
            self.ch.insert("events", list(manifest.clickhouse_rows[:1]), column_names=list(PROTOCOL_CLICKHOUSE_COLUMNS))

        manifest = self._conflict(mutate)
        self.assertEqual(verify_ingest_batch(self.ch, manifest).outcome, "partial")

    def test_different_hash_conflict_fails_closed(self):
        def mutate(manifest, _batch):
            self.ch.insert("events", list(manifest.clickhouse_rows), column_names=list(PROTOCOL_CLICKHOUSE_COLUMNS))
            bad = list(manifest.clickhouse_rows[0])
            bad[PROTOCOL_CLICKHOUSE_COLUMNS.index("ingest_row_hash")] = "f" * 64
            self.ch.insert("events", [tuple(bad)], column_names=list(PROTOCOL_CLICKHOUSE_COLUMNS))

        manifest = self._conflict(mutate)
        self.assertEqual(verify_ingest_batch(self.ch, manifest).outcome, "duplicate_different")

    def test_hash_mismatch_fails_closed(self):
        def mutate(manifest, _batch):
            rows = [list(row) for row in manifest.clickhouse_rows]
            rows[0][PROTOCOL_CLICKHOUSE_COLUMNS.index("ingest_row_hash")] = "e" * 64
            self.ch.insert("events", [tuple(row) for row in rows], column_names=list(PROTOCOL_CLICKHOUSE_COLUMNS))

        manifest = self._conflict(mutate)
        self.assertEqual(verify_ingest_batch(self.ch, manifest).outcome, "hash_mismatch")

    def test_extra_ordinal_fails_closed(self):
        def mutate(manifest, _batch):
            self.ch.insert("events", list(manifest.clickhouse_rows), column_names=list(PROTOCOL_CLICKHOUSE_COLUMNS))
            extra = list(manifest.clickhouse_rows[0])
            extra[PROTOCOL_CLICKHOUSE_COLUMNS.index("ingest_row_ordinal")] = 99
            self.ch.insert("events", [tuple(extra)], column_names=list(PROTOCOL_CLICKHOUSE_COLUMNS))

        manifest = self._conflict(mutate)
        self.assertEqual(verify_ingest_batch(self.ch, manifest).outcome, "extra_ordinal")

    def test_aggregate_mismatch_fails_closed(self):
        from utils.ingest_identity import batch_content_hash

        generation = self._generation()
        attempt = create_ingest_attempt(session=self.session, generation=generation)
        events = [self._event(1), self._event(2)]
        manifest = construct_managed_batch(
            generation=generation, attempt=attempt, events=events, batch_ordinal=0
        )
        batch = reserve_staged_batch(session=self.session, manifest=manifest)
        self.ch.insert("events", list(manifest.clickhouse_rows), column_names=list(PROTOCOL_CLICKHOUSE_COLUMNS))
        wrong = batch_content_hash(["a" * 64, "b" * 64])
        batch.batch_content_hash = wrong
        self.session.commit()
        tampered = replace(manifest, batch_content_hash=wrong)
        with self.assertRaises(ManagedBatchVerificationError) as ctx:
            commit_managed_batch_exactly_once(
                session=self.session, clickhouse_client=self.ch, manifest=tampered
            )
        self.assertEqual(ctx.exception.verification.outcome, "aggregate_mismatch")
        self.session.rollback()
        self.session.expire_all()
        self.assertEqual(self.session.get(IngestBatch, batch.id).state, IngestBatchState.STAGED)

    def test_manifest_mismatch_fails_closed(self):
        generation = self._generation()
        attempt = create_ingest_attempt(session=self.session, generation=generation)
        events = [self._event(1), self._event(2)]
        manifest = construct_managed_batch(
            generation=generation, attempt=attempt, events=events, batch_ordinal=0
        )
        reserve_staged_batch(session=self.session, manifest=manifest)
        self.session.commit()
        changed = construct_managed_batch(
            generation=generation, attempt=attempt, events=[self._event(8), self._event(9)], batch_ordinal=0
        )
        with self.assertRaises(ManifestMismatchError):
            commit_managed_batch_exactly_once(
                session=self.session, clickhouse_client=self.ch, manifest=changed
            )
        self.assertEqual(self.session.query(IngestBatch).one().state, IngestBatchState.STAGED)


if __name__ == "__main__":
    unittest.main()
