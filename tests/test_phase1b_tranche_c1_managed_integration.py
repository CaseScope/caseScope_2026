from __future__ import annotations

import os
import time
import unittest
from unittest.mock import patch

os.environ.setdefault("SECRET_KEY", "phase1b-c1-managed-test-secret")

import clickhouse_connect
from flask import Flask
from sqlalchemy import text

from config import Config
from migrations.add_events_table import EVENTS_COLUMN_DEFINITIONS
from migrations.add_phase1b_tranche_b_manifest_protocol import clickhouse_control_table_ddl
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
    IngestBatchState,
)
from tests.test_phase1b_tranche_c1_determinism import (
    CERTIFIED_CANDIDATES,
    Phase1BTrancheC1DeterminismTestCase,
)
from tasks.celery_tasks import _process_managed_initial_case_file
from utils.ingest_fence import install_memory_backend, reset_fence_backend


PG_URL = os.environ.get("PHASE1B_PG_TEST_DATABASE_URL")
CH_DB = os.environ.get("PHASE1B_CH_TEST_DATABASE")


@unittest.skipUnless(PG_URL and CH_DB, "PHASE1B_PG_TEST_DATABASE_URL and PHASE1B_CH_TEST_DATABASE are required")
class Phase1BTrancheC1ManagedIntegrationTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        install_memory_backend()
        cls._old_flag = getattr(Config, "PHASE1B_MANIFEST_PROTOCOL_ENABLED", False)
        cls._old_batch_size = getattr(Config, "PHASE1B_MANIFEST_BATCH_SIZE", None)
        Config.PHASE1B_MANIFEST_PROTOCOL_ENABLED = True
        Config.PHASE1B_MANIFEST_BATCH_SIZE = 3
        cls.app = Flask(__name__)
        cls.app.config.update(
            SQLALCHEMY_DATABASE_URI=PG_URL,
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            SECRET_KEY="phase1b-c1-managed",
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
            CaseCapabilitySourceState.__table__,
        ):
            table.create(db.engine, checkfirst=True)
        with db.engine.begin() as conn:
            conn.execute(text("""
                ALTER TABLE case_files
                ADD COLUMN IF NOT EXISTS ingest_protocol_origin VARCHAR(32)
                NOT NULL DEFAULT 'not_started'
            """))
        cls.client = clickhouse_connect.get_client(
            host=os.environ.get("CLICKHOUSE_HOST", "localhost"),
            port=int(os.environ.get("CLICKHOUSE_PORT", 8123)),
            username=os.environ.get("CLICKHOUSE_USER", "default"),
            password=os.environ.get("CLICKHOUSE_PASSWORD", ""),
            database=CH_DB,
            autogenerate_session_id=False,
        )
        cls._create_events_table()
        for ddl in clickhouse_control_table_ddl():
            cls.client.command(ddl)
        cls._app_patch = patch("tasks.celery_tasks.get_flask_app", return_value=cls.app)
        cls._app_patch.start()
        cls.fixture_case = Phase1BTrancheC1DeterminismTestCase(methodName="run")
        cls.fixture_case.setUp()

    @classmethod
    def tearDownClass(cls):
        cls.fixture_case.tearDown()
        cls.client.command("DROP TABLE IF EXISTS events")
        cls.client.command("DROP TABLE IF EXISTS visible_evidence_generations")
        cls.client.command("DROP TABLE IF EXISTS durable_ingest_batches")
        cls.client.close()
        db.session.remove()
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
        cls._app_patch.stop()
        reset_fence_backend()

    @classmethod
    def _create_events_table(cls):
        columns = ",\n".join(
            f"    {name} {definition}"
            for name, definition in EVENTS_COLUMN_DEFINITIONS.items()
        )
        cls.client.command(f"""
        CREATE TABLE IF NOT EXISTS events (
        {columns}
        )
        ENGINE = MergeTree
        PARTITION BY case_id
        ORDER BY (case_id, timestamp_utc, artifact_type, source_host, source_file, event_id)
        SETTINGS index_granularity = 8192
        """)

    def setUp(self):
        self._reset_state()

    def _reset_state(self):
        self.client.command("TRUNCATE TABLE events")
        self.client.command("TRUNCATE TABLE visible_evidence_generations")
        self.client.command("TRUNCATE TABLE durable_ingest_batches")
        db.session.query(IngestBatch).delete()
        db.session.query(IngestAttempt).delete()
        db.session.query(EvidenceSourceGeneration).delete()
        db.session.query(CaseFile).delete()
        db.session.query(Case).delete()
        db.session.query(Client).delete()
        db.session.commit()
        self.pg_client = Client(name="C1 Managed", code=f"C1{time.time_ns() % 100000}", created_by="tester")
        self.case = Case(uuid=f"c1-case-{time.time_ns()}", name="C1 Case", company="Example", client=self.pg_client, created_by="tester")
        db.session.add_all([self.pg_client, self.case])
        db.session.commit()

    def _case_file_for(self, class_name, fixture_path):
        case_file = CaseFile(
            case_uuid=self.case.uuid,
            filename=fixture_path.name,
            original_filename=fixture_path.name,
            file_path=str(fixture_path),
            file_size=fixture_path.stat().st_size,
            sha256_hash=f"{abs(hash(class_name)):064x}"[-64:],
            uploaded_by="tester",
            ingest_protocol_origin=IngestProtocolOrigin.NOT_STARTED,
        )
        db.session.add(case_file)
        db.session.commit()
        return case_file

    def test_each_certified_parser_real_managed_ingest_and_retry(self):
        for class_name, fixture_path in self.fixture_case.fixtures.items():
            with self.subTest(parser=class_name):
                self._reset_state()
                candidate = CERTIFIED_CANDIDATES[class_name]
                case_file = self._case_file_for(class_name, fixture_path)
                parser = candidate["class"](
                    case_id=self.case.id,
                    source_host="C1HOST",
                    case_file_id=case_file.id,
                    case_tz="America/New_York",
                )
                first = _process_managed_initial_case_file(
                    parser=parser,
                    file_path=str(fixture_path),
                    case_id=self.case.id,
                    case_file_id=case_file.id,
                    clickhouse_client=self.client,
                    task_id=f"c1-first-{class_name}",
                )
                self.assertTrue(first.success)
                self.assertEqual(first.events_count, 11)
                generation = db.session.query(EvidenceSourceGeneration).one()
                self.assertEqual(generation.visibility_state, EvidenceGenerationState.ACTIVE)
                self.assertEqual(generation.ordering_contract, candidate["contract"])
                batches = db.session.query(IngestBatch).order_by(IngestBatch.batch_ordinal).all()
                self.assertEqual(len(batches), 4)
                self.assertTrue(all(batch.state == IngestBatchState.DURABLE for batch in batches))
                first_batch_ids = [batch.ingest_batch_id for batch in batches]

                retry_parser = candidate["class"](
                    case_id=self.case.id,
                    source_host="C1HOST",
                    case_file_id=case_file.id,
                    case_tz="America/New_York",
                )
                retry = _process_managed_initial_case_file(
                    parser=retry_parser,
                    file_path=str(fixture_path),
                    case_id=self.case.id,
                    case_file_id=case_file.id,
                    clickhouse_client=self.client,
                    task_id=f"c1-retry-{class_name}",
                )
                self.assertTrue(retry.success)
                attempts = [attempt.ingest_attempt_id for attempt in db.session.query(IngestAttempt).order_by(IngestAttempt.id).all()]
                self.assertEqual(len(attempts), 2)
                self.assertNotEqual(attempts[0], attempts[1])
                retry_batches = db.session.query(IngestBatch).order_by(IngestBatch.generation_id, IngestBatch.batch_ordinal).all()
                self.assertEqual(len(retry_batches), 8)
                second_batch_ids = [batch.ingest_batch_id for batch in retry_batches[4:]]
                self.assertNotEqual(second_batch_ids, first_batch_ids)
                db.session.expire_all()
                self.assertEqual(db.session.get(CaseFile, case_file.id).ingest_protocol_origin, IngestProtocolOrigin.MANIFEST_INITIAL)
                generations = db.session.query(EvidenceSourceGeneration).order_by(EvidenceSourceGeneration.source_generation).all()
                self.assertEqual([row.visibility_state for row in generations], [
                    EvidenceGenerationState.SUPERSEDED,
                    EvidenceGenerationState.ACTIVE,
                ])
                physical_rows = self.client.query("SELECT count() FROM events").result_rows[0][0]
                self.assertEqual(physical_rows, 22)
                projected = self.client.query("SELECT count() FROM durable_ingest_batches").result_rows[0][0]
                self.assertGreaterEqual(projected, 8)


if __name__ == "__main__":
    unittest.main()
