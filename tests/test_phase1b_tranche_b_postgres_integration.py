from __future__ import annotations

import os
import threading
import unittest

os.environ.setdefault("SECRET_KEY", "phase1b-pg-test-secret")

from flask import Flask
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import scoped_session, sessionmaker

from migrations.add_phase1b_tranche_b_manifest_protocol import POSTGRES_INDEX_DDL
from models.case import Case
from models.case_file import CaseFile
from models.client import Client
from models.database import db
from models.database_flow import (
    CaseCapabilitySourceState,
    EvidenceGenerationState,
    EvidenceSourceGeneration,
    IngestAttempt,
    IngestBatch,
    SourceRefType,
)
from utils.manifest_protocol import (
    ManifestMismatchError,
    ManifestParserContract,
    allocate_case_file_initial_generation,
    construct_managed_batches,
    create_ingest_attempt,
    reserve_staged_batch,
)
from parsers.base import ParsedEvent


TEST_DATABASE_URL = os.environ.get("PHASE1B_PG_TEST_DATABASE_URL")


@unittest.skipUnless(TEST_DATABASE_URL, "PHASE1B_PG_TEST_DATABASE_URL is not set")
class Phase1BPostgresIntegrationTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = Flask(__name__)
        cls.app.config.update(
            SQLALCHEMY_DATABASE_URI=TEST_DATABASE_URL,
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            SECRET_KEY="phase1b-pg-test",
        )
        db.init_app(cls.app)
        cls.ctx = cls.app.app_context()
        cls.ctx.push()
        cls.engine = create_engine(TEST_DATABASE_URL)
        cls.Session = scoped_session(sessionmaker(bind=cls.engine))
        with cls.engine.begin() as conn:
            conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            conn.execute(text("CREATE SCHEMA public"))
        for table in (
            Client.__table__,
            Case.__table__,
            CaseFile.__table__,
            EvidenceSourceGeneration.__table__,
            IngestAttempt.__table__,
            IngestBatch.__table__,
            CaseCapabilitySourceState.__table__,
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

    def setUp(self):
        self.session = self.Session()
        self.session.query(IngestBatch).delete()
        self.session.query(IngestAttempt).delete()
        self.session.query(EvidenceSourceGeneration).delete()
        self.session.query(CaseFile).delete()
        self.session.query(Case).delete()
        self.session.query(Client).delete()
        self.session.commit()
        self.client = Client(name="Phase1B", code="P1B", created_by="tester")
        self.case = Case(uuid="pg-case", name="PG Case", company="Example", client=self.client, created_by="tester")
        self.case_file = CaseFile(
            case_uuid=self.case.uuid,
            filename="pg.log",
            original_filename="pg.log",
            file_path="/tmp/pg.log",
            file_size=1,
            sha256_hash="d" * 64,
            uploaded_by="tester",
        )
        self.session.add_all([self.client, self.case, self.case_file])
        self.session.commit()
        self.contract = ManifestParserContract(
            parser_version="pg-parser:v1",
            normalization_version="pg-normalization:v1",
            configured_batch_size=2,
            ordering_contract="test:fixture-order:v1",
            producer_version="pg-test",
            manifest_eligible=True,
        )

    def tearDown(self):
        self.session.close()
        self.Session.remove()

    def _event(self, record_id):
        return ParsedEvent(
            case_id=self.case.id,
            artifact_type="pg_fixture",
            timestamp=None,
            timestamp_utc=None,
            timestamp_source_tz="UTC",
            source_file="pg.log",
            source_path="/tmp/pg.log",
            source_host="PGHOST",
            case_file_id=self.case_file.id,
            event_id=str(record_id),
            record_id=record_id,
            command_line=f"record {record_id}",
            raw_json=f'{{"record_id":{record_id}}}',
            search_blob=f"record {record_id}",
            parser_version="pg-parser:v1",
            native_record_id_authoritative=True,
        )

    def test_catalog_partial_index_predicates(self):
        rows = self.session.execute(text("""
            SELECT indexname, pg_get_expr(indexprs, indrelid), pg_get_expr(indpred, indrelid)
            FROM pg_indexes
            JOIN pg_class ON pg_class.relname = pg_indexes.tablename
            JOIN pg_index ON pg_index.indexrelid = (pg_indexes.indexname)::regclass
            WHERE tablename = 'evidence_source_generations'
              AND indexname IN (
                'uq_evidence_source_generation_open_building',
                'uq_evidence_source_generation_active'
              )
            ORDER BY indexname
        """)).all()
        predicates = {row[0]: row[2] for row in rows}
        self.assertIn("visibility_state", predicates["uq_evidence_source_generation_open_building"])
        self.assertIn("BUILDING_INITIAL", predicates["uq_evidence_source_generation_open_building"])
        self.assertIn("BUILDING_REPLACEMENT", predicates["uq_evidence_source_generation_open_building"])
        self.assertIn("ACTIVE", predicates["uq_evidence_source_generation_active"])

    def test_concurrent_allocation_with_independent_sessions_reuses_one_generation(self):
        barrier = threading.Barrier(2)
        results = []
        errors = []

        def worker():
            session = self.Session()
            try:
                barrier.wait(timeout=10)
                generation = allocate_case_file_initial_generation(
                    session=session,
                    case_id=self.case.id,
                    case_file_id=self.case_file.id,
                    contract=self.contract,
                )
                session.commit()
                results.append((generation.id, generation.source_generation, generation.visibility_state))
            except Exception as exc:  # pragma: no cover - surfaced by assertion
                session.rollback()
                errors.append(exc)
            finally:
                session.close()

        threads = [threading.Thread(target=worker), threading.Thread(target=worker)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=20)
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 2)
        rows = self.session.query(EvidenceSourceGeneration).all()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].source_generation, 1)
        self.assertEqual(rows[0].visibility_state, EvidenceGenerationState.BUILDING_INITIAL)
        self.assertEqual({result[0] for result in results}, {rows[0].id})

    def test_state_constraints_active_replacement_allowed_duplicate_active_building_rejected(self):
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
        self.session.add_all([active, replacement])
        self.session.commit()

        duplicate_active = EvidenceSourceGeneration(
            case_id=self.case.id,
            source_ref_type=SourceRefType.CASE_FILE,
            source_ref_id=str(self.case_file.id),
            source_generation=3,
            visibility_state=EvidenceGenerationState.ACTIVE,
            parser_version="p",
            normalization_version="n",
            batching_contract_version="ingest-batch:v1",
            configured_batch_size=2,
            ordering_contract="test:fixture-order:v1",
        )
        self.session.add(duplicate_active)
        with self.assertRaises(IntegrityError):
            self.session.commit()
        self.session.rollback()

        duplicate_building = EvidenceSourceGeneration(
            case_id=self.case.id,
            source_ref_type=SourceRefType.CASE_FILE,
            source_ref_id=str(self.case_file.id),
            source_generation=4,
            visibility_state=EvidenceGenerationState.BUILDING_INITIAL,
            parser_version="p",
            normalization_version="n",
            batching_contract_version="ingest-batch:v1",
            configured_batch_size=2,
            ordering_contract="test:fixture-order:v1",
        )
        self.session.add(duplicate_building)
        with self.assertRaises(IntegrityError):
            self.session.commit()
        self.session.rollback()

    def test_staged_manifest_idempotency_and_conflict(self):
        generation = allocate_case_file_initial_generation(
            session=self.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        attempt = create_ingest_attempt(session=self.session, generation=generation)
        batches = construct_managed_batches(
            generation=generation,
            attempt=attempt,
            events=[self._event(1), self._event(2)],
        )
        first = reserve_staged_batch(session=self.session, manifest=batches[0])
        self.session.commit()
        second = reserve_staged_batch(session=self.session, manifest=batches[0])
        self.session.commit()
        self.assertEqual(first.id, second.id)
        self.assertEqual(self.session.query(IngestBatch).count(), 1)

        changed = batches[0].__class__(
            **{
                **batches[0].__dict__,
                "row_hashes": ("e" * 64,) + batches[0].row_hashes[1:],
                "batch_content_hash": "f" * 64,
            }
        )
        with self.assertRaises(ManifestMismatchError):
            reserve_staged_batch(session=self.session, manifest=changed)


if __name__ == "__main__":
    unittest.main()
