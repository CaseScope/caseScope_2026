from __future__ import annotations

import os
import time
import unittest
from datetime import datetime
from datetime import timedelta

os.environ.setdefault("SECRET_KEY", "phase1b-ch-test-secret")

import clickhouse_connect
from flask import Flask
from sqlalchemy import text

from migrations.add_events_table import EVENTS_COLUMN_DEFINITIONS
from migrations.add_phase1b_tranche_b_manifest_protocol import clickhouse_control_table_ddl
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
    IngestBatchState,
)
from models.graph_saved_view import GraphSavedView  # noqa: F401
from models.investigation_thread import InvestigationThread  # noqa: F401
from parsers.base import ParsedEvent
from utils.ingest_fence import install_memory_backend, reset_fence_backend
from utils.manifest_protocol import (
    PROTOCOL_CLICKHOUSE_COLUMNS,
    ManifestParserContract,
    allocate_case_file_initial_generation,
    construct_managed_batches,
    create_ingest_attempt,
    handle_failed_verification,
    insert_managed_batch,
    mark_batch_durable,
    project_generation_control_state,
    reserve_staged_batch,
    update_generation_ingest_accounting,
    verify_ingest_batch,
)


PG_URL = os.environ.get("PHASE1B_PG_TEST_DATABASE_URL")
CH_DB = os.environ.get("PHASE1B_CH_TEST_DATABASE")


@unittest.skipUnless(PG_URL and CH_DB, "PHASE1B_PG_TEST_DATABASE_URL and PHASE1B_CH_TEST_DATABASE are required")
class Phase1BClickHouseIntegrationTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        install_memory_backend()
        cls.app = Flask(__name__)
        cls.app.config.update(
            SQLALCHEMY_DATABASE_URI=PG_URL,
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            SECRET_KEY="phase1b-ch-test",
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
            IngestAttempt.__table__,
            IngestBatch.__table__,
            CaseCapabilitySourceState.__table__,
        ):
            table.create(db.engine, checkfirst=True)
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

    @classmethod
    def tearDownClass(cls):
        cls.client.command("DROP TABLE IF EXISTS events")
        cls.client.command("DROP TABLE IF EXISTS visible_evidence_generations")
        cls.client.command("DROP TABLE IF EXISTS durable_ingest_batches")
        cls.client.close()
        db.session.remove()
        with db.engine.begin() as conn:
            conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            conn.execute(text("CREATE SCHEMA public"))
        cls.ctx.pop()
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
        self.pg_client = Client(name="CH Phase1B", code=f"CHP1B{int(time.time() * 1000) % 100000}", created_by="tester")
        self.case = Case(uuid=f"ch-case-{time.time_ns()}", name="CH Case", company="Example", client=self.pg_client, created_by="tester")
        self.case_file = CaseFile(
            case_uuid=self.case.uuid,
            filename="ch.log",
            original_filename="ch.log",
            file_path="/tmp/ch.log",
            file_size=1,
            sha256_hash="a" * 64,
            uploaded_by="tester",
        )
        self.other_case_file = CaseFile(
            case_uuid=self.case.uuid,
            filename="other.log",
            original_filename="other.log",
            file_path="/tmp/other.log",
            file_size=1,
            sha256_hash="b" * 64,
            uploaded_by="tester",
        )
        db.session.add_all([self.pg_client, self.case, self.case_file, self.other_case_file])
        db.session.commit()
        self.contract = ManifestParserContract(
            parser_version="ch-parser:v1",
            normalization_version="ch-normalization:v1",
            configured_batch_size=2,
            ordering_contract="test:fixture-order:v1",
            producer_version="ch-test",
            manifest_eligible=True,
        )

    def _event(self, case_file, record_id):
        return ParsedEvent(
            case_id=self.case.id,
            artifact_type="ch_fixture",
            timestamp=datetime(2026, 1, 1) + timedelta(seconds=record_id),
            timestamp_utc=datetime(2026, 1, 1) + timedelta(seconds=record_id),
            timestamp_source_tz="UTC",
            source_file=case_file.filename,
            source_path=f"/tmp/{case_file.filename}",
            source_host="CHHOST",
            case_file_id=case_file.id,
            event_id=str(record_id),
            record_id=record_id,
            command_line=f"record {record_id}",
            raw_json=f'{{"record_id":{record_id}}}',
            search_blob=f"record {record_id}",
            parser_version="ch-parser:v1",
            native_record_id_authoritative=True,
        )

    def _batch(self, events=None, case_file=None):
        generation = allocate_case_file_initial_generation(
            session=db.session,
            case_id=self.case.id,
            case_file_id=(case_file or self.case_file).id,
            contract=self.contract,
        )
        attempt = create_ingest_attempt(session=db.session, generation=generation)
        events = events or [self._event(case_file or self.case_file, 1), self._event(case_file or self.case_file, 2)]
        batches = construct_managed_batches(generation=generation, attempt=attempt, events=events)
        return generation, attempt, batches

    def test_real_managed_insert_verifier_matrix_and_durable_transition(self):
        generation, _attempt, batches = self._batch()
        batch = batches[0]
        absent = verify_ingest_batch(self.client, batch)
        self.assertEqual((absent.outcome, absent.success), ("absent", False))

        insert_managed_batch(self.client, batch)
        rows = self.client.query(
            """
            SELECT source_ref_type, source_ref_id, source_generation, ingest_batch_id,
                   ingest_row_ordinal, ingest_row_hash, toString(ingest_attempt_id)
            FROM events
            WHERE ingest_batch_id = {id:String}
            ORDER BY ingest_row_ordinal
            """,
            parameters={"id": batch.ingest_batch_id},
        ).result_rows
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0][0], "CASE_FILE")
        self.assertEqual(rows[0][1], str(self.case_file.id))
        self.assertEqual(rows[0][2], 1)
        self.assertEqual([row[4] for row in rows], [0, 1])
        self.assertEqual([row[5] for row in rows], list(batch.row_hashes))
        self.assertTrue(all(row[6] == batch.ingest_attempt_id for row in rows))
        exact = verify_ingest_batch(self.client, batch)
        self.assertEqual((exact.outcome, exact.success), ("exact", True))

        batch_row = reserve_staged_batch(session=db.session, manifest=batch)
        mark_batch_durable(session=db.session, batch=batch_row, verification=exact)
        update_generation_ingest_accounting(session=db.session, generation=generation, expected_rows=2)
        db.session.commit()
        self.assertEqual(batch_row.state, IngestBatchState.DURABLE)
        self.assertEqual(generation.visibility_state, EvidenceGenerationState.BUILDING_INITIAL)

    def test_real_verifier_failure_conditions_and_physical_duplicates(self):
        _generation, _attempt, batches = self._batch()
        batch = batches[0]

        self.client.insert("events", list(batch.clickhouse_rows[:1]), column_names=list(PROTOCOL_CLICKHOUSE_COLUMNS))
        self.assertEqual(verify_ingest_batch(self.client, batch).outcome, "partial")

        self.client.command("TRUNCATE TABLE events")
        insert_managed_batch(self.client, batch)
        extra = list(batch.clickhouse_rows[0])
        ordinal_idx = PROTOCOL_CLICKHOUSE_COLUMNS.index("ingest_row_ordinal")
        extra[ordinal_idx] = 99
        self.client.insert("events", [tuple(extra)], column_names=list(PROTOCOL_CLICKHOUSE_COLUMNS))
        self.assertEqual(verify_ingest_batch(self.client, batch).outcome, "extra_ordinal")

        self.client.command("TRUNCATE TABLE events")
        insert_managed_batch(self.client, batch)
        self.client.insert("events", [batch.clickhouse_rows[0]], column_names=list(PROTOCOL_CLICKHOUSE_COLUMNS))
        duplicate = verify_ingest_batch(self.client, batch)
        self.assertEqual((duplicate.outcome, duplicate.success), ("duplicate_identical", True))
        grouped = self.client.query(
            """
            SELECT ingest_row_ordinal, ingest_row_hash, count(), uniqExact(ingest_row_hash)
            FROM events
            WHERE ingest_batch_id = {id:String}
            GROUP BY ingest_row_ordinal, ingest_row_hash
            HAVING count() > 1
            """,
            parameters={"id": batch.ingest_batch_id},
        ).result_rows
        self.assertEqual(grouped[0][2], 2)
        self.assertEqual(grouped[0][3], 1)

        self.client.command("TRUNCATE TABLE events")
        insert_managed_batch(self.client, batch)
        conflict = list(batch.clickhouse_rows[0])
        hash_idx = PROTOCOL_CLICKHOUSE_COLUMNS.index("ingest_row_hash")
        conflict[hash_idx] = "f" * 64
        self.client.insert("events", [tuple(conflict)], column_names=list(PROTOCOL_CLICKHOUSE_COLUMNS))
        self.assertEqual(verify_ingest_batch(self.client, batch).outcome, "duplicate_different")

        self.client.command("TRUNCATE TABLE events")
        insert_managed_batch(self.client, batch)
        wrong = list(batch.clickhouse_rows[0])
        wrong[hash_idx] = "e" * 64
        self.client.command("TRUNCATE TABLE events")
        self.client.insert("events", [tuple(wrong), batch.clickhouse_rows[1]], column_names=list(PROTOCOL_CLICKHOUSE_COLUMNS))
        self.assertEqual(verify_ingest_batch(self.client, batch).outcome, "hash_mismatch")

        self.client.command("TRUNCATE TABLE events")
        insert_managed_batch(self.client, batch)
        aggregate_mismatch = batch.__class__(
            **{**batch.__dict__, "batch_content_hash": "d" * 64}
        )
        self.assertEqual(verify_ingest_batch(self.client, aggregate_mismatch).outcome, "aggregate_mismatch")

    def test_real_batch_purge_is_scoped_to_ingest_batch_id(self):
        _generation, _attempt, batches = self._batch(events=[
            self._event(self.case_file, 1),
            self._event(self.case_file, 2),
            self._event(self.case_file, 3),
            self._event(self.case_file, 4),
        ])
        other_generation, _other_attempt, other_batches = self._batch(
            events=[self._event(self.other_case_file, 5), self._event(self.other_case_file, 6)],
            case_file=self.other_case_file,
        )
        del other_generation
        insert_managed_batch(self.client, batches[0])
        insert_managed_batch(self.client, batches[1])
        insert_managed_batch(self.client, other_batches[0])
        before = self.client.query("SELECT ingest_batch_id, count() FROM events GROUP BY ingest_batch_id").result_rows
        self.assertEqual(dict(before)[batches[0].ingest_batch_id], 2)

        handle_failed_verification(
            clickhouse_client=self.client,
            verification=verify_ingest_batch(self.client, batches[0]).__class__("partial", False),
            manifest=batches[0],
        )
        after = dict(self.client.query("SELECT ingest_batch_id, count() FROM events GROUP BY ingest_batch_id").result_rows)
        self.assertNotIn(batches[0].ingest_batch_id, after)
        self.assertEqual(after[batches[1].ingest_batch_id], 2)
        self.assertEqual(after[other_batches[0].ingest_batch_id], 2)

    def test_real_shadow_projection_replay_and_idempotency(self):
        generation, _attempt, batches = self._batch(events=[
            self._event(self.case_file, 1),
            self._event(self.case_file, 2),
            self._event(self.case_file, 3),
            self._event(self.case_file, 4),
        ])
        durable = reserve_staged_batch(session=db.session, manifest=batches[0])
        staged = reserve_staged_batch(session=db.session, manifest=batches[1])
        durable.state = IngestBatchState.DURABLE
        durable.state_version = 2
        durable.durable_at = datetime.utcnow()
        db.session.commit()

        project_generation_control_state(self.client, db.session, generation)
        projected_batches = self.client.query("SELECT ingest_batch_id FROM durable_ingest_batches").result_rows
        self.assertEqual(projected_batches, [(batches[0].ingest_batch_id,)])

        staged.state = IngestBatchState.DURABLE
        staged.state_version = 2
        staged.durable_at = datetime.utcnow()
        db.session.commit()
        project_generation_control_state(self.client, db.session, generation)
        project_generation_control_state(self.client, db.session, generation)
        projected = self.client.query(
            "SELECT ingest_batch_id, max(state_version) FROM durable_ingest_batches GROUP BY ingest_batch_id"
        ).result_rows
        self.assertEqual({row[0] for row in projected}, {batches[0].ingest_batch_id, batches[1].ingest_batch_id})
        visible = self.client.query(
            "SELECT visibility_state, publishable FROM visible_evidence_generations FINAL"
        ).result_rows
        self.assertEqual(visible[-1], (EvidenceGenerationState.BUILDING_INITIAL, 1))

    def test_synthetic_managed_performance_sanity(self):
        generation, attempt, _ = self._batch(events=[])
        generation.configured_batch_size = 10000
        db.session.commit()
        events = [self._event(self.case_file, i + 1) for i in range(10000)]
        start = time.perf_counter()
        batches = construct_managed_batches(generation=generation, attempt=attempt, events=events)
        construct_seconds = time.perf_counter() - start
        self.assertEqual(len(batches), 1)
        insert_start = time.perf_counter()
        insert_managed_batch(self.client, batches[0])
        insert_seconds = time.perf_counter() - insert_start
        verify_start = time.perf_counter()
        verification = verify_ingest_batch(self.client, batches[0])
        verify_seconds = time.perf_counter() - verify_start
        self.assertTrue(verification.success)
        rows_per_second = 10000 / max(time.perf_counter() - start, 0.001)
        print(
            "PHASE1B_CH_PERF "
            f"rows=10000 batches=1 batch_size=10000 rows_per_second={rows_per_second:.2f} "
            f"hash_construct_seconds={construct_seconds:.3f} insert_seconds={insert_seconds:.3f} "
            f"verify_seconds={verify_seconds:.3f}"
        )


if __name__ == "__main__":
    unittest.main()
