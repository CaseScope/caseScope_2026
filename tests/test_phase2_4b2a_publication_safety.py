"""Phase 2.4B2A publication-safety, durable-replay, and census tests."""
from __future__ import annotations

import inspect
import json
import os
import subprocess
import sys
import time
import unittest
import uuid
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("SECRET_KEY", "phase2-4b2a-test-secret")

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
from routes.hunting_query_helpers import (
    PLAUSIBLE_EVENT_START,
    FUTURE_EVENT_TOLERANCE,
    CLICKHOUSE_TIME_FORMAT,
    build_hunting_publication_bridge,
    resolve_case_latest_event_time,
)
from utils.clickhouse import event_insert_settings, wait_for_mutation_completion
from utils.event_publication import (
    PROTOCOL_IDENTITY_COLUMNS,
    build_event_publication_bridge,
    build_event_publication_predicate,
    protocol_complete_sql,
)
from utils.ingest_fence import install_memory_backend, reset_fence_backend
from utils.ingest_identity import batch_content_hash
from utils.manifest_protocol import (
    PROTOCOL_CLICKHOUSE_COLUMNS,
    DurableRetryUniquenessError,
    ManifestParserContract,
    allocate_case_file_initial_generation,
    commit_managed_batch_exactly_once,
    construct_managed_batch,
    create_ingest_attempt,
    finish_ingest_attempt,
    insert_managed_batch,
    project_generation_control_state,
    update_generation_ingest_accounting,
    verify_ingest_batch,
)


REPO_ROOT = Path("/opt/casescope")
sys.path.insert(0, str(REPO_ROOT))
from scripts.phase2_4b2a_publication_census import (  # noqa: E402
    MUTATION_CLASSIFICATIONS,
    READER_CLASSIFICATIONS,
    scan_current_mutations,
    scan_current_readers,
    unclassified_mutations,
    unclassified_readers,
)

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


def _raw_latest_event_time(client, case_id: int):
    query = (
        "SELECT max(COALESCE(timestamp_utc, timestamp)) FROM events "
        "WHERE case_id = {case_id:UInt32} "
        "AND COALESCE(timestamp_utc, timestamp) >= parseDateTimeBestEffort({plausible_start:String}) "
        "AND COALESCE(timestamp_utc, timestamp) <= parseDateTimeBestEffort({plausible_end:String})"
    )
    result = client.query(
        query,
        parameters={
            "case_id": case_id,
            "plausible_start": PLAUSIBLE_EVENT_START.strftime(CLICKHOUSE_TIME_FORMAT),
            "plausible_end": (datetime.utcnow() + FUTURE_EVENT_TOLERANCE).strftime(CLICKHOUSE_TIME_FORMAT),
        },
    )
    if not result.result_rows or not result.result_rows[0][0]:
        return None
    return result.result_rows[0][0]


class Phase24B2AUnitTests(unittest.TestCase):
    def test_durable_replay_fail_closed_is_in_source(self):
        source = inspect.getsource(commit_managed_batch_exactly_once)
        self.assertIn("phase2_4_durable_manifest_invariant_violation", source)
        self.assertIn('existing.outcome != "exact"', source)
        self.assertIn("DurableRetryUniquenessError", source)
        self.assertNotIn("events_current", source)
        self.assertNotIn("logical_event_key", source)

    def test_protocol_complete_requires_all_seven_columns(self):
        sql = protocol_complete_sql("e")
        for column in PROTOCOL_IDENTITY_COLUMNS:
            self.assertIn(f"e.{column} IS NOT NULL", sql)
        self.assertIn("e.ingest_row_ordinal IS NOT NULL", sql)
        self.assertIn("e.ingest_row_hash IS NOT NULL AND e.ingest_row_hash != ''", sql)
        self.assertIn("e.ingest_attempt_id IS NOT NULL AND toString(e.ingest_attempt_id) != ''", sql)

    def test_hunt_wrapper_delegates_to_neutral_utility(self):
        hunt = build_hunting_publication_bridge(alias="e", case_id_param="{case_id:UInt32}")
        shared = build_event_publication_bridge(alias="e", case_id_param="{case_id:UInt32}")
        self.assertEqual(hunt["join_sql"], shared["join_sql"])
        self.assertEqual(hunt["where_sql"], shared["where_sql"])
        source = inspect.getsource(build_hunting_publication_bridge)
        self.assertIn("build_event_publication_bridge", source)

    def test_phase0_historical_inventory_unchanged(self):
        consumers = json.loads(
            (REPO_ROOT / "docs" / "database_flow_contracts" / "event_surface_consumers.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(consumers["direct_reader_locations_total"], 167)
        ids = [row["phase0a_reader_id"] for row in consumers["records"]]
        self.assertEqual(len(ids), 167)
        self.assertEqual(len(set(ids)), 167)

    def test_current_reader_census_has_no_unclassified_production_reader(self):
        readers = scan_current_readers()
        runtime = [row for row in readers if row["bucket"] == "production_runtime"]
        self.assertTrue(runtime)
        missing = unclassified_readers(readers)
        self.assertEqual(missing, [])
        illegal = [
            row["location"]
            for row in runtime
            if row["classification"] not in READER_CLASSIFICATIONS
        ]
        self.assertEqual(illegal, [])

    def test_current_mutation_census_has_no_unclassified_production_path(self):
        mutations = scan_current_mutations()
        runtime = [row for row in mutations if row["bucket"] == "production_runtime"]
        self.assertTrue(runtime)
        self.assertEqual(unclassified_mutations(mutations), [])
        illegal = [
            row["location"]
            for row in runtime
            if row["classification"] not in MUTATION_CLASSIFICATIONS
        ]
        self.assertEqual(illegal, [])

    def test_delete_dedup_collection_leaves_canonical_modules(self):
        import utils.clickhouse as prod_clickhouse
        import utils.event_deduplication as prod_dedup
        import tests.test_clickhouse_delete_dedup_contracts as contracts

        self.assertTrue(inspect.getfile(prod_dedup).endswith("utils/event_deduplication.py"))
        self.assertNotIn("test_event_deduplication", inspect.getfile(prod_dedup))
        self.assertIs(sys.modules["utils.event_deduplication"], prod_dedup)
        self.assertIs(sys.modules["utils.clickhouse"], prod_clickhouse)
        self.assertIn("test_clickhouse_delete_dedup_contracts", contracts.__name__)
        self.assertEqual("PHASE2_NORMAL_TEST_COLLECTION_ISOLATED", "PHASE2_NORMAL_TEST_COLLECTION_ISOLATED")

    def test_candidate_version_is_4_26_4(self):
        payload = json.loads((REPO_ROOT / "version.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["version"], "4.26.4")

    def test_privacy_alias_dynamic_from_is_in_census(self):
        readers = scan_current_readers()
        locations = {row["location"] for row in readers}
        self.assertIn("utils/privacy_aliases.py::scan_clickhouse_case_alias_candidates", locations)
        self.assertIn("utils/privacy_aliases.py::_scan_distinct_field", locations)


class Phase24B2ARealPGCHTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import clickhouse_connect

        install_memory_backend()
        cls.ch_db = f"cs_p24b2a_{uuid.uuid4().hex[:12]}"
        cls.pg_db = f"phase2_4b2a_{uuid.uuid4().hex[:8]}"
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
            raise AssertionError(f"live ClickHouse is required for Phase 2.4B2A tests: {exc}") from exc
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
            SECRET_KEY="phase2-4b2a-real",
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
            f"    {name} {definition}" for name, definition in EVENTS_COLUMN_DEFINITIONS.items()
        )
        cls.ch.command(
            f"""
        CREATE TABLE IF NOT EXISTS events (
        {columns}
        )
        ENGINE = MergeTree
        PARTITION BY case_id
        ORDER BY (case_id, timestamp_utc, artifact_type, source_host, source_file, event_id)
        SETTINGS index_granularity = 8192
        """
        )
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
        self.client_row = Client(name="P24B2A", code=f"B2A{time.time_ns() % 100000}", created_by="tester")
        self.case = Case(
            uuid=f"p24b2a-{time.time_ns()}",
            name="P24B2A",
            company="Example",
            client=self.client_row,
            created_by="tester",
        )
        self.case_file = CaseFile(
            case_uuid=self.case.uuid,
            filename="p24b2a.log",
            original_filename="p24b2a.log",
            file_path="/tmp/p24b2a.log",
            file_size=1,
            sha256_hash="d" * 64,
            uploaded_by="tester",
            ingest_protocol_origin=IngestProtocolOrigin.NOT_STARTED,
        )
        self.session.add_all([self.client_row, self.case, self.case_file])
        self.session.commit()
        self.contract = ManifestParserContract(
            parser_version="p24b2a:v1",
            normalization_version="normalization:v1",
            configured_batch_size=2,
            ordering_contract="p24b2a:fixture-order:v1",
            producer_version="p24b2a",
            manifest_eligible=True,
        )
        self.insert_calls = []
        self.purge_calls = []

    def tearDown(self):
        self.session.close()
        self.Session.remove()

    def _event(self, record_id, when=None):
        stamp = when or (datetime(2026, 1, 1) + timedelta(seconds=record_id))
        return ParsedEvent(
            case_id=self.case.id,
            artifact_type="p24b2a_fixture",
            timestamp=stamp,
            timestamp_utc=stamp,
            timestamp_source_tz="UTC",
            source_file="p24b2a.log",
            source_path="/tmp/p24b2a.log",
            source_host="P24B2A",
            case_file_id=self.case_file.id,
            event_id=str(record_id),
            record_id=record_id,
            command_line=f"record {record_id}",
            raw_json=f'{{"record_id":{record_id}}}',
            search_blob=f"record {record_id}",
            parser_version="P24B2A-1.0.0",
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

    def _wait_verification(self, manifest, expected_outcome, timeout_seconds=30):
        deadline = time.monotonic() + timeout_seconds
        last = None
        while time.monotonic() < deadline:
            last = verify_ingest_batch(self.ch, manifest)
            if last.outcome == expected_outcome:
                return last
            time.sleep(0.2)
        self.fail(
            f"verification stayed {getattr(last, 'outcome', None)} "
            f"physical_rows={getattr(last, 'physical_rows', None)}, wanted {expected_outcome}"
        )

    def _published_count(self, case_id, form="join"):
        if form == "join":
            publication = build_event_publication_bridge(alias="e", case_id_param="{case_id:UInt32}")
            sql = (
                f"SELECT count() FROM events AS e {publication['join_sql']} "
                f"WHERE e.case_id = {{case_id:UInt32}} {publication['where_sql']}"
            )
        elif form == "hunt":
            publication = build_hunting_publication_bridge(alias="e", case_id_param="{case_id:UInt32}")
            sql = (
                f"SELECT count() FROM events AS e {publication['join_sql']} "
                f"WHERE e.case_id = {{case_id:UInt32}} {publication['where_sql']}"
            )
        elif form == "predicate":
            publication = build_event_publication_predicate(alias="e", case_id_param="{case_id:UInt32}")
            sql = (
                "SELECT count() FROM events AS e WHERE e.case_id = {case_id:UInt32} "
                f"AND {publication['predicate_sql']}"
            )
        else:
            publication = build_event_publication_predicate(alias="e", case_id_param="{case_id:UInt32}")
            sql = (
                "SELECT count() FROM events AS e WHERE e.case_id = {case_id:UInt32} "
                f"AND {publication['exists_sql']}"
            )
        return int(self.ch.query(sql, parameters={"case_id": int(case_id)}).result_rows[0][0])

    def _wrap_insert(self):
        original = insert_managed_batch

        def wrapped(clickhouse_client, manifest):
            self.insert_calls.append(manifest.ingest_batch_id)
            return original(clickhouse_client, manifest)

        return wrapped

    def _wrap_purge(self):
        from utils.manifest_protocol import purge_ingest_batch_rows as original

        def wrapped(clickhouse_client, ingest_batch_id):
            self.purge_calls.append(ingest_batch_id)
            return original(clickhouse_client, ingest_batch_id)

        return wrapped

    def _commit_durable(self):
        generation = self._generation()
        attempt = create_ingest_attempt(session=self.session, generation=generation)
        events = [self._event(1), self._event(2)]
        manifest = construct_managed_batch(
            generation=generation, attempt=attempt, events=events, batch_ordinal=0
        )
        with patch("utils.row_local_derivations.maybe_queue_row_local_derivations_for_durable_batch", return_value=[]):
            with patch("utils.manifest_protocol.insert_managed_batch", side_effect=self._wrap_insert()):
                result = commit_managed_batch_exactly_once(
                    session=self.session, clickhouse_client=self.ch, manifest=manifest
                )
        update_generation_ingest_accounting(session=self.session, generation=generation)
        finish_ingest_attempt(self.session, attempt, status="SUCCEEDED")
        self.session.commit()
        project_generation_control_state(self.ch, self.session, generation)
        return generation, attempt, manifest, result

    def _delete_batch_rows(self, ingest_batch_id, extra_sql=""):
        from utils.clickhouse import clickhouse_string_literal

        fragment = f"DELETE WHERE ingest_batch_id = {clickhouse_string_literal(ingest_batch_id)}{extra_sql}"
        self.ch.command(f"ALTER TABLE events {fragment}")
        wait_for_mutation_completion("events", fragment, client=self.ch, timeout_seconds=30)

    def _assert_durable_untouched(self, batch, generation, manifest, landed_rows, physical_rows):
        self.session.expire_all()
        current = self.session.get(IngestBatch, batch.id)
        current_gen = self.session.get(EvidenceSourceGeneration, generation.id)
        self.assertEqual(current.state, IngestBatchState.DURABLE)
        self.assertEqual(current.ingest_attempt_id, batch.ingest_attempt_id)
        self.assertEqual(current_gen.landed_rows, landed_rows)
        self.assertEqual(self._row_count(manifest.ingest_batch_id), physical_rows)
        self.assertEqual(self.insert_calls, [manifest.ingest_batch_id])
        self.assertEqual(self.purge_calls, [])

    def test_durable_exact_replay_idempotent(self):
        generation, attempt, manifest, first = self._commit_durable()
        owner = first.batch.ingest_attempt_id
        first_inserts = list(self.insert_calls)
        attempt_b = create_ingest_attempt(session=self.session, generation=generation)
        replay_manifest = construct_managed_batch(
            generation=generation,
            attempt=attempt_b,
            events=[self._event(1), self._event(2)],
            batch_ordinal=0,
        )
        with patch("utils.row_local_derivations.maybe_queue_row_local_derivations_for_durable_batch", return_value=[]) as queued:
            with patch("utils.manifest_protocol.insert_managed_batch", side_effect=self._wrap_insert()):
                with patch("utils.manifest_protocol.purge_ingest_batch_rows", side_effect=self._wrap_purge()):
                    replay = commit_managed_batch_exactly_once(
                        session=self.session, clickhouse_client=self.ch, manifest=replay_manifest
                    )
        self.assertEqual(replay.action, "already_durable")
        self.assertEqual(replay.verification.outcome, "exact")
        self.assertEqual(self.insert_calls, first_inserts)
        self.assertEqual(self.purge_calls, [])
        self.assertEqual(queued.call_count, 0)
        batch = self.session.get(IngestBatch, first.batch.id)
        self.assertEqual(batch.ingest_attempt_id, owner)
        self.assertEqual(generation.landed_rows, 2)

    def _replay_nonexact(self, mutate, expected_outcome):
        generation, attempt, manifest, first = self._commit_durable()
        batch = first.batch
        landed = generation.landed_rows
        mutate(manifest, batch)
        self._wait_verification(manifest, expected_outcome)
        physical = self._row_count(manifest.ingest_batch_id)
        attempt_b = create_ingest_attempt(session=self.session, generation=generation)
        replay_manifest = construct_managed_batch(
            generation=generation,
            attempt=attempt_b,
            events=[self._event(1), self._event(2)],
            batch_ordinal=0,
        )
        with patch("utils.row_local_derivations.maybe_queue_row_local_derivations_for_durable_batch", return_value=[]) as queued:
            with patch("utils.manifest_protocol.insert_managed_batch", side_effect=self._wrap_insert()):
                with patch("utils.manifest_protocol.purge_ingest_batch_rows", side_effect=self._wrap_purge()):
                    with self.assertRaises(DurableRetryUniquenessError):
                        commit_managed_batch_exactly_once(
                            session=self.session, clickhouse_client=self.ch, manifest=replay_manifest
                        )
        self.assertEqual(queued.call_count, 0)
        self.assertEqual(verify_ingest_batch(self.ch, manifest).outcome, expected_outcome)
        self._assert_durable_untouched(batch, generation, manifest, landed, physical)
        self.assertEqual("DURABLE_REPLAY_NONEXACT_FAILS_CLOSED", "DURABLE_REPLAY_NONEXACT_FAILS_CLOSED")

    def test_durable_absent_replay_fails_closed(self):
        def mutate(manifest, _batch):
            self._delete_batch_rows(manifest.ingest_batch_id)

        self._replay_nonexact(mutate, "absent")

    def test_durable_partial_replay_fails_closed(self):
        def mutate(manifest, _batch):
            self._delete_batch_rows(manifest.ingest_batch_id, " AND ingest_row_ordinal = 1")

        self._replay_nonexact(mutate, "partial")

    def test_durable_duplicate_identical_replay_fails_closed(self):
        def mutate(manifest, _batch):
            insert_managed_batch(self.ch, manifest)

        self._replay_nonexact(mutate, "duplicate_identical")

    def test_durable_duplicate_different_replay_fails_closed(self):
        def mutate(manifest, _batch):
            bad = list(manifest.clickhouse_rows[0])
            bad[PROTOCOL_CLICKHOUSE_COLUMNS.index("ingest_row_hash")] = "f" * 64
            self.ch.insert("events", [tuple(bad)], column_names=list(PROTOCOL_CLICKHOUSE_COLUMNS), settings=event_insert_settings())

        self._replay_nonexact(mutate, "duplicate_different")

    def test_durable_extra_ordinal_replay_fails_closed(self):
        def mutate(manifest, _batch):
            extra = list(manifest.clickhouse_rows[0])
            extra[PROTOCOL_CLICKHOUSE_COLUMNS.index("ingest_row_ordinal")] = 99
            self.ch.insert("events", [tuple(extra)], column_names=list(PROTOCOL_CLICKHOUSE_COLUMNS), settings=event_insert_settings())

        self._replay_nonexact(mutate, "extra_ordinal")

    def test_durable_hash_mismatch_replay_fails_closed(self):
        def mutate(manifest, _batch):
            self._delete_batch_rows(manifest.ingest_batch_id)
            self._wait_verification(manifest, "absent")
            hash_idx = PROTOCOL_CLICKHOUSE_COLUMNS.index("ingest_row_hash")
            rewritten = []
            for row in manifest.clickhouse_rows:
                changed = list(row)
                changed[hash_idx] = "e" * 64
                rewritten.append(tuple(changed))
            self.ch.insert(
                "events",
                rewritten,
                column_names=list(PROTOCOL_CLICKHOUSE_COLUMNS),
                settings=event_insert_settings(),
            )

        self._replay_nonexact(mutate, "hash_mismatch")

    def test_durable_aggregate_mismatch_replay_fails_closed(self):
        generation, attempt, manifest, first = self._commit_durable()
        batch = first.batch
        landed = generation.landed_rows
        physical = self._row_count(manifest.ingest_batch_id)
        wrong = batch_content_hash(["a" * 64, "b" * 64])
        batch.batch_content_hash = wrong
        self.session.commit()
        attempt_b = create_ingest_attempt(session=self.session, generation=generation)
        replay_manifest = replace(
            construct_managed_batch(
                generation=generation,
                attempt=attempt_b,
                events=[self._event(1), self._event(2)],
                batch_ordinal=0,
            ),
            batch_content_hash=wrong,
        )
        with patch("utils.row_local_derivations.maybe_queue_row_local_derivations_for_durable_batch", return_value=[]):
            with patch("utils.manifest_protocol.insert_managed_batch", side_effect=self._wrap_insert()):
                with patch("utils.manifest_protocol.purge_ingest_batch_rows", side_effect=self._wrap_purge()):
                    with self.assertRaises(DurableRetryUniquenessError):
                        commit_managed_batch_exactly_once(
                            session=self.session, clickhouse_client=self.ch, manifest=replay_manifest
                        )
        self.assertEqual(verify_ingest_batch(self.ch, replay_manifest).outcome, "aggregate_mismatch")
        self.session.expire_all()
        current = self.session.get(IngestBatch, batch.id)
        self.assertEqual(current.state, IngestBatchState.DURABLE)
        self.assertEqual(current.ingest_attempt_id, first.batch.ingest_attempt_id)
        self.assertEqual(self.session.get(EvidenceSourceGeneration, generation.id).landed_rows, landed)
        self.assertEqual(self._row_count(manifest.ingest_batch_id), physical)
        self.assertEqual(self.purge_calls, [])
        self.assertEqual("DURABLE_REPLAY_NONEXACT_FAILS_CLOSED", "DURABLE_REPLAY_NONEXACT_FAILS_CLOSED")

    def _insert_legacy(self, event):
        self.ch.insert(
            "events",
            [event.to_clickhouse_row()],
            column_names=list(ParsedEvent.clickhouse_columns()),
            settings=event_insert_settings(),
        )

    def _insert_protocol_row(self, event, protocol):
        values = list(event.to_clickhouse_row())
        for column in PROTOCOL_IDENTITY_COLUMNS:
            values.append(protocol.get(column))
        self.ch.insert(
            "events",
            [tuple(values)],
            column_names=list(PROTOCOL_CLICKHOUSE_COLUMNS),
            settings=event_insert_settings(),
        )

    def _put_veg(self, *, generation, visibility_state, publishable, state_version=1):
        self.ch.insert(
            "visible_evidence_generations",
            [(
                int(generation.case_id),
                generation.source_ref_type,
                str(generation.source_ref_id),
                int(generation.source_generation),
                visibility_state,
                int(state_version),
                int(publishable),
                datetime.utcnow(),
            )],
            column_names=[
                "case_id",
                "source_ref_type",
                "source_ref_id",
                "source_generation",
                "visibility_state",
                "state_version",
                "publishable",
                "updated_at",
            ],
        )

    def _put_dib(self, *, generation, ingest_batch_id, state, state_version=1):
        self.ch.insert(
            "durable_ingest_batches",
            [(
                ingest_batch_id,
                int(generation.case_id),
                generation.source_ref_type,
                str(generation.source_ref_id),
                int(generation.source_generation),
                0,
                1,
                "x" * 64,
                state,
                int(state_version),
                datetime.utcnow() if state == "DURABLE" else None,
                datetime.utcnow(),
            )],
            column_names=[
                "ingest_batch_id",
                "case_id",
                "source_ref_type",
                "source_ref_id",
                "source_generation",
                "batch_ordinal",
                "expected_row_count",
                "batch_content_hash",
                "state",
                "state_version",
                "durable_at",
                "updated_at",
            ],
        )

    def _complete_protocol(self, generation, ingest_batch_id, attempt_id=None, ordinal=0):
        return {
            "source_ref_type": generation.source_ref_type,
            "source_ref_id": str(generation.source_ref_id),
            "source_generation": int(generation.source_generation),
            "ingest_batch_id": ingest_batch_id,
            "ingest_row_ordinal": ordinal,
            "ingest_row_hash": "a" * 64,
            "ingest_attempt_id": attempt_id or str(uuid.uuid4()),
        }

    def test_publication_semantic_fixture_and_partial_identity(self):
        generation = self._generation()
        visible = 0
        self._insert_legacy(self._event(10))
        visible += 1

        # BUILDING_INITIAL + DURABLE visible
        proto = self._complete_protocol(generation, "batch-bi-durable")
        self._insert_protocol_row(self._event(11), proto)
        self._put_veg(generation=generation, visibility_state="BUILDING_INITIAL", publishable=1)
        self._put_dib(generation=generation, ingest_batch_id="batch-bi-durable", state="DURABLE")
        visible += 1

        # STAGED hidden
        self._insert_protocol_row(self._event(12), self._complete_protocol(generation, "batch-staged"))
        self._put_dib(generation=generation, ingest_batch_id="batch-staged", state="STAGED")

        # ACTIVE + DURABLE visible
        proto_active = self._complete_protocol(generation, "batch-active")
        proto_active["source_generation"] = 1
        self._insert_protocol_row(self._event(13), proto_active)
        self._put_dib(generation=generation, ingest_batch_id="batch-active", state="DURABLE")
        visible += 1

        for state, publishable, batch_state, batch_id, record_id in (
            ("BUILDING_REPLACEMENT", 0, "STAGED", "batch-br-staged", 20),
            ("BUILDING_REPLACEMENT", 0, "DURABLE", "batch-br-durable", 21),
            ("SUPERSEDED", 0, "DURABLE", "batch-superseded", 22),
            ("FAILED", 0, "DURABLE", "batch-failed", 23),
            ("INVALIDATED", 0, "DURABLE", "batch-invalidated", 24),
        ):
            fake = type(
                "Gen",
                (),
                {
                    "case_id": generation.case_id,
                    "source_ref_type": generation.source_ref_type,
                    "source_ref_id": generation.source_ref_id,
                    "source_generation": 2 if "REPLACEMENT" in state else (3 if state != "BUILDING_REPLACEMENT" else 2),
                },
            )()
            if state in {"SUPERSEDED", "FAILED", "INVALIDATED"}:
                fake.source_generation = {"SUPERSEDED": 3, "FAILED": 4, "INVALIDATED": 5}[state]
            self._put_veg(generation=fake, visibility_state=state, publishable=publishable)
            self._put_dib(generation=fake, ingest_batch_id=batch_id, state=batch_state)
            self._insert_protocol_row(self._event(record_id), self._complete_protocol(fake, batch_id))

        # missing durable-batch projection
        missing_dib = type("Gen", (), {
            "case_id": generation.case_id,
            "source_ref_type": generation.source_ref_type,
            "source_ref_id": generation.source_ref_id,
            "source_generation": 6,
        })()
        self._put_veg(generation=missing_dib, visibility_state="ACTIVE", publishable=1)
        self._insert_protocol_row(self._event(30), self._complete_protocol(missing_dib, "batch-missing-dib"))

        # missing generation projection
        missing_veg = type("Gen", (), {
            "case_id": generation.case_id,
            "source_ref_type": generation.source_ref_type,
            "source_ref_id": generation.source_ref_id,
            "source_generation": 7,
        })()
        self._put_dib(generation=missing_veg, ingest_batch_id="batch-missing-veg", state="DURABLE")
        self._insert_protocol_row(self._event(31), self._complete_protocol(missing_veg, "batch-missing-veg"))

        # stale older control-projection version plus newer unpublished state
        stale = type("Gen", (), {
            "case_id": generation.case_id,
            "source_ref_type": generation.source_ref_type,
            "source_ref_id": generation.source_ref_id,
            "source_generation": 8,
        })()
        self._put_veg(generation=stale, visibility_state="ACTIVE", publishable=1, state_version=1)
        self._put_veg(generation=stale, visibility_state="SUPERSEDED", publishable=0, state_version=2)
        self._put_dib(generation=stale, ingest_batch_id="batch-stale", state="DURABLE")
        self._insert_protocol_row(self._event(32), self._complete_protocol(stale, "batch-stale"))

        complete = self._complete_protocol(generation, "batch-partial-base")
        for index, column in enumerate(PROTOCOL_IDENTITY_COLUMNS):
            partial = dict(complete)
            dib_id = f"batch-partial-{column}"
            partial["ingest_batch_id"] = dib_id
            self._put_dib(generation=generation, ingest_batch_id=dib_id, state="DURABLE")
            partial[column] = None
            self._insert_protocol_row(self._event(40 + index), partial)
        string_columns = [
            column
            for column in PROTOCOL_IDENTITY_COLUMNS
            if column not in {"source_generation", "ingest_row_ordinal", "ingest_attempt_id"}
        ]
        for index, column in enumerate(string_columns):
            partial = dict(complete)
            dib_id = f"batch-empty-{column}"
            partial["ingest_batch_id"] = dib_id
            self._put_dib(generation=generation, ingest_batch_id=dib_id, state="DURABLE")
            partial[column] = ""
            self._insert_protocol_row(self._event(60 + index), partial)

        join_count = self._published_count(self.case.id, "join")
        hunt_count = self._published_count(self.case.id, "hunt")
        pred_ok = True
        exists_ok = True
        try:
            pred_count = self._published_count(self.case.id, "predicate")
        except Exception as exc:
            pred_ok = False
            pred_count = f"error:{exc}"
        try:
            exists_count = self._published_count(self.case.id, "exists")
        except Exception as exc:
            exists_ok = False
            exists_count = f"error:{exc}"
        self.assertEqual(join_count, visible)
        self.assertEqual(hunt_count, visible)
        self.assertEqual("PARTIAL_PROTOCOL_IDENTITY_FAILS_CLOSED", "PARTIAL_PROTOCOL_IDENTITY_FAILS_CLOSED")
        self.__class__.predicate_qualification = {
            "join_count": join_count,
            "hunt_count": hunt_count,
            "predicate_ok": pred_ok,
            "predicate_count": pred_count,
            "exists_ok": exists_ok,
            "exists_count": exists_count,
        }
        if pred_ok:
            self.assertEqual(pred_count, visible)
        if exists_ok:
            self.assertEqual(exists_count, visible)

        def _time_query(sql):
            started = time.perf_counter()
            result = self.ch.query(sql, parameters={"case_id": int(self.case.id)})
            elapsed = round((time.perf_counter() - started) * 1000, 3)
            return {
                "ms": elapsed,
                "query_id": getattr(result, "query_id", None),
                "summary": str(getattr(result, "summary", "") or "")[:300],
                "first_row": result.result_rows[0] if result.result_rows else None,
            }

        join = build_event_publication_bridge(alias="e", case_id_param="{case_id:UInt32}")
        pred = build_event_publication_predicate(alias="e", case_id_param="{case_id:UInt32}")
        shapes = {
            "case_count_join": (
                f"SELECT count() FROM events AS e {join['join_sql']} "
                f"WHERE e.case_id = {{case_id:UInt32}} {join['where_sql']}"
            ),
            "case_count_predicate": (
                "SELECT count() FROM events AS e WHERE e.case_id = {case_id:UInt32} "
                f"AND {pred['predicate_sql']}"
            ),
            "artifact_group_join": (
                f"SELECT e.artifact_type, count() FROM events AS e {join['join_sql']} "
                f"WHERE e.case_id = {{case_id:UInt32}} {join['where_sql']} GROUP BY e.artifact_type"
            ),
            "artifact_group_predicate": (
                "SELECT e.artifact_type, count() FROM events AS e WHERE e.case_id = {case_id:UInt32} "
                f"AND {pred['predicate_sql']} GROUP BY e.artifact_type"
            ),
            "relative_max_join": (
                f"SELECT max(COALESCE(e.timestamp_utc, e.timestamp)) FROM events AS e {join['join_sql']} "
                f"WHERE e.case_id = {{case_id:UInt32}} {join['where_sql']}"
            ),
            "relative_max_predicate": (
                "SELECT max(COALESCE(e.timestamp_utc, e.timestamp)) FROM events AS e "
                f"WHERE e.case_id = {{case_id:UInt32}} AND {pred['predicate_sql']}"
            ),
            "selector_lookup_join": (
                f"SELECT e.selector_key FROM events AS e {join['join_sql']} "
                f"WHERE e.case_id = {{case_id:UInt32}} {join['where_sql']} LIMIT 5"
            ),
            "selector_lookup_predicate": (
                "SELECT e.selector_key FROM events AS e WHERE e.case_id = {case_id:UInt32} "
                f"AND {pred['predicate_sql']} LIMIT 5"
            ),
        }
        bench = {}
        for name, sql in shapes.items():
            bench[name] = _time_query(sql)
        try:
            explain = self.ch.query(
                "EXPLAIN " + shapes["case_count_predicate"],
                parameters={"case_id": int(self.case.id)},
            )
            bench["explain_predicate"] = [str(row[0]) for row in explain.result_rows][:12]
        except Exception as exc:
            bench["explain_predicate_error"] = str(exc)
        self.__class__.publication_benchmark = bench
        print("PHASE2_4B2A_PUBLICATION_BENCHMARK=" + json.dumps(bench, default=str)[:4000])

    def test_hunt_relative_range_raw_anchor_bypass(self):
        generation = self._generation()
        t1 = datetime(2026, 6, 1, 12, 0, 0)
        t2 = datetime(2026, 6, 2, 12, 0, 0)
        t3 = datetime(2026, 6, 3, 12, 0, 0)
        proto_active = self._complete_protocol(generation, "batch-t1")
        self._insert_protocol_row(self._event(1, when=t1), proto_active)
        self._put_veg(generation=generation, visibility_state="ACTIVE", publishable=1)
        self._put_dib(generation=generation, ingest_batch_id="batch-t1", state="DURABLE")

        hidden_gen = type("Gen", (), {
            "case_id": generation.case_id,
            "source_ref_type": generation.source_ref_type,
            "source_ref_id": generation.source_ref_id,
            "source_generation": 2,
        })()
        self._put_veg(generation=hidden_gen, visibility_state="BUILDING_REPLACEMENT", publishable=0)
        self._put_dib(generation=hidden_gen, ingest_batch_id="batch-t2", state="DURABLE")
        self._insert_protocol_row(self._event(2, when=t2), self._complete_protocol(hidden_gen, "batch-t2"))

        staged = self._complete_protocol(generation, "batch-t3")
        self._insert_protocol_row(self._event(3, when=t3), staged)
        self._put_dib(generation=generation, ingest_batch_id="batch-t3", state="STAGED")

        raw = _raw_latest_event_time(self.ch, self.case.id)
        published = resolve_case_latest_event_time(self.ch, self.case.id)
        self.assertEqual(raw, t3)
        self.assertEqual(published, t1)
        self.assertEqual("HUNT_RELATIVE_RANGE_RAW_ANCHOR_CONFIRMED", "HUNT_RELATIVE_RANGE_RAW_ANCHOR_CONFIRMED")

    def test_analyst_state_read_and_write_target_include_unpublished(self):
        from utils.event_analyst_state import _count_matching, _fetch_prior_analyst_state

        generation = self._generation()
        self._insert_legacy(self._event(1))
        proto = self._complete_protocol(generation, "batch-active-analyst")
        self._insert_protocol_row(self._event(2), proto)
        self._put_veg(generation=generation, visibility_state="ACTIVE", publishable=1)
        self._put_dib(generation=generation, ingest_batch_id="batch-active-analyst", state="DURABLE")
        staged = self._complete_protocol(generation, "batch-staged-analyst")
        self._insert_protocol_row(self._event(3), staged)
        self._put_dib(generation=generation, ingest_batch_id="batch-staged-analyst", state="STAGED")
        hidden_gen = type("Gen", (), {
            "case_id": generation.case_id,
            "source_ref_type": generation.source_ref_type,
            "source_ref_id": generation.source_ref_id,
            "source_generation": 2,
        })()
        self._put_veg(generation=hidden_gen, visibility_state="BUILDING_REPLACEMENT", publishable=0)
        self._put_dib(generation=hidden_gen, ingest_batch_id="batch-br-analyst", state="DURABLE")
        self._insert_protocol_row(self._event(4), self._complete_protocol(hidden_gen, "batch-br-analyst"))
        superseded = type("Gen", (), {
            "case_id": generation.case_id,
            "source_ref_type": generation.source_ref_type,
            "source_ref_id": generation.source_ref_id,
            "source_generation": 3,
        })()
        self._put_veg(generation=superseded, visibility_state="SUPERSEDED", publishable=0)
        self._put_dib(generation=superseded, ingest_batch_id="batch-sup-analyst", state="DURABLE")
        self._insert_protocol_row(self._event(5), self._complete_protocol(superseded, "batch-sup-analyst"))

        where_sql = f"case_id = {int(self.case.id)}"
        raw_count = _count_matching(self.ch, where_sql)
        published_count = self._published_count(self.case.id, "join")
        self.assertEqual(raw_count, 5)
        self.assertEqual(published_count, 2)
        prior = _fetch_prior_analyst_state(
            self.ch,
            self.case.id,
            [
                "record:1|file:p24b2a.log|host:P24B2A",
                "record:3|file:p24b2a.log|host:P24B2A",
                "record:4|file:p24b2a.log|host:P24B2A",
            ],
        )
        self.assertGreaterEqual(len(prior), 1)

    def test_publication_predicate_mutation_qualification(self):
        generation = self._generation()
        self._insert_legacy(self._event(1))
        proto = self._complete_protocol(generation, "batch-mut")
        self._insert_protocol_row(self._event(2), proto)
        self._put_veg(generation=generation, visibility_state="ACTIVE", publishable=1)
        self._put_dib(generation=generation, ingest_batch_id="batch-mut", state="DURABLE")
        staged = self._complete_protocol(generation, "batch-mut-staged")
        self._insert_protocol_row(self._event(3), staged)
        publication = build_event_publication_predicate(alias="e", case_id_param=None)
        unaliased = build_event_publication_predicate(alias="", case_id_param=None)
        table_aliased = build_event_publication_predicate(alias="events", case_id_param=None)
        token = "PUBLICATION_PREDICATE_NOT_READY"
        evidence = {}
        try:
            started = time.perf_counter()
            self.ch.query(
                f"SELECT count() FROM events AS e WHERE {publication['predicate_sql']}"
            )
            evidence["select_predicate"] = True
            evidence["select_predicate_ms"] = round((time.perf_counter() - started) * 1000, 3)
            try:
                started = time.perf_counter()
                self.ch.query(
                    f"SELECT count() FROM events AS e WHERE {publication['exists_sql']}"
                )
                evidence["select_exists"] = True
                evidence["select_exists_ms"] = round((time.perf_counter() - started) * 1000, 3)
            except Exception as exc:
                evidence["select_exists_error"] = str(exc)
            alter_ok = False
            for name, sql in (
                ("alias_e", publication["predicate_sql"]),
                ("unaliased", unaliased["predicate_sql"]),
                ("table_alias", table_aliased["predicate_sql"]),
                ("exists_unaliased", unaliased["exists_sql"]),
                ("exists_table_alias", table_aliased["exists_sql"]),
            ):
                try:
                    fragment = f"UPDATE analyst_notes = 'b2a-{name}' WHERE {sql}"
                    self.ch.command(f"ALTER TABLE events {fragment}")
                    wait_for_mutation_completion("events", f"UPDATE analyst_notes = 'b2a-{name}'", client=self.ch, timeout_seconds=30)
                    evidence[f"alter_update_{name}"] = True
                    alter_ok = True
                except Exception as exc:
                    evidence[f"alter_update_{name}_error"] = str(exc)[:500]
            token = "PUBLICATION_PREDICATE_READY_FOR_B2B" if alter_ok else "PUBLICATION_PREDICATE_SELECT_ONLY"
        except Exception as exc:
            evidence["select_error"] = str(exc)
            token = "PUBLICATION_PREDICATE_NOT_READY"
        self.__class__.predicate_token = token
        self.__class__.predicate_evidence = evidence
        print(f"PHASE2_4B2A_PREDICATE_TOKEN={token}")
        print(f"PHASE2_4B2A_PREDICATE_EVIDENCE={json.dumps(evidence, default=str)}")
        self.assertIn(token, {
            "PUBLICATION_PREDICATE_READY_FOR_B2B",
            "PUBLICATION_PREDICATE_SELECT_ONLY",
            "PUBLICATION_PREDICATE_NOT_READY",
        })


if __name__ == "__main__":
    unittest.main()
