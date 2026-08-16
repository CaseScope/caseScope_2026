from __future__ import annotations

import os
import shutil
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault("SECRET_KEY", "phase1b-d1-test-secret")

import clickhouse_connect
from flask import Flask
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import scoped_session, sessionmaker

from config import Config
from migrations.add_events_table import EVENTS_COLUMN_DEFINITIONS
from migrations.add_phase1b_tranche_b_manifest_protocol import clickhouse_control_table_ddl
from migrations.add_phase1b_tranche_b_manifest_protocol import POSTGRES_INDEX_DDL
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
    SourceRefType,
)
from parsers.base import BaseParser, ParsedEvent
from tests.test_phase1b_tranche_c1_determinism import Phase1BTrancheC1DeterminismTestCase
from tasks.celery_tasks import _process_managed_initial_case_file
from utils.ingest_fence import install_memory_backend, reset_fence_backend
from utils.manifest_protocol import (
    INGEST_MODE_LEGACY,
    INGEST_MODE_MANAGED_INITIAL,
    INGEST_MODE_MANAGED_REPLACEMENT,
    ActivationCompletenessError,
    ManifestRoutingError,
    ManifestParserContract,
    ReplacementInProgressError,
    activate_initial_generation,
    activate_replacement_generation,
    allocate_case_file_initial_generation,
    allocate_case_file_replacement_generation,
    check_generation_activation_completeness,
    construct_managed_batches,
    create_ingest_attempt,
    declare_generation_ingest_complete,
    fail_generation_terminal,
    insert_managed_batch,
    mark_batch_durable,
    project_generation_authority_swap,
    project_generation_control_state,
    reserve_staged_batch,
    resolve_projected_visible_generation,
    select_case_file_ingest_mode,
    update_generation_ingest_accounting,
    verify_ingest_batch,
)


PG_URL = os.environ.get("PHASE1B_PG_TEST_DATABASE_URL")
CH_DB = os.environ.get("PHASE1B_CH_TEST_DATABASE")


class _D1Parser(BaseParser):
    supports_manifest_protocol = True
    manifest_ordering_contract = "d1:fixture-order:v1"
    VERSION = "1.0.0"

    def __init__(self, *args, events=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._events = list(events or [])

    @property
    def artifact_type(self):
        return "d1_fixture"

    def can_parse(self, _file_path):
        return True

    def parse(self, _file_path):
        return iter(self._events)

    def manifest_producer_version(self):
        return "d1-parser:v1"


class _DeferredParser(BaseParser):
    @property
    def artifact_type(self):
        return "d1_deferred"

    def can_parse(self, _file_path):
        return True

    def parse(self, _file_path):
        return iter(())


class _MemoryClickHouse:
    def __init__(self):
        self.events = []
        self.inserts = []

    def insert(self, table, rows, column_names=None):
        self.inserts.append((table, list(rows), list(column_names or [])))
        if table == "events":
            for row in rows:
                self.events.append(dict(zip(column_names or [], row)))

    def query(self, sql, parameters=None):
        ingest_batch_id = (parameters or {}).get("id")
        grouped = {}
        for row in self.events:
            if row.get("ingest_batch_id") != ingest_batch_id:
                continue
            key = (row["ingest_row_ordinal"], row["ingest_row_hash"])
            grouped[key] = grouped.get(key, 0) + 1
        return SimpleNamespace(result_rows=[(k[0], k[1], v, 1) for k, v in grouped.items()])


class Phase1BD1LifecycleUnitTestCase(unittest.TestCase):
    def setUp(self):
        install_memory_backend()
        self._old_flag = getattr(Config, "PHASE1B_MANIFEST_PROTOCOL_ENABLED", False)
        self._old_batch_size = getattr(Config, "PHASE1B_MANIFEST_BATCH_SIZE", None)
        Config.PHASE1B_MANIFEST_PROTOCOL_ENABLED = True
        Config.PHASE1B_MANIFEST_BATCH_SIZE = 2
        self.app = Flask(__name__)
        self.app.config.update(
            SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            SECRET_KEY="phase1b-d1-unit",
        )
        db.init_app(self.app)
        self.ctx = self.app.app_context()
        self.ctx.push()
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
        self.client = Client(name="D1", code=f"D1{time.time_ns() % 100000}", created_by="tester")
        self.case = Case(uuid=f"d1-case-{time.time_ns()}", name="D1 Case", company="Example", client=self.client, created_by="tester")
        self.case_file = CaseFile(
            case_uuid=self.case.uuid,
            filename="d1.log",
            original_filename="d1.log",
            file_path="/tmp/d1.log",
            file_size=1,
            sha256_hash="1" * 64,
            uploaded_by="tester",
            ingest_protocol_origin=IngestProtocolOrigin.NOT_STARTED,
        )
        db.session.add_all([self.client, self.case, self.case_file])
        db.session.commit()
        parser = _D1Parser(case_id=self.case.id, case_file_id=self.case_file.id)
        self.contract = ManifestParserContract(
            parser_version=parser.parser_version,
            normalization_version="normalization:v1",
            configured_batch_size=2,
            ordering_contract="d1:fixture-order:v1",
            producer_version="d1-parser:v1",
            manifest_eligible=True,
        )

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()
        Config.PHASE1B_MANIFEST_PROTOCOL_ENABLED = self._old_flag
        if self._old_batch_size is None:
            try:
                delattr(Config, "PHASE1B_MANIFEST_BATCH_SIZE")
            except AttributeError:
                pass
        else:
            Config.PHASE1B_MANIFEST_BATCH_SIZE = self._old_batch_size
        reset_fence_backend()

    def _event(self, record_id):
        return ParsedEvent(
            case_id=self.case.id,
            artifact_type="d1_fixture",
            timestamp=datetime(2026, 1, 1) + timedelta(seconds=record_id),
            timestamp_utc=datetime(2026, 1, 1) + timedelta(seconds=record_id),
            timestamp_source_tz="UTC",
            source_file="d1.log",
            source_path="/tmp/d1.log",
            source_host="D1HOST",
            case_file_id=self.case_file.id,
            event_id=str(record_id),
            record_id=record_id,
            command_line=f"record {record_id}",
            raw_json=f'{{"record_id":{record_id}}}',
            search_blob=f"record {record_id}",
            parser_version="D1Parser-1.0.0",
            native_record_id_authoritative=True,
        )

    def _durable_generation(self, events):
        generation = allocate_case_file_initial_generation(
            session=db.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        attempt = create_ingest_attempt(session=db.session, generation=generation)
        batches = construct_managed_batches(generation=generation, attempt=attempt, events=events)
        ch = _MemoryClickHouse()
        for batch in batches:
            row = reserve_staged_batch(session=db.session, manifest=batch)
            insert_managed_batch(ch, batch)
            mark_batch_durable(session=db.session, batch=row, verification=verify_ingest_batch(ch, batch))
        update_generation_ingest_accounting(session=db.session, generation=generation)
        db.session.commit()
        return generation, batches

    def test_activation_requires_explicit_eof_not_just_durable_batches(self):
        generation, _batches = self._durable_generation([self._event(1), self._event(2)])
        result = check_generation_activation_completeness(session=db.session, generation=generation)
        self.assertFalse(result.complete)
        self.assertIn("missing durable ingest completion declaration", result.errors)
        with self.assertRaises(ActivationCompletenessError):
            activate_initial_generation(session=db.session, generation=generation)

    def test_zero_event_generation_activates_without_fake_batch(self):
        generation = allocate_case_file_initial_generation(
            session=db.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        declare_generation_ingest_complete(
            session=db.session,
            generation=generation,
            expected_rows=0,
            final_batch_ordinal=None,
        )
        activate_initial_generation(session=db.session, generation=generation, actor="tester", reason="zero_events")
        db.session.commit()
        self.assertEqual(generation.visibility_state, EvidenceGenerationState.ACTIVE)
        self.assertEqual(generation.expected_rows, 0)
        self.assertIsNone(generation.final_batch_ordinal)
        self.assertEqual(db.session.query(IngestBatch).count(), 0)

    def test_replacement_allocation_failure_and_generation_numbering(self):
        generation, batches = self._durable_generation([self._event(1), self._event(2)])
        declare_generation_ingest_complete(
            session=db.session,
            generation=generation,
            expected_rows=2,
            final_batch_ordinal=batches[-1].batch_ordinal,
        )
        activate_initial_generation(session=db.session, generation=generation)
        db.session.commit()

        replacement = allocate_case_file_replacement_generation(
            session=db.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        self.assertEqual(replacement.source_generation, 2)
        with self.assertRaises(ReplacementInProgressError):
            allocate_case_file_replacement_generation(
                session=db.session,
                case_id=self.case.id,
                case_file_id=self.case_file.id,
                contract=self.contract,
            )
        fail_generation_terminal(session=db.session, generation=replacement, actor="tester", reason="terminal replacement failure")
        db.session.commit()
        db.session.refresh(generation)
        self.assertEqual(generation.visibility_state, EvidenceGenerationState.ACTIVE)
        next_replacement = allocate_case_file_replacement_generation(
            session=db.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        self.assertEqual(next_replacement.source_generation, 3)

    def test_managed_active_routes_to_replacement_with_flag_off(self):
        generation, batches = self._durable_generation([self._event(1), self._event(2)])
        declare_generation_ingest_complete(
            session=db.session,
            generation=generation,
            expected_rows=2,
            final_batch_ordinal=batches[-1].batch_ordinal,
        )
        activate_initial_generation(session=db.session, generation=generation)
        db.session.commit()
        Config.PHASE1B_MANIFEST_PROTOCOL_ENABLED = False
        parser = _D1Parser(case_id=self.case.id, case_file_id=self.case_file.id)
        mode = select_case_file_ingest_mode(parser=parser, case_file=self.case_file, config=Config, session=db.session)
        self.assertEqual(mode, INGEST_MODE_MANAGED_REPLACEMENT)

    def test_legacy_and_deferred_sources_do_not_adopt_managed_reprocess(self):
        parser = _D1Parser(case_id=self.case.id, case_file_id=self.case_file.id)
        self.case_file.ingest_protocol_origin = IngestProtocolOrigin.LEGACY_OR_UNKNOWN
        db.session.commit()
        mode = select_case_file_ingest_mode(parser=parser, case_file=self.case_file, config=Config, session=db.session)
        self.assertEqual(mode, INGEST_MODE_LEGACY)

        self.case_file.ingest_protocol_origin = IngestProtocolOrigin.NOT_STARTED
        db.session.commit()
        deferred_parser = _DeferredParser(case_id=self.case.id, case_file_id=self.case_file.id)
        mode = select_case_file_ingest_mode(
            parser=deferred_parser,
            case_file=self.case_file,
            config=Config,
            session=db.session,
        )
        self.assertEqual(mode, INGEST_MODE_LEGACY)

        generation = allocate_case_file_initial_generation(
            session=db.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        mode = select_case_file_ingest_mode(parser=parser, case_file=self.case_file, config=Config, session=db.session)
        self.assertEqual(mode, INGEST_MODE_MANAGED_INITIAL)
        with self.assertRaises(ManifestRoutingError):
            select_case_file_ingest_mode(
                parser=deferred_parser,
                case_file=self.case_file,
                config=Config,
                session=db.session,
            )
        self.assertEqual(generation.visibility_state, EvidenceGenerationState.BUILDING_INITIAL)

    def test_helper_does_not_call_broad_cleanup_for_managed_replacement(self):
        first_parser = _D1Parser(case_id=self.case.id, case_file_id=self.case_file.id, events=[self._event(1), self._event(2)])
        with patch("tasks.celery_tasks.get_flask_app", return_value=self.app):
            first = _process_managed_initial_case_file(
                parser=first_parser,
                file_path="/tmp/d1.log",
                case_id=self.case.id,
                case_file_id=self.case_file.id,
                clickhouse_client=_MemoryClickHouse(),
                task_id="d1-initial",
            )
        self.assertTrue(first.success)
        self.assertEqual(db.session.query(EvidenceSourceGeneration).one().visibility_state, EvidenceGenerationState.ACTIVE)

        Config.PHASE1B_MANIFEST_PROTOCOL_ENABLED = False
        replacement_parser = _D1Parser(case_id=self.case.id, case_file_id=self.case_file.id, events=[self._event(1), self._event(2)])
        with patch("tasks.celery_tasks._cleanup_case_file_events", side_effect=AssertionError("legacy cleanup called")):
            with patch("tasks.celery_tasks.get_flask_app", return_value=self.app):
                replacement = _process_managed_initial_case_file(
                    parser=replacement_parser,
                    file_path="/tmp/d1.log",
                    case_id=self.case.id,
                    case_file_id=self.case_file.id,
                    clickhouse_client=_MemoryClickHouse(),
                    task_id="d1-replacement",
                )
        self.assertTrue(replacement.success)
        states = {
            row.source_generation: row.visibility_state
            for row in db.session.query(EvidenceSourceGeneration).all()
        }
        self.assertEqual(states[1], EvidenceGenerationState.SUPERSEDED)
        self.assertEqual(states[2], EvidenceGenerationState.ACTIVE)

    def test_single_file_rebuild_routes_managed_active_to_replacement_without_delete_scope(self):
        from tasks.celery_tasks import rebuild_single_case_file_task

        generation = allocate_case_file_initial_generation(
            session=db.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        declare_generation_ingest_complete(
            session=db.session,
            generation=generation,
            expected_rows=0,
            final_batch_ordinal=None,
        )
        activate_initial_generation(session=db.session, generation=generation)
        db.session.commit()

        with tempfile.NamedTemporaryFile("wb", delete=False) as handle:
            handle.write(b"d1 managed reprocess")
            retained_path = handle.name
        self.case_file.file_path = retained_path
        self.case_file.source_path = retained_path
        db.session.commit()

        try:
            queued_task = SimpleNamespace(id="managed-replacement-task")
            with patch("tasks.celery_tasks.get_flask_app", return_value=self.app):
                with patch("utils.rebuilds.ensure_case_rebuild_workspace", return_value="/tmp/d1-managed-rebuild"):
                    with patch("utils.rebuilds.resolve_standard_rebuild_target", return_value={
                        "source_path": retained_path,
                        "mode": "parent_archive",
                    }):
                        with patch("utils.rebuilds.remove_path_if_exists") as remove_mock:
                            with patch("tasks.celery_tasks._delete_standard_case_file_scope", side_effect=AssertionError("delete scope called")):
                                with patch("tasks.celery_tasks.parse_file_task.delay", return_value=queued_task) as delay_mock:
                                    result = rebuild_single_case_file_task.run(
                                        case_uuid=self.case.uuid,
                                        case_id=self.case.id,
                                        case_file_id=self.case_file.id,
                                        username="tester",
                                    )
            self.assertTrue(result["success"])
            self.assertEqual(result["mode"], "managed_replacement")
            self.assertEqual(result["records_deleted"], 0)
            self.assertEqual(result["events_deleted"], 0)
            delay_mock.assert_called_once()
            self.assertEqual(delay_mock.call_args.kwargs["case_file_id"], self.case_file.id)
            remove_mock.assert_called_once_with("/tmp/d1-managed-rebuild")
        finally:
            os.remove(retained_path)

    def test_single_file_rebuild_routes_managed_building_initial_without_delete_scope(self):
        from tasks.celery_tasks import rebuild_single_case_file_task

        generation = allocate_case_file_initial_generation(
            session=db.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        db.session.commit()
        self.assertEqual(generation.visibility_state, EvidenceGenerationState.BUILDING_INITIAL)

        with tempfile.NamedTemporaryFile("wb", delete=False) as handle:
            handle.write(b"d1 managed initial retry")
            retained_path = handle.name
        self.case_file.file_path = retained_path
        self.case_file.source_path = retained_path
        db.session.commit()

        try:
            queued_task = SimpleNamespace(id="managed-initial-retry-task")
            with patch("tasks.celery_tasks.get_flask_app", return_value=self.app):
                with patch("utils.rebuilds.ensure_case_rebuild_workspace", return_value="/tmp/d1-managed-initial-retry"):
                    with patch("utils.rebuilds.resolve_standard_rebuild_target", return_value={
                        "source_path": retained_path,
                        "mode": "parent_archive",
                    }):
                        with patch("utils.rebuilds.remove_path_if_exists") as remove_mock:
                            with patch("tasks.celery_tasks._delete_standard_case_file_scope", side_effect=AssertionError("delete scope called")):
                                with patch("tasks.celery_tasks.parse_file_task.delay", return_value=queued_task) as delay_mock:
                                    result = rebuild_single_case_file_task.run(
                                        case_uuid=self.case.uuid,
                                        case_id=self.case.id,
                                        case_file_id=self.case_file.id,
                                        username="tester",
                                    )
            self.assertTrue(result["success"])
            self.assertEqual(result["mode"], "managed_initial_retry")
            self.assertEqual(result["records_deleted"], 0)
            self.assertEqual(result["events_deleted"], 0)
            delay_mock.assert_called_once()
            self.assertEqual(delay_mock.call_args.kwargs["case_file_id"], self.case_file.id)
            remove_mock.assert_called_once_with("/tmp/d1-managed-initial-retry")
        finally:
            os.remove(retained_path)


@unittest.skipUnless(PG_URL and CH_DB, "PHASE1B_PG_TEST_DATABASE_URL and PHASE1B_CH_TEST_DATABASE are required")
class Phase1BD1RealPGCHTestCase(unittest.TestCase):
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
            SECRET_KEY="phase1b-d1-real",
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
        for ddl in clickhouse_control_table_ddl():
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
        self.session.query(IngestBatch).delete()
        self.session.query(IngestAttempt).delete()
        self.session.query(EvidenceGenerationAudit).delete()
        self.session.query(EvidenceSourceGeneration).delete()
        self.session.query(CaseFile).delete()
        self.session.query(Case).delete()
        self.session.query(Client).delete()
        self.session.commit()
        self.client = Client(name="D1 Real", code=f"D1R{time.time_ns() % 100000}", created_by="tester")
        self.case = Case(uuid=f"d1-real-{time.time_ns()}", name="D1 Real", company="Example", client=self.client, created_by="tester")
        self.case_file = CaseFile(
            case_uuid=self.case.uuid,
            filename="d1-real.log",
            original_filename="d1-real.log",
            file_path="/tmp/d1-real.log",
            file_size=1,
            sha256_hash="2" * 64,
            uploaded_by="tester",
            ingest_protocol_origin=IngestProtocolOrigin.NOT_STARTED,
        )
        self.session.add_all([self.client, self.case, self.case_file])
        self.session.commit()
        parser = _D1Parser(case_id=self.case.id, case_file_id=self.case_file.id)
        self.contract = ManifestParserContract(
            parser_version=parser.parser_version,
            normalization_version="normalization:v1",
            configured_batch_size=2,
            ordering_contract="d1:fixture-order:v1",
            producer_version="d1-parser:v1",
            manifest_eligible=True,
        )

    def tearDown(self):
        self.session.close()
        self.Session.remove()

    def _event(self, generation_number, record_id):
        return ParsedEvent(
            case_id=self.case.id,
            artifact_type="d1_fixture",
            timestamp=datetime(2026, 1, 1) + timedelta(seconds=record_id),
            timestamp_utc=datetime(2026, 1, 1) + timedelta(seconds=record_id),
            timestamp_source_tz="UTC",
            source_file="d1-real.log",
            source_path="/tmp/d1-real.log",
            source_host="D1HOST",
            case_file_id=self.case_file.id,
            event_id=f"{generation_number}-{record_id}",
            record_id=record_id,
            command_line=f"generation {generation_number} record {record_id}",
            raw_json=f'{{"generation":{generation_number},"record_id":{record_id}}}',
            search_blob=f"generation {generation_number} record {record_id}",
            parser_version="D1Parser-1.0.0",
            native_record_id_authoritative=True,
        )

    def _complete_generation(self, generation, events):
        attempt = create_ingest_attempt(session=self.session, generation=generation)
        batches = construct_managed_batches(generation=generation, attempt=attempt, events=events)
        for batch in batches:
            row = reserve_staged_batch(session=self.session, manifest=batch)
            insert_managed_batch(self.ch, batch)
            mark_batch_durable(session=self.session, batch=row, verification=verify_ingest_batch(self.ch, batch))
        update_generation_ingest_accounting(session=self.session, generation=generation)
        declare_generation_ingest_complete(
            session=self.session,
            generation=generation,
            expected_rows=len(events),
            final_batch_ordinal=None if not events else batches[-1].batch_ordinal,
        )
        self.session.commit()
        project_generation_control_state(self.ch, self.session, generation)
        return batches

    def _certified_iis_fixture(self):
        fixture_case = Phase1BTrancheC1DeterminismTestCase(methodName="run")
        fixture_case.setUp()
        self.addCleanup(fixture_case.tearDown)
        return fixture_case.fixtures["IISLogParser"]

    def _copy_fixture_to_case_originals(self, fixture_path):
        originals_base = tempfile.TemporaryDirectory(prefix="casescope-d1-originals-")
        self.addCleanup(originals_base.cleanup)
        case_originals = os.path.join(originals_base.name, self.case.uuid, "originals")
        os.makedirs(case_originals, exist_ok=True)
        retained_path = os.path.join(case_originals, os.path.basename(str(fixture_path)))
        shutil.copy2(str(fixture_path), retained_path)
        return originals_base.name, retained_path

    def test_real_rebuild_task_managed_active_uses_replacement_lifecycle_with_cleanup_tripwires(self):
        from tasks.celery_tasks import parse_file_task, rebuild_single_case_file_task

        fixture_path = self._certified_iis_fixture()
        originals_base, retained_path = self._copy_fixture_to_case_originals(fixture_path)
        self.case_file.filename = os.path.basename(retained_path)
        self.case_file.original_filename = os.path.basename(retained_path)
        self.case_file.file_path = retained_path
        self.case_file.source_path = retained_path
        self.case_file.file_size = os.path.getsize(retained_path)
        self.case_file.sha256_hash = "3" * 64
        self.case_file.file_type = "Other"
        self.session.commit()

        with patch("tasks.celery_tasks.get_flask_app", return_value=self.app):
            with patch("utils.clickhouse.get_fresh_client", return_value=self.ch):
                with patch.object(parse_file_task, "update_state"):
                    initial_result = parse_file_task.run(
                        file_path=retained_path,
                        case_id=self.case.id,
                        source_host="C1HOST",
                        case_file_id=self.case_file.id,
                    )
        self.assertTrue(initial_result["success"])
        self.assertEqual(initial_result["events_count"], 11)
        initial = (
            self.session.query(EvidenceSourceGeneration)
            .filter_by(source_ref_id=str(self.case_file.id), source_generation=1)
            .one()
        )
        self.assertEqual(initial.visibility_state, EvidenceGenerationState.ACTIVE)
        self.assertEqual(self.ch.query("SELECT count() FROM events WHERE source_generation = 1").result_rows[0][0], 11)

        Config.PHASE1B_MANIFEST_PROTOCOL_ENABLED = False
        parse_results = []

        def _run_parse_file_now(**kwargs):
            with patch.object(parse_file_task, "update_state"):
                result = parse_file_task.run(**kwargs)
            parse_results.append(result)
            return SimpleNamespace(id="d1-managed-replacement-sync")

        with patch("utils.artifact_paths.get_originals_base_path", return_value=originals_base):
            with patch("tasks.celery_tasks.get_flask_app", return_value=self.app):
                with patch("utils.clickhouse.get_fresh_client", return_value=self.ch):
                    with patch("tasks.celery_tasks._delete_standard_case_file_scope", side_effect=AssertionError("broad delete scope called")):
                        with patch("tasks.celery_tasks._cleanup_case_file_events", side_effect=AssertionError("legacy file cleanup called")):
                            with patch("utils.clickhouse.delete_file_events", side_effect=AssertionError("delete_file_events called")):
                                with patch("utils.clickhouse.delete_case_events", side_effect=AssertionError("delete_case_events called")):
                                    with patch("tasks.celery_tasks.parse_file_task.delay", side_effect=_run_parse_file_now) as delay_mock:
                                        rebuild_result = rebuild_single_case_file_task.run(
                                            case_uuid=self.case.uuid,
                                            case_id=self.case.id,
                                            case_file_id=self.case_file.id,
                                            username="tester",
                                        )

        self.assertTrue(rebuild_result["success"])
        self.assertEqual(rebuild_result["mode"], "managed_replacement")
        self.assertEqual(rebuild_result["records_deleted"], 0)
        self.assertEqual(rebuild_result["events_deleted"], 0)
        delay_mock.assert_called_once()
        self.assertEqual(len(parse_results), 1)
        self.assertTrue(parse_results[0]["success"])
        self.assertEqual(parse_results[0]["events_count"], 11)

        self.session.expire_all()
        generations = {
            row.source_generation: row
            for row in self.session.query(EvidenceSourceGeneration)
            .filter_by(source_ref_id=str(self.case_file.id))
            .order_by(EvidenceSourceGeneration.source_generation)
            .all()
        }
        self.assertEqual(generations[1].visibility_state, EvidenceGenerationState.SUPERSEDED)
        self.assertEqual(generations[2].visibility_state, EvidenceGenerationState.ACTIVE)
        physical = dict(self.ch.query("SELECT source_generation, count() FROM events GROUP BY source_generation").result_rows)
        self.assertEqual(physical[1], 11)
        self.assertEqual(physical[2], 11)
        self.assertEqual(
            resolve_projected_visible_generation(
                self.ch,
                case_id=self.case.id,
                source_ref_type=SourceRefType.CASE_FILE,
                source_ref_id=str(self.case_file.id),
            ),
            2,
        )

    def test_real_eof_completeness_rejects_known_durable_without_declaration_and_holes(self):
        generation = allocate_case_file_initial_generation(
            session=self.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        self._complete_generation(
            generation,
            [
                self._event(1, 1),
                self._event(1, 2),
                self._event(1, 3),
                self._event(1, 4),
                self._event(1, 5),
                self._event(1, 6),
            ],
        )
        batches = self.session.query(IngestBatch).filter_by(generation_id=generation.id).order_by(IngestBatch.batch_ordinal).all()
        self.assertEqual([batch.batch_ordinal for batch in batches], [0, 1, 2])
        self.assertTrue(all(batch.state == IngestBatchState.DURABLE for batch in batches))
        generation.completed_at = None
        generation.expected_rows = None
        generation.final_batch_ordinal = None
        self.session.commit()

        missing_eof = check_generation_activation_completeness(session=self.session, generation=generation)
        self.assertFalse(missing_eof.complete)
        self.assertIn("missing durable ingest completion declaration", missing_eof.errors)
        with self.assertRaises(ActivationCompletenessError):
            activate_initial_generation(session=self.session, generation=generation)

        declare_generation_ingest_complete(
            session=self.session,
            generation=generation,
            expected_rows=8,
            final_batch_ordinal=3,
        )
        self.session.commit()
        hole = check_generation_activation_completeness(session=self.session, generation=generation)
        self.assertFalse(hole.complete)
        self.assertIn("missing expected batch ordinals [3]", hole.errors)

        declare_generation_ingest_complete(
            session=self.session,
            generation=generation,
            expected_rows=6,
            final_batch_ordinal=2,
        )
        activated = activate_initial_generation(session=self.session, generation=generation)
        self.session.commit()
        self.assertEqual(activated.visibility_state, EvidenceGenerationState.ACTIVE)

    def test_real_initial_replacement_activation_projection_and_coexistence(self):
        initial = allocate_case_file_initial_generation(
            session=self.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        initial_batches = self._complete_generation(initial, [self._event(1, 1), self._event(1, 2), self._event(1, 3)])
        activate_initial_generation(session=self.session, generation=initial, actor="tester", reason="d1 initial")
        self.session.commit()
        project_generation_control_state(self.ch, self.session, initial)
        self.assertEqual(
            resolve_projected_visible_generation(
                self.ch,
                case_id=self.case.id,
                source_ref_type=SourceRefType.CASE_FILE,
                source_ref_id=str(self.case_file.id),
            ),
            1,
        )

        replacement = allocate_case_file_replacement_generation(
            session=self.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        replacement_batches = self._complete_generation(replacement, [self._event(2, 1), self._event(2, 2), self._event(2, 3)])
        project_generation_control_state(self.ch, self.session, replacement)
        self.assertEqual(
            resolve_projected_visible_generation(
                self.ch,
                case_id=self.case.id,
                source_ref_type=SourceRefType.CASE_FILE,
                source_ref_id=str(self.case_file.id),
            ),
            1,
        )
        physical = dict(self.ch.query("SELECT source_generation, count() FROM events GROUP BY source_generation").result_rows)
        self.assertEqual(physical[1], 3)
        self.assertEqual(physical[2], 3)
        self.assertNotEqual(initial_batches[0].ingest_batch_id, replacement_batches[0].ingest_batch_id)

        activate_replacement_generation(session=self.session, replacement=replacement, actor="tester", reason="d1 replacement")
        self.session.commit()
        project_generation_authority_swap(
            self.ch,
            self.session,
            prior_generation=initial,
            new_generation=replacement,
        )
        self.assertEqual(
            resolve_projected_visible_generation(
                self.ch,
                case_id=self.case.id,
                source_ref_type=SourceRefType.CASE_FILE,
                source_ref_id=str(self.case_file.id),
            ),
            2,
        )
        self.assertEqual(self.session.query(EvidenceGenerationAudit).count(), 2)

        stale_initial = list(self.ch.query(
            """
            SELECT case_id, source_ref_type, source_ref_id, source_generation,
                   visibility_state, state_version, publishable, now()
            FROM visible_evidence_generations
            WHERE source_generation = 1
            LIMIT 1
            """
        ).result_rows[0])
        stale_initial[4] = EvidenceGenerationState.ACTIVE
        stale_initial[5] = 1
        stale_initial[6] = 1
        self.ch.insert(
            "visible_evidence_generations",
            [tuple(stale_initial)],
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
        self.assertEqual(
            resolve_projected_visible_generation(
                self.ch,
                case_id=self.case.id,
                source_ref_type=SourceRefType.CASE_FILE,
                source_ref_id=str(self.case_file.id),
            ),
            2,
        )

    def test_real_rollback_and_concurrent_replacement_constraints(self):
        initial = allocate_case_file_initial_generation(
            session=self.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        self._complete_generation(initial, [self._event(1, 1), self._event(1, 2)])
        activate_initial_generation(session=self.session, generation=initial)
        self.session.commit()
        replacement = allocate_case_file_replacement_generation(
            session=self.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        self._complete_generation(replacement, [self._event(2, 1), self._event(2, 2)])
        try:
            activate_replacement_generation(
                session=self.session,
                replacement=replacement,
                inject_failure_after_supersede=True,
            )
            self.session.commit()
        except RuntimeError:
            self.session.rollback()
        self.session.expire_all()
        states = {
            row.source_generation: row.visibility_state
            for row in self.session.query(EvidenceSourceGeneration).all()
        }
        self.assertEqual(states[1], EvidenceGenerationState.ACTIVE)
        self.assertEqual(states[2], EvidenceGenerationState.BUILDING_REPLACEMENT)

        errors = []
        results = []
        barrier = threading.Barrier(2)

        def worker():
            session = self.Session()
            try:
                barrier.wait(timeout=10)
                row = EvidenceSourceGeneration(
                    case_id=self.case.id,
                    source_ref_type=SourceRefType.CASE_FILE,
                    source_ref_id=str(self.case_file.id),
                    source_generation=99 + len(results),
                    visibility_state=EvidenceGenerationState.BUILDING_REPLACEMENT,
                    parser_version="p",
                    normalization_version="n",
                    batching_contract_version="ingest-batch:v1",
                    configured_batch_size=2,
                    ordering_contract="d1:fixture-order:v1",
                )
                session.add(row)
                session.commit()
                results.append(row.id)
            except Exception as exc:
                session.rollback()
                errors.append(exc)
            finally:
                session.close()

        threads = [threading.Thread(target=worker), threading.Thread(target=worker)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=20)
        self.assertEqual(len(results), 0)
        self.assertTrue(errors)
        self.assertTrue(any(isinstance(exc, IntegrityError) for exc in errors))

    def test_real_concurrent_reprocess_allows_exactly_one_building_replacement(self):
        initial = allocate_case_file_initial_generation(
            session=self.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        self._complete_generation(initial, [self._event(1, 1), self._event(1, 2)])
        activate_initial_generation(session=self.session, generation=initial)
        self.session.commit()

        results = []
        errors = []
        barrier = threading.Barrier(2)

        def worker(label):
            session = self.Session()
            try:
                barrier.wait(timeout=10)
                replacement = allocate_case_file_replacement_generation(
                    session=session,
                    case_id=self.case.id,
                    case_file_id=self.case_file.id,
                    contract=self.contract,
                )
                session.commit()
                results.append((label, replacement.source_generation))
            except Exception as exc:
                session.rollback()
                errors.append((label, exc.__class__.__name__, str(exc)))
            finally:
                session.close()

        threads = [threading.Thread(target=worker, args=(label,)) for label in ("caller-a", "caller-b")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=20)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][1], 2)
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0][1], "ReplacementInProgressError")
        states = {
            row.source_generation: row.visibility_state
            for row in self.session.query(EvidenceSourceGeneration).order_by(EvidenceSourceGeneration.source_generation).all()
        }
        self.assertEqual(states, {1: EvidenceGenerationState.ACTIVE, 2: EvidenceGenerationState.BUILDING_REPLACEMENT})

    def test_real_concurrent_activation_is_single_swap_and_second_call_idempotent(self):
        initial = allocate_case_file_initial_generation(
            session=self.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        self._complete_generation(initial, [self._event(1, 1), self._event(1, 2)])
        activate_initial_generation(session=self.session, generation=initial)
        replacement = allocate_case_file_replacement_generation(
            session=self.session,
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            contract=self.contract,
        )
        self._complete_generation(replacement, [self._event(2, 1), self._event(2, 2)])
        self.session.commit()

        results = []
        errors = []
        barrier = threading.Barrier(2)

        def worker(label):
            session = self.Session()
            try:
                replacement_row = session.get(EvidenceSourceGeneration, replacement.id)
                barrier.wait(timeout=10)
                activated = activate_replacement_generation(
                    session=session,
                    replacement=replacement_row,
                    actor="tester",
                    reason="concurrent activation",
                )
                session.commit()
                results.append((label, activated.source_generation, activated.visibility_state))
            except Exception as exc:
                session.rollback()
                errors.append((label, exc.__class__.__name__, str(exc)))
            finally:
                session.close()

        threads = [threading.Thread(target=worker, args=(label,)) for label in ("caller-a", "caller-b")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=20)

        self.assertEqual(errors, [])
        self.assertEqual(len(results), 2)
        self.assertEqual({row[1] for row in results}, {2})
        self.assertEqual({row[2] for row in results}, {EvidenceGenerationState.ACTIVE})
        self.session.expire_all()
        states = {
            row.source_generation: row.visibility_state
            for row in self.session.query(EvidenceSourceGeneration).order_by(EvidenceSourceGeneration.source_generation).all()
        }
        self.assertEqual(states, {1: EvidenceGenerationState.SUPERSEDED, 2: EvidenceGenerationState.ACTIVE})
        self.assertEqual(
            self.session.query(EvidenceSourceGeneration)
            .filter_by(visibility_state=EvidenceGenerationState.ACTIVE)
            .count(),
            1,
        )
        self.assertEqual(
            self.session.query(EvidenceGenerationAudit)
            .filter_by(transition="BUILDING_REPLACEMENT_TO_ACTIVE")
            .count(),
            1,
        )


if __name__ == "__main__":
    unittest.main()
