"""Phase 2.2B explicit synchronous events INSERT activation tests.

These tests lock the accepted PHASE2_2_MODE_SYNC per-call settings on the
two canonical events writers. They must not skip when disposable PG/CH
fixtures are unset: unit gates always run. Live ClickHouse proof fails
closed if the server is unreachable.
"""
from __future__ import annotations

import inspect
import json
import os
import time
import unittest
import uuid
from datetime import datetime, timedelta
from types import SimpleNamespace

os.environ.setdefault("SECRET_KEY", "phase2-2b-test-secret")

from flask import Flask

from migrations.add_events_table import EVENTS_SCHEMA
from migrations.add_phase1b_tranche_b_manifest_protocol import clickhouse_control_table_ddl
from models.case import Case
from models.case_file import CaseFile
from models.database import db
from models.database_flow import (
    EvidenceGenerationState,
    EvidenceSourceGeneration,
    IngestAttempt,
    IngestBatch,
    IngestBatchState,
    SourceRefType,
)
from parsers.base import ParsedEvent
from parsers.registry import BatchProcessor
from utils import clickhouse as clickhouse_utils
from utils.clickhouse import EVENT_INSERT_MODE, event_insert_settings
from utils.ingest_fence import (
    FailingFenceBackend,
    IngestFenceUnavailable,
    install_fence_backend,
    install_memory_backend,
    reset_fence_backend,
)
from utils.ingest_identity import batch_content_hash, deterministic_ingest_batch_id, ingest_row_hash
from utils.manifest_protocol import (
    PROTOCOL_CLICKHOUSE_COLUMNS,
    VISIBLE_EVIDENCE_GENERATIONS_COLUMNS,
    construct_managed_batch,
    insert_managed_batch,
    project_generation_control_state,
    reserve_staged_batch,
    verify_ingest_batch,
)
from utils.search_blob_text_index import list_part_files, part_has_text_index_files


EXPECTED_EVENT_INSERT_SETTINGS = {
    "async_insert": 0,
    "materialize_skip_indexes_on_insert": 1,
}
NGRAM_SENTINEL = "skp_idx_idx_search_ngram.idx"


class _RecordingInsertClient:
    def __init__(self, *, fail_insert=False, drop_rows_after_insert=False):
        self.events = []
        self.inserts = []
        self.commands = []
        self.fail_insert = fail_insert
        self.drop_rows_after_insert = drop_rows_after_insert

    def insert(self, table, rows, column_names=None, settings=None, **kwargs):
        call = {
            "table": table,
            "rows": list(rows),
            "column_names": list(column_names or []),
            "settings": None if settings is None else dict(settings),
            "kwargs": dict(kwargs),
            "settings_passed": "settings" in kwargs or settings is not None,
        }
        # Distinguish omitted settings from settings=None by using a sentinel
        # in the bound signature: tests that need "not injected" inspect kwargs.
        call["raw_kwargs_keys"] = sorted(kwargs.keys())
        if settings is not None:
            call["settings_passed"] = True
        self.inserts.append(call)
        if table == "events":
            if self.fail_insert:
                raise RuntimeError("simulated events INSERT failure")
            for row in rows:
                self.events.append(dict(zip(column_names or [], row)))
            if self.drop_rows_after_insert:
                self.events = []
        return SimpleNamespace(query_id=lambda: "fake-qid")

    def query(self, sql, parameters=None):
        ingest_batch_id = (parameters or {}).get("id")
        grouped = {}
        for row in self.events:
            if ingest_batch_id is not None and row.get("ingest_batch_id") != ingest_batch_id:
                continue
            key = (row["ingest_row_ordinal"], row["ingest_row_hash"])
            grouped[key] = grouped.get(key, 0) + 1
        return SimpleNamespace(
            result_rows=[(k[0], k[1], v, 1) for k, v in grouped.items()]
        )

    def command(self, sql):
        self.commands.append(sql)


class _KwargRecordingClient:
    """Records whether the settings keyword was supplied at all."""

    def __init__(self):
        self.calls = []

    def insert(self, table, data, column_names=None, **kwargs):
        self.calls.append(
            {
                "table": table,
                "column_names": list(column_names or []),
                "kwargs": dict(kwargs),
            }
        )


def _fixture_event(index: int, *, case_id: int, case_file_id: int) -> ParsedEvent:
    ts = datetime(2024, 6, 1, 12, 0, 0) + timedelta(seconds=index)
    ntlm = " NTLM" if index == 0 else ""
    blob = f"host P22BHOST user analyst event 4688 powershell{ntlm} row{index}"
    return ParsedEvent(
        case_id=case_id,
        artifact_type="evtx",
        timestamp=ts,
        timestamp_utc=ts,
        timestamp_source_tz="UTC",
        source_file="Security.evtx",
        source_path="/evidence/Security.evtx",
        source_host="P22BHOST",
        case_file_id=case_file_id,
        event_id="4688",
        channel="Security",
        provider="Microsoft-Windows-Security-Auditing",
        record_id=index + 1,
        level="Information",
        username="analyst",
        domain="CORP",
        process_name="powershell.exe",
        command_line="powershell.exe -NoProfile",
        raw_json='{"EventID":"4688","Channel":"Security"}',
        search_blob=blob,
        extra_fields='{"native_record_id_authoritative":true,"provenance_source":"parser_emitted"}',
        parser_version="phase2-2b:v1",
        evidence_record_key=f"erk-p22b-{case_id}-{index:08d}",
        evidence_identity_version="v1",
        evidence_identity_quality="high",
        native_record_id_authoritative=True,
    )


def _generation_attempt(*, case_id: int = 42, case_file_id: int = 99, batch_size: int = 10):
    generation = EvidenceSourceGeneration(
        case_id=case_id,
        source_ref_type=SourceRefType.CASE_FILE,
        source_ref_id=str(case_file_id),
        source_generation=1,
        visibility_state=EvidenceGenerationState.BUILDING_INITIAL,
        parser_version="phase2-2b:v1",
        normalization_version="normalization:v1",
        batching_contract_version="ingest-batch:v1",
        configured_batch_size=batch_size,
        ordering_contract="test:phase2-2b-order:v1",
        producer_version="phase2-2b:v1",
    )
    generation.id = 1
    attempt = IngestAttempt(ingest_attempt_id=str(uuid.uuid4()), generation_id=1)
    return generation, attempt


def _summary_query_id(summary) -> str:
    if summary is None:
        return ""
    value = getattr(summary, "query_id", "")
    if callable(value):
        value = value()
    return str(value or "")


def _fresh_style_client(database: str):
    Config = clickhouse_utils._get_app_config()
    import clickhouse_connect

    return clickhouse_connect.get_client(
        host=Config.CLICKHOUSE_HOST,
        port=Config.CLICKHOUSE_PORT,
        database=database,
        username=Config.CLICKHOUSE_USER,
        password=Config.CLICKHOUSE_PASSWORD,
        autogenerate_session_id=False,
        settings={
            "max_threads": clickhouse_utils._get_config_attr("CLICKHOUSE_MAX_THREADS", 8),
            "max_execution_time": clickhouse_utils._get_config_attr("CLICKHOUSE_QUERY_TIMEOUT", 300),
        },
        connect_timeout=10,
        send_receive_timeout=300,
    )


class _LiveRecordingClient:
    def __init__(self, inner):
        self._inner = inner
        self.insert_calls = []

    def insert(self, table, data, column_names=None, settings=None, **kwargs):
        summary = self._inner.insert(
            table,
            data,
            column_names=column_names,
            settings=settings,
            **kwargs,
        )
        self.insert_calls.append(
            {
                "table": table,
                "settings": None if settings is None else dict(settings),
                "query_id": _summary_query_id(summary),
                "settings_kwarg_present": settings is not None or "settings" in kwargs,
            }
        )
        return summary

    def query(self, *args, **kwargs):
        return self._inner.query(*args, **kwargs)

    def command(self, *args, **kwargs):
        return self._inner.command(*args, **kwargs)

    def close(self):
        return self._inner.close()


class EventInsertSettingsUnitTests(unittest.TestCase):
    def test_event_insert_settings_exact_and_fresh(self):
        self.assertEqual(EVENT_INSERT_MODE, "sync")
        first = event_insert_settings()
        second = event_insert_settings()
        self.assertEqual(first, EXPECTED_EVENT_INSERT_SETTINGS)
        self.assertEqual(set(first.keys()), {"async_insert", "materialize_skip_indexes_on_insert"})
        self.assertNotIn("wait_for_async_insert", first)
        self.assertIsNot(first, second)
        first["async_insert"] = 1
        self.assertEqual(event_insert_settings()["async_insert"], 0)

    def test_helper_has_no_environment_override(self):
        source = inspect.getsource(event_insert_settings)
        self.assertNotIn("os.environ", source)
        self.assertNotIn("getenv", source)
        constant_src = inspect.getsource(clickhouse_utils)
        start = constant_src.index("EVENT_INSERT_MODE")
        end = constant_src.index("def event_insert_settings")
        self.assertNotIn("os.environ", constant_src[start:end])

    def test_generic_clients_do_not_pin_insert_mode(self):
        source = inspect.getsource(clickhouse_utils.get_client) + inspect.getsource(
            clickhouse_utils.get_fresh_client
        )
        self.assertNotIn("async_insert", source)
        self.assertNotIn("wait_for_async_insert", source)
        self.assertNotIn("materialize_skip_indexes_on_insert", source)
        self.assertNotIn("event_insert_settings", source)

    def test_no_fifteen_percent_heuristic_in_runtime(self):
        runtime_sources = (
            inspect.getsource(clickhouse_utils.event_insert_settings),
            inspect.getsource(insert_managed_batch),
            inspect.getsource(BatchProcessor.flush),
        )
        joined = "\n".join(runtime_sources)
        self.assertNotIn("0.15", joined)
        self.assertNotIn("15%", joined)
        self.assertNotIn("10% slower", joined)

    def test_version_is_patch_4_26_1(self):
        with open(os.path.join(os.path.dirname(os.path.dirname(__file__)), "version.json"), encoding="utf-8") as handle:
            payload = json.load(handle)
        versions = [entry.get("version") for entry in payload.get("changelog") or []]
        self.assertIn("4.26.1", versions)
        entry = next(item for item in payload["changelog"] if item.get("version") == "4.26.1")
        joined = " ".join(entry["changes"])
        self.assertIn("synchronous", joined.lower())
        self.assertIn("10k", joined)
        self.assertTrue(str(payload["version"]).startswith("4.26."), msg=payload["version"])


class ManagedAndLegacyInsertUnitTests(unittest.TestCase):
    def setUp(self):
        install_memory_backend()

    def tearDown(self):
        reset_fence_backend()

    def test_insert_managed_batch_passes_exact_event_settings(self):
        generation, attempt = _generation_attempt()
        events = [_fixture_event(i, case_id=42, case_file_id=99) for i in range(3)]
        manifest = construct_managed_batch(
            generation=generation, attempt=attempt, events=tuple(events), batch_ordinal=0
        )
        client = _RecordingInsertClient()
        insert_managed_batch(client, manifest)
        self.assertEqual(len(client.inserts), 1)
        call = client.inserts[0]
        self.assertEqual(call["table"], "events")
        self.assertEqual(call["settings"], EXPECTED_EVENT_INSERT_SETTINGS)
        self.assertNotIn("wait_for_async_insert", call["settings"])
        self.assertEqual(call["column_names"], list(PROTOCOL_CLICKHOUSE_COLUMNS))
        self.assertEqual(len(call["rows"]), 3)

    def test_batch_processor_events_passes_exact_settings(self):
        client = _KwargRecordingClient()
        processor = BatchProcessor(client, batch_size=10, use_buffer=False)
        self.assertEqual(processor.table, "events")
        self.assertEqual(BatchProcessor.DEFAULT_BATCH_SIZE, 10000)
        processor.add_event(SimpleNamespace(to_clickhouse_row=lambda: (1, "row")))
        processor.flush()
        self.assertEqual(len(client.calls), 1)
        self.assertEqual(client.calls[0]["table"], "events")
        self.assertEqual(client.calls[0]["kwargs"]["settings"], EXPECTED_EVENT_INSERT_SETTINGS)
        self.assertNotIn("wait_for_async_insert", client.calls[0]["kwargs"]["settings"])

    def test_batch_processor_non_events_does_not_inject_settings(self):
        client = _KwargRecordingClient()
        processor = BatchProcessor(client, batch_size=10, use_buffer=True)
        self.assertEqual(processor.table, "events_buffer")
        processor.add_event(SimpleNamespace(to_clickhouse_row=lambda: (1, "row")))
        processor.flush()
        self.assertEqual(len(client.calls), 1)
        self.assertEqual(client.calls[0]["table"], "events_buffer")
        self.assertNotIn("settings", client.calls[0]["kwargs"])


class RecoveryRetryAndIsolationUnitTests(unittest.TestCase):
    def test_celery_recovery_paths_inherit_insert_managed_batch(self):
        from tasks import celery_tasks

        recover_src = inspect.getsource(celery_tasks.recover_staged_ingest_batch_task)
        initial_src = inspect.getsource(celery_tasks._process_managed_initial_case_file)
        directory_src = inspect.getsource(celery_tasks._process_managed_evtx_directory_group)
        reconciler_src = inspect.getsource(celery_tasks.reconcile_stale_staged_ingest_batches_task)
        schedule_src = inspect.getsource(celery_tasks._schedule_staged_batch_recovery)
        for name, source in (
            ("recover_staged_ingest_batch_task", recover_src),
            ("_process_managed_initial_case_file", initial_src),
            ("_process_managed_evtx_directory_group", directory_src),
        ):
            self.assertIn("_commit_reserved_managed_batch", source, msg=name)
            self.assertNotIn("async_insert", source, msg=name)
            self.assertNotIn("wait_for_async_insert", source, msg=name)
            self.assertNotIn("event_insert_settings", source, msg=name)
            self.assertNotIn("materialize_skip_indexes_on_insert", source, msg=name)
        helper_src = inspect.getsource(celery_tasks._commit_reserved_managed_batch)
        self.assertIn("commit_managed_batch_exactly_once", helper_src)
        from utils.manifest_protocol import commit_managed_batch_exactly_once
        commit_src = inspect.getsource(commit_managed_batch_exactly_once)
        self.assertIn("insert_managed_batch", commit_src)
        self.assertIn("verify_ingest_batch", commit_src)
        self.assertIn("mark_batch_durable", commit_src)
        self.assertIn("MANAGED_REPLACEMENT", initial_src)
        self.assertIn("_commit_reserved_managed_batch", initial_src)
        self.assertIn("_schedule_staged_batch_recovery", reconciler_src)
        self.assertIn("recover_staged_ingest_batch_task.delay", schedule_src)
        self.assertNotIn("async_insert", reconciler_src)
        self.assertNotIn("async_insert", schedule_src)

        from utils.staged_batch_reconciler import reconcile_staged_batch

        recon_src = inspect.getsource(reconcile_staged_batch)
        self.assertNotIn("async_insert", recon_src)
        self.assertNotIn("event_insert_settings", recon_src)

    def test_publication_order_uses_shared_exact_durable_commit(self):
        from tasks.celery_tasks import (
            _commit_reserved_managed_batch,
            _process_managed_evtx_directory_group,
            _process_managed_initial_case_file,
            recover_staged_ingest_batch_task,
        )
        from utils.manifest_protocol import commit_managed_batch_exactly_once, insert_managed_batch

        for fn in (
            _process_managed_initial_case_file,
            _process_managed_evtx_directory_group,
            recover_staged_ingest_batch_task,
        ):
            source = inspect.getsource(fn)
            self.assertIn("_commit_reserved_managed_batch", source, msg=fn.__name__)
            self.assertIn("project_generation_control_state(", source, msg=fn.__name__)
        helper_src = inspect.getsource(_commit_reserved_managed_batch)
        self.assertIn("commit_managed_batch_exactly_once", helper_src)
        commit_src = inspect.getsource(commit_managed_batch_exactly_once)
        self.assertIn("verify_ingest_batch", commit_src)
        self.assertIn("insert_managed_batch", commit_src)
        self.assertIn("mark_batch_durable", commit_src)
        insert_src = inspect.getsource(insert_managed_batch)
        self.assertNotIn("mark_batch_durable", insert_src)
        self.assertNotIn("verify_ingest_batch", insert_src)
        from utils.manifest_protocol import mark_batch_durable
        self.assertIn('verification.outcome != "exact"', inspect.getsource(mark_batch_durable))

    def test_control_projection_does_not_inherit_event_settings(self):
        install_memory_backend()
        self.addCleanup(reset_fence_backend)
        generation, attempt = _generation_attempt()
        events = [_fixture_event(0, case_id=42, case_file_id=99)]
        manifest = construct_managed_batch(
            generation=generation, attempt=attempt, events=tuple(events), batch_ordinal=0
        )
        client = _RecordingInsertClient()
        insert_managed_batch(client, manifest)
        self.assertEqual(client.inserts[0]["settings"]["async_insert"], 0)

        app = Flask(__name__)
        app.config.update(
            SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            SECRET_KEY="phase2-2b-projection",
        )
        db.init_app(app)
        ctx = app.app_context()
        ctx.push()
        self.addCleanup(ctx.pop)
        for table in (
            Case.__table__,
            CaseFile.__table__,
            EvidenceSourceGeneration.__table__,
            IngestAttempt.__table__,
            IngestBatch.__table__,
        ):
            table.create(db.engine, checkfirst=True)
        case = Case(uuid="p22b-case", name="P22B", company="Example", created_by="tester")
        db.session.add(case)
        db.session.flush()
        case_file = CaseFile(
            case_uuid=case.uuid,
            filename="fixture.log",
            original_filename="fixture.log",
            file_path="/tmp/fixture.log",
            file_size=1,
            sha256_hash="a" * 64,
            uploaded_by="tester",
        )
        db.session.add(case_file)
        db.session.flush()
        stored_generation = EvidenceSourceGeneration(
            case_id=case.id,
            source_ref_type=SourceRefType.CASE_FILE,
            source_ref_id=str(case_file.id),
            source_generation=1,
            visibility_state=EvidenceGenerationState.BUILDING_INITIAL,
            parser_version="phase2-2b:v1",
            normalization_version="normalization:v1",
            batching_contract_version="ingest-batch:v1",
            configured_batch_size=10,
            ordering_contract="test:phase2-2b-order:v1",
            producer_version="phase2-2b:v1",
        )
        db.session.add(stored_generation)
        db.session.commit()
        project_generation_control_state(client, db.session, stored_generation)
        control_calls = [call for call in client.inserts if call["table"] != "events"]
        self.assertTrue(control_calls)
        self.assertEqual(control_calls[0]["table"], "visible_evidence_generations")
        self.assertIsNone(control_calls[0]["settings"])
        self.assertEqual(control_calls[0]["column_names"], list(VISIBLE_EVIDENCE_GENERATIONS_COLUMNS))
        db.session.remove()

    def test_identity_excludes_insertion_mode(self):
        generation, attempt = _generation_attempt()
        events = [_fixture_event(i, case_id=42, case_file_id=99) for i in range(4)]
        manifest = construct_managed_batch(
            generation=generation, attempt=attempt, events=tuple(events), batch_ordinal=2
        )
        expected_id = deterministic_ingest_batch_id(
            case_id=42,
            source_ref_type=SourceRefType.CASE_FILE,
            source_ref_id="99",
            source_generation=1,
            batch_ordinal=2,
            batching_contract_version="ingest-batch:v1",
        )
        self.assertEqual(manifest.ingest_batch_id, expected_id)
        self.assertEqual([row.ordinal for row in manifest.rows], list(range(4)))
        self.assertEqual(manifest.row_hashes, tuple(row.ingest_row_hash for row in manifest.rows))
        self.assertEqual(manifest.batch_content_hash, batch_content_hash(manifest.row_hashes))
        self.assertEqual(
            {event.evidence_record_key for event in events},
            {row.event.evidence_record_key for row in manifest.rows},
        )
        payload = inspect.getsource(ingest_row_hash)
        self.assertNotIn("async_insert", payload)
        self.assertNotIn("EVENT_INSERT_MODE", inspect.getsource(deterministic_ingest_batch_id))
        self.assertNotIn("async_insert", manifest.ingest_batch_id)
        self.assertNotIn("async_insert", manifest.batch_content_hash)
        for row in manifest.rows:
            self.assertNotIn("async_insert", row.ingest_row_hash)

    def test_batch_size_contract_unchanged(self):
        from config import Config
        from tasks.celery_tasks import (
            _process_managed_evtx_directory_group,
            _process_managed_initial_case_file,
        )

        self.assertEqual(BatchProcessor.DEFAULT_BATCH_SIZE, 10000)
        self.assertEqual(Config.PARSER_BATCH_SIZE, 10000)
        self.assertEqual(getattr(Config, "PHASE1B_MANIFEST_BATCH_SIZE", 10000), 10000)
        initial_src = inspect.getsource(_process_managed_initial_case_file)
        directory_src = inspect.getsource(_process_managed_evtx_directory_group)
        self.assertIn("PHASE1B_MANIFEST_BATCH_SIZE', 10000)", initial_src)
        self.assertIn("PHASE1B_MANIFEST_BATCH_SIZE', 10000)", directory_src)


class FailureSemanticsTests(unittest.TestCase):
    def setUp(self):
        install_memory_backend()
        self.app = Flask(__name__)
        self.app.config.update(
            SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            SECRET_KEY="phase2-2b-failure",
        )
        db.init_app(self.app)
        self.ctx = self.app.app_context()
        self.ctx.push()
        for table in (
            Case.__table__,
            CaseFile.__table__,
            EvidenceSourceGeneration.__table__,
            IngestAttempt.__table__,
            IngestBatch.__table__,
        ):
            table.create(db.engine, checkfirst=True)
        self.case = Case(uuid="p22b-fail", name="Fail", company="Example", created_by="tester")
        db.session.add(self.case)
        db.session.flush()
        self.case_file = CaseFile(
            case_uuid=self.case.uuid,
            filename="fixture.log",
            original_filename="fixture.log",
            file_path="/tmp/fixture.log",
            file_size=1,
            sha256_hash="b" * 64,
            uploaded_by="tester",
        )
        db.session.add(self.case_file)
        db.session.flush()
        self.generation = EvidenceSourceGeneration(
            case_id=self.case.id,
            source_ref_type=SourceRefType.CASE_FILE,
            source_ref_id=str(self.case_file.id),
            source_generation=1,
            visibility_state=EvidenceGenerationState.BUILDING_INITIAL,
            parser_version="phase2-2b:v1",
            normalization_version="normalization:v1",
            batching_contract_version="ingest-batch:v1",
            configured_batch_size=10,
            ordering_contract="test:phase2-2b-order:v1",
            producer_version="phase2-2b:v1",
        )
        db.session.add(self.generation)
        db.session.commit()
        self.attempt = IngestAttempt(
            ingest_attempt_id=str(uuid.uuid4()),
            generation_id=self.generation.id,
        )
        db.session.add(self.attempt)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()
        reset_fence_backend()

    def _manifest(self):
        events = [
            _fixture_event(i, case_id=self.case.id, case_file_id=self.case_file.id)
            for i in range(2)
        ]
        return construct_managed_batch(
            generation=self.generation,
            attempt=self.attempt,
            events=tuple(events),
            batch_ordinal=0,
        )

    def test_a_insert_raise_keeps_staged(self):
        manifest = self._manifest()
        batch = reserve_staged_batch(session=db.session, manifest=manifest)
        db.session.commit()
        client = _RecordingInsertClient(fail_insert=True)
        with self.assertRaises(RuntimeError):
            insert_managed_batch(client, manifest)
        db.session.refresh(batch)
        self.assertEqual(batch.state, IngestBatchState.STAGED)
        self.assertEqual(len(client.inserts), 1)

    def test_b_fence_unavailable_never_calls_insert(self):
        manifest = self._manifest()
        batch = reserve_staged_batch(session=db.session, manifest=manifest)
        db.session.commit()
        install_fence_backend(FailingFenceBackend())
        client = _RecordingInsertClient()
        with self.assertRaises(IngestFenceUnavailable):
            insert_managed_batch(client, manifest)
        self.assertEqual(client.inserts, [])
        db.session.refresh(batch)
        self.assertEqual(batch.state, IngestBatchState.STAGED)

    def test_c_verify_failure_does_not_mark_durable(self):
        manifest = self._manifest()
        batch = reserve_staged_batch(session=db.session, manifest=manifest)
        db.session.commit()
        client = _RecordingInsertClient(drop_rows_after_insert=True)
        insert_managed_batch(client, manifest)
        verification = verify_ingest_batch(client, manifest)
        self.assertFalse(verification.success)
        db.session.refresh(batch)
        self.assertEqual(batch.state, IngestBatchState.STAGED)
        self.assertNotEqual(verification.outcome, "exact")

    def test_d_retry_duplicate_identical_preserved(self):
        manifest = self._manifest()
        reserve_staged_batch(session=db.session, manifest=manifest)
        db.session.commit()
        client = _RecordingInsertClient()
        insert_managed_batch(client, manifest)
        insert_managed_batch(client, manifest)
        verification = verify_ingest_batch(client, manifest)
        self.assertEqual(verification.outcome, "duplicate_identical")
        self.assertTrue(verification.success)
        self.assertEqual(client.inserts[0]["settings"], EXPECTED_EVENT_INSERT_SETTINGS)
        self.assertEqual(client.inserts[1]["settings"], EXPECTED_EVENT_INSERT_SETTINGS)


class LiveSyncEventInsertTests(unittest.TestCase):
    """Server-observed SYNC proof using the production insert helper.

    Fails closed if ClickHouse is unreachable. Does not insert into
    production casescope.events.
    """

    @classmethod
    def setUpClass(cls):
        install_memory_backend()
        try:
            admin = _fresh_style_client("default")
            admin.query("SELECT 1")
        except Exception as exc:
            reset_fence_backend()
            raise AssertionError(
                f"live ClickHouse is required for Phase 2.2B and was unreachable: {exc}"
            ) from exc
        cls.database = f"cs_p22b_{uuid.uuid4().hex[:12]}"
        admin.command(f"CREATE DATABASE {cls.database}")
        admin.close()
        inner = _fresh_style_client(cls.database)
        inner.command(EVENTS_SCHEMA.replace("CREATE TABLE IF NOT EXISTS events", "CREATE TABLE IF NOT EXISTS events", 1))
        for ddl in clickhouse_control_table_ddl():
            inner.command(ddl)
        inner.command(
            "CREATE TABLE IF NOT EXISTS control_probe (k UInt32, v String) ENGINE = MergeTree ORDER BY k"
        )
        cls.inner = inner
        cls.client = _LiveRecordingClient(inner)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.inner.command(f"DROP DATABASE IF EXISTS {cls.database}")
        except Exception:
            pass
        try:
            cls.inner.close()
        except Exception:
            pass
        reset_fence_backend()

    def test_live_sync_event_insert_and_same_client_control_isolation(self):
        install_memory_backend()
        generation, attempt = _generation_attempt(case_id=9022, case_file_id=2202, batch_size=8)
        events = [_fixture_event(i, case_id=9022, case_file_id=2202) for i in range(8)]
        events[0].search_blob = "host P22BHOST powershell NTLM uniqueP22BToken row0"
        manifest = construct_managed_batch(
            generation=generation, attempt=attempt, events=tuple(events), batch_ordinal=0
        )
        insert_managed_batch(self.client, manifest)
        event_call = self.client.insert_calls[0]
        self.assertEqual(event_call["table"], "events")
        self.assertEqual(event_call["settings"], EXPECTED_EVENT_INSERT_SETTINGS)
        event_qid = event_call["query_id"]
        self.assertTrue(event_qid)

        counted = self.inner.query(
            "SELECT count(), uniqExact(evidence_record_key) FROM events"
        ).result_rows[0]
        self.assertEqual(int(counted[0]), 8)
        self.assertEqual(int(counted[1]), 8)
        identity = self.inner.query(
            """
            SELECT ingest_batch_id, ingest_row_ordinal, ingest_row_hash, evidence_record_key
            FROM events
            ORDER BY ingest_row_ordinal
            """
        )
        rows = identity.result_rows
        self.assertEqual([row[0] for row in rows], [manifest.ingest_batch_id] * 8)
        self.assertEqual([row[1] for row in rows], list(range(8)))
        self.assertEqual([row[2] for row in rows], list(manifest.row_hashes))
        self.assertEqual(
            [row[3] for row in rows],
            [event.evidence_record_key for event in events],
        )

        tokens = self.inner.query(
            "SELECT count() FROM events WHERE hasAllTokens(search_blob, {tok:String})",
            parameters={"tok": "uniqueP22BToken"},
        ).result_rows[0][0]
        self.assertEqual(int(tokens), 1)
        ntlm = self.inner.query(
            "SELECT count() FROM events WHERE search_blob LIKE {pat:String}",
            parameters={"pat": "%NTLM%"},
        ).result_rows[0][0]
        self.assertEqual(int(ntlm), 1)

        explain_text = "\n".join(
            str(row[0])
            for row in self.inner.query(
                "EXPLAIN indexes = 1 SELECT count() FROM events "
                "WHERE hasAllTokens(search_blob, 'uniqueP22BToken')"
            ).result_rows
        )
        self.assertTrue(
            "idx_search_blob_text" in explain_text or "text_index" in explain_text.lower(),
            msg=explain_text,
        )
        explain_like = "\n".join(
            str(row[0])
            for row in self.inner.query(
                "EXPLAIN indexes = 1 SELECT count() FROM events WHERE search_blob LIKE '%NTLM%'"
            ).result_rows
        )
        self.assertIn("idx_search_ngram", explain_like)

        parts = self.inner.query(
            """
            SELECT name, path, secondary_indices_compressed_bytes
            FROM system.parts
            WHERE database = currentDatabase() AND table = 'events' AND active
            """
        ).result_rows
        self.assertTrue(parts)
        text_ok = 0
        ngram_ok = 0
        for _name, path, compressed in parts:
            listed = False
            names = []
            try:
                names = list_part_files(path)
                listed = True
            except Exception:
                listed = False
            if listed and part_has_text_index_files(names):
                text_ok += 1
            elif int(compressed or 0) > 0:
                text_ok += 1
            if listed and NGRAM_SENTINEL in names:
                ngram_ok += 1
            elif int(compressed or 0) > 0:
                ngram_ok += 1
        self.assertEqual(text_ok, len(parts))
        self.assertEqual(ngram_ok, len(parts))

        control_summary = self.inner.insert(
            "control_probe",
            [(1, "isolation")],
            column_names=["k", "v"],
        )
        control_qid = _summary_query_id(control_summary)
        self.assertTrue(control_qid)

        self.inner.command("SYSTEM FLUSH LOGS")
        time.sleep(1.2)
        self.inner.command("SYSTEM FLUSH LOGS")

        event_ail = self.inner.query(
            """
            SELECT count()
            FROM system.asynchronous_insert_log
            WHERE query_id = {id:String}
            """,
            parameters={"id": event_qid},
        ).result_rows[0][0]
        self.assertEqual(int(event_ail), 0, msg=f"event INSERT {event_qid} entered asynchronous_insert_log")

        event_ql = self.inner.query(
            """
            SELECT
                query_id,
                Settings['async_insert'] AS async_insert,
                Settings['wait_for_async_insert'] AS wait_for_async_insert,
                Settings['materialize_skip_indexes_on_insert'] AS materialize_skip_indexes_on_insert
            FROM system.query_log
            WHERE query_id = {id:String}
              AND type = 'QueryFinish'
            ORDER BY event_time_microseconds DESC
            LIMIT 1
            """,
            parameters={"id": event_qid},
        ).result_rows
        if event_ql:
            self.assertIn(str(event_ql[0][1]), {"0", "false", "False"})
            self.assertIn(str(event_ql[0][3]), {"1", "true", "True", ""})

        type(self).live_proof = {
            "database": self.database,
            "event_query_id": event_qid,
            "control_query_id": control_qid,
            "event_async_insert_log_rows": int(event_ail),
            "event_query_log": event_ql[0] if event_ql else None,
            "explain_text": explain_text,
            "explain_like": explain_like,
        }


if __name__ == "__main__":
    unittest.main()
