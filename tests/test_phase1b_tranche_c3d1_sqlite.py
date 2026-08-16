from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("SECRET_KEY", "phase1b-c3d1-test-secret")

from parsers.browser_parsers import BrowserSQLiteParser
from parsers.windows_parsers import ActivitiesCacheParser


CASE_ID = 91
CASE_FILE_ID = 905
SOURCE_HOST = "C3D1HOST"
CASE_TZ = "America/New_York"
ATTEMPT_A = "99999999-9999-4999-8999-999999999999"
ATTEMPT_B = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


def _filetime(value: datetime) -> int:
    return int((value - datetime(1601, 1, 1)).total_seconds() * 10_000_000)


def write_activities_cache_fixture(root: Path, *, reverse_insert: bool = False, row_count: int = 5) -> Path:
    db_path = root / "Users" / "analyst" / "AppData" / "Local" / "ConnectedDevicesPlatform" / "device" / "ActivitiesCache.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE Activity (
            Id TEXT PRIMARY KEY,
            AppId TEXT,
            PackageIdHash TEXT,
            AppActivityId TEXT,
            ActivityType INTEGER,
            ActivityStatus INTEGER,
            Priority INTEGER,
            IsLocalOnly INTEGER,
            ETag TEXT,
            CreatedInCloud INTEGER,
            StartTime INTEGER,
            EndTime INTEGER,
            LastModifiedTime INTEGER,
            ExpirationTime INTEGER,
            Payload TEXT,
            OriginalPayload TEXT,
            ClipboardPayload TEXT,
            PlatformDeviceId TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE ActivityOperation (
            OperationOrder INTEGER PRIMARY KEY,
            AppId TEXT,
            ActivityType INTEGER,
            CreatedTime INTEGER,
            EndTime INTEGER,
            LastModifiedTime INTEGER,
            OperationType TEXT,
            Payload TEXT,
            ClipboardPayload TEXT
        )
        """
    )

    base_time = datetime(2024, 7, 14, 12, 0, 0)
    activity_rows = []
    for idx in range(1, row_count + 1):
        payload = {
            "displayText": f"Document {idx}",
            "description": f"CaseScope activity {idx}",
            "contentUri": f"file:///C:/Users/analyst/Documents/doc{idx}.txt",
            "appDisplayName": "CaseScope Viewer",
        }
        clipboard = [
            {
                "formatName": "Text",
                "content": base64.b64encode(f"clipboard-{idx}".encode("utf-16-le")).decode("ascii"),
            }
        ]
        start = _filetime(base_time + timedelta(minutes=idx))
        activity_rows.append(
            (
                f"A{idx:03d}",
                "viewer.exe",
                f"pkg{idx}",
                f"activity/{idx}",
                10 if idx % 2 else 5,
                1,
                idx,
                0,
                f"etag-{idx}",
                0,
                start,
                start + 10_000_000,
                start + 20_000_000,
                start + 30_000_000,
                json.dumps(payload, sort_keys=True),
                json.dumps({"original": idx}, sort_keys=True),
                json.dumps(clipboard, sort_keys=True),
                "device-1",
            )
        )

    operation_rows = []
    for idx in range(1, 5):
        created = _filetime(base_time + timedelta(hours=1, minutes=idx))
        operation_rows.append(
            (
                idx,
                "clip.exe",
                10,
                created,
                created + 10_000_000,
                created + 20_000_000,
                "copy",
                json.dumps({"operation": idx}, sort_keys=True),
                json.dumps({"clip": idx}, sort_keys=True),
            )
        )

    if reverse_insert:
        activity_rows = list(reversed(activity_rows))
        operation_rows = list(reversed(operation_rows))

    conn.executemany(
        """
        INSERT INTO Activity (
            Id, AppId, PackageIdHash, AppActivityId, ActivityType, ActivityStatus,
            Priority, IsLocalOnly, ETag, CreatedInCloud, StartTime, EndTime,
            LastModifiedTime, ExpirationTime, Payload, OriginalPayload,
            ClipboardPayload, PlatformDeviceId
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        activity_rows,
    )
    conn.executemany(
        """
        INSERT INTO ActivityOperation (
            OperationOrder, AppId, ActivityType, CreatedTime, EndTime,
            LastModifiedTime, OperationType, Payload, ClipboardPayload
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        operation_rows,
    )
    conn.commit()
    conn.close()
    return db_path


PROCESS_SNIPPET = r"""
import json
import sys
from types import SimpleNamespace

from parsers.windows_parsers import ActivitiesCacheParser
from utils.manifest_protocol import construct_managed_batches

path, attempt_id, batch_size = sys.argv[1:4]
parser = ActivitiesCacheParser(case_id=91, source_host='C3D1HOST', case_file_id=905, case_tz='America/New_York')
parser.managed_manifest_mode = True
events = list(parser.parse(path))
for event in events:
    event.compute_utc_timestamp()
generation = SimpleNamespace(
    id=1,
    case_id=91,
    source_ref_type='CASE_FILE',
    source_ref_id='905',
    source_generation=1,
    configured_batch_size=int(batch_size),
    batching_contract_version='ingest-batch:v1',
)
attempt = SimpleNamespace(ingest_attempt_id=attempt_id)
batches = construct_managed_batches(generation=generation, attempt=attempt, events=events)
payload = {
    'count': len(events),
    'errors': list(parser.errors),
    'warnings': list(parser.warnings),
    'event_rows': [list(event.to_clickhouse_row()) for event in events],
    'locators': [event.source_record_identifier_value for event in events],
    'batch_ids': [batch.ingest_batch_id for batch in batches],
    'batch_hashes': [batch.batch_content_hash for batch in batches],
    'row_hashes': [list(batch.row_hashes) for batch in batches],
    'batch_locators': [[batch.first_source_locator, batch.last_source_locator] for batch in batches],
    'ordinals': [[row.ordinal for row in batch.rows] for batch in batches],
    'attempt_id': attempt_id,
    'producer_version': parser.manifest_producer_version(),
}
print(json.dumps(payload, default=str, sort_keys=True))
"""


class Phase1BTrancheC3D1ActivitiesCacheTestCase(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(prefix="casescope-c3d1-activities-")
        self.root = Path(self.tempdir.name)
        self.fixture_path = write_activities_cache_fixture(self.root)

    def tearDown(self):
        self.tempdir.cleanup()

    def _run_process(self, attempt_id=ATTEMPT_A, hashseed="1", batch_size=3, tmp_parent: Path | None = None):
        env = {
            **os.environ,
            "SECRET_KEY": "phase1b-c3d1-subprocess",
            "PYTHONHASHSEED": hashseed,
        }
        if tmp_parent is not None:
            tmp_parent.mkdir(parents=True, exist_ok=True)
            env["TMPDIR"] = str(tmp_parent)
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                PROCESS_SNIPPET,
                str(self.fixture_path),
                attempt_id,
                str(batch_size),
            ],
            cwd="/opt/casescope",
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        return json.loads(result.stdout)

    def test_c3d1_capability_inventory(self):
        self.assertTrue(ActivitiesCacheParser.supports_manifest_protocol)
        self.assertEqual(
            ActivitiesCacheParser.manifest_ordering_contract,
            "activities-cache:activity-id-then-operation-order:v1",
        )
        self.assertFalse(BrowserSQLiteParser.supports_manifest_protocol)
        self.assertIsNone(BrowserSQLiteParser.manifest_ordering_contract)

    def test_activities_cache_independent_process_retry_and_temp_path_determinism(self):
        runs = [
            self._run_process(ATTEMPT_A, "1", tmp_parent=self.root / "tmp-one"),
            self._run_process(ATTEMPT_A, "7", tmp_parent=self.root / "tmp-two"),
            self._run_process(ATTEMPT_A, "random", tmp_parent=self.root / "tmp-three"),
        ]
        self.assertEqual([run["count"] for run in runs], [9, 9, 9])
        baseline = runs[0]
        self.assertEqual(
            baseline["locators"],
            [
                "Activity:A001",
                "Activity:A002",
                "Activity:A003",
                "Activity:A004",
                "Activity:A005",
                "ActivityOperation:1",
                "ActivityOperation:2",
                "ActivityOperation:3",
                "ActivityOperation:4",
            ],
        )
        self.assertEqual(baseline["ordinals"], [[0, 1, 2], [0, 1, 2], [0, 1, 2]])
        self.assertIn("sqlite_companions=absent", baseline["producer_version"])

        for run in runs[1:]:
            self.assertEqual(run["event_rows"], baseline["event_rows"])
            self.assertEqual(run["batch_ids"], baseline["batch_ids"])
            self.assertEqual(run["row_hashes"], baseline["row_hashes"])
            self.assertEqual(run["batch_hashes"], baseline["batch_hashes"])
            self.assertEqual(run["batch_locators"], baseline["batch_locators"])

        retry = self._run_process(ATTEMPT_B, "7")
        self.assertNotEqual(baseline["attempt_id"], retry["attempt_id"])
        self.assertEqual(retry["event_rows"], baseline["event_rows"])
        self.assertEqual(retry["batch_ids"], baseline["batch_ids"])
        self.assertEqual(retry["row_hashes"], baseline["row_hashes"])
        self.assertEqual(retry["batch_hashes"], baseline["batch_hashes"])
        self.assertEqual(retry["batch_locators"], baseline["batch_locators"])

    def test_activities_cache_insertion_order_does_not_define_output_order(self):
        with tempfile.TemporaryDirectory(prefix="casescope-c3d1-layout-") as other_tmp:
            other_path = write_activities_cache_fixture(Path(other_tmp), reverse_insert=True)
            parser_a = ActivitiesCacheParser(case_id=CASE_ID, source_host=SOURCE_HOST, case_file_id=CASE_FILE_ID, case_tz=CASE_TZ)
            parser_b = ActivitiesCacheParser(case_id=CASE_ID, source_host=SOURCE_HOST, case_file_id=CASE_FILE_ID, case_tz=CASE_TZ)
            parser_a.managed_manifest_mode = True
            parser_b.managed_manifest_mode = True
            events_a = list(parser_a.parse(str(self.fixture_path)))
            events_b = list(parser_b.parse(str(other_path)))

        self.assertEqual(
            [event.source_record_identifier_value for event in events_a],
            [event.source_record_identifier_value for event in events_b],
        )

    def test_activities_cache_managed_sidecars_fail_closed_legacy_still_parses(self):
        sidecar_path = str(self.fixture_path) + "-wal"
        Path(sidecar_path).write_bytes(b"SQLite WAL placeholder")

        legacy_parser = ActivitiesCacheParser(case_id=CASE_ID, source_host=SOURCE_HOST, case_file_id=CASE_FILE_ID, case_tz=CASE_TZ)
        self.assertEqual(len(list(legacy_parser.parse(str(self.fixture_path)))), 9)

        managed_parser = ActivitiesCacheParser(case_id=CASE_ID, source_host=SOURCE_HOST, case_file_id=CASE_FILE_ID, case_tz=CASE_TZ)
        managed_parser.managed_manifest_mode = True
        with self.assertRaisesRegex(RuntimeError, "standalone SQLite source"):
            list(managed_parser.parse(str(self.fixture_path)))

    def test_activities_cache_legacy_managed_semantic_parity(self):
        legacy_parser = ActivitiesCacheParser(case_id=CASE_ID, source_host=SOURCE_HOST, case_file_id=CASE_FILE_ID, case_tz=CASE_TZ)
        legacy_rows = []
        for event in legacy_parser.parse(str(self.fixture_path)):
            event.compute_utc_timestamp()
            legacy_rows.append(list(event.to_clickhouse_row()))

        managed = self._run_process(ATTEMPT_A, "random")
        self.assertEqual(managed["event_rows"], json.loads(json.dumps(legacy_rows, default=str)))


PG_URL = os.environ.get("PHASE1B_PG_TEST_DATABASE_URL")
CH_DB = os.environ.get("PHASE1B_CH_TEST_DATABASE")


@unittest.skipUnless(PG_URL and CH_DB, "PHASE1B_PG_TEST_DATABASE_URL and PHASE1B_CH_TEST_DATABASE are required")
class Phase1BTrancheC3D1ActivitiesManagedIntegrationTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import clickhouse_connect
        from flask import Flask
        from sqlalchemy import text

        from config import Config
        from migrations.add_events_table import EVENTS_COLUMN_DEFINITIONS
        from migrations.add_phase1b_tranche_b_manifest_protocol import clickhouse_control_table_ddl
        from models.case import Case
        from models.case_file import CaseFile
        from models.client import Client
        from models.database import db
        from models.database_flow import CaseCapabilitySourceState, EvidenceGenerationAudit, EvidenceSourceGeneration, IngestAttempt, IngestBatch
        from utils.ingest_fence import install_memory_backend

        cls.Config = Config
        cls.Case = Case
        cls.CaseFile = CaseFile
        cls.Client = Client
        cls.db = db
        cls.EvidenceSourceGeneration = EvidenceSourceGeneration
        cls.IngestAttempt = IngestAttempt
        cls.IngestBatch = IngestBatch
        install_memory_backend()
        cls._old_flag = getattr(Config, "PHASE1B_MANIFEST_PROTOCOL_ENABLED", False)
        cls._old_batch_size = getattr(Config, "PHASE1B_MANIFEST_BATCH_SIZE", None)
        Config.PHASE1B_MANIFEST_PROTOCOL_ENABLED = True
        Config.PHASE1B_MANIFEST_BATCH_SIZE = 3
        cls.app = Flask(__name__)
        cls.app.config.update(
            SQLALCHEMY_DATABASE_URI=PG_URL,
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            SECRET_KEY="phase1b-c3d1-managed",
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
        for ddl in clickhouse_control_table_ddl():
            cls.client.command(ddl)
        cls._app_patch = patch("tasks.celery_tasks.get_flask_app", return_value=cls.app)
        cls._app_patch.start()
        cls.tempdir = tempfile.TemporaryDirectory(prefix="casescope-c3d1-managed-")
        cls.fixture_path = write_activities_cache_fixture(Path(cls.tempdir.name))

    @classmethod
    def tearDownClass(cls):
        from config import Config
        from sqlalchemy import text
        from utils.ingest_fence import reset_fence_backend

        cls.tempdir.cleanup()
        cls.client.command("DROP TABLE IF EXISTS events")
        cls.client.command("DROP TABLE IF EXISTS visible_evidence_generations")
        cls.client.command("DROP TABLE IF EXISTS durable_ingest_batches")
        cls.client.close()
        cls.db.session.remove()
        with cls.db.engine.begin() as conn:
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

    def setUp(self):
        from models.case_file import IngestProtocolOrigin

        self.client.command("TRUNCATE TABLE events")
        self.client.command("TRUNCATE TABLE visible_evidence_generations")
        self.client.command("TRUNCATE TABLE durable_ingest_batches")
        self.db.session.query(self.IngestBatch).delete()
        self.db.session.query(self.IngestAttempt).delete()
        self.db.session.query(self.EvidenceSourceGeneration).delete()
        self.db.session.query(self.CaseFile).delete()
        self.db.session.query(self.Case).delete()
        self.db.session.query(self.Client).delete()
        self.db.session.commit()
        self.pg_client = self.Client(name="C3D1 Managed", code=f"C3D1{time.time_ns() % 100000}", created_by="tester")
        self.case = self.Case(uuid=f"c3d1-case-{time.time_ns()}", name="C3D1 Case", company="Example", client=self.pg_client, created_by="tester")
        digest = hashlib.sha256(self.fixture_path.read_bytes()).hexdigest()
        self.case_file = self.CaseFile(
            case_uuid=self.case.uuid,
            filename=self.fixture_path.name,
            original_filename=self.fixture_path.name,
            file_path=str(self.fixture_path),
            file_size=self.fixture_path.stat().st_size,
            sha256_hash=digest,
            uploaded_by="tester",
            ingest_protocol_origin=IngestProtocolOrigin.NOT_STARTED,
        )
        self.db.session.add_all([self.pg_client, self.case, self.case_file])
        self.db.session.commit()

    def _parser(self):
        return ActivitiesCacheParser(
            case_id=self.case.id,
            source_host=SOURCE_HOST,
            case_file_id=self.case_file.id,
            case_tz=CASE_TZ,
        )

    def test_activities_cache_real_managed_ingest_retry_and_batch_isolation(self):
        from models.database_flow import EvidenceGenerationState, IngestBatchState
        from tasks.celery_tasks import _process_managed_initial_case_file

        first = _process_managed_initial_case_file(
            parser=self._parser(),
            file_path=str(self.fixture_path),
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            clickhouse_client=self.client,
            task_id="c3d1-first-activities",
        )
        self.assertTrue(first.success)
        self.assertEqual(first.events_count, 9)
        generation = self.db.session.query(self.EvidenceSourceGeneration).one()
        self.assertEqual(generation.visibility_state, EvidenceGenerationState.ACTIVE)
        self.assertEqual(generation.ordering_contract, "activities-cache:activity-id-then-operation-order:v1")
        self.assertIn("sqlite_companions=absent", generation.producer_version)
        batches = self.db.session.query(self.IngestBatch).order_by(self.IngestBatch.batch_ordinal).all()
        self.assertEqual([batch.row_count for batch in batches], [3, 3, 3])
        self.assertTrue(all(batch.state == IngestBatchState.DURABLE for batch in batches))
        first_batch_ids = [batch.ingest_batch_id for batch in batches]

        retry = _process_managed_initial_case_file(
            parser=self._parser(),
            file_path=str(self.fixture_path),
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            clickhouse_client=self.client,
            task_id="c3d1-retry-activities",
        )
        self.assertTrue(retry.success)
        retry_batches = self.db.session.query(self.IngestBatch).order_by(self.IngestBatch.generation_id, self.IngestBatch.batch_ordinal).all()
        self.assertEqual(len(retry_batches), 6)
        second_batch_ids = [batch.ingest_batch_id for batch in retry_batches[3:]]
        self.assertNotEqual(second_batch_ids, first_batch_ids)
        max_sources = self.client.query("""
            SELECT max(source_count)
            FROM (
                SELECT ingest_batch_id, countDistinct(case_file_id) AS source_count
                FROM events
                WHERE case_id = {case_id:UInt32}
                GROUP BY ingest_batch_id
            )
        """, parameters={"case_id": int(self.case.id)}).result_rows[0][0]
        self.assertEqual(max_sources, 1)
        self.db.session.expire_all()
        generations = self.db.session.query(self.EvidenceSourceGeneration).order_by(self.EvidenceSourceGeneration.source_generation).all()
        self.assertEqual([row.visibility_state for row in generations], [
            EvidenceGenerationState.SUPERSEDED,
            EvidenceGenerationState.ACTIVE,
        ])

    def test_activities_cache_partial_failure_retry_preserves_durable_batches(self):
        from tasks.celery_tasks import _process_managed_initial_case_file
        from utils.manifest_protocol import insert_managed_batch as real_insert

        calls = {"count": 0}

        def fail_second_insert(client, manifest):
            calls["count"] += 1
            if calls["count"] == 2:
                raise RuntimeError("injected c3d1 failure after first durable batch")
            return real_insert(client, manifest)

        with patch("utils.manifest_protocol.insert_managed_batch", side_effect=fail_second_insert):
            with self.assertRaises(RuntimeError):
                _process_managed_initial_case_file(
                    parser=self._parser(),
                    file_path=str(self.fixture_path),
                    case_id=self.case.id,
                    case_file_id=self.case_file.id,
                    clickhouse_client=self.client,
                    task_id="c3d1-partial-activities",
                )

        durable_before = self.db.session.query(self.IngestBatch).filter_by(state="DURABLE").all()
        self.assertEqual(len(durable_before), 1)
        first_batch_id = durable_before[0].ingest_batch_id

        retry = _process_managed_initial_case_file(
            parser=self._parser(),
            file_path=str(self.fixture_path),
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            clickhouse_client=self.client,
            task_id="c3d1-partial-retry-activities",
        )
        self.assertTrue(retry.success)
        batches = self.db.session.query(self.IngestBatch).order_by(self.IngestBatch.batch_ordinal).all()
        self.assertEqual(len(batches), 3)
        self.assertEqual(batches[0].ingest_batch_id, first_batch_id)
        self.assertTrue(all(batch.state == "DURABLE" for batch in batches))


if __name__ == "__main__":
    unittest.main()
