from __future__ import annotations

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

os.environ.setdefault("SECRET_KEY", "phase1b-c3d2b-test-secret")

from parsers.kape_gap_parsers import WindowsSearchDbParser
from parsers.windows_artifact_parsers import EventTranscriptDbParser


CASE_ID = 92
CASE_FILE_ID = 906
SOURCE_HOST = "C3D2BHOST"
CASE_TZ = "America/New_York"
ATTEMPT_A = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
ATTEMPT_B = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"


def write_eventtranscript_fixture(root: Path) -> Path:
    db_path = root / "Users" / "analyst" / "AppData" / "Local" / "ConnectedDevicesPlatform" / "device" / "EventTranscript.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE ProviderEvents (
            EventId TEXT,
            Provider TEXT,
            EventTime TEXT,
            Message TEXT,
            Path TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE AppInteractions (
            EventDate TEXT,
            AppName TEXT,
            Uri TEXT,
            Payload TEXT
        )
        """
    )
    base_time = datetime(2024, 8, 15, 12, 0, 0)
    provider_rows = []
    for idx in range(1, 6):
        provider_rows.append(
            (
                f"provider-{idx}",
                "CaseScope.Provider",
                (base_time + timedelta(minutes=idx)).isoformat(),
                f"provider message {idx}",
                f"C:/Users/analyst/Documents/provider-{idx}.txt",
            )
        )
    app_rows = []
    for idx in range(1, 5):
        app_rows.append(
            (
                "" if idx == 4 else (base_time + timedelta(hours=1, minutes=idx)).isoformat(),
                "CaseScopeApp",
                f"case://eventtranscript/{idx}",
                json.dumps({"interaction": idx, "source": "generated-lab"}, sort_keys=True),
            )
        )
    conn.executemany(
        "INSERT INTO ProviderEvents (EventId, Provider, EventTime, Message, Path) VALUES (?, ?, ?, ?, ?)",
        provider_rows,
    )
    conn.executemany(
        "INSERT INTO AppInteractions (EventDate, AppName, Uri, Payload) VALUES (?, ?, ?, ?)",
        app_rows,
    )
    conn.commit()
    conn.close()
    return db_path


PROCESS_SNIPPET = r"""
import json
import sys
from types import SimpleNamespace

from parsers.windows_artifact_parsers import EventTranscriptDbParser
from utils.manifest_protocol import construct_managed_batches

path, attempt_id, batch_size = sys.argv[1:4]
parser = EventTranscriptDbParser(case_id=92, source_host='C3D2BHOST', case_file_id=906, case_tz='America/New_York')
parser.managed_manifest_mode = True
events = list(parser.parse(path))
for event in events:
    event.compute_utc_timestamp()
generation = SimpleNamespace(
    id=1,
    case_id=92,
    source_ref_type='CASE_FILE',
    source_ref_id='906',
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


class Phase1BTrancheC3D2BEventTranscriptTestCase(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(prefix="casescope-c3d2b-eventtranscript-")
        self.root = Path(self.tempdir.name)
        self.fixture_path = write_eventtranscript_fixture(self.root)

    def tearDown(self):
        self.tempdir.cleanup()

    def _run_process(self, attempt_id=ATTEMPT_A, hashseed="1", batch_size=3):
        env = {
            **os.environ,
            "SECRET_KEY": "phase1b-c3d2b-subprocess",
            "PYTHONHASHSEED": hashseed,
        }
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

    def test_c3d2b_capability_inventory(self):
        self.assertFalse(WindowsSearchDbParser.supports_manifest_protocol)
        self.assertIsNone(WindowsSearchDbParser.manifest_ordering_contract)
        self.assertTrue(EventTranscriptDbParser.supports_manifest_protocol)
        self.assertEqual(
            EventTranscriptDbParser.manifest_ordering_contract,
            "eventtranscript:sqlite-rootpage-rowid-order:v1",
        )

    def test_eventtranscript_independent_process_retry_and_missing_time_determinism(self):
        runs = [
            self._run_process(ATTEMPT_A, "1"),
            self._run_process(ATTEMPT_A, "7"),
            self._run_process(ATTEMPT_A, "random"),
        ]
        self.assertEqual([run["count"] for run in runs], [9, 9, 9])
        baseline = runs[0]
        for run in runs[1:]:
            self.assertEqual(run["event_rows"], baseline["event_rows"])
            self.assertEqual(run["locators"], baseline["locators"])
            self.assertEqual(run["batch_ids"], baseline["batch_ids"])
            self.assertEqual(run["batch_hashes"], baseline["batch_hashes"])
            self.assertEqual(run["row_hashes"], baseline["row_hashes"])
            self.assertEqual(run["batch_locators"], baseline["batch_locators"])
        self.assertEqual([len(batch) for batch in baseline["ordinals"]], [3, 3, 3])
        self.assertIn("missing_ts=epoch", baseline["producer_version"])

        retry = self._run_process(ATTEMPT_B, "random")
        self.assertNotEqual(retry["attempt_id"], baseline["attempt_id"])
        self.assertEqual(retry["event_rows"], baseline["event_rows"])
        self.assertEqual(retry["batch_ids"], baseline["batch_ids"])
        self.assertEqual(retry["batch_hashes"], baseline["batch_hashes"])
        self.assertEqual(retry["row_hashes"], baseline["row_hashes"])

    def test_eventtranscript_source_native_table_and_rowid_locator_sequence(self):
        parser = EventTranscriptDbParser(
            case_id=CASE_ID,
            source_host=SOURCE_HOST,
            case_file_id=CASE_FILE_ID,
            case_tz=CASE_TZ,
        )
        parser.managed_manifest_mode = True
        events = list(parser.parse(str(self.fixture_path)))
        locators = [event.source_record_identifier_value for event in events]
        self.assertEqual(len(locators), 9)
        self.assertTrue(all("table:ProviderEvents;" in locator for locator in locators[:5]))
        self.assertTrue(all("table:AppInteractions;" in locator for locator in locators[5:]))
        self.assertEqual([locator.rsplit("rowid:", 1)[1] for locator in locators[:5]], ["1", "2", "3", "4", "5"])
        self.assertEqual([locator.rsplit("rowid:", 1)[1] for locator in locators[5:]], ["1", "2", "3", "4"])

    def test_eventtranscript_managed_sidecars_fail_closed(self):
        Path(str(self.fixture_path) + "-wal").write_bytes(b"SQLite WAL placeholder")
        managed_parser = EventTranscriptDbParser(
            case_id=CASE_ID,
            source_host=SOURCE_HOST,
            case_file_id=CASE_FILE_ID,
            case_tz=CASE_TZ,
        )
        managed_parser.managed_manifest_mode = True
        with self.assertRaisesRegex(RuntimeError, "standalone SQLite source"):
            list(managed_parser.parse(str(self.fixture_path)))

    def test_eventtranscript_legacy_managed_semantic_parity(self):
        legacy_parser = EventTranscriptDbParser(
            case_id=CASE_ID,
            source_host=SOURCE_HOST,
            case_file_id=CASE_FILE_ID,
            case_tz=CASE_TZ,
        )
        legacy_rows = []
        for event in legacy_parser.parse(str(self.fixture_path)):
            event.compute_utc_timestamp()
            legacy_rows.append(list(event.to_clickhouse_row()))

        managed = self._run_process(ATTEMPT_A, "random")
        self.assertEqual(managed["event_rows"], json.loads(json.dumps(legacy_rows, default=str)))


PG_URL = os.environ.get("PHASE1B_PG_TEST_DATABASE_URL")
CH_DB = os.environ.get("PHASE1B_CH_TEST_DATABASE")


@unittest.skipUnless(PG_URL and CH_DB, "PHASE1B_PG_TEST_DATABASE_URL and PHASE1B_CH_TEST_DATABASE are required")
class Phase1BTrancheC3D2BEventTranscriptManagedIntegrationTestCase(unittest.TestCase):
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
        from models.database_flow import CaseCapabilitySourceState, EvidenceSourceGeneration, IngestAttempt, IngestBatch
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
            SECRET_KEY="phase1b-c3d2b-managed",
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
        cls.tempdir = tempfile.TemporaryDirectory(prefix="casescope-c3d2b-managed-")
        cls.fixture_path = write_eventtranscript_fixture(Path(cls.tempdir.name))

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
        self.pg_client = self.Client(name="C3D2B Managed", code=f"C3D2B{time.time_ns() % 100000}", created_by="tester")
        self.case = self.Case(uuid=f"c3d2b-case-{time.time_ns()}", name="C3D2B Case", company="Example", client=self.pg_client, created_by="tester")
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
        return EventTranscriptDbParser(
            case_id=self.case.id,
            source_host=SOURCE_HOST,
            case_file_id=self.case_file.id,
            case_tz=CASE_TZ,
        )

    def test_eventtranscript_real_managed_ingest_retry_and_batch_isolation(self):
        from models.database_flow import EvidenceGenerationState, IngestBatchState
        from tasks.celery_tasks import _process_managed_initial_case_file

        first = _process_managed_initial_case_file(
            parser=self._parser(),
            file_path=str(self.fixture_path),
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            clickhouse_client=self.client,
            task_id="c3d2b-first-eventtranscript",
        )
        self.assertTrue(first.success)
        self.assertEqual(first.events_count, 9)
        generation = self.db.session.query(self.EvidenceSourceGeneration).one()
        self.assertEqual(generation.visibility_state, EvidenceGenerationState.BUILDING_INITIAL)
        self.assertEqual(generation.ordering_contract, "eventtranscript:sqlite-rootpage-rowid-order:v1")
        self.assertIn("sqlite=standalone", generation.producer_version)
        batches = self.db.session.query(self.IngestBatch).order_by(self.IngestBatch.batch_ordinal).all()
        self.assertEqual([batch.row_count for batch in batches], [3, 3, 3])
        self.assertTrue(all(batch.state == IngestBatchState.DURABLE for batch in batches))
        first_batch_ids = [batch.ingest_batch_id for batch in batches]
        first_hashes = [batch.batch_content_hash for batch in batches]

        retry = _process_managed_initial_case_file(
            parser=self._parser(),
            file_path=str(self.fixture_path),
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            clickhouse_client=self.client,
            task_id="c3d2b-retry-eventtranscript",
        )
        self.assertTrue(retry.success)
        retry_batches = self.db.session.query(self.IngestBatch).order_by(self.IngestBatch.batch_ordinal).all()
        self.assertEqual([batch.ingest_batch_id for batch in retry_batches], first_batch_ids)
        self.assertEqual([batch.batch_content_hash for batch in retry_batches], first_hashes)
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
        self.assertEqual(
            self.db.session.get(self.EvidenceSourceGeneration, generation.id).visibility_state,
            EvidenceGenerationState.BUILDING_INITIAL,
        )

    def test_eventtranscript_partial_failure_retry_preserves_durable_batches(self):
        from tasks.celery_tasks import _process_managed_initial_case_file
        from utils.manifest_protocol import insert_managed_batch as real_insert

        calls = {"count": 0}

        def fail_second_insert(client, manifest):
            calls["count"] += 1
            if calls["count"] == 2:
                raise RuntimeError("injected c3d2b failure after first durable batch")
            return real_insert(client, manifest)

        with patch("utils.manifest_protocol.insert_managed_batch", side_effect=fail_second_insert):
            with self.assertRaises(RuntimeError):
                _process_managed_initial_case_file(
                    parser=self._parser(),
                    file_path=str(self.fixture_path),
                    case_id=self.case.id,
                    case_file_id=self.case_file.id,
                    clickhouse_client=self.client,
                    task_id="c3d2b-partial-eventtranscript",
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
            task_id="c3d2b-partial-retry-eventtranscript",
        )
        self.assertTrue(retry.success)
        batches = self.db.session.query(self.IngestBatch).order_by(self.IngestBatch.batch_ordinal).all()
        self.assertEqual(len(batches), 3)
        self.assertEqual(batches[0].ingest_batch_id, first_batch_id)
        self.assertTrue(all(batch.state == "DURABLE" for batch in batches))


if __name__ == "__main__":
    unittest.main()
