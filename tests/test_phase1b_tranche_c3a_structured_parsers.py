from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("SECRET_KEY", "phase1b-c3a-test-secret")

from parsers.browser_parsers import FirefoxJSONLZ4Parser
from parsers.dissect_parsers import LnkParser, PrefetchParser
from parsers.windows_parsers import ScheduledTaskParser


CASE_ID = 88
CASE_FILE_ID = 902
SOURCE_HOST = "C3AHOST"
CASE_TZ = "America/New_York"
ATTEMPT_A = "33333333-3333-4333-8333-333333333333"
ATTEMPT_B = "44444444-4444-4444-8444-444444444444"


CERTIFIED_C3A_CANDIDATES = {
    "ScheduledTaskParser": {
        "class": ScheduledTaskParser,
        "module": "parsers.windows_parsers",
        "contract": "scheduled-task:single-xml-document:v1",
        "locator": "authoritative scheduled task URI when present; deterministic ordinal fallback otherwise",
    },
}


PROCESS_SNIPPET = r"""
import importlib
import json
import sys
from types import SimpleNamespace

from utils.manifest_protocol import construct_managed_batches

module_name, class_name, path, attempt_id, batch_size = sys.argv[1:6]
parser_cls = getattr(importlib.import_module(module_name), class_name)
parser = parser_cls(case_id=88, source_host='C3AHOST', case_file_id=902, case_tz='America/New_York')
events = list(parser.parse(path))
for event in events:
    event.compute_utc_timestamp()
generation = SimpleNamespace(
    id=1,
    case_id=88,
    source_ref_type='CASE_FILE',
    source_ref_id='902',
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
    'batch_ids': [batch.ingest_batch_id for batch in batches],
    'batch_hashes': [batch.batch_content_hash for batch in batches],
    'row_hashes': [list(batch.row_hashes) for batch in batches],
    'locators': [[batch.first_source_locator, batch.last_source_locator] for batch in batches],
    'ordinals': [[row.ordinal for row in batch.rows] for batch in batches],
    'attempt_id': attempt_id,
}
print(json.dumps(payload, default=str, sort_keys=True))
"""


def write_scheduled_task_fixture(root: Path) -> Path:
    tasks_dir = root / "C" / "Windows" / "System32" / "Tasks" / "CaseScope"
    tasks_dir.mkdir(parents=True, exist_ok=True)
    path = tasks_dir / "C3A-MultiAction"
    body = textwrap.dedent("""\
        <?xml version="1.0" encoding="UTF-16"?>
        <Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
          <RegistrationInfo>
            <Date>2026-01-01T00:00:00</Date>
            <Author>ACME\\Analyst</Author>
            <Description>C3A generated valid scheduled task fixture</Description>
            <URI>\\CaseScope\\C3A-MultiAction</URI>
          </RegistrationInfo>
          <Triggers>
            <BootTrigger>
              <Enabled>true</Enabled>
              <Delay>PT30S</Delay>
            </BootTrigger>
            <CalendarTrigger>
              <StartBoundary>2026-01-01T00:05:00</StartBoundary>
              <Enabled>true</Enabled>
              <ScheduleByDay>
                <DaysInterval>1</DaysInterval>
              </ScheduleByDay>
            </CalendarTrigger>
          </Triggers>
          <Principals>
            <Principal id="Author">
              <UserId>S-1-5-18</UserId>
              <RunLevel>HighestAvailable</RunLevel>
              <LogonType>ServiceAccount</LogonType>
            </Principal>
          </Principals>
          <Settings>
            <Enabled>true</Enabled>
            <Hidden>false</Hidden>
          </Settings>
          <Actions Context="Author">
            <Exec>
              <Command>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Command>
              <Arguments>-NoProfile -ExecutionPolicy Bypass -File C:\\ProgramData\\CaseScope\\task.ps1</Arguments>
              <WorkingDirectory>C:\\ProgramData\\CaseScope</WorkingDirectory>
            </Exec>
            <Exec>
              <Command>C:\\Windows\\System32\\cmd.exe</Command>
              <Arguments>/c echo second action</Arguments>
            </Exec>
          </Actions>
        </Task>
    """)
    path.write_text(body, encoding="utf-16")
    return path


class Phase1BTrancheC3ADeterminismTestCase(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(prefix="casescope-c3a-fixtures-")
        self.root = Path(self.tempdir.name)
        self.fixtures = {"ScheduledTaskParser": write_scheduled_task_fixture(self.root)}

    def tearDown(self):
        self.tempdir.cleanup()

    def _run_process(self, class_name, path, attempt_id=ATTEMPT_A, hashseed="1", batch_size=1):
        candidate = CERTIFIED_C3A_CANDIDATES[class_name]
        env = {
            **os.environ,
            "SECRET_KEY": "phase1b-c3a-subprocess",
            "PYTHONHASHSEED": hashseed,
        }
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                PROCESS_SNIPPET,
                candidate["module"],
                class_name,
                str(path),
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

    def test_c3a_capability_inventory(self):
        self.assertTrue(ScheduledTaskParser.supports_manifest_protocol)
        self.assertEqual(
            ScheduledTaskParser.manifest_ordering_contract,
            "scheduled-task:single-xml-document:v1",
        )
        self.assertFalse(PrefetchParser.supports_manifest_protocol)
        self.assertIsNone(PrefetchParser.manifest_ordering_contract)
        self.assertFalse(LnkParser.supports_manifest_protocol)
        self.assertIsNone(LnkParser.manifest_ordering_contract)
        self.assertFalse(FirefoxJSONLZ4Parser.supports_manifest_protocol)
        self.assertIsNone(FirefoxJSONLZ4Parser.manifest_ordering_contract)

    def test_scheduled_task_independent_process_retry_determinism(self):
        path = self.fixtures["ScheduledTaskParser"]
        runs = [
            self._run_process("ScheduledTaskParser", path, ATTEMPT_A, "1"),
            self._run_process("ScheduledTaskParser", path, ATTEMPT_A, "7"),
            self._run_process("ScheduledTaskParser", path, ATTEMPT_A, "random"),
        ]
        self.assertEqual([run["count"] for run in runs], [1, 1, 1])
        self.assertTrue(all(not run["errors"] for run in runs), runs)
        baseline = runs[0]
        for run in runs[1:]:
            self.assertEqual(run["event_rows"], baseline["event_rows"])
            self.assertEqual(run["batch_ids"], baseline["batch_ids"])
            self.assertEqual(run["row_hashes"], baseline["row_hashes"])
            self.assertEqual(run["batch_hashes"], baseline["batch_hashes"])
            self.assertEqual(run["locators"], baseline["locators"])
            self.assertEqual(run["ordinals"], [[0]])

        retry = self._run_process("ScheduledTaskParser", path, ATTEMPT_B, "7")
        self.assertNotEqual(baseline["attempt_id"], retry["attempt_id"])
        self.assertEqual(retry["event_rows"], baseline["event_rows"])
        self.assertEqual(retry["batch_ids"], baseline["batch_ids"])
        self.assertEqual(retry["row_hashes"], baseline["row_hashes"])
        self.assertEqual(retry["batch_hashes"], baseline["batch_hashes"])
        self.assertEqual(retry["locators"], baseline["locators"])

        self.assertEqual(
            baseline["locators"],
            [[
                {"type": "parser_source_id", "value": "\\CaseScope\\C3A-MultiAction"},
                {"type": "parser_source_id", "value": "\\CaseScope\\C3A-MultiAction"},
            ]],
        )

    def test_scheduled_task_legacy_managed_semantic_parity(self):
        path = self.fixtures["ScheduledTaskParser"]
        baseline = self._run_process("ScheduledTaskParser", path, ATTEMPT_A, "1")
        retry = self._run_process("ScheduledTaskParser", path, ATTEMPT_B, "random")
        self.assertEqual(baseline["event_rows"], retry["event_rows"])
        self.assertEqual(baseline["count"], retry["count"])

    def test_scheduled_task_single_event_batching_is_naturally_bounded(self):
        path = self.fixtures["ScheduledTaskParser"]
        one_event = self._run_process("ScheduledTaskParser", path, ATTEMPT_A, "1", batch_size=1)
        large_batch = self._run_process("ScheduledTaskParser", path, ATTEMPT_A, "1", batch_size=10000)
        self.assertEqual(one_event["count"], 1)
        self.assertEqual(len(one_event["batch_ids"]), 1)
        self.assertEqual(large_batch["count"], 1)
        self.assertEqual(len(large_batch["batch_ids"]), 1)


PG_URL = os.environ.get("PHASE1B_PG_TEST_DATABASE_URL")
CH_DB = os.environ.get("PHASE1B_CH_TEST_DATABASE")


@unittest.skipUnless(PG_URL and CH_DB, "PHASE1B_PG_TEST_DATABASE_URL and PHASE1B_CH_TEST_DATABASE are required")
class Phase1BTrancheC3AManagedIntegrationTestCase(unittest.TestCase):
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
        Config.PHASE1B_MANIFEST_BATCH_SIZE = 1
        cls.app = Flask(__name__)
        cls.app.config.update(
            SQLALCHEMY_DATABASE_URI=PG_URL,
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            SECRET_KEY="phase1b-c3a-managed",
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
        cls.tempdir = tempfile.TemporaryDirectory(prefix="casescope-c3a-managed-")
        cls.fixture_path = write_scheduled_task_fixture(Path(cls.tempdir.name))

    @classmethod
    def tearDownClass(cls):
        from config import Config
        from utils.ingest_fence import reset_fence_backend

        cls.tempdir.cleanup()
        cls.client.command("DROP TABLE IF EXISTS events")
        cls.client.command("DROP TABLE IF EXISTS visible_evidence_generations")
        cls.client.command("DROP TABLE IF EXISTS durable_ingest_batches")
        cls.client.close()
        cls.db.session.remove()
        with cls.db.engine.begin() as conn:
            from sqlalchemy import text
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
        self.pg_client = self.Client(name="C3A Managed", code=f"C3A{time.time_ns() % 100000}", created_by="tester")
        self.case = self.Case(uuid=f"c3a-case-{time.time_ns()}", name="C3A Case", company="Example", client=self.pg_client, created_by="tester")
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

    def test_scheduled_task_real_managed_ingest_and_retry(self):
        from models.case_file import IngestProtocolOrigin
        from models.database_flow import EvidenceGenerationState, IngestBatchState
        from tasks.celery_tasks import _process_managed_initial_case_file

        parser = ScheduledTaskParser(
            case_id=self.case.id,
            source_host=SOURCE_HOST,
            case_file_id=self.case_file.id,
            case_tz=CASE_TZ,
        )
        first = _process_managed_initial_case_file(
            parser=parser,
            file_path=str(self.fixture_path),
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            clickhouse_client=self.client,
            task_id="c3a-first-scheduled-task",
        )
        self.assertTrue(first.success)
        self.assertEqual(first.events_count, 1)
        generation = self.db.session.query(self.EvidenceSourceGeneration).one()
        self.assertEqual(generation.visibility_state, EvidenceGenerationState.BUILDING_INITIAL)
        self.assertEqual(generation.ordering_contract, "scheduled-task:single-xml-document:v1")
        batches = self.db.session.query(self.IngestBatch).order_by(self.IngestBatch.batch_ordinal).all()
        self.assertEqual(len(batches), 1)
        self.assertTrue(all(batch.state == IngestBatchState.DURABLE for batch in batches))
        first_batch_ids = [batch.ingest_batch_id for batch in batches]
        first_row_hashes = [list(batch.expected_ingest_row_hashes) for batch in batches]
        first_batch_hashes = [batch.batch_content_hash for batch in batches]

        retry_parser = ScheduledTaskParser(
            case_id=self.case.id,
            source_host=SOURCE_HOST,
            case_file_id=self.case_file.id,
            case_tz=CASE_TZ,
        )
        retry = _process_managed_initial_case_file(
            parser=retry_parser,
            file_path=str(self.fixture_path),
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            clickhouse_client=self.client,
            task_id="c3a-retry-scheduled-task",
        )
        self.assertTrue(retry.success)
        attempts = self.db.session.query(self.IngestAttempt).order_by(self.IngestAttempt.id).all()
        self.assertEqual(len(attempts), 2)
        self.assertNotEqual(attempts[0].ingest_attempt_id, attempts[1].ingest_attempt_id)
        retry_batches = self.db.session.query(self.IngestBatch).order_by(self.IngestBatch.batch_ordinal).all()
        self.assertEqual([batch.ingest_batch_id for batch in retry_batches], first_batch_ids)
        self.assertEqual([list(batch.expected_ingest_row_hashes) for batch in retry_batches], first_row_hashes)
        self.assertEqual([batch.batch_content_hash for batch in retry_batches], first_batch_hashes)
        self.db.session.expire_all()
        self.assertEqual(
            self.db.session.get(self.CaseFile, self.case_file.id).ingest_protocol_origin,
            IngestProtocolOrigin.MANIFEST_INITIAL,
        )
        self.assertEqual(
            self.db.session.get(self.EvidenceSourceGeneration, generation.id).visibility_state,
            EvidenceGenerationState.BUILDING_INITIAL,
        )
        physical_rows = self.client.query("SELECT count() FROM events").result_rows[0][0]
        self.assertEqual(physical_rows, 2)


if __name__ == "__main__":
    unittest.main()
