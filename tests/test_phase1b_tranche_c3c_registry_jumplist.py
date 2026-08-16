from __future__ import annotations

import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("SECRET_KEY", "phase1b-c3c-test-secret")

from parsers.dissect_parsers import JumpListParser, RegistryParser
from parsers.windows_artifact_parsers import RegistryPolParser


CASE_ID = 90
CASE_FILE_ID = 904
SOURCE_HOST = "C3CHOST"
CASE_TZ = "America/New_York"
ATTEMPT_A = "77777777-7777-4777-8777-777777777777"
ATTEMPT_B = "88888888-8888-4888-8888-888888888888"

REG_SZ = 1
REG_BINARY = 3
REG_DWORD = 4
REG_MULTI_SZ = 7
REG_QWORD = 11


def _utf16z(value: str) -> bytes:
    return value.encode("utf-16-le") + b"\x00\x00"


def _pol_record(key: str, value: str, value_type: int, data: bytes) -> bytes:
    return (
        b"[\x00"
        + _utf16z(key)
        + b";\x00"
        + _utf16z(value)
        + b";\x00"
        + struct.pack("<I", value_type)
        + b";\x00"
        + struct.pack("<I", len(data))
        + b";\x00"
        + data
        + b"]\x00"
    )


def write_registry_pol_fixture(root: Path) -> Path:
    policy_dir = root / "C" / "Windows" / "System32" / "GroupPolicy" / "Machine"
    policy_dir.mkdir(parents=True, exist_ok=True)
    path = policy_dir / "Registry.pol"
    records = [
        _pol_record(
            r"Software\Policies\CaseScope",
            "Enabled",
            REG_DWORD,
            struct.pack("<I", 1),
        ),
        _pol_record(
            r"Software\Policies\CaseScope",
            "Server",
            REG_SZ,
            _utf16z("https://casescope.example.test"),
        ),
        _pol_record(
            r"Software\Policies\CaseScope",
            "BinarySecret",
            REG_BINARY,
            bytes.fromhex("00112233445566778899aabbccddeeff"),
        ),
        _pol_record(
            r"Software\Policies\CaseScope",
            "AllowedTools",
            REG_MULTI_SZ,
            ("evtxecmd\x00hayabusa\x00\x00").encode("utf-16-le"),
        ),
        _pol_record(
            r"Software\Policies\CaseScope\Nested",
            "",
            REG_SZ,
            _utf16z("default-policy-value"),
        ),
        _pol_record(
            r"Software\Policies\CaseScope",
            "Enabled",
            REG_DWORD,
            struct.pack("<I", 0),
        ),
        _pol_record(
            r"Software\Policies\CaseScope",
            "MaxRows",
            REG_QWORD,
            struct.pack("<Q", 50000),
        ),
        _pol_record(
            r"Software\Policies\CaseScope\Delete",
            "**Del.ObsoleteValue",
            REG_SZ,
            _utf16z(""),
        ),
    ]
    path.write_bytes(b"PReg" + struct.pack("<I", 1) + b"".join(records))
    return path


PROCESS_SNIPPET = r"""
import importlib
import json
import sys
from types import SimpleNamespace

from utils.manifest_protocol import construct_managed_batches

module_name, class_name, path, attempt_id, batch_size = sys.argv[1:6]
parser_cls = getattr(importlib.import_module(module_name), class_name)
parser = parser_cls(case_id=90, source_host='C3CHOST', case_file_id=904, case_tz='America/New_York')
events = list(parser.parse(path))
for event in events:
    event.compute_utc_timestamp()
generation = SimpleNamespace(
    id=1,
    case_id=90,
    source_ref_type='CASE_FILE',
    source_ref_id='904',
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
    'offsets': [json.loads(event.raw_json)['record_offset'] for event in events],
    'value_names': [event.reg_value for event in events],
    'batch_ids': [batch.ingest_batch_id for batch in batches],
    'batch_hashes': [batch.batch_content_hash for batch in batches],
    'row_hashes': [list(batch.row_hashes) for batch in batches],
    'locators': [[batch.first_source_locator, batch.last_source_locator] for batch in batches],
    'ordinals': [[row.ordinal for row in batch.rows] for batch in batches],
    'attempt_id': attempt_id,
    'producer_version': parser.manifest_producer_version(),
}
print(json.dumps(payload, default=str, sort_keys=True))
"""


class Phase1BTrancheC3CRegistryPolDeterminismTestCase(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(prefix="casescope-c3c-regpol-")
        self.root = Path(self.tempdir.name)
        self.fixture_path = write_registry_pol_fixture(self.root)

    def tearDown(self):
        self.tempdir.cleanup()

    def _run_process(self, attempt_id=ATTEMPT_A, hashseed="1", batch_size=3):
        env = {
            **os.environ,
            "SECRET_KEY": "phase1b-c3c-subprocess",
            "PYTHONHASHSEED": hashseed,
        }
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                PROCESS_SNIPPET,
                "parsers.windows_artifact_parsers",
                "RegistryPolParser",
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

    def test_c3c_capability_inventory(self):
        self.assertFalse(RegistryParser.supports_manifest_protocol)
        self.assertIsNone(RegistryParser.manifest_ordering_contract)
        self.assertTrue(RegistryPolParser.supports_manifest_protocol)
        self.assertEqual(
            RegistryPolParser.manifest_ordering_contract,
            "registry-pol:physical-record-offset-order:v1",
        )
        self.assertFalse(JumpListParser.supports_manifest_protocol)
        self.assertIsNone(JumpListParser.manifest_ordering_contract)

    def test_registry_pol_independent_process_retry_determinism(self):
        runs = [
            self._run_process(ATTEMPT_A, "1"),
            self._run_process(ATTEMPT_A, "7"),
            self._run_process(ATTEMPT_A, "random"),
        ]
        self.assertEqual([run["count"] for run in runs], [8, 8, 8])
        self.assertTrue(all(not run["errors"] for run in runs), runs)
        baseline = runs[0]
        self.assertEqual(baseline["offsets"], sorted(baseline["offsets"]))
        self.assertEqual(baseline["ordinals"], [[0, 1, 2], [0, 1, 2], [0, 1]])
        self.assertIn("registry_pol_format=1", baseline["producer_version"])
        self.assertIn("(Default)", baseline["value_names"])

        for run in runs[1:]:
            self.assertEqual(run["event_rows"], baseline["event_rows"])
            self.assertEqual(run["offsets"], baseline["offsets"])
            self.assertEqual(run["batch_ids"], baseline["batch_ids"])
            self.assertEqual(run["row_hashes"], baseline["row_hashes"])
            self.assertEqual(run["batch_hashes"], baseline["batch_hashes"])
            self.assertEqual(run["locators"], baseline["locators"])

        retry = self._run_process(ATTEMPT_B, "7")
        self.assertNotEqual(baseline["attempt_id"], retry["attempt_id"])
        self.assertEqual(retry["event_rows"], baseline["event_rows"])
        self.assertEqual(retry["batch_ids"], baseline["batch_ids"])
        self.assertEqual(retry["row_hashes"], baseline["row_hashes"])
        self.assertEqual(retry["batch_hashes"], baseline["batch_hashes"])
        self.assertEqual(retry["locators"], baseline["locators"])

    def test_registry_pol_legacy_managed_semantic_parity(self):
        parser = RegistryPolParser(case_id=CASE_ID, source_host=SOURCE_HOST, case_file_id=CASE_FILE_ID, case_tz=CASE_TZ)
        legacy_rows = []
        for event in parser.parse(str(self.fixture_path)):
            event.compute_utc_timestamp()
            legacy_rows.append(list(event.to_clickhouse_row()))
        managed = self._run_process(ATTEMPT_A, "random")
        self.assertEqual(
            managed["event_rows"],
            json.loads(json.dumps(legacy_rows, default=str)),
        )


PG_URL = os.environ.get("PHASE1B_PG_TEST_DATABASE_URL")
CH_DB = os.environ.get("PHASE1B_CH_TEST_DATABASE")


@unittest.skipUnless(PG_URL and CH_DB, "PHASE1B_PG_TEST_DATABASE_URL and PHASE1B_CH_TEST_DATABASE are required")
class Phase1BTrancheC3CRegistryPolManagedIntegrationTestCase(unittest.TestCase):
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
            SECRET_KEY="phase1b-c3c-managed",
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
        cls.tempdir = tempfile.TemporaryDirectory(prefix="casescope-c3c-managed-")
        cls.fixture_path = write_registry_pol_fixture(Path(cls.tempdir.name))

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
        self.pg_client = self.Client(name="C3C Managed", code=f"C3C{time.time_ns() % 100000}", created_by="tester")
        self.case = self.Case(uuid=f"c3c-case-{time.time_ns()}", name="C3C Case", company="Example", client=self.pg_client, created_by="tester")
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
        return RegistryPolParser(
            case_id=self.case.id,
            source_host=SOURCE_HOST,
            case_file_id=self.case_file.id,
            case_tz=CASE_TZ,
        )

    def test_registry_pol_real_managed_ingest_retry_and_batch_isolation(self):
        from models.database_flow import EvidenceGenerationState, IngestBatchState
        from tasks.celery_tasks import _process_managed_initial_case_file

        first = _process_managed_initial_case_file(
            parser=self._parser(),
            file_path=str(self.fixture_path),
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            clickhouse_client=self.client,
            task_id="c3c-first-registry-pol",
        )
        self.assertTrue(first.success)
        self.assertEqual(first.events_count, 8)
        generation = self.db.session.query(self.EvidenceSourceGeneration).one()
        self.assertEqual(generation.visibility_state, EvidenceGenerationState.ACTIVE)
        self.assertEqual(generation.ordering_contract, "registry-pol:physical-record-offset-order:v1")
        self.assertIn("registry_pol_format=1", generation.producer_version)
        batches = self.db.session.query(self.IngestBatch).order_by(self.IngestBatch.batch_ordinal).all()
        self.assertEqual([batch.row_count for batch in batches], [3, 3, 2])
        self.assertTrue(all(batch.state == IngestBatchState.DURABLE for batch in batches))
        first_batch_ids = [batch.ingest_batch_id for batch in batches]

        retry = _process_managed_initial_case_file(
            parser=self._parser(),
            file_path=str(self.fixture_path),
            case_id=self.case.id,
            case_file_id=self.case_file.id,
            clickhouse_client=self.client,
            task_id="c3c-retry-registry-pol",
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

    def test_registry_pol_partial_failure_retry_preserves_durable_batches(self):
        from tasks.celery_tasks import _process_managed_initial_case_file
        from utils.manifest_protocol import insert_managed_batch as real_insert

        calls = {"count": 0}

        def fail_second_insert(client, manifest):
            calls["count"] += 1
            if calls["count"] == 2:
                raise RuntimeError("injected c3c failure after first durable batch")
            return real_insert(client, manifest)

        with patch("utils.manifest_protocol.insert_managed_batch", side_effect=fail_second_insert):
            with self.assertRaises(RuntimeError):
                _process_managed_initial_case_file(
                    parser=self._parser(),
                    file_path=str(self.fixture_path),
                    case_id=self.case.id,
                    case_file_id=self.case_file.id,
                    clickhouse_client=self.client,
                    task_id="c3c-partial-registry-pol",
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
            task_id="c3c-partial-retry-registry-pol",
        )
        self.assertTrue(retry.success)
        batches = self.db.session.query(self.IngestBatch).order_by(self.IngestBatch.batch_ordinal).all()
        self.assertEqual(len(batches), 3)
        self.assertEqual(batches[0].ingest_batch_id, first_batch_id)
        self.assertTrue(all(batch.state == "DURABLE" for batch in batches))


if __name__ == "__main__":
    unittest.main()
