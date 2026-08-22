"""Phase 2.3 bounded lightweight UPDATE bridge tests.

Unit gates always run. Live ClickHouse proofs fail closed if the server
is unreachable and never mutate production `casescope.events`.
"""
from __future__ import annotations

import inspect
import json
import os
import threading
import time
import unittest
import uuid
from datetime import datetime
from unittest.mock import patch

os.environ.setdefault("SECRET_KEY", "phase2-3-test-secret")

from migrations.add_events_table import EVENTS_SCHEMA
from utils import clickhouse as clickhouse_utils
from utils.clickhouse import (
    LIGHTWEIGHT_UPDATE_MAX_SELECTOR_KEYS,
    LightweightUpdateRefused,
    run_events_lightweight_update,
    run_events_update,
)
from utils.event_analyst_state import upsert_event_analyst_state_rows
from utils.event_ioc_state import insert_ioc_scan_matches, start_ioc_refresh
from utils.event_mitre_state import insert_mitre_rule_matches, rebuild_mitre_summary_columns
from utils.event_noise_state import (
    insert_noise_scan_matches,
    start_noise_scan,
    upsert_manual_noise_state_rows,
)
from utils.event_overlay_repair import purge_case_event_overlay_state
from utils.evidence_audit import EventChange
from utils.ingest_fence import (
    FailingFenceBackend,
    IngestAdmissionDenied,
    IngestFenceUnavailable,
    active_shared_writer_count,
    exclusive_ingest_fence,
    get_active_exclusive_fence,
    install_fence_backend,
    install_memory_backend,
    reset_fence_backend,
)


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FORENSIC_IDENTITY_COLUMNS = (
    "evidence_record_key",
    "selector_key",
    "search_blob",
    "raw_json",
    "extra_fields",
    "source_ref_type",
    "source_ref_id",
    "source_generation",
    "ingest_batch_id",
    "ingest_row_ordinal",
    "ingest_row_hash",
    "ingest_attempt_id",
    "timestamp",
    "timestamp_utc",
    "timestamp_source_tz",
    "indexed_at",
    "source_file",
    "source_path",
    "source_host",
    "case_file_id",
    "event_id",
    "channel",
    "provider",
    "record_id",
    "username",
    "domain",
    "command_line",
    "process_name",
)
INSERT_COLUMNS = [
    "case_id",
    "artifact_type",
    "timestamp",
    "timestamp_utc",
    "source_file",
    "source_host",
    "event_id",
    "record_id",
    "raw_json",
    "search_blob",
    "extra_fields",
    "evidence_record_key",
    "evidence_identity_version",
    "evidence_identity_quality",
    "source_ref_type",
    "source_ref_id",
    "source_generation",
    "ingest_batch_id",
    "ingest_row_ordinal",
    "ingest_row_hash",
    "ingest_attempt_id",
    "username",
    "domain",
    "command_line",
    "process_name",
    "channel",
    "provider",
]
LATER_PHASE_TOKENS = (
    "events_current",
    "event_observations_current",
    "logical_event_key",
    "IOCEvidenceMatch",
)


class _QueryResult:
    def __init__(self, rows):
        self.result_rows = list(rows or [])


class _RecordingClient:
    def __init__(self):
        self.commands = []
        self.on_command = None

    def command(self, sql):
        self.commands.append(sql)
        if self.on_command is not None:
            self.on_command(sql)
        return True

    def query(self, sql, parameters=None):
        return _QueryResult([(0,)])


class _PriorStateClient:
    def __init__(self, prior_rows, count=None):
        self.commands = []
        self.prior_rows = list(prior_rows)
        self.count = len(self.prior_rows) if count is None else int(count)

    def command(self, sql):
        self.commands.append(sql)

    def query(self, sql, parameters=None):
        if "SELECT count()" in sql:
            return _QueryResult([(self.count,)])
        return _QueryResult(self.prior_rows)


def _selector(record_id, *, source_file="Security.evtx", source_host="P23HOST"):
    return f"record:{int(record_id)}|file:{source_file}|host:{source_host}"


def _fresh_style_client(database):
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


def _fixture_rows(case_id, count, *, source_host="P23HOST"):
    ts = datetime(2026, 1, 1, 12, 0, 0)
    rows = []
    for index in range(count):
        record_id = index + 1
        rows.append(
            [
                int(case_id),
                "evtx",
                ts,
                ts,
                "Security.evtx",
                source_host,
                "4688",
                record_id,
                '{"EventID":"4688"}',
                f"blob row{record_id} powershell",
                '{"k":1}',
                f"erk-p23-{case_id}-{record_id:08d}",
                "v1",
                "high",
                "CASE_FILE",
                str(case_id),
                1,
                f"batch-{case_id}",
                index,
                f"hash-{case_id}-{record_id}",
                str(uuid.uuid4()),
                "analyst",
                "CORP",
                "powershell.exe -NoProfile",
                "powershell.exe",
                "Security",
                "Microsoft-Windows-Security-Auditing",
            ]
        )
    return rows


class Phase23ContractTests(unittest.TestCase):
    def test_lightweight_cap_is_1000(self):
        self.assertEqual(LIGHTWEIGHT_UPDATE_MAX_SELECTOR_KEYS, 1000)
        self.assertIs(clickhouse_utils.LIGHTWEIGHT_UPDATE_MAX_SELECTOR_KEYS, LIGHTWEIGHT_UPDATE_MAX_SELECTOR_KEYS)

    def test_lightweight_helper_requires_bounded_selector_keys(self):
        signature = inspect.signature(run_events_lightweight_update)
        self.assertIn("selector_keys", signature.parameters)
        self.assertEqual(
            signature.parameters["selector_keys"].kind,
            inspect.Parameter.KEYWORD_ONLY,
        )
        self.assertEqual(
            signature.parameters["case_id"].kind,
            inspect.Parameter.KEYWORD_ONLY,
        )
        self.assertNotIn("where_sql", signature.parameters)
        self.assertNotIn("lightweight", signature.parameters)
        self.assertNotIn("mode", signature.parameters)

    def test_lightweight_helper_sql_and_admission_shape(self):
        source = inspect.getsource(run_events_lightweight_update)
        self.assertIn("UPDATE events SET", source)
        self.assertIn("shared_ingest_admission", source)
        self.assertIn("events_lightweight_update", source)
        self.assertIn("has(", source)
        self.assertNotIn("ALTER TABLE events UPDATE", source)
        self.assertNotIn("exclusive_ingest_fence", source)

    def test_classic_helper_remains_alter_and_exclusive(self):
        source = inspect.getsource(run_events_update)
        signature = inspect.signature(run_events_update)
        self.assertIn("ALTER TABLE events UPDATE", source)
        self.assertIn("exclusive_ingest_fence", source)
        self.assertNotIn("UPDATE events SET", source)
        self.assertNotIn("shared_ingest_admission", source)
        self.assertNotIn("lightweight", signature.parameters)
        self.assertNotIn("mode", signature.parameters)

    def test_event_insert_mode_unchanged(self):
        self.assertEqual(clickhouse_utils.EVENT_INSERT_MODE, "sync")
        settings = clickhouse_utils.event_insert_settings()
        self.assertEqual(settings["async_insert"], 0)
        self.assertEqual(settings["materialize_skip_indexes_on_insert"], 1)

    def test_classic_paths_remain_classic(self):
        for function in (
            start_noise_scan,
            insert_noise_scan_matches,
            start_ioc_refresh,
            insert_ioc_scan_matches,
            insert_mitre_rule_matches,
            rebuild_mitre_summary_columns,
            purge_case_event_overlay_state,
        ):
            source = inspect.getsource(function)
            self.assertIn("run_events_update", source, msg=function.__name__)
            self.assertNotIn(
                "run_events_lightweight_update",
                source,
                msg=function.__name__,
            )

        hayabusa_path = os.path.join(REPO_ROOT, "utils", "hayabusa_mitre_reenrichment.py")
        with open(hayabusa_path, encoding="utf-8") as handle:
            hayabusa_source = handle.read()
        self.assertIn("run_events_update", hayabusa_source)
        self.assertNotIn("run_events_lightweight_update", hayabusa_source)
        self.assertIn("MUTATION_RECORD_BATCH_SIZE = 5000", hayabusa_source)

    def test_small_paths_choose_helper_in_source(self):
        analyst_source = inspect.getsource(upsert_event_analyst_state_rows)
        noise_source = inspect.getsource(upsert_manual_noise_state_rows)
        for source in (analyst_source, noise_source):
            self.assertIn("run_events_lightweight_update", source)
            self.assertIn("LIGHTWEIGHT_UPDATE_MAX_SELECTOR_KEYS", source)
            self.assertIn("run_events_update", source)
            self.assertIn("record_event_changes", source)

    def test_hunting_routes_keep_selector_identity(self):
        from routes import hunting as hunting_routes

        source = inspect.getsource(hunting_routes)
        self.assertIn("upsert_event_analyst_state_rows", source)
        self.assertIn("upsert_manual_noise_state_rows", source)
        self.assertIn("_selector_key_from_event_payload", source)
        self.assertNotIn("run_events_lightweight_update", source)

    def test_no_later_phase_tokens_in_bridge_runtime(self):
        paths = [
            os.path.join(REPO_ROOT, "utils", "clickhouse.py"),
            os.path.join(REPO_ROOT, "utils", "event_analyst_state.py"),
            os.path.join(REPO_ROOT, "utils", "event_noise_state.py"),
            os.path.join(REPO_ROOT, "utils", "evidence_audit.py"),
            os.path.join(REPO_ROOT, "utils", "ingest_fence.py"),
        ]
        for path in paths:
            with open(path, encoding="utf-8") as handle:
                text = handle.read()
            for token in LATER_PHASE_TOKENS:
                self.assertNotIn(token, text, msg=f"{os.path.basename(path)} {token}")

    def test_version_records_phase23_and_current_candidate(self):
        with open(os.path.join(REPO_ROOT, "version.json"), encoding="utf-8") as handle:
            payload = json.load(handle)
        parts = tuple(int(part) for part in payload["version"].split("."))
        self.assertGreaterEqual(parts, (4, 26, 2))
        phase23 = next(item for item in payload["changelog"] if item["version"] == "4.26.2")
        joined = " ".join(phase23["changes"]).lower()
        self.assertIn("lightweight", joined)
        self.assertIn("classic", joined)
        self.assertIn("audit", joined)


class Phase23RoutingTests(unittest.TestCase):
    def test_analyst_small_uses_lightweight(self):
        prior = [("event_id:4624", False, [], None, "Security.evtx")]
        client = _PriorStateClient(prior)
        with patch("utils.event_analyst_state.run_events_lightweight_update") as lightweight, patch(
            "utils.event_analyst_state.run_events_update"
        ) as classic, patch("utils.event_analyst_state.record_event_changes") as audit:
            updated = upsert_event_analyst_state_rows(
                7,
                [
                    {
                        "selector_key": "event_id:4624",
                        "artifact_type": "evtx",
                        "analyst_tagged": True,
                        "analyst_tags": ["keep"],
                        "analyst_notes": "note",
                    }
                ],
                updated_by="tester",
                client=client,
                remote_ip="203.0.113.9",
                operation_id="op-analyst-small",
            )
        self.assertEqual(updated, 1)
        lightweight.assert_called_once()
        classic.assert_not_called()
        kwargs = lightweight.call_args.kwargs
        self.assertEqual(kwargs["case_id"], 7)
        self.assertEqual(kwargs["selector_keys"], ["event_id:4624"])
        self.assertEqual(kwargs["artifact_type"], "evtx")
        self.assertEqual(kwargs["client"], client)
        audit.assert_called_once()

    def test_analyst_oversize_uses_classic_for_whole_operation(self):
        keys = [f"sel-{index}" for index in range(1001)]
        tagged = [{"selector_key": key, "analyst_tagged": True} for key in keys[:500]]
        untagged = [{"selector_key": key, "analyst_tagged": False} for key in keys[500:]]
        prior = [(key, False, [], None, "Security.evtx") for key in keys]
        client = _PriorStateClient(prior, count=1)
        with patch("utils.event_analyst_state.run_events_lightweight_update") as lightweight, patch(
            "utils.event_analyst_state.run_events_update"
        ) as classic, patch("utils.event_analyst_state.record_event_changes"):
            upsert_event_analyst_state_rows(
                7,
                tagged + untagged,
                updated_by="tester",
                client=client,
            )
        lightweight.assert_not_called()
        self.assertEqual(classic.call_count, 2)

    def test_analyst_boundary_1000_uses_lightweight(self):
        keys = [f"sel-{index}" for index in range(1000)]
        prior = [(key, False, [], None, "Security.evtx") for key in keys]
        client = _PriorStateClient(prior, count=1)
        with patch("utils.event_analyst_state.run_events_lightweight_update") as lightweight, patch(
            "utils.event_analyst_state.run_events_update"
        ) as classic, patch("utils.event_analyst_state.record_event_changes"):
            upsert_event_analyst_state_rows(
                7,
                [{"selector_key": key, "analyst_tagged": True} for key in keys],
                updated_by="tester",
                client=client,
            )
        lightweight.assert_called_once()
        classic.assert_not_called()

    def test_manual_noise_small_uses_lightweight(self):
        prior = [("event_id:4624", False, [], "Security.evtx")]
        client = _PriorStateClient(prior)
        with patch("utils.event_noise_state.run_events_lightweight_update") as lightweight, patch(
            "utils.event_noise_state.run_events_update"
        ) as classic, patch("utils.event_noise_state.record_event_changes") as audit:
            updated = upsert_manual_noise_state_rows(
                7,
                [
                    {
                        "selector_key": "event_id:4624",
                        "artifact_type": "evtx",
                        "noise_matched": True,
                        "noise_rules": [],
                    }
                ],
                updated_by="tester",
                client=client,
                remote_ip="203.0.113.9",
                operation_id="op-noise-small",
            )
        self.assertEqual(updated, 1)
        lightweight.assert_called_once()
        classic.assert_not_called()
        self.assertEqual(lightweight.call_args.kwargs["selector_keys"], ["event_id:4624"])
        audit.assert_called_once()

    def test_manual_noise_oversize_uses_classic(self):
        keys = [f"sel-{index}" for index in range(1001)]
        prior = [(key, False, [], "Security.evtx") for key in keys]
        client = _PriorStateClient(prior, count=1)
        with patch("utils.event_noise_state.run_events_lightweight_update") as lightweight, patch(
            "utils.event_noise_state.run_events_update"
        ) as classic, patch("utils.event_noise_state.record_event_changes"):
            upsert_manual_noise_state_rows(
                7,
                [{"selector_key": key, "noise_matched": True, "noise_rules": []} for key in keys],
                updated_by="tester",
                client=client,
            )
        lightweight.assert_not_called()
        classic.assert_called_once()


class Phase23HelperUnitTests(unittest.TestCase):
    def setUp(self):
        install_memory_backend()

    def tearDown(self):
        reset_fence_backend()

    def test_empty_selector_keys_are_noop(self):
        client = _RecordingClient()
        result = run_events_lightweight_update(
            "analyst_tagged = true",
            case_id=7,
            selector_keys=[],
            client=client,
        )
        self.assertTrue(result)
        self.assertEqual(client.commands, [])
        self.assertEqual(active_shared_writer_count(), 0)

    def test_refuses_more_than_1000_keys(self):
        client = _RecordingClient()
        keys = [f"sel-{index}" for index in range(1001)]
        with self.assertRaises(LightweightUpdateRefused):
            run_events_lightweight_update(
                "analyst_tagged = true",
                case_id=7,
                selector_keys=keys,
                client=client,
            )
        self.assertEqual(client.commands, [])

    def test_string_selector_keys_are_refused(self):
        client = _RecordingClient()
        with self.assertRaises(TypeError):
            run_events_lightweight_update(
                "analyst_tagged = true",
                case_id=7,
                selector_keys="sel-1",
                client=client,
            )
        self.assertEqual(client.commands, [])

    def test_helper_emits_sql_update_not_alter(self):
        client = _RecordingClient()
        run_events_lightweight_update(
            "analyst_tagged = true",
            case_id=7,
            selector_keys=["sel-1", "sel-2"],
            artifact_type="evtx",
            client=client,
        )
        self.assertEqual(len(client.commands), 1)
        sql = client.commands[0]
        self.assertTrue(sql.startswith("UPDATE events SET analyst_tagged = true WHERE "))
        self.assertIn("case_id = 7", sql)
        self.assertIn("artifact_type = 'evtx'", sql)
        self.assertIn("has(['sel-1', 'sel-2'], selector_key)", sql)
        self.assertNotIn("ALTER TABLE", sql)
        self.assertNotIn("mutations_sync", sql)

    def test_helper_acquires_shared_admission(self):
        seen = []
        client = _RecordingClient()

        def on_command(_sql):
            seen.append(active_shared_writer_count())

        client.on_command = on_command
        run_events_lightweight_update(
            "analyst_tagged = true",
            case_id=9,
            selector_keys=["sel-1"],
            client=client,
        )
        self.assertEqual(seen, [1])
        self.assertEqual(active_shared_writer_count(), 0)

    def test_helper_fails_closed_when_fence_unavailable(self):
        install_fence_backend(FailingFenceBackend())
        client = _RecordingClient()
        with self.assertRaises(IngestFenceUnavailable):
            run_events_lightweight_update(
                "analyst_tagged = true",
                case_id=7,
                selector_keys=["sel-1"],
                client=client,
            )
        self.assertEqual(client.commands, [])


class Phase23FenceTests(unittest.TestCase):
    def setUp(self):
        install_memory_backend()

    def tearDown(self):
        reset_fence_backend()

    def test_exclusive_pending_prevents_lightweight_writer(self):
        client = _RecordingClient()
        entered = threading.Event()
        hold = threading.Event()

        def admin():
            with exclusive_ingest_fence("events_alter_update", timeout_seconds=2):
                entered.set()
                hold.wait(timeout=2)

        thread = threading.Thread(target=admin)
        thread.start()
        self.assertTrue(entered.wait(timeout=2))
        with self.assertRaises(IngestAdmissionDenied):
            run_events_lightweight_update(
                "analyst_tagged = true",
                case_id=7,
                selector_keys=["sel-1"],
                client=client,
            )
        self.assertEqual(client.commands, [])
        hold.set()
        thread.join(timeout=2)

    def test_exclusive_waits_for_active_lightweight_writer_to_drain(self):
        client = _RecordingClient()
        holding = threading.Event()
        release = threading.Event()
        exclusive_saw = []

        def on_command(_sql):
            holding.set()
            release.wait(timeout=3)

        client.on_command = on_command

        def writer():
            run_events_lightweight_update(
                "analyst_tagged = true",
                case_id=7,
                selector_keys=["sel-1"],
                client=client,
            )

        def admin():
            self.assertTrue(holding.wait(timeout=2))
            with exclusive_ingest_fence(
                "events_alter_update",
                timeout_seconds=3,
                poll_interval_seconds=0.02,
            ):
                exclusive_saw.append(active_shared_writer_count())

        writer_thread = threading.Thread(target=writer)
        admin_thread = threading.Thread(target=admin)
        writer_thread.start()
        self.assertTrue(holding.wait(timeout=2))
        admin_thread.start()
        time.sleep(0.1)
        self.assertTrue(admin_thread.is_alive())
        release.set()
        writer_thread.join(timeout=2)
        admin_thread.join(timeout=2)
        self.assertEqual(exclusive_saw, [0])
        self.assertEqual(len(client.commands), 1)

    def test_lightweight_proceeds_after_exclusive_release(self):
        client = _RecordingClient()
        with exclusive_ingest_fence("events_alter_update", timeout_seconds=1):
            pass
        run_events_lightweight_update(
            "analyst_tagged = true",
            case_id=7,
            selector_keys=["sel-1"],
            client=client,
        )
        self.assertEqual(len(client.commands), 1)
        self.assertIn("UPDATE events SET", client.commands[0])

    def test_classic_update_retains_exclusive_behavior(self):
        seen_exclusive = []
        client = _RecordingClient()

        def on_command(_sql):
            seen_exclusive.append(get_active_exclusive_fence() is not None)

        client.on_command = on_command
        run_events_update("analyst_tagged = true", "case_id = 7 AND selector_key = 'sel-1'", client=client)
        self.assertEqual(seen_exclusive, [True])
        self.assertIn("ALTER TABLE events UPDATE", client.commands[0])
        self.assertIsNone(get_active_exclusive_fence())


class Phase23AuditTests(unittest.TestCase):
    def setUp(self):
        install_memory_backend()

    def tearDown(self):
        reset_fence_backend()

    def test_successful_lightweight_records_per_event_audit(self):
        prior = [("event_id:4624", False, [], None, "Security.evtx")]
        client = _PriorStateClient(prior)
        with patch(
            "utils.event_analyst_state.run_events_lightweight_update",
            return_value=True,
        ), patch("utils.event_analyst_state.run_events_update") as classic, patch(
            "utils.event_analyst_state.record_event_changes"
        ) as audit:
            upsert_event_analyst_state_rows(
                7,
                [
                    {
                        "selector_key": "event_id:4624",
                        "artifact_type": "evtx",
                        "analyst_tagged": True,
                        "analyst_tags": ["keep"],
                        "analyst_notes": "note",
                    }
                ],
                updated_by="alice",
                client=client,
                remote_ip="198.51.100.10",
                operation_id="op-audit-1",
            )
        classic.assert_not_called()
        change, events = audit.call_args.args
        self.assertEqual(change.operation_id, "op-audit-1")
        self.assertEqual(change.username, "alice")
        self.assertEqual(change.remote_ip, "198.51.100.10")
        self.assertEqual(change.affected_count, 1)
        self.assertEqual(len(events), 1)
        self.assertIsInstance(events[0], EventChange)
        self.assertEqual(events[0].selector_key, "event_id:4624")
        self.assertEqual(events[0].source_file, "Security.evtx")
        self.assertEqual(events[0].old_value["analyst_tagged"], False)
        self.assertEqual(events[0].new_value["analyst_tagged"], True)

    def test_failed_lightweight_does_not_record_success_audit(self):
        prior = [("event_id:4624", False, [], None, "Security.evtx")]
        client = _PriorStateClient(prior)
        with patch(
            "utils.event_analyst_state.run_events_lightweight_update",
            side_effect=RuntimeError("update failed"),
        ), patch("utils.event_analyst_state.record_event_changes") as audit:
            with self.assertRaises(RuntimeError):
                upsert_event_analyst_state_rows(
                    7,
                    [{"selector_key": "event_id:4624", "analyst_tagged": True}],
                    updated_by="alice",
                    client=client,
                    operation_id="op-audit-fail",
                )
        audit.assert_not_called()

    def test_fence_failure_does_not_mutate_or_audit(self):
        install_fence_backend(FailingFenceBackend())
        prior = [("event_id:4624", False, [], None, "Security.evtx")]
        client = _PriorStateClient(prior)
        with patch("utils.event_analyst_state.record_event_changes") as audit:
            with self.assertRaises(IngestFenceUnavailable):
                upsert_event_analyst_state_rows(
                    7,
                    [{"selector_key": "event_id:4624", "analyst_tagged": True}],
                    updated_by="alice",
                    client=client,
                )
        self.assertEqual(client.commands, [])
        audit.assert_not_called()

    def test_manual_noise_audit_parity(self):
        prior = [("event_id:4624", False, [], "Security.evtx")]
        client = _PriorStateClient(prior)
        with patch(
            "utils.event_noise_state.run_events_lightweight_update",
            return_value=True,
        ), patch("utils.event_noise_state.record_event_changes") as audit:
            upsert_manual_noise_state_rows(
                7,
                [{"selector_key": "event_id:4624", "noise_matched": True, "noise_rules": []}],
                updated_by="bob",
                client=client,
                remote_ip="192.0.2.5",
                operation_id="op-noise-audit",
            )
        change, events = audit.call_args.args
        self.assertEqual(change.operation_id, "op-noise-audit")
        self.assertEqual(change.username, "bob")
        self.assertEqual(change.remote_ip, "192.0.2.5")
        self.assertEqual(events[0].old_value["noise_matched"], False)
        self.assertEqual(events[0].new_value["noise_matched"], True)


class LivePhase23Tests(unittest.TestCase):
    """Disposable ClickHouse correctness proof using the final events schema."""

    @classmethod
    def setUpClass(cls):
        install_memory_backend()
        try:
            admin = _fresh_style_client("default")
            admin.query("SELECT 1")
        except Exception as exc:
            reset_fence_backend()
            raise AssertionError(
                f"live ClickHouse is required for Phase 2.3 and was unreachable: {exc}"
            ) from exc
        cls.database = f"cs_p23_{uuid.uuid4().hex[:12]}"
        admin.command(f"CREATE DATABASE {cls.database}")
        admin.close()
        cls.client = _fresh_style_client(cls.database)
        cls.client.command(EVENTS_SCHEMA)
        version = cls.client.query("SELECT version()").result_rows[0][0]
        if not str(version).startswith("26.7.3"):
            raise AssertionError(f"expected deployed ClickHouse 26.7.3.x, got {version}")
        cls.clickhouse_version = str(version)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.client.command(f"DROP DATABASE IF EXISTS {cls.database}")
        except Exception:
            pass
        try:
            cls.client.close()
        except Exception:
            pass
        reset_fence_backend()

    def setUp(self):
        install_memory_backend()
        self.client.command("TRUNCATE TABLE IF EXISTS events")

    def tearDown(self):
        reset_fence_backend()

    def _insert(self, case_id, count, **kwargs):
        self.client.insert("events", _fixture_rows(case_id, count, **kwargs), column_names=INSERT_COLUMNS)

    def _snapshot(self, case_id):
        columns = ", ".join(FORENSIC_IDENTITY_COLUMNS)
        result = self.client.query(
            f"SELECT {columns} FROM events WHERE case_id = {{case_id:UInt32}} ORDER BY record_id",
            parameters={"case_id": int(case_id)},
        )
        return {row[1]: row for row in result.result_rows}

    def test_a_b_c_d_helper_sizes_and_refuse(self):
        self._insert(11, 1100)
        recording = []

        class _Wrap:
            def __init__(self, inner):
                self._inner = inner
                self.commands = []

            def command(self, sql):
                self.commands.append(sql)
                recording.append(sql)
                return self._inner.command(sql)

            def query(self, *args, **kwargs):
                return self._inner.query(*args, **kwargs)

        wrapped = _Wrap(self.client)
        for size in (1, 100, 1000):
            keys = [_selector(index) for index in range(1, size + 1)]
            run_events_lightweight_update(
                "analyst_tagged = true",
                case_id=11,
                selector_keys=keys,
                client=wrapped,
            )
            tagged = self.client.query(
                "SELECT countIf(analyst_tagged) FROM events WHERE case_id = 11"
            ).result_rows[0][0]
            self.assertEqual(int(tagged), size)
            self.assertTrue(wrapped.commands[-1].startswith("UPDATE events SET"))
            self.assertNotIn("ALTER TABLE", wrapped.commands[-1])
            self.assertNotIn("OPTIMIZE", wrapped.commands[-1])
            self.assertNotIn("MATERIALIZE", wrapped.commands[-1])

        with self.assertRaises(LightweightUpdateRefused):
            run_events_lightweight_update(
                "analyst_tagged = true",
                case_id=11,
                selector_keys=[_selector(index) for index in range(1, 1002)],
                client=wrapped,
            )
        self.assertEqual(len(wrapped.commands), 3)

    def test_e_oversize_analyst_and_noise_use_classic(self):
        self._insert(12, 1010)
        keys = [_selector(index) for index in range(1, 1002)]
        commands = []

        class _Wrap:
            def command(inner_self, sql):
                commands.append(sql)
                return self.client.command(sql)

            def query(inner_self, *args, **kwargs):
                return self.client.query(*args, **kwargs)

        wrapped = _Wrap()
        with patch("utils.event_analyst_state.record_event_changes"), patch(
            "utils.event_noise_state.record_event_changes"
        ):
            upsert_event_analyst_state_rows(
                12,
                [{"selector_key": key, "artifact_type": "evtx", "analyst_tagged": True} for key in keys],
                updated_by="tester",
                client=wrapped,
            )
            upsert_manual_noise_state_rows(
                12,
                [{"selector_key": key, "artifact_type": "evtx", "noise_matched": True, "noise_rules": []} for key in keys],
                updated_by="tester",
                client=wrapped,
            )
        alter_commands = [sql for sql in commands if "ALTER TABLE events UPDATE" in sql]
        light_commands = [sql for sql in commands if sql.startswith("UPDATE events SET")]
        self.assertGreaterEqual(len(alter_commands), 2)
        self.assertEqual(light_commands, [])
        tagged = self.client.query(
            "SELECT countIf(analyst_tagged), countIf(noise_matched) FROM events WHERE case_id = 12"
        ).result_rows[0]
        self.assertEqual(int(tagged[0]), 1001)
        self.assertEqual(int(tagged[1]), 1001)

    def test_immediate_same_and_fresh_client_visibility(self):
        self._insert(13, 5)
        run_events_lightweight_update(
            "analyst_tagged = true, analyst_notes = 'visible-now'",
            case_id=13,
            selector_keys=[_selector(3)],
            client=self.client,
        )
        same = self.client.query(
            "SELECT analyst_tagged, analyst_notes FROM events WHERE case_id = 13 AND selector_key = {k:String}",
            parameters={"k": _selector(3)},
        ).result_rows[0]
        self.assertTrue(bool(same[0]))
        self.assertEqual(same[1], "visible-now")
        fresh = _fresh_style_client(self.database)
        try:
            other = fresh.query(
                "SELECT analyst_tagged, analyst_notes FROM events WHERE case_id = 13 AND selector_key = {k:String}",
                parameters={"k": _selector(3)},
            ).result_rows[0]
        finally:
            fresh.close()
        self.assertTrue(bool(other[0]))
        self.assertEqual(other[1], "visible-now")

    def test_forensic_identity_invariance(self):
        self._insert(14, 8)
        before_count = self.client.query("SELECT count() FROM events WHERE case_id = 14").result_rows[0][0]
        before = self._snapshot(14)
        run_events_lightweight_update(
            "analyst_tagged = true, analyst_tags = ['bridge']",
            case_id=14,
            selector_keys=[_selector(2), _selector(4)],
            client=self.client,
        )
        after_count = self.client.query("SELECT count() FROM events WHERE case_id = 14").result_rows[0][0]
        after = self._snapshot(14)
        self.assertEqual(int(before_count), 8)
        self.assertEqual(int(after_count), 8)
        self.assertEqual(set(before), set(after))
        for selector_key, row in after.items():
            self.assertEqual(row, before[selector_key])
        tagged = {
            row[0]: bool(row[1])
            for row in self.client.query(
                "SELECT selector_key, analyst_tagged FROM events WHERE case_id = 14"
            ).result_rows
        }
        self.assertTrue(tagged[_selector(2)])
        self.assertTrue(tagged[_selector(4)])
        self.assertFalse(tagged[_selector(1)])
        self.assertFalse(tagged[_selector(8)])

    def test_lightweight_classic_state_parity(self):
        self._insert(21, 12)
        self._insert(22, 12)
        target = [_selector(index) for index in range(1, 7)]
        assignments = "analyst_tagged = true, analyst_tags = ['parity'], analyst_notes = 'same'"
        with patch("utils.event_analyst_state.record_event_changes"):
            upsert_event_analyst_state_rows(
                21,
                [
                    {
                        "selector_key": key,
                        "artifact_type": "evtx",
                        "analyst_tagged": True,
                        "analyst_tags": ["parity"],
                        "analyst_notes": "same",
                    }
                    for key in target
                ],
                updated_by="tester",
                client=self.client,
            )
        run_events_update(
            assignments,
            "case_id = 22 AND artifact_type = 'evtx' AND has(["
            + ", ".join(f"'{key}'" for key in target)
            + "], selector_key)",
            client=self.client,
        )
        light_state = self.client.query(
            """
            SELECT selector_key, analyst_tagged, analyst_tags, analyst_notes
            FROM events WHERE case_id = 21 ORDER BY record_id
            """
        ).result_rows
        classic_state = self.client.query(
            """
            SELECT selector_key, analyst_tagged, analyst_tags, analyst_notes
            FROM events WHERE case_id = 22 ORDER BY record_id
            """
        ).result_rows
        self.assertEqual(
            [(row[1], list(row[2] or []), row[3]) for row in light_state],
            [(row[1], list(row[2] or []), row[3]) for row in classic_state],
        )
        self._insert(31, 12)
        self._insert(32, 12)
        noise_assignments = "noise_matched = true, noise_rules = []"
        with patch("utils.event_noise_state.record_event_changes"):
            upsert_manual_noise_state_rows(
                31,
                [
                    {
                        "selector_key": key,
                        "artifact_type": "evtx",
                        "noise_matched": True,
                        "noise_rules": [],
                    }
                    for key in target
                ],
                updated_by="tester",
                client=self.client,
            )
        run_events_update(
            noise_assignments,
            "case_id = 32 AND artifact_type = 'evtx' AND has(["
            + ", ".join(f"'{key}'" for key in target)
            + "], selector_key)",
            client=self.client,
        )
        light_noise = self.client.query(
            "SELECT selector_key, noise_matched, noise_rules FROM events WHERE case_id = 31 ORDER BY record_id"
        ).result_rows
        classic_noise = self.client.query(
            "SELECT selector_key, noise_matched, noise_rules FROM events WHERE case_id = 32 ORDER BY record_id"
        ).result_rows
        self.assertEqual(
            [(row[1], list(row[2] or [])) for row in light_noise],
            [(row[1], list(row[2] or [])) for row in classic_noise],
        )
        nontarget_noise = [
            bool(row[0])
            for row in self.client.query(
                "SELECT noise_matched FROM events WHERE case_id = 31 AND not has({keys:Array(String)}, selector_key)",
                parameters={"keys": target},
            ).result_rows
        ]
        self.assertTrue(nontarget_noise)
        self.assertTrue(all(flag is False for flag in nontarget_noise))


if __name__ == "__main__":
    unittest.main()
