"""Phase 1 Step 2 tests: ingest fence coverage plus Buffer removal.

Run with:

    /opt/casescope/venv/bin/python -m unittest tests.test_phase1_step2 tests.test_ingest_fence

Do not use production-bound full unittest discovery.
"""
from __future__ import annotations

import ast
import importlib.util
import os
import sys
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault("SECRET_KEY", "phase1-step2-test-secret")

from migrations.add_events_table import EVENTS_BUFFER_SCHEMA_TEMPLATE
from migrations.remove_events_buffer import remove_events_buffer
from parsers.registry import BatchProcessor
from utils.ingest_fence import (
    FailingFenceBackend,
    IngestExclusiveTimeout,
    IngestFenceUnavailable,
    install_fence_backend,
    install_memory_backend,
    reset_fence_backend,
    shared_ingest_admission,
)
from utils.privacy_aliases import resolve_alias_scan_table


class _QueryResult:
    def __init__(self, rows=None):
        self.result_rows = list(rows or [])


class _BufferMigrationClient:
    def __init__(
        self,
        *,
        database="phase0a_ingest_step2",
        tables=None,
        events_rows=10,
        buffer_visible=10,
        drain_to_zero=True,
        engine="Buffer",
    ):
        self.database = database
        self.tables = set(tables if tables is not None else {"events", "events_buffer"})
        self.events_rows = events_rows
        self.buffer_visible = buffer_visible
        self.drain_to_zero = drain_to_zero
        self.engine = engine
        self.commands = []
        self.queries = []

    def query(self, sql, parameters=None):
        parameters = parameters or {}
        self.queries.append((sql, parameters))
        text = " ".join(sql.split())
        if "SELECT currentDatabase()" in text:
            return _QueryResult([(self.database,)])
        table = parameters.get("table_name") or parameters.get("table")
        if "FROM system.tables" in text and "engine" in text.lower():
            if table not in self.tables:
                return _QueryResult([])
            return _QueryResult([(self.engine,)])
        if "FROM system.tables" in text:
            name = parameters.get("table_name") or parameters.get("name")
            if name is None and "events_buffer" in text:
                name = "events_buffer"
            return _QueryResult([(1 if name in self.tables else 0,)])
        if "FROM events_buffer" in text:
            return _QueryResult([(self.buffer_visible,)])
        if "FROM events" in text:
            return _QueryResult([(self.events_rows,)])
        return _QueryResult([])

    def command(self, sql):
        self.commands.append(sql)
        compact = " ".join(sql.split())
        if compact == "OPTIMIZE TABLE events_buffer":
            if self.drain_to_zero:
                self.buffer_visible = self.events_rows
            return
        if compact.startswith("DROP TABLE"):
            self.tables.discard("events_buffer")


class _ArchiveResetClickHouseClient:
    def __init__(self, *, tables=None, fail_table_probe=False, fail_counts=None):
        self.tables = dict(
            tables
            if tables is not None
            else {
                "events": 0,
                "network_logs": 0,
                "case_unified_findings": 0,
                "detection_summary": 0,
                "timeline_hourly": 0,
                "network_logs_buffer": 0,
            }
        )
        self.fail_table_probe = fail_table_probe
        self.fail_counts = set(fail_counts or [])
        self.queries = []

    def query(self, sql, parameters=None):
        parameters = parameters or {}
        self.queries.append((sql, parameters))
        text = " ".join(sql.split())
        if "FROM system.tables" in text:
            if self.fail_table_probe:
                raise RuntimeError("system.tables unavailable")
            table = parameters.get("table_name")
            return _QueryResult([(1 if table in self.tables else 0,)])
        if text.startswith("SELECT count() FROM "):
            table = text.rsplit(" ", 1)[-1]
            if table in self.fail_counts:
                raise RuntimeError(f"count failed for {table}")
            return _QueryResult([(self.tables[table],)])
        return _QueryResult([])


def _load_archive_then_reset():
    module_name = "test_archive_then_reset_module"
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "bin", "archive_then_reset.py")
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


class Phase1Step2BufferRemovalTests(unittest.TestCase):
    def setUp(self):
        install_memory_backend()

    def tearDown(self):
        reset_fence_backend()

    def test_batch_processor_defaults_to_direct_events_inserts(self):
        processor = BatchProcessor(SimpleNamespace(), batch_size=10)
        self.assertEqual(processor.table, "events")
        self.assertFalse(processor.__init__.__defaults__[1])

    def test_alias_scan_targets_events(self):
        self.assertEqual(resolve_alias_scan_table(SimpleNamespace()), "events")

    def test_fresh_install_does_not_create_buffer(self):
        import inspect
        from migrations import add_events_table

        source = inspect.getsource(add_events_table.migrate_clickhouse)
        self.assertNotIn("_ensure_events_buffer_schema(client)", source)
        self.assertIn("events_buffer is not required for fresh installs", source)

    def test_idempotent_already_removed_migration(self):
        client = _BufferMigrationClient(tables={"events"})
        result = remove_events_buffer(client, allow_production=False)
        self.assertTrue(result["already_removed"])
        self.assertFalse(result["dropped"])
        self.assertNotIn("DROP TABLE IF EXISTS events_buffer", client.commands)

    def test_drained_buffer_is_dropped(self):
        client = _BufferMigrationClient(
            events_rows=10,
            buffer_visible=14,
            drain_to_zero=True,
        )
        result = remove_events_buffer(client, allow_production=False)
        self.assertTrue(result["dropped"])
        self.assertEqual(result["pending_after_drain"], 0)
        self.assertIn("OPTIMIZE TABLE events_buffer", client.commands)
        self.assertIn("DROP TABLE IF EXISTS events_buffer", client.commands)
        self.assertNotIn("events_buffer", client.tables)

    def test_non_empty_buffer_cannot_be_dropped(self):
        client = _BufferMigrationClient(
            events_rows=10,
            buffer_visible=14,
            drain_to_zero=False,
        )
        with self.assertRaisesRegex(RuntimeError, "pending rows"):
            remove_events_buffer(client, allow_production=False)
        self.assertNotIn("DROP TABLE IF EXISTS events_buffer", client.commands)
        self.assertIn("events_buffer", client.tables)

    def test_redis_outage_prevents_cutover(self):
        install_fence_backend(FailingFenceBackend())
        client = _BufferMigrationClient()
        with self.assertRaises(IngestFenceUnavailable):
            remove_events_buffer(client, allow_production=False)
        self.assertEqual(client.commands, [])

    def test_active_writer_prevents_cutover(self):
        client = _BufferMigrationClient()
        holding = threading.Event()
        release = threading.Event()

        def writer():
            with shared_ingest_admission("events_insert"):
                holding.set()
                release.wait(timeout=3)

        thread = threading.Thread(target=writer)
        thread.start()
        self.assertTrue(holding.wait(timeout=2))
        with self.assertRaises(IngestExclusiveTimeout):
            remove_events_buffer(client, allow_production=False, timeout_seconds=0.15)
        release.set()
        thread.join(timeout=2)
        self.assertNotIn("DROP TABLE IF EXISTS events_buffer", client.commands)

    def test_production_database_is_refused(self):
        client = _BufferMigrationClient(database="casescope", tables={"events"})
        with self.assertRaisesRegex(RuntimeError, "production database"):
            remove_events_buffer(client, allow_production=False)

    def test_completion_does_not_require_buffer_optimize(self):
        import inspect
        from tasks import celery_tasks

        source = inspect.getsource(celery_tasks.case_indexing_complete_task)
        self.assertIn('_table_exists(client, "events_buffer")', source)
        self.assertIn("not_required", source)

    def test_buffer_schema_template_is_not_startup_required(self):
        self.assertIn("ENGINE = Buffer", EVENTS_BUFFER_SCHEMA_TEMPLATE)

    def test_archive_then_reset_does_not_require_events_buffer(self):
        archive_reset = _load_archive_then_reset()
        client = _ArchiveResetClickHouseClient(tables={"events": 7})
        self.assertEqual(archive_reset._clickhouse_table_count(client, "events_buffer"), 0)

    def test_archive_then_reset_counts_existing_required_events_table(self):
        archive_reset = _load_archive_then_reset()
        client = _ArchiveResetClickHouseClient(tables={"events": 7})
        self.assertEqual(archive_reset._clickhouse_table_count(client, "events"), 7)

    def test_archive_then_reset_fails_when_events_table_missing(self):
        archive_reset = _load_archive_then_reset()
        client = _ArchiveResetClickHouseClient(tables={})
        with self.assertRaisesRegex(RuntimeError, "Required ClickHouse table is missing: events"):
            archive_reset._clickhouse_table_count(client, "events")

    def test_archive_then_reset_fails_when_required_analytics_table_missing(self):
        archive_reset = _load_archive_then_reset()
        client = _ArchiveResetClickHouseClient(tables={"events": 1})
        with self.assertRaisesRegex(RuntimeError, "case_unified_findings"):
            archive_reset._clickhouse_table_count(client, "case_unified_findings")

    def test_archive_then_reset_fails_when_table_probe_fails(self):
        archive_reset = _load_archive_then_reset()
        client = _ArchiveResetClickHouseClient(fail_table_probe=True)
        with self.assertRaisesRegex(RuntimeError, "system.tables unavailable"):
            archive_reset._clickhouse_table_count(client, "events_buffer")

    def test_archive_then_reset_fails_when_existing_table_count_fails(self):
        archive_reset = _load_archive_then_reset()
        client = _ArchiveResetClickHouseClient(tables={"events": 1}, fail_counts={"events"})
        with self.assertRaisesRegex(RuntimeError, "count failed for events"):
            archive_reset._clickhouse_table_count(client, "events")

    def test_runtime_insert_path_has_no_required_buffer_dependency(self):
        import parsers.registry as registry

        with open(registry.__file__, encoding="utf-8") as handle:
            tree = ast.parse(handle.read())
        defaults = None
        for node in tree.body:
            if isinstance(node, ast.ClassDef) and node.name == "BatchProcessor":
                for item in node.body:
                    if isinstance(item, ast.FunctionDef) and item.name == "__init__":
                        defaults = item.args.defaults
        self.assertTrue(defaults)
        use_buffer_default = defaults[-1]
        self.assertIsInstance(use_buffer_default, ast.Constant)
        self.assertFalse(use_buffer_default.value)


if __name__ == "__main__":
    unittest.main()
