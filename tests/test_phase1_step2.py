"""Phase 1 Step 2 tests: ingest fence coverage plus Buffer removal.

Run with:

    /opt/casescope/venv/bin/python -m unittest tests.test_phase1_step2 tests.test_ingest_fence

Do not use production-bound full unittest discovery.
"""
from __future__ import annotations

import ast
import os
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
        from pathlib import Path

        source = Path("/opt/casescope/bin/archive_then_reset.py").read_text(encoding="utf-8")
        self.assertIn("def _clickhouse_table_count", source)
        self.assertIn("missing table as zero", source)
        self.assertIn("system.tables", source)
        self.assertIn("_clickhouse_table_count(clickhouse_client, table)", source)

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
