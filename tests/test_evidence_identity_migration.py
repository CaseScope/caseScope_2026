import inspect
import importlib.util
import os
import sys
import types
import unittest
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("SECRET_KEY", "test-secret")

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_module(module_name, relative_path):
    spec = importlib.util.spec_from_file_location(module_name, REPO_ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


@contextmanager
def _rewrite_guard(*args, **kwargs):
    yield {"operation": args[0] if args else "test"}


evidence_identity_module = _load_module("evidence_identity_under_test", "utils/evidence_identity.py")
_original_utils = sys.modules.get("utils")
_original_clickhouse = sys.modules.get("utils.clickhouse")
_original_evidence_identity = sys.modules.get("utils.evidence_identity")
try:
    utils_package = types.ModuleType("utils")
    clickhouse_module = types.ModuleType("utils.clickhouse")
    clickhouse_module.destructive_event_rewrite_guard = _rewrite_guard
    clickhouse_module.get_fresh_client = lambda: None
    utils_package.clickhouse = clickhouse_module
    utils_package.evidence_identity = evidence_identity_module
    sys.modules["utils"] = utils_package
    sys.modules["utils.clickhouse"] = clickhouse_module
    sys.modules["utils.evidence_identity"] = evidence_identity_module
    from migrations import add_evidence_record_identity as migration
finally:
    if _original_utils is None:
        sys.modules.pop("utils", None)
    else:
        sys.modules["utils"] = _original_utils
    if _original_clickhouse is None:
        sys.modules.pop("utils.clickhouse", None)
    else:
        sys.modules["utils.clickhouse"] = _original_clickhouse
    if _original_evidence_identity is None:
        sys.modules.pop("utils.evidence_identity", None)
    else:
        sys.modules["utils.evidence_identity"] = _original_evidence_identity

EVIDENCE_RECORD_KEY_PREFIX = evidence_identity_module.EVIDENCE_RECORD_KEY_PREFIX


class _Stream:
    def __init__(self, rows):
        self.rows = rows
        self.source = SimpleNamespace(column_names=[])

    def __enter__(self):
        return iter(self.rows)

    def __exit__(self, exc_type, exc, tb):
        return False


class EvidenceIdentityMigrationTestCase(unittest.TestCase):
    def test_backfill_strategy_does_not_contain_per_event_alter_update(self):
        source = inspect.getsource(migration.backfill_identity_columns)
        source += inspect.getsource(migration._rewrite_rows_to_shadow)

        self.assertNotIn("ALTER TABLE events UPDATE", source)
        self.assertIn("query_rows_stream", source)
        self.assertIn("SHADOW_TABLE", source)

    def test_shadow_rewrite_streams_batches_and_generates_identity(self):
        columns = [
            "case_id",
            "artifact_type",
            "timestamp",
            "timestamp_utc",
            "timestamp_source_tz",
            "source_file",
            "source_path",
            "source_host",
            "case_file_id",
            "event_id",
            "record_id",
            "raw_json",
            "search_blob",
            "extra_fields",
            "parser_version",
            "evidence_record_key",
            "evidence_identity_version",
            "evidence_identity_quality",
        ]
        row = [
            7,
            "custom_log",
            datetime(2026, 4, 21, 12, 0, 0, 123456),
            datetime(2026, 4, 21, 12, 0, 0, 123000),
            "UTC",
            "source.log",
            "/archive/source.log",
            "HOST1",
            99,
            "1000",
            None,
            '{"message": "alpha"}',
            "mutable search",
            "{}",
            "Parser-1.0",
            "",
            "",
            "",
        ]

        class FakeClient:
            def __init__(self):
                self.inserts = []
                self.commands = []

            def query_rows_stream(self, query):
                return _Stream([tuple(row)])

            def insert(self, table, rows, column_names=None):
                self.inserts.append((table, rows, column_names))

            def command(self, sql):
                self.commands.append(sql)

        client = FakeClient()
        rewritten = migration._rewrite_rows_to_shadow(
            client,
            columns=columns,
            batch_size=1,
            case_id=None,
            recompute_existing=False,
        )

        self.assertEqual(rewritten, 1)
        self.assertEqual(client.inserts[0][0], migration.SHADOW_TABLE)
        inserted_row = client.inserts[0][1][0]
        self.assertTrue(inserted_row[columns.index("evidence_record_key")].startswith(EVIDENCE_RECORD_KEY_PREFIX))
        self.assertFalse(any("ALTER TABLE events UPDATE" in command for command in client.commands))

    def test_ensure_identity_index_adds_missing_bloom_index(self):
        class FakeClient:
            def __init__(self):
                self.commands = []

            def query(self, sql, parameters=None):
                return SimpleNamespace(result_rows=[])

            def command(self, sql):
                self.commands.append(sql)

        client = FakeClient()

        self.assertTrue(migration.ensure_identity_index(client))
        self.assertTrue(any("ADD INDEX IF NOT EXISTS" in command for command in client.commands))
        self.assertTrue(any("idx_evidence_record_key" in command for command in client.commands))

    def test_buffer_table_is_recreated_when_buffer_schema_diverges(self):
        class FakeClient:
            def __init__(self):
                self.commands = []

            def query(self, sql, parameters=None):
                table = (parameters or {}).get("table_name")
                if "SELECT count() FROM events_buffer" in sql:
                    return SimpleNamespace(result_rows=[(10,)])
                if "SELECT count() FROM events" in sql:
                    return SimpleNamespace(result_rows=[(10,)])
                if "FROM system.tables" in sql and "engine" not in sql.lower():
                    return SimpleNamespace(result_rows=[(1,)])
                if "SELECT engine" in sql:
                    return SimpleNamespace(result_rows=[("Buffer",)])
                if "FROM system.columns" in sql:
                    if table == "events":
                        return SimpleNamespace(result_rows=[
                            ("case_id", ""),
                            ("artifact_type", ""),
                            ("evidence_record_key", ""),
                            ("selector_key", "MATERIALIZED"),
                        ])
                    return SimpleNamespace(result_rows=[
                        ("case_id", ""),
                        ("artifact_type", ""),
                        ("selector_key", "MATERIALIZED"),
                    ])
                return SimpleNamespace(result_rows=[])

            def command(self, sql):
                self.commands.append(sql)

        client = FakeClient()
        migration.ensure_events_buffer_schema(client)

        self.assertIn("OPTIMIZE TABLE events_buffer", client.commands)
        self.assertIn("DROP TABLE IF EXISTS events_buffer", client.commands)
        self.assertTrue(any("ENGINE = Buffer" in command for command in client.commands))

    def test_case_id_scope_does_not_mutate_other_case_empty_keys(self):
        columns = [
            "case_id", "artifact_type", "timestamp", "timestamp_utc", "timestamp_source_tz",
            "source_file", "source_path", "source_host", "case_file_id", "event_id",
            "record_id", "raw_json", "search_blob", "extra_fields", "parser_version",
            "evidence_record_key", "evidence_identity_version", "evidence_identity_quality",
        ]
        base_row = [
            1, "custom_log", datetime(2026, 4, 21, 12), datetime(2026, 4, 21, 12), "UTC",
            "source.log", "/archive/source.log", "HOST1", 99, "1000", None,
            '{"message": "alpha"}', "", "{}", "Parser-1", "", "", "",
        ]
        other_case_row = list(base_row)
        other_case_row[0] = 2
        other_case_row[11] = '{"message": "bravo"}'

        class FakeClient:
            def __init__(self):
                self.inserts = []

            def query_rows_stream(self, query):
                return _Stream([tuple(base_row), tuple(other_case_row)])

            def insert(self, table, rows, column_names=None):
                self.inserts.extend(rows)

        client = FakeClient()
        rewritten = migration._rewrite_rows_to_shadow(
            client,
            columns=columns,
            batch_size=10,
            case_id=1,
            recompute_existing=False,
        )

        self.assertEqual(rewritten, 1)
        first, second = client.inserts
        self.assertTrue(first[columns.index("evidence_record_key")].startswith(EVIDENCE_RECORD_KEY_PREFIX))
        self.assertEqual(second[columns.index("evidence_record_key")], "")
        self.assertEqual(second[columns.index("evidence_identity_version")], "")

    def test_v1_identity_is_upgraded_to_v2_during_migration(self):
        columns = [
            "case_id", "artifact_type", "timestamp", "timestamp_utc", "timestamp_source_tz",
            "source_file", "source_path", "source_host", "case_file_id", "event_id",
            "record_id", "raw_json", "search_blob", "extra_fields", "parser_version",
            "evidence_record_key", "evidence_identity_version", "evidence_identity_quality",
        ]
        row = [
            7, "custom_log", datetime(2026, 4, 21, 12), datetime(2026, 4, 21, 12), "UTC",
            "source.log", "/archive/source.log", "HOST1", 99, "1000", None,
            '{"message": "alpha"}', "", "{}", "Parser-1", "erk:v1:legacy", "1", "fingerprinted",
        ]

        class FakeClient:
            def __init__(self):
                self.inserts = []

            def query_rows_stream(self, query):
                return _Stream([tuple(row)])

            def insert(self, table, rows, column_names=None):
                self.inserts.extend(rows)

        client = FakeClient()
        rewritten = migration._rewrite_rows_to_shadow(
            client,
            columns=columns,
            batch_size=10,
            case_id=None,
            recompute_existing=False,
        )

        self.assertEqual(rewritten, 1)
        inserted = client.inserts[0]
        self.assertTrue(inserted[columns.index("evidence_record_key")].startswith(EVIDENCE_RECORD_KEY_PREFIX))
        self.assertEqual(inserted[columns.index("evidence_identity_version")], "2")

    def test_fully_v2_table_exits_without_shadow_rewrite(self):
        class FakeClient:
            def __init__(self):
                self.commands = []
                self.queries = []

            def query(self, sql, parameters=None):
                self.queries.append((sql, parameters or {}))
                if "FROM system.columns" in sql:
                    return SimpleNamespace(result_rows=[(name, "") for name in ParsedEventColumns])
                if "SELECT engine" in sql:
                    return SimpleNamespace(result_rows=[("Buffer",)])
                if "FROM system.tables" in sql and "total_bytes" in sql:
                    return SimpleNamespace(result_rows=[(1234,)])
                if "FROM system.tables" in sql:
                    table = (parameters or {}).get("table_name")
                    return SimpleNamespace(result_rows=[(1 if table in {"events_buffer"} else 0,)])
                if "system.data_skipping_indices" in sql:
                    return SimpleNamespace(result_rows=[(1,)])
                if "NOT startsWith" in sql:
                    return SimpleNamespace(result_rows=[(0,)])
                if "startsWith" in sql:
                    prefix = (parameters or {}).get("prefix")
                    return SimpleNamespace(result_rows=[(2 if prefix == EVIDENCE_RECORD_KEY_PREFIX else 0,)])
                if "evidence_record_key = ''" in sql:
                    return SimpleNamespace(result_rows=[(0,)])
                if "SELECT count() FROM events_buffer" in sql:
                    return SimpleNamespace(result_rows=[(2,)])
                if "SELECT count() FROM events" in sql:
                    return SimpleNamespace(result_rows=[(2,)])
                return SimpleNamespace(result_rows=[(0,)])

            def command(self, sql):
                self.commands.append(sql)

        client = FakeClient()
        rewritten = migration.backfill_identity_columns(client)

        self.assertEqual(rewritten, 0)
        self.assertIn("OPTIMIZE TABLE events_buffer", client.commands)
        self.assertFalse(any("CREATE TABLE events_evidence_identity_backfill" in command for command in client.commands))
        self.assertFalse(any("RENAME TABLE events TO" in command for command in client.commands))

    def test_existing_previous_table_blocks_rewrite_by_default(self):
        class FakeClient:
            def __init__(self):
                self.commands = []

            def query(self, sql, parameters=None):
                if "FROM system.columns" in sql:
                    return SimpleNamespace(result_rows=[(name, "") for name in ParsedEventColumns])
                if "SELECT engine" in sql:
                    return SimpleNamespace(result_rows=[("Buffer",)])
                if "FROM system.tables" in sql and "total_bytes" in sql:
                    return SimpleNamespace(result_rows=[(1234,)])
                if "FROM system.tables" in sql:
                    table = (parameters or {}).get("table_name")
                    return SimpleNamespace(result_rows=[(1 if table in {"events_buffer", migration.OLD_TABLE} else 0,)])
                if "system.data_skipping_indices" in sql:
                    return SimpleNamespace(result_rows=[(1,)])
                if "NOT startsWith" in sql or "startsWith" in sql:
                    return SimpleNamespace(result_rows=[(0,)])
                if "evidence_record_key = ''" in sql:
                    return SimpleNamespace(result_rows=[(1,)])
                if "SELECT count() FROM events_buffer" in sql:
                    return SimpleNamespace(result_rows=[(1,)])
                if "SELECT count() FROM events" in sql:
                    return SimpleNamespace(result_rows=[(1,)])
                return SimpleNamespace(result_rows=[(0,)])

            def command(self, sql):
                self.commands.append(sql)

        client = FakeClient()
        with self.assertRaisesRegex(RuntimeError, "already exists"):
            migration.backfill_identity_columns(client)

        self.assertFalse(any("CREATE TABLE events_evidence_identity_backfill" in command for command in client.commands))

    def test_unsafe_buffer_aborts_before_shadow_snapshot(self):
        class FakeClient:
            def __init__(self):
                self.commands = []

            def query(self, sql, parameters=None):
                if "FROM system.columns" in sql:
                    return SimpleNamespace(result_rows=[(name, "") for name in ParsedEventColumns])
                if "SELECT engine" in sql:
                    return SimpleNamespace(result_rows=[("Buffer",)])
                if "FROM system.tables" in sql:
                    return SimpleNamespace(result_rows=[(1 if (parameters or {}).get("table_name") == "events_buffer" else 0,)])
                if "SELECT count() FROM events_buffer" in sql:
                    return SimpleNamespace(result_rows=[(3,)])
                if "SELECT count() FROM events" in sql:
                    return SimpleNamespace(result_rows=[(1,)])
                return SimpleNamespace(result_rows=[(0,)])

            def command(self, sql):
                self.commands.append(sql)

        client = FakeClient()
        with self.assertRaisesRegex(RuntimeError, "events_buffer still has pending rows"):
            migration.backfill_identity_columns(client)

        self.assertIn("OPTIMIZE TABLE events_buffer", client.commands)
        self.assertFalse(any("CREATE TABLE events_evidence_identity_backfill" in command for command in client.commands))

    def test_status_reports_version_distribution_and_buffer_state(self):
        class FakeClient:
            def query(self, sql, parameters=None):
                if "SELECT engine" in sql:
                    return SimpleNamespace(result_rows=[("Buffer",)])
                if "FROM system.tables" in sql:
                    return SimpleNamespace(result_rows=[(1,)])
                if "system.data_skipping_indices" in sql:
                    return SimpleNamespace(result_rows=[(1,)])
                if "NOT startsWith" in sql:
                    return SimpleNamespace(result_rows=[(1,)])
                if "startsWith" in sql:
                    return SimpleNamespace(result_rows=[(5 if (parameters or {}).get("prefix") == EVIDENCE_RECORD_KEY_PREFIX else 2,)])
                if "evidence_record_key = ''" in sql:
                    return SimpleNamespace(result_rows=[(3,)])
                if "SELECT count() FROM events_buffer" in sql:
                    return SimpleNamespace(result_rows=[(11,)])
                if "SELECT count() FROM events" in sql:
                    return SimpleNamespace(result_rows=[(10,)])
                return SimpleNamespace(result_rows=[(0,)])

        from io import StringIO
        from contextlib import redirect_stdout

        output = StringIO()
        with redirect_stdout(output):
            migration.print_status(FakeClient())

        status = output.getvalue()
        self.assertIn("erk:v1 evidence_record_key rows: 2", status)
        self.assertIn("erk:v2 evidence_record_key rows: 5", status)
        self.assertIn("pending_rows=1", status)


ParsedEventColumns = migration.ParsedEvent.clickhouse_columns()


if __name__ == "__main__":
    unittest.main()
