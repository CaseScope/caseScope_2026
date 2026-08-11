import inspect
import importlib.util
import os
import shutil
import subprocess
import sys
import types
import unittest
from contextlib import contextmanager
from datetime import datetime
from multiprocessing import Manager
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
    clickhouse_module.get_migration_client = lambda: None
    clickhouse_module.migration_source_query_settings = lambda: {
        "max_threads": 1,
        "max_block_size": 8192,
        "max_execution_time": 0,
    }
    clickhouse_module.migration_client_effective_settings = lambda: {
        "CLICKHOUSE_HOST": "localhost",
        "CLICKHOUSE_PORT": 8123,
        "CLICKHOUSE_DATABASE": "casescope",
        "CLICKHOUSE_USER": "default",
        "max_threads": 1,
        "max_block_size": 8192,
        "max_execution_time": 0,
        "max_memory_usage": None,
        "send_receive_timeout": 86400,
    }
    utils_package.clickhouse = clickhouse_module
    utils_package.evidence_identity = evidence_identity_module
    sys.modules["utils"] = utils_package
    sys.modules["utils.clickhouse"] = clickhouse_module
    sys.modules["utils.evidence_identity"] = evidence_identity_module
    from migrations import add_evidence_record_identity as migration
    from migrations import add_events_table as events_table_migration
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


class _FailingStream:
    def __init__(self, rows, exc):
        self.rows = rows
        self.exc = exc

    def __enter__(self):
        def _iter():
            for row in self.rows:
                yield row
            raise self.exc

        return _iter()

    def __exit__(self, exc_type, exc, tb):
        return False


def _event_row(columns, *, case_id=7, raw_json='{"message": "alpha"}', evidence_key=""):
    defaults = {
        "case_id": case_id,
        "artifact_type": "custom_log",
        "timestamp": datetime(2026, 4, 21, 12),
        "timestamp_utc": datetime(2026, 4, 21, 12),
        "timestamp_source_tz": "UTC",
        "source_file": "source.log",
        "source_path": "/archive/source.log",
        "source_host": "HOST1",
        "case_file_id": 99,
        "event_id": "1000",
        "record_id": None,
        "raw_json": raw_json,
        "search_blob": "",
        "extra_fields": "{}",
        "parser_version": "Parser-1",
        "evidence_record_key": evidence_key,
        "evidence_identity_version": "",
        "evidence_identity_quality": "",
    }
    return tuple(defaults.get(column, None) for column in columns)


class _RewriteFakeClient:
    def __init__(
        self,
        *,
        source_rows=100,
        final_source_rows=None,
        shadow_count_override=None,
    ):
        self.source_rows = source_rows
        self.final_source_rows = final_source_rows
        self.shadow_count_override = shadow_count_override
        self.tables = {"events", "events_buffer"}
        self.commands = []
        self.inserts = []
        self.operations = []
        self.after_fence_source_count_calls = 0
        self.swapped = False
        self.last_stream_query = None
        self.last_stream_parameters = None
        self.last_stream_settings = None
        self.stream_rows = [
            _event_row(ParsedEventColumns, raw_json=f'{{"message": "row-{index}"}}')
            for index in range(source_rows)
        ]

    def query(self, sql, parameters=None):
        parameters = parameters or {}
        compact = " ".join(sql.split())
        table = parameters.get("table_name")
        if "FROM system.columns" in sql:
            return SimpleNamespace(result_rows=[(name, "") for name in ParsedEventColumns])
        if "SELECT engine" in sql:
            return SimpleNamespace(result_rows=[("Buffer",)] if table in self.tables else [])
        if "FROM system.tables" in sql and "total_bytes" in sql:
            return SimpleNamespace(result_rows=[(1234,)])
        if "FROM system.tables" in sql:
            return SimpleNamespace(result_rows=[(1 if table in self.tables else 0,)])
        if "system.data_skipping_indices" in sql:
            return SimpleNamespace(result_rows=[(1,)])
        if compact == "SELECT DISTINCT case_id FROM events ORDER BY case_id":
            return SimpleNamespace(result_rows=[(7,)])
        if "toStartOfInterval(timestamp_utc" in sql:
            return SimpleNamespace(result_rows=[(0,)])
        inserted_rows = [
            row
            for _table, rows, _columns in self.inserts
            for row in rows
        ]
        query_targets_shadow = f"FROM {migration.SHADOW_TABLE}" in compact
        query_targets_active_events = "FROM events " in compact or compact.endswith("FROM events")
        use_inserted_rows = query_targets_shadow or (self.swapped and query_targets_active_events)
        active_rows = inserted_rows if use_inserted_rows else []
        key_index = ParsedEventColumns.index("evidence_record_key")
        version_index = ParsedEventColumns.index("evidence_identity_version")
        quality_index = ParsedEventColumns.index("evidence_identity_quality")
        valid_v2 = lambda value: str(value or "").startswith(EVIDENCE_RECORD_KEY_PREFIX) and len(str(value or "")) == len(EVIDENCE_RECORD_KEY_PREFIX) + 64
        if compact == f"SELECT count() FROM {migration.SHADOW_TABLE}":
            count = self.shadow_count_override
            if count is None:
                count = sum(len(rows) for _table, rows, _columns in self.inserts)
            self.operations.append("count_shadow")
            return SimpleNamespace(result_rows=[(count,)])
        if "SELECT count() FROM events_buffer" in compact:
            self.operations.append("count_buffer")
            return SimpleNamespace(result_rows=[(self.source_rows,)])
        if compact == "SELECT count() FROM events":
            self.operations.append("count_events")
            if "events_buffer" not in self.tables:
                self.after_fence_source_count_calls += 1
                if self.after_fence_source_count_calls >= 2 and self.final_source_rows is not None:
                    return SimpleNamespace(result_rows=[(self.final_source_rows,)])
            return SimpleNamespace(result_rows=[(self.source_rows,)])
        if "evidence_record_key = ''" in sql:
            return SimpleNamespace(result_rows=[(
                sum(1 for row in active_rows if row[key_index] == "") if use_inserted_rows else self.source_rows
            ,)])
        if "NOT match(evidence_record_key" in sql:
            return SimpleNamespace(result_rows=[(0,)])
        if "match(evidence_record_key" in sql and "evidence_identity_version" in sql:
            return SimpleNamespace(result_rows=[(
                sum(
                    1
                    for row in active_rows
                    if valid_v2(row[key_index])
                    and (row[version_index] != "2" or row[quality_index] == "")
                )
                if use_inserted_rows
                else 0
            ,)])
        if "match(evidence_record_key" in sql:
            return SimpleNamespace(result_rows=[(
                sum(1 for row in active_rows if valid_v2(row[key_index])) if use_inserted_rows else 0
            ,)])
        if "startsWith" in sql or "NOT startsWith" in sql:
            return SimpleNamespace(result_rows=[(0,)])
        return SimpleNamespace(result_rows=[(0,)])

    def query_rows_stream(self, query, parameters=None, settings=None):
        self.operations.append("shadow_copy")
        self.last_stream_query = query
        self.last_stream_parameters = parameters or {}
        self.last_stream_settings = settings or {}
        return _Stream(self.stream_rows)

    def insert(self, table, rows, column_names=None):
        self.operations.append(f"insert:{table}")
        self.inserts.append((table, rows, column_names))

    def command(self, sql):
        self.commands.append(sql)
        compact = " ".join(sql.split())
        if compact == "OPTIMIZE TABLE events_buffer":
            self.operations.append("drain_buffer")
        elif compact == "DROP TABLE IF EXISTS events_buffer":
            self.operations.append("drop_buffer")
            self.tables.discard("events_buffer")
        elif compact == f"CREATE TABLE {migration.SHADOW_TABLE} AS events":
            self.operations.append("create_shadow")
            self.tables.add(migration.SHADOW_TABLE)
        elif compact == f"DROP TABLE IF EXISTS {migration.SHADOW_TABLE}":
            self.operations.append("drop_shadow")
            self.tables.discard(migration.SHADOW_TABLE)
        elif compact.startswith("RENAME TABLE events TO"):
            self.operations.append("rename_swap")
            self.swapped = True
            self.tables.add(migration.OLD_TABLE)
            self.tables.discard(migration.SHADOW_TABLE)
        elif "ENGINE = Buffer" in sql:
            self.operations.append("create_buffer")
            self.tables.add("events_buffer")


class _NonBufferEventsBufferClient:
    def __init__(self):
        self.commands = []
        self.tables = {"events", "events_buffer"}

    def query(self, sql, parameters=None):
        parameters = parameters or {}
        compact = " ".join(sql.split())
        table = parameters.get("table_name")
        if "SELECT engine" in sql:
            return SimpleNamespace(result_rows=[("MergeTree",)] if table in self.tables else [])
        if "FROM system.tables" in sql:
            return SimpleNamespace(result_rows=[(1 if table in self.tables else 0,)])
        if "FROM system.columns" in sql:
            return SimpleNamespace(result_rows=[
                ("case_id", ""),
                ("artifact_type", ""),
                ("evidence_record_key", ""),
            ])
        if compact == "SELECT count() FROM events":
            return SimpleNamespace(result_rows=[(100,)])
        if compact == "SELECT count() FROM events_buffer":
            return SimpleNamespace(result_rows=[(100,)])
        return SimpleNamespace(result_rows=[(0,)])

    def command(self, sql):
        self.commands.append(sql)
        compact = " ".join(sql.split())
        if compact in {
            "DROP TABLE IF EXISTS events_buffer",
            "DROP TABLE events_buffer",
            "DETACH TABLE events_buffer",
        }:
            self.tables.discard("events_buffer")
        if "ENGINE = Buffer" in sql:
            self.tables.add("events_buffer")


class _PreIdentitySchemaClient:
    def __init__(self, *, source_rows):
        self.source_rows = source_rows
        self.commands = []
        self.inserts = []
        self.queries = []
        self.tables = {"events", "events_buffer"}

    def query(self, sql, parameters=None):
        self.queries.append((sql, parameters or {}))
        compact = " ".join(sql.split())
        if (
            "evidence_record_key" in sql
            and "system.data_skipping_indices" not in sql
            and "FROM system.columns" not in sql
        ):
            raise AssertionError(f"identity-column query should not run before schema install: {sql}")
        if "FROM system.columns" in sql:
            table = (parameters or {}).get("table_name")
            if table == "events":
                return SimpleNamespace(result_rows=[
                    ("case_id", ""),
                    ("artifact_type", ""),
                    ("timestamp_utc", ""),
                ])
            return SimpleNamespace(result_rows=[])
        if "SELECT engine" in sql:
            table = (parameters or {}).get("table_name")
            return SimpleNamespace(result_rows=[("Buffer",)] if table == "events_buffer" else [])
        if "FROM system.tables" in sql and "total_bytes" in sql:
            table = (parameters or {}).get("table_name")
            return SimpleNamespace(result_rows=[(1234,)] if table == "events" else [])
        if "FROM system.tables" in sql:
            table = (parameters or {}).get("table_name")
            return SimpleNamespace(result_rows=[(1 if table in self.tables else 0,)])
        if "system.data_skipping_indices" in sql:
            return SimpleNamespace(result_rows=[])
        if compact == "SELECT DISTINCT case_id FROM events ORDER BY case_id":
            return SimpleNamespace(result_rows=[(7,)] if self.source_rows else [])
        if compact == "SELECT count() FROM events_buffer":
            return SimpleNamespace(result_rows=[(self.source_rows,)])
        if compact.startswith("SELECT count() FROM events"):
            return SimpleNamespace(result_rows=[(self.source_rows,)])
        return SimpleNamespace(result_rows=[(0,)])

    def command(self, sql):
        self.commands.append(sql)

    def insert(self, table, rows, column_names=None):
        self.inserts.append((table, rows, column_names))


class EvidenceIdentityMigrationTestCase(unittest.TestCase):
    def test_backfill_strategy_does_not_contain_per_event_alter_update(self):
        source = inspect.getsource(migration.backfill_identity_columns)
        source += inspect.getsource(migration._rewrite_rows_to_shadow)
        source += inspect.getsource(migration._copy_source_window_to_shadow)

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

            def query(self, sql, parameters=None):
                compact = " ".join(sql.split())
                if compact == "SELECT DISTINCT case_id FROM events ORDER BY case_id":
                    return SimpleNamespace(result_rows=[(7,)])
                if compact == "SELECT count() FROM events":
                    return SimpleNamespace(result_rows=[(1,)])
                return SimpleNamespace(result_rows=[(0,)])

            def query_rows_stream(self, query, parameters=None, settings=None):
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
                self.index_exists = False

            def query(self, sql, parameters=None):
                if "FROM system.columns" in sql:
                    return SimpleNamespace(result_rows=[(name,) for name in ParsedEventColumns])
                if "system.data_skipping_indices" in sql:
                    return SimpleNamespace(result_rows=[(migration.IDENTITY_INDEX_NAME,)] if self.index_exists else [])
                return SimpleNamespace(result_rows=[])

            def command(self, sql):
                self.commands.append(sql)
                if "ADD INDEX" in sql:
                    self.index_exists = True

        client = FakeClient()

        self.assertTrue(migration.ensure_identity_index(client))
        self.assertEqual(
            client.commands,
            [
                "ALTER TABLE events ADD INDEX IF NOT EXISTS "
                "idx_evidence_record_key evidence_record_key TYPE bloom_filter(0.01) GRANULARITY 4"
            ],
        )
        self.assertFalse(any("IF NOT EXISTS INDEX" in command for command in client.commands))

    def test_buffer_table_is_recreated_when_buffer_schema_diverges(self):
        class FakeClient:
            def __init__(self):
                self.commands = []
                self.events_buffer_exists = True

            def query(self, sql, parameters=None):
                table = (parameters or {}).get("table_name")
                if "SELECT count() FROM events_buffer" in sql:
                    return SimpleNamespace(result_rows=[(10,)])
                if "SELECT count() FROM events" in sql:
                    return SimpleNamespace(result_rows=[(10,)])
                if "FROM system.tables" in sql and "engine" not in sql.lower():
                    if table == "events_buffer":
                        return SimpleNamespace(result_rows=[(1 if self.events_buffer_exists else 0,)])
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
                        *([("evidence_record_key", "")] if self.events_buffer_exists and any("ENGINE = Buffer" in command for command in self.commands) else []),
                        ("selector_key", "MATERIALIZED"),
                    ])
                return SimpleNamespace(result_rows=[])

            def command(self, sql):
                self.commands.append(sql)
                if "DROP TABLE IF EXISTS events_buffer" in sql:
                    self.events_buffer_exists = False
                if "ENGINE = Buffer" in sql:
                    self.events_buffer_exists = True

        client = FakeClient()
        migration.ensure_events_buffer_schema(client)

        self.assertIn("OPTIMIZE TABLE events_buffer", client.commands)
        self.assertIn("DROP TABLE IF EXISTS events_buffer", client.commands)
        self.assertTrue(any("ENGINE = Buffer" in command for command in client.commands))

    def test_non_buffer_events_buffer_aborts_without_drop_or_recreation(self):
        client = _NonBufferEventsBufferClient()

        with self.assertRaisesRegex(RuntimeError, "not a Buffer-engine table"):
            migration.fence_events_buffer_ingestion(client, context="test fence")

        command_text = "\n".join(client.commands).upper()
        self.assertNotIn("DROP TABLE", command_text)
        self.assertNotIn("DETACH TABLE", command_text)
        self.assertNotIn("ENGINE = BUFFER", command_text)
        self.assertIn("events_buffer", client.tables)

    def test_identity_buffer_schema_path_rejects_non_buffer_events_buffer(self):
        client = _NonBufferEventsBufferClient()

        with self.assertRaisesRegex(RuntimeError, "not a Buffer-engine table"):
            migration.ensure_events_buffer_schema(client)

        self.assertEqual(client.commands, [])
        self.assertIn("events_buffer", client.tables)

    def test_events_schema_path_rejects_non_buffer_events_buffer(self):
        client = _NonBufferEventsBufferClient()

        with self.assertRaisesRegex(RuntimeError, "not a Buffer-engine table"):
            events_table_migration._ensure_events_buffer_schema(client)

        self.assertEqual(client.commands, [])
        self.assertIn("events_buffer", client.tables)

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

            def query(self, sql, parameters=None):
                compact = " ".join(sql.split())
                if compact == "SELECT DISTINCT case_id FROM events ORDER BY case_id":
                    return SimpleNamespace(result_rows=[(1,), (2,)])
                if compact == "SELECT count() FROM events":
                    return SimpleNamespace(result_rows=[(2,)])
                return SimpleNamespace(result_rows=[(0,)])

            def query_rows_stream(self, query, parameters=None, settings=None):
                if (parameters or {}).get("case_id") == 1:
                    return _Stream([tuple(base_row)])
                return _Stream([tuple(other_case_row)])

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

            def query(self, sql, parameters=None):
                compact = " ".join(sql.split())
                if compact == "SELECT DISTINCT case_id FROM events ORDER BY case_id":
                    return SimpleNamespace(result_rows=[(7,)])
                if compact == "SELECT count() FROM events":
                    return SimpleNamespace(result_rows=[(1,)])
                return SimpleNamespace(result_rows=[(0,)])

            def query_rows_stream(self, query, parameters=None, settings=None):
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

    def test_unknown_and_malformed_keys_are_recomputed_to_valid_v2(self):
        columns = [
            "case_id", "artifact_type", "timestamp", "timestamp_utc", "timestamp_source_tz",
            "source_file", "source_path", "source_host", "case_file_id", "event_id",
            "record_id", "raw_json", "search_blob", "extra_fields", "parser_version",
            "evidence_record_key", "evidence_identity_version", "evidence_identity_quality",
        ]
        bad_keys = ["garbage-key", "erk:v3:abc", "erk:v2:garbage"]
        rows = [
            list(_event_row(columns, raw_json=f'{{"message": "bad-{index}"}}', evidence_key=bad_key))
            for index, bad_key in enumerate(bad_keys)
        ]

        class FakeClient:
            def __init__(self):
                self.inserts = []

            def query(self, sql, parameters=None):
                compact = " ".join(sql.split())
                if compact == "SELECT DISTINCT case_id FROM events ORDER BY case_id":
                    return SimpleNamespace(result_rows=[(7,)])
                if compact == "SELECT count() FROM events":
                    return SimpleNamespace(result_rows=[(len(rows),)])
                return SimpleNamespace(result_rows=[(0,)])

            def query_rows_stream(self, query, parameters=None, settings=None):
                return _Stream([tuple(row) for row in rows])

            def insert(self, table, inserted_rows, column_names=None):
                self.inserts.extend(inserted_rows)

        client = FakeClient()
        rewritten = migration._rewrite_rows_to_shadow(
            client,
            columns=columns,
            batch_size=10,
            case_id=None,
            recompute_existing=False,
        )

        self.assertEqual(rewritten, 3)
        for inserted in client.inserts:
            key = inserted[columns.index("evidence_record_key")]
            self.assertRegex(key, r"^erk:v2:[0-9a-f]{64}$")
            self.assertEqual(inserted[columns.index("evidence_identity_version")], "2")
            self.assertNotEqual(inserted[columns.index("evidence_identity_quality")], "")

    def test_valid_v2_key_preserved_while_missing_metadata_is_repaired(self):
        columns = [
            "case_id", "artifact_type", "timestamp", "timestamp_utc", "timestamp_source_tz",
            "source_file", "source_path", "source_host", "case_file_id", "event_id",
            "record_id", "raw_json", "search_blob", "extra_fields", "parser_version",
            "evidence_record_key", "evidence_identity_version", "evidence_identity_quality",
        ]
        valid_existing_key = "erk:v2:" + ("a" * 64)
        row = list(_event_row(columns, evidence_key=valid_existing_key))

        class FakeClient:
            def __init__(self):
                self.inserts = []

            def query(self, sql, parameters=None):
                compact = " ".join(sql.split())
                if compact == "SELECT DISTINCT case_id FROM events ORDER BY case_id":
                    return SimpleNamespace(result_rows=[(7,)])
                if compact == "SELECT count() FROM events":
                    return SimpleNamespace(result_rows=[(1,)])
                return SimpleNamespace(result_rows=[(0,)])

            def query_rows_stream(self, query, parameters=None, settings=None):
                return _Stream([tuple(row)])

            def insert(self, table, inserted_rows, column_names=None):
                self.inserts.extend(inserted_rows)

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
        self.assertEqual(inserted[columns.index("evidence_record_key")], valid_existing_key)
        self.assertEqual(inserted[columns.index("evidence_identity_version")], "2")
        self.assertNotEqual(inserted[columns.index("evidence_identity_quality")], "")

    def test_rewrite_required_for_unknown_and_invalid_metadata(self):
        self.assertTrue(
            migration._rewrite_required(
                {"empty": 0, "v1": 0, "v2": 1, "unknown": 1, "metadata_invalid": 0},
                scoped_rows=1,
                recompute_existing=False,
            )
        )
        self.assertTrue(
            migration._rewrite_required(
                {"empty": 0, "v1": 0, "v2": 1, "unknown": 0, "metadata_invalid": 1},
                scoped_rows=1,
                recompute_existing=False,
            )
        )

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
                if "NOT match(evidence_record_key" in sql:
                    return SimpleNamespace(result_rows=[(0,)])
                if "match(evidence_record_key" in sql and "evidence_identity_version" in sql:
                    return SimpleNamespace(result_rows=[(0,)])
                if "match(evidence_record_key" in sql:
                    return SimpleNamespace(result_rows=[(2,)])
                if "NOT startsWith" in sql:
                    return SimpleNamespace(result_rows=[(0,)])
                if "startsWith" in sql:
                    prefix = (parameters or {}).get("prefix")
                    return SimpleNamespace(result_rows=[(0,)])
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
        self.assertNotIn("OPTIMIZE TABLE events_buffer", client.commands)
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
                if "system.data_skipping_indices" in sql:
                    return SimpleNamespace(result_rows=[(1,)])
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

    def test_buffer_is_removed_before_authoritative_source_snapshot(self):
        client = _RewriteFakeClient(source_rows=100)

        migration.backfill_identity_columns(client, batch_size=200)

        drop_index = client.operations.index("drop_buffer")
        post_fence_count_index = next(
            index for index, operation in enumerate(client.operations)
            if operation == "count_events" and index > drop_index
        )
        create_shadow_index = client.operations.index("create_shadow")
        shadow_copy_index = client.operations.index("shadow_copy")

        self.assertLess(client.operations.index("drain_buffer"), drop_index)
        self.assertLess(drop_index, post_fence_count_index)
        self.assertLess(post_fence_count_index, create_shadow_index)
        self.assertLess(create_shadow_index, shadow_copy_index)

    def test_source_count_change_during_copy_aborts_before_swap(self):
        client = _RewriteFakeClient(source_rows=100, final_source_rows=101)

        with self.assertRaisesRegex(RuntimeError, "Source events row count changed"):
            migration.backfill_identity_columns(client, batch_size=200)

        self.assertIn("count_shadow", client.operations)
        self.assertNotIn("rename_swap", client.operations)
        self.assertNotIn("create_buffer", client.operations)
        self.assertIn("events", client.tables)
        self.assertNotIn(migration.OLD_TABLE, client.tables)

    def test_shadow_validation_failure_does_not_recreate_buffer_before_swap(self):
        client = _RewriteFakeClient(source_rows=100, shadow_count_override=99)

        with self.assertRaisesRegex(RuntimeError, "Shadow row count mismatch"):
            migration.backfill_identity_columns(client, batch_size=200)

        self.assertIn("count_shadow", client.operations)
        self.assertNotIn("rename_swap", client.operations)
        self.assertNotIn("create_buffer", client.operations)
        self.assertNotIn("events_buffer", client.tables)

    def test_bad_shadow_identity_validation_aborts_before_swap_and_buffer_recreation(self):
        class BadShadowClient(_RewriteFakeClient):
            def query(self, sql, parameters=None):
                compact = " ".join(sql.split())
                if f"FROM {migration.SHADOW_TABLE}" in compact and "NOT match(evidence_record_key" in sql:
                    return SimpleNamespace(result_rows=[(1,)])
                return super().query(sql, parameters=parameters)

        client = BadShadowClient(source_rows=100)

        with self.assertRaisesRegex(RuntimeError, "validation failed on events_evidence_identity_backfill"):
            migration.backfill_identity_columns(client, batch_size=200)

        self.assertIn("count_shadow", client.operations)
        self.assertNotIn("rename_swap", client.operations)
        self.assertNotIn("create_buffer", client.operations)
        self.assertNotIn("events_buffer", client.tables)
        self.assertNotIn(migration.OLD_TABLE, client.tables)

    def test_lost_rewrite_lease_immediately_before_swap_aborts_without_buffer_recreation(self):
        assert_calls = {"count": 0}

        @contextmanager
        def guarded_rewrite(*args, **kwargs):
            def assert_active():
                assert_calls["count"] += 1
                if assert_calls["count"] >= 3:
                    raise RuntimeError("Lost Redis-backed destructive rewrite lock; refusing to continue")

            yield {"assert_active": assert_active}

        client = _RewriteFakeClient(source_rows=100)
        original_guard = migration.destructive_event_rewrite_guard
        migration.destructive_event_rewrite_guard = guarded_rewrite
        try:
            with self.assertRaisesRegex(RuntimeError, "Lost Redis-backed destructive rewrite lock"):
                migration.backfill_identity_columns(client, batch_size=200)
        finally:
            migration.destructive_event_rewrite_guard = original_guard

        self.assertIn("count_shadow", client.operations)
        self.assertNotIn("rename_swap", client.operations)
        self.assertNotIn("create_buffer", client.operations)
        self.assertNotIn("events_buffer", client.tables)
        self.assertNotIn(migration.OLD_TABLE, client.tables)

    def test_rogue_late_ingestion_cannot_use_removed_buffer_target(self):
        client = _RewriteFakeClient(source_rows=100)

        migration.fence_events_buffer_ingestion(client, context="test fence")

        self.assertNotIn("events_buffer", client.tables)
        self.assertIn("drop_buffer", client.operations)

    def test_successful_rewrite_recreates_buffer_only_after_swap(self):
        client = _RewriteFakeClient(source_rows=100)

        migration.backfill_identity_columns(client, batch_size=200)

        self.assertLess(client.operations.index("rename_swap"), client.operations.index("create_buffer"))
        self.assertIn("events_buffer", client.tables)

    def test_dry_run_and_status_are_write_free(self):
        forbidden = (
            "ALTER", "CREATE", "DROP", "DETACH", "ATTACH", "RENAME", "OPTIMIZE",
            "INSERT", "UPDATE", "DELETE", "MATERIALIZE",
        )

        for args in (["--dry-run"], ["--status"]):
            client = _RewriteFakeClient(source_rows=100)
            original_get_client = migration.get_migration_client
            migration.get_migration_client = lambda: client
            try:
                from io import StringIO
                from contextlib import redirect_stdout

                with redirect_stdout(StringIO()):
                    migration.migrate(args)
            finally:
                migration.get_migration_client = original_get_client

            self.assertEqual(client.inserts, [])
            self.assertEqual(client.commands, [])
            self.assertFalse(
                any(token in command.upper() for command in client.commands for token in forbidden)
            )

    def test_status_reports_version_distribution_and_buffer_state(self):
        class FakeClient:
            def query(self, sql, parameters=None):
                if "FROM system.columns" in sql:
                    return SimpleNamespace(result_rows=[(name, "") for name in ParsedEventColumns])
                if "SELECT engine" in sql:
                    return SimpleNamespace(result_rows=[("Buffer",)])
                if "FROM system.tables" in sql:
                    return SimpleNamespace(result_rows=[(1,)])
                if "system.data_skipping_indices" in sql:
                    return SimpleNamespace(result_rows=[(1,)])
                if "NOT match(evidence_record_key" in sql:
                    return SimpleNamespace(result_rows=[(1,)])
                if "match(evidence_record_key" in sql and "evidence_identity_version" in sql:
                    return SimpleNamespace(result_rows=[(1,)])
                if "match(evidence_record_key" in sql:
                    return SimpleNamespace(result_rows=[(5,)])
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

    def test_status_before_identity_columns_reports_unavailable_without_writes(self):
        client = _PreIdentitySchemaClient(source_rows=100)
        original_get_client = migration.get_migration_client
        migration.get_migration_client = lambda: client
        try:
            from io import StringIO
            from contextlib import redirect_stdout

            output = StringIO()
            with redirect_stdout(output):
                migration.migrate(["--status"])
        finally:
            migration.get_migration_client = original_get_client

        status = output.getvalue()
        self.assertIn("events table present: true", status)
        self.assertIn("events rows: 100", status)
        self.assertIn("Evidence Identity schema installed: false", status)
        self.assertIn("missing identity columns: evidence_record_key", status)
        self.assertIn("erk:v1 evidence_record_key rows: unavailable", status)
        self.assertEqual(client.commands, [])
        self.assertEqual(client.inserts, [])

    def test_dry_run_before_identity_columns_plans_rewrite_without_writes(self):
        client = _PreIdentitySchemaClient(source_rows=100)
        original_get_client = migration.get_migration_client
        migration.get_migration_client = lambda: client
        try:
            from io import StringIO
            from contextlib import redirect_stdout

            output = StringIO()
            with redirect_stdout(output):
                migration.migrate(["--dry-run"])
        finally:
            migration.get_migration_client = original_get_client

        dry_run = output.getvalue()
        self.assertIn("schema change required: true", dry_run)
        self.assertIn("identity rewrite required: true", dry_run)
        self.assertIn("v1 keys to upgrade: unavailable", dry_run)
        self.assertIn("empty keys to generate: unavailable", dry_run)
        self.assertIn("Dry run only; no ClickHouse DDL or data writes were executed", dry_run)
        self.assertEqual(client.commands, [])
        self.assertEqual(client.inserts, [])

    def test_dry_run_before_identity_columns_with_zero_events_skips_rewrite(self):
        client = _PreIdentitySchemaClient(source_rows=0)
        original_get_client = migration.get_migration_client
        migration.get_migration_client = lambda: client
        try:
            from io import StringIO
            from contextlib import redirect_stdout

            output = StringIO()
            with redirect_stdout(output):
                migration.migrate(["--dry-run"])
        finally:
            migration.get_migration_client = original_get_client

        dry_run = output.getvalue()
        self.assertIn("schema change required: true", dry_run)
        self.assertIn("identity rewrite required: false", dry_run)
        self.assertIn("full table copy required: false", dry_run)
        self.assertEqual(client.commands, [])
        self.assertEqual(client.inserts, [])

    def test_migration_import_does_not_require_secret_key(self):
        env = os.environ.copy()
        env.pop("SECRET_KEY", None)
        env.setdefault("CLICKHOUSE_HOST", "localhost")
        env.setdefault("CLICKHOUSE_PORT", "8123")
        env.setdefault("CLICKHOUSE_DATABASE", "casescope")
        env.setdefault("CLICKHOUSE_USER", "default")
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import migrations.add_evidence_record_identity as m; "
                "from utils.clickhouse import migration_client_effective_settings as s; "
                "print(m.IDENTITY_INDEX_NAME, s()['max_execution_time'])",
            ],
            cwd=REPO_ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("idx_evidence_record_key 0", result.stdout)

    def test_web_config_still_requires_secret_key(self):
        env = os.environ.copy()
        env.pop("SECRET_KEY", None)
        result = subprocess.run(
            [sys.executable, "-c", "import config"],
            cwd=REPO_ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SECRET_KEY environment variable is not set", result.stderr)

    def test_add_identity_columns_converges_partial_schema_combinations(self):
        base_columns = {"case_id", "artifact_type", "timestamp_utc"}
        combinations = [
            set(),
            {"evidence_record_key"},
            {"evidence_record_key", "evidence_identity_version"},
            {"evidence_identity_version", "evidence_identity_quality"},
        ]

        class FakeClient:
            def __init__(self, identity_columns):
                self.columns = set(base_columns) | set(identity_columns)
                self.commands = []

            def query(self, sql, parameters=None):
                if "FROM system.columns" in sql:
                    return SimpleNamespace(result_rows=[(name,) for name in sorted(self.columns)])
                return SimpleNamespace(result_rows=[])

            def command(self, sql):
                self.commands.append(sql)
                for column in migration.IDENTITY_COLUMNS:
                    if f"ADD COLUMN IF NOT EXISTS {column} " in sql:
                        self.columns.add(column)

        for identity_columns in combinations:
            with self.subTest(identity_columns=sorted(identity_columns)):
                client = FakeClient(identity_columns)
                migration.add_identity_columns(client)
                self.assertTrue(set(migration.IDENTITY_COLUMNS).issubset(client.columns))

    def test_source_query_uses_case_scope_settings_and_no_order_by(self):
        client = _RewriteFakeClient(source_rows=2)

        migration._rewrite_rows_to_shadow(
            client,
            columns=ParsedEventColumns,
            batch_size=10,
            case_id=None,
            recompute_existing=False,
        )

        self.assertIn("WHERE case_id = {case_id:UInt32}", client.last_stream_query)
        self.assertIn("timestamp_utc >=", client.last_stream_query)
        self.assertNotIn("ORDER BY", client.last_stream_query.upper())
        self.assertEqual(
            client.last_stream_parameters,
            {"case_id": 7, "window_start_ms": 0, "window_end_ms": 900000},
        )
        self.assertEqual(client.last_stream_settings["max_threads"], 1)
        self.assertEqual(client.last_stream_settings["max_block_size"], 8192)
        self.assertEqual(client.last_stream_settings["max_execution_time"], 0)

    def test_source_query_streams_each_case_time_window(self):
        class WindowedClient(_RewriteFakeClient):
            def query(self, sql, parameters=None):
                if "toStartOfInterval(timestamp_utc" in sql:
                    return SimpleNamespace(result_rows=[(0,), (900000,)])
                return super().query(sql, parameters=parameters)

            def query_rows_stream(self, query, parameters=None, settings=None):
                self.operations.append(f"window:{parameters['window_start_ms']}")
                self.last_stream_query = query
                self.last_stream_parameters = parameters or {}
                self.last_stream_settings = settings or {}
                return _Stream(self.stream_rows[:1])

        client = WindowedClient(source_rows=2)

        migration._rewrite_rows_to_shadow(
            client,
            columns=ParsedEventColumns,
            batch_size=10,
            case_id=None,
            recompute_existing=False,
        )

        self.assertEqual(client.operations.count("window:0"), 1)
        self.assertEqual(client.operations.count("window:900000"), 1)
        self.assertNotIn("ORDER BY", client.last_stream_query.upper())

    def test_native_evtx_sql_fast_path_is_inserted_before_python_fallback(self):
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
        fallback_defaults = {
            "case_id": 7,
            "artifact_type": "registry",
            "timestamp": datetime(2026, 4, 21, 12),
            "timestamp_utc": datetime(2026, 4, 21, 12),
            "timestamp_source_tz": "UTC",
            "source_file": "registry.log",
            "source_path": "/archive/registry.log",
            "source_host": "HOST1",
            "case_file_id": 99,
            "event_id": "reg",
            "record_id": None,
            "raw_json": '{"key":"value"}',
            "search_blob": "",
            "extra_fields": "{}",
            "parser_version": "Parser-1",
            "evidence_record_key": "",
            "evidence_identity_version": "",
            "evidence_identity_quality": "",
        }
        fallback_row = tuple(fallback_defaults.get(column, None) for column in ParsedEventColumns)
        test_case = self

        class FastPathClient:
            def __init__(self):
                self.commands = []
                self.last_stream_query = ""

            def query(self, sql, parameters=None):
                compact = " ".join(sql.split())
                if compact == "SELECT DISTINCT case_id FROM events ORDER BY case_id":
                    return SimpleNamespace(result_rows=[(7,)])
                if compact == "SELECT count() FROM events":
                    return SimpleNamespace(result_rows=[(2,)])
                if "toStartOfInterval(timestamp_utc" in sql:
                    test_case.assertIn("AND NOT (artifact_type = 'evtx'", sql)
                    return SimpleNamespace(result_rows=[(0, 1)])
                if "WHERE artifact_type = 'evtx'" in sql:
                    return SimpleNamespace(result_rows=[(1,)])
                return SimpleNamespace(result_rows=[(0,)])

            def query_rows_stream(self, query, parameters=None, settings=None):
                self.last_stream_query = query
                return _Stream([fallback_row])

            def insert(self, table, rows, column_names=None):
                pass

            def command(self, sql):
                self.commands.append(sql)

        client = FastPathClient()
        rewritten = migration._rewrite_rows_to_shadow(
            client,
            columns=columns,
            batch_size=10,
            case_id=None,
            recompute_existing=False,
            native_evtx_sql_fast_path=True,
        )

        self.assertEqual(rewritten, 2)
        self.assertTrue(any(command.startswith(f"INSERT INTO {migration.SHADOW_TABLE}") for command in client.commands))
        self.assertTrue(any("SHA256" in command for command in client.commands))
        self.assertTrue(any("SETTINGS max_threads = 6, max_insert_threads = 4" in command for command in client.commands))
        self.assertIn("AND NOT (artifact_type = 'evtx'", client.last_stream_query)

    def test_native_evtx_sql_identity_expression_matches_python_contract(self):
        if shutil.which("clickhouse-client") is None:
            self.skipTest("clickhouse-client not available")

        python_identity = evidence_identity_module.build_evidence_record_identity(
            {
                "case_id": 7,
                "artifact_type": "evtx",
                "case_file_id": 99,
                "record_id": 100,
                "raw_json": "{}",
            }
        )
        query = (
            f"SELECT {migration._sql_native_evtx_identity_key_expression()} "
            "FROM (SELECT toUInt32(7) AS case_id, toUInt32(99) AS case_file_id, "
            "toUInt64(100) AS record_id)"
        )
        result = subprocess.run(
            ["clickhouse-client", "--query", query],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            self.skipTest(f"clickhouse-client unavailable: {result.stderr.strip()}")

        self.assertEqual(result.stdout.strip(), python_identity.evidence_record_key)

    def test_dense_source_windows_are_split_by_row_count(self):
        class DenseWindowClient:
            def query(self, sql, parameters=None):
                parameters = parameters or {}
                if "toStartOfInterval(timestamp_utc" in sql:
                    return SimpleNamespace(result_rows=[(0, 900)])
                if "timestamp_utc >= fromUnixTimestamp64Milli" in sql:
                    duration_seconds = (
                        int(parameters["window_end_ms"]) - int(parameters["window_start_ms"])
                    ) // 1000
                    return SimpleNamespace(result_rows=[(duration_seconds,)])
                return SimpleNamespace(result_rows=[(0,)])

        windows = migration._case_source_windows(
            DenseWindowClient(),
            7,
            window_seconds=900,
            max_rows=300,
            min_seconds=225,
        )

        self.assertEqual(
            windows,
            [
                (0, 225000),
                (225000, 450000),
                (450000, 675000),
                (675000, 900000),
            ],
        )

    def test_parallel_copy_workers_copy_disjoint_windows(self):
        class CoordinatorClient(_RewriteFakeClient):
            def query(self, sql, parameters=None):
                if "toStartOfInterval(timestamp_utc" in sql:
                    return SimpleNamespace(result_rows=[(0,), (900000,)])
                return super().query(sql, parameters=parameters)

        manager = Manager()
        shared_insert_counts = manager.list()
        seen_windows = manager.list()

        class WorkerClient:
            def query_rows_stream(self, query, parameters=None, settings=None):
                seen_windows.append(parameters["window_start_ms"])
                row = _event_row(
                    ParsedEventColumns,
                    raw_json=f'{{"window": {parameters["window_start_ms"]}}}',
                )
                return _Stream([row])

            def insert(self, table, rows, column_names=None):
                shared_insert_counts.append(len(rows))

        original_get_client = migration.get_migration_client
        migration.get_migration_client = WorkerClient
        try:
            rewritten = migration._rewrite_rows_to_shadow(
                CoordinatorClient(source_rows=2),
                columns=ParsedEventColumns,
                batch_size=10,
                case_id=None,
                recompute_existing=False,
                copy_workers=2,
            )
        finally:
            migration.get_migration_client = original_get_client

        try:
            self.assertEqual(rewritten, 2)
            self.assertEqual(sum(shared_insert_counts), 2)
            self.assertEqual(sorted(seen_windows), [0, 900000])
        finally:
            manager.shutdown()

    def test_parallel_copy_workers_reuse_client_per_process(self):
        class CoordinatorClient(_RewriteFakeClient):
            def query(self, sql, parameters=None):
                if "toStartOfInterval(timestamp_utc" in sql:
                    return SimpleNamespace(result_rows=[(0,), (900000,), (1800000,), (2700000,)])
                return super().query(sql, parameters=parameters)

        manager = Manager()
        client_creations = manager.list()
        seen_windows = manager.list()

        class WorkerClient:
            def __init__(self):
                client_creations.append(os.getpid())

            def query_rows_stream(self, query, parameters=None, settings=None):
                seen_windows.append(parameters["window_start_ms"])
                return _Stream([_event_row(ParsedEventColumns)])

            def insert(self, table, rows, column_names=None):
                pass

        original_get_client = migration.get_migration_client
        original_worker_client = migration._WORKER_MIGRATION_CLIENT
        migration.get_migration_client = WorkerClient
        migration._WORKER_MIGRATION_CLIENT = None
        try:
            rewritten = migration._rewrite_rows_to_shadow(
                CoordinatorClient(source_rows=4),
                columns=ParsedEventColumns,
                batch_size=10,
                case_id=None,
                recompute_existing=False,
                copy_workers=2,
            )
        finally:
            migration.get_migration_client = original_get_client
            migration._WORKER_MIGRATION_CLIENT = original_worker_client

        try:
            self.assertEqual(rewritten, 4)
            self.assertEqual(sorted(seen_windows), [0, 900000, 1800000, 2700000])
            self.assertGreaterEqual(len(client_creations), 1)
            self.assertLessEqual(len(client_creations), 2)
        finally:
            manager.shutdown()

    def test_parallel_worker_failure_aborts_before_swap_and_buffer_recreation(self):
        class CoordinatorClient(_RewriteFakeClient):
            def query(self, sql, parameters=None):
                if "toStartOfInterval(timestamp_utc" in sql:
                    return SimpleNamespace(result_rows=[(0,), (900000,)])
                return super().query(sql, parameters=parameters)

        class FailingWorkerClient:
            def query_rows_stream(self, query, parameters=None, settings=None):
                if parameters["window_start_ms"] == 900000:
                    raise RuntimeError("worker window failed")
                return _Stream([_event_row(ParsedEventColumns)])

            def insert(self, table, rows, column_names=None):
                pass

        client = CoordinatorClient(source_rows=2)
        original_get_client = migration.get_migration_client
        migration.get_migration_client = FailingWorkerClient
        try:
            with self.assertRaisesRegex(RuntimeError, "worker window failed"):
                migration.backfill_identity_columns(client, batch_size=10, copy_workers=2)
        finally:
            migration.get_migration_client = original_get_client

        self.assertNotIn("rename_swap", client.operations)
        self.assertNotIn("create_buffer", client.operations)
        self.assertNotIn("events_buffer", client.tables)
        self.assertNotIn(migration.OLD_TABLE, client.tables)

    def test_copy_workers_one_uses_existing_client_path(self):
        original_get_client = migration.get_migration_client
        migration.get_migration_client = lambda: (_ for _ in ()).throw(
            AssertionError("fresh worker client should not be used")
        )
        try:
            rewritten = migration._rewrite_rows_to_shadow(
                _RewriteFakeClient(source_rows=2),
                columns=ParsedEventColumns,
                batch_size=10,
                case_id=None,
                recompute_existing=False,
                copy_workers=1,
            )
        finally:
            migration.get_migration_client = original_get_client

        self.assertEqual(rewritten, 2)

    def test_shadow_insert_timeout_splits_batch(self):
        class TimeoutOnceClient(_RewriteFakeClient):
            def __init__(self):
                super().__init__(source_rows=20)
                self.failed_once = False

            def insert(self, table, rows, column_names=None):
                if not self.failed_once and len(rows) == 20:
                    self.failed_once = True
                    raise RuntimeError("ProtocolError: Connection aborted TimeoutError timed out")
                return super().insert(table, rows, column_names=column_names)

        client = TimeoutOnceClient()

        rewritten = migration._rewrite_rows_to_shadow(
            client,
            columns=ParsedEventColumns,
            batch_size=20,
            case_id=None,
            recompute_existing=False,
        )

        inserted_rows = sum(len(rows) for _table, rows, _columns in client.inserts)
        self.assertEqual(rewritten, 20)
        self.assertEqual(inserted_rows, 20)
        self.assertEqual([len(rows) for _table, rows, _columns in client.inserts], [10, 10])

    def test_interrupted_shadow_is_discarded_and_rebuilt_with_buffer_absent(self):
        client = _RewriteFakeClient(source_rows=3)
        client.tables = {"events", migration.SHADOW_TABLE}

        migration.backfill_identity_columns(client, batch_size=2)

        self.assertIn("drop_shadow", client.operations)
        self.assertIn("create_shadow", client.operations)
        self.assertNotIn("drop_buffer", client.operations)
        self.assertLess(client.operations.index("create_shadow"), client.operations.index("shadow_copy"))
        self.assertLess(client.operations.index("rename_swap"), client.operations.index("create_buffer"))

    def test_source_stream_failure_keeps_events_authoritative_and_buffer_absent(self):
        class FailingClient(_RewriteFakeClient):
            def query_rows_stream(self, query, parameters=None, settings=None):
                self.operations.append("shadow_copy")
                return _FailingStream(
                    [self.stream_rows[0]],
                    RuntimeError("TIMEOUT_EXCEEDED simulated"),
                )

        client = FailingClient(source_rows=3)

        with self.assertRaisesRegex(RuntimeError, "TIMEOUT_EXCEEDED"):
            migration.backfill_identity_columns(client, batch_size=1)

        self.assertIn("events", client.tables)
        self.assertNotIn(migration.OLD_TABLE, client.tables)
        self.assertNotIn("events_buffer", client.tables)
        self.assertIn(migration.SHADOW_TABLE, client.tables)
        self.assertNotIn("rename_swap", client.operations)
        self.assertNotIn("create_buffer", client.operations)

    def test_batch_size_changes_only_insert_grouping(self):
        totals = []
        generated_keys = []
        for batch_size in (1, 2, 10):
            client = _RewriteFakeClient(source_rows=5)
            migration._rewrite_rows_to_shadow(
                client,
                columns=ParsedEventColumns,
                batch_size=batch_size,
                case_id=None,
                recompute_existing=False,
            )
            rows = [row for _table, batch, _columns in client.inserts for row in batch]
            totals.append(len(rows))
            generated_keys.append([row[ParsedEventColumns.index("evidence_record_key")] for row in rows])
            self.assertEqual(client.last_stream_settings["max_block_size"], 8192)

        self.assertEqual(totals, [5, 5, 5])
        self.assertEqual(generated_keys[0], generated_keys[1])
        self.assertEqual(generated_keys[1], generated_keys[2])


ParsedEventColumns = migration.ParsedEvent.clickhouse_columns()


if __name__ == "__main__":
    unittest.main()
