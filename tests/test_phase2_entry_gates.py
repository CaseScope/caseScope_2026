"""Phase 2 entry-gate migration tests.

    /opt/casescope/venv/bin/python -m pytest tests/test_phase2_entry_gates.py tests/test_query_hardening_regressions.py tests/test_ingest_fence.py tests/test_event_analyst_state.py tests/test_event_noise_state.py tests/test_overlay_audit_repairs.py tests/test_clickhouse_delete_dedup_contracts.py tests/test_phase1_step2.py tests/test_phase1b_tranche_a_contracts.py -q
"""
from __future__ import annotations

import inspect
import os
import unittest
import uuid

os.environ.setdefault("SECRET_KEY", "phase2-entry-gate-test-secret")

from migrations.add_events_block_number_offset import (
    MODIFY_SETTING_SQL,
    add_events_block_number_offset,
    events_has_block_columns_enabled,
)
from migrations.add_events_search_blob_text_index import (
    ADD_INDEX_SQL,
    BLOOM_INDEX_NAMES,
    INDEX_NAME,
    INDEX_TYPE_SQL,
    IncompatibleSearchBlobTextIndex,
    add_events_search_blob_text_index,
    search_blob_index_expression_is_compatible,
    search_blob_text_index_is_compatible,
    text_index_type_is_compatible,
)
from migrations.add_events_table import EVENTS_SCHEMA
from routes import hunting_query_helpers
from utils.clickhouse import run_events_update
from utils.ingest_fence import install_memory_backend, reset_fence_backend


class _QueryResult:
    def __init__(self, rows=None):
        self.result_rows = list(rows or [])


class _FakeClickHouse:
    def __init__(self, *, database="phase2_gate_test", engine_full="", indices=None, table_exists=True):
        self.database = database
        self.engine_full = engine_full
        self.indices = list(indices or [])
        self.table_exists = table_exists
        self.commands = []

    def query(self, sql, parameters=None):
        parameters = parameters or {}
        text = " ".join(sql.split())
        if "SELECT currentDatabase()" in text:
            return _QueryResult([(self.database,)])
        if "FROM system.tables" in text and "engine_full" in text:
            if not self.table_exists:
                return _QueryResult([])
            return _QueryResult([(self.engine_full,)])
        if "FROM system.tables" in text:
            return _QueryResult([(1 if self.table_exists else 0,)])
        if "FROM system.data_skipping_indices" in text:
            return _QueryResult(
                [
                    (
                        item["name"],
                        item.get("type", "text"),
                        item.get("type_full", ""),
                        item.get("expr", "search_blob"),
                        item.get("granularity", 1),
                    )
                    for item in self.indices
                ]
            )
        return _QueryResult([])

    def command(self, sql):
        self.commands.append(sql)
        if "ADD INDEX" in sql and INDEX_NAME not in [item["name"] for item in self.indices]:
            self.indices.append(
                {
                    "name": INDEX_NAME,
                    "type": "text",
                    "type_full": INDEX_TYPE_SQL,
                    "expr": "search_blob",
                    "granularity": 100000000,
                }
            )
        if "exclude_materialize_skip_indexes_on_merge" in sql:
            self.engine_full = (
                (self.engine_full + ", " if self.engine_full else "")
                + "exclude_materialize_skip_indexes_on_merge = 'idx_search_blob_text'"
            )
        if "enable_block_number_column = 1" in sql:
            self.engine_full = (
                "MergeTree SETTINGS index_granularity = 8192, "
                "enable_block_number_column = 1, enable_block_offset_column = 1"
            )


class SearchBlobTextIndexMigrationTests(unittest.TestCase):
    def test_compatible_type_ignores_granularity_and_quoting(self):
        self.assertTrue(
            text_index_type_is_compatible(
                "text(tokenizer = 'splitByNonAlpha', preprocessor = lower(search_blob))"
            )
        )
        self.assertTrue(
            text_index_type_is_compatible(
                "text(tokenizer = splitByNonAlpha, preprocessor = lower(search_blob))"
            )
        )
        self.assertFalse(
            text_index_type_is_compatible("text(tokenizer = ngrams(3), preprocessor = lower(search_blob))")
        )

    def test_a_correct_type_and_search_blob_expression_is_compatible(self):
        index = {
            "name": INDEX_NAME,
            "type": "text",
            "type_full": INDEX_TYPE_SQL,
            "expr": "search_blob",
            "granularity": 100000000,
        }
        self.assertTrue(search_blob_text_index_is_compatible(index))
        client = _FakeClickHouse(indices=[index])
        result = add_events_search_blob_text_index(client, allow_production=True)
        self.assertTrue(result["already_applied"])
        self.assertFalse(any("DROP INDEX" in command or "CLEAR INDEX" in command for command in client.commands))

    def test_b_correct_type_command_line_expression_fails_closed(self):
        client = _FakeClickHouse(
            indices=[
                {
                    "name": INDEX_NAME,
                    "type": "text",
                    "type_full": INDEX_TYPE_SQL,
                    "expr": "command_line",
                    "granularity": 1,
                }
            ]
        )
        with self.assertRaises(IncompatibleSearchBlobTextIndex):
            add_events_search_blob_text_index(client, allow_production=True)
        self.assertEqual(client.commands, [])

    def test_c_correct_type_lower_search_blob_expression_fails_closed(self):
        client = _FakeClickHouse(
            indices=[
                {
                    "name": INDEX_NAME,
                    "type": "text",
                    "type_full": INDEX_TYPE_SQL,
                    "expr": "lower(search_blob)",
                    "granularity": 1,
                }
            ]
        )
        with self.assertRaises(IncompatibleSearchBlobTextIndex):
            add_events_search_blob_text_index(client, allow_production=True)
        self.assertEqual(client.commands, [])

    def test_d_wrong_type_correct_expression_fails_closed(self):
        client = _FakeClickHouse(
            indices=[
                {
                    "name": INDEX_NAME,
                    "type": "text",
                    "type_full": "text(tokenizer = ngrams(3), preprocessor = lower(search_blob))",
                    "expr": "search_blob",
                    "granularity": 1,
                }
            ]
        )
        with self.assertRaises(IncompatibleSearchBlobTextIndex):
            add_events_search_blob_text_index(client, allow_production=True)
        self.assertEqual(client.commands, [])

    def test_e_new_migration_validates_type_and_expression_after_add(self):
        client = _FakeClickHouse(indices=[])
        result = add_events_search_blob_text_index(client, allow_production=True)
        self.assertTrue(result["changed"])
        self.assertTrue(search_blob_text_index_is_compatible(result["index_after"]))
        self.assertTrue(text_index_type_is_compatible(result["index_after"]["type_full"]))
        self.assertTrue(search_blob_index_expression_is_compatible(result["index_after"]["expr"]))
        self.assertEqual(result["index_after"]["expr"], "search_blob")

    def test_concat_and_other_column_expressions_fail_closed(self):
        for expr in ("concat(search_blob, command_line)", "raw_json", "`command_line`"):
            client = _FakeClickHouse(
                indices=[
                    {
                        "name": INDEX_NAME,
                        "type": "text",
                        "type_full": INDEX_TYPE_SQL,
                        "expr": expr,
                        "granularity": 1,
                    }
                ]
            )
            with self.assertRaises(IncompatibleSearchBlobTextIndex):
                add_events_search_blob_text_index(client, allow_production=True)
            self.assertEqual(client.commands, [])

    def test_expression_quoting_normalization_is_not_semantic(self):
        self.assertTrue(search_blob_index_expression_is_compatible("search_blob"))
        self.assertTrue(search_blob_index_expression_is_compatible("`search_blob`"))
        self.assertTrue(search_blob_index_expression_is_compatible('"search_blob"'))
        self.assertFalse(search_blob_index_expression_is_compatible("lower(search_blob)"))
        self.assertFalse(search_blob_index_expression_is_compatible("lower(`search_blob`)"))
        self.assertFalse(search_blob_index_expression_is_compatible("concat(search_blob, '')"))

    def test_refuses_production_without_flag(self):
        client = _FakeClickHouse(database="casescope")
        with self.assertRaises(RuntimeError):
            add_events_search_blob_text_index(client, allow_production=False)

    def test_refuses_production_materialize_even_with_apply_flag(self):
        client = _FakeClickHouse(database="casescope", table_exists=True)
        with self.assertRaises(RuntimeError):
            add_events_search_blob_text_index(
                client,
                allow_production=True,
                materialize=True,
            )

    def test_upgrade_is_idempotent_and_keeps_bloom_indexes(self):
        client = _FakeClickHouse(
            indices=[
                {
                    "name": "idx_search_ngram",
                    "type": "ngrambf_v1",
                    "type_full": "ngrambf_v1(3, 512, 2, 0)",
                    "expr": "search_blob",
                    "granularity": 4,
                },
                {
                    "name": "idx_search_token",
                    "type": "tokenbf_v1",
                    "type_full": "tokenbf_v1(32768, 3, 0)",
                    "expr": "search_blob",
                    "granularity": 4,
                },
            ]
        )
        first = add_events_search_blob_text_index(client, allow_production=True)
        self.assertTrue(first["changed"])
        self.assertEqual(first["sql"], ADD_INDEX_SQL)
        self.assertTrue(first["exclude_from_merge_sql"])
        self.assertIsNone(first["materialize_sql"])
        self.assertEqual(set(first["bloom_indexes_present"]), set(BLOOM_INDEX_NAMES))
        self.assertFalse(first["search_blob_mutated"])
        command_count = len(client.commands)
        second = add_events_search_blob_text_index(client, allow_production=True)
        self.assertTrue(second["already_applied"])
        self.assertFalse(second["changed"])
        self.assertEqual(len(client.commands), command_count)

    def test_incompatible_existing_index_fails_closed(self):
        client = _FakeClickHouse(
            indices=[
                {
                    "name": INDEX_NAME,
                    "type": "text",
                    "type_full": "text(tokenizer = ngrams(3), preprocessor = lower(search_blob))",
                    "expr": "search_blob",
                    "granularity": 1,
                }
            ]
        )
        with self.assertRaises(IncompatibleSearchBlobTextIndex):
            add_events_search_blob_text_index(client, allow_production=True)

    def test_fresh_schema_declares_text_index_and_keeps_blooms(self):
        self.assertIn(INDEX_NAME, EVENTS_SCHEMA)
        self.assertIn("tokenizer = 'splitByNonAlpha'", EVENTS_SCHEMA)
        self.assertIn("preprocessor = lower(search_blob)", EVENTS_SCHEMA)
        self.assertIn("idx_search_ngram", EVENTS_SCHEMA)
        self.assertIn("idx_search_token", EVENTS_SCHEMA)
        self.assertNotIn("MATERIALIZE INDEX", EVENTS_SCHEMA)


class BlockNumberOffsetMigrationTests(unittest.TestCase):
    def test_detects_enabled_settings(self):
        self.assertTrue(
            events_has_block_columns_enabled(
                "MergeTree SETTINGS enable_block_number_column = 1, enable_block_offset_column = 1"
            )
        )
        self.assertFalse(
            events_has_block_columns_enabled("MergeTree SETTINGS index_granularity = 8192")
        )

    def test_refuses_production_without_flag(self):
        client = _FakeClickHouse(database="casescope")
        with self.assertRaises(RuntimeError):
            add_events_block_number_offset(client, allow_production=False)

    def test_upgrade_is_idempotent(self):
        client = _FakeClickHouse(engine_full="MergeTree SETTINGS index_granularity = 8192")
        first = add_events_block_number_offset(client, allow_production=True)
        self.assertTrue(first["changed"])
        self.assertEqual(first["sql"], MODIFY_SETTING_SQL)
        self.assertTrue(first["block_columns_enabled"])
        second = add_events_block_number_offset(client, allow_production=True)
        self.assertTrue(second["already_applied"])
        self.assertFalse(second["changed"])
        self.assertEqual(client.commands, [MODIFY_SETTING_SQL])

    def test_fresh_schema_enables_block_columns(self):
        self.assertIn("enable_block_number_column = 1", EVENTS_SCHEMA)
        self.assertIn("enable_block_offset_column = 1", EVENTS_SCHEMA)


class ReaderAndFenceBoundaryTests(unittest.TestCase):
    def test_hunt_token_cutover_keeps_substring_and_exclusions(self):
        self.assertIn("hasAllTokens", inspect.getsource(hunting_query_helpers))
        self.assertIn("hasAnyTokens", inspect.getsource(hunting_query_helpers))
        self.assertIn("search_blob ilike", inspect.getsource(hunting_query_helpers.build_hunting_search_clause))
        self.assertNotIn("hasAllTokens(lower(search_blob)", inspect.getsource(hunting_query_helpers))
        self.assertNotIn("hasAllTokens(lower(e.search_blob)", inspect.getsource(hunting_query_helpers))

    def test_event_detail_match_search_blob_remains_position(self):
        from routes import hunting as hunting_routes

        source = inspect.getsource(hunting_routes.get_hunting_event_detail)
        self.assertIn("position(e.search_blob", source)
        self.assertNotIn("hasAllTokens", source)

    def test_run_events_update_still_exclusive_fenced_classic_mutation(self):
        source = inspect.getsource(run_events_update)
        self.assertIn("ALTER TABLE events UPDATE", source)
        self.assertIn("exclusive_ingest_fence", source)
        self.assertNotIn("UPDATE events SET", source)

    def test_no_phase_3_or_4_surfaces_were_added_by_gate_migrations(self):
        from migrations import add_events_block_number_offset as gate_b
        from migrations import add_events_search_blob_text_index as gate_a

        for module in (gate_a, gate_b):
            source = inspect.getsource(module)
            self.assertNotIn("event_observations_current", source)
            self.assertNotIn("events_current", source)
            self.assertNotIn("logical_event_key", source)
            self.assertNotIn("IOCEvidenceMatch", source)


def _live_client(database):
    import clickhouse_connect

    return clickhouse_connect.get_client(
        host=os.environ.get("CLICKHOUSE_HOST") or "localhost",
        port=int(os.environ.get("CLICKHOUSE_PORT") or 8123),
        database=database,
        username=os.environ.get("CLICKHOUSE_USER") or "default",
        password=os.environ.get("CLICKHOUSE_PASSWORD") or "",
        autogenerate_session_id=False,
        settings={"async_insert": 0, "wait_for_async_insert": 1},
    )


def _clickhouse_available():
    try:
        client = _live_client("default")
        client.query("SELECT 1")
        return True
    except Exception:
        return False


@unittest.skipUnless(_clickhouse_available(), "live ClickHouse is required")
class LivePhase2EntryGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.database = f"cs_p2_gate_{uuid.uuid4().hex[:12]}"
        admin = _live_client("default")
        admin.command(f"CREATE DATABASE {cls.database}")
        cls.client = _live_client(cls.database)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.client.command(f"DROP DATABASE IF EXISTS {cls.database}")
        except Exception:
            pass

    def test_fresh_events_schema_creates_text_index_and_block_settings(self):
        self.client.command(EVENTS_SCHEMA)
        create = self.client.query("SHOW CREATE TABLE events").result_rows[0][0]
        self.assertIn(INDEX_NAME, create)
        self.assertIn("splitByNonAlpha", create)
        self.assertIn("lower(search_blob)", create)
        self.assertIn("idx_search_ngram", create)
        self.assertIn("idx_search_token", create)
        self.assertIn("enable_block_number_column = 1", create)
        self.assertIn("enable_block_offset_column = 1", create)
        self.client.command("DROP TABLE events")

    def test_upgrade_text_index_and_block_settings_on_populated_table(self):
        self.client.command(
            """
            CREATE TABLE events (
                case_id UInt32,
                selector_key String,
                search_blob String,
                analyst_tagged Bool DEFAULT false,
                INDEX idx_search_ngram search_blob TYPE ngrambf_v1(3, 512, 2, 0) GRANULARITY 4,
                INDEX idx_search_token search_blob TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4
            )
            ENGINE = MergeTree
            ORDER BY (case_id, selector_key)
            """
        )
        self.client.command(
            "INSERT INTO events VALUES (1, 'sel-1', 'PowerShell Invoke-Expression', 0)"
        )
        before_blob = self.client.query("SELECT search_blob FROM events").result_rows[0][0]
        text_result = add_events_search_blob_text_index(self.client, allow_production=True)
        block_result = add_events_block_number_offset(self.client, allow_production=True)
        after_blob = self.client.query("SELECT search_blob FROM events").result_rows[0][0]
        self.assertEqual(before_blob, after_blob)
        self.assertTrue(text_result["changed"])
        self.assertTrue(search_blob_text_index_is_compatible(text_result["index_after"]))
        self.assertEqual(text_result["index_after"]["expr"], "search_blob")
        self.assertTrue(text_index_type_is_compatible(text_result["index_after"]["type_full"]))
        self.assertTrue(block_result["changed"])
        second_text = add_events_search_blob_text_index(self.client, allow_production=True)
        second_block = add_events_block_number_offset(self.client, allow_production=True)
        self.assertTrue(second_text["already_applied"])
        self.assertTrue(second_block["already_applied"])
        create = self.client.query("SHOW CREATE TABLE events").result_rows[0][0]
        self.assertIn("idx_search_ngram", create)
        self.assertIn("idx_search_token", create)
        self.assertIn(INDEX_NAME, create)
        self.assertIn("enable_block_number_column = 1", create)
        self.client.query("SELECT _block_number, _block_offset FROM events")
        self.client.command("DROP TABLE events")

    def test_existing_same_name_on_command_line_fails_closed_without_drop(self):
        self.client.command(
            """
            CREATE TABLE events (
                case_id UInt32,
                selector_key String,
                search_blob String,
                command_line String
            )
            ENGINE = MergeTree
            ORDER BY (case_id, selector_key)
            """
        )
        self.client.command(
            """
            ALTER TABLE events ADD INDEX idx_search_blob_text command_line TYPE text(
                tokenizer = 'splitByNonAlpha',
                preprocessor = lower(command_line)
            ) GRANULARITY 1
            """
        )
        with self.assertRaises(IncompatibleSearchBlobTextIndex):
            add_events_search_blob_text_index(self.client, allow_production=True)
        reported = self.client.query(
            """
            SELECT expr, type_full
            FROM system.data_skipping_indices
            WHERE database = currentDatabase()
              AND table = 'events'
              AND name = {name:String}
            """,
            parameters={"name": INDEX_NAME},
        ).result_rows
        self.assertEqual(len(reported), 1)
        self.assertEqual(reported[0][0], "command_line")
        create = self.client.query("SHOW CREATE TABLE events").result_rows[0][0]
        self.assertIn("INDEX idx_search_blob_text command_line", create)
        self.client.command("DROP TABLE events")

    def test_lightweight_update_matches_classic_on_small_state(self):
        install_memory_backend()
        try:
            self.client.command(
                """
                CREATE TABLE events (
                    case_id UInt32,
                    selector_key String,
                    analyst_tagged Bool DEFAULT false
                )
                ENGINE = MergeTree
                ORDER BY (case_id, selector_key)
                SETTINGS enable_block_number_column = 1, enable_block_offset_column = 1
                """
            )
            self.client.command(
                "INSERT INTO events VALUES (7, 'keep', 0), (7, 'patch', 0), (8, 'other', 0)"
            )
            self.client.command(
                "UPDATE events SET analyst_tagged = true WHERE case_id = 7 AND selector_key = 'patch'"
            )
            rows = {
                row[0]: bool(row[1])
                for row in self.client.query(
                    "SELECT selector_key, analyst_tagged FROM events ORDER BY selector_key"
                ).result_rows
            }
            self.assertEqual(rows, {"keep": False, "other": False, "patch": True})
            run_events_update(
                "analyst_tagged = false",
                "case_id = 7 AND selector_key = 'patch'",
                client=self.client,
            )
            reset = self.client.query(
                "SELECT analyst_tagged FROM events WHERE selector_key = 'patch'"
            ).result_rows[0][0]
            self.assertFalse(bool(reset))
        finally:
            reset_fence_backend()
            self.client.command("DROP TABLE IF EXISTS events")
