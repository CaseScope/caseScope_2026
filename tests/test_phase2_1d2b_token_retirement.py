"""Phase 2.1D2B token-bloom retirement / PHASE2_1_EXC_001 tests.

Fresh installs must create idx_search_ngram + idx_search_blob_text and must
not create idx_search_token. The dedicated upgrade migration drops only the
canonical legacy token bloom, is idempotent, and fails closed on identity drift.
"""
from __future__ import annotations

import inspect
import json
import os
import unittest
import uuid

os.environ.setdefault("SECRET_KEY", "phase2-1d2b-test-secret")

from migrations.add_events_table import EVENTS_SCHEMA
from migrations.drop_events_search_token_bloom import (
    ARCHITECTURE_EXCEPTION_ID,
    DROP_INDEX_SQL_TEMPLATE,
    EXPECTED_GRANULARITY,
    EXPECTED_TYPE_FULL,
    INDEX_NAME,
    NGRAM_INDEX_NAME,
    PRESERVED_INDEX_NAMES,
    TEXT_INDEX_NAME,
    IncompatibleSearchTokenIndex,
    TokenBloomRetirementRefused,
    drop_events_search_token_bloom,
    drop_index_sql,
    ngram_index_is_approved_exception,
    token_bloom_identity_is_canonical,
)
from utils.search_blob_text_index import REQUIRED_BLOOM_INDEX_NAMES, require_bloom_indexes


LOCKED_PLAN = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "casescope_database_flow_plan_v4_locked.md",
)
MIGRATION_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "migrations",
    "drop_events_search_token_bloom.py",
)
D2B_EVIDENCE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "docs",
    "database_flow_phase2",
    "phase2_1d2b_token_retirement_final_exit.json",
)
D2B_MD = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "docs",
    "database_flow_phase2",
    "phase2_1d2b_token_retirement_final_exit.md",
)
VERSION_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "version.json",
)

LEGACY_EVENTS_DDL = """
CREATE TABLE events (
    case_id UInt32,
    selector_key String,
    search_blob String,
    evidence_record_key String,
    event_id String DEFAULT '',
    source_ref_type Nullable(String) DEFAULT NULL,
    source_ref_id Nullable(String) DEFAULT NULL,
    source_generation Nullable(UInt32) DEFAULT NULL,
    ingest_batch_id Nullable(String) DEFAULT NULL,
    ingest_row_ordinal Nullable(UInt32) DEFAULT NULL,
    ingest_row_hash Nullable(String) DEFAULT NULL,
    ingest_attempt_id Nullable(UUID) DEFAULT NULL,
    INDEX idx_search_ngram search_blob TYPE ngrambf_v1(3, 512, 2, 0) GRANULARITY 4,
    INDEX idx_search_token search_blob TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4,
    INDEX idx_search_blob_text search_blob TYPE text(
        tokenizer = 'splitByNonAlpha',
        preprocessor = lower(search_blob)
    ) GRANULARITY 1,
    INDEX idx_event_id event_id TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_selector_key selector_key TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_evidence_record_key evidence_record_key TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY case_id
ORDER BY (case_id, selector_key)
SETTINGS
    index_granularity = 8192,
    enable_block_number_column = 1,
    enable_block_offset_column = 1
"""


class _QueryResult:
    def __init__(self, rows=None, column_names=None):
        self.result_rows = list(rows or [])
        self.column_names = list(column_names or [])


class _FakeClickHouse:
    def __init__(self, *, database="phase2_1d2b_test", table_exists=True, indices=None):
        self.database = database
        self.table_exists = table_exists
        self.indices = list(indices or [])
        self.commands = []

    def query(self, sql, parameters=None):
        text = " ".join(sql.split())
        if "SELECT currentDatabase()" in text:
            return _QueryResult([(self.database,)])
        if "FROM system.tables" in text:
            return _QueryResult([(1 if self.table_exists else 0,)])
        if "FROM system.data_skipping_indices" in text:
            return _QueryResult(
                [
                    (
                        item["name"],
                        item.get("type", ""),
                        item.get("type_full", ""),
                        item.get("expr", "search_blob"),
                        item.get("granularity", 4),
                    )
                    for item in self.indices
                ],
                ["name", "type", "type_full", "expr", "granularity"],
            )
        return _QueryResult([])

    def command(self, sql):
        self.commands.append(sql)
        if "DROP INDEX" in sql and INDEX_NAME in sql:
            self.indices = [item for item in self.indices if item["name"] != INDEX_NAME]


def _canonical_indices(*, include_token=True, token_override=None):
    items = [
        {
            "name": NGRAM_INDEX_NAME,
            "type": "ngrambf_v1",
            "type_full": "ngrambf_v1(3, 512, 2, 0)",
            "expr": "search_blob",
            "granularity": 4,
        },
        {
            "name": TEXT_INDEX_NAME,
            "type": "text",
            "type_full": "text(tokenizer = 'splitByNonAlpha', preprocessor = lower(search_blob))",
            "expr": "search_blob",
            "granularity": 100000000,
        },
        {
            "name": "idx_event_id",
            "type": "bloom_filter",
            "type_full": "bloom_filter(0.01)",
            "expr": "event_id",
            "granularity": 4,
        },
        {
            "name": "idx_selector_key",
            "type": "bloom_filter",
            "type_full": "bloom_filter(0.01)",
            "expr": "selector_key",
            "granularity": 4,
        },
        {
            "name": "idx_evidence_record_key",
            "type": "bloom_filter",
            "type_full": "bloom_filter(0.01)",
            "expr": "evidence_record_key",
            "granularity": 4,
        },
    ]
    if include_token:
        items.append(
            token_override
            or {
                "name": INDEX_NAME,
                "type": "tokenbf_v1",
                "type_full": EXPECTED_TYPE_FULL,
                "expr": "search_blob",
                "granularity": EXPECTED_GRANULARITY,
            }
        )
    return items


class Phase21D2BContractTests(unittest.TestCase):
    def test_architecture_exception_is_canonical(self):
        self.assertEqual(ARCHITECTURE_EXCEPTION_ID, "PHASE2_1_EXC_001")
        with open(LOCKED_PLAN, encoding="utf-8") as handle:
            plan = handle.read()
        self.assertIn("PHASE2_1_EXC_001", plan)
        self.assertIn("`idx_search_ngram` is retained", plan)
        self.assertIn("`idx_search_token` is retired by Phase 2.1", plan)
        self.assertNotIn("drop both bloom indexes after `EXPLAIN` validation;", plan)

    def test_version_is_feature_bump_4_26_0(self):
        with open(VERSION_PATH, encoding="utf-8") as handle:
            payload = json.load(handle)
        self.assertEqual(payload["version"], "4.26.0")
        self.assertEqual(payload["changelog"][0]["version"], "4.26.0")

    def test_d2b_evidence_records_pass_and_exc_001(self):
        self.assertTrue(os.path.exists(D2B_MD), msg="D2B markdown evidence is required")
        self.assertTrue(os.path.exists(D2B_EVIDENCE), msg="D2B JSON evidence is required")
        with open(D2B_EVIDENCE, encoding="utf-8") as handle:
            payload = json.load(handle)
        self.assertEqual(payload["verdict"], "PHASE2_1D2B_PASS")
        self.assertEqual(payload["version"], "4.26.0")
        self.assertTrue(payload["version_bumped"])
        self.assertEqual(payload["architecture_exception"]["id"], "PHASE2_1_EXC_001")
        self.assertEqual(payload["architecture_exception"]["keep"], "idx_search_ngram")
        self.assertEqual(payload["architecture_exception"]["retire"], "idx_search_token")
        self.assertTrue(payload["production_index_after"]["idx_search_blob_text"]["present"])
        self.assertTrue(payload["production_index_after"]["idx_search_ngram"]["present"])
        self.assertFalse(payload["production_index_after"]["idx_search_token"]["present"])
        self.assertEqual(
            payload["insert_index_decision"],
            "KEEP_PRODUCTION_MATERIALIZE_SKIP_INDEXES_ON_INSERT_1",
        )
        self.assertEqual(payload["command_line_decision"], "COMMAND_LINE_INDEX_DEFER")
        self.assertTrue(payload["phase2_1_exit_gates"]["9_idx_search_ngram_present_under_PHASE2_1_EXC_001"])
        self.assertTrue(payload["fingerprints"]["unchanged"])
        self.assertTrue(payload["semantic_parity"]["ok"])
        with open(D2B_MD, encoding="utf-8") as handle:
            markdown = handle.read()
        self.assertIn("PHASE2_1_EXC_001", markdown)
        self.assertIn("PHASE2_1D2B_PASS", markdown)
        self.assertIn("KEEP_PRODUCTION_MATERIALIZE_SKIP_INDEXES_ON_INSERT_1", markdown)
        self.assertIn("COMMAND_LINE_INDEX_DEFER", markdown)

    def test_fresh_schema_contract(self):
        self.assertIn(
            "INDEX idx_search_ngram search_blob TYPE ngrambf_v1(3, 512, 2, 0) GRANULARITY 4",
            EVENTS_SCHEMA,
        )
        self.assertIn("INDEX idx_search_blob_text search_blob TYPE text(", EVENTS_SCHEMA)
        self.assertNotIn("idx_search_token", EVENTS_SCHEMA)
        self.assertIn("INDEX idx_event_id", EVENTS_SCHEMA)
        self.assertIn("INDEX idx_selector_key", EVENTS_SCHEMA)
        self.assertIn("INDEX idx_evidence_record_key", EVENTS_SCHEMA)
        self.assertIn("enable_block_number_column = 1", EVENTS_SCHEMA)
        self.assertIn("enable_block_offset_column = 1", EVENTS_SCHEMA)

    def test_migration_source_never_drops_or_mutates_ngram(self):
        source = open(MIGRATION_PATH, encoding="utf-8").read()
        self.assertNotIn("ALTER TABLE events DROP INDEX idx_search_ngram", source)
        self.assertNotIn("ALTER TABLE events OPTIMIZE", source)
        self.assertNotIn("ALTER TABLE events MATERIALIZE INDEX", source)
        self.assertNotIn("pattern_rules", source)
        sql = drop_index_sql("events")
        self.assertEqual(
            sql,
            DROP_INDEX_SQL_TEMPLATE.format(table="events", index=INDEX_NAME),
        )
        self.assertNotIn(NGRAM_INDEX_NAME, sql)

    def test_token_identity_helper(self):
        self.assertTrue(
            token_bloom_identity_is_canonical(
                {
                    "expr": "search_blob",
                    "type_full": "tokenbf_v1(32768, 3, 0)",
                    "granularity": 4,
                }
            )
        )
        self.assertFalse(
            token_bloom_identity_is_canonical(
                {
                    "expr": "search_blob",
                    "type_full": "tokenbf_v1(65536, 3, 0)",
                    "granularity": 4,
                }
            )
        )
        self.assertTrue(
            ngram_index_is_approved_exception(
                {
                    "name": NGRAM_INDEX_NAME,
                    "expr": "`search_blob`",
                    "type_full": "ngrambf_v1(3, 512, 2, 0)",
                    "granularity": 4,
                }
            )
        )

    def test_refuses_production_without_flag(self):
        client = _FakeClickHouse(database="casescope", indices=_canonical_indices())
        with self.assertRaises(TokenBloomRetirementRefused):
            drop_events_search_token_bloom(client, allow_production=False)
        self.assertEqual(client.commands, [])

    def test_upgrade_drops_only_canonical_token_and_is_idempotent(self):
        client = _FakeClickHouse(indices=_canonical_indices())
        first = drop_events_search_token_bloom(client, allow_production=True)
        self.assertTrue(first["changed"])
        self.assertIn("DROP INDEX idx_search_token", first["sql"])
        self.assertNotIn(NGRAM_INDEX_NAME, first["sql"])
        self.assertIsNone(first["index_after"])
        self.assertEqual(len(client.commands), 1)
        second = drop_events_search_token_bloom(client, allow_production=True)
        self.assertTrue(second["already_applied"])
        self.assertFalse(second["changed"])
        self.assertEqual(len(client.commands), 1)
        names = {item["name"] for item in client.indices}
        self.assertIn(NGRAM_INDEX_NAME, names)
        self.assertIn(TEXT_INDEX_NAME, names)
        self.assertNotIn(INDEX_NAME, names)
        for preserved in PRESERVED_INDEX_NAMES:
            self.assertIn(preserved, names)

    def test_absent_token_is_noop(self):
        client = _FakeClickHouse(indices=_canonical_indices(include_token=False))
        result = drop_events_search_token_bloom(client, allow_production=True)
        self.assertTrue(result["already_applied"])
        self.assertFalse(result["changed"])
        self.assertEqual(client.commands, [])

    def test_schema_drift_refuses_drop(self):
        drifted = {
            "name": INDEX_NAME,
            "type": "tokenbf_v1",
            "type_full": "tokenbf_v1(1024, 3, 0)",
            "expr": "search_blob",
            "granularity": 4,
        }
        client = _FakeClickHouse(indices=_canonical_indices(token_override=drifted))
        with self.assertRaises(IncompatibleSearchTokenIndex):
            drop_events_search_token_bloom(client, allow_production=True)
        self.assertEqual(client.commands, [])
        self.assertTrue(any(item["name"] == INDEX_NAME for item in client.indices))

    def test_wrong_expression_refuses_drop(self):
        drifted = {
            "name": INDEX_NAME,
            "type": "tokenbf_v1",
            "type_full": EXPECTED_TYPE_FULL,
            "expr": "lower(search_blob)",
            "granularity": 4,
        }
        client = _FakeClickHouse(indices=_canonical_indices(token_override=drifted))
        with self.assertRaises(IncompatibleSearchTokenIndex):
            drop_events_search_token_bloom(client, allow_production=True)
        self.assertEqual(client.commands, [])

    def test_missing_ngram_refuses(self):
        indices = [
            item
            for item in _canonical_indices()
            if item["name"] != NGRAM_INDEX_NAME
        ]
        client = _FakeClickHouse(indices=indices)
        with self.assertRaises(TokenBloomRetirementRefused):
            drop_events_search_token_bloom(client, allow_production=True)
        self.assertEqual(client.commands, [])

    def test_require_bloom_indexes_does_not_require_token(self):
        self.assertEqual(REQUIRED_BLOOM_INDEX_NAMES, (NGRAM_INDEX_NAME,))
        client = _FakeClickHouse(indices=_canonical_indices(include_token=False))
        self.assertEqual(require_bloom_indexes(client), (NGRAM_INDEX_NAME,))

    def test_runtime_does_not_require_token_index_name(self):
        from utils import search_blob_text_index as module

        source = inspect.getsource(module.require_bloom_indexes)
        self.assertNotIn("idx_search_token", source)
        self.assertIn("idx_search_ngram", inspect.getsource(module))

    def test_pattern_rules_not_rewritten(self):
        from models import pattern_rules

        source = inspect.getsource(pattern_rules)
        self.assertIn("search_blob LIKE '%NTLM%'", source)
        self.assertIn("search_blob LIKE '%RC4%'", source)
        self.assertIn("search_blob LIKE '%IPC$%'", source)
        self.assertIn("search_blob LIKE '%TXT%'", source)
        self.assertIn("search_blob LIKE '%cmd /c%'", source)
        self.assertNotIn("ILIKE '%NTLM%' AND search_blob LIKE '%NTLM%'", source)


def _live_client(database):
    import clickhouse_connect

    return clickhouse_connect.get_client(
        host=os.environ.get("CLICKHOUSE_HOST") or "localhost",
        port=int(os.environ.get("CLICKHOUSE_PORT") or 8123),
        database=database,
        username=os.environ.get("CLICKHOUSE_USER") or "default",
        password=os.environ.get("CLICKHOUSE_PASSWORD") or "",
        autogenerate_session_id=False,
        send_receive_timeout=120,
        settings={"async_insert": 0, "wait_for_async_insert": 1},
    )


def _clickhouse_available():
    try:
        client = _live_client("default")
        client.query("SELECT 1")
        return True
    except Exception:
        return False


def _fingerprint(client):
    row = client.query(
        """
        SELECT
            count() AS rows,
            sum(cityHash64(evidence_record_key)) AS erk_fp,
            sum(cityHash64(search_blob)) AS blob_fp,
            countIf(source_ref_type IS NOT NULL) AS protocol_identity_nonnull
        FROM events
        """
    ).result_rows[0]
    return {
        "rows": int(row[0] or 0),
        "erk_fp": str(row[1] or 0),
        "blob_fp": str(row[2] or 0),
        "protocol_identity_nonnull": int(row[3] or 0),
    }


def _index_names(client):
    return {
        row[0]
        for row in client.query(
            """
            SELECT name FROM system.data_skipping_indices
            WHERE database = currentDatabase() AND table = 'events'
            """
        ).result_rows
    }


@unittest.skipUnless(_clickhouse_available(), "live ClickHouse is required")
class LivePhase21D2BMigrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.database = f"cs_p21d2b_test_{uuid.uuid4().hex[:12]}"
        admin = _live_client("default")
        admin.command(f"CREATE DATABASE {cls.database}")
        cls.client = _live_client(cls.database)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.client.command(f"DROP DATABASE IF EXISTS {cls.database}")
        except Exception:
            pass

    def test_fresh_install_schema_omits_token_keeps_ngram(self):
        self.client.command("DROP TABLE IF EXISTS events")
        self.client.command(EVENTS_SCHEMA)
        names = _index_names(self.client)
        self.assertIn(NGRAM_INDEX_NAME, names)
        self.assertIn(TEXT_INDEX_NAME, names)
        self.assertNotIn(INDEX_NAME, names)
        self.assertIn("idx_event_id", names)
        self.assertIn("idx_selector_key", names)
        self.assertIn("idx_evidence_record_key", names)
        create = self.client.query("SHOW CREATE TABLE events").result_rows[0][0]
        self.assertIn("enable_block_number_column = 1", create)
        self.assertIn("enable_block_offset_column = 1", create)
        self.assertNotIn("idx_search_token", create)
        require_bloom_indexes(self.client)
        self.client.command("DROP TABLE events")

    def test_upgrade_idempotence_and_value_identity(self):
        self.client.command("DROP TABLE IF EXISTS events")
        self.client.command(LEGACY_EVENTS_DDL)
        rows = []
        for i in range(200):
            blob = f"row{i} powershell host01"
            if i % 10 == 0:
                blob += " NTLM RC4 IPC$ TXT cmd /c"
            rows.append((1, f"sel-{i}", blob, f"erk-{i}", "CASE_FILE", "1", 1, "batch-1"))
        self.client.insert(
            "events",
            rows,
            column_names=[
                "case_id",
                "selector_key",
                "search_blob",
                "evidence_record_key",
                "source_ref_type",
                "source_ref_id",
                "source_generation",
                "ingest_batch_id",
            ],
            settings={"materialize_skip_indexes_on_insert": 1},
        )
        before = _fingerprint(self.client)
        names_before = _index_names(self.client)
        self.assertIn(INDEX_NAME, names_before)
        self.assertIn(NGRAM_INDEX_NAME, names_before)
        self.assertIn(TEXT_INDEX_NAME, names_before)
        first = drop_events_search_token_bloom(self.client, allow_production=True)
        self.assertTrue(first["changed"])
        names_after = _index_names(self.client)
        self.assertNotIn(INDEX_NAME, names_after)
        self.assertIn(NGRAM_INDEX_NAME, names_after)
        self.assertIn(TEXT_INDEX_NAME, names_after)
        self.assertIn("idx_event_id", names_after)
        after = _fingerprint(self.client)
        self.assertEqual(before, after)
        second = drop_events_search_token_bloom(self.client, allow_production=True)
        self.assertTrue(second["already_applied"])
        self.assertFalse(second["changed"])
        self.assertIsNone(second["sql"])
        self.assertEqual(_fingerprint(self.client), before)
        explain = "\n".join(
            row[0]
            for row in self.client.query(
                "EXPLAIN indexes = 1 SELECT count() FROM events "
                "WHERE search_blob LIKE {pat:String}",
                parameters={"pat": "%NTLM%"},
            ).result_rows
        )
        self.assertIn("Name: idx_search_ngram", explain)
        self.assertNotIn("Name: idx_search_token", explain)
        self.client.command("DROP TABLE events")

    def test_schema_drift_live_refuses_without_drop(self):
        self.client.command("DROP TABLE IF EXISTS events")
        self.client.command(
            """
            CREATE TABLE events (
                case_id UInt32,
                search_blob String,
                evidence_record_key String,
                INDEX idx_search_ngram search_blob TYPE ngrambf_v1(3, 512, 2, 0) GRANULARITY 4,
                INDEX idx_search_token search_blob TYPE tokenbf_v1(1024, 3, 0) GRANULARITY 4,
                INDEX idx_search_blob_text search_blob TYPE text(
                    tokenizer = 'splitByNonAlpha',
                    preprocessor = lower(search_blob)
                ) GRANULARITY 1
            )
            ENGINE = MergeTree
            ORDER BY (case_id, evidence_record_key)
            """
        )
        with self.assertRaises(IncompatibleSearchTokenIndex):
            drop_events_search_token_bloom(self.client, allow_production=True)
        names = _index_names(self.client)
        self.assertIn(INDEX_NAME, names)
        self.assertIn(NGRAM_INDEX_NAME, names)
        create = self.client.query("SHOW CREATE TABLE events").result_rows[0][0]
        self.assertIn("idx_search_token", create)
        self.client.command("DROP TABLE events")
