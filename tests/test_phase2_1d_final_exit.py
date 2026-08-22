"""Phase 2.1D bloom-retirement history and updated Phase 2.1 exit contract.

Phase 2.1D recorded PHASE2_1D_NOT_READY: production EXPLAIN showed
idx_search_ngram pruning retained search_blob LIKE queries, so both blooms
stayed. D2A attributed prune to ngram and found idx_search_token redundant.
D2B records PHASE2_1_EXC_001 (keep ngram) and retires only idx_search_token.

This file keeps the D1 measurement proofs (ngram still prunes case-sensitive
LIKE) and updates the canonical schema contract after the exception.
"""
from __future__ import annotations

import inspect
import os
import unittest
import uuid

os.environ.setdefault("SECRET_KEY", "phase2-1d-test-secret")

from migrations.add_events_table import EVENTS_SCHEMA
from migrations.drop_events_search_token_bloom import (
    ARCHITECTURE_EXCEPTION_ID,
    INDEX_NAME as TOKEN_INDEX_NAME,
    NGRAM_INDEX_NAME,
)
from routes import hunting_query_helpers
from utils import clickhouse as clickhouse_utils


LOCKED_PLAN = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "casescope_database_flow_plan_v4_locked.md",
)
D1_EVIDENCE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "docs",
    "database_flow_phase2",
    "phase2_1d_final_exit.json",
)


class Phase21DHistoryAndUpdatedContractTests(unittest.TestCase):
    def test_d1_not_ready_evidence_is_preserved(self):
        import json

        self.assertTrue(os.path.exists(D1_EVIDENCE), msg="D1 JSON evidence is required")
        with open(D1_EVIDENCE, encoding="utf-8") as handle:
            payload = json.load(handle)
        self.assertEqual(payload["verdict"], "PHASE2_1D_NOT_READY")
        self.assertEqual(payload["bloom_retirement_decision"], "BLOOM_DEPENDENCY_BLOCKS_EXIT")
        self.assertTrue(payload["production_index_inventory"]["idx_search_ngram"]["present"])
        self.assertTrue(payload["production_index_inventory"]["idx_search_token"]["present"])
        self.assertFalse(payload["upgrade_migration"]["executed"])

    def test_canonical_schema_keeps_ngram_exception_and_drops_token(self):
        self.assertIn("INDEX idx_search_blob_text search_blob TYPE text(", EVENTS_SCHEMA)
        self.assertIn("tokenizer = 'splitByNonAlpha'", EVENTS_SCHEMA)
        self.assertIn("preprocessor = lower(search_blob)", EVENTS_SCHEMA)
        self.assertIn(
            "INDEX idx_search_ngram search_blob TYPE ngrambf_v1(3, 512, 2, 0) GRANULARITY 4",
            EVENTS_SCHEMA,
        )
        self.assertNotIn("INDEX idx_search_token", EVENTS_SCHEMA)
        self.assertNotIn("tokenbf_v1(32768, 3, 0)", EVENTS_SCHEMA)
        self.assertIn("INDEX idx_event_id event_id TYPE bloom_filter(0.01) GRANULARITY 4", EVENTS_SCHEMA)
        self.assertIn(
            "INDEX idx_selector_key selector_key TYPE bloom_filter(0.01) GRANULARITY 4",
            EVENTS_SCHEMA,
        )
        self.assertIn(
            "INDEX idx_evidence_record_key evidence_record_key TYPE bloom_filter(0.01) GRANULARITY 4",
            EVENTS_SCHEMA,
        )
        self.assertIn("enable_block_number_column = 1", EVENTS_SCHEMA)
        self.assertIn("enable_block_offset_column = 1", EVENTS_SCHEMA)

    def test_phase2_1_exc_001_is_recorded_and_protects_ngram(self):
        with open(LOCKED_PLAN, encoding="utf-8") as handle:
            plan = handle.read()
        self.assertIn(ARCHITECTURE_EXCEPTION_ID, plan)
        self.assertIn("`idx_search_ngram` is retained", plan)
        self.assertIn("`idx_search_token` is retired by Phase 2.1", plan)
        self.assertIn(
            "INDEX idx_search_ngram search_blob TYPE ngrambf_v1(3, 512, 2, 0) GRANULARITY 4",
            EVENTS_SCHEMA,
        )
        self.assertEqual(NGRAM_INDEX_NAME, "idx_search_ngram")
        self.assertEqual(TOKEN_INDEX_NAME, "idx_search_token")

    def test_accidental_ngram_removal_fails_phase2_1_contract(self):
        self.assertIn("idx_search_ngram", EVENTS_SCHEMA)
        with open(LOCKED_PLAN, encoding="utf-8") as handle:
            plan = handle.read()
        self.assertIn(ARCHITECTURE_EXCEPTION_ID, plan)
        # A future drop of ngram is not authorized by this exception.
        self.assertIn("new architecture review", plan)

    def test_token_only_drop_migration_exists_dual_bloom_drop_does_not(self):
        migrations_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "migrations")
        names = os.listdir(migrations_dir)
        self.assertIn("drop_events_search_token_bloom.py", names)
        self.assertNotIn("drop_events_search_blob_bloom_indexes.py", names)
        source = open(
            os.path.join(migrations_dir, "drop_events_search_token_bloom.py"),
            encoding="utf-8",
        ).read()
        self.assertNotIn("ALTER TABLE events DROP INDEX idx_search_ngram", source)
        self.assertNotIn("ALTER TABLE events OPTIMIZE", source)
        self.assertNotIn("ALTER TABLE events MATERIALIZE INDEX", source)

    def test_hunt_token_and_substring_paths_unchanged(self):
        source = inspect.getsource(hunting_query_helpers.build_hunting_search_clause)
        self.assertIn("hasAllTokens", inspect.getsource(hunting_query_helpers))
        self.assertIn("hasAnyTokens", inspect.getsource(hunting_query_helpers))
        self.assertIn("search_blob ilike", source)
        self.assertNotIn("hasAllTokens(lower(search_blob)", inspect.getsource(hunting_query_helpers))

    def test_pattern_rules_still_use_case_sensitive_search_blob_like(self):
        from models import pattern_rules

        source = inspect.getsource(pattern_rules)
        self.assertIn("search_blob LIKE '%NTLM%'", source)
        self.assertIn("search_blob LIKE '%ADMIN$%'", source)

    def test_runtime_client_does_not_force_materialize_skip_indexes_on_insert_0(self):
        source = inspect.getsource(clickhouse_utils.get_client) + inspect.getsource(
            clickhouse_utils.get_fresh_client
        )
        self.assertNotIn("materialize_skip_indexes_on_insert", source)


def _live_client(database):
    import clickhouse_connect

    return clickhouse_connect.get_client(
        host=os.environ.get("CLICKHOUSE_HOST") or "localhost",
        port=int(os.environ.get("CLICKHOUSE_PORT") or 8123),
        database=database,
        username=os.environ.get("CLICKHOUSE_USER") or "default",
        password=os.environ.get("CLICKHOUSE_PASSWORD") or "",
        autogenerate_session_id=False,
        send_receive_timeout=60,
    )


def _clickhouse_available():
    try:
        client = _live_client("default")
        client.query("SELECT 1")
        return True
    except Exception:
        return False


@unittest.skipUnless(_clickhouse_available(), "live ClickHouse is required")
class LivePhase21DExplainContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.database = f"cs_p21d_test_{uuid.uuid4().hex[:12]}"
        admin = _live_client("default")
        admin.command(f"CREATE DATABASE {cls.database}")
        cls.client = _live_client(cls.database)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.client.command(f"DROP DATABASE IF EXISTS {cls.database}")
        except Exception:
            pass

    def test_case_sensitive_like_uses_ngram_bloom_on_26_7(self):
        self.client.command("DROP TABLE IF EXISTS events_like")
        self.client.command(
            """
            CREATE TABLE events_like (
                case_id UInt32,
                search_blob String,
                evidence_record_key String,
                INDEX idx_search_ngram search_blob TYPE ngrambf_v1(3, 512, 2, 0) GRANULARITY 4,
                INDEX idx_search_token search_blob TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4,
                INDEX idx_search_blob_text search_blob TYPE text(
                    tokenizer = 'splitByNonAlpha',
                    preprocessor = lower(search_blob)
                ) GRANULARITY 1
            )
            ENGINE = MergeTree
            ORDER BY (case_id, evidence_record_key)
            """
        )
        rows = []
        for i in range(2000):
            blob = f"row{i} powershell host01"
            if i % 20 == 0:
                blob += " NTLM"
            rows.append((1, blob, f"erk-{i}"))
        self.client.insert(
            "events_like",
            rows,
            column_names=["case_id", "search_blob", "evidence_record_key"],
            settings={"materialize_skip_indexes_on_insert": 1},
        )
        text = "\n".join(
            row[0]
            for row in self.client.query(
                "EXPLAIN indexes = 1 SELECT count() FROM events_like "
                "WHERE search_blob LIKE {pat:String}",
                parameters={"pat": "%NTLM%"},
            ).result_rows
        )
        self.assertIn("Name: idx_search_ngram", text)
        count = self.client.query(
            "SELECT count() FROM events_like WHERE search_blob LIKE {pat:String}",
            parameters={"pat": "%NTLM%"},
        ).result_rows[0][0]
        self.assertEqual(int(count), 100)
