"""Phase 2.1D bloom-retirement / final-exit tests.

Phase 2.1D measured production EXPLAIN and did NOT drop idx_search_ngram or
idx_search_token: models/pattern_rules.py case-sensitive search_blob LIKE still
uses those skip indexes. These tests lock that NOT_READY contract and the
materialize_skip_indexes_on_insert decision. They do not migrate readers.
"""
from __future__ import annotations

import inspect
import os
import unittest
import uuid

os.environ.setdefault("SECRET_KEY", "phase2-1d-test-secret")

from migrations.add_events_table import EVENTS_SCHEMA
from routes import hunting_query_helpers
from utils import clickhouse as clickhouse_utils


class Phase21DNotReadyContractTests(unittest.TestCase):
    def test_canonical_schema_still_declares_both_blooms_and_text_index(self):
        self.assertIn("INDEX idx_search_blob_text search_blob TYPE text(", EVENTS_SCHEMA)
        self.assertIn("tokenizer = 'splitByNonAlpha'", EVENTS_SCHEMA)
        self.assertIn("preprocessor = lower(search_blob)", EVENTS_SCHEMA)
        self.assertIn(
            "INDEX idx_search_ngram search_blob TYPE ngrambf_v1(3, 512, 2, 0) GRANULARITY 4",
            EVENTS_SCHEMA,
        )
        self.assertIn(
            "INDEX idx_search_token search_blob TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4",
            EVENTS_SCHEMA,
        )
        self.assertIn("INDEX idx_event_id event_id TYPE bloom_filter(0.01) GRANULARITY 4", EVENTS_SCHEMA)
        self.assertIn(
            "INDEX idx_selector_key selector_key TYPE bloom_filter(0.01) GRANULARITY 4",
            EVENTS_SCHEMA,
        )
        self.assertIn(
            "INDEX idx_evidence_record_key evidence_record_key TYPE bloom_filter(0.01) GRANULARITY 4",
            EVENTS_SCHEMA,
        )

    def test_no_bloom_drop_migration_shipped(self):
        migrations_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "migrations")
        names = os.listdir(migrations_dir)
        self.assertFalse(
            any("bloom" in name and "drop" in name for name in names),
            msg=names,
        )
        self.assertNotIn("drop_events_search_blob_bloom_indexes.py", names)

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
