"""Phase 2.1D2A bloom-dependency measurement contract tests.

D2A is measurement-only. These tests lock predicate/prefilter logic, the
preserved 2.1D NOT_READY schema, and disposable ClickHouse proofs that do
not touch production events.
"""
from __future__ import annotations

import inspect
import json
import os
import unittest
import uuid

os.environ.setdefault("SECRET_KEY", "phase2-1d2a-test-secret")

from migrations.add_events_table import EVENTS_SCHEMA
from models.pattern_rules import ALL_PATTERN_RULES
from routes import hunting_query_helpers
from tests.phase2_1d2a_lib import (
    TEXT_INDEX_ILIKE_MIN_ALNUM,
    collect_pattern_rule_predicates,
    derive_prefilter,
    parse_explain_indexes,
    wrap_like_sql,
)
from utils import clickhouse as clickhouse_utils


EVIDENCE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "docs",
    "database_flow_phase2",
    "phase2_1d2a_bloom_dependency_resolution.json",
)


class Phase21D2AContractTests(unittest.TestCase):
    def test_version_unchanged(self):
        with open(os.path.join(os.path.dirname(os.path.dirname(__file__)), "version.json")) as handle:
            payload = json.load(handle)
        self.assertEqual(payload["version"], "4.25.2")

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

    def test_no_bloom_drop_migration_shipped(self):
        migrations_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "migrations")
        names = os.listdir(migrations_dir)
        self.assertFalse(any("bloom" in name and "drop" in name for name in names), msg=names)
        self.assertNotIn("drop_events_search_blob_bloom_indexes.py", names)

    def test_hunt_and_pattern_readers_not_migrated(self):
        source = inspect.getsource(hunting_query_helpers.build_hunting_search_clause)
        self.assertIn("hasAllTokens", inspect.getsource(hunting_query_helpers))
        self.assertIn("hasAnyTokens", inspect.getsource(hunting_query_helpers))
        self.assertIn("search_blob ilike", source)
        from models import pattern_rules

        pattern_source = inspect.getsource(pattern_rules)
        self.assertIn("search_blob LIKE '%NTLM%'", pattern_source)
        self.assertIn("search_blob LIKE '%ADMIN$%'", pattern_source)
        self.assertNotIn("search_blob ILIKE '%NTLM%' AND search_blob LIKE '%NTLM%'", pattern_source)

    def test_pattern_predicate_inventory_keeps_distinct_shapes(self):
        inventory = collect_pattern_rule_predicates(ALL_PATTERN_RULES)
        shapes = {item["shape"] for item in inventory}
        self.assertIn("search_blob LIKE '%NTLM%'", shapes)
        self.assertIn("search_blob LIKE '%NtLmSsp%'", shapes)
        self.assertIn("search_blob LIKE '%Kerberos%'", shapes)
        self.assertIn("search_blob LIKE '%ADMIN$%'", shapes)
        self.assertIn("search_blob LIKE '%\\\\ADMIN$%'", shapes)
        self.assertIn(
            "lower(search_blob) LIKE '%1131f6aa-9c07-11d1-f79f-00c04fc2dcd2%'",
            shapes,
        )
        ntlm = next(item for item in inventory if item["shape"] == "search_blob LIKE '%NTLM%'")
        self.assertIn("pass_the_hash", ntlm["rule_ids"])

    def test_safe_prefilter_ntlm_admin_guid_and_short_token(self):
        ntlm = derive_prefilter(
            {
                "expr": "search_blob",
                "op": "LIKE",
                "negated": False,
                "pattern": "%NTLM%",
                "sql": "search_blob LIKE '%NTLM%'",
            }
        )
        self.assertEqual(ntlm["classification"], "SAFE_TEXT_PREFILTER")
        self.assertEqual(ntlm["alnum_run"], "NTLM")
        self.assertEqual(
            ntlm["candidate_sql"],
            "(search_blob ILIKE '%NTLM%' AND search_blob LIKE '%NTLM%')",
        )

        admin = derive_prefilter(
            {
                "expr": "search_blob",
                "op": "LIKE",
                "negated": False,
                "pattern": "%ADMIN$%",
                "sql": "search_blob LIKE '%ADMIN$%'",
            }
        )
        self.assertEqual(admin["alnum_run"], "ADMIN")
        self.assertEqual(
            admin["candidate_sql"],
            "(search_blob ILIKE '%ADMIN%' AND search_blob LIKE '%ADMIN$%')",
        )

        guid = derive_prefilter(
            {
                "expr": "lower(search_blob)",
                "op": "LIKE",
                "negated": False,
                "pattern": "%1131f6aa-9c07-11d1-f79f-00c04fc2dcd2%",
                "sql": "lower(search_blob) LIKE '%1131f6aa-9c07-11d1-f79f-00c04fc2dcd2%'",
            }
        )
        self.assertEqual(guid["classification"], "SAFE_TEXT_PREFILTER")
        self.assertEqual(guid["alnum_run"], "00c04fc2dcd2")
        self.assertTrue(guid["candidate_sql"].startswith("(search_blob ILIKE '%00c04fc2dcd2%'"))

        rc4 = derive_prefilter(
            {
                "expr": "search_blob",
                "op": "LIKE",
                "negated": False,
                "pattern": "%RC4%",
                "sql": "search_blob LIKE '%RC4%'",
            }
        )
        self.assertEqual(rc4["classification"], "SAFE_LOGICAL_PREFILTER_NO_TEXT_PRUNE")
        self.assertEqual(rc4["alnum_len"], 3)
        self.assertFalse(rc4["text_index_usable_length"])
        self.assertEqual(TEXT_INDEX_ILIKE_MIN_ALNUM, 4)

        denied = derive_prefilter(
            {
                "expr": "search_blob",
                "op": "LIKE",
                "negated": True,
                "pattern": "%PasswordPolicy%",
                "sql": "search_blob NOT LIKE '%PasswordPolicy%'",
            }
        )
        self.assertEqual(denied["classification"], "NO_SAFE_TEXT_PREFILTER")

    def test_or_wrap_is_branch_local(self):
        original = "(search_blob LIKE '%NTLM%' OR search_blob LIKE '%NtLmSsp%')"
        wrapped = wrap_like_sql(original)
        self.assertIn("(search_blob ILIKE '%NTLM%' AND search_blob LIKE '%NTLM%')", wrapped)
        self.assertIn("(search_blob ILIKE '%NtLmSsp%' AND search_blob LIKE '%NtLmSsp%')", wrapped)
        self.assertIn(" OR ", wrapped)

    def test_runtime_client_does_not_force_materialize_skip_indexes_on_insert_0(self):
        source = inspect.getsource(clickhouse_utils.get_client) + inspect.getsource(
            clickhouse_utils.get_fresh_client
        )
        self.assertNotIn("materialize_skip_indexes_on_insert", source)

    def test_evidence_artifact_records_not_ready_and_no_drop(self):
        self.assertTrue(os.path.exists(EVIDENCE), msg="D2A JSON evidence is required")
        with open(EVIDENCE) as handle:
            payload = json.load(handle)
        self.assertEqual(payload["version"], "4.25.2")
        self.assertFalse(payload["version_bumped"])
        self.assertEqual(payload["phase2_1_state"], "PHASE2_1_NOT_READY")
        self.assertEqual(payload["phase2_1d_preserved"], "PHASE2_1D_NOT_READY")
        self.assertIn(payload["token_decision"]["decision"], {
            "TOKEN_BLOOM_REDUNDANT",
            "TOKEN_BLOOM_INDEPENDENTLY_REQUIRED",
        })
        self.assertIn(payload["ngram_decision"]["decision"], {
            "NGRAM_TEXT_PREFILTER_REPLACEMENT_FEASIBLE",
            "NGRAM_MEASURED_EXCEPTION_REQUIRED",
            "NGRAM_DEPENDENCY_UNRESOLVED",
        })
        self.assertFalse(payload["no_later_phase"]["DROP_INDEX_production"])
        self.assertFalse(payload["no_later_phase"]["production_reader_changes"])


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
class LivePhase21D2AExplainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.database = f"cs_p21d2a_test_{uuid.uuid4().hex[:12]}"
        admin = _live_client("default")
        admin.command(f"CREATE DATABASE {cls.database}")
        cls.client = _live_client(cls.database)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.client.command(f"DROP DATABASE IF EXISTS {cls.database}")
        except Exception:
            pass

    def test_like_uses_ngram_ilike_four_char_uses_text_three_char_does_not(self):
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
                blob += " NTLM RC4"
            rows.append((1, blob, f"erk-{i}"))
        self.client.insert(
            "events_like",
            rows,
            column_names=["case_id", "search_blob", "evidence_record_key"],
            settings={"materialize_skip_indexes_on_insert": 1},
        )

        def explain(pred, settings=None):
            text = "\n".join(
                row[0]
                for row in self.client.query(
                    "EXPLAIN indexes = 1 SELECT count() FROM events_like WHERE " + pred,
                    settings=settings or {},
                ).result_rows
            )
            return parse_explain_indexes(text)

        like_ntlm = explain("search_blob LIKE '%NTLM%'")
        self.assertIn("idx_search_ngram", like_ntlm["skip_names"])
        self.assertFalse(like_ntlm["direct_text_index"])

        ilike_ntlm = explain("search_blob ILIKE '%NTLM%'")
        self.assertTrue(ilike_ntlm["direct_text_index"])
        self.assertIn("idx_search_blob_text", ilike_ntlm["skip_names"])

        ilike_rc4 = explain("search_blob ILIKE '%RC4%'")
        self.assertFalse(ilike_rc4["direct_text_index"])

        no_ngram = explain(
            "search_blob LIKE '%NTLM%'",
            settings={"ignore_data_skipping_indices": "idx_search_ngram"},
        )
        self.assertFalse(no_ngram.get("ngram_pruned"))
        self.assertFalse(no_ngram.get("token_pruned"))

        compound = explain(
            "search_blob ILIKE '%NTLM%' AND search_blob LIKE '%NTLM%'",
            settings={"ignore_data_skipping_indices": "idx_search_ngram,idx_search_token"},
        )
        self.assertTrue(compound["direct_text_index"])
        self.assertNotIn("idx_search_ngram", compound["skip_names"])
        self.assertNotIn("idx_search_token", compound["skip_names"])

        original_n = int(
            self.client.query(
                "SELECT count() FROM events_like WHERE search_blob LIKE {pat:String}",
                parameters={"pat": "%NTLM%"},
            ).result_rows[0][0]
        )
        candidate_n = int(
            self.client.query(
                "SELECT count() FROM events_like WHERE search_blob ILIKE {ilike:String} "
                "AND search_blob LIKE {pat:String}",
                parameters={"ilike": "%NTLM%", "pat": "%NTLM%"},
            ).result_rows[0][0]
        )
        self.assertEqual(original_n, 100)
        self.assertEqual(candidate_n, original_n)
