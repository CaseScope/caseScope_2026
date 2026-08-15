"""Phase 1 Step 3 tests: IOC recall comparator + profiler set-based semantics.

Run with:

    /opt/casescope/venv/bin/python -m unittest tests.test_phase1_step3 tests.test_ioc_artifact_tagger tests.test_behavioral_profiler_contract

Do not use production-bound full unittest discovery.
"""
from __future__ import annotations

import os
import unittest
from types import SimpleNamespace

os.environ.setdefault("SECRET_KEY", "phase1-step3-test-secret")

from utils.ioc_artifact_tagger import build_ioc_match_clause
from utils.phase1_step3_ioc_recall import (
    PATH_ILIKE,
    PATH_LEGACY,
    PATH_NO_LOWER,
    PATH_NO_RAW_JSON,
    PATH_STRUCTURED_BLOB,
    build_path_clause,
    classify_miss,
    compare_sets,
    fixture_events,
    fixture_specs,
    match_key,
)
from utils.phase1_step3_profiler import (
    canonicalize_system_profile,
    canonicalize_user_profile,
    diff_canonical,
)


class IOCClauseContractTestCase(unittest.TestCase):
    def test_legacy_default_still_searches_raw_json_and_search_blob(self):
        clause = build_ioc_match_clause("evil.example", "Domain", "substring")
        self.assertIn("lower(raw_json)", clause)
        self.assertIn("lower(search_blob)", clause)

    def test_no_raw_json_path_drops_raw_json_keeps_blob(self):
        clause = build_path_clause("evil.example", "Domain", "substring", path=PATH_NO_RAW_JSON)
        self.assertNotIn("raw_json", clause)
        self.assertIn("search_blob", clause)

    def test_username_no_raw_json_keeps_username_column(self):
        clause = build_path_clause("alice", "Username", "substring", path=PATH_NO_RAW_JSON)
        self.assertIn("username", clause)
        self.assertIn("search_blob", clause)
        self.assertNotIn("raw_json", clause)

    def test_sensitive_path_removes_lower_wrapper(self):
        clause = build_path_clause("evil.example", "Domain", "substring", path=PATH_NO_LOWER)
        self.assertIn("search_blob LIKE", clause)
        self.assertNotIn("lower(search_blob)", clause)
        self.assertNotIn("lower(raw_json)", clause)

    def test_ilike_path_uses_ilike(self):
        clause = build_path_clause("evil.example", "Domain", "substring", path=PATH_ILIKE)
        self.assertIn("ILIKE", clause)
        self.assertNotIn("lower(search_blob)", clause)

    def test_structured_path_adds_typed_hash_column(self):
        clause = build_path_clause(
            "a" * 64, "SHA256 Hash", "token", path=PATH_STRUCTURED_BLOB
        )
        self.assertIn("file_hash_sha256", clause)
        self.assertIn("search_blob", clause)
        self.assertNotIn("raw_json", clause)

    def test_token_still_uses_has_token_case_insensitive(self):
        clause = build_path_clause("ltsvc", "File Name", "token", path=PATH_LEGACY)
        self.assertIn("hasTokenCaseInsensitive", clause)


class IOCRecallSetMathTestCase(unittest.TestCase):
    def test_compare_sets_empty_a_minus_b_is_pass(self):
        a = [(1, "erk:v2:" + "a" * 64, "u1")]
        b = [(1, "erk:v2:" + "a" * 64, "u1"), (1, "erk:v2:" + "b" * 64, "u1")]
        result = compare_sets(a, b)
        self.assertTrue(result["recall_gate_pass"])
        self.assertEqual(result["a_minus_b_count"], 0)
        self.assertEqual(result["b_minus_a_count"], 1)

    def test_raw_json_only_miss_classification(self):
        rec = SimpleNamespace(
            hit_raw_json=True,
            hit_search_blob=False,
            hit_structured=False,
            hit_username=False,
            hit_extra_fields=False,
        )
        self.assertEqual(classify_miss(rec), "RAW_JSON_ONLY_TRUE_MATCH")

    def test_fixture_specs_cover_required_shapes(self):
        labels = {spec.label for spec in fixture_specs()}
        for required in (
            "typed_username",
            "blob_only_token",
            "raw_json_only_domain",
            "nested_json_domain",
            "mixed_case_domain",
            "ipv4",
            "ipv6",
            "sha256",
            "url",
            "filename",
            "path",
            "punct_adjacent",
            "substring_fp",
        ):
            self.assertIn(required, labels)

    def test_fixture_events_isolate_raw_json_only(self):
        events = {event.source_file: event for event in fixture_events()}
        raw_only = events["raw_json_only_domain.json"]
        self.assertIn("rawjson-only.example", raw_only.raw_json)
        self.assertNotIn("rawjson-only.example", raw_only.search_blob)

    def test_match_key_uses_case_erk_uuid(self):
        self.assertEqual(
            match_key(3, "erk:v2:" + "c" * 64, "uuid"),
            (3, "erk:v2:" + "c" * 64, "uuid"),
        )


class ProfilerCanonicalParityTestCase(unittest.TestCase):
    def test_username_or_sid_metrics_count_event_once(self):
        from tests.test_behavioral_profiler_contract import BehavioralProfiler

        profiler = BehavioralProfiler(case_id=7, analysis_id="step3")
        profiler.min_events_for_profile = 1
        rows = [(9, 2, "2024-08-16", "4624", "HOST-A", "HOST-B", "NTLM", 3, 4)]
        metrics = profiler._user_metrics_from_rows(rows)
        self.assertEqual(metrics["total_events"], 4)
        self.assertEqual(metrics["total_logons"], 4)

    def test_system_or_match_does_not_triple_count_same_grouped_row(self):
        from tests.test_behavioral_profiler_contract import BehavioralProfiler

        profiler = BehavioralProfiler(case_id=7, analysis_id="step3")
        profiler.min_events_for_profile = 1
        # Legacy/set-based grouped rows already collapse the OR; one row = one count.
        rows = [(9, "2024-08-16", "ALICE", "10.0.0.1", "4624", "CMD.EXE", 7)]
        metrics = profiler._system_metrics_from_rows(rows, "HOST-A")
        self.assertEqual(metrics["total_events"], 7)

    def test_canonical_user_sorts_top_n_ties(self):
        payload = canonicalize_user_profile({
            "identity": "user:1",
            "username": "alice",
            "sid": "S-1-5-1",
            "total_events": 10,
            "activity_hours": {8: 5, 9: 5},
            "peak_hours": [9, 8],
            "typical_source_hosts": [
                {"value": "B", "count": 5, "percentage": 50},
                {"value": "A", "count": 5, "percentage": 50},
            ],
        })
        self.assertEqual([row["value"] for row in payload["typical_source_hosts"]], ["A", "B"])
        self.assertEqual(payload["peak_hours"], [8, 9])

    def test_diff_canonical_detects_count_change(self):
        left = {"users": [{"identity": "user:1", "total_events": 10}], "systems": [], "user_digest": "a", "system_digest": "b"}
        right = {"users": [{"identity": "user:1", "total_events": 11}], "systems": [], "user_digest": "c", "system_digest": "b"}
        diff = diff_canonical(left, right)
        self.assertFalse(diff["semantic_parity"])
        self.assertEqual(diff["user_payload_mismatches"], ["user:1"])


if __name__ == "__main__":
    unittest.main()
