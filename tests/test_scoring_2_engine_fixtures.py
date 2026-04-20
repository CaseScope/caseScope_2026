import importlib.util
import os
import sys
import types
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("SECRET_KEY", "test-secret")

REPO_ROOT = Path(__file__).resolve().parents[1]
UTILS_DIR = REPO_ROOT / "utils"


def _load_module(name: str, relative_path: str):
    module_path = REPO_ROOT / relative_path
    spec = importlib.util.spec_from_file_location(name, module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


utils_pkg = sys.modules.setdefault("utils", types.ModuleType("utils"))
utils_pkg.__path__ = [str(UTILS_DIR)]

pattern_check_definitions = _load_module(
    "scoring2_pattern_check_definitions",
    Path("utils") / "pattern_check_definitions.py",
)
deterministic_evidence_engine = _load_module(
    "scoring2_deterministic_evidence_engine",
    Path("utils") / "deterministic_evidence_engine.py",
)

CheckDefinition = pattern_check_definitions.CheckDefinition
CheckResult = pattern_check_definitions.CheckResult
CoverageAssessment = pattern_check_definitions.CoverageAssessment
EvidencePackage = pattern_check_definitions.EvidencePackage


class Scoring2EngineFixturesTestCase(unittest.TestCase):
    def setUp(self):
        self.engine = object.__new__(deterministic_evidence_engine.DeterministicEvidenceEngine)

    def test_field_match_machine_account_disqualifier_detects_computer_account(self):
        result = self.engine._evaluate_field_match(
            CheckDefinition(
                id="ptt_machine_account",
                name="Account is a machine account ($)",
                weight=0,
                check_type="field_match",
                disqualifier=True,
                role="context",
            ),
            {"username": "HOST-A$"},
        )

        self.assertEqual(result.status, "PASS")
        self.assertEqual(result.contribution, 0.0)
        self.assertIn("machine/system account", result.detail)

    def test_scoring_v2_keeps_missing_telemetry_at_zero_contribution(self):
        scoring = self.engine._compute_score_v2(
            pattern_id="fixture_pattern",
            pattern_name="Fixture Pattern",
            pattern_config={
                "scoring_version": "2.0",
                "anchor_class": "gateway",
                "emit_threshold_mode": "score_and_required",
                "required_pass_count": 1,
                "allow_anchor_only_emit": False,
            },
            check_defs=[
                CheckDefinition(
                    id="anchor",
                    name="Anchor",
                    weight=20,
                    check_type="anchor_match",
                    role="anchor",
                ),
                CheckDefinition(
                    id="required_user_signal",
                    name="Required User Signal",
                    weight=30,
                    check_type="field_match",
                    role="corroboration",
                    required_pass=True,
                ),
                CheckDefinition(
                    id="missing_context",
                    name="Missing Context",
                    weight=50,
                    check_type="threshold",
                    coverage_policy="zero",
                ),
            ],
            checks=[
                CheckResult(
                    check_id="anchor",
                    status="PASS",
                    weight=20,
                    contribution=20,
                    detail="username=alice, source_host=HOST-A",
                    source="anchor_match",
                ),
                CheckResult(
                    check_id="required_user_signal",
                    status="PASS",
                    weight=30,
                    contribution=30,
                    detail="username=alice (user account)",
                    source="field_match",
                ),
                CheckResult(
                    check_id="missing_context",
                    status="INCONCLUSIVE",
                    weight=50,
                    contribution=15,
                    detail="Missing critical source: Sysmon",
                    source="coverage",
                ),
            ],
            bursts=[],
            sequences=[],
            coverage=CoverageAssessment(host="HOST-A", coverage_status="partial"),
        )

        self.assertEqual(scoring["score"], 50.0)
        self.assertEqual(scoring["max_possible"], 100.0)
        self.assertEqual(scoring["evaluable_weight"], 100.0)
        self.assertEqual(scoring["excluded_weight"], 0.0)
        self.assertTrue(scoring["eligible_to_emit"])
        self.assertTrue(scoring["coverage_gap_present"])

    def test_scoring_v2_tracks_excluded_weight_for_exclude_policy(self):
        scoring = self.engine._compute_score_v2(
            pattern_id="fixture_pattern",
            pattern_name="Fixture Pattern",
            pattern_config={"scoring_version": "2.0", "anchor_class": "definitive"},
            check_defs=[
                CheckDefinition(
                    id="anchor",
                    name="Anchor",
                    weight=20,
                    check_type="anchor_match",
                    role="anchor",
                ),
                CheckDefinition(
                    id="excluded_missing_context",
                    name="Excluded Missing Context",
                    weight=40,
                    check_type="threshold",
                    coverage_policy="exclude",
                ),
            ],
            checks=[
                CheckResult(
                    check_id="anchor",
                    status="PASS",
                    weight=20,
                    contribution=20,
                    detail="username=alice, source_host=HOST-A",
                    source="anchor_match",
                ),
                CheckResult(
                    check_id="excluded_missing_context",
                    status="INCONCLUSIVE",
                    weight=40,
                    contribution=12,
                    detail="Missing critical source: Security",
                    source="coverage",
                ),
            ],
            bursts=[],
            sequences=[],
            coverage=CoverageAssessment(host="HOST-A", coverage_status="partial"),
        )

        self.assertEqual(scoring["score"], 20.0)
        self.assertEqual(scoring["evaluable_weight"], 20.0)
        self.assertEqual(scoring["excluded_weight"], 40.0)
        self.assertEqual(scoring["raw_total_weight"], 60.0)
        self.assertTrue(scoring["coverage_gap_present"])

    def test_scoring_v2_requires_explicit_anchor_detail(self):
        with self.assertRaises(RuntimeError):
            self.engine._compute_score_v2(
                pattern_id="fixture_pattern",
                pattern_name="Fixture Pattern",
                pattern_config={"scoring_version": "2.0", "anchor_class": "definitive"},
                check_defs=[
                    CheckDefinition(
                        id="anchor",
                        name="Anchor",
                        weight=20,
                        check_type="anchor_match",
                        role="anchor",
                    ),
                ],
                checks=[
                    CheckResult(
                        check_id="anchor",
                        status="PASS",
                        weight=20,
                        contribution=20,
                        detail="anchor matched",
                        source="anchor_match",
                    ),
                ],
                bursts=[],
                sequences=[],
                coverage=CoverageAssessment(host="HOST-A", coverage_status="full"),
            )

    def test_sanitize_anchor_stringifies_uuid_values_for_json_storage(self):
        sanitized = self.engine._sanitize_anchor(
            {
                "source_host": "HOST-A",
                "event_uuid": uuid.UUID("12345678-1234-5678-1234-567812345678"),
            }
        )

        self.assertEqual(
            sanitized["event_uuid"],
            "12345678-1234-5678-1234-567812345678",
        )
        self.assertIsInstance(sanitized["event_uuid"], str)

    def test_spread_bonus_reconciles_scoring_v2_metadata(self):
        class FakeClient:
            @staticmethod
            def query(_query, parameters=None):
                return SimpleNamespace(
                    result_rows=[(20, 1, "2026-04-20T00:00:00", "2026-04-20T00:05:00", 5)]
                )

        self.engine.case_id = 135
        self.engine._get_ch = lambda: FakeClient()
        self.engine._parse_ts = deterministic_evidence_engine.DeterministicEvidenceEngine._parse_ts

        packages = [
            EvidencePackage(
                anchor={"username": "alice", "source_host": "HOST-A"},
                pattern_id="pass_the_ticket",
                pattern_name="Pass the Ticket",
                correlation_key="HOST-A|alice",
                deterministic_score=40.0,
                max_possible_score=40.0,
                eligible_to_emit=False,
                emit_block_reasons=["score_below_emit_threshold"],
                scoring_version="2.0",
                evaluable_weight=40.0,
                raw_total_weight=40.0,
            ),
            EvidencePackage(
                anchor={"username": "alice", "source_host": "HOST-B"},
                pattern_id="pass_the_ticket",
                pattern_name="Pass the Ticket",
                correlation_key="HOST-B|alice",
                deterministic_score=40.0,
                max_possible_score=40.0,
                eligible_to_emit=False,
                emit_block_reasons=["score_below_emit_threshold"],
                scoring_version="2.0",
                evaluable_weight=40.0,
                raw_total_weight=40.0,
            ),
        ]

        self.engine._evaluate_spread(
            packages,
            {
                "pivot_field": "username",
                "weight": 15,
                "event_filter": "event_id = '4624'",
                "target_field": "source_host",
                "tiers": [(2, 0.3), (5, 0.6), (10, 0.85), (20, 1.0)],
            },
            {
                "scoring_version": "2.0",
                "anchor_class": "gateway",
                "emit_threshold_mode": "score_only",
            },
        )

        for package in packages:
            self.assertEqual(package.deterministic_score, 55.0)
            self.assertEqual(package.evaluable_weight, 55.0)
            self.assertEqual(package.raw_total_weight, 55.0)
            self.assertEqual(package.max_possible_score, 55.0)
            self.assertEqual(package.emit_block_reasons, [])
            self.assertTrue(package.eligible_to_emit)

    def test_burst_query_scopes_to_pattern_correlation_fields(self):
        captured = {}

        class FakeClient:
            @staticmethod
            def query(query, parameters=None):
                captured["query"] = query
                captured["parameters"] = parameters
                return SimpleNamespace(
                    result_rows=[
                        (
                            "alice",
                            "HOST-A",
                            "10.0.0.5",
                            "2026-04-20T00:00:00",
                            12,
                            1,
                            "2026-04-20T00:00:00",
                            "2026-04-20T00:00:18",
                            18,
                        )
                    ]
                )

        self.engine.case_id = 135
        self.engine.rule_catalog = SimpleNamespace(
            get_burst_config=lambda pattern_id: {
                "window_seconds": 120,
                "min_events": 5,
                "event_ids": ["4625", "18456"],
            }
            if pattern_id == "brute_force"
            else None
        )
        self.engine._get_ch = lambda: FakeClient()

        bursts = self.engine._detect_bursts(
            "brute_force",
            {
                "case_id": 135,
                "window_start": "2026-04-20T00:00:00",
                "window_end": "2026-04-20T01:00:00",
                "username": "alice",
                "source_host": "HOST-A",
                "src_ip": "10.0.0.5",
            },
            correlation_fields=["username", "src_ip", "source_host"],
        )

        self.assertEqual(len(bursts), 1)
        self.assertIn("AND username = {username:String}", captured["query"])
        self.assertIn("AND source_host = {source_host:String}", captured["query"])
        self.assertIn("AND src_ip = {src_ip:String}", captured["query"])
        self.assertEqual(captured["parameters"]["username"], "alice")
        self.assertEqual(captured["parameters"]["source_host"], "HOST-A")
        self.assertEqual(captured["parameters"]["src_ip"], "10.0.0.5")

    def test_spread_uses_anchor_times_when_coverage_windows_are_missing(self):
        captured = {}

        class FakeClient:
            @staticmethod
            def query(query, parameters=None):
                captured["query"] = query
                captured["parameters"] = parameters
                return SimpleNamespace(
                    result_rows=[(2, 1, "2026-04-20T00:00:00", "2026-04-20T00:05:00", 5)]
                )

        self.engine.case_id = 135
        self.engine._get_ch = lambda: FakeClient()
        self.engine._parse_ts = deterministic_evidence_engine.DeterministicEvidenceEngine._parse_ts

        packages = [
            EvidencePackage(
                anchor={"username": "alice", "timestamp": "2026-04-20T00:00:00"},
                pattern_id="pass_the_ticket",
                pattern_name="Pass the Ticket",
                correlation_key="HOST-A|alice",
                coverage=CoverageAssessment(host="", coverage_status="unknown"),
            ),
            EvidencePackage(
                anchor={"username": "alice", "timestamp": "2026-04-20T00:05:00"},
                pattern_id="pass_the_ticket",
                pattern_name="Pass the Ticket",
                correlation_key="HOST-B|alice",
                coverage=CoverageAssessment(host="", coverage_status="unknown"),
            ),
        ]

        self.engine._evaluate_spread(
            packages,
            {
                "pivot_field": "username",
                "weight": 15,
                "event_filter": "event_id = '4624'",
                "target_field": "source_host",
                "tiers": [(2, 0.3), (5, 0.6), (10, 0.85), (20, 1.0)],
            },
            {
                "scoring_version": "2.0",
                "anchor_class": "gateway",
                "emit_threshold_mode": "score_only",
            },
        )

        self.assertIn("AND timestamp BETWEEN {spread_ws:DateTime64} AND {spread_we:DateTime64}", captured["query"])
        self.assertEqual(captured["parameters"]["spread_ws"].isoformat(), "2026-04-20T00:00:00")
        self.assertEqual(captured["parameters"]["spread_we"].isoformat(), "2026-04-20T00:05:00")


if __name__ == "__main__":
    unittest.main()
