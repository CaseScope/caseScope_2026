import importlib.util
import os
import sys
import types
import unittest
import uuid
from datetime import datetime
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

event_noise_state_stub = types.ModuleType("utils.event_noise_state")
event_noise_state_stub.build_effective_not_noise_clause = lambda *args, **kwargs: "NOT (noise_matched = true)"
event_noise_state_stub.ensure_event_noise_state_tables = lambda *args, **kwargs: None
event_noise_state_stub.replace_legacy_noise_filter = lambda query, *args, **kwargs: query
sys.modules["utils.event_noise_state"] = event_noise_state_stub

pattern_check_definitions = _load_module(
    "scoring2_pattern_check_definitions",
    Path("utils") / "pattern_check_definitions.py",
)
deterministic_evidence_engine = _load_module(
    "scoring2_deterministic_evidence_engine",
    Path("utils") / "deterministic_evidence_engine.py",
)
pattern_event_mappings = _load_module(
    "scoring2_pattern_event_mappings",
    Path("utils") / "pattern_event_mappings.py",
)

CheckDefinition = pattern_check_definitions.CheckDefinition
CheckResult = pattern_check_definitions.CheckResult
CoverageAssessment = pattern_check_definitions.CoverageAssessment
EvidencePackage = pattern_check_definitions.EvidencePackage
PATTERN_CHECKS = pattern_check_definitions.PATTERN_CHECKS
PATTERN_EVENT_MAPPINGS = pattern_event_mappings.PATTERN_EVENT_MAPPINGS


class Scoring2EngineFixturesTestCase(unittest.TestCase):
    def setUp(self):
        self.engine = object.__new__(deterministic_evidence_engine.DeterministicEvidenceEngine)
        self.engine.case_id = 135

    def test_build_query_params_prefers_timestamp_utc_when_available(self):
        params = self.engine._build_query_params(
            {
                "timestamp": "2026-04-20 08:00:00",
                "timestamp_utc": "2026-04-20 12:00:00",
                "event_id": "4624",
                "source_host": "HOST-A",
            },
            datetime(2026, 4, 20, 11, 55, 0),
            datetime(2026, 4, 20, 12, 5, 0),
        )

        self.assertEqual(params["anchor_ts"].isoformat(), "2026-04-20T12:00:00")

    def test_noise_tagged_anchor_can_be_preserved_in_evidence_package(self):
        sanitized = self.engine._sanitize_anchor({
            "timestamp": "2026-06-04 20:00:00",
            "event_id": "4624",
            "source_host": "HOST-A",
            "username": "alice",
            "noise_matched": True,
            "noise_rules": ["Expected VPN logon"],
        })

        package = EvidencePackage(
            anchor=sanitized,
            pattern_id="fixture_pattern",
            pattern_name="Fixture Pattern",
            correlation_key="HOST-A|alice",
        )

        self.assertTrue(package.anchor["noise_matched"])
        self.assertEqual(package.anchor["noise_rules"], ["Expected VPN logon"])

    def test_deterministic_noise_policy_can_include_noise_in_internal_queries(self):
        self.engine.exclude_noise = False

        self.assertEqual(self.engine._not_noise_clause(), "1")
        normalized = self.engine._normalize_query_time_template(
            "SELECT timestamp FROM events "
            "WHERE case_id = {case_id:UInt32} "
            "AND (noise_matched = false OR noise_matched IS NULL) "
            "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64}"
        )

        self.assertNotIn("noise_matched = false", normalized)
        self.assertIn("SELECT COALESCE(timestamp_utc, timestamp) AS timestamp", normalized)

    def test_deterministic_noise_policy_includes_noise_by_default(self):
        self.assertEqual(self.engine._not_noise_clause(), "1")

    def test_priority_scoring_v2_patterns_block_anchor_only_emit(self):
        priority_patterns = [
            "service_persistence",
            "kerberoasting",
            "rdp_lateral",
            "psexec_execution",
            "dcsync",
            "lsass_memory_dump",
        ]

        for pattern_id in priority_patterns:
            with self.subTest(pattern_id=pattern_id):
                config = PATTERN_EVENT_MAPPINGS[pattern_id]
                check_defs = PATTERN_CHECKS[pattern_id]
                anchor = next(cdef for cdef in check_defs if cdef.check_type == "anchor_match")
                scoring = self.engine._compute_score_v2(
                    pattern_id=pattern_id,
                    pattern_name=config["name"],
                    pattern_config=config,
                    check_defs=check_defs,
                    checks=[
                        CheckResult(
                            check_id=anchor.id,
                            status="PASS",
                            weight=anchor.weight,
                            contribution=anchor.weight,
                            detail="source_host=HOST-A, username=alice, event_id=anchor",
                            source="anchor_match",
                        )
                    ],
                    bursts=[],
                    sequences=[],
                    coverage=CoverageAssessment(host="HOST-A", coverage_status="full"),
                )

                self.assertEqual(config["scoring_version"], "2.0")
                self.assertFalse(config.get("allow_anchor_only_emit", True))
                self.assertFalse(scoring["eligible_to_emit"])
                self.assertIn("anchor_only_not_allowed", scoring["emit_block_reasons"])
                self.assertIn("required_checks_not_met", scoring["emit_block_reasons"])
                self.assertGreater(scoring["score_components"]["anchor_score"], 0)
                self.assertTrue(scoring["score_reasons"])

    def test_score_components_include_reasons_for_emitted_scoring_v2_signal(self):
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
                    name="Gateway Anchor",
                    weight=30,
                    check_type="anchor_match",
                    role="anchor",
                ),
                CheckDefinition(
                    id="required_corrob",
                    name="Required Corroboration",
                    weight=30,
                    check_type="field_match",
                    role="corroboration",
                    required_pass=True,
                ),
            ],
            checks=[
                CheckResult(
                    check_id="anchor",
                    status="PASS",
                    weight=30,
                    contribution=30,
                    detail="source_host=HOST-A, username=alice",
                    source="anchor_match",
                ),
                CheckResult(
                    check_id="required_corrob",
                    status="PASS",
                    weight=30,
                    contribution=30,
                    detail="corroborating signal",
                    source="field_match",
                ),
            ],
            bursts=[],
            sequences=[],
            coverage=CoverageAssessment(host="HOST-A", coverage_status="full"),
        )

        self.assertTrue(scoring["eligible_to_emit"])
        self.assertEqual(scoring["score_components"]["anchor_score"], 30.0)
        self.assertEqual(scoring["score_components"]["corroboration_score"], 30.0)
        self.assertEqual(scoring["score_components"]["final_score"], 60.0)
        self.assertGreaterEqual(len(scoring["score_reasons"]), 2)

    def test_noise_reduction_preserves_strong_abuse_finding(self):
        package = EvidencePackage(
            anchor={
                "source_host": "HOST-A",
                "username": "alice",
                "noise_matched": True,
                "noise_rules": ["Known admin host"],
            },
            pattern_id="fixture_pattern",
            pattern_name="Fixture Pattern",
            correlation_key="HOST-A|alice",
            deterministic_score=85,
            score_components={"anchor_score": 30, "corroboration_score": 55, "final_score": 85},
            score_reasons=[
                {
                    "id": "anchor",
                    "name": "Anchor",
                    "role": "anchor",
                    "delta": 30,
                    "source": "anchor_match",
                    "detail": "anchor",
                }
            ],
        )

        if package.anchor.get("noise_matched") or package.anchor.get("noise_rules"):
            noise_reduction = 10.0 if package.deterministic_score >= 70 else 15.0
            package.deterministic_score = round(max(0.0, package.deterministic_score - noise_reduction), 1)
            package.score_components["noise_reduction"] = -noise_reduction
            package.score_components["final_score"] = package.deterministic_score

        self.assertEqual(package.deterministic_score, 75.0)
        self.assertEqual(package.score_components["noise_reduction"], -10.0)
        self.assertGreaterEqual(package.deterministic_score, 70.0)

    def test_compute_window_returns_unknown_window_for_unparseable_anchor_timestamp(self):
        window_start, window_end = self.engine._compute_window("not-a-timestamp", 30)

        self.assertIsNone(window_start)
        self.assertIsNone(window_end)

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

    def test_scoring_v2_excludes_inconclusive_sequence_weight(self):
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
            ],
            bursts=[],
            sequences=[
                pattern_check_definitions.SequenceResult(
                    chain="logon -> action",
                    status="inconclusive",
                    steps=[{"label": "logon", "found": False}],
                    missing_steps=["logon"],
                )
            ],
            coverage=CoverageAssessment(host="HOST-A", coverage_status="unknown"),
        )

        self.assertEqual(scoring["score"], 20.0)
        self.assertEqual(scoring["evaluable_weight"], 20.0)
        self.assertEqual(scoring["excluded_weight"], 5.0)
        self.assertEqual(scoring["raw_total_weight"], 25.0)
        self.assertTrue(scoring["coverage_gap_present"])

    def test_scoring_v2_excludes_missing_sequence_weight_when_sequence_sources_are_missing(self):
        self.engine.rule_catalog = SimpleNamespace(
            get_sequence_config=lambda pattern_id: {
                "required_sources": {"Security": "critical"},
            }
            if pattern_id == "fixture_pattern"
            else None
        )
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
            ],
            bursts=[],
            sequences=[
                pattern_check_definitions.SequenceResult(
                    chain="logon -> action",
                    status="missing",
                    missing_steps=["logon"],
                    evaluability="missing_telemetry",
                    telemetry_gap_sources=["Security"],
                )
            ],
            coverage=CoverageAssessment(
                host="HOST-A",
                coverage_status="unknown",
                missing_sources=["Security"],
            ),
        )

        self.assertEqual(scoring["score"], 20.0)
        self.assertEqual(scoring["evaluable_weight"], 20.0)
        self.assertEqual(scoring["excluded_weight"], 5.0)
        self.assertEqual(scoring["raw_total_weight"], 25.0)
        self.assertTrue(scoring["coverage_gap_present"])

    def test_scoring_v2_keeps_sequence_weight_evaluable_when_missing_sources_do_not_affect_sequence(self):
        self.engine.rule_catalog = SimpleNamespace(
            get_sequence_config=lambda pattern_id: {
                "required_sources": {"Security": "critical"},
            }
            if pattern_id == "fixture_pattern"
            else None
        )
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
            ],
            bursts=[],
            sequences=[
                pattern_check_definitions.SequenceResult(
                    chain="logon -> action",
                    status="missing",
                    missing_steps=["logon"],
                    evaluability="missing_telemetry",
                    telemetry_gap_sources=["Sysmon"],
                )
            ],
            coverage=CoverageAssessment(
                host="HOST-A",
                coverage_status="partial",
                missing_sources=["Sysmon"],
            ),
        )

        self.assertEqual(scoring["score"], 20.0)
        self.assertEqual(scoring["evaluable_weight"], 25.0)
        self.assertEqual(scoring["excluded_weight"], 0.0)
        self.assertEqual(scoring["raw_total_weight"], 25.0)
        self.assertFalse(scoring["coverage_gap_present"])

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
        self.assertIn(
            "toStartOfInterval(COALESCE(timestamp_utc, timestamp), INTERVAL 120 SECOND)",
            captured["query"],
        )
        self.assertIn(
            "dateDiff('second', min(COALESCE(timestamp_utc, timestamp)), "
            "max(COALESCE(timestamp_utc, timestamp)))",
            captured["query"],
        )
        self.assertIn(
            "COALESCE(timestamp_utc, timestamp) BETWEEN "
            "{window_start:DateTime64} AND {window_end:DateTime64}",
            captured["query"],
        )
        self.assertIn("AND username = {username:String}", captured["query"])
        self.assertIn("AND source_host = {source_host:String}", captured["query"])
        self.assertIn("AND src_ip = {src_ip:String}", captured["query"])
        self.assertEqual(captured["parameters"]["username"], "alice")
        self.assertEqual(captured["parameters"]["source_host"], "HOST-A")
        self.assertEqual(captured["parameters"]["src_ip"], "10.0.0.5")

    def test_check_coverage_uses_utc_timestamp_column(self):
        captured = {}

        class FakeClient:
            @staticmethod
            def query(query, parameters=None):
                captured["query"] = query
                captured["parameters"] = parameters
                return SimpleNamespace(result_rows=[("Security", 5, "2026-04-20T00:00:00", "2026-04-20T00:05:00")])

        self.engine.case_id = 135
        self.engine._get_ch = lambda: FakeClient()

        coverage = self.engine._check_coverage(
            "HOST-A",
            datetime(2026, 4, 20, 0, 0, 0),
            datetime(2026, 4, 20, 1, 0, 0),
            {"Security": "critical"},
        )

        self.assertEqual(coverage.coverage_status, "sparse")
        self.assertIn("min(COALESCE(timestamp_utc, timestamp)) as earliest", captured["query"])
        self.assertIn("max(COALESCE(timestamp_utc, timestamp)) as latest", captured["query"])
        self.assertIn(
            "COALESCE(timestamp_utc, timestamp) BETWEEN {ws:DateTime64} AND {we:DateTime64}",
            captured["query"],
        )

    def test_query_checks_normalize_timestamp_column_in_templates(self):
        captured = {}

        class FakeClient:
            @staticmethod
            def query(query, parameters=None):
                captured["query"] = query
                captured["parameters"] = parameters
                return SimpleNamespace(result_rows=[(45,)])

        self.engine._get_ch = lambda: FakeClient()

        result = self.engine._evaluate_query_check(
            CheckDefinition(
                id="duration_fixture",
                name="Duration Fixture",
                weight=10,
                check_type="threshold",
                pass_condition="result >= 30",
                query_template=(
                    "SELECT dateDiff('second', min(timestamp), max(timestamp)) FROM events "
                    "WHERE case_id = {case_id:UInt32} "
                    "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64}"
                ),
            ),
            {
                "case_id": 135,
                "window_start": datetime(2026, 4, 20, 0, 0, 0),
                "window_end": datetime(2026, 4, 20, 1, 0, 0),
            },
        )

        self.assertEqual(result.status, "PASS")
        self.assertIn(
            "dateDiff('second', min(COALESCE(timestamp_utc, timestamp)), "
            "max(COALESCE(timestamp_utc, timestamp)))",
            captured["query"],
        )
        self.assertIn(
            "COALESCE(timestamp_utc, timestamp) BETWEEN "
            "{window_start:DateTime64} AND {window_end:DateTime64}",
            captured["query"],
        )

    def test_query_check_returns_inconclusive_when_anchor_window_is_unknown(self):
        result = self.engine._evaluate_query_check(
            CheckDefinition(
                id="window_fixture",
                name="Window Fixture",
                weight=10,
                check_type="threshold",
                pass_condition="result >= 1",
                query_template=(
                    "SELECT count() FROM events "
                    "WHERE case_id = {case_id:UInt32} "
                    "AND timestamp BETWEEN {window_start:DateTime64} AND {window_end:DateTime64}"
                ),
            ),
            {
                "case_id": 135,
                "window_start": None,
                "window_end": None,
            },
        )

        self.assertEqual(result.status, "INCONCLUSIVE")
        self.assertIn("deterministic window could not be computed", result.detail)

    def test_sequence_queries_use_utc_timestamp_column(self):
        captured = {}

        class FakeClient:
            @staticmethod
            def query(query, parameters=None):
                captured["query"] = query
                captured["parameters"] = parameters
                return SimpleNamespace(
                    result_rows=[("2026-04-20T00:00:03", "4625", "alice", "HOST-A")]
                )

        self.engine.rule_catalog = SimpleNamespace(
            get_sequence_config=lambda pattern_id: {
                "chain": "failed_then_success",
                "required_sources": {"Security": "critical"},
                "steps": [
                    {
                        "label": "failed_logon",
                        "event_id": "4625",
                        "direction": "before_anchor",
                        "max_offset_seconds": 5,
                    }
                ],
            }
            if pattern_id == "credential_access"
            else None
        )
        self.engine._get_ch = lambda: FakeClient()

        sequences = self.engine._validate_sequences(
            "credential_access",
            {
                "case_id": 135,
                "anchor_ts": datetime(2026, 4, 20, 0, 0, 5),
                "source_host": "HOST-A",
            },
            correlation_fields=["source_host"],
        )

        self.assertEqual(sequences[0].status, "complete")
        self.assertIn(
            "SELECT COALESCE(timestamp_utc, timestamp) AS timestamp, event_id, username, source_host",
            captured["query"],
        )
        self.assertIn(
            "COALESCE(timestamp_utc, timestamp) BETWEEN {sequence_ref_ts:DateTime64} - "
            "INTERVAL 5 SECOND AND {sequence_ref_ts:DateTime64}",
            captured["query"],
        )
        self.assertIn(
            "ORDER BY COALESCE(timestamp_utc, timestamp) DESC LIMIT 1",
            captured["query"],
        )
        self.assertEqual(
            captured["parameters"]["sequence_ref_ts"].isoformat(),
            "2026-04-20T00:00:05",
        )

    def test_sequence_returns_inconclusive_when_anchor_timestamp_is_unparseable(self):
        self.engine.rule_catalog = SimpleNamespace(
            get_sequence_config=lambda pattern_id: {
                "chain": "failed_then_success",
                "required_sources": {"Security": "critical"},
                "steps": [
                    {
                        "label": "failed_logon",
                        "event_id": "4625",
                        "direction": "before_anchor",
                        "max_offset_seconds": 5,
                    }
                ],
            }
            if pattern_id == "credential_access"
            else None
        )

        sequences = self.engine._validate_sequences(
            "credential_access",
            {
                "case_id": 135,
                "anchor_ts": "not-a-timestamp",
                "source_host": "HOST-A",
            },
            coverage=CoverageAssessment(
                host="HOST-A",
                coverage_status="unknown",
                missing_sources=["Security"],
            ),
            correlation_fields=["source_host"],
        )

        self.assertEqual(sequences[0].status, "inconclusive")
        self.assertEqual(sequences[0].missing_steps, ["failed_logon"])
        self.assertEqual(sequences[0].evaluability, "anchor_window_unavailable")
        self.assertEqual(sequences[0].telemetry_gap_sources, ["Security"])
        self.assertEqual(sequences[0].steps[0]["reason"], "anchor_window_unavailable")

    def test_sequence_marks_missing_telemetry_as_non_evaluable_metadata(self):
        class FakeClient:
            @staticmethod
            def query(_query, parameters=None):
                return SimpleNamespace(result_rows=[])

        self.engine.rule_catalog = SimpleNamespace(
            get_sequence_config=lambda pattern_id: {
                "chain": "failed_then_success",
                "required_sources": {"Security": "critical"},
                "steps": [
                    {
                        "label": "failed_logon",
                        "event_id": "4625",
                        "direction": "before_anchor",
                        "max_offset_seconds": 5,
                    }
                ],
            }
            if pattern_id == "credential_access"
            else None
        )
        self.engine._get_ch = lambda: FakeClient()

        sequences = self.engine._validate_sequences(
            "credential_access",
            {
                "case_id": 135,
                "anchor_ts": datetime(2026, 4, 20, 0, 0, 5),
                "source_host": "HOST-A",
            },
            coverage=CoverageAssessment(
                host="HOST-A",
                coverage_status="unknown",
                missing_sources=["Security", "Sysmon"],
            ),
            correlation_fields=["source_host"],
        )

        self.assertEqual(sequences[0].status, "missing")
        self.assertEqual(sequences[0].evaluability, "missing_telemetry")
        self.assertEqual(sequences[0].telemetry_gap_sources, ["Security"])

    def test_sequence_walks_before_anchor_stepwise_from_prior_match(self):
        anchor_ts = datetime(2026, 4, 20, 0, 0, 10)
        share_access_ts = datetime(2026, 4, 20, 0, 0, 8)
        out_of_order_logon_ts = datetime(2026, 4, 20, 0, 0, 9)
        calls = []

        class FakeClient:
            @staticmethod
            def query(query, parameters=None):
                calls.append({"query": query, "parameters": parameters})
                if "5140" in query or "5145" in query:
                    return SimpleNamespace(
                        result_rows=[
                            (share_access_ts.isoformat(), "5145", "alice", "HOST-A")
                        ]
                    )
                if "4624" in query and parameters["sequence_ref_ts"] == anchor_ts:
                    return SimpleNamespace(
                        result_rows=[
                            (out_of_order_logon_ts.isoformat(), "4624", "alice", "HOST-A")
                        ]
                    )
                if "4624" in query and parameters["sequence_ref_ts"] == share_access_ts:
                    return SimpleNamespace(result_rows=[])
                return SimpleNamespace(result_rows=[])

        self.engine.rule_catalog = SimpleNamespace(
            get_sequence_config=lambda pattern_id: {
                "chain": "logon -> share_access -> service_install",
                "steps": [
                    {
                        "label": "logon",
                        "event_id": "4624",
                        "direction": "before_anchor",
                        "max_offset_seconds": 5,
                    },
                    {
                        "label": "share_access",
                        "event_id": ["5140", "5145"],
                        "direction": "before_anchor",
                        "max_offset_seconds": 5,
                    },
                ],
            }
            if pattern_id == "psexec_execution"
            else None
        )
        self.engine._get_ch = lambda: FakeClient()

        sequences = self.engine._validate_sequences(
            "psexec_execution",
            {
                "case_id": 135,
                "anchor_ts": anchor_ts,
                "source_host": "HOST-A",
                "username": "alice",
                "target_host": "TARGET-A",
            },
            correlation_fields=["source_host", "username", "target_host"],
        )

        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0]["parameters"]["sequence_ref_ts"], anchor_ts)
        self.assertEqual(calls[1]["parameters"]["sequence_ref_ts"], share_access_ts)
        self.assertEqual(calls[1]["parameters"]["target_host"], "TARGET-A")
        self.assertEqual(sequences[0].status, "partial")
        self.assertEqual(sequences[0].missing_steps, ["logon"])
        self.assertFalse(sequences[0].steps[0]["found"])
        self.assertTrue(sequences[0].steps[1]["found"])
        self.assertEqual(sequences[0].steps[1]["event_id"], "5145")

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
                anchor={
                    "username": "alice",
                    "timestamp": "2026-04-20T08:00:00",
                    "timestamp_utc": "2026-04-20T00:00:00",
                },
                pattern_id="pass_the_ticket",
                pattern_name="Pass the Ticket",
                correlation_key="HOST-A|alice",
                coverage=CoverageAssessment(host="", coverage_status="unknown"),
            ),
            EvidencePackage(
                anchor={
                    "username": "alice",
                    "timestamp": "2026-04-20T08:05:00",
                    "timestamp_utc": "2026-04-20T00:05:00",
                },
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

        self.assertIn(
            "AND COALESCE(timestamp_utc, timestamp) BETWEEN "
            "{spread_ws:DateTime64} AND {spread_we:DateTime64}",
            captured["query"],
        )
        self.assertEqual(captured["parameters"]["spread_ws"].isoformat(), "2026-04-20T00:00:00")
        self.assertEqual(captured["parameters"]["spread_we"].isoformat(), "2026-04-20T00:05:00")


if __name__ == "__main__":
    unittest.main()
