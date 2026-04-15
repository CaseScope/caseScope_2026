import importlib.util
import os
import sys
import types
import unittest
from pathlib import Path

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


class Scoring2EngineFixturesTestCase(unittest.TestCase):
    def setUp(self):
        self.engine = object.__new__(deterministic_evidence_engine.DeterministicEvidenceEngine)

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


if __name__ == "__main__":
    unittest.main()
