import importlib.util
import os
import sys
import types
import unittest
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
    "scoring2_emit_pattern_check_definitions",
    Path("utils") / "pattern_check_definitions.py",
)
deterministic_evidence_engine = _load_module(
    "scoring2_emit_deterministic_evidence_engine",
    Path("utils") / "deterministic_evidence_engine.py",
)
finding_contract = _load_module(
    "scoring2_emit_finding_contract",
    Path("utils") / "finding_contract.py",
)

CheckDefinition = pattern_check_definitions.CheckDefinition
CheckResult = pattern_check_definitions.CheckResult
CoverageAssessment = pattern_check_definitions.CoverageAssessment


class Scoring2EmitEligibilityTestCase(unittest.TestCase):
    def setUp(self):
        self.engine = object.__new__(deterministic_evidence_engine.DeterministicEvidenceEngine)

    def test_scoring_v2_disqualifier_blocks_emit(self):
        scoring = self.engine._compute_score_v2(
            pattern_id="fixture_pattern",
            pattern_name="Fixture Pattern",
            pattern_config={"scoring_version": "2.0", "anchor_class": "definitive"},
            check_defs=[
                CheckDefinition(
                    id="anchor",
                    name="Anchor",
                    weight=30,
                    check_type="anchor_match",
                    role="anchor",
                ),
                CheckDefinition(
                    id="bad_benign_signal",
                    name="Bad Benign Signal",
                    weight=30,
                    check_type="field_match",
                    role="corroboration",
                    disqualifier=True,
                ),
            ],
            checks=[
                CheckResult(
                    check_id="anchor",
                    status="PASS",
                    weight=30,
                    contribution=30,
                    detail="username=alice, source_host=HOST-A",
                    source="anchor_match",
                ),
                CheckResult(
                    check_id="bad_benign_signal",
                    status="PASS",
                    weight=30,
                    contribution=30,
                    detail="benign admin workflow bypassed",
                    source="field_match",
                ),
            ],
            bursts=[],
            sequences=[],
            coverage=CoverageAssessment(host="HOST-A", coverage_status="full"),
        )

        self.assertFalse(scoring["eligible_to_emit"])
        self.assertEqual(scoring["emit_block_reasons"], ["disqualifier:bad_benign_signal"])

    def test_scoring_v2_anchor_only_emit_can_be_blocked(self):
        scoring = self.engine._compute_score_v2(
            pattern_id="fixture_pattern",
            pattern_name="Fixture Pattern",
            pattern_config={
                "scoring_version": "2.0",
                "anchor_class": "gateway",
                "allow_anchor_only_emit": False,
                "required_pass_count": 1,
                "emit_threshold_mode": "score_and_required",
            },
            check_defs=[
                CheckDefinition(
                    id="anchor",
                    name="Anchor",
                    weight=60,
                    check_type="anchor_match",
                    role="anchor",
                ),
            ],
            checks=[
                CheckResult(
                    check_id="anchor",
                    status="PASS",
                    weight=60,
                    contribution=60,
                    detail="username=alice, source_host=HOST-A",
                    source="anchor_match",
                ),
            ],
            bursts=[],
            sequences=[],
            coverage=CoverageAssessment(host="HOST-A", coverage_status="full"),
        )

        self.assertFalse(scoring["eligible_to_emit"])
        self.assertIn("anchor_only_not_allowed", scoring["emit_block_reasons"])
        self.assertIn("required_checks_not_met", scoring["emit_block_reasons"])

    def test_scoring_v2_requires_anchor_class_declaration(self):
        with self.assertRaises(RuntimeError):
            self.engine._compute_score_v2(
                pattern_id="fixture_pattern",
                pattern_name="Fixture Pattern",
                pattern_config={"scoring_version": "2.0"},
                check_defs=[
                    CheckDefinition(
                        id="anchor",
                        name="Anchor",
                        weight=60,
                        check_type="anchor_match",
                        role="anchor",
                    ),
                ],
                checks=[
                    CheckResult(
                        check_id="anchor",
                        status="PASS",
                        weight=60,
                        contribution=60,
                        detail="event_id=4624, username=alice, source_host=HOST-A",
                        source="anchor_match",
                    ),
                ],
                bursts=[],
                sequences=[],
                coverage=CoverageAssessment(host="HOST-A", coverage_status="full"),
            )

    def test_finalize_deterministic_package_preserves_scoring_v2_emit_decision(self):
        package = SimpleNamespace(
            deterministic_score=62,
            scoring_version="2.0",
            eligible_to_emit=False,
            emit_block_reasons=["required_checks_not_met"],
            ai_judgment={},
            ai_escalated=False,
        )
        package.final_score = lambda: 62
        package.bounded_ai_adjustment = lambda: 0
        package.to_dict = lambda: {"scoring_context": {"eligible_to_emit": False}}

        finalized = finding_contract.finalize_deterministic_package(
            package,
            ai_full_threshold=40,
            ai_gray_threshold=20,
            run_full_analysis=lambda: {},
            run_light_analysis=lambda: {},
        )

        self.assertFalse(finalized["should_emit_finding"])
        self.assertEqual(finalized["emit_block_reasons"], ["required_checks_not_met"])


if __name__ == "__main__":
    unittest.main()
