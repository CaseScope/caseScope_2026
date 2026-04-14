import importlib.util
import json
import os
import unittest
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("SECRET_KEY", "test-secret")

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_module(name: str, relative_path: str):
    module_path = REPO_ROOT / relative_path
    spec = importlib.util.spec_from_file_location(name, module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


scoring_telemetry = _load_module(
    "scoring_telemetry_under_test",
    Path("utils") / "scoring_telemetry.py",
)


class ScoringTelemetryTestCase(unittest.TestCase):
    def test_build_scoring_telemetry_projects_phase1_contract(self):
        package = SimpleNamespace(
            correlation_key="HOST-A|alice",
            scoring_version="1.0",
            scoring_changes=["forced_legacy_scoring"],
            deterministic_score=76,
            ai_escalated=False,
            ai_judgment={
                "reasoning": "Likely known administrative workflow with missing telemetry on one source.",
                "false_positive_assessment": "Expected system behavior for a machine account.",
            },
            eligible_to_emit=False,
            emit_block_reasons=["score_below_emit_threshold"],
            evaluable_weight=80,
            excluded_weight=20,
            raw_total_weight=100,
            coverage_gap_present=True,
            overlay_score_adjustment=4,
        )

        payload = scoring_telemetry.build_scoring_telemetry(
            case_id=7,
            analysis_id="analysis-7",
            pattern_id="service_persistence",
            pattern_name="Service Persistence",
            pattern_config={"scoring_version": "2.0"},
            package=package,
            finalized={
                "final_score": 48,
                "ai_adjustment": -8,
                "ai_analyzed": True,
                "should_emit_finding": False,
                "emit_block_reasons": ["score_below_emit_threshold"],
            },
            outcome="materialized",
            soft_suppression_adjustment=10,
        )

        self.assertEqual(payload["event"], "scoring_telemetry")
        self.assertEqual(payload["requested_scoring_version"], "2.0")
        self.assertEqual(payload["effective_scoring_version"], "1.0")
        self.assertTrue(payload["legacy_forced"])
        self.assertEqual(payload["deterministic_score"], 76.0)
        self.assertEqual(payload["final_score"], 48)
        self.assertEqual(payload["ai_adjustment"], -8)
        self.assertFalse(payload["eligible_to_emit"])
        self.assertEqual(payload["emit_block_reasons"], ["score_below_emit_threshold"])
        self.assertEqual(payload["excluded_weight"], 20.0)
        self.assertTrue(payload["coverage_gap_present"])
        self.assertEqual(payload["soft_suppression_adjustment"], 10.0)
        self.assertEqual(
            payload["ai_rationale_tags"],
            [
                "admin_workflow",
                "expected_system_behavior",
                "machine_account",
                "missing_telemetry",
            ],
        )

    def test_emit_scoring_telemetry_serializes_json(self):
        lines = []

        scoring_telemetry.emit_scoring_telemetry(
            {"event": "scoring_telemetry", "case_id": 7},
            writer=lines.append,
        )

        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0]), {"event": "scoring_telemetry", "case_id": 7})


if __name__ == "__main__":
    unittest.main()
