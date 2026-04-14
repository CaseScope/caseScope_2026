import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("SECRET_KEY", "test-secret")

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_module(name: str, relative_path: str):
    module_path = REPO_ROOT / relative_path
    spec = importlib.util.spec_from_file_location(name, module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


artifact_module = _load_module(
    "scoring_baseline_artifact_under_test",
    Path("utils") / "scoring_baseline_artifact.py",
)


class ScoringBaselineArtifactTestCase(unittest.TestCase):
    def test_parse_scoring_telemetry_line_ignores_non_json_and_non_scoring_events(self):
        self.assertIsNone(artifact_module.parse_scoring_telemetry_line("plain text"))
        self.assertIsNone(
            artifact_module.parse_scoring_telemetry_line(
                '2026-04-14 22:00:00 | INFO | {"event":"other"}'
            )
        )

    def test_load_and_build_baseline_artifact(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "hunting.log"
            log_path.write_text(
                "\n".join(
                    [
                        '2026-04-14 22:00:00 | INFO | {"event":"scoring_telemetry","case_id":135,"analysis_id":"analysis-1","pattern_id":"rdp_lateral","pattern_name":"RDP Lateral","correlation_key":"alpha","outcome":"materialized","ai_adjustment":-16,"eligible_to_emit":true,"coverage_gap_present":false,"legacy_forced":false}',
                        '2026-04-14 22:00:01 | INFO | {"event":"scoring_telemetry","case_id":135,"analysis_id":"analysis-1","pattern_id":"rdp_lateral","pattern_name":"RDP Lateral","correlation_key":"bravo","outcome":"suppressed","legacy_forced":false}',
                        '2026-04-14 22:00:02 | INFO | {"event":"scoring_telemetry","case_id":135,"analysis_id":"analysis-1","pattern_id":"service_persistence","pattern_name":"Service Persistence","correlation_key":"charlie","outcome":"materialized","ai_adjustment":-4,"eligible_to_emit":false,"coverage_gap_present":true,"legacy_forced":true}',
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            payloads = artifact_module.load_scoring_telemetry_from_log(log_path)
            artifact = artifact_module.build_scoring_baseline_artifact(
                case_id=135,
                source_logs=[str(log_path)],
                telemetry_payloads=payloads,
                analyst_verdicts=[
                    {"pattern_id": "rdp_lateral", "correlation_key": "alpha", "verdict": "confirmed"},
                    {"pattern_id": "service_persistence", "correlation_key": "charlie", "verdict": "false_positive"},
                ],
            )

        self.assertEqual(artifact["overall"]["packages_evaluated"], 3)
        self.assertEqual(artifact["overall"]["suppressed_count"], 1)
        self.assertEqual(artifact["overall"]["strong_downrank_count"], 1)
        self.assertEqual(artifact["analysis_ids"], ["analysis-1"])
        self.assertEqual(artifact["patterns"][0]["pattern_id"], "rdp_lateral")
        self.assertEqual(artifact["patterns"][0]["volume"], 2)
        self.assertEqual(artifact["patterns"][0]["strong_downrank_rate"], 1.0)
        self.assertEqual(artifact["patterns"][0]["verdict_counts"], {"confirmed": 1})
        self.assertEqual(artifact["patterns"][1]["legacy_forced_count"], 1)
        self.assertEqual(artifact["patterns"][1]["coverage_gap_count"], 1)
        self.assertEqual(artifact["patterns"][1]["verdict_counts"], {"false_positive": 1})

    def test_render_scoring_baseline_text_includes_key_metrics(self):
        artifact = {
            "case_id": 135,
            "generated_at": "2026-04-14T23:00:00",
            "analysis_ids": ["analysis-1"],
            "source_logs": ["/tmp/hunting.log"],
            "overall": {
                "packages_evaluated": 3,
                "materialized_count": 2,
                "suppressed_count": 1,
                "suppression_rate": 0.3333,
                "strong_downrank_count": 1,
                "strong_downrank_rate": 0.5,
                "reviewed_count": 1,
                "verdict_counts": {"confirmed": 1},
            },
            "patterns": [
                {
                    "pattern_id": "rdp_lateral",
                    "pattern_name": "RDP Lateral",
                    "volume": 2,
                    "materialized_count": 1,
                    "suppressed_count": 1,
                    "suppression_rate": 0.5,
                    "strong_downrank_count": 1,
                    "strong_downrank_rate": 1.0,
                    "coverage_gap_count": 0,
                    "coverage_gap_rate": 0.0,
                    "eligible_emit_count": 1,
                    "eligible_emit_rate": 1.0,
                    "reviewed_count": 1,
                    "verdict_counts": {"confirmed": 1},
                }
            ],
        }

        report = artifact_module.render_scoring_baseline_text(artifact)

        self.assertIn("Scoring 2.0 baseline artifact for case 135", report)
        self.assertIn("Strong downranks: 1 (50.00%)", report)
        self.assertIn("RDP Lateral (rdp_lateral)", report)


if __name__ == "__main__":
    unittest.main()
