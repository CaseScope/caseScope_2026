import importlib.util
import sys
import types
import unittest
from pathlib import Path


def _load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class Phase7DetectAnomaliesStageTestCase(unittest.TestCase):
    def _load_detect_anomalies_module(self, *, findings=None):
        fake_utils = types.ModuleType("utils")
        fake_utils.__path__ = []
        fake_detectors = types.ModuleType("utils.stateful_detectors")

        recorded = {
            "managers": [],
        }

        class FakeGapDetectionManager:
            def __init__(self, case_id, analysis_id, progress_callback=None):
                recorded["managers"].append({
                    "case_id": case_id,
                    "analysis_id": analysis_id,
                    "progress_callback": progress_callback,
                })
                self.progress_callback = progress_callback

            def run_all_detectors(self):
                if self.progress_callback is not None:
                    self.progress_callback("gap_detection", 60, "Evaluating anomaly gaps...")
                return findings if findings is not None else [{"id": "gap-1"}]

        fake_detectors.GapDetectionManager = FakeGapDetectionManager

        previous_modules = {
            name: sys.modules.get(name)
            for name in [
                "utils",
                "utils.stateful_detectors",
            ]
        }
        sys.modules["utils"] = fake_utils
        sys.modules["utils.stateful_detectors"] = fake_detectors
        try:
            detect_anomalies = _load_module(
                "phase7_detect_anomalies_under_test",
                "/opt/casescope/pipeline/detect_anomalies.py",
            )
        finally:
            for name, previous in previous_modules.items():
                if previous is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = previous

        return detect_anomalies, recorded

    def test_run_detect_anomalies_delegates_and_accepts_progress_callback(self):
        detect_anomalies, recorded = self._load_detect_anomalies_module()
        progress_messages = []

        result = detect_anomalies.run_detect_anomalies(
            case_id=17,
            analysis_id="analysis-5",
            progress_callback=lambda phase, percent, message: progress_messages.append(
                (phase, percent, message)
            ),
        )

        self.assertEqual(len(recorded["managers"]), 1)
        self.assertEqual(recorded["managers"][0]["case_id"], 17)
        self.assertEqual(recorded["managers"][0]["analysis_id"], "analysis-5")
        self.assertEqual(result, [{"id": "gap-1"}])
        self.assertEqual(progress_messages[0], ("gap_detection", 60, "Evaluating anomaly gaps..."))

    def test_run_detect_anomalies_returns_empty_findings(self):
        detect_anomalies, recorded = self._load_detect_anomalies_module(findings=[])

        result = detect_anomalies.run_detect_anomalies(
            case_id=19,
            analysis_id="analysis-6",
        )

        self.assertEqual(result, [])
        self.assertEqual(len(recorded["managers"]), 1)

    def test_gap_detection_callers_use_pipeline_detect_anomalies_stage(self):
        rag_tasks_source = Path("/opt/casescope/tasks/rag_tasks.py").read_text()
        case_analyzer_source = Path("/opt/casescope/utils/case_analyzer.py").read_text()

        self.assertIn("from pipeline.detect_anomalies import run_detect_anomalies", rag_tasks_source)
        self.assertIn(
            "findings = run_detect_anomalies(case_id=case_id, analysis_id=analysis_id)",
            rag_tasks_source,
        )
        self.assertNotIn("from utils.stateful_detectors import GapDetectionManager", rag_tasks_source)

        self.assertIn("from pipeline.detect_anomalies import run_detect_anomalies", case_analyzer_source)
        self.assertIn("findings = run_detect_anomalies(", case_analyzer_source)


if __name__ == "__main__":
    unittest.main()
