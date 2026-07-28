import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.phase7_rag_tasks_loader import load_rag_tasks_with_stubs

REPO_ROOT = Path(__file__).resolve().parents[1]


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
                self.failed_stages = []

            def run_all_detectors(self):
                if self.progress_callback is not None:
                    self.progress_callback("gap_detection", 60, "Evaluating anomaly gaps...")
                return findings if findings is not None else [{"id": "gap-1"}]

            @property
            def has_failures(self):
                return bool(self.failed_stages)

            def failure_summary(self):
                return ", ".join(self.failed_stages)

        fake_detectors.GapDetectionManager = FakeGapDetectionManager

        class FakeGapDetectionError(RuntimeError):
            def __init__(self, message, findings=None, failed_detectors=None):
                super().__init__(message)
                self.findings = findings or []
                self.failed_detectors = failed_detectors or []

        fake_detectors.GapDetectionError = FakeGapDetectionError

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

    def test_gap_detection_is_not_dispatched_as_its_own_task(self):
        """It has to run after profiling, so it cannot be a parallel wave task.

        Every gap detector reads the behavioural profiles and peer groups that
        profiling writes. While gap detection was dispatched alongside profiling,
        the behavioural anomaly detector queried a profile table that run
        initialisation had just emptied and profiling had not yet refilled.
        """
        rag_tasks_source = (REPO_ROOT / "tasks" / "rag_tasks.py").read_text()

        self.assertNotIn("analyze_phase_gaps", rag_tasks_source)
        self.assertNotIn("run_detect_anomalies", rag_tasks_source)

    def test_gap_detection_runs_after_the_baseline_phases(self):
        case_analyzer_source = (REPO_ROOT / "utils" / "case_analyzer.py").read_text()

        resume = case_analyzer_source.index("def resume_from_baselines")
        absorb = case_analyzer_source.index("self._absorb_wave_results", resume)
        gaps = case_analyzer_source.index("self._run_gap_detection_phase()", resume)
        tail = case_analyzer_source.index("self._run_tail_phases()", resume)

        self.assertLess(
            absorb,
            gaps,
            msg="the baseline results must be absorbed before gap detection runs",
        )
        self.assertLess(
            gaps, tail, msg="gap detection must run before the phases that consume it"
        )

    def test_the_gap_phase_delegates_to_the_pipeline_stage(self):
        case_analyzer_source = (REPO_ROOT / "utils" / "case_analyzer.py").read_text()

        self.assertIn(
            "from pipeline.detect_anomalies import run_detect_anomalies",
            case_analyzer_source,
        )
        self.assertIn("findings = run_detect_anomalies(", case_analyzer_source)


if __name__ == "__main__":
    unittest.main()
