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


class Phase7PatternTaskIterationStageTestCase(unittest.TestCase):
    def _load_pattern_analysis_module(self):
        fake_utils = types.ModuleType("utils")
        fake_utils.__path__ = []
        fake_candidate_extractor = types.ModuleType("utils.candidate_extractor")
        fake_evidence_engine = types.ModuleType("utils.deterministic_evidence_engine")
        fake_pattern_suppression = types.ModuleType("utils.pattern_suppression")

        fake_candidate_extractor.CandidateExtractor = object
        fake_evidence_engine.DeterministicEvidenceEngine = object
        fake_pattern_suppression.PATTERN_SUPPRESSION_PRIORITY = {}
        fake_pattern_suppression.get_pattern_suppression_matches = lambda *args, **kwargs: []

        previous_modules = {
            name: sys.modules.get(name)
            for name in [
                "utils",
                "utils.candidate_extractor",
                "utils.deterministic_evidence_engine",
                "utils.pattern_suppression",
            ]
        }
        sys.modules["utils"] = fake_utils
        sys.modules["utils.candidate_extractor"] = fake_candidate_extractor
        sys.modules["utils.deterministic_evidence_engine"] = fake_evidence_engine
        sys.modules["utils.pattern_suppression"] = fake_pattern_suppression

        def restore_modules():
            for name, previous in previous_modules.items():
                if previous is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = previous

        pattern_analysis = _load_module(
            "phase7_pattern_task_iteration_under_test",
            "/opt/casescope/pipeline/pattern_analysis.py",
        )
        return pattern_analysis, restore_modules

    def test_run_task_ai_pattern_iteration_runs_preparation_execution_and_stats(self):
        pattern_analysis, restore_modules = self._load_pattern_analysis_module()
        try:
            recorded = {}

            def fake_prepare_task_ai_pattern_inputs(**kwargs):
                recorded["prepare_kwargs"] = kwargs
                return {
                    "extraction_result": {"anchor_count": 1},
                    "extraction_stats": {"total_stored": 5},
                    "should_skip": False,
                    "anchor_events": [{"id": 99}],
                }

            def fake_execute_task_ai_pattern(**kwargs):
                recorded["execute_kwargs"] = kwargs

            original_prepare = pattern_analysis.prepare_task_ai_pattern_inputs
            original_execute = pattern_analysis.execute_task_ai_pattern
            pattern_analysis.prepare_task_ai_pattern_inputs = fake_prepare_task_ai_pattern_inputs
            pattern_analysis.execute_task_ai_pattern = fake_execute_task_ai_pattern
            try:
                result = pattern_analysis.run_task_ai_pattern_iteration(
                    extractor="extractor",
                    case_id=11,
                    analysis_id="analysis-11",
                    pattern_id="pattern-11",
                    pattern_config={"name": "Pattern Eleven"},
                    time_start="start",
                    time_end="end",
                    opencti_provider="provider",
                    evidence_engine="engine",
                    confirmed_patterns={"existing": []},
                    findings_output=["finding"],
                    run_full_analysis_for_package=lambda package: package,
                    run_light_analysis_for_package=lambda package: package,
                    get_analysis_stats=lambda: {"calls": 3},
                    model_name="model-x",
                    event_callback="event-callback",
                    ai_gray_threshold_default=25,
                )
            finally:
                pattern_analysis.prepare_task_ai_pattern_inputs = original_prepare
                pattern_analysis.execute_task_ai_pattern = original_execute

            self.assertEqual(recorded["prepare_kwargs"]["extractor"], "extractor")
            self.assertEqual(recorded["prepare_kwargs"]["time_start"], "start")
            self.assertEqual(recorded["execute_kwargs"]["pattern_id"], "pattern-11")
            self.assertEqual(recorded["execute_kwargs"]["anchor_events"], [{"id": 99}])
            self.assertEqual(result["extraction_stats"], {"total_stored": 5})
            self.assertFalse(result["skipped"])
            self.assertEqual(result["analysis_stats"], {"calls": 3})
            self.assertIsNone(result["error"])
        finally:
            restore_modules()

    def test_run_task_ai_pattern_iteration_preserves_extraction_stats_on_error(self):
        pattern_analysis, restore_modules = self._load_pattern_analysis_module()
        try:
            pattern_analysis.prepare_task_ai_pattern_inputs = lambda **kwargs: {
                "extraction_result": {"anchor_count": 1},
                "extraction_stats": {"total_stored": 2},
                "should_skip": False,
                "anchor_events": [],
            }
            pattern_analysis.execute_task_ai_pattern = lambda **kwargs: (_ for _ in ()).throw(RuntimeError("boom"))

            result = pattern_analysis.run_task_ai_pattern_iteration(
                extractor="extractor",
                case_id=11,
                analysis_id="analysis-11",
                pattern_id="pattern-11",
                pattern_config={"name": "Pattern Eleven"},
                opencti_provider="provider",
                evidence_engine="engine",
                confirmed_patterns={},
                findings_output=[],
                run_full_analysis_for_package=lambda package: package,
                run_light_analysis_for_package=lambda package: package,
            )

            self.assertEqual(result["extraction_stats"], {"total_stored": 2})
            self.assertFalse(result["skipped"])
            self.assertIsNone(result["analysis_stats"])
            self.assertEqual(result["error"], {"pattern_id": "pattern-11", "error": "boom"})
        finally:
            restore_modules()

    def test_rag_task_uses_shared_task_iteration_helper(self):
        source = Path("/opt/casescope/tasks/rag_tasks.py").read_text()

        self.assertIn("from pipeline.pattern_analysis import (", source)
        self.assertIn("run_task_ai_pattern_iteration,", source)
        self.assertIn("iteration_result = run_task_ai_pattern_iteration(", source)
        self.assertNotIn("prepared = prepare_task_ai_pattern_inputs(", source)
        self.assertNotIn("execute_task_ai_pattern(", source)


if __name__ == "__main__":
    unittest.main()
