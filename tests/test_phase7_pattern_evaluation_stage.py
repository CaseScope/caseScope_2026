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


class Phase7PatternEvaluationStageTestCase(unittest.TestCase):
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
            "phase7_pattern_evaluation_under_test",
            "/opt/casescope/pipeline/pattern_analysis.py",
        )
        return pattern_analysis, restore_modules

    def test_evaluate_ai_pattern_drives_engine_selection_and_processing(self):
        pattern_analysis, restore_modules = self._load_pattern_analysis_module()
        try:
            recorded = {
                "evaluate_calls": [],
                "selected_inputs": [],
                "processed_kwargs": None,
            }

            class FakeEngine:
                def evaluate_pattern(self, pattern_id, pattern_config, anchor_events, time_window):
                    recorded["evaluate_calls"].append(
                        (pattern_id, pattern_config["name"], anchor_events, time_window)
                    )
                    return ["pkg-a", "pkg-b"]

            def fake_select_highest_scoring_packages(packages):
                recorded["selected_inputs"].append(list(packages))
                return ["pkg-b"]

            def fake_process_ai_pattern_packages(**kwargs):
                recorded["processed_kwargs"] = kwargs
                return {"result_records": ["record"], "findings": ["finding"], "confirmed_pattern_entries": ["cp"]}

            original_select = pattern_analysis.select_highest_scoring_packages
            original_process = pattern_analysis.process_ai_pattern_packages
            pattern_analysis.select_highest_scoring_packages = fake_select_highest_scoring_packages
            pattern_analysis.process_ai_pattern_packages = fake_process_ai_pattern_packages
            try:
                result = pattern_analysis.evaluate_ai_pattern(
                    case_id=21,
                    analysis_id="analysis-10",
                    pattern_id="pattern-10",
                    pattern_name="Pattern Ten",
                    pattern_config={
                        "name": "Pattern Ten",
                        "time_window_minutes": 90,
                        "ai_full_threshold": 55,
                    },
                    extraction_result={"anchor_count": 2},
                    anchor_events=[{"id": 1}],
                    evidence_engine=FakeEngine(),
                    confirmed_patterns={"higher": [{"score": 99}]},
                    run_full_analysis_for_package=lambda package: {"mode": "full", "package": package},
                    run_light_analysis_for_package=lambda package: {"mode": "light", "package": package},
                    model_name="test-model",
                    ai_gray_threshold_default=25,
                )
            finally:
                pattern_analysis.select_highest_scoring_packages = original_select
                pattern_analysis.process_ai_pattern_packages = original_process

            self.assertEqual(
                recorded["evaluate_calls"],
                [("pattern-10", "Pattern Ten", [{"id": 1}], 90)],
            )
            self.assertEqual(recorded["selected_inputs"], [["pkg-a", "pkg-b"]])
            self.assertEqual(recorded["processed_kwargs"]["evidence_packages"], ["pkg-b"])
            self.assertEqual(recorded["processed_kwargs"]["ai_full_threshold"], 55)
            self.assertEqual(recorded["processed_kwargs"]["ai_gray_threshold"], 25)
            self.assertEqual(recorded["processed_kwargs"]["model_name"], "test-model")
            self.assertEqual(result["findings"], ["finding"])
        finally:
            restore_modules()

    def test_evaluate_ai_pattern_uses_default_time_window(self):
        pattern_analysis, restore_modules = self._load_pattern_analysis_module()
        try:
            recorded = {"time_windows": []}

            class FakeEngine:
                def evaluate_pattern(self, pattern_id, pattern_config, anchor_events, time_window):
                    recorded["time_windows"].append(time_window)
                    return []

            original_process = pattern_analysis.process_ai_pattern_packages
            pattern_analysis.process_ai_pattern_packages = lambda **kwargs: kwargs
            try:
                result = pattern_analysis.evaluate_ai_pattern(
                    case_id=22,
                    analysis_id="analysis-11",
                    pattern_id="pattern-11",
                    pattern_name="Pattern Eleven",
                    pattern_config={},
                    extraction_result={},
                    anchor_events=[],
                    evidence_engine=FakeEngine(),
                    confirmed_patterns={},
                    run_full_analysis_for_package=lambda package: package,
                    run_light_analysis_for_package=lambda package: package,
                )
            finally:
                pattern_analysis.process_ai_pattern_packages = original_process

            self.assertEqual(recorded["time_windows"], [60])
            self.assertEqual(result["ai_full_threshold"], 40)
            self.assertEqual(result["ai_gray_threshold"], 30)
        finally:
            restore_modules()

    def test_pattern_callers_use_shared_evaluation_helper(self):
        case_analyzer_source = Path("/opt/casescope/utils/case_analyzer.py").read_text()
        rag_tasks_source = Path("/opt/casescope/tasks/rag_tasks.py").read_text()

        self.assertIn("evaluate_ai_pattern,", case_analyzer_source)
        self.assertIn("processed = evaluate_ai_pattern(", case_analyzer_source)
        self.assertNotIn("evidence_packages = evidence_engine.evaluate_pattern(", case_analyzer_source)

        self.assertIn("from pipeline.pattern_analysis import (", rag_tasks_source)
        self.assertIn("evaluate_ai_pattern,", rag_tasks_source)
        self.assertIn("processed = evaluate_ai_pattern(", rag_tasks_source)
        self.assertNotIn("evidence_packages = evidence_engine.evaluate_pattern(", rag_tasks_source)


if __name__ == "__main__":
    unittest.main()
