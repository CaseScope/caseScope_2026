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


class Phase7PatternTaskExecutionStageTestCase(unittest.TestCase):
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
            "phase7_pattern_task_execution_under_test",
            "/opt/casescope/pipeline/pattern_analysis.py",
        )
        return pattern_analysis, restore_modules

    def test_execute_task_ai_pattern_orchestrates_context_evaluation_and_persistence(self):
        pattern_analysis, restore_modules = self._load_pattern_analysis_module()
        try:
            recorded = {}

            def fake_build_pattern_threat_intel_context(provider, pattern_config, max_chars=500):
                recorded["ti_call"] = {
                    "provider": provider,
                    "pattern_config": pattern_config,
                    "max_chars": max_chars,
                }
                return "ti-context"

            def fake_evaluate_ai_pattern(**kwargs):
                recorded["evaluate_kwargs"] = kwargs
                full_result = kwargs["run_full_analysis_for_package"]("pkg-a")
                light_result = kwargs["run_light_analysis_for_package"]("pkg-b")
                recorded["full_result"] = full_result
                recorded["light_result"] = light_result
                return {"result_records": ["record"], "findings": ["finding"], "confirmed_pattern_entries": ["cp"]}

            def fake_persist_ai_pattern_results(**kwargs):
                recorded["persist_kwargs"] = kwargs
                return ["cp"]

            original_build = pattern_analysis.build_pattern_threat_intel_context
            original_evaluate = pattern_analysis.evaluate_ai_pattern
            original_persist = pattern_analysis.persist_ai_pattern_results
            pattern_analysis.build_pattern_threat_intel_context = fake_build_pattern_threat_intel_context
            pattern_analysis.evaluate_ai_pattern = fake_evaluate_ai_pattern
            pattern_analysis.persist_ai_pattern_results = fake_persist_ai_pattern_results
            try:
                result = pattern_analysis.execute_task_ai_pattern(
                    case_id=12,
                    analysis_id="analysis-12",
                    pattern_id="pattern-12",
                    pattern_config={"name": "Pattern Twelve"},
                    extraction_result={"anchor_count": 2},
                    anchor_events=[{"id": 1}],
                    opencti_provider="provider",
                    evidence_engine="engine",
                    confirmed_patterns={"existing": []},
                    findings_output=[],
                    run_full_analysis_for_package=lambda package, ti_context: {
                        "package": package,
                        "ti_context": ti_context,
                    },
                    run_light_analysis_for_package=lambda package: {"package": package, "mode": "light"},
                    model_name="test-model",
                    event_callback="event-callback",
                    ai_gray_threshold_default=25,
                )
            finally:
                pattern_analysis.build_pattern_threat_intel_context = original_build
                pattern_analysis.evaluate_ai_pattern = original_evaluate
                pattern_analysis.persist_ai_pattern_results = original_persist

            self.assertEqual(recorded["ti_call"]["provider"], "provider")
            self.assertEqual(recorded["evaluate_kwargs"]["pattern_name"], "Pattern Twelve")
            self.assertEqual(recorded["evaluate_kwargs"]["model_name"], "test-model")
            self.assertEqual(recorded["evaluate_kwargs"]["ai_gray_threshold_default"], 25)
            self.assertEqual(recorded["full_result"], {"package": "pkg-a", "ti_context": "ti-context"})
            self.assertEqual(recorded["light_result"], {"package": "pkg-b", "mode": "light"})
            self.assertEqual(recorded["persist_kwargs"]["pattern_id"], "pattern-12")
            self.assertEqual(result["processed"]["findings"], ["finding"])
            self.assertEqual(result["confirmed_pattern_entries"], ["cp"])
            self.assertEqual(result["threat_intel_context"], "ti-context")
        finally:
            restore_modules()

    def test_rag_task_uses_shared_task_execution_helper(self):
        source = Path("/opt/casescope/tasks/rag_tasks.py").read_text()

        self.assertIn("from pipeline.pattern_analysis import (", source)
        self.assertIn("run_task_ai_pattern_iteration,", source)
        self.assertIn("iteration_result = run_task_ai_pattern_iteration(", source)
        self.assertNotIn("execute_task_ai_pattern(", source)
        self.assertNotIn("processed = evaluate_ai_pattern(", source)


if __name__ == "__main__":
    unittest.main()
