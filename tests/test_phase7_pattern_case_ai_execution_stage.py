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


class Phase7PatternCaseAIExecutionStageTestCase(unittest.TestCase):
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
            "phase7_pattern_case_ai_execution_under_test",
            "/opt/casescope/pipeline/pattern_analysis.py",
        )
        return pattern_analysis, restore_modules

    def test_execute_case_ai_pattern_orchestrates_evaluation_and_persistence(self):
        pattern_analysis, restore_modules = self._load_pattern_analysis_module()
        try:
            recorded = {}

            def fake_evaluate_ai_pattern(**kwargs):
                recorded["evaluate_kwargs"] = kwargs
                return {"result_records": ["record"], "findings": ["finding"], "confirmed_pattern_entries": ["cp"]}

            def fake_persist_ai_pattern_results(**kwargs):
                recorded["persist_kwargs"] = kwargs
                return ["cp"]

            original_evaluate = pattern_analysis.evaluate_ai_pattern
            original_persist = pattern_analysis.persist_ai_pattern_results
            pattern_analysis.evaluate_ai_pattern = fake_evaluate_ai_pattern
            pattern_analysis.persist_ai_pattern_results = fake_persist_ai_pattern_results
            try:
                result = pattern_analysis.execute_case_ai_pattern(
                    case_id=5,
                    analysis_id="analysis-5",
                    pattern_id="pattern-5",
                    pattern_name="Pattern Five",
                    pattern_config={"name": "Pattern Five"},
                    extraction_result={"anchor_count": 3},
                    anchor_events=[{"id": 1}],
                    evidence_engine="engine",
                    confirmed_patterns={"existing": []},
                    findings_output=[],
                    run_full_analysis_for_package=lambda package: {"mode": "full", "package": package},
                    run_light_analysis_for_package=lambda package: {"mode": "light", "package": package},
                    model_name="model-y",
                    extra_finding_fields_for_package=lambda package: {"package": package},
                    event_callback="event-callback",
                )
            finally:
                pattern_analysis.evaluate_ai_pattern = original_evaluate
                pattern_analysis.persist_ai_pattern_results = original_persist

            self.assertEqual(recorded["evaluate_kwargs"]["pattern_name"], "Pattern Five")
            self.assertEqual(recorded["evaluate_kwargs"]["model_name"], "model-y")
            self.assertEqual(recorded["persist_kwargs"]["pattern_id"], "pattern-5")
            self.assertEqual(result["processed"]["findings"], ["finding"])
            self.assertEqual(result["confirmed_pattern_entries"], ["cp"])
        finally:
            restore_modules()

    def test_case_analyzer_uses_shared_case_ai_execution_helper(self):
        source = Path("/opt/casescope/utils/case_analyzer.py").read_text()

        self.assertIn("execute_case_ai_pattern,", source)
        self.assertIn("execute_case_ai_pattern(", source)
        self.assertNotIn("processed = evaluate_ai_pattern(", source)
        self.assertNotIn("pattern_confirmed = persist_ai_pattern_results(", source)


if __name__ == "__main__":
    unittest.main()
