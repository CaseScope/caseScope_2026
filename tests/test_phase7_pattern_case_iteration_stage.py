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


class Phase7PatternCaseIterationStageTestCase(unittest.TestCase):
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
            "phase7_pattern_case_iteration_under_test",
            "/opt/casescope/pipeline/pattern_analysis.py",
        )
        return pattern_analysis, restore_modules

    def test_run_case_pattern_iteration_runs_case_ai_path(self):
        pattern_analysis, restore_modules = self._load_pattern_analysis_module()
        try:
            recorded = {}

            def fake_prepare_case_pattern_inputs(**kwargs):
                recorded["prepare_kwargs"] = kwargs
                return {
                    "extraction_result": {"anchor_count": 2},
                    "should_skip": False,
                    "anchor_events": [{"id": 7}],
                }

            def fake_execute_case_ai_pattern(**kwargs):
                recorded["execute_kwargs"] = kwargs

            original_prepare = pattern_analysis.prepare_case_pattern_inputs
            original_execute = pattern_analysis.execute_case_ai_pattern
            pattern_analysis.prepare_case_pattern_inputs = fake_prepare_case_pattern_inputs
            pattern_analysis.execute_case_ai_pattern = fake_execute_case_ai_pattern
            try:
                result = pattern_analysis.run_case_pattern_iteration(
                    extractor="extractor",
                    case_id=4,
                    analysis_id="analysis-4",
                    pattern_id="pattern-4",
                    pattern_name="Pattern Four",
                    pattern_config={"name": "Pattern Four"},
                    mode="B",
                    evidence_engine="engine",
                    confirmed_patterns={"existing": []},
                    findings_output=[],
                    run_full_analysis_for_package=lambda package: package,
                    run_light_analysis_for_package=lambda package: package,
                    model_name="model-4",
                    extra_finding_fields_for_package=lambda package: {"package": package},
                    event_callback="event-callback",
                )
            finally:
                pattern_analysis.prepare_case_pattern_inputs = original_prepare
                pattern_analysis.execute_case_ai_pattern = original_execute

            self.assertEqual(recorded["prepare_kwargs"]["pattern_id"], "pattern-4")
            self.assertEqual(recorded["execute_kwargs"]["anchor_events"], [{"id": 7}])
            self.assertEqual(recorded["execute_kwargs"]["model_name"], "model-4")
            self.assertFalse(result["skipped"])
            self.assertIsNone(result["error"])
        finally:
            restore_modules()

    def test_run_case_pattern_iteration_runs_rule_path(self):
        pattern_analysis, restore_modules = self._load_pattern_analysis_module()
        try:
            recorded = {}
            confirmed_patterns = {}
            findings_output = []

            pattern_analysis.prepare_case_pattern_inputs = lambda **kwargs: {
                "extraction_result": {"anchor_count": 2},
                "should_skip": False,
                "anchor_events": [],
            }

            def fake_evaluate_rule_based_pattern(**kwargs):
                recorded["evaluate_kwargs"] = kwargs
                return [{"finding": "rule"}]

            def fake_persist_rule_based_pattern_results(**kwargs):
                recorded["persist_kwargs"] = kwargs

            original_evaluate = pattern_analysis.evaluate_rule_based_pattern
            original_persist = pattern_analysis.persist_rule_based_pattern_results
            pattern_analysis.evaluate_rule_based_pattern = fake_evaluate_rule_based_pattern
            pattern_analysis.persist_rule_based_pattern_results = fake_persist_rule_based_pattern_results
            try:
                result = pattern_analysis.run_case_pattern_iteration(
                    extractor="extractor",
                    case_id=4,
                    analysis_id="analysis-4",
                    pattern_id="pattern-4",
                    pattern_name="Pattern Four",
                    pattern_config={"name": "Pattern Four"},
                    mode="A",
                    rule_analyzer="rule-analyzer",
                    confirmed_patterns=confirmed_patterns,
                    findings_output=findings_output,
                )
            finally:
                pattern_analysis.evaluate_rule_based_pattern = original_evaluate
                pattern_analysis.persist_rule_based_pattern_results = original_persist

            self.assertEqual(recorded["evaluate_kwargs"]["rule_analyzer"], "rule-analyzer")
            self.assertEqual(recorded["persist_kwargs"]["pattern_results"], [{"finding": "rule"}])
            self.assertIs(recorded["persist_kwargs"]["findings_output"], findings_output)
            self.assertIs(recorded["persist_kwargs"]["confirmed_patterns"], confirmed_patterns)
            self.assertFalse(result["skipped"])
            self.assertIsNone(result["error"])
        finally:
            restore_modules()

    def test_run_case_pattern_iteration_returns_error_payload(self):
        pattern_analysis, restore_modules = self._load_pattern_analysis_module()
        try:
            pattern_analysis.prepare_case_pattern_inputs = lambda **kwargs: {
                "extraction_result": {"anchor_count": 2},
                "should_skip": False,
                "anchor_events": [{"id": 8}],
            }
            pattern_analysis.execute_case_ai_pattern = lambda **kwargs: (_ for _ in ()).throw(RuntimeError("boom"))

            result = pattern_analysis.run_case_pattern_iteration(
                extractor="extractor",
                case_id=4,
                analysis_id="analysis-4",
                pattern_id="pattern-4",
                pattern_name="Pattern Four",
                pattern_config={"name": "Pattern Four"},
                mode="B",
                evidence_engine="engine",
                confirmed_patterns={},
                findings_output=[],
                run_full_analysis_for_package=lambda package: package,
                run_light_analysis_for_package=lambda package: package,
            )

            self.assertFalse(result["skipped"])
            self.assertEqual(result["error"], {"pattern_id": "pattern-4", "error": "boom"})
        finally:
            restore_modules()

    def test_case_analyzer_uses_shared_case_iteration_helper(self):
        source = Path("/opt/casescope/utils/case_analyzer.py").read_text()

        self.assertIn("run_case_pattern_iteration,", source)
        self.assertIn("iteration_result = run_case_pattern_iteration(", source)
        self.assertNotIn("prepared = prepare_case_pattern_inputs(", source)
        self.assertNotIn("execute_case_ai_pattern(", source)
        self.assertNotIn("pattern_results = evaluate_rule_based_pattern(", source)


if __name__ == "__main__":
    unittest.main()
