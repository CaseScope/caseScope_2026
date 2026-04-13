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


class Phase7PatternCaseLoopStageTestCase(unittest.TestCase):
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
            "phase7_pattern_case_loop_under_test",
            "/opt/casescope/pipeline/pattern_analysis.py",
        )
        return pattern_analysis, restore_modules

    def test_run_case_pattern_loop_emits_progress_and_delegates_iterations(self):
        pattern_analysis, restore_modules = self._load_pattern_analysis_module()
        try:
            recorded = {"iterations": [], "progress": []}

            class FakeAIAnalyzer:
                model = "fake-model"

                def analyze_with_evidence(self, package, pattern_config):
                    return {"package": package, "pattern": pattern_config["name"]}

                def analyze_with_evidence_lightweight(self, package, pattern_config):
                    return {"light": True, "package": package, "pattern": pattern_config["name"]}

            def fake_run_case_pattern_iteration(**kwargs):
                recorded["iterations"].append(kwargs)
                kwargs["findings_output"].append({"pattern_id": kwargs["pattern_id"]})
                return {"skipped": False, "error": None}

            original_iteration = pattern_analysis.run_case_pattern_iteration
            pattern_analysis.run_case_pattern_iteration = fake_run_case_pattern_iteration
            try:
                findings_output = []
                result = pattern_analysis.run_case_pattern_loop(
                    ordered_patterns=[
                        ("alpha", {"name": "Alpha"}),
                        ("beta", {"name": "Beta"}),
                    ],
                    case_id=7,
                    analysis_id="analysis-7",
                    mode="B",
                    extractor="extractor",
                    evidence_engine="engine",
                    ai_analyzer=FakeAIAnalyzer(),
                    rule_analyzer=None,
                    confirmed_patterns={"existing": []},
                    findings_output=findings_output,
                    progress_callback=lambda phase, percent, message: recorded["progress"].append(
                        (phase, percent, message)
                    ),
                )
            finally:
                pattern_analysis.run_case_pattern_iteration = original_iteration

            self.assertIs(result, findings_output)
            self.assertEqual(
                recorded["progress"],
                [
                    ("pattern_analysis", 52, "Analyzing Alpha..."),
                    ("pattern_analysis", 68, "Analyzing Beta..."),
                ],
            )
            self.assertEqual(
                [call["pattern_id"] for call in recorded["iterations"]],
                ["alpha", "beta"],
            )
            self.assertEqual(recorded["iterations"][0]["model_name"], "fake-model")
            self.assertEqual(findings_output, [{"pattern_id": "alpha"}, {"pattern_id": "beta"}])
        finally:
            restore_modules()

    def test_run_case_pattern_loop_reports_iteration_warnings(self):
        pattern_analysis, restore_modules = self._load_pattern_analysis_module()
        try:
            warnings = []
            original_iteration = pattern_analysis.run_case_pattern_iteration
            pattern_analysis.run_case_pattern_iteration = lambda **kwargs: {
                "skipped": False,
                "error": {"pattern_id": kwargs["pattern_id"], "error": "boom"},
            }
            try:
                pattern_analysis.run_case_pattern_loop(
                    ordered_patterns=[("alpha", {"name": "Alpha"})],
                    case_id=7,
                    analysis_id="analysis-7",
                    mode="A",
                    extractor="extractor",
                    evidence_engine="engine",
                    ai_analyzer=None,
                    rule_analyzer="rule-analyzer",
                    confirmed_patterns={},
                    findings_output=[],
                    warning_callback=lambda pattern_id, error: warnings.append((pattern_id, error)),
                )
            finally:
                pattern_analysis.run_case_pattern_iteration = original_iteration

            self.assertEqual(warnings, [("alpha", "boom")])
        finally:
            restore_modules()

    def test_case_analyzer_uses_shared_case_loop_helper(self):
        source = Path("/opt/casescope/utils/case_analyzer.py").read_text()

        self.assertIn("run_case_pattern_loop,", source)
        self.assertIn("run_case_pattern_loop(", source)
        self.assertNotIn("iteration_result = run_case_pattern_iteration(", source)


if __name__ == "__main__":
    unittest.main()
