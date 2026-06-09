import importlib.util
import sys
import types
import unittest


def _load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class Phase7PatternCaseSetupStageTestCase(unittest.TestCase):
    def _load_pattern_analysis_module(self):
        fake_utils = types.ModuleType("utils")
        fake_utils.__path__ = []
        fake_candidate_extractor = types.ModuleType("utils.candidate_extractor")
        fake_evidence_engine = types.ModuleType("utils.deterministic_evidence_engine")
        fake_pattern_suppression = types.ModuleType("utils.pattern_suppression")
        fake_ai_correlation_analyzer = types.ModuleType("utils.ai_correlation_analyzer")

        recorded = {
            "extractor_inits": [],
            "engine_inits": [],
            "ai_inits": [],
            "rule_inits": [],
        }

        class FakeCandidateExtractor:
            def __init__(self, *, case_id, analysis_id=None, exclude_noise=False):
                recorded["extractor_inits"].append(
                    {"case_id": case_id, "analysis_id": analysis_id, "exclude_noise": exclude_noise}
                )
                self.case_id = case_id
                self.analysis_id = analysis_id
                self.exclude_noise = exclude_noise

        class FakeEvidenceEngine:
            def __init__(self, *, case_id, analysis_id, census=None, gap_findings=None, case_tz='UTC', exclude_noise=False):
                recorded["engine_inits"].append(
                    {
                        "case_id": case_id,
                        "analysis_id": analysis_id,
                        "census": census,
                        "gap_findings": gap_findings,
                        "case_tz": case_tz,
                        "exclude_noise": exclude_noise,
                    }
                )
                self.case_id = case_id
                self.analysis_id = analysis_id
                self.census = census
                self.gap_findings = gap_findings
                self.case_tz = case_tz
                self.exclude_noise = exclude_noise

        class FakeAIAnalyzer:
            def __init__(self, case_id, analysis_id, model=None, temperature=None):
                recorded["ai_inits"].append(
                    {
                        "case_id": case_id,
                        "analysis_id": analysis_id,
                        "model": model,
                        "temperature": temperature,
                    }
                )
                self.case_id = case_id
                self.analysis_id = analysis_id
                self.model = "fake-model"

        class FakeRuleAnalyzer:
            def __init__(self, case_id, analysis_id):
                recorded["rule_inits"].append(
                    {"case_id": case_id, "analysis_id": analysis_id}
                )
                self.case_id = case_id
                self.analysis_id = analysis_id

        fake_candidate_extractor.CandidateExtractor = FakeCandidateExtractor
        fake_evidence_engine.DeterministicEvidenceEngine = FakeEvidenceEngine
        fake_pattern_suppression.PATTERN_SUPPRESSION_PRIORITY = {}
        fake_pattern_suppression.get_pattern_suppression_matches = lambda *args, **kwargs: []
        fake_ai_correlation_analyzer.AICorrelationAnalyzer = FakeAIAnalyzer
        fake_ai_correlation_analyzer.RuleBasedAnalyzer = FakeRuleAnalyzer

        previous_modules = {
            name: sys.modules.get(name)
            for name in [
                "utils",
                "utils.candidate_extractor",
                "utils.deterministic_evidence_engine",
                "utils.pattern_suppression",
                "utils.ai_correlation_analyzer",
            ]
        }
        sys.modules["utils"] = fake_utils
        sys.modules["utils.candidate_extractor"] = fake_candidate_extractor
        sys.modules["utils.deterministic_evidence_engine"] = fake_evidence_engine
        sys.modules["utils.pattern_suppression"] = fake_pattern_suppression
        sys.modules["utils.ai_correlation_analyzer"] = fake_ai_correlation_analyzer

        def restore_modules():
            for name, previous in previous_modules.items():
                if previous is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = previous

        pattern_analysis = _load_module(
            "phase7_pattern_case_setup_under_test",
            "/opt/casescope/pipeline/pattern_analysis.py",
        )
        return pattern_analysis, recorded, restore_modules

    def test_prepare_case_pattern_runtime_builds_ai_mode_runtime(self):
        pattern_analysis, recorded, restore_modules = self._load_pattern_analysis_module()
        try:
            runtime = pattern_analysis.prepare_case_pattern_runtime(
                case_id=21,
                analysis_id="analysis-21",
                mode="B",
                census={"4624": 7},
                gap_findings=["gap-1"],
                case_tz="America/New_York",
            )

            self.assertEqual(
                recorded["extractor_inits"],
                [{"case_id": 21, "analysis_id": "analysis-21", "exclude_noise": False}],
            )
            self.assertEqual(
                recorded["engine_inits"],
                [
                    {
                        "case_id": 21,
                        "analysis_id": "analysis-21",
                        "census": {"4624": 7},
                        "gap_findings": ["gap-1"],
                        "case_tz": "America/New_York",
                        "exclude_noise": False,
                    }
                ],
            )
            self.assertEqual(
                recorded["ai_inits"],
                [{"case_id": 21, "analysis_id": "analysis-21", "model": None, "temperature": None}],
            )
            self.assertEqual(recorded["rule_inits"], [])
            self.assertIsNotNone(runtime["ai_analyzer"])
            self.assertIsNone(runtime["rule_analyzer"])
            self.assertEqual(runtime["confirmed_patterns"], {})
        finally:
            restore_modules()

    def test_prepare_case_pattern_runtime_builds_rule_mode_runtime(self):
        pattern_analysis, recorded, restore_modules = self._load_pattern_analysis_module()
        try:
            runtime = pattern_analysis.prepare_case_pattern_runtime(
                case_id=22,
                analysis_id="analysis-22",
                mode="A",
                census={"4625": 3},
                case_tz="UTC",
            )

            self.assertEqual(recorded["ai_inits"], [])
            self.assertEqual(
                recorded["rule_inits"],
                [{"case_id": 22, "analysis_id": "analysis-22"}],
            )
            self.assertIsNone(runtime["ai_analyzer"])
            self.assertIsNotNone(runtime["rule_analyzer"])
            self.assertEqual(runtime["confirmed_patterns"], {})
        finally:
            restore_modules()

if __name__ == "__main__":
    unittest.main()
