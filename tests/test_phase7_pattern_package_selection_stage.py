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


class Phase7PatternPackageSelectionStageTestCase(unittest.TestCase):
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
            "phase7_pattern_package_selection_under_test",
            "/opt/casescope/pipeline/pattern_analysis.py",
        )
        return pattern_analysis, restore_modules

    def test_select_highest_scoring_packages_keeps_best_package_per_key(self):
        pattern_analysis, restore_modules = self._load_pattern_analysis_module()
        try:
            package_a_low = types.SimpleNamespace(correlation_key="alpha", deterministic_score=25)
            package_a_high = types.SimpleNamespace(correlation_key="alpha", deterministic_score=80)
            package_b = types.SimpleNamespace(correlation_key="bravo", deterministic_score=40)

            result = pattern_analysis.select_highest_scoring_packages(
                [package_a_low, package_b, package_a_high]
            )

            self.assertEqual(len(result), 2)
            self.assertIs(result[0], package_a_high)
            self.assertIs(result[1], package_b)
        finally:
            restore_modules()

    def test_select_highest_scoring_packages_handles_empty_input(self):
        pattern_analysis, restore_modules = self._load_pattern_analysis_module()
        try:
            self.assertEqual(pattern_analysis.select_highest_scoring_packages([]), [])
        finally:
            restore_modules()

    def test_pattern_callers_use_shared_package_selection_helper(self):
        case_analyzer_source = Path("/opt/casescope/utils/case_analyzer.py").read_text()
        rag_tasks_source = Path("/opt/casescope/tasks/rag_tasks.py").read_text()

        self.assertIn("run_case_pattern_iteration,", case_analyzer_source)
        self.assertNotIn("evidence_packages = select_highest_scoring_packages(evidence_packages)", case_analyzer_source)
        self.assertNotIn("best_by_key = {}", case_analyzer_source)

        self.assertIn("from pipeline.pattern_analysis import (", rag_tasks_source)
        self.assertIn("run_task_ai_pattern_iteration,", rag_tasks_source)
        self.assertNotIn("evidence_packages = select_highest_scoring_packages(evidence_packages)", rag_tasks_source)
        self.assertNotIn("best_by_key = {}", rag_tasks_source)


if __name__ == "__main__":
    unittest.main()
