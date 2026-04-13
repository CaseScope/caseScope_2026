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


class Phase7PatternCaseHeadStageTestCase(unittest.TestCase):
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
            "phase7_pattern_case_head_under_test",
            "/opt/casescope/pipeline/pattern_analysis.py",
        )
        return pattern_analysis, restore_modules

    def test_prepare_case_pattern_head_short_circuits_when_no_patterns(self):
        pattern_analysis, restore_modules = self._load_pattern_analysis_module()
        try:
            progress = []
            pattern_analysis.prepare_pattern_analysis = lambda case_id: {
                "patterns": {},
                "census": {"1": 1},
                "ordered_patterns": [],
                "skipped_count": 0,
            }

            result = pattern_analysis.prepare_case_pattern_head(
                case_id=5,
                progress_callback=lambda phase, percent, message: progress.append(
                    (phase, percent, message)
                ),
            )

            self.assertTrue(result["should_return"])
            self.assertEqual(result["pattern_total"], 0)
            self.assertEqual(result["pattern_count"], 0)
            self.assertEqual(progress, [("pattern_analysis", 85, "No patterns to analyze")])
        finally:
            restore_modules()

    def test_prepare_case_pattern_head_emits_census_messages_and_keeps_running(self):
        pattern_analysis, restore_modules = self._load_pattern_analysis_module()
        try:
            progress = []
            info = []
            pattern_analysis.prepare_pattern_analysis = lambda case_id: {
                "patterns": {"a": {"name": "A"}, "b": {"name": "B"}},
                "census": {"1001": 2},
                "ordered_patterns": [("a", {"name": "A"})],
                "skipped_count": 1,
            }

            result = pattern_analysis.prepare_case_pattern_head(
                case_id=6,
                progress_callback=lambda phase, percent, message: progress.append(
                    (phase, percent, message)
                ),
                info_callback=info.append,
            )

            self.assertFalse(result["should_return"])
            self.assertEqual(result["census"], {"1001": 2})
            self.assertEqual(result["ordered_patterns"], [("a", {"name": "A"})])
            self.assertEqual(result["pattern_total"], 2)
            self.assertEqual(result["pattern_count"], 1)
            self.assertEqual(
                progress,
                [
                    ("pattern_analysis", 51, "Running event census..."),
                    ("pattern_analysis", 52, "Analyzing 1 patterns (1 skipped by census)..."),
                ],
            )
            self.assertEqual(
                info,
                ["[CaseAnalyzer] Census filter: 1/2 patterns eligible (1 skipped — anchor events not in case)"],
            )
        finally:
            restore_modules()

    def test_case_analyzer_uses_shared_case_head_helper(self):
        source = Path("/opt/casescope/utils/case_analyzer.py").read_text()

        self.assertIn("prepare_case_pattern_head,", source)
        self.assertIn("head = prepare_case_pattern_head(", source)
        self.assertNotIn("prep = prepare_pattern_analysis(self.case_id)", source)
        self.assertNotIn("self._update_progress('pattern_analysis', 51, 'Running event census...')", source)


if __name__ == "__main__":
    unittest.main()
