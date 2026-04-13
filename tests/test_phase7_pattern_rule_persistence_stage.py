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


class Phase7PatternRulePersistenceStageTestCase(unittest.TestCase):
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
        fake_pattern_suppression.should_track_pattern_for_suppression = lambda pattern_id: True
        fake_pattern_suppression.build_confirmed_pattern_entry = lambda *, correlation_key, score, anchor=None: {
            "correlation_key": correlation_key,
            "score": score,
            "anchor": anchor,
        }

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
            "phase7_pattern_rule_persistence_under_test",
            "/opt/casescope/pipeline/pattern_analysis.py",
        )
        return pattern_analysis, fake_pattern_suppression, restore_modules

    def test_persist_rule_based_pattern_results_extends_findings_and_tracks_confirmed_entries(self):
        pattern_analysis, _, restore_modules = self._load_pattern_analysis_module()
        try:
            findings_output = [{"pattern_id": "existing"}]
            confirmed_patterns = {}
            pattern_results = [
                {"correlation_key": "alpha", "final_confidence": 71},
                {"correlation_key": "bravo", "final_confidence": 63},
            ]

            result = pattern_analysis.persist_rule_based_pattern_results(
                pattern_id="pattern-7",
                pattern_results=pattern_results,
                findings_output=findings_output,
                confirmed_patterns=confirmed_patterns,
            )

            self.assertEqual(findings_output[1:], pattern_results)
            self.assertEqual(
                result,
                [
                    {"correlation_key": "alpha", "score": 71, "anchor": None},
                    {"correlation_key": "bravo", "score": 63, "anchor": None},
                ],
            )
            self.assertEqual(confirmed_patterns["pattern-7"], result)
        finally:
            restore_modules()

    def test_persist_rule_based_pattern_results_skips_tracking_when_disabled(self):
        pattern_analysis, fake_pattern_suppression, restore_modules = self._load_pattern_analysis_module()
        try:
            fake_pattern_suppression.should_track_pattern_for_suppression = lambda pattern_id: False
            findings_output = []
            confirmed_patterns = {}

            result = pattern_analysis.persist_rule_based_pattern_results(
                pattern_id="pattern-8",
                pattern_results=[{"correlation_key": "alpha", "final_confidence": 55}],
                findings_output=findings_output,
                confirmed_patterns=confirmed_patterns,
            )

            self.assertEqual(len(findings_output), 1)
            self.assertEqual(result, [])
            self.assertEqual(confirmed_patterns, {})
        finally:
            restore_modules()

    def test_case_analyzer_uses_shared_case_iteration_helper_for_rule_persistence(self):
        source = Path("/opt/casescope/utils/case_analyzer.py").read_text()

        self.assertIn("run_case_pattern_iteration,", source)
        self.assertIn("iteration_result = run_case_pattern_iteration(", source)
        self.assertNotIn("build_confirmed_pattern_entry(", source)


if __name__ == "__main__":
    unittest.main()
