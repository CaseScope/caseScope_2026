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


class Phase7PatternCasePrepStageTestCase(unittest.TestCase):
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
            "phase7_pattern_case_prep_under_test",
            "/opt/casescope/pipeline/pattern_analysis.py",
        )
        return pattern_analysis, restore_modules

    def test_prepare_case_pattern_inputs_shapes_branch_inputs(self):
        pattern_analysis, restore_modules = self._load_pattern_analysis_module()
        try:
            recorded = {}

            class FakeExtractor:
                def extract_pattern_candidates(self, pattern_config):
                    recorded["extract_pattern_config"] = dict(pattern_config)
                    return {
                        "anchor_count": 2,
                        "correlation_key": "alpha",
                        "anchors": [{"id": "anchor"}],
                    }

                def get_candidates_for_key(self, pattern_id, key):
                    recorded["key_lookup"] = (pattern_id, key)
                    return [{"behavioral_context": {"user": "alice"}}]

                def attach_behavioral_context(self, candidates):
                    recorded["context_candidates"] = list(candidates)
                    return [{"behavioral_context": {"user": "alice"}, "id": "candidate"}]

            pattern_config = {"name": "Pattern Seven"}
            result = pattern_analysis.prepare_case_pattern_inputs(
                extractor=FakeExtractor(),
                pattern_id="pattern-7",
                pattern_config=pattern_config,
            )

            self.assertEqual(pattern_config["id"], "pattern-7")
            self.assertEqual(recorded["extract_pattern_config"]["id"], "pattern-7")
            self.assertEqual(recorded["key_lookup"], ("pattern-7", "alpha"))
            self.assertFalse(result["should_skip"])
            self.assertEqual(result["anchor_events"], [{"id": "anchor"}])
        finally:
            restore_modules()

    def test_prepare_case_pattern_inputs_skips_when_no_anchors(self):
        pattern_analysis, restore_modules = self._load_pattern_analysis_module()
        try:
            class FakeExtractor:
                def extract_pattern_candidates(self, pattern_config):
                    return {"anchor_count": 0}

            result = pattern_analysis.prepare_case_pattern_inputs(
                extractor=FakeExtractor(),
                pattern_id="pattern-8",
                pattern_config={"name": "Pattern Eight"},
            )

            self.assertTrue(result["should_skip"])
            self.assertEqual(result["anchor_events"], [])
        finally:
            restore_modules()

    def test_case_analyzer_uses_shared_case_iteration_helper_for_prep(self):
        source = Path("/opt/casescope/utils/case_analyzer.py").read_text()

        self.assertIn("run_case_pattern_iteration,", source)
        self.assertIn("iteration_result = run_case_pattern_iteration(", source)
        self.assertNotIn("extraction_result = extractor.extract_pattern_candidates(pattern_config)", source)


if __name__ == "__main__":
    unittest.main()
