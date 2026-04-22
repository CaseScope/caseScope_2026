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


class Phase7PatternCaseTailStageTestCase(unittest.TestCase):
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
            "phase7_pattern_case_tail_under_test",
            "/opt/casescope/pipeline/pattern_analysis.py",
        )
        return pattern_analysis, restore_modules

    def test_complete_case_pattern_run_cleans_up_updates_progress_and_returns_results(self):
        pattern_analysis, restore_modules = self._load_pattern_analysis_module()
        try:
            recorded = {"cleanup": 0, "progress": []}

            class FakeExtractor:
                def cleanup(self):
                    recorded["cleanup"] += 1

            def fake_progress_callback(phase, percent, message):
                recorded["progress"].append((phase, percent, message))

            results = [{"pattern_id": "alpha"}, {"pattern_id": "beta"}]
            returned = pattern_analysis.complete_case_pattern_run(
                extractor=FakeExtractor(),
                results=results,
                progress_callback=fake_progress_callback,
            )

            self.assertIs(returned, results)
            self.assertEqual(recorded["cleanup"], 1)
            self.assertEqual(
                recorded["progress"],
                [("pattern_analysis", 85, "Completed 2 pattern analyses")],
            )
        finally:
            restore_modules()

if __name__ == "__main__":
    unittest.main()
