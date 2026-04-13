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


class Phase7PatternTaskLogStageTestCase(unittest.TestCase):
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
            "phase7_pattern_task_log_under_test",
            "/opt/casescope/pipeline/pattern_analysis.py",
        )
        return pattern_analysis, restore_modules

    def test_log_task_ai_pattern_completion_emits_summary(self):
        pattern_analysis, restore_modules = self._load_pattern_analysis_module()
        try:
            recorded = {}

            class FakeHuntLog:
                def log_complete(self, **kwargs):
                    recorded["kwargs"] = kwargs

            pattern_analysis.log_task_ai_pattern_completion(
                FakeHuntLog(),
                patterns_analyzed=14,
                results_count=5,
                error_count=2,
            )

            self.assertEqual(
                recorded["kwargs"],
                {
                    "patterns_checked": 14,
                    "matches_found": 5,
                    "errors": 2,
                },
            )
        finally:
            restore_modules()

    def test_rag_task_uses_shared_log_helper(self):
        source = Path("/opt/casescope/tasks/rag_tasks.py").read_text()

        self.assertIn("from pipeline.pattern_analysis import (", source)
        self.assertIn("log_task_ai_pattern_completion,", source)
        self.assertIn("log_task_ai_pattern_completion(", source)
        self.assertNotIn("patterns_checked=response_payload['patterns_analyzed']", source)


if __name__ == "__main__":
    unittest.main()
