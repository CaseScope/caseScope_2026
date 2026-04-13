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

    def test_complete_task_ai_pattern_run_emits_progress_and_log_then_returns_payload(self):
        pattern_analysis, restore_modules = self._load_pattern_analysis_module()
        try:
            recorded = {"progress": [], "logs": []}

            def fake_build_task_ai_pattern_completion_meta(*, results_count):
                recorded["progress"].append(("meta", results_count))
                return {"progress": 100, "results_count": results_count}

            def fake_log_task_ai_pattern_completion(hunt_log, **kwargs):
                recorded["logs"].append((hunt_log, kwargs))

            original_build = pattern_analysis.build_task_ai_pattern_completion_meta
            original_log = pattern_analysis.log_task_ai_pattern_completion
            pattern_analysis.build_task_ai_pattern_completion_meta = fake_build_task_ai_pattern_completion_meta
            pattern_analysis.log_task_ai_pattern_completion = fake_log_task_ai_pattern_completion
            try:
                payload = {"patterns_analyzed": 9, "results_count": 4}
                result = pattern_analysis.complete_task_ai_pattern_run(
                    response_payload=payload,
                    error_count=2,
                    hunt_log="hunt-log",
                    progress_callback=recorded["progress"].append,
                )
            finally:
                pattern_analysis.build_task_ai_pattern_completion_meta = original_build
                pattern_analysis.log_task_ai_pattern_completion = original_log

            self.assertIs(result, payload)
            self.assertEqual(
                recorded["progress"],
                [("meta", 4), {"progress": 100, "results_count": 4}],
            )
            self.assertEqual(
                recorded["logs"],
                [("hunt-log", {"patterns_analyzed": 9, "results_count": 4, "error_count": 2})],
            )
        finally:
            restore_modules()

    def test_rag_task_uses_shared_tail_helper(self):
        source = Path("/opt/casescope/tasks/rag_tasks.py").read_text()

        self.assertIn("from pipeline.pattern_analysis import (", source)
        self.assertIn("complete_task_ai_pattern_run,", source)
        self.assertIn("return complete_task_ai_pattern_run(", source)
        self.assertNotIn("patterns_analyzed=response_payload['patterns_analyzed']", source)
        self.assertNotIn("meta=build_task_ai_pattern_completion_meta(", source)


if __name__ == "__main__":
    unittest.main()
