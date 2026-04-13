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


class Phase7PatternTaskProgressStageTestCase(unittest.TestCase):
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
            "phase7_pattern_task_progress_under_test",
            "/opt/casescope/pipeline/pattern_analysis.py",
        )
        return pattern_analysis, restore_modules

    def test_build_task_ai_pattern_progress_meta_shapes_analysis_payload(self):
        pattern_analysis, restore_modules = self._load_pattern_analysis_module()
        try:
            result = pattern_analysis.build_task_ai_pattern_progress_meta(
                pattern_id="pattern-7",
                pattern_name="Pattern Seven",
                pattern_index=2,
                total_patterns=5,
            )

            self.assertEqual(
                result,
                {
                    "progress": 42,
                    "status": "Analyzing Pattern Seven",
                    "stage": "analysis",
                    "pattern": "pattern-7",
                    "pattern_index": 3,
                    "total_patterns": 5,
                },
            )
        finally:
            restore_modules()

    def test_rag_task_uses_shared_progress_helper(self):
        source = Path("/opt/casescope/tasks/rag_tasks.py").read_text()

        self.assertIn("from pipeline.pattern_analysis import (", source)
        self.assertIn("build_task_ai_pattern_progress_meta,", source)
        self.assertIn("meta=build_task_ai_pattern_progress_meta(", source)
        self.assertNotIn("'status': f'Analyzing {pattern_config[\"name\"]}'", source)


if __name__ == "__main__":
    unittest.main()
