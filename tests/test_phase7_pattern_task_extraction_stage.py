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


class Phase7PatternTaskExtractionStageTestCase(unittest.TestCase):
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
            "phase7_pattern_task_extraction_under_test",
            "/opt/casescope/pipeline/pattern_analysis.py",
        )
        return pattern_analysis, restore_modules

    def test_prepare_task_ai_pattern_inputs_shapes_stats_and_skip_decision(self):
        pattern_analysis, restore_modules = self._load_pattern_analysis_module()
        try:
            recorded = {}

            class FakeExtractor:
                def extract_pattern_candidates(self, **kwargs):
                    recorded["kwargs"] = kwargs
                    return {
                        "anchor_count": 2,
                        "supporting_count": 5,
                        "total_stored": 7,
                        "anchors": [{"id": 1}],
                    }

            result = pattern_analysis.prepare_task_ai_pattern_inputs(
                extractor=FakeExtractor(),
                pattern_config={"name": "Pattern X"},
                time_start="start",
                time_end="end",
            )

            self.assertEqual(
                recorded["kwargs"],
                {
                    "pattern_config": {"name": "Pattern X"},
                    "time_start": "start",
                    "time_end": "end",
                },
            )
            self.assertEqual(result["extraction_result"]["total_stored"], 7)
            self.assertEqual(
                result["extraction_stats"],
                {"anchor_count": 2, "supporting_count": 5, "total_stored": 7},
            )
            self.assertFalse(result["should_skip"])
            self.assertEqual(result["anchor_events"], [{"id": 1}])
        finally:
            restore_modules()

    def test_prepare_task_ai_pattern_inputs_flags_empty_extractions(self):
        pattern_analysis, restore_modules = self._load_pattern_analysis_module()
        try:
            class FakeExtractor:
                def extract_pattern_candidates(self, **kwargs):
                    return {
                        "anchor_count": 0,
                        "supporting_count": 0,
                        "total_stored": 0,
                    }

            result = pattern_analysis.prepare_task_ai_pattern_inputs(
                extractor=FakeExtractor(),
                pattern_config={"name": "Pattern Y"},
            )

            self.assertTrue(result["should_skip"])
            self.assertEqual(result["anchor_events"], [])
        finally:
            restore_modules()

    def test_rag_task_uses_shared_task_extraction_helper(self):
        source = Path("/opt/casescope/tasks/rag_tasks.py").read_text()

        self.assertIn("from pipeline.pattern_analysis import (", source)
        self.assertIn("prepare_task_ai_pattern_inputs,", source)
        self.assertIn("prepared = prepare_task_ai_pattern_inputs(", source)
        self.assertIn("extraction_result = prepared['extraction_result']", source)
        self.assertNotIn("extraction_result = extractor.extract_pattern_candidates(", source)


if __name__ == "__main__":
    unittest.main()
