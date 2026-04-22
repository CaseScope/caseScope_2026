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


class Phase7PatternFinalizationStageTestCase(unittest.TestCase):
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
            "phase7_pattern_finalization_under_test",
            "/opt/casescope/pipeline/pattern_analysis.py",
        )
        return pattern_analysis, restore_modules

    def test_finalize_task_ai_pattern_results_sorts_annotates_and_packages_response(self):
        pattern_analysis, restore_modules = self._load_pattern_analysis_module()
        try:
            recorded = {}

            def fake_annotate_task_pattern_overlaps(findings):
                recorded["annotated_findings"] = findings
                findings[0]["overlapping_patterns"] = ["lsass_memory_dump"]
                return findings

            original_annotate = pattern_analysis.annotate_task_pattern_overlaps
            pattern_analysis.annotate_task_pattern_overlaps = fake_annotate_task_pattern_overlaps
            try:
                all_results = [
                    {"pattern_id": "process_injection", "confidence": 65},
                    {"pattern_id": "lsass_memory_dump", "confidence": 91},
                    {"pattern_id": "other", "confidence": 40},
                ]
                response = pattern_analysis.finalize_task_ai_pattern_results(
                    case_id=10,
                    case_uuid="case-uuid-10",
                    analysis_id="analysis-10",
                    pattern_configs={"a": {}, "b": {}},
                    all_results=all_results,
                    extraction_stats={"a": {"total_stored": 1}},
                    errors=[{"pattern_id": "a", "error": "boom"}],
                )
            finally:
                pattern_analysis.annotate_task_pattern_overlaps = original_annotate

            self.assertEqual(
                [finding["pattern_id"] for finding in recorded["annotated_findings"]],
                ["lsass_memory_dump", "process_injection", "other"],
            )
            self.assertEqual(response["case_id"], 10)
            self.assertEqual(response["case_uuid"], "case-uuid-10")
            self.assertEqual(response["patterns_analyzed"], 2)
            self.assertEqual(response["results_count"], 3)
            self.assertEqual(response["high_confidence_count"], 1)
            self.assertEqual(response["results"][0]["pattern_id"], "lsass_memory_dump")
            self.assertEqual(response["errors"], [{"pattern_id": "a", "error": "boom"}])
        finally:
            restore_modules()

if __name__ == "__main__":
    unittest.main()
