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


class Phase7PatternOverlapStageTestCase(unittest.TestCase):
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
            "phase7_pattern_overlap_under_test",
            "/opt/casescope/pipeline/pattern_analysis.py",
        )
        return pattern_analysis, restore_modules

    def test_annotate_task_pattern_overlaps_marks_related_findings(self):
        pattern_analysis, restore_modules = self._load_pattern_analysis_module()
        try:
            findings = [
                {"pattern_id": "lsass_memory_dump", "confidence": 90},
                {"pattern_id": "process_injection", "confidence": 75},
                {"pattern_id": "powershell_credential_dump", "confidence": 72},
                {"pattern_id": "other_pattern", "confidence": 60},
            ]

            result = pattern_analysis.annotate_task_pattern_overlaps(findings)

            self.assertIs(result, findings)
            self.assertEqual(
                result[0]["overlapping_patterns"],
                ["process_injection", "powershell_credential_dump"],
            )
            self.assertEqual(result[1]["overlapping_patterns"], ["lsass_memory_dump"])
            self.assertEqual(result[2]["overlapping_patterns"], ["lsass_memory_dump"])
            self.assertNotIn("overlapping_patterns", result[3])
        finally:
            restore_modules()

if __name__ == "__main__":
    unittest.main()
