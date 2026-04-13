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


class Phase7PatternSuppressionStageTestCase(unittest.TestCase):
    def _load_pattern_analysis_module(self, *, suppression_matches=None):
        fake_utils = types.ModuleType("utils")
        fake_utils.__path__ = []
        fake_candidate_extractor = types.ModuleType("utils.candidate_extractor")
        fake_evidence_engine = types.ModuleType("utils.deterministic_evidence_engine")
        fake_pattern_suppression = types.ModuleType("utils.pattern_suppression")

        fake_candidate_extractor.CandidateExtractor = object
        fake_evidence_engine.DeterministicEvidenceEngine = object
        fake_pattern_suppression.PATTERN_SUPPRESSION_PRIORITY = {}

        recorded = {
            "calls": [],
        }

        def fake_get_pattern_suppression_matches(pattern_id, anchor, confirmed_patterns):
            recorded["calls"].append({
                "pattern_id": pattern_id,
                "anchor": anchor,
                "confirmed_patterns": confirmed_patterns,
            })
            return suppression_matches or []

        fake_pattern_suppression.get_pattern_suppression_matches = fake_get_pattern_suppression_matches

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
            "phase7_pattern_suppression_under_test",
            "/opt/casescope/pipeline/pattern_analysis.py",
        )
        return pattern_analysis, recorded, restore_modules

    def test_apply_pattern_suppression_marks_hard_suppression(self):
        pattern_analysis, recorded, restore_modules = self._load_pattern_analysis_module(
            suppression_matches=[{"mode": "hard", "suppressor": "bloodhound_sharphound", "adjustment": 100}],
        )
        try:
            package = types.SimpleNamespace(
                correlation_key="alpha",
                deterministic_score=80,
                anchor={"source_host": "host-1"},
            )

            result = pattern_analysis.apply_pattern_suppression(
                "dcsync",
                package,
                {"bloodhound_sharphound": [{"score": 90}]},
            )

            self.assertTrue(result["suppressed"])
            self.assertEqual(result["suppressor"], "bloodhound_sharphound")
            self.assertEqual(result["soft_adjustment"], 0)
            self.assertIs(result["package"], package)
            self.assertEqual(recorded["calls"][0]["pattern_id"], "dcsync")
        finally:
            restore_modules()

    def test_apply_pattern_suppression_soft_adjusts_score(self):
        pattern_analysis, _, restore_modules = self._load_pattern_analysis_module(
            suppression_matches=[{"mode": "soft", "suppressor": "registry_run_keys", "adjustment": 20}],
        )
        try:
            package = types.SimpleNamespace(
                correlation_key="bravo",
                deterministic_score=65,
                anchor={"source_host": "host-2"},
            )

            result = pattern_analysis.apply_pattern_suppression(
                "scheduled_task_persistence",
                package,
                {"registry_run_keys": [{"score": 75}]},
            )

            self.assertFalse(result["suppressed"])
            self.assertIsNone(result["suppressor"])
            self.assertEqual(result["soft_adjustment"], 20)
            self.assertEqual(package.deterministic_score, 45)
        finally:
            restore_modules()

    def test_apply_pattern_suppression_leaves_unsuppressed_package_unchanged(self):
        pattern_analysis, _, restore_modules = self._load_pattern_analysis_module()
        try:
            package = types.SimpleNamespace(
                correlation_key="charlie",
                deterministic_score=33,
                anchor={"source_host": "host-3"},
            )

            result = pattern_analysis.apply_pattern_suppression("winrm_lateral", package, {})

            self.assertFalse(result["suppressed"])
            self.assertEqual(result["soft_adjustment"], 0)
            self.assertEqual(package.deterministic_score, 33)
        finally:
            restore_modules()

    def test_pattern_callers_use_shared_suppression_helper(self):
        case_analyzer_source = Path("/opt/casescope/utils/case_analyzer.py").read_text()
        rag_tasks_source = Path("/opt/casescope/tasks/rag_tasks.py").read_text()

        self.assertIn("execute_case_ai_pattern,", case_analyzer_source)
        self.assertNotIn("suppression_result = apply_pattern_suppression(", case_analyzer_source)
        self.assertNotIn("suppression_matches = get_pattern_suppression_matches(", case_analyzer_source)

        self.assertIn("run_task_ai_pattern_iteration,", rag_tasks_source)
        self.assertNotIn("suppression_result = apply_pattern_suppression(", rag_tasks_source)
        self.assertNotIn("suppression_matches = get_pattern_suppression_matches(", rag_tasks_source)


if __name__ == "__main__":
    unittest.main()
