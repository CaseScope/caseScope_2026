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


class Phase7PatternPersistenceStageTestCase(unittest.TestCase):
    def _load_pattern_analysis_module(self, *, track_for_suppression=True):
        fake_utils = types.ModuleType("utils")
        fake_utils.__path__ = []
        fake_candidate_extractor = types.ModuleType("utils.candidate_extractor")
        fake_evidence_engine = types.ModuleType("utils.deterministic_evidence_engine")
        fake_pattern_suppression = types.ModuleType("utils.pattern_suppression")
        fake_models = types.ModuleType("models")
        fake_models.__path__ = []
        fake_models_database = types.ModuleType("models.database")

        fake_candidate_extractor.CandidateExtractor = object
        fake_evidence_engine.DeterministicEvidenceEngine = object
        fake_pattern_suppression.PATTERN_SUPPRESSION_PRIORITY = {}
        fake_pattern_suppression.get_pattern_suppression_matches = lambda *args, **kwargs: []
        fake_pattern_suppression.should_track_pattern_for_suppression = (
            lambda pattern_id: track_for_suppression
        )

        recorded = {
            "added": [],
            "commits": 0,
        }

        class FakeSession:
            def add(self, value):
                recorded["added"].append(value)

            def commit(self):
                recorded["commits"] += 1

        fake_models_database.db = types.SimpleNamespace(session=FakeSession())

        previous_modules = {
            name: sys.modules.get(name)
            for name in [
                "utils",
                "utils.candidate_extractor",
                "utils.deterministic_evidence_engine",
                "utils.pattern_suppression",
                "models",
                "models.database",
            ]
        }
        sys.modules["utils"] = fake_utils
        sys.modules["utils.candidate_extractor"] = fake_candidate_extractor
        sys.modules["utils.deterministic_evidence_engine"] = fake_evidence_engine
        sys.modules["utils.pattern_suppression"] = fake_pattern_suppression
        sys.modules["models"] = fake_models
        sys.modules["models.database"] = fake_models_database

        def restore_modules():
            for name, previous in previous_modules.items():
                if previous is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = previous

        pattern_analysis = _load_module(
            "phase7_pattern_persistence_under_test",
            "/opt/casescope/pipeline/pattern_analysis.py",
        )
        return pattern_analysis, recorded, restore_modules

    def test_persist_ai_pattern_results_adds_records_and_tracks_confirmed_patterns(self):
        pattern_analysis, recorded, restore_modules = self._load_pattern_analysis_module()
        try:
            findings_output = []
            confirmed_patterns = {}
            processed = {
                "result_records": ["record-1", "record-2"],
                "findings": [{"pattern_id": "pattern-1"}],
                "confirmed_pattern_entries": [{"correlation_key": "alpha"}],
            }

            result = pattern_analysis.persist_ai_pattern_results(
                pattern_id="pattern-1",
                processed=processed,
                findings_output=findings_output,
                confirmed_patterns=confirmed_patterns,
            )

            self.assertEqual(recorded["added"], ["record-1", "record-2"])
            self.assertEqual(recorded["commits"], 1)
            self.assertEqual(findings_output, [{"pattern_id": "pattern-1"}])
            self.assertEqual(confirmed_patterns["pattern-1"], [{"correlation_key": "alpha"}])
            self.assertEqual(result, [{"correlation_key": "alpha"}])
        finally:
            restore_modules()

    def test_persist_ai_pattern_results_skips_tracking_for_unsuppressed_patterns(self):
        pattern_analysis, recorded, restore_modules = self._load_pattern_analysis_module(
            track_for_suppression=False
        )
        try:
            findings_output = []
            confirmed_patterns = {"existing": [{"correlation_key": "zulu"}]}
            processed = {
                "result_records": ["record-3"],
                "findings": [{"pattern_id": "pattern-2"}],
                "confirmed_pattern_entries": [{"correlation_key": "bravo"}],
            }

            result = pattern_analysis.persist_ai_pattern_results(
                pattern_id="pattern-2",
                processed=processed,
                findings_output=findings_output,
                confirmed_patterns=confirmed_patterns,
            )

            self.assertEqual(recorded["added"], ["record-3"])
            self.assertEqual(recorded["commits"], 1)
            self.assertEqual(findings_output, [{"pattern_id": "pattern-2"}])
            self.assertNotIn("pattern-2", confirmed_patterns)
            self.assertEqual(result, [{"correlation_key": "bravo"}])
        finally:
            restore_modules()

    def test_pattern_callers_use_shared_persistence_helper(self):
        case_analyzer_source = Path("/opt/casescope/utils/case_analyzer.py").read_text()
        rag_tasks_source = Path("/opt/casescope/tasks/rag_tasks.py").read_text()

        self.assertIn("run_case_pattern_loop,", case_analyzer_source)
        self.assertIn("run_case_pattern_loop(", case_analyzer_source)
        self.assertNotIn("for result_record in processed['result_records']:", case_analyzer_source)

        self.assertIn("run_task_ai_pattern_iteration,", rag_tasks_source)
        self.assertIn("iteration_result = run_task_ai_pattern_iteration(", rag_tasks_source)
        self.assertNotIn("for result_record in processed['result_records']:", rag_tasks_source)


if __name__ == "__main__":
    unittest.main()
