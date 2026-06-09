import importlib.util
import sys
import types
import unittest
from unittest.mock import patch

from tests.phase7_rag_tasks_loader import load_rag_tasks_with_stubs


def _load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class Phase7PatternTaskIterationStageTestCase(unittest.TestCase):
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
            "phase7_pattern_task_iteration_under_test",
            "/opt/casescope/pipeline/pattern_analysis.py",
        )
        return pattern_analysis, restore_modules

    def test_run_task_ai_pattern_iteration_runs_preparation_execution_and_stats(self):
        pattern_analysis, restore_modules = self._load_pattern_analysis_module()
        try:
            recorded = {}

            def fake_prepare_task_ai_pattern_inputs(**kwargs):
                recorded["prepare_kwargs"] = kwargs
                return {
                    "extraction_result": {"anchor_count": 1},
                    "extraction_stats": {"total_stored": 5},
                    "should_skip": False,
                    "anchor_events": [{"id": 99}],
                }

            def fake_execute_task_ai_pattern(**kwargs):
                recorded["execute_kwargs"] = kwargs

            original_prepare = pattern_analysis.prepare_task_ai_pattern_inputs
            original_execute = pattern_analysis.execute_task_ai_pattern
            pattern_analysis.prepare_task_ai_pattern_inputs = fake_prepare_task_ai_pattern_inputs
            pattern_analysis.execute_task_ai_pattern = fake_execute_task_ai_pattern
            try:
                result = pattern_analysis.run_task_ai_pattern_iteration(
                    extractor="extractor",
                    case_id=11,
                    analysis_id="analysis-11",
                    pattern_id="pattern-11",
                    pattern_config={"name": "Pattern Eleven"},
                    time_start="start",
                    time_end="end",
                    opencti_provider="provider",
                    evidence_engine="engine",
                    confirmed_patterns={"existing": []},
                    findings_output=["finding"],
                    run_full_analysis_for_package=lambda package: package,
                    run_light_analysis_for_package=lambda package: package,
                    get_analysis_stats=lambda: {"calls": 3},
                    model_name="model-x",
                    event_callback="event-callback",
                    ai_gray_threshold_default=25,
                )
            finally:
                pattern_analysis.prepare_task_ai_pattern_inputs = original_prepare
                pattern_analysis.execute_task_ai_pattern = original_execute

            self.assertEqual(recorded["prepare_kwargs"]["extractor"], "extractor")
            self.assertEqual(recorded["prepare_kwargs"]["time_start"], "start")
            self.assertEqual(recorded["execute_kwargs"]["pattern_id"], "pattern-11")
            self.assertEqual(recorded["execute_kwargs"]["anchor_events"], [{"id": 99}])
            self.assertEqual(result["extraction_stats"], {"total_stored": 5})
            self.assertFalse(result["skipped"])
            self.assertEqual(result["analysis_stats"], {"calls": 3})
            self.assertIsNone(result["error"])
        finally:
            restore_modules()

    def test_run_task_ai_pattern_iteration_preserves_extraction_stats_on_error(self):
        pattern_analysis, restore_modules = self._load_pattern_analysis_module()
        try:
            pattern_analysis.prepare_task_ai_pattern_inputs = lambda **kwargs: {
                "extraction_result": {"anchor_count": 1},
                "extraction_stats": {"total_stored": 2},
                "should_skip": False,
                "anchor_events": [],
            }
            pattern_analysis.execute_task_ai_pattern = lambda **kwargs: (_ for _ in ()).throw(RuntimeError("boom"))

            result = pattern_analysis.run_task_ai_pattern_iteration(
                extractor="extractor",
                case_id=11,
                analysis_id="analysis-11",
                pattern_id="pattern-11",
                pattern_config={"name": "Pattern Eleven"},
                opencti_provider="provider",
                evidence_engine="engine",
                confirmed_patterns={},
                findings_output=[],
                run_full_analysis_for_package=lambda package: package,
                run_light_analysis_for_package=lambda package: package,
            )

            self.assertEqual(result["extraction_stats"], {"total_stored": 2})
            self.assertFalse(result["skipped"])
            self.assertIsNone(result["analysis_stats"])
            self.assertEqual(result["error"]["pattern_id"], "pattern-11")
            self.assertEqual(result["error"]["error"], "boom")
            self.assertIn("Traceback", result["error"]["traceback"])
        finally:
            restore_modules()

    def test_ai_pattern_task_uses_shared_task_iteration_helper(self):
        rag_tasks, restore_modules = load_rag_tasks_with_stubs(
            "phase7_pattern_task_iteration_rag_task_under_test"
        )
        try:
            recorded = {}

            fake_pattern_analysis = types.ModuleType("pipeline.pattern_analysis")

            def run_task_ai_pattern_iteration(**kwargs):
                recorded["iteration_pattern_id"] = kwargs["pattern_id"]
                return {
                    "extraction_stats": {"total_stored": 3},
                    "skipped": False,
                    "analysis_stats": {"calls": 2},
                    "error": {"pattern_id": kwargs["pattern_id"], "error": "boom"},
                }

            def finalize_task_ai_pattern_results(**kwargs):
                recorded["finalize_kwargs"] = kwargs
                return {
                    "success": True,
                    "patterns_analyzed": len(kwargs["pattern_configs"]),
                    "results_count": len(kwargs["all_results"]),
                }

            fake_pattern_analysis.build_task_ai_pattern_completion_meta = lambda **kwargs: kwargs
            fake_pattern_analysis.build_task_ai_pattern_progress_meta = lambda **kwargs: kwargs
            fake_pattern_analysis.cleanup_task_pattern_extractor = lambda *args, **kwargs: None
            fake_pattern_analysis.complete_task_ai_pattern_run = lambda **kwargs: kwargs["response_payload"]
            fake_pattern_analysis.create_candidate_extractor = lambda *args, **kwargs: object()
            fake_pattern_analysis.create_evidence_engine = lambda *args, **kwargs: object()
            fake_pattern_analysis.finalize_task_ai_pattern_results = finalize_task_ai_pattern_results
            fake_pattern_analysis.log_task_ai_pattern_completion = lambda *args, **kwargs: None
            fake_pattern_analysis.run_pattern_census = lambda case_id, **kwargs: {"4624": case_id}
            fake_pattern_analysis.run_task_ai_pattern_iteration = run_task_ai_pattern_iteration

            fake_pipeline = types.ModuleType("pipeline")
            fake_pipeline.__path__ = []
            fake_pipeline.pattern_analysis = fake_pattern_analysis

            class FakeAnalyzer:
                def __init__(self, case_id, analysis_id):
                    self.model = "fake-model"

                def analyze_with_evidence(self, package, pattern_config):
                    return {}

                def analyze_with_evidence_lightweight(self, package, pattern_config):
                    return {}

                def get_stats(self):
                    return {}

            runtime_modules = {
                "pipeline": fake_pipeline,
                "pipeline.pattern_analysis": fake_pattern_analysis,
                "models.case": types.SimpleNamespace(Case=object()),
                "models.database": types.SimpleNamespace(db=types.SimpleNamespace(session=None)),
                "utils.ai_correlation_analyzer": types.SimpleNamespace(
                    AICorrelationAnalyzer=FakeAnalyzer
                ),
                "utils.feature_availability": types.SimpleNamespace(
                    FeatureAvailability=types.SimpleNamespace(is_ai_enabled=lambda: True)
                ),
                "utils.opencti_context": types.SimpleNamespace(
                    OpenCTIContextProvider=lambda *args, **kwargs: types.SimpleNamespace(
                        is_available=lambda: False
                    )
                ),
                "utils.pattern_event_mappings": types.SimpleNamespace(
                    get_all_patterns=lambda: {"pattern-11": {"name": "Pattern Eleven"}},
                    get_patterns_by_ids=lambda _ids: {"pattern-11": {"name": "Pattern Eleven"}},
                ),
            }

            result = None
            with patch.dict(sys.modules, runtime_modules):
                result = rag_tasks.ai_pattern_correlation(
                    types.SimpleNamespace(update_state=lambda **kwargs: None),
                    case_id=11,
                    case_uuid="case-11",
                    patterns=["pattern-11"],
                )

            self.assertTrue(result["success"])
            self.assertEqual(recorded["iteration_pattern_id"], "pattern-11")
            self.assertEqual(
                recorded["finalize_kwargs"]["extraction_stats"],
                {"pattern-11": {"total_stored": 3}},
            )
            self.assertEqual(
                recorded["finalize_kwargs"]["errors"],
                [{"pattern_id": "pattern-11", "error": "boom"}],
            )
        finally:
            restore_modules()


if __name__ == "__main__":
    unittest.main()
