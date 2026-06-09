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

    def test_ai_pattern_task_uses_shared_tail_helper(self):
        rag_tasks, restore_modules = load_rag_tasks_with_stubs(
            "phase7_pattern_task_log_rag_task_under_test"
        )
        try:
            recorded = {"states": []}

            fake_pattern_analysis = types.ModuleType("pipeline.pattern_analysis")

            def complete_task_ai_pattern_run(**kwargs):
                recorded["complete_kwargs"] = kwargs
                kwargs["progress_callback"]({"progress": 100, "status": "done"})
                return {"wrapped": True, "payload": kwargs["response_payload"]}

            fake_pattern_analysis.build_task_ai_pattern_completion_meta = lambda **kwargs: kwargs
            fake_pattern_analysis.build_task_ai_pattern_progress_meta = lambda **kwargs: kwargs
            fake_pattern_analysis.cleanup_task_pattern_extractor = lambda *args, **kwargs: None
            fake_pattern_analysis.complete_task_ai_pattern_run = complete_task_ai_pattern_run
            fake_pattern_analysis.create_candidate_extractor = lambda *args, **kwargs: object()
            fake_pattern_analysis.create_evidence_engine = lambda *args, **kwargs: object()
            fake_pattern_analysis.finalize_task_ai_pattern_results = lambda **kwargs: {
                "success": True,
                "patterns_analyzed": len(kwargs["pattern_configs"]),
                "results_count": len(kwargs["all_results"]),
            }
            fake_pattern_analysis.log_task_ai_pattern_completion = lambda *args, **kwargs: None
            fake_pattern_analysis.run_pattern_census = lambda case_id, **kwargs: {"4624": case_id}
            fake_pattern_analysis.PatternRunContext = lambda **kwargs: types.SimpleNamespace(**kwargs)
            fake_pattern_analysis.run_pattern_iteration = lambda ctx, pattern_id, pattern_config: {
                "extraction_stats": {"total_stored": 0},
                "skipped": True,
                "analysis_stats": None,
                "error": None,
            }

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
                    get_all_patterns=lambda: {"pattern-14": {"name": "Pattern Fourteen"}},
                    get_patterns_by_ids=lambda _ids: {"pattern-14": {"name": "Pattern Fourteen"}},
                ),
            }

            task_self = types.SimpleNamespace(update_state=lambda **kwargs: recorded["states"].append(kwargs))
            with patch.dict(sys.modules, runtime_modules):
                result = rag_tasks.ai_pattern_correlation(
                    task_self,
                    case_id=14,
                    case_uuid="case-14",
                    patterns=["pattern-14"],
                )

            self.assertTrue(result["wrapped"])
            self.assertEqual(recorded["complete_kwargs"]["error_count"], 0)
            self.assertEqual(recorded["complete_kwargs"]["response_payload"]["success"], True)
            self.assertTrue(
                any(state["meta"].get("progress") == 100 for state in recorded["states"])
            )
        finally:
            restore_modules()


if __name__ == "__main__":
    unittest.main()
