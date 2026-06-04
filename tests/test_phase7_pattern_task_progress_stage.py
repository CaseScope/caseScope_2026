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

    def test_ai_pattern_task_uses_shared_progress_helper_at_runtime(self):
        rag_tasks, restore_modules = load_rag_tasks_with_stubs(
            "phase7_pattern_task_progress_rag_task_under_test"
        )
        try:
            recorded = {"states": []}

            fake_pattern_analysis = types.ModuleType("pipeline.pattern_analysis")

            def build_task_ai_pattern_progress_meta(**kwargs):
                recorded["progress_kwargs"] = kwargs
                return {
                    "progress": 42,
                    "status": f"Analyzing {kwargs['pattern_name']}",
                    "stage": "analysis",
                    "pattern": kwargs["pattern_id"],
                }

            fake_pattern_analysis.build_task_ai_pattern_progress_meta = (
                build_task_ai_pattern_progress_meta
            )
            fake_pattern_analysis.build_task_ai_pattern_completion_meta = lambda **kwargs: kwargs
            fake_pattern_analysis.cleanup_task_pattern_extractor = lambda *args, **kwargs: None
            fake_pattern_analysis.complete_task_ai_pattern_run = lambda **kwargs: kwargs[
                "response_payload"
            ]
            fake_pattern_analysis.create_candidate_extractor = lambda *args, **kwargs: object()
            fake_pattern_analysis.create_evidence_engine = lambda *args, **kwargs: object()
            fake_pattern_analysis.finalize_task_ai_pattern_results = lambda **kwargs: {
                "success": True,
                "patterns_analyzed": len(kwargs["pattern_configs"]),
                "results_count": len(kwargs["all_results"]),
            }
            fake_pattern_analysis.log_task_ai_pattern_completion = lambda *args, **kwargs: None
            fake_pattern_analysis.run_pattern_census = lambda case_id, **kwargs: {"4624": case_id}
            fake_pattern_analysis.run_task_ai_pattern_iteration = lambda **kwargs: {
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
                    get_all_patterns=lambda: {"pattern-16": {"name": "Pattern Sixteen"}},
                    get_patterns_by_ids=lambda _ids: {"pattern-16": {"name": "Pattern Sixteen"}},
                ),
            }

            task_self = types.SimpleNamespace(
                update_state=lambda **kwargs: recorded["states"].append(kwargs)
            )
            with patch.dict(sys.modules, runtime_modules):
                result = rag_tasks.ai_pattern_correlation(
                    task_self,
                    case_id=16,
                    case_uuid="case-16",
                    patterns=["pattern-16"],
                )

            self.assertTrue(result["success"])
            self.assertEqual(
                recorded["progress_kwargs"],
                {
                    "pattern_id": "pattern-16",
                    "pattern_name": "Pattern Sixteen",
                    "pattern_index": 0,
                    "total_patterns": 1,
                },
            )
            self.assertIn(
                {
                    "state": "PROGRESS",
                    "meta": {
                        "progress": 42,
                        "status": "Analyzing Pattern Sixteen",
                        "stage": "analysis",
                        "pattern": "pattern-16",
                    },
                },
                recorded["states"],
            )
        finally:
            restore_modules()


if __name__ == "__main__":
    unittest.main()
