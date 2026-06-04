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


class Phase7PatternTaskCleanupStageTestCase(unittest.TestCase):
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
            "phase7_pattern_task_cleanup_under_test",
            "/opt/casescope/pipeline/pattern_analysis.py",
        )
        return pattern_analysis, restore_modules

    def test_cleanup_task_pattern_extractor_runs_cleanup(self):
        pattern_analysis, restore_modules = self._load_pattern_analysis_module()
        try:
            recorded = {"cleaned": False}

            class FakeExtractor:
                def cleanup(self):
                    recorded["cleaned"] = True

            pattern_analysis.cleanup_task_pattern_extractor(FakeExtractor())
            self.assertTrue(recorded["cleaned"])
        finally:
            restore_modules()

    def test_cleanup_task_pattern_extractor_reports_warning(self):
        pattern_analysis, restore_modules = self._load_pattern_analysis_module()
        try:
            warnings = []

            class BrokenExtractor:
                def cleanup(self):
                    raise RuntimeError("cleanup failed")

            pattern_analysis.cleanup_task_pattern_extractor(
                BrokenExtractor(),
                warning_callback=warnings.append,
            )
            self.assertEqual(warnings, ["cleanup failed"])
        finally:
            restore_modules()

    def test_ai_pattern_task_uses_shared_cleanup_helper_at_runtime(self):
        rag_tasks, restore_modules = load_rag_tasks_with_stubs(
            "phase7_pattern_task_cleanup_rag_task_under_test"
        )
        try:
            recorded = {}
            extractor = object()

            fake_pattern_analysis = types.ModuleType("pipeline.pattern_analysis")

            def cleanup_task_pattern_extractor(received_extractor, **kwargs):
                recorded["cleanup"] = {
                    "extractor": received_extractor,
                    "warning_callback": kwargs.get("warning_callback"),
                }

            fake_pattern_analysis.build_task_ai_pattern_completion_meta = lambda **kwargs: kwargs
            fake_pattern_analysis.build_task_ai_pattern_progress_meta = lambda **kwargs: kwargs
            fake_pattern_analysis.cleanup_task_pattern_extractor = cleanup_task_pattern_extractor
            fake_pattern_analysis.complete_task_ai_pattern_run = lambda **kwargs: kwargs[
                "response_payload"
            ]
            fake_pattern_analysis.create_candidate_extractor = lambda *args, **kwargs: extractor
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
                    get_all_patterns=lambda: {"pattern-17": {"name": "Pattern Seventeen"}},
                    get_patterns_by_ids=lambda _ids: {"pattern-17": {"name": "Pattern Seventeen"}},
                ),
            }

            with patch.dict(sys.modules, runtime_modules):
                result = rag_tasks.ai_pattern_correlation(
                    types.SimpleNamespace(update_state=lambda **kwargs: None),
                    case_id=17,
                    case_uuid="case-17",
                    patterns=["pattern-17"],
                )

            self.assertTrue(result["success"])
            self.assertIs(recorded["cleanup"]["extractor"], extractor)
            self.assertTrue(callable(recorded["cleanup"]["warning_callback"]))
        finally:
            restore_modules()


if __name__ == "__main__":
    unittest.main()
