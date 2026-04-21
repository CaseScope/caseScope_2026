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
                evidence_engine=None,
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
                evidence_engine=None,
            )

            self.assertTrue(result["should_skip"])
            self.assertEqual(result["anchor_events"], [])
        finally:
            restore_modules()

    def test_prepare_task_ai_pattern_inputs_uses_gap_only_anchors(self):
        pattern_analysis, restore_modules = self._load_pattern_analysis_module()
        try:
            class FakeExtractor:
                def extract_pattern_candidates(self, **kwargs):
                    raise AssertionError("gap-only patterns should not hit extractor")

            class FakeEvidenceEngine:
                def build_gap_only_anchor_events(self, pattern_id):
                    self.pattern_id = pattern_id
                    return [{"gap_finding_id": 77}]

            engine = FakeEvidenceEngine()
            result = pattern_analysis.prepare_task_ai_pattern_inputs(
                extractor=FakeExtractor(),
                pattern_config={
                    "id": "behavioral_volume_spike",
                    "name": "Behavioral Volume Spike",
                    "gap_only": True,
                },
                evidence_engine=engine,
            )

            self.assertEqual(engine.pattern_id, "behavioral_volume_spike")
            self.assertFalse(result["should_skip"])
            self.assertEqual(result["anchor_events"], [{"gap_finding_id": 77}])
            self.assertEqual(
                result["extraction_stats"],
                {"anchor_count": 1, "supporting_count": 0, "total_stored": 1},
            )
        finally:
            restore_modules()

    def test_ai_pattern_task_uses_shared_task_extraction_helper(self):
        rag_tasks, restore_modules = load_rag_tasks_with_stubs(
            "phase7_pattern_task_extraction_rag_task_under_test"
        )
        try:
            recorded = {}
            extractor = types.SimpleNamespace(
                extract_pattern_candidates=lambda **kwargs: (_ for _ in ()).throw(
                    AssertionError("rag task should delegate extraction through helper")
                )
            )

            fake_pattern_analysis = types.ModuleType("pipeline.pattern_analysis")

            def create_candidate_extractor(case_id, analysis_id):
                recorded["extractor_init"] = {
                    "case_id": case_id,
                    "analysis_id": analysis_id,
                }
                return extractor

            def run_task_ai_pattern_iteration(**kwargs):
                recorded["iteration_kwargs"] = kwargs
                return {
                    "extraction_stats": {"total_stored": 1},
                    "skipped": True,
                    "analysis_stats": None,
                    "error": None,
                }

            fake_pattern_analysis.build_task_ai_pattern_completion_meta = lambda **kwargs: kwargs
            fake_pattern_analysis.build_task_ai_pattern_progress_meta = lambda **kwargs: kwargs
            fake_pattern_analysis.cleanup_task_pattern_extractor = lambda *args, **kwargs: None
            fake_pattern_analysis.complete_task_ai_pattern_run = lambda **kwargs: kwargs["response_payload"]
            fake_pattern_analysis.create_candidate_extractor = create_candidate_extractor
            fake_pattern_analysis.create_evidence_engine = lambda *args, **kwargs: object()
            fake_pattern_analysis.finalize_task_ai_pattern_results = lambda **kwargs: {
                "success": True,
                "patterns_analyzed": len(kwargs["pattern_configs"]),
                "results_count": len(kwargs["all_results"]),
            }
            fake_pattern_analysis.log_task_ai_pattern_completion = lambda *args, **kwargs: None
            fake_pattern_analysis.run_pattern_census = lambda case_id: {"4624": case_id}
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
                    get_all_patterns=lambda: {"pattern-12": {"name": "Pattern Twelve"}},
                    get_patterns_by_ids=lambda _ids: {"pattern-12": {"name": "Pattern Twelve"}},
                ),
            }

            with patch.dict(sys.modules, runtime_modules):
                result = rag_tasks.ai_pattern_correlation(
                    types.SimpleNamespace(update_state=lambda **kwargs: None),
                    case_id=12,
                    case_uuid="case-12",
                    patterns=["pattern-12"],
                )

            self.assertTrue(result["success"])
            self.assertEqual(recorded["extractor_init"]["case_id"], 12)
            self.assertIs(recorded["iteration_kwargs"]["extractor"], extractor)
            self.assertEqual(recorded["iteration_kwargs"]["case_id"], 12)
            self.assertEqual(recorded["iteration_kwargs"]["pattern_id"], "pattern-12")
        finally:
            restore_modules()


if __name__ == "__main__":
    unittest.main()
