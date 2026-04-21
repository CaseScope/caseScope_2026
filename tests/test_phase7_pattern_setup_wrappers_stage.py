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


class Phase7PatternSetupWrappersStageTestCase(unittest.TestCase):
    def _load_pattern_analysis_module(self):
        fake_utils = types.ModuleType("utils")
        fake_utils.__path__ = []
        fake_candidate_extractor = types.ModuleType("utils.candidate_extractor")
        fake_evidence_engine = types.ModuleType("utils.deterministic_evidence_engine")
        fake_event_noise_state = types.ModuleType("utils.event_noise_state")
        fake_pattern_suppression = types.ModuleType("utils.pattern_suppression")
        fake_clickhouse = types.ModuleType("utils.clickhouse")

        recorded = {
            "extractor_inits": [],
            "engine_inits": [],
            "query_calls": [],
        }

        class FakeCandidateExtractor:
            def __init__(self, *, case_id, analysis_id=None):
                recorded["extractor_inits"].append(
                    {"case_id": case_id, "analysis_id": analysis_id}
                )
                self.case_id = case_id
                self.analysis_id = analysis_id

        class FakeEvidenceEngine:
            def __init__(self, *, case_id, analysis_id, census=None, gap_findings=None, case_tz='UTC'):
                recorded["engine_inits"].append(
                    {
                        "case_id": case_id,
                        "analysis_id": analysis_id,
                        "census": census,
                        "gap_findings": gap_findings,
                        "case_tz": case_tz,
                    }
                )
                self.case_id = case_id
                self.analysis_id = analysis_id
                self.census = census
                self.gap_findings = gap_findings
                self.case_tz = case_tz

        class FakeQueryResult:
            result_rows = [(4624, 7), (4625, 3)]

        class FakeClient:
            def query(self, sql, parameters):
                recorded["query_calls"].append(
                    {"sql": sql, "parameters": parameters}
                )
                return FakeQueryResult()

        fake_candidate_extractor.CandidateExtractor = FakeCandidateExtractor
        fake_evidence_engine.DeterministicEvidenceEngine = FakeEvidenceEngine
        fake_event_noise_state.build_effective_not_noise_clause = lambda *args, **kwargs: "1"
        fake_event_noise_state.ensure_event_noise_state_tables = lambda *args, **kwargs: None
        fake_pattern_suppression.PATTERN_SUPPRESSION_PRIORITY = {}
        fake_pattern_suppression.get_pattern_suppression_matches = lambda *args, **kwargs: []
        fake_clickhouse.get_fresh_client = lambda: FakeClient()

        previous_modules = {
            name: sys.modules.get(name)
            for name in [
                "utils",
                "utils.candidate_extractor",
                "utils.deterministic_evidence_engine",
                "utils.event_noise_state",
                "utils.pattern_suppression",
                "utils.clickhouse",
            ]
        }
        sys.modules["utils"] = fake_utils
        sys.modules["utils.candidate_extractor"] = fake_candidate_extractor
        sys.modules["utils.deterministic_evidence_engine"] = fake_evidence_engine
        sys.modules["utils.event_noise_state"] = fake_event_noise_state
        sys.modules["utils.pattern_suppression"] = fake_pattern_suppression
        sys.modules["utils.clickhouse"] = fake_clickhouse

        def restore_modules():
            for name, previous in previous_modules.items():
                if previous is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = previous

        pattern_analysis = _load_module(
            "phase7_pattern_setup_wrappers_under_test",
            "/opt/casescope/pipeline/pattern_analysis.py",
        )
        return pattern_analysis, recorded, restore_modules

    def test_setup_wrappers_delegate_to_shared_dependencies(self):
        pattern_analysis, recorded, restore_modules = self._load_pattern_analysis_module()
        try:
            extractor = pattern_analysis.create_candidate_extractor(15, "analysis-15")
            engine = pattern_analysis.create_evidence_engine(
                15,
                "analysis-15",
                census={"4624": 7},
                gap_findings=["gap-1"],
                case_tz="America/Chicago",
            )
            census = pattern_analysis.run_pattern_census(15)

            self.assertEqual(extractor.case_id, 15)
            self.assertEqual(extractor.analysis_id, "analysis-15")
            self.assertEqual(
                recorded["extractor_inits"],
                [{"case_id": 15, "analysis_id": "analysis-15"}],
            )

            self.assertEqual(engine.case_id, 15)
            self.assertEqual(engine.analysis_id, "analysis-15")
            self.assertEqual(
                recorded["engine_inits"],
                [
                    {
                        "case_id": 15,
                        "analysis_id": "analysis-15",
                        "census": {"4624": 7},
                        "gap_findings": ["gap-1"],
                        "case_tz": "America/Chicago",
                    }
                ],
            )

            self.assertEqual(census, {"4624": 7, "4625": 3})
            self.assertEqual(recorded["query_calls"][0]["parameters"], {"case_id": 15})
        finally:
            restore_modules()

    def test_ai_pattern_task_uses_shared_pattern_setup_wrappers(self):
        rag_tasks, restore_modules = load_rag_tasks_with_stubs(
            "phase7_pattern_setup_wrappers_rag_task_under_test"
        )
        try:
            recorded = {}

            fake_pattern_analysis = types.ModuleType("pipeline.pattern_analysis")

            def create_candidate_extractor(case_id, analysis_id):
                recorded["extractor"] = {
                    "case_id": case_id,
                    "analysis_id": analysis_id,
                }
                return object()

            def run_pattern_census(case_id):
                recorded["census_case_id"] = case_id
                return {"4624": 7}

            def create_evidence_engine(case_id, analysis_id, census=None, gap_findings=None):
                recorded["engine"] = {
                    "case_id": case_id,
                    "analysis_id": analysis_id,
                    "census": census,
                    "gap_findings": gap_findings,
                }
                return object()

            fake_pattern_analysis.build_task_ai_pattern_completion_meta = lambda **kwargs: kwargs
            fake_pattern_analysis.build_task_ai_pattern_progress_meta = lambda **kwargs: kwargs
            fake_pattern_analysis.cleanup_task_pattern_extractor = lambda *args, **kwargs: None
            fake_pattern_analysis.complete_task_ai_pattern_run = lambda **kwargs: kwargs["response_payload"]
            fake_pattern_analysis.create_candidate_extractor = create_candidate_extractor
            fake_pattern_analysis.create_evidence_engine = create_evidence_engine
            fake_pattern_analysis.finalize_task_ai_pattern_results = lambda **kwargs: {
                "success": True,
                "patterns_analyzed": len(kwargs["pattern_configs"]),
                "results_count": len(kwargs["all_results"]),
            }
            fake_pattern_analysis.log_task_ai_pattern_completion = lambda *args, **kwargs: None
            fake_pattern_analysis.run_pattern_census = run_pattern_census
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
                    recorded["analyzer"] = {
                        "case_id": case_id,
                        "analysis_id": analysis_id,
                    }
                    self.model = "fake-model"

                def analyze_with_evidence(self, package, pattern_config):
                    return {"package": package, "pattern_config": pattern_config}

                def analyze_with_evidence_lightweight(self, package, pattern_config):
                    return {"package": package, "mode": "light", "pattern_config": pattern_config}

                def get_stats(self):
                    return {"calls": 0}

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
                    get_all_patterns=lambda: {"pattern-15": {"name": "Pattern Fifteen"}},
                    get_patterns_by_ids=lambda _ids: {"pattern-15": {"name": "Pattern Fifteen"}},
                ),
            }

            with patch.dict(sys.modules, runtime_modules):
                result = rag_tasks.ai_pattern_correlation(
                    types.SimpleNamespace(update_state=lambda **kwargs: None),
                    case_id=15,
                    case_uuid="case-15",
                    patterns=["pattern-15"],
                )

            self.assertTrue(result["success"])
            self.assertEqual(recorded["extractor"]["case_id"], 15)
            self.assertEqual(recorded["census_case_id"], 15)
            self.assertEqual(recorded["engine"]["case_id"], 15)
            self.assertEqual(recorded["engine"]["census"], {"4624": 7})
            self.assertEqual(recorded["engine"]["gap_findings"], [])
            self.assertEqual(
                recorded["extractor"]["analysis_id"],
                recorded["engine"]["analysis_id"],
            )
            self.assertEqual(
                recorded["analyzer"]["analysis_id"],
                recorded["engine"]["analysis_id"],
            )
        finally:
            restore_modules()


if __name__ == "__main__":
    unittest.main()
