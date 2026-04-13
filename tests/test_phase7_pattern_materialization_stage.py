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


class Phase7PatternMaterializationStageTestCase(unittest.TestCase):
    def _load_pattern_analysis_module(self):
        fake_utils = types.ModuleType("utils")
        fake_utils.__path__ = []
        fake_candidate_extractor = types.ModuleType("utils.candidate_extractor")
        fake_evidence_engine = types.ModuleType("utils.deterministic_evidence_engine")
        fake_pattern_suppression = types.ModuleType("utils.pattern_suppression")
        fake_analysis_summary = types.ModuleType("utils.analysis_summary")
        fake_finding_contract = types.ModuleType("utils.finding_contract")
        fake_models = types.ModuleType("models")
        fake_models.__path__ = []
        fake_models_rag = types.ModuleType("models.rag")

        recorded = {
            "finalize_calls": [],
            "artifact_calls": [],
            "confirmed_calls": [],
        }

        fake_candidate_extractor.CandidateExtractor = object
        fake_evidence_engine.DeterministicEvidenceEngine = object
        fake_pattern_suppression.PATTERN_SUPPRESSION_PRIORITY = {}
        fake_pattern_suppression.get_pattern_suppression_matches = lambda *args, **kwargs: []

        def fake_build_confirmed_pattern_entry(*, correlation_key, score, anchor=None):
            recorded["confirmed_calls"].append(
                {
                    "correlation_key": correlation_key,
                    "score": score,
                    "anchor": anchor,
                }
            )
            return {
                "correlation_key": correlation_key,
                "score": score,
                "anchor": anchor,
            }

        def fake_severity_from_confidence(score):
            return "high" if score >= 70 else "medium"

        def fake_finalize_deterministic_package(
            package,
            *,
            ai_full_threshold,
            ai_gray_threshold,
            run_full_analysis,
            run_light_analysis,
        ):
            recorded["finalize_calls"].append(
                {
                    "package": package,
                    "ai_full_threshold": ai_full_threshold,
                    "ai_gray_threshold": ai_gray_threshold,
                }
            )
            return {
                "final_score": 88,
                "ai_adjustment": 12,
                "evidence_package": {"package": package.correlation_key},
                "ai_reasoning": "reasoned",
                "ai_false_positive_assessment": "unlikely",
                "should_emit_finding": True,
            }

        def fake_build_deterministic_analysis_artifacts(**kwargs):
            recorded["artifact_calls"].append(kwargs)
            return {
                "analysis_result_payload": {
                    "pattern_id": kwargs["pattern_id"],
                    "confidence": kwargs["confidence"],
                    "model_used": kwargs["model_used"],
                },
                "finding": {
                    "pattern_id": kwargs["pattern_id"],
                    "confidence": kwargs["confidence"],
                },
            }

        class FakeAIAnalysisResult:
            def __init__(self, **kwargs):
                self.payload = kwargs

        fake_pattern_suppression.build_confirmed_pattern_entry = fake_build_confirmed_pattern_entry
        fake_analysis_summary.severity_from_confidence = fake_severity_from_confidence
        fake_finding_contract.finalize_deterministic_package = fake_finalize_deterministic_package
        fake_finding_contract.build_deterministic_analysis_artifacts = (
            fake_build_deterministic_analysis_artifacts
        )
        fake_models_rag.AIAnalysisResult = FakeAIAnalysisResult

        previous_modules = {
            name: sys.modules.get(name)
            for name in [
                "utils",
                "utils.candidate_extractor",
                "utils.deterministic_evidence_engine",
                "utils.pattern_suppression",
                "utils.analysis_summary",
                "utils.finding_contract",
                "models",
                "models.rag",
            ]
        }
        sys.modules["utils"] = fake_utils
        sys.modules["utils.candidate_extractor"] = fake_candidate_extractor
        sys.modules["utils.deterministic_evidence_engine"] = fake_evidence_engine
        sys.modules["utils.pattern_suppression"] = fake_pattern_suppression
        sys.modules["utils.analysis_summary"] = fake_analysis_summary
        sys.modules["utils.finding_contract"] = fake_finding_contract
        sys.modules["models"] = fake_models
        sys.modules["models.rag"] = fake_models_rag

        def restore_modules():
            for name, previous in previous_modules.items():
                if previous is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = previous

        pattern_analysis = _load_module(
            "phase7_pattern_materialization_under_test",
            "/opt/casescope/pipeline/pattern_analysis.py",
        )
        return pattern_analysis, recorded, restore_modules

    def test_materialize_pattern_package_builds_record_and_finding(self):
        pattern_analysis, recorded, restore_modules = self._load_pattern_analysis_module()
        try:
            package = types.SimpleNamespace(
                correlation_key="alpha",
                deterministic_score=76,
                ai_escalated=True,
                ai_judgment=True,
                anchor={"source_host": "host-1"},
                coverage=types.SimpleNamespace(
                    coverage_score=92,
                    window_start="2026-04-13T00:00:00",
                    window_end="2026-04-13T01:00:00",
                ),
            )

            result = pattern_analysis.materialize_pattern_package(
                case_id=7,
                analysis_id="analysis-7",
                pattern_id="pattern-1",
                pattern_name="Pattern One",
                pattern_config={"mitre_techniques": ["T1003"]},
                package=package,
                extraction_result={"anchor_count": 4, "base_confidence": 55},
                ai_full_threshold=40,
                ai_gray_threshold=30,
                run_full_analysis=lambda: {"mode": "full"},
                run_light_analysis=lambda: {"mode": "light"},
                model_name="test-model",
                extra_finding_fields={"overlay_score_adjustment": 5},
            )

            self.assertEqual(recorded["finalize_calls"][0]["ai_full_threshold"], 40)
            self.assertEqual(recorded["artifact_calls"][0]["pattern_name"], "Pattern One")
            self.assertEqual(recorded["artifact_calls"][0]["model_used"], "test-model")
            self.assertEqual(
                recorded["artifact_calls"][0]["extra_finding_fields"],
                {"overlay_score_adjustment": 5},
            )
            self.assertTrue(result["should_emit_finding"])
            self.assertEqual(result["finding"]["confidence"], 88)
            self.assertEqual(result["result_record"].payload["pattern_id"], "pattern-1")
            self.assertEqual(result["confirmed_pattern_entry"]["correlation_key"], "alpha")
        finally:
            restore_modules()

    def test_materialize_pattern_package_falls_back_to_deterministic_model_name(self):
        pattern_analysis, recorded, restore_modules = self._load_pattern_analysis_module()
        try:
            package = types.SimpleNamespace(
                correlation_key="bravo",
                deterministic_score=61,
                ai_escalated=False,
                ai_judgment=False,
                anchor={"source_host": "host-2"},
                coverage=None,
            )

            result = pattern_analysis.materialize_pattern_package(
                case_id=9,
                analysis_id="analysis-8",
                pattern_id="pattern-2",
                pattern_name="Pattern Two",
                pattern_config={},
                package=package,
                extraction_result={"anchor_count": 1},
                ai_full_threshold=50,
                ai_gray_threshold=20,
                run_full_analysis=lambda: {},
                run_light_analysis=lambda: {},
                model_name="unused-model",
            )

            self.assertEqual(recorded["artifact_calls"][0]["model_used"], "deterministic")
            self.assertEqual(result["confirmed_pattern_entry"]["score"], 88)
        finally:
            restore_modules()

    def test_pattern_callers_use_shared_materialization_helper(self):
        case_analyzer_source = Path("/opt/casescope/utils/case_analyzer.py").read_text()
        rag_tasks_source = Path("/opt/casescope/tasks/rag_tasks.py").read_text()

        self.assertIn("process_ai_pattern_packages,", case_analyzer_source)
        self.assertNotIn("materialized = materialize_pattern_package(", case_analyzer_source)
        self.assertNotIn("finalized = finalize_deterministic_package(", case_analyzer_source)

        self.assertIn("process_ai_pattern_packages,", rag_tasks_source)
        self.assertNotIn("materialized = materialize_pattern_package(", rag_tasks_source)
        self.assertNotIn("finalized = finalize_deterministic_package(", rag_tasks_source)


if __name__ == "__main__":
    unittest.main()
