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


class Phase7PatternProcessingStageTestCase(unittest.TestCase):
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
            "phase7_pattern_processing_under_test",
            "/opt/casescope/pipeline/pattern_analysis.py",
        )
        return pattern_analysis, restore_modules

    def test_process_ai_pattern_packages_filters_and_materializes(self):
        pattern_analysis, restore_modules = self._load_pattern_analysis_module()
        try:
            recorded = {
                "suppression_calls": [],
                "materialization_calls": [],
                "events": [],
                "full_calls": [],
                "light_calls": [],
            }

            kept_package = types.SimpleNamespace(correlation_key="alpha")
            downranked_package = types.SimpleNamespace(correlation_key="bravo")
            suppressed_package = types.SimpleNamespace(correlation_key="charlie")

            def fake_apply_pattern_suppression(pattern_id, package, confirmed_patterns):
                recorded["suppression_calls"].append((pattern_id, package.correlation_key))
                if package is suppressed_package:
                    return {
                        "suppressed": True,
                        "suppressor": "higher-pattern",
                        "soft_adjustment": 0,
                        "package": package,
                    }
                if package is downranked_package:
                    return {
                        "suppressed": False,
                        "suppressor": None,
                        "soft_adjustment": 15,
                        "package": package,
                    }
                return {
                    "suppressed": False,
                    "suppressor": None,
                    "soft_adjustment": 0,
                    "package": package,
                }

            def fake_materialize_pattern_package(**kwargs):
                package = kwargs["package"]
                recorded["materialization_calls"].append(package.correlation_key)
                return {
                    "result_record": f"record:{package.correlation_key}",
                    "finding": {"pattern_id": kwargs["pattern_id"], "correlation_key": package.correlation_key},
                    "should_emit_finding": package is not downranked_package,
                    "confirmed_pattern_entry": {"correlation_key": package.correlation_key},
                }

            original_apply = pattern_analysis.apply_pattern_suppression
            original_materialize = pattern_analysis.materialize_pattern_package
            pattern_analysis.apply_pattern_suppression = fake_apply_pattern_suppression
            pattern_analysis.materialize_pattern_package = fake_materialize_pattern_package
            try:
                result = pattern_analysis.process_ai_pattern_packages(
                    case_id=17,
                    analysis_id="analysis-9",
                    pattern_id="pattern-9",
                    pattern_name="Pattern Nine",
                    pattern_config={"name": "Pattern Nine"},
                    extraction_result={"anchor_count": 3},
                    evidence_packages=[kept_package, downranked_package, suppressed_package],
                    confirmed_patterns={"higher-pattern": [{"score": 90}]},
                    ai_full_threshold=40,
                    ai_gray_threshold=30,
                    run_full_analysis_for_package=lambda package: recorded["full_calls"].append(package.correlation_key),
                    run_light_analysis_for_package=lambda package: recorded["light_calls"].append(package.correlation_key),
                    extra_finding_fields_for_package=lambda package: {"key": package.correlation_key},
                    event_callback=lambda event, package, detail: recorded["events"].append(
                        (event, package.correlation_key, detail)
                    ),
                )
            finally:
                pattern_analysis.apply_pattern_suppression = original_apply
                pattern_analysis.materialize_pattern_package = original_materialize

            self.assertEqual(
                recorded["suppression_calls"],
                [("pattern-9", "alpha"), ("pattern-9", "bravo"), ("pattern-9", "charlie")],
            )
            self.assertEqual(recorded["materialization_calls"], ["alpha", "bravo"])
            self.assertEqual(
                recorded["events"],
                [("downranked", "bravo", 15), ("suppressed", "charlie", "higher-pattern")],
            )
            self.assertEqual(result["result_records"], ["record:alpha", "record:bravo"])
            self.assertEqual(result["findings"], [{"pattern_id": "pattern-9", "correlation_key": "alpha"}])
            self.assertEqual(
                result["confirmed_pattern_entries"],
                [{"correlation_key": "alpha"}, {"correlation_key": "bravo"}],
            )
        finally:
            restore_modules()

    def test_pattern_callers_use_shared_processing_helper(self):
        case_analyzer_source = Path("/opt/casescope/utils/case_analyzer.py").read_text()
        rag_tasks_source = Path("/opt/casescope/tasks/rag_tasks.py").read_text()

        self.assertIn("execute_case_ai_pattern,", case_analyzer_source)
        self.assertIn("execute_case_ai_pattern(", case_analyzer_source)
        self.assertNotIn("for pkg in evidence_packages:", case_analyzer_source)

        self.assertIn("from pipeline.pattern_analysis import (", rag_tasks_source)
        self.assertIn("run_task_ai_pattern_iteration,", rag_tasks_source)
        self.assertIn("iteration_result = run_task_ai_pattern_iteration(", rag_tasks_source)
        self.assertNotIn("for pkg in evidence_packages:", rag_tasks_source)


if __name__ == "__main__":
    unittest.main()
