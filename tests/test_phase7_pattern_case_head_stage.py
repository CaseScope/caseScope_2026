import importlib.util
import sys
import types
import unittest
from unittest.mock import patch

from tests.phase7_case_analyzer_loader import load_case_analyzer_with_stubs


def _load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class Phase7PatternCaseHeadStageTestCase(unittest.TestCase):
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
            "phase7_pattern_case_head_under_test",
            "/opt/casescope/pipeline/pattern_analysis.py",
        )
        return pattern_analysis, restore_modules

    def test_prepare_case_pattern_head_short_circuits_when_no_patterns(self):
        pattern_analysis, restore_modules = self._load_pattern_analysis_module()
        try:
            progress = []
            pattern_analysis.prepare_pattern_analysis = lambda case_id: {
                "patterns": {},
                "census": {"1": 1},
                "ordered_patterns": [],
                "skipped_count": 0,
            }

            result = pattern_analysis.prepare_case_pattern_head(
                case_id=5,
                progress_callback=lambda phase, percent, message: progress.append(
                    (phase, percent, message)
                ),
            )

            self.assertTrue(result["should_return"])
            self.assertEqual(result["pattern_total"], 0)
            self.assertEqual(result["pattern_count"], 0)
            self.assertEqual(progress, [("pattern_analysis", 85, "No patterns to analyze")])
        finally:
            restore_modules()

    def test_prepare_case_pattern_head_emits_census_messages_and_keeps_running(self):
        pattern_analysis, restore_modules = self._load_pattern_analysis_module()
        try:
            progress = []
            info = []
            pattern_analysis.prepare_pattern_analysis = lambda case_id: {
                "patterns": {"a": {"name": "A"}, "b": {"name": "B"}},
                "census": {"1001": 2},
                "ordered_patterns": [("a", {"name": "A"})],
                "skipped_count": 1,
            }

            result = pattern_analysis.prepare_case_pattern_head(
                case_id=6,
                progress_callback=lambda phase, percent, message: progress.append(
                    (phase, percent, message)
                ),
                info_callback=info.append,
            )

            self.assertFalse(result["should_return"])
            self.assertEqual(result["census"], {"1001": 2})
            self.assertEqual(result["ordered_patterns"], [("a", {"name": "A"})])
            self.assertEqual(result["pattern_total"], 2)
            self.assertEqual(result["pattern_count"], 1)
            self.assertEqual(
                progress,
                [
                    ("pattern_analysis", 51, "Running event census..."),
                    ("pattern_analysis", 52, "Analyzing 1 patterns (1 skipped by census)..."),
                ],
            )
            self.assertEqual(
                info,
                ["[CaseAnalyzer] Census filter: 1/2 patterns eligible (1 skipped — anchor events not in case)"],
            )
        finally:
            restore_modules()

    def test_case_analyzer_run_pattern_analysis_delegates_to_shared_phase_helpers(self):
        case_analyzer, restore_modules = load_case_analyzer_with_stubs(
            "phase7_case_head_case_analyzer_under_test"
        )
        try:
            analyzer = case_analyzer.CaseAnalyzer(case_id=31, progress_callback=None, parallel=False)
            analyzer.analysis_id = "analysis-31"
            analyzer.mode = "B"
            analyzer._gap_findings = ["gap-1"]

            recorded = {}
            extractor = object()
            evidence_engine = object()
            ai_analyzer = object()

            fake_pattern_analysis = types.ModuleType("pipeline.pattern_analysis")

            def prepare_case_pattern_head(**kwargs):
                recorded["head_kwargs"] = kwargs
                return {
                    "should_return": False,
                    "census": {"4624": 2},
                    "ordered_patterns": [("pattern-1", {"name": "Pattern One"})],
                    "pattern_total": 2,
                    "pattern_count": 1,
                    "skipped_count": 1,
                }

            def prepare_case_pattern_runtime(**kwargs):
                recorded["runtime_kwargs"] = kwargs
                return {
                    "extractor": extractor,
                    "evidence_engine": evidence_engine,
                    "ai_analyzer": ai_analyzer,
                    "rule_analyzer": None,
                    "confirmed_patterns": {"existing": []},
                }

            def run_case_pattern_loop(**kwargs):
                recorded["loop_kwargs"] = kwargs
                kwargs["findings_output"].append({"pattern_id": "pattern-1"})

            def complete_case_pattern_run(**kwargs):
                recorded["complete_kwargs"] = kwargs
                return list(kwargs["results"])

            fake_pattern_analysis.prepare_case_pattern_head = prepare_case_pattern_head
            fake_pattern_analysis.prepare_case_pattern_runtime = prepare_case_pattern_runtime
            fake_pattern_analysis.run_case_pattern_loop = run_case_pattern_loop
            fake_pattern_analysis.complete_case_pattern_run = complete_case_pattern_run

            original_query = case_analyzer.Case.query
            case_analyzer.Case.query = types.SimpleNamespace(
                get=lambda _case_id: types.SimpleNamespace(timezone="America/Chicago")
            )
            try:
                with patch.dict(sys.modules, {"pipeline.pattern_analysis": fake_pattern_analysis}):
                    result = analyzer._run_pattern_analysis([])
            finally:
                case_analyzer.Case.query = original_query

            self.assertEqual(result, [{"pattern_id": "pattern-1"}])
            self.assertEqual(recorded["head_kwargs"]["case_id"], 31)
            self.assertEqual(
                recorded["runtime_kwargs"],
                {
                    "case_id": 31,
                    "analysis_id": "analysis-31",
                    "mode": "B",
                    "census": {"4624": 2},
                    "gap_findings": ["gap-1"],
                    "case_tz": "America/Chicago",
                },
            )
            self.assertEqual(
                recorded["loop_kwargs"]["ordered_patterns"],
                [("pattern-1", {"name": "Pattern One"})],
            )
            self.assertIs(recorded["loop_kwargs"]["extractor"], extractor)
            self.assertIs(recorded["loop_kwargs"]["evidence_engine"], evidence_engine)
            self.assertIs(recorded["loop_kwargs"]["ai_analyzer"], ai_analyzer)
            self.assertEqual(
                recorded["complete_kwargs"]["results"],
                [{"pattern_id": "pattern-1"}],
            )
        finally:
            restore_modules()


if __name__ == "__main__":
    unittest.main()
