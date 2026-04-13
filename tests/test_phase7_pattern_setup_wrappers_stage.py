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


class Phase7PatternSetupWrappersStageTestCase(unittest.TestCase):
    def _load_pattern_analysis_module(self):
        fake_utils = types.ModuleType("utils")
        fake_utils.__path__ = []
        fake_candidate_extractor = types.ModuleType("utils.candidate_extractor")
        fake_evidence_engine = types.ModuleType("utils.deterministic_evidence_engine")
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
            def __init__(self, *, case_id, analysis_id, census=None, gap_findings=None):
                recorded["engine_inits"].append(
                    {
                        "case_id": case_id,
                        "analysis_id": analysis_id,
                        "census": census,
                        "gap_findings": gap_findings,
                    }
                )
                self.case_id = case_id
                self.analysis_id = analysis_id
                self.census = census
                self.gap_findings = gap_findings

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
        fake_pattern_suppression.PATTERN_SUPPRESSION_PRIORITY = {}
        fake_pattern_suppression.get_pattern_suppression_matches = lambda *args, **kwargs: []
        fake_clickhouse.get_fresh_client = lambda: FakeClient()

        previous_modules = {
            name: sys.modules.get(name)
            for name in [
                "utils",
                "utils.candidate_extractor",
                "utils.deterministic_evidence_engine",
                "utils.pattern_suppression",
                "utils.clickhouse",
            ]
        }
        sys.modules["utils"] = fake_utils
        sys.modules["utils.candidate_extractor"] = fake_candidate_extractor
        sys.modules["utils.deterministic_evidence_engine"] = fake_evidence_engine
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
                    }
                ],
            )

            self.assertEqual(census, {"4624": 7, "4625": 3})
            self.assertEqual(recorded["query_calls"][0]["parameters"], {"case_id": 15})
        finally:
            restore_modules()

    def test_rag_task_uses_shared_pattern_setup_wrappers(self):
        source = Path("/opt/casescope/tasks/rag_tasks.py").read_text()

        self.assertIn("from pipeline.pattern_analysis import (", source)
        self.assertIn("create_candidate_extractor,", source)
        self.assertIn("create_evidence_engine,", source)
        self.assertIn("run_pattern_census,", source)
        self.assertIn("extractor = create_candidate_extractor(case_id, analysis_id)", source)
        self.assertIn("census = run_pattern_census(case_id)", source)
        self.assertIn("evidence_engine = create_evidence_engine(", source)
        self.assertNotIn("from utils.candidate_extractor import CandidateExtractor", source)
        self.assertNotIn("from utils.deterministic_evidence_engine import DeterministicEvidenceEngine", source)


if __name__ == "__main__":
    unittest.main()
