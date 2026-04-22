import importlib.util
import sys
import types
import unittest


def _load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class Phase7PatternPrepStageTestCase(unittest.TestCase):
    def _load_pattern_analysis_module(self, *, census_rows=None, query_error=None, patterns=None):
        fake_utils = types.ModuleType("utils")
        fake_utils.__path__ = []
        fake_candidate_extractor = types.ModuleType("utils.candidate_extractor")
        fake_evidence_engine = types.ModuleType("utils.deterministic_evidence_engine")
        fake_clickhouse = types.ModuleType("utils.clickhouse")
        fake_event_noise_state = types.ModuleType("utils.event_noise_state")
        fake_pattern_mappings = types.ModuleType("utils.pattern_event_mappings")
        fake_pattern_suppression = types.ModuleType("utils.pattern_suppression")

        fake_candidate_extractor.CandidateExtractor = object
        fake_evidence_engine.DeterministicEvidenceEngine = object
        fake_event_noise_state.build_effective_not_noise_clause = (
            lambda *args, **kwargs: "1"
        )
        fake_event_noise_state.ensure_event_noise_state_tables = (
            lambda *args, **kwargs: None
        )
        fake_pattern_suppression.PATTERN_SUPPRESSION_PRIORITY = {
            "pattern-b": 10,
            "pattern-a": 20,
        }
        fake_pattern_suppression.get_pattern_suppression_matches = lambda *args, **kwargs: []

        recorded = {
            "queried_case_ids": [],
        }

        class FakeClient:
            def query(self, sql, parameters=None):
                recorded["queried_case_ids"].append(parameters["case_id"])
                if query_error is not None:
                    raise query_error
                return types.SimpleNamespace(result_rows=census_rows or [])

        def fake_get_fresh_client():
            return FakeClient()

        fake_clickhouse.get_fresh_client = fake_get_fresh_client
        fake_pattern_mappings.PATTERN_EVENT_MAPPINGS = patterns or {
            "pattern-a": {"name": "Zulu Pattern", "anchor_events": [1001]},
            "pattern-b": {"name": "Alpha Pattern", "anchor_events": [2002]},
            "pattern-c": {"name": "No Anchor Pattern"},
        }

        previous_modules = {
            name: sys.modules.get(name)
            for name in [
                "utils",
                "utils.candidate_extractor",
                "utils.deterministic_evidence_engine",
                "utils.clickhouse",
                "utils.event_noise_state",
                "utils.pattern_event_mappings",
                "utils.pattern_suppression",
            ]
        }
        sys.modules["utils"] = fake_utils
        sys.modules["utils.candidate_extractor"] = fake_candidate_extractor
        sys.modules["utils.deterministic_evidence_engine"] = fake_evidence_engine
        sys.modules["utils.clickhouse"] = fake_clickhouse
        sys.modules["utils.event_noise_state"] = fake_event_noise_state
        sys.modules["utils.pattern_event_mappings"] = fake_pattern_mappings
        sys.modules["utils.pattern_suppression"] = fake_pattern_suppression
        def restore_modules():
            for name, previous in previous_modules.items():
                if previous is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = previous
        pattern_analysis = _load_module(
            "phase7_pattern_analysis_under_test",
            "/opt/casescope/pipeline/pattern_analysis.py",
        )
        return pattern_analysis, recorded, restore_modules

    def test_prepare_pattern_analysis_filters_and_orders_patterns(self):
        pattern_analysis, recorded, restore_modules = self._load_pattern_analysis_module(
            census_rows=[(2002, 7)],
        )
        try:
            result = pattern_analysis.prepare_pattern_analysis(case_id=41)

            self.assertEqual(recorded["queried_case_ids"], [41])
            self.assertEqual(result["census"], {"2002": 7})
            self.assertEqual(list(result["runnable_patterns"].keys()), ["pattern-b", "pattern-c"])
            self.assertEqual(
                [pattern_id for pattern_id, _ in result["ordered_patterns"]],
                ["pattern-b", "pattern-c"],
            )
            self.assertEqual(result["skipped_count"], 1)
        finally:
            restore_modules()

    def test_prepare_pattern_analysis_fails_open_when_census_query_fails(self):
        pattern_analysis, recorded, restore_modules = self._load_pattern_analysis_module(
            query_error=RuntimeError("clickhouse unavailable"),
        )
        try:
            result = pattern_analysis.prepare_pattern_analysis(case_id=99)

            self.assertEqual(recorded["queried_case_ids"], [99])
            self.assertEqual(result["census"], {})
            self.assertEqual(len(result["runnable_patterns"]), 3)
            self.assertEqual(
                [pattern_id for pattern_id, _ in result["ordered_patterns"]],
                ["pattern-b", "pattern-a", "pattern-c"],
            )
            self.assertEqual(result["skipped_count"], 0)
        finally:
            restore_modules()

if __name__ == "__main__":
    unittest.main()
