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


class Phase7PatternRuleStageTestCase(unittest.TestCase):
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
            "phase7_pattern_rule_under_test",
            "/opt/casescope/pipeline/pattern_analysis.py",
        )
        return pattern_analysis, restore_modules

    def test_evaluate_rule_based_pattern_analyzes_each_correlation_key(self):
        pattern_analysis, restore_modules = self._load_pattern_analysis_module()
        try:
            recorded = {
                "analyzer_calls": [],
            }

            class FakeExtractor:
                def get_correlation_keys(self, pattern_id):
                    self.pattern_id = pattern_id
                    return ["alpha", "bravo"]

                def get_candidates_for_key(self, pattern_id, key):
                    candidates_by_key = {
                        "alpha": [{"behavioral_context": {"user": "alice"}, "event_id": 1}],
                        "bravo": [{"behavioral_context": {"user": "bob"}, "event_id": 2}],
                    }
                    return candidates_by_key[key]

            class FakeRuleAnalyzer:
                def analyze_without_ai(self, *, candidates, pattern_config, behavioral_context):
                    recorded["analyzer_calls"].append(
                        {
                            "candidate_count": len(candidates),
                            "pattern_name": pattern_config["name"],
                            "behavioral_context": behavioral_context,
                        }
                    )
                    return {"final_confidence": 61 + len(recorded["analyzer_calls"])}

            result = pattern_analysis.evaluate_rule_based_pattern(
                extractor=FakeExtractor(),
                rule_analyzer=FakeRuleAnalyzer(),
                pattern_id="pattern-12",
                pattern_config={"name": "Pattern Twelve"},
            )

            self.assertEqual(len(result), 2)
            self.assertEqual(result[0]["correlation_key"], "alpha")
            self.assertEqual(result[0]["pattern_id"], "pattern-12")
            self.assertEqual(result[1]["correlation_key"], "bravo")
            self.assertEqual(
                recorded["analyzer_calls"],
                [
                    {
                        "candidate_count": 1,
                        "pattern_name": "Pattern Twelve",
                        "behavioral_context": {"user": "alice"},
                    },
                    {
                        "candidate_count": 1,
                        "pattern_name": "Pattern Twelve",
                        "behavioral_context": {"user": "bob"},
                    },
                ],
            )
        finally:
            restore_modules()

if __name__ == "__main__":
    unittest.main()
