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


class Phase7PatternThreatIntelStageTestCase(unittest.TestCase):
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
            "phase7_pattern_threat_intel_under_test",
            "/opt/casescope/pipeline/pattern_analysis.py",
        )
        return pattern_analysis, restore_modules

    def test_build_pattern_threat_intel_context_formats_opencti_data(self):
        pattern_analysis, restore_modules = self._load_pattern_analysis_module()
        try:
            class FakeProvider:
                def get_attack_pattern_context(self, mitre_id):
                    contexts = {
                        "T1110": {
                            "technique_name": "Brute Force",
                            "threat_actors": [
                                {"name": "APT1"},
                                {"name": "APT2"},
                                {"name": "APT3"},
                                {"name": "APT4"},
                            ],
                            "detection_guidance": "A" * 220,
                        },
                        "T1059": {
                            "technique_name": "Command and Scripting Interpreter",
                            "threat_actors": [{"name": "APT5"}],
                            "detection_guidance": "Use PowerShell telemetry.",
                        },
                    }
                    return contexts[mitre_id]

            context = pattern_analysis.build_pattern_threat_intel_context(
                FakeProvider(),
                {"mitre_techniques": ["T1110", "T1059", "T1021"]},
            )

            self.assertIn("THREAT INTEL: T1110 is used by APT1, APT2, APT3.", context)
            self.assertIn("THREAT INTEL: T1059 is used by APT5.", context)
            self.assertIn("Detection guidance: " + ("A" * 150), context)
            self.assertIn("Note: use 'consistent with' language, not definitive attribution.", context)
            self.assertNotIn("APT4", context)
            self.assertNotIn("T1021", context)
        finally:
            restore_modules()

    def test_build_pattern_threat_intel_context_handles_missing_provider_and_errors(self):
        pattern_analysis, restore_modules = self._load_pattern_analysis_module()
        try:
            class BrokenProvider:
                def get_attack_pattern_context(self, mitre_id):
                    raise RuntimeError("boom")

            self.assertEqual(
                pattern_analysis.build_pattern_threat_intel_context(
                    None,
                    {"mitre_techniques": ["T1110"]},
                ),
                "",
            )
            self.assertEqual(
                pattern_analysis.build_pattern_threat_intel_context(
                    BrokenProvider(),
                    {"mitre_techniques": ["T1110"]},
                ),
                "",
            )
        finally:
            restore_modules()

    def test_rag_task_uses_shared_pattern_threat_intel_helper(self):
        source = Path("/opt/casescope/tasks/rag_tasks.py").read_text()

        self.assertIn("from pipeline.pattern_analysis import (", source)
        self.assertIn("run_task_ai_pattern_iteration,", source)
        self.assertIn("iteration_result = run_task_ai_pattern_iteration(", source)
        self.assertNotIn("ctx = opencti_provider.get_attack_pattern_context(mid)", source)


if __name__ == "__main__":
    unittest.main()
