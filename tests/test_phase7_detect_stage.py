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


class Phase7DetectStageTestCase(unittest.TestCase):
    def _load_detect_module(self, *, detection_groups=None):
        fake_utils = types.ModuleType("utils")
        fake_utils.__path__ = []
        fake_hayabusa = types.ModuleType("utils.hayabusa_correlator")
        fake_attack_chain = types.ModuleType("utils.attack_chain_builder")

        recorded = {
            "correlators": [],
            "builders": [],
            "progress_messages": [],
        }

        class FakeHayabusaCorrelator:
            def __init__(self, case_id, analysis_id, progress_callback=None):
                recorded["correlators"].append({
                    "case_id": case_id,
                    "analysis_id": analysis_id,
                    "progress_callback": progress_callback,
                })
                self.progress_callback = progress_callback

            def correlate(self):
                if self.progress_callback is not None:
                    self.progress_callback("hayabusa_correlation", 40, "Clustering detections...")
                return detection_groups if detection_groups is not None else [{"id": "group-1"}]

        class FakeChain:
            def __init__(self, chain_id):
                self.chain_id = chain_id

            def to_dict(self):
                return {"chain_id": self.chain_id}

        class FakeAttackChainBuilder:
            def __init__(self, case_id, analysis_id):
                recorded["builders"].append({
                    "case_id": case_id,
                    "analysis_id": analysis_id,
                })

            def build_chains(self, groups):
                return [FakeChain(f"chain-{len(groups)}")]

        fake_hayabusa.HayabusaCorrelator = FakeHayabusaCorrelator
        fake_attack_chain.AttackChainBuilder = FakeAttackChainBuilder

        previous_modules = {
            name: sys.modules.get(name)
            for name in [
                "utils",
                "utils.hayabusa_correlator",
                "utils.attack_chain_builder",
            ]
        }
        sys.modules["utils"] = fake_utils
        sys.modules["utils.hayabusa_correlator"] = fake_hayabusa
        sys.modules["utils.attack_chain_builder"] = fake_attack_chain
        try:
            detect = _load_module(
                "phase7_detect_under_test",
                "/opt/casescope/pipeline/detect.py",
            )
        finally:
            for name, previous in previous_modules.items():
                if previous is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = previous

        return detect, recorded

    def test_run_hayabusa_correlation_delegates_and_builds_attack_chains(self):
        detect, recorded = self._load_detect_module()
        progress_messages = []

        result = detect.run_hayabusa_correlation(
            case_id=13,
            analysis_id="analysis-3",
            progress_callback=lambda phase, percent, message: progress_messages.append(
                (phase, percent, message)
            ),
        )

        self.assertEqual(len(recorded["correlators"]), 1)
        self.assertEqual(len(recorded["builders"]), 1)
        self.assertEqual(recorded["correlators"][0]["case_id"], 13)
        self.assertEqual(recorded["builders"][0]["analysis_id"], "analysis-3")
        self.assertEqual(result["detection_groups"], [{"id": "group-1"}])
        self.assertEqual([chain.to_dict() for chain in result["attack_chains"]], [{"chain_id": "chain-1"}])
        self.assertEqual(progress_messages[0], ("hayabusa_correlation", 40, "Clustering detections..."))
        self.assertEqual(progress_messages[1], ("hayabusa_correlation", 48, "Building attack chains..."))

    def test_run_hayabusa_correlation_skips_builder_without_detections(self):
        detect, recorded = self._load_detect_module(detection_groups=[])

        result = detect.run_hayabusa_correlation(
            case_id=21,
            analysis_id="analysis-4",
        )

        self.assertEqual(result["detection_groups"], [])
        self.assertEqual(result["attack_chains"], [])
        self.assertEqual(recorded["builders"], [])

    def test_parallel_hayabusa_task_uses_pipeline_detect_stage(self):
        rag_tasks_source = Path("/opt/casescope/tasks/rag_tasks.py").read_text()

        self.assertIn("from pipeline.detect import run_hayabusa_correlation", rag_tasks_source)
        self.assertIn("result = run_hayabusa_correlation(case_id=case_id, analysis_id=analysis_id)", rag_tasks_source)
        self.assertNotIn("from utils.hayabusa_correlator import HayabusaCorrelator", rag_tasks_source)
        self.assertNotIn("from utils.attack_chain_builder import AttackChainBuilder", rag_tasks_source)


if __name__ == "__main__":
    unittest.main()
