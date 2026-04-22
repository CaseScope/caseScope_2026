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


class Phase7BaselinesStageTestCase(unittest.TestCase):
    def _load_baselines_module(self):
        fake_utils = types.ModuleType("utils")
        fake_utils.__path__ = []
        fake_behavioral_profiler = types.ModuleType("utils.behavioral_profiler")
        fake_peer_clustering = types.ModuleType("utils.peer_clustering")

        recorded = {
            "profilers": [],
            "peer_builders": [],
            "progress_messages": [],
        }

        class FakeBehavioralProfiler:
            def __init__(self, case_id, analysis_id, progress_callback=None):
                recorded["profilers"].append({
                    "case_id": case_id,
                    "analysis_id": analysis_id,
                    "progress_callback": progress_callback,
                })
                self.progress_callback = progress_callback

            def profile_all(self):
                if self.progress_callback is not None:
                    self.progress_callback("profiling", 12, "Profiling users")
                return {
                    "users_profiled": 4,
                    "systems_profiled": 2,
                    "duration_seconds": 99.0,
                }

        class FakePeerGroupBuilder:
            def __init__(self, case_id, analysis_id):
                recorded["peer_builders"].append({
                    "case_id": case_id,
                    "analysis_id": analysis_id,
                })

            def build_all_peer_groups(self):
                return {
                    "user_groups": 3,
                    "system_groups": 1,
                    "total_groups": 4,
                }

        fake_behavioral_profiler.BehavioralProfiler = FakeBehavioralProfiler
        fake_peer_clustering.PeerGroupBuilder = FakePeerGroupBuilder

        previous_modules = {
            name: sys.modules.get(name)
            for name in [
                "utils",
                "utils.behavioral_profiler",
                "utils.peer_clustering",
            ]
        }
        sys.modules["utils"] = fake_utils
        sys.modules["utils.behavioral_profiler"] = fake_behavioral_profiler
        sys.modules["utils.peer_clustering"] = fake_peer_clustering
        try:
            baselines = _load_module(
                "phase7_baselines_under_test",
                "/opt/casescope/pipeline/baselines.py",
            )
        finally:
            for name, previous in previous_modules.items():
                if previous is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = previous

        return baselines, recorded

    def test_run_behavioral_profiling_delegates_and_accepts_progress_callback(self):
        baselines, recorded = self._load_baselines_module()
        progress_messages = []

        result = baselines.run_behavioral_profiling(
            case_id=7,
            analysis_id="analysis-1",
            progress_callback=lambda phase, percent, message: progress_messages.append(
                (phase, percent, message)
            ),
        )

        self.assertEqual(len(recorded["profilers"]), 1)
        self.assertEqual(recorded["profilers"][0]["case_id"], 7)
        self.assertEqual(recorded["profilers"][0]["analysis_id"], "analysis-1")
        self.assertEqual(result["users_profiled"], 4)
        self.assertEqual(result["systems_profiled"], 2)
        self.assertIsInstance(result["duration_seconds"], float)
        self.assertTrue(progress_messages)
        self.assertEqual(progress_messages[0], ("profiling", 12, "Profiling users"))

    def test_run_build_baselines_combines_profiling_and_clustering_contracts(self):
        baselines, recorded = self._load_baselines_module()

        result = baselines.run_build_baselines(
            case_id=9,
            analysis_id="analysis-2",
        )

        self.assertEqual(len(recorded["profilers"]), 1)
        self.assertEqual(len(recorded["peer_builders"]), 1)
        self.assertEqual(recorded["peer_builders"][0]["case_id"], 9)
        self.assertEqual(result["users_profiled"], 4)
        self.assertEqual(result["systems_profiled"], 2)
        self.assertEqual(result["user_groups"], 3)
        self.assertEqual(result["system_groups"], 1)
        self.assertEqual(result["total_groups"], 4)

    def test_parallel_profile_task_delegates_to_pipeline_baselines_stage(self):
        rag_tasks, restore_modules = load_rag_tasks_with_stubs(
            "phase7_baselines_rag_task_under_test"
        )
        try:
            recorded = {}
            fake_baselines = types.ModuleType("pipeline.baselines")

            def run_build_baselines(**kwargs):
                recorded["kwargs"] = kwargs
                return {
                    "users_profiled": 4,
                    "systems_profiled": 2,
                    "user_groups": 3,
                    "system_groups": 1,
                }

            fake_baselines.run_build_baselines = run_build_baselines
            fake_pipeline = types.ModuleType("pipeline")
            fake_pipeline.__path__ = []
            fake_pipeline.baselines = fake_baselines

            with patch.dict(
                sys.modules,
                {
                    "pipeline": fake_pipeline,
                    "pipeline.baselines": fake_baselines,
                },
            ):
                result = rag_tasks.analyze_phase_profile(
                    types.SimpleNamespace(),
                    case_id=11,
                    analysis_id="analysis-11",
                )

            self.assertEqual(
                recorded["kwargs"],
                {
                    "case_id": 11,
                    "analysis_id": "analysis-11",
                },
            )
            self.assertTrue(result["success"])
            self.assertEqual(result["phase"], "profile_cluster")
            self.assertEqual(result["users_profiled"], 4)
            self.assertEqual(result["systems_profiled"], 2)
            self.assertEqual(result["user_groups"], 3)
            self.assertEqual(result["system_groups"], 1)
            self.assertIsInstance(result["duration_seconds"], float)
        finally:
            restore_modules()


if __name__ == "__main__":
    unittest.main()
