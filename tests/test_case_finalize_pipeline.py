import importlib.util
import os
import sys
import types
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(__file__))


class _FakeSession:
    def __init__(self):
        self.commit_calls = 0

    def commit(self):
        self.commit_calls += 1


def _load_module(module_name: str, relative_path: str):
    spec = importlib.util.spec_from_file_location(
        module_name,
        os.path.join(BASE_DIR, relative_path),
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CaseFinalizePipelineTestCase(unittest.TestCase):
    def test_finalize_case_analysis_run_persists_summary_and_sync_outcome(self):
        fake_session = _FakeSession()
        fake_db = types.SimpleNamespace(session=fake_session)
        phase_outcomes = {"gap_detection": {"success": True, "message": "done"}}
        recorded_outcomes = []
        stubbed_module_names = [
            "models",
            "models.database",
            "models.behavioral_profiles",
            "utils",
            "utils.analysis_summary",
            "utils.unified_findings_store",
        ]
        original_modules = {name: sys.modules.get(name) for name in stubbed_module_names}

        try:
            models_package = types.ModuleType("models")
            sys.modules["models"] = models_package
            sys.modules["models.database"] = types.SimpleNamespace(db=fake_db)
            sys.modules["models.behavioral_profiles"] = types.SimpleNamespace(
                AnalysisStatus=types.SimpleNamespace(COMPLETE="complete", PARTIAL="partial", FAILED="failed")
            )
            utils_package = types.ModuleType("utils")
            sys.modules["utils"] = utils_package
            sys.modules["utils.analysis_summary"] = types.SimpleNamespace(
                summarize_findings=lambda findings: {
                    "total_findings": len(findings),
                    "critical_findings": 1,
                    "high_findings": 1,
                    "medium_findings": 0,
                    "low_findings": 0,
                    "high_confidence_findings": 2,
                    "severity_breakdown": {"critical": 1, "high": 1},
                    "top_findings": [{"title": "Top finding"}],
                }
            )
            sys.modules["utils.unified_findings_store"] = types.SimpleNamespace(
                sync_case_findings=lambda case_id, analysis_id, findings: len(findings)
            )

            case_finalize = _load_module("case_finalize_under_test", "pipeline/case_finalize.py")

            analysis_run = types.SimpleNamespace(
                mode="D",
                status="running",
                completed_at=None,
                last_progress_at=None,
                progress_percent=0,
                current_phase="running",
                partial_results_available=False,
                error_message=None,
                findings_generated=0,
                high_confidence_findings=0,
                users_profiled=0,
                systems_profiled=0,
                peer_groups_created=0,
                patterns_evaluated=0,
                gap_findings=0,
                attack_chains_found=0,
                patterns_analyzed=0,
                summary={},
            )

            def record_phase_outcome(phase, success, details=None, duration_seconds=None, message=None):
                outcome = {"success": success, "message": message or ("completed" if success else "failed")}
                if details:
                    outcome["details"] = details
                if duration_seconds is not None:
                    outcome["duration_seconds"] = duration_seconds
                phase_outcomes[phase] = outcome
                recorded_outcomes.append((phase, outcome))

            finalized = case_finalize.finalize_case_analysis_run(
                analysis_run,
                case_id=42,
                analysis_id="analysis-42",
                all_findings=[{"id": 1}, {"id": 2}],
                profiling_stats={"users_profiled": 3, "systems_profiled": 2, "user_groups": 1, "system_groups": 1},
                pattern_results=[{"pattern": "one"}],
                gap_findings=[{"gap": "one"}],
                hayabusa_findings=[{"rule": "one"}],
                attack_chains=[{"chain": "one"}],
                census={"4624": 5, "4688": 2},
                ioc_timeline={"entries": [1, 2], "cross_host_links": [1]},
                storyline_results={"storylines": [{"id": "story-1"}]},
                triage_result={"summary": "triage"},
                synthesis_result={"summary": "synthesis"},
                phase_outcomes=phase_outcomes,
                degraded_reasons=["ioc_timeline degraded"],
                final_status="partial",
                phase_message="Analysis completed with degraded phases",
                progress_percent=100,
                error_message="ioc_timeline degraded",
                partial_results_available=True,
                start_time=None,
                make_json_safe=lambda value: value,
                record_phase_outcome=record_phase_outcome,
            )

            self.assertTrue(finalized)
            self.assertEqual(analysis_run.status, "partial")
            self.assertEqual(analysis_run.current_phase, "Analysis completed with degraded phases")
            self.assertEqual(analysis_run.findings_generated, 2)
            self.assertEqual(analysis_run.summary["total_findings"], 2)
            self.assertEqual(analysis_run.summary["phase_outcomes"]["finding_storage_sync"]["success"], True)
            self.assertEqual(analysis_run.summary["degraded_reasons"], ["ioc_timeline degraded"])
            self.assertEqual(fake_session.commit_calls, 3)
            self.assertEqual(recorded_outcomes[0][0], "finding_storage_sync")
        finally:
            for module_name, original_module in original_modules.items():
                if original_module is None:
                    sys.modules.pop(module_name, None)
                else:
                    sys.modules[module_name] = original_module


if __name__ == "__main__":
    unittest.main()
