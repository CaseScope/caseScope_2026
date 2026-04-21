import importlib.util
import os
import sys
import types
import unittest
from contextlib import nullcontext
from unittest.mock import patch

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
os.environ.setdefault("SECRET_KEY", "test-secret")

_STUBBED_MODULE_NAMES = [
    "celery",
    "celery.exceptions",
    "models",
    "models.database",
    "models.pcap_file",
    "models.behavioral_profiles",
    "pipeline.case_finalize",
    "utils.async_cancellation",
]
_ORIGINAL_MODULES = {name: sys.modules.get(name) for name in _STUBBED_MODULE_NAMES}


def _load_module(module_name: str, relative_path: str):
    spec = importlib.util.spec_from_file_location(
        module_name,
        os.path.join(BASE_DIR, relative_path),
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


celery_module = types.ModuleType("celery")
celery_module.shared_task = lambda *args, **kwargs: (lambda func: func)
sys.modules["celery"] = celery_module

celery_exceptions = types.ModuleType("celery.exceptions")
celery_exceptions.SoftTimeLimitExceeded = type("SoftTimeLimitExceeded", (Exception,), {})
sys.modules["celery.exceptions"] = celery_exceptions

models_package = types.ModuleType("models")
sys.modules["models"] = models_package


class _FakeSession:
    def __init__(self, record=None):
        self.record = record
        self.commits = 0
        self.added = []

    def add(self, obj):
        self.added.append(obj)

    def commit(self):
        self.commits += 1

    def rollback(self):
        return None

    def refresh(self, _obj):
        return None

    def get(self, _model, _record_id):
        return self.record


database_module = types.ModuleType("models.database")
database_module.db = types.SimpleNamespace(session=_FakeSession())
sys.modules["models.database"] = database_module
models_package.database = database_module

pcap_file_module = types.ModuleType("models.pcap_file")
pcap_file_module.PcapFile = type("PcapFile", (), {})
pcap_file_module.PcapFileStatus = types.SimpleNamespace(
    ERROR="error",
    PROCESSING="processing",
    DONE="done",
    NEW="new",
    QUEUED="queued",
)
sys.modules["models.pcap_file"] = pcap_file_module
models_package.pcap_file = pcap_file_module


class _FakeDeleteQuery:
    def filter_by(self, **_kwargs):
        return self

    def delete(self):
        return None


class _FakeAnalysisStatus:
    PENDING = "pending"
    PROFILING = "profiling"
    CORRELATING = "correlating"
    ANALYZING = "analyzing"
    PARTIAL = "partial"
    COMPLETE = "complete"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @classmethod
    def running_statuses(cls):
        return (cls.PENDING, cls.PROFILING, cls.CORRELATING, cls.ANALYZING)


class _FakeCaseAnalysisRun:
    def __init__(self, **kwargs):
        self.case_id = kwargs.get("case_id")
        self.analysis_id = kwargs.get("analysis_id")
        self.mode = kwargs.get("mode")
        self.status = kwargs.get("status")
        self.ai_enabled = kwargs.get("ai_enabled", False)
        self.opencti_enabled = kwargs.get("opencti_enabled", False)
        self.started_at = kwargs.get("started_at")
        self.last_progress_at = kwargs.get("last_progress_at")
        self.current_phase = kwargs.get("current_phase")
        self.progress_percent = 0
        self.profiling_started_at = None
        self.correlation_started_at = None
        self.ai_analysis_started_at = None
        self.completed_at = None
        self.partial_results_available = False
        self.error_message = None
        self.summary = None
        self.findings_generated = 0
        self.high_confidence_findings = 0
        self.users_profiled = 0
        self.systems_profiled = 0
        self.peer_groups_created = 0
        self.patterns_analyzed = 0
        self.attack_chains_found = 0

    def has_partial_results(self):
        return bool(self.partial_results_available or self.status == _FakeAnalysisStatus.PARTIAL)


behavioral_profiles_module = types.ModuleType("models.behavioral_profiles")
behavioral_profiles_module.CaseAnalysisRun = _FakeCaseAnalysisRun
behavioral_profiles_module.AnalysisMode = types.SimpleNamespace()
behavioral_profiles_module.AnalysisStatus = _FakeAnalysisStatus
behavioral_profiles_module.UserBehaviorProfile = types.SimpleNamespace(query=_FakeDeleteQuery())
behavioral_profiles_module.SystemBehaviorProfile = types.SimpleNamespace(query=_FakeDeleteQuery())
behavioral_profiles_module.PeerGroup = types.SimpleNamespace(query=_FakeDeleteQuery())
behavioral_profiles_module.GapDetectionFinding = type("GapDetectionFinding", (), {})
behavioral_profiles_module.SuggestedAction = type("SuggestedAction", (), {})
behavioral_profiles_module.OpenCTICache = types.SimpleNamespace(query=_FakeDeleteQuery())
sys.modules["models.behavioral_profiles"] = behavioral_profiles_module

case_finalize_module = types.ModuleType("pipeline.case_finalize")
case_finalize_module.finalize_case_analysis_run = lambda *args, **kwargs: True
sys.modules["pipeline.case_finalize"] = case_finalize_module

async_cancellation_module = types.ModuleType("utils.async_cancellation")
async_cancellation_module.clear_cancellation = lambda *_args, **_kwargs: None
async_cancellation_module.is_cancellation_requested = lambda *_args, **_kwargs: False
sys.modules["utils.async_cancellation"] = async_cancellation_module


pcap_tasks = _load_module("pcap_tasks_remaining_cancellation_test", "tasks/pcap_tasks.py")
case_analyzer = _load_module("case_analyzer_remaining_cancellation_test", "utils/case_analyzer.py")

for module_name, original_module in _ORIGINAL_MODULES.items():
    if original_module is None:
        sys.modules.pop(module_name, None)
    else:
        sys.modules[module_name] = original_module


class _FakeApp:
    def app_context(self):
        return nullcontext()


class RemainingAsyncCancellationContractTestCase(unittest.TestCase):
    def test_process_pcap_returns_cancelled_when_zeek_work_is_cancelled(self):
        fake_pcap = types.SimpleNamespace(
            id=41,
            case_uuid="case-uuid",
            file_path="/tmp/capture.pcap",
            source_path=None,
            is_extracted=False,
            status=None,
            indexed_at=None,
            logs_indexed=0,
            error_message=None,
            filename="capture.pcap",
            zeek_output_path=None,
            processed_at=None,
            logs_generated=0,
            hostname="HOST-A",
        )
        fake_session = _FakeSession(record=fake_pcap)

        with patch.object(pcap_tasks, "db", types.SimpleNamespace(session=fake_session)), patch.object(
            pcap_tasks, "get_flask_app", return_value=_FakeApp()
        ), patch.object(
            pcap_tasks.os.path, "exists", return_value=True
        ), patch.object(
            pcap_tasks, "get_zeek_output_dir", return_value="/tmp/zeek-output"
        ), patch.object(
            pcap_tasks, "_run_zeek_with_cancellation", side_effect=pcap_tasks.PcapTaskCancelled("cancelled")
        ), patch.object(
            pcap_tasks, "_finalize_pcap_working_copy"
        ):
            result = pcap_tasks.process_pcap_with_zeek(
                types.SimpleNamespace(request=types.SimpleNamespace(id="pcap-task-1")),
                41,
            )

        self.assertTrue(result["cancelled"])
        self.assertEqual(result["pcap_id"], 41)
        self.assertEqual(fake_pcap.status, "cancelled")
        self.assertEqual(fake_pcap.error_message, "PCAP processing cancelled")

    def test_index_zeek_logs_returns_cancelled_before_next_log_after_request(self):
        fake_pcap = types.SimpleNamespace(
            id=52,
            case_uuid="case-uuid",
            zeek_output_path="/tmp/zeek-output",
            hostname="HOST-A",
            filename="capture.pcap",
            indexed_at=None,
            logs_indexed=0,
            error_message=None,
            status="done",
        )
        fake_session = _FakeSession(record=fake_pcap)
        cancel_state = {"requested": False}

        def parse_log(**kwargs):
            cancel_state["requested"] = True
            return 3, []

        with patch.object(pcap_tasks, "db", types.SimpleNamespace(session=fake_session)), patch.object(
            pcap_tasks, "get_flask_app", return_value=_FakeApp()
        ), patch.object(
            pcap_tasks.os.path, "exists", return_value=True
        ), patch.object(
            pcap_tasks.os, "listdir", return_value=["conn.log", "dns.log"]
        ), patch.object(
            pcap_tasks, "_get_case_for_task", return_value=types.SimpleNamespace(id=7)
        ), patch.object(
            pcap_tasks, "parse_zeek_log_file", side_effect=parse_log
        ), patch.object(
            pcap_tasks, "is_cancellation_requested", side_effect=lambda *_args, **_kwargs: cancel_state["requested"]
        ), patch.object(
            pcap_tasks, "clear_cancellation"
        ):
            result = pcap_tasks.index_zeek_logs(
                types.SimpleNamespace(request=types.SimpleNamespace(id="pcap-index-task-1")),
                52,
            )

        self.assertTrue(result["cancelled"])
        self.assertEqual(result["pcap_id"], 52)
        self.assertEqual(fake_pcap.error_message, "PCAP indexing cancelled")
        self.assertEqual(fake_pcap.logs_indexed, 0)

    def test_case_analyzer_stops_before_next_phase_after_cancellation_request(self):
        fake_session = _FakeSession()
        cancel_state = {"requested": False}
        recorded_finalize = {}

        class _FeatureSnapshot:
            mode = "A"
            ai_enabled = False
            threat_intel_enabled = False
            capabilities = {}

        def fake_finalize(analysis_run, *args, **kwargs):
            analysis_run.status = kwargs["final_status"]
            analysis_run.current_phase = kwargs["phase_message"]
            analysis_run.error_message = kwargs["error_message"]
            analysis_run.partial_results_available = kwargs["partial_results_available"]
            recorded_finalize["status"] = kwargs["final_status"]
            recorded_finalize["phase_message"] = kwargs["phase_message"]
            recorded_finalize["error_message"] = kwargs["error_message"]
            recorded_finalize["partial"] = kwargs["partial_results_available"]
            return True

        def fake_behavioral_profiling():
            cancel_state["requested"] = True
            return {"users_profiled": 1, "systems_profiled": 1}

        with patch.object(case_analyzer, "db", types.SimpleNamespace(session=fake_session)), patch.object(
            case_analyzer, "finalize_case_analysis_run", side_effect=fake_finalize
        ), patch.object(
            case_analyzer, "is_cancellation_requested", side_effect=lambda *_args, **_kwargs: cancel_state["requested"]
        ), patch.object(
            case_analyzer, "clear_cancellation"
        ), patch.dict(
            sys.modules,
            {
                "utils.feature_availability": types.SimpleNamespace(
                    FeatureAvailability=types.SimpleNamespace(
                        get_feature_snapshot=staticmethod(lambda: _FeatureSnapshot())
                    )
                ),
            },
        ):
            analyzer = case_analyzer.CaseAnalyzer(case_id=7, progress_callback=None, parallel=False)
            analyzer._clear_previous_analysis_data = lambda: None
            analyzer._run_behavioral_profiling = fake_behavioral_profiling
            analyzer._run_peer_clustering = lambda: self.fail("Peer clustering should not run after cancellation")

            with self.assertRaises(case_analyzer.AnalysisCancelled):
                analyzer.run_full_analysis()

        self.assertEqual(analyzer._analysis_run.status, _FakeAnalysisStatus.CANCELLED)
        self.assertEqual(recorded_finalize["status"], _FakeAnalysisStatus.CANCELLED)
        self.assertEqual(recorded_finalize["phase_message"], "Analysis cancelled")
        self.assertEqual(recorded_finalize["error_message"], "Analysis cancellation requested")


if __name__ == "__main__":
    unittest.main()
