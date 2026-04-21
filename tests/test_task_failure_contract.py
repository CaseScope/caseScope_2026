import importlib.util
import os
import sys
import types
import unittest
from contextlib import nullcontext
from unittest.mock import patch

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
os.environ.setdefault("SECRET_KEY", "test-secret")

celery_module = types.ModuleType("celery")
celery_module.shared_task = lambda *args, **kwargs: (lambda func: func)
sys.modules.setdefault("celery", celery_module)

redis_module = types.ModuleType("redis")
redis_module.Redis = object
sys.modules.setdefault("redis", redis_module)

models_package = types.ModuleType("models")
sys.modules.setdefault("models", models_package)

database_module = types.ModuleType("models.database")
database_module.db = types.SimpleNamespace(session=types.SimpleNamespace(get=lambda *_args, **_kwargs: None, commit=lambda: None))
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

utils_package = types.ModuleType("utils")
sys.modules.setdefault("utils", utils_package)

artifact_paths_module = types.ModuleType("utils.artifact_paths")
artifact_paths_module.copy_to_directory = lambda *_args, **_kwargs: None
artifact_paths_module.ensure_case_artifact_paths = lambda *_args, **_kwargs: {}
artifact_paths_module.get_case_originals_root = lambda *_args, **_kwargs: "/tmp/originals"
sys.modules["utils.artifact_paths"] = artifact_paths_module
utils_package.artifact_paths = artifact_paths_module


def _load_module(module_name: str, relative_path: str):
    spec = importlib.util.spec_from_file_location(
        module_name,
        os.path.join(BASE_DIR, relative_path),
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


archive_tasks = _load_module("archive_tasks_under_test", "tasks/archive_tasks.py")
memory_tasks = _load_module("memory_tasks_under_test", "tasks/memory_tasks.py")
pcap_tasks = _load_module("pcap_tasks_under_test", "tasks/pcap_tasks.py")


class _FakeSession:
    def __init__(self, record=None):
        self.record = record
        self.commit_calls = 0

    def commit(self):
        self.commit_calls += 1

    def get(self, _model, _record_id):
        return self.record


class _FakeQuery:
    def __init__(self, obj):
        self.obj = obj

    def get(self, _record_id):
        return self.obj


class _FakeApp:
    def app_context(self):
        return nullcontext()


class TaskFailureContractTestCase(unittest.TestCase):
    def test_archive_case_task_raises_after_marking_failed_job(self):
        fake_session = _FakeSession()
        failed = {}

        def mark_failed(message, stage=None):
            failed["message"] = message
            failed["stage"] = stage

        def update_stage(_stage):
            return None

        fake_job = types.SimpleNamespace(
            case_id=7,
            status="pending",
            started_at=None,
            celery_task_id=None,
            original_status=None,
            archive_path=None,
            archive_folder=None,
            mark_failed=mark_failed,
            update_stage=update_stage,
        )
        fake_case = types.SimpleNamespace(uuid="case-uuid", status="open")
        archive_stage = types.SimpleNamespace(
            VALIDATING=types.SimpleNamespace(value="validating"),
        )

        with patch.dict(
            sys.modules,
            {
                "models.database": types.SimpleNamespace(db=types.SimpleNamespace(session=fake_session)),
                "models.archive_job": types.SimpleNamespace(
                    ArchiveJob=types.SimpleNamespace(query=_FakeQuery(fake_job)),
                    ArchiveStage=archive_stage,
                ),
                "models.case": types.SimpleNamespace(
                    Case=types.SimpleNamespace(query=_FakeQuery(fake_case)),
                    CaseStatus=types.SimpleNamespace(ARCHIVED="archived", IN_PROGRESS="in_progress"),
                ),
                "models.system_settings": types.SimpleNamespace(
                    SystemSettings=types.SimpleNamespace(get=staticmethod(lambda _key, default=None: "/missing-archive")),
                    SettingKeys=types.SimpleNamespace(ARCHIVE_PATH="archive_path"),
                ),
            },
        ), patch.object(archive_tasks, "get_flask_app", return_value=_FakeApp()), patch.object(
            archive_tasks, "update_archive_progress"
        ), patch.object(archive_tasks.os.path, "exists", return_value=False):
            with self.assertRaisesRegex(RuntimeError, "Archive path does not exist"):
                archive_tasks.archive_case_task(
                    types.SimpleNamespace(request=types.SimpleNamespace(id="archive-task-1")),
                    11,
                )

        self.assertEqual(failed["stage"], "validating")
        self.assertIn("Archive path does not exist", failed["message"])
        self.assertEqual(fake_session.commit_calls, 3)

    def test_process_memory_dump_raises_after_persisting_failed_status(self):
        fake_session = _FakeSession()
        progress_updates = []
        fake_job = types.SimpleNamespace(
            id=19,
            case=types.SimpleNamespace(uuid="case-uuid"),
            source_file="/retained/original.raw",
            source_filename="original.raw",
            hostname="HOST-A",
            os_type="windows",
            memory_type="raw",
            selected_plugins=[],
            status="pending",
            started_at=None,
            completed_at=None,
            progress=0,
            current_plugin=None,
            celery_task_id=None,
            output_folder=None,
            extracted_file_path=None,
            plugins_completed=[],
            plugins_failed=[],
            error_message=None,
            memory_timestamp=None,
        )

        with patch.dict(
            sys.modules,
            {
                "models.database": types.SimpleNamespace(db=types.SimpleNamespace(session=fake_session)),
                "models.memory_job": types.SimpleNamespace(
                    MemoryJob=types.SimpleNamespace(query=_FakeQuery(fake_job))
                ),
            },
        ), patch.object(memory_tasks, "get_flask_app", return_value=_FakeApp()), patch.object(
            memory_tasks, "update_job_progress", side_effect=lambda *args, **kwargs: progress_updates.append((args, kwargs))
        ), patch.object(
            memory_tasks, "ensure_case_artifact_paths", return_value={"memory_staging": "/tmp/memory-staging"}
        ), patch.object(
            memory_tasks, "copy_to_directory", return_value="/tmp/working.raw"
        ), patch.object(
            memory_tasks, "ingest_memory_data", return_value={"success": False, "error": "ingest failed"}
        ), patch.object(
            memory_tasks.os, "makedirs"
        ), patch.object(
            memory_tasks.os.path, "isdir", return_value=False
        ):
            with self.assertRaisesRegex(RuntimeError, "ingest failed"):
                memory_tasks.process_memory_dump(
                    types.SimpleNamespace(request=types.SimpleNamespace(id="memory-task-1")),
                    19,
                )

        self.assertEqual(fake_job.status, "failed")
        self.assertEqual(fake_job.error_message, "ingest failed")
        self.assertTrue(any(kwargs.get("status") == "failed" for _, kwargs in progress_updates))

    def test_process_pcap_with_zeek_raises_after_persisting_error_status(self):
        fake_pcap = types.SimpleNamespace(
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
            pcap_tasks, "get_zeek_output_dir", return_value="/tmp/zeek-output"
        ), patch.object(
            pcap_tasks, "_finalize_pcap_working_copy"
        ), patch.object(
            pcap_tasks.os.path, "exists", return_value=True
        ), patch.object(
            pcap_tasks.subprocess,
            "run",
            return_value=types.SimpleNamespace(returncode=1, stderr="zeek exploded"),
        ):
            with self.assertRaisesRegex(RuntimeError, "zeek exploded"):
                pcap_tasks.process_pcap_with_zeek(
                    types.SimpleNamespace(request=types.SimpleNamespace(id="pcap-task-1")),
                    23,
                )

        self.assertEqual(fake_pcap.status, pcap_tasks.PcapFileStatus.ERROR)
        self.assertIn("zeek exploded", fake_pcap.error_message)


if __name__ == "__main__":
    unittest.main()
