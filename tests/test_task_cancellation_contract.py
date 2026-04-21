import importlib.util
import os
import sys
import tempfile
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
database_module.db = types.SimpleNamespace(session=types.SimpleNamespace(commit=lambda: None))
sys.modules["models.database"] = database_module
models_package.database = database_module

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


archive_tasks = _load_module("archive_tasks_cancellation_test", "tasks/archive_tasks.py")
memory_tasks = _load_module("memory_tasks_cancellation_test", "tasks/memory_tasks.py")


class _FakeApp:
    def app_context(self):
        return nullcontext()


class _FakeSession:
    def __init__(self):
        self.commit_calls = 0

    def commit(self):
        self.commit_calls += 1


class _FakeQuery:
    def __init__(self, obj):
        self.obj = obj

    def get(self, _job_id):
        return self.obj


class TaskCancellationContractTestCase(unittest.TestCase):
    def test_archive_compression_stops_when_job_is_marked_cancelled(self):
        fake_job = types.SimpleNamespace(
            status="cancelled",
            update_stage=lambda *_args, **_kwargs: None,
            update_file_progress=lambda *_args, **_kwargs: None,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            source_folder = os.path.join(tmpdir, "source")
            os.makedirs(source_folder, exist_ok=True)
            with open(os.path.join(source_folder, "evidence.txt"), "w", encoding="utf-8") as handle:
                handle.write("evidence")

            zip_path = os.path.join(tmpdir, "archive.zip")

            with patch.dict(
                sys.modules,
                {
                    "models.database": types.SimpleNamespace(db=types.SimpleNamespace(session=_FakeSession())),
                    "models.archive_job": types.SimpleNamespace(
                        ArchiveJob=types.SimpleNamespace(query=_FakeQuery(fake_job)),
                        ArchiveJobStatus=types.SimpleNamespace(CANCELLED=types.SimpleNamespace(value="cancelled")),
                    ),
                },
            ), patch.object(archive_tasks, "get_flask_app", return_value=_FakeApp()), patch.object(
                archive_tasks, "update_archive_progress"
            ):
                with self.assertRaises(archive_tasks.ArchiveTaskCancelled):
                    archive_tasks.compress_folder_to_zip(
                        source_folder=source_folder,
                        zip_path=zip_path,
                        job_id=41,
                        stage="compressing_storage",
                    )

    def test_memory_task_returns_cancelled_before_next_plugin_after_request(self):
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
            selected_plugins=["windows.pslist", "windows.dlllist"],
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
        executed_plugins = []

        def run_plugin(_memory_file, plugin_name, _output_dir, _os_type):
            executed_plugins.append(plugin_name)
            if plugin_name == "windows.pslist":
                fake_job.status = "cancelled"
            return True, f"/tmp/{plugin_name}.json", None

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
            memory_tasks, "run_volatility_plugin", side_effect=run_plugin
        ), patch.object(
            memory_tasks.os, "makedirs"
        ), patch.object(
            memory_tasks.os.path, "isdir", return_value=False
        ), patch.object(
            memory_tasks, "ingest_memory_data"
        ) as ingest_memory_data:
            result = memory_tasks.process_memory_dump(
                types.SimpleNamespace(request=types.SimpleNamespace(id="memory-task-1")),
                19,
            )

        self.assertEqual(executed_plugins, ["windows.pslist"])
        self.assertTrue(result["cancelled"])
        self.assertEqual(result["job_id"], 19)
        self.assertFalse(ingest_memory_data.called)
        self.assertTrue(any(kwargs.get("status") == "cancelled" for _, kwargs in progress_updates))


if __name__ == "__main__":
    unittest.main()
