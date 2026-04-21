import importlib.util
import os
import sys
import types
import unittest
from contextlib import contextmanager


BASE_DIR = os.path.dirname(os.path.dirname(__file__))
os.environ.setdefault("SECRET_KEY", "test-secret")


class _FakeCeleryConfig(dict):
    def __init__(self):
        super().__init__()
        self.beat_schedule = {}
        self.task_routes = {}

    def update(self, **kwargs):
        super().update(kwargs)


class _FakeCelery:
    def __init__(self, *_args, **_kwargs):
        self.conf = _FakeCeleryConfig()

    def task(self, *args, **kwargs):
        def decorator(func):
            return func

        return decorator


@contextmanager
def _stubbed_celery_import_environment():
    original_modules = {
        name: sys.modules.get(name)
        for name in (
            "celery",
            "celery.exceptions",
            "celery.schedules",
            "config",
            "tasks",
            "tasks.pcap_tasks",
        )
    }

    celery_module = types.ModuleType("celery")
    celery_module.Celery = _FakeCelery
    celery_module.chain = lambda *args, **kwargs: None
    celery_module.group = lambda *args, **kwargs: None
    celery_module.chord = lambda *args, **kwargs: None
    sys.modules["celery"] = celery_module

    celery_exceptions = types.ModuleType("celery.exceptions")
    celery_exceptions.SoftTimeLimitExceeded = type("SoftTimeLimitExceeded", (Exception,), {})
    sys.modules["celery.exceptions"] = celery_exceptions

    celery_schedules = types.ModuleType("celery.schedules")
    celery_schedules.crontab = lambda *args, **kwargs: None
    sys.modules["celery.schedules"] = celery_schedules

    sys.modules["config"] = types.SimpleNamespace(
        Config=types.SimpleNamespace(
            CELERY_BROKER_URL="redis://localhost:6379/0",
            CELERY_RESULT_BACKEND="redis://localhost:6379/0",
        )
    )

    tasks_package = types.ModuleType("tasks")
    tasks_package.__path__ = []
    sys.modules["tasks"] = tasks_package
    sys.modules["tasks.pcap_tasks"] = types.ModuleType("tasks.pcap_tasks")

    try:
        yield
    finally:
        for module_name, original in original_modules.items():
            if original is None:
                sys.modules.pop(module_name, None)
            else:
                sys.modules[module_name] = original


def _load_celery_tasks_module():
    with _stubbed_celery_import_environment():
        spec = importlib.util.spec_from_file_location(
            "celery_tasks_ioc_queue_contract",
            os.path.join(BASE_DIR, "tasks", "celery_tasks.py"),
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module


class IOCQueueRoutingTestCase(unittest.TestCase):
    def test_interactive_ioc_tasks_route_to_ioc_queue(self):
        celery_tasks = _load_celery_tasks_module()

        self.assertEqual(celery_tasks.IOC_TASK_QUEUE, "ioc")
        self.assertEqual(
            celery_tasks.celery_app.conf.task_routes["tasks.find_iocs_in_events"]["queue"],
            "ioc",
        )
        self.assertEqual(
            celery_tasks.celery_app.conf.task_routes["tasks.extract_iocs_from_report"]["queue"],
            "ioc",
        )
        self.assertEqual(
            celery_tasks.celery_app.conf.task_routes["tasks.tag_iocs_for_case"]["queue"],
            "ioc",
        )


if __name__ == "__main__":
    unittest.main()
