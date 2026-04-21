import importlib.util
import os
import sys
import types
import unittest

from flask import Flask
from unittest.mock import patch

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
os.environ.setdefault("SECRET_KEY", "test-secret")

_STUBBED_MODULE_NAMES = [
    "flask_login",
    "sqlalchemy",
    "utils",
    "utils.async_status",
    "utils.event_analyst_state",
    "models.case",
    "models.database",
    "models.case_file",
    "routes.route_helpers",
    "routes.hunting_query_helpers",
    "utils.forensic_chat_sources",
    "utils.artifact_paths",
    "celery.result",
    "tasks",
    "tasks.celery_tasks",
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


flask_login_module = types.ModuleType("flask_login")
flask_login_module.login_required = lambda func: func
flask_login_module.current_user = types.SimpleNamespace(
    permission_level="admin",
    is_administrator=True,
)
sys.modules["flask_login"] = flask_login_module

sqlalchemy_module = types.ModuleType("sqlalchemy")
sqlalchemy_module.or_ = lambda *args, **kwargs: None
sys.modules["sqlalchemy"] = sqlalchemy_module

utils_package = types.ModuleType("utils")
utils_package.__path__ = []
sys.modules["utils"] = utils_package

async_status_module = _load_module("async_status_under_test", "utils/async_status.py")
sys.modules["utils.async_status"] = async_status_module
utils_package.async_status = async_status_module
event_analyst_state_module = types.SimpleNamespace(
    build_analyst_projection=lambda *_args, **_kwargs: {
        "join": "",
        "select": [
            "0 AS analyst_tagged",
            "[] AS analyst_tags",
            "'' AS analyst_notes",
        ],
        "analyst_tagged_sql": "0",
        "analyst_tags_sql": "[]",
        "analyst_notes_sql": "''",
    },
    build_event_selector_key=lambda *_args, **_kwargs: "selector",
    ensure_event_analyst_state_table=lambda *_args, **_kwargs: None,
    normalize_analyst_tags=lambda tags: tags or [],
    upsert_event_analyst_state_rows=lambda *_args, **_kwargs: 0,
)
sys.modules["utils.event_analyst_state"] = event_analyst_state_module
utils_package.event_analyst_state = event_analyst_state_module

sys.modules["models.case"] = types.SimpleNamespace(
    Case=types.SimpleNamespace(
        get_by_uuid=staticmethod(lambda _uuid: types.SimpleNamespace(id=7, uuid="case-uuid")),
        get_by_id=staticmethod(lambda _case_id: types.SimpleNamespace(id=7, uuid="case-uuid")),
    )
)
sys.modules["models.database"] = types.SimpleNamespace(db=types.SimpleNamespace(session=types.SimpleNamespace()))
sys.modules["models.case_file"] = types.SimpleNamespace(CaseFile=object)
sys.modules["routes.route_helpers"] = types.SimpleNamespace(
    _remember_task_access=lambda *_args, **_kwargs: None,
    _require_case_write_access=lambda *_args, **_kwargs: None,
    _task_access_allowed=lambda *_args, **_kwargs: True,
    _load_case_or_404=lambda *_args, **_kwargs: (None, None),
    _viewer_write_error=lambda *_args, **_kwargs: None,
)
sys.modules["routes.hunting_query_helpers"] = types.SimpleNamespace(
    _build_hunting_alert_type_filter=lambda *_args, **_kwargs: ("", {}),
    build_hunting_search_clause=lambda *_args, **_kwargs: ("", {}),
    build_event_description=lambda *_args, **_kwargs: "",
    build_hunting_time_filter=lambda *_args, **_kwargs: ("", {}),
    build_hunting_type_filter=lambda *_args, **_kwargs: ("", {}),
)
sys.modules["utils.forensic_chat_sources"] = types.SimpleNamespace(
    get_browser_download_rows=lambda *_args, **_kwargs: []
)
utils_package.forensic_chat_sources = sys.modules["utils.forensic_chat_sources"]
sys.modules["utils.artifact_paths"] = types.SimpleNamespace(
    ensure_case_artifact_paths=lambda *_args, **_kwargs: {},
    is_within_any_root=lambda *_args, **_kwargs: True,
)
utils_package.artifact_paths = sys.modules["utils.artifact_paths"]


class _FakeTask:
    def __init__(self, state, *, info=None, result=None):
        self.state = state
        self.status = state
        self.info = info
        self.result = result

    def ready(self):
        return self.state in {"SUCCESS", "FAILURE"}

    def successful(self):
        return self.state == "SUCCESS"


rag_task = _FakeTask("PROGRESS", info={"progress": 44, "status": "Embedding events"})
hunting_task = _FakeTask("FAILURE", result=RuntimeError("boom"))
parsing_task = _FakeTask("SUCCESS", result={"rows": 12})
ioc_task = _FakeTask("FAILURE", result=RuntimeError("tag failed"))


def _async_result_factory(task):
    return lambda *_args, **_kwargs: task


sys.modules["celery.result"] = types.SimpleNamespace(
    AsyncResult=_async_result_factory(rag_task)
)
sys.modules["tasks.celery_tasks"] = types.SimpleNamespace(celery_app=types.SimpleNamespace())
sys.modules["tasks"] = types.SimpleNamespace(celery_app=types.SimpleNamespace(AsyncResult=_async_result_factory(parsing_task)))

rag_routes = _load_module("rag_routes_async_status_test", "routes/rag.py")
hunting_routes = _load_module("hunting_routes_async_status_test", "routes/hunting.py")
parsing_routes = _load_module("parsing_routes_async_status_test", "routes/parsing.py")
ioc_routes = _load_module("ioc_routes_async_status_test", "routes/iocs.py")

for module_name, original_module in _ORIGINAL_MODULES.items():
    if original_module is None:
        sys.modules.pop(module_name, None)
    else:
        sys.modules[module_name] = original_module


class AsyncStatusEnvelopeTestCase(unittest.TestCase):
    def test_rag_status_route_uses_canonical_processing_envelope(self):
        app = Flask(__name__)
        with app.test_request_context("/"):
            with patch.dict(
                sys.modules,
                {
                    "celery.result": types.SimpleNamespace(AsyncResult=_async_result_factory(rag_task)),
                    "tasks.celery_tasks": types.SimpleNamespace(celery_app=types.SimpleNamespace()),
                },
            ):
                response, status_code = rag_routes.get_task_status("rag-task-1")

        self.assertEqual(status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["success"], True)
        self.assertEqual(payload["task_id"], "rag-task-1")
        self.assertEqual(payload["state"], "processing")
        self.assertEqual(payload["status"], "processing")
        self.assertEqual(payload["message"], "Embedding events")

    def test_hunting_status_route_uses_canonical_failure_envelope(self):
        app = Flask(__name__)
        with app.test_request_context("/"):
            with patch.dict(
                sys.modules,
                {
                    "celery.result": types.SimpleNamespace(AsyncResult=_async_result_factory(hunting_task)),
                    "tasks.celery_tasks": types.SimpleNamespace(celery_app=types.SimpleNamespace()),
                },
            ):
                response, status_code = hunting_routes.get_noise_task_status("hunt-task-1")

        self.assertEqual(status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["success"], True)
        self.assertEqual(payload["task_id"], "hunt-task-1")
        self.assertEqual(payload["state"], "failed")
        self.assertEqual(payload["status"], "failed")
        self.assertEqual(payload["error"], "boom")

    def test_parsing_status_route_uses_canonical_success_envelope(self):
        app = Flask(__name__)
        with app.test_request_context("/"):
            with patch.object(parsing_routes, "_task_access_allowed", return_value=True), patch.dict(
                sys.modules,
                {
                    "tasks": types.SimpleNamespace(
                        celery_app=types.SimpleNamespace(AsyncResult=_async_result_factory(parsing_task))
                    ),
                },
            ):
                response, status_code = parsing_routes.get_task_status("parse-task-1")

        self.assertEqual(status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["success"], True)
        self.assertEqual(payload["task_id"], "parse-task-1")
        self.assertEqual(payload["state"], "completed")
        self.assertEqual(payload["status"], "completed")
        self.assertEqual(payload["result"], {"rows": 12})

    def test_ioc_tag_results_route_uses_canonical_failure_envelope(self):
        app = Flask(__name__)
        with app.test_request_context("/"):
            with patch.object(ioc_routes, "_task_access_allowed", return_value=True), patch.object(
                ioc_routes.Case, "get_by_uuid", return_value=types.SimpleNamespace(id=7)
            ), patch.dict(
                sys.modules,
                {
                    "celery.result": types.SimpleNamespace(AsyncResult=_async_result_factory(ioc_task)),
                    "tasks.celery_tasks": types.SimpleNamespace(celery_app=types.SimpleNamespace()),
                },
            ):
                response, status_code = ioc_routes.get_tag_artifacts_results("case-uuid", "ioc-task-1")

        self.assertEqual(status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["success"], True)
        self.assertEqual(payload["task_id"], "ioc-task-1")
        self.assertEqual(payload["state"], "failed")
        self.assertEqual(payload["status"], "failed")
        self.assertEqual(payload["error"], "tag failed")


if __name__ == "__main__":
    unittest.main()
