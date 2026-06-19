"""Shared dependency stubs for unittest discovery.

The fakes in this module are intentionally small and are installed only when
the corresponding real dependency is not importable in the test environment.
"""

from __future__ import annotations

import importlib.util
import builtins
import os
import sys
import types
from contextlib import nullcontext
from unittest.mock import MagicMock


os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("TESTING", "1")

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
_REAL_PACKAGE_PATHS = {
    "models": os.path.join(_REPO_ROOT, "models"),
    "parsers": os.path.join(_REPO_ROOT, "parsers"),
    "pipeline": os.path.join(_REPO_ROOT, "pipeline"),
    "routes": os.path.join(_REPO_ROOT, "routes"),
    "tasks": os.path.join(_REPO_ROOT, "tasks"),
    "utils": os.path.join(_REPO_ROOT, "utils"),
}
_ORIGINAL_IMPORT = None


def _is_importable(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def _install_module(name: str, module: types.ModuleType) -> types.ModuleType:
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    sys.modules[name] = module
    return module


def _ensure_real_package_path(name: str) -> None:
    root = name.split(".", 1)[0]
    package_path = _REAL_PACKAGE_PATHS.get(root)
    if not package_path:
        return

    package = sys.modules.get(root)
    if not isinstance(package, types.ModuleType):
        return

    current_path = list(getattr(package, "__path__", []) or [])
    if package_path not in current_path:
        current_path.append(package_path)
        package.__path__ = current_path


def _augment_known_fake_modules() -> None:
    clickhouse = sys.modules.get("utils.clickhouse")
    if isinstance(clickhouse, types.ModuleType):
        clickhouse.clickhouse_bool_literal = getattr(
            clickhouse,
            "clickhouse_bool_literal",
            lambda value: "true" if value else "false",
        )
        clickhouse.clickhouse_nullable_string_literal = getattr(
            clickhouse,
            "clickhouse_nullable_string_literal",
            lambda value: "NULL" if value is None else repr(value),
        )
        clickhouse.clickhouse_string_array_literal = getattr(
            clickhouse,
            "clickhouse_string_array_literal",
            lambda values: "[" + ",".join(repr(v) for v in values) + "]",
        )
        clickhouse.clickhouse_string_literal = getattr(
            clickhouse,
            "clickhouse_string_literal",
            lambda value: repr(value),
        )
        clickhouse.get_client = getattr(clickhouse, "get_client", lambda *args, **kwargs: None)
        clickhouse.get_fresh_client = getattr(clickhouse, "get_fresh_client", lambda *args, **kwargs: None)
        clickhouse.run_events_update = getattr(clickhouse, "run_events_update", lambda *args, **kwargs: None)
        clickhouse.wait_for_mutation_completion = getattr(
            clickhouse,
            "wait_for_mutation_completion",
            lambda *args, **kwargs: None,
        )


def install_import_path_guard() -> None:
    """Allow real submodule imports under fake test packages."""

    global _ORIGINAL_IMPORT
    if _ORIGINAL_IMPORT is not None:
        return

    _ORIGINAL_IMPORT = builtins.__import__

    def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0:
            _ensure_real_package_path(name)
            _augment_known_fake_modules()
        return _ORIGINAL_IMPORT(name, globals, locals, fromlist, level)

    builtins.__import__ = guarded_import


class _DynamicModule(types.ModuleType):
    def __getattr__(self, name):
        value = MagicMock(name=f"{self.__name__}.{name}")
        setattr(self, name, value)
        return value


class _FakeFlaskApp:
    def __init__(self, *args, **kwargs):
        self.config = {}
        self.extensions = {}
        self.blueprints = {}
        self.before_request_funcs = {}
        self.after_request_funcs = {}
        self.teardown_request_funcs = {}
        self.jinja_env = types.SimpleNamespace(filters={}, globals={})

    def app_context(self):
        return nullcontext()

    def test_request_context(self, *args, **kwargs):
        return nullcontext()

    def route(self, *args, **kwargs):
        return lambda func: func

    def before_request(self, func):
        return func

    def after_request(self, func):
        return func

    def errorhandler(self, *args, **kwargs):
        return lambda func: func

    def context_processor(self, func):
        return func

    def template_filter(self, *args, **kwargs):
        return lambda func: func

    def register_blueprint(self, blueprint, *args, **kwargs):
        self.blueprints[getattr(blueprint, "name", str(blueprint))] = blueprint


class _FakeBlueprint:
    def __init__(self, name, import_name=None, *args, **kwargs):
        self.name = name
        self.import_name = import_name

    def route(self, *args, **kwargs):
        return lambda func: func

    def before_request(self, func):
        return func

    def after_request(self, func):
        return func

    def errorhandler(self, *args, **kwargs):
        return lambda func: func


class _FakeCelery:
    def __init__(self, *args, **kwargs):
        self.conf = {}

    def task(self, *args, **kwargs):
        if args and callable(args[0]) and not kwargs:
            return args[0]
        return lambda func: func

    def config_from_object(self, *args, **kwargs):
        return None

    def autodiscover_tasks(self, *args, **kwargs):
        return None


class _FakeClickHouseClient:
    def query(self, *args, **kwargs):
        return types.SimpleNamespace(result_rows=[], result_columns=[], column_names=[])

    def query_df(self, *args, **kwargs):
        return []

    def command(self, *args, **kwargs):
        return None

    def insert(self, *args, **kwargs):
        return None

    def close(self):
        return None


def _install_flask_stub() -> None:
    if _is_importable("flask"):
        return

    flask = _DynamicModule("flask")
    flask.__path__ = []
    flask.Flask = _FakeFlaskApp
    flask.Blueprint = _FakeBlueprint
    flask.current_app = _FakeFlaskApp()
    flask.g = types.SimpleNamespace()
    flask.request = types.SimpleNamespace(args={}, form={}, json=None, method="GET")
    flask.session = {}
    flask.has_request_context = lambda: False
    flask.has_app_context = lambda: False
    flask.jsonify = lambda *args, **kwargs: kwargs if kwargs else list(args)
    flask.redirect = lambda location, *args, **kwargs: location
    flask.url_for = lambda endpoint, **values: endpoint
    flask.render_template = lambda template, **context: template
    flask.flash = lambda *args, **kwargs: None
    flask.abort = lambda code, *args, **kwargs: (_ for _ in ()).throw(Exception(code))
    flask.send_file = lambda *args, **kwargs: None
    flask.make_response = lambda value=None, *args, **kwargs: value
    _install_module("flask", flask)


def _install_celery_stub() -> None:
    if _is_importable("celery"):
        return

    celery = _DynamicModule("celery")
    celery.__path__ = []
    celery.Celery = _FakeCelery
    celery.current_app = _FakeCelery()
    celery.shared_task = lambda *args, **kwargs: (args[0] if args and callable(args[0]) else lambda func: func)
    _install_module("celery", celery)

    exceptions = types.ModuleType("celery.exceptions")
    exceptions.SoftTimeLimitExceeded = type("SoftTimeLimitExceeded", (Exception,), {})
    exceptions.TimeoutError = TimeoutError
    _install_module("celery.exceptions", exceptions)

    states = types.ModuleType("celery.states")
    states.SUCCESS = "SUCCESS"
    states.FAILURE = "FAILURE"
    states.PENDING = "PENDING"
    states.STARTED = "STARTED"
    _install_module("celery.states", states)


def _install_clickhouse_stub() -> None:
    if _is_importable("clickhouse_connect"):
        return

    clickhouse = _DynamicModule("clickhouse_connect")
    clickhouse.get_client = lambda *args, **kwargs: _FakeClickHouseClient()
    _install_module("clickhouse_connect", clickhouse)

    driver = types.ModuleType("clickhouse_connect.driver")
    _install_module("clickhouse_connect.driver", driver)

    exceptions = types.ModuleType("clickhouse_connect.driver.exceptions")
    exceptions.ClickHouseError = type("ClickHouseError", (Exception,), {})
    exceptions.OperationalError = type("OperationalError", (Exception,), {})
    _install_module("clickhouse_connect.driver.exceptions", exceptions)


def _install_qdrant_stub() -> None:
    if _is_importable("qdrant_client"):
        return

    qdrant = _DynamicModule("qdrant_client")
    qdrant.__path__ = []
    qdrant.QdrantClient = MagicMock(name="QdrantClient")
    _install_module("qdrant_client", qdrant)

    models = _DynamicModule("qdrant_client.models")
    _install_module("qdrant_client.models", models)
    http = types.ModuleType("qdrant_client.http")
    http.__path__ = []
    _install_module("qdrant_client.http", http)
    http_models = _DynamicModule("qdrant_client.http.models")
    _install_module("qdrant_client.http.models", http_models)


def install_dependency_stubs() -> None:
    """Install all baseline optional dependency stubs idempotently."""

    install_import_path_guard()
    _install_flask_stub()
    _install_celery_stub()
    _install_clickhouse_stub()
    _install_qdrant_stub()
