import importlib.util
import os
import sys
import types
from contextlib import nullcontext


BASE_DIR = os.path.dirname(os.path.dirname(__file__))
os.environ.setdefault("SECRET_KEY", "test-secret")


class _FakeCeleryApp:
    def task(self, *args, **kwargs):
        def decorator(func):
            return func

        return decorator


class FakeApp:
    def app_context(self):
        return nullcontext()


def _load_module(module_name: str, relative_path: str):
    spec = importlib.util.spec_from_file_location(
        module_name,
        os.path.join(BASE_DIR, relative_path),
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def load_rag_tasks_with_stubs(module_name: str):
    fake_tasks = types.ModuleType("tasks")
    fake_tasks.__path__ = []

    fake_celery_tasks = types.ModuleType("tasks.celery_tasks")
    fake_celery_tasks.celery_app = _FakeCeleryApp()
    fake_celery_tasks.get_flask_app = lambda: FakeApp()
    fake_tasks.celery_tasks = fake_celery_tasks

    fake_event_ioc_state = types.ModuleType("utils.event_ioc_state")
    fake_event_ioc_state.build_effective_has_ioc_clause = lambda *args, **kwargs: "1"

    fake_event_noise_state = types.ModuleType("utils.event_noise_state")
    fake_event_noise_state.build_effective_not_noise_clause = lambda *args, **kwargs: "1"
    fake_event_noise_state.ensure_event_noise_state_tables = lambda *args, **kwargs: None
    fake_event_noise_state.replace_legacy_noise_filter = lambda query, *args, **kwargs: query

    fake_attack_pattern_loader = types.ModuleType("utils.attack_pattern_loader")
    fake_attack_pattern_loader.OPENCTI_ATTACK_PATTERN_UPDATE_FIELDS = ()
    fake_attack_pattern_loader.SYNC_ATTACK_PATTERN_UPDATE_FIELDS = ()
    fake_attack_pattern_loader.apply_pattern_sync_result = lambda *args, **kwargs: None
    fake_attack_pattern_loader.build_attack_pattern_payload = lambda *args, **kwargs: {}
    fake_attack_pattern_loader.normalize_mitre_attack_pattern = lambda *args, **kwargs: {}
    fake_attack_pattern_loader.normalize_opencti_attack_pattern = lambda *args, **kwargs: {}
    fake_attack_pattern_loader.normalize_opencti_sigma_indicator = lambda *args, **kwargs: {}
    fake_attack_pattern_loader.persist_attack_pattern_payload = lambda *args, **kwargs: None
    fake_attack_pattern_loader.resolve_attack_pattern_lookup = lambda *args, **kwargs: {}
    fake_attack_pattern_loader.save_synced_attack_pattern = lambda *args, **kwargs: None

    fake_hunting_logger = types.ModuleType("utils.hunting_logger")
    fake_hunting_logger.HuntingLogger = object
    fake_hunting_logger.get_hunting_logger = lambda *args, **kwargs: types.SimpleNamespace(
        logger=types.SimpleNamespace(
            info=lambda *a, **k: None,
            warning=lambda *a, **k: None,
            error=lambda *a, **k: None,
        ),
        log_start=lambda *a, **k: None,
        log_error=lambda *a, **k: None,
        log_complete=lambda *a, **k: None,
    )

    fake_pattern_sync_execution = types.ModuleType("utils.pattern_sync_execution")
    fake_pattern_sync_execution.build_external_sync_source_stage_runners = lambda *args, **kwargs: []
    fake_pattern_sync_execution.run_pattern_vector_update_stage = lambda *args, **kwargs: {}

    fake_pattern_sync_reporting = types.ModuleType("utils.pattern_sync_reporting")
    fake_pattern_sync_reporting.get_default_external_sync_sources = lambda *args, **kwargs: []
    fake_pattern_sync_reporting.initialize_external_sync_stats = lambda *args, **kwargs: {}
    fake_pattern_sync_reporting.apply_external_source_sync_result = lambda *args, **kwargs: None
    fake_pattern_sync_reporting.run_external_sync_stage = lambda *args, **kwargs: {}
    fake_pattern_sync_reporting.build_mitre_sync_response = lambda *args, **kwargs: {}
    fake_pattern_sync_reporting.build_multi_source_sync_response = lambda *args, **kwargs: {}
    fake_pattern_sync_reporting.build_opencti_sync_response = lambda *args, **kwargs: {}
    fake_pattern_sync_reporting.finalize_rag_sync_log = lambda *args, **kwargs: None
    fake_pattern_sync_reporting.summarize_sync_errors = lambda *args, **kwargs: []

    fake_pattern_suppression = types.ModuleType("utils.pattern_suppression")
    fake_pattern_suppression.PATTERN_SUPPRESSION_PRIORITY = {}
    fake_pattern_suppression.should_track_pattern_for_suppression = lambda *args, **kwargs: False

    stubbed_modules = {
        "tasks": fake_tasks,
        "tasks.celery_tasks": fake_celery_tasks,
        "utils.event_ioc_state": fake_event_ioc_state,
        "utils.event_noise_state": fake_event_noise_state,
        "utils.attack_pattern_loader": fake_attack_pattern_loader,
        "utils.hunting_logger": fake_hunting_logger,
        "utils.pattern_sync_execution": fake_pattern_sync_execution,
        "utils.pattern_sync_reporting": fake_pattern_sync_reporting,
        "utils.pattern_suppression": fake_pattern_suppression,
    }
    original_modules = {name: sys.modules.get(name) for name in stubbed_modules}

    for name, module in stubbed_modules.items():
        sys.modules[name] = module

    rag_tasks = _load_module(module_name, "tasks/rag_tasks.py")

    def restore_modules():
        sys.modules.pop(module_name, None)
        for name, previous in original_modules.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous

    return rag_tasks, restore_modules
