import importlib.util
import json
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
    "celery.schedules",
    "redis",
    "tasks",
    "tasks.celery_tasks",
    "tasks.pcap_tasks",
    "utils.attack_pattern_loader",
    "utils.hunting_logger",
    "utils.pattern_sync_execution",
    "utils.pattern_sync_reporting",
    "utils.pattern_suppression",
]
_ORIGINAL_MODULES = {name: sys.modules.get(name) for name in _STUBBED_MODULE_NAMES}


class _FakeCeleryConfig(dict):
    def __init__(self):
        super().__init__()
        self.beat_schedule = {}

    def update(self, **kwargs):
        super().update(kwargs)


class _FakeCelery:
    def __init__(self, *_args, **_kwargs):
        self.conf = _FakeCeleryConfig()

    def task(self, *args, **kwargs):
        def decorator(func):
            return func

        return decorator


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

redis_module = types.ModuleType("redis")
redis_module.Redis = object
sys.modules["redis"] = redis_module

tasks_package = types.ModuleType("tasks")
tasks_package.__path__ = []
sys.modules["tasks"] = tasks_package
sys.modules["tasks.pcap_tasks"] = types.ModuleType("tasks.pcap_tasks")

attack_pattern_loader = types.ModuleType("utils.attack_pattern_loader")
attack_pattern_loader.OPENCTI_ATTACK_PATTERN_UPDATE_FIELDS = ()
attack_pattern_loader.SYNC_ATTACK_PATTERN_UPDATE_FIELDS = ()
attack_pattern_loader.apply_pattern_sync_result = lambda *args, **kwargs: None
attack_pattern_loader.build_attack_pattern_payload = lambda *args, **kwargs: {}
attack_pattern_loader.normalize_mitre_attack_pattern = lambda *args, **kwargs: {}
attack_pattern_loader.normalize_opencti_attack_pattern = lambda *args, **kwargs: {}
attack_pattern_loader.normalize_opencti_sigma_indicator = lambda *args, **kwargs: {}
attack_pattern_loader.persist_attack_pattern_payload = lambda *args, **kwargs: None
attack_pattern_loader.resolve_attack_pattern_lookup = lambda *args, **kwargs: None
attack_pattern_loader.save_synced_attack_pattern = lambda *args, **kwargs: None
sys.modules["utils.attack_pattern_loader"] = attack_pattern_loader

hunting_logger = types.ModuleType("utils.hunting_logger")
hunting_logger.HuntingLogger = object
hunting_logger.get_hunting_logger = lambda *_args, **_kwargs: types.SimpleNamespace(
    logger=types.SimpleNamespace(info=lambda *a, **k: None),
    log_start=lambda *a, **k: None,
    log_error=lambda *a, **k: None,
)
sys.modules["utils.hunting_logger"] = hunting_logger

pattern_sync_execution = types.ModuleType("utils.pattern_sync_execution")
pattern_sync_execution.build_external_sync_source_stage_runners = lambda *args, **kwargs: []
pattern_sync_execution.run_pattern_vector_update_stage = lambda *args, **kwargs: {}
sys.modules["utils.pattern_sync_execution"] = pattern_sync_execution

pattern_sync_reporting = types.ModuleType("utils.pattern_sync_reporting")
pattern_sync_reporting.get_default_external_sync_sources = lambda *args, **kwargs: []
pattern_sync_reporting.initialize_external_sync_stats = lambda *args, **kwargs: {}
pattern_sync_reporting.apply_external_source_sync_result = lambda *args, **kwargs: None
pattern_sync_reporting.run_external_sync_stage = lambda *args, **kwargs: {}
pattern_sync_reporting.build_mitre_sync_response = lambda *args, **kwargs: {}
pattern_sync_reporting.build_multi_source_sync_response = lambda *args, **kwargs: {}
pattern_sync_reporting.build_opencti_sync_response = lambda *args, **kwargs: {}
pattern_sync_reporting.finalize_rag_sync_log = lambda *args, **kwargs: None
pattern_sync_reporting.summarize_sync_errors = lambda *args, **kwargs: []
sys.modules["utils.pattern_sync_reporting"] = pattern_sync_reporting

pattern_suppression = types.ModuleType("utils.pattern_suppression")
pattern_suppression.PATTERN_SUPPRESSION_PRIORITY = {}
pattern_suppression.should_track_pattern_for_suppression = lambda *args, **kwargs: False
sys.modules["utils.pattern_suppression"] = pattern_suppression


def _load_module(module_name: str, relative_path: str):
    spec = importlib.util.spec_from_file_location(
        module_name,
        os.path.join(BASE_DIR, relative_path),
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


celery_tasks = _load_module("celery_tasks_remaining_failure_contract", "tasks/celery_tasks.py")
sys.modules["tasks.celery_tasks"] = celery_tasks
tasks_package.celery_tasks = celery_tasks
rag_tasks = _load_module("rag_tasks_remaining_failure_contract", "tasks/rag_tasks.py")

for module_name, original_module in _ORIGINAL_MODULES.items():
    if original_module is None:
        sys.modules.pop(module_name, None)
    else:
        sys.modules[module_name] = original_module


class _FakeRedis:
    def __init__(self):
        self.storage = {}

    def setex(self, key, _ttl, value):
        self.storage[key] = value


class _FakeApp:
    def app_context(self):
        return nullcontext()


class _FakeQuery:
    def __init__(self, obj):
        self.obj = obj

    def get(self, _record_id):
        return self.obj


class RemainingAsyncFailureContractTestCase(unittest.TestCase):
    def test_tag_iocs_task_raises_when_tagger_reports_failed_result(self):
        with patch.object(celery_tasks, "get_flask_app", return_value=_FakeApp()), patch.dict(
            sys.modules,
            {
                "models.case": types.SimpleNamespace(Case=types.SimpleNamespace(query=_FakeQuery(None))),
                "utils.ioc_artifact_tagger": types.SimpleNamespace(
                    tag_all_iocs_globally=lambda _case_id: {
                        "success": False,
                        "error": "commit failed",
                    }
                ),
            },
        ):
            with self.assertRaisesRegex(RuntimeError, "commit failed"):
                celery_tasks.tag_iocs_for_case(
                    types.SimpleNamespace(
                        request=types.SimpleNamespace(id="tag-task-1"),
                        update_state=lambda **_kwargs: None,
                    ),
                    11,
                )

    def test_find_iocs_task_raises_after_writing_failed_progress_payload(self):
        fake_redis = _FakeRedis()

        with patch.object(celery_tasks, "get_flask_app", return_value=_FakeApp()), patch.dict(
            sys.modules,
            {
                "redis": types.SimpleNamespace(Redis=lambda **_kwargs: fake_redis),
                "utils.clickhouse": types.SimpleNamespace(
                    get_fresh_client=lambda: (_ for _ in ()).throw(RuntimeError("clickhouse down"))
                ),
                "utils.ioc_extractor": types.SimpleNamespace(
                    process_extraction_for_import=lambda **_kwargs: {},
                    run_deterministic_ioc_extraction=lambda _raw: {},
                ),
                "models.ioc": types.SimpleNamespace(IOC=object),
            },
        ):
            with self.assertRaisesRegex(RuntimeError, "clickhouse down"):
                celery_tasks.find_iocs_in_events_task(
                    types.SimpleNamespace(request=types.SimpleNamespace(id="find-task-1")),
                    7,
                )

        progress = json.loads(fake_redis.storage["find_iocs_progress:7:find-task-1"])
        self.assertEqual(progress["status"], "failed")
        self.assertEqual(progress["error"], "clickhouse down")

    def test_extract_iocs_task_raises_after_writing_failed_progress_payload(self):
        fake_redis = _FakeRedis()
        fake_case = types.SimpleNamespace(id=5, uuid="case-uuid", edr_report="report one")

        with patch.object(celery_tasks, "get_flask_app", return_value=_FakeApp()), patch.dict(
            sys.modules,
            {
                "redis": types.SimpleNamespace(Redis=lambda **_kwargs: fake_redis),
                "models.case": types.SimpleNamespace(Case=types.SimpleNamespace(query=_FakeQuery(fake_case))),
                "utils.ioc_extractor": types.SimpleNamespace(
                    extract_iocs_with_ai=lambda _text: (_ for _ in ()).throw(RuntimeError("extract boom")),
                    get_report_preview=lambda text, _limit: text[:20],
                    process_extraction_for_import=lambda **_kwargs: {},
                    split_edr_reports=lambda _text: ["report one"],
                ),
            },
        ):
            with self.assertRaisesRegex(RuntimeError, "extract boom"):
                celery_tasks.extract_iocs_from_report_task(
                    types.SimpleNamespace(request=types.SimpleNamespace(id="extract-task-1")),
                    5,
                    "case-uuid",
                    0,
                )

        progress = json.loads(fake_redis.storage["ioc_extract_progress:5:extract-task-1"])
        self.assertEqual(progress["status"], "failed")
        self.assertEqual(progress["message"], "extract boom")
        self.assertEqual(progress["report_index"], 0)

    def test_run_case_analysis_raises_instead_of_returning_failed_payload(self):
        fake_case = types.SimpleNamespace(id=17)

        class FakeAnalysisError(Exception):
            pass

        class FakeAnalyzer:
            def __init__(self, _case_id, _progress_callback):
                self.failure_persisted = True

            def run_full_analysis(self):
                raise FakeAnalysisError("analysis exploded")

        with patch.object(rag_tasks, "get_flask_app", return_value=_FakeApp()), patch.dict(
            sys.modules,
            {
                "models.case": types.SimpleNamespace(Case=types.SimpleNamespace(query=_FakeQuery(fake_case))),
                "models.database": types.SimpleNamespace(db=types.SimpleNamespace(session=types.SimpleNamespace())),
                "utils.case_analyzer": types.SimpleNamespace(
                    CaseAnalyzer=FakeAnalyzer,
                    AnalysisError=FakeAnalysisError,
                ),
            },
        ):
            with self.assertRaisesRegex(RuntimeError, "analysis exploded"):
                rag_tasks.run_case_analysis(
                    types.SimpleNamespace(request=types.SimpleNamespace(id="analysis-task-1")),
                    17,
                )

    def test_rag_event_embedding_raises_for_invalid_scope_instead_of_returning_failed_payload(self):
        with patch.object(rag_tasks, "get_flask_app", return_value=_FakeApp()), patch.object(
            rag_tasks, "_acquire_event_embedding_lock", return_value=True
        ), patch.object(rag_tasks, "_release_event_embedding_lock"), patch.dict(
            sys.modules,
            {
                "utils.clickhouse": types.SimpleNamespace(get_fresh_client=lambda: None),
                "utils.rag_embeddings": types.SimpleNamespace(embed_texts=lambda *_args, **_kwargs: []),
                "utils.rag_vectorstore": types.SimpleNamespace(
                    get_qdrant_client=lambda: object(),
                    ensure_collection=lambda *_args, **_kwargs: True,
                ),
            },
        ):
            with self.assertRaisesRegex(RuntimeError, "Unsupported embedding scope: invalid"):
                rag_tasks.rag_embed_high_severity_events(
                    types.SimpleNamespace(
                        request=types.SimpleNamespace(id="embed-task-1"),
                        update_state=lambda **_kwargs: None,
                    ),
                    7,
                    "case-uuid",
                    scope="invalid",
                )


if __name__ == "__main__":
    unittest.main()
