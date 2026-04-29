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
    "kombu",
    "flask_login",
    "redis",
    "tasks",
    "tasks.celery_tasks",
    "tasks.pcap_tasks",
    "utils",
    "utils.archive_extraction",
    "utils.attack_pattern_loader",
    "utils.event_analyst_state",
    "utils.event_ioc_state",
    "utils.event_noise_state",
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

kombu_module = types.ModuleType("kombu")
kombu_module.Queue = lambda name, *args, **kwargs: types.SimpleNamespace(name=name)
sys.modules["kombu"] = kombu_module

flask_login_module = types.ModuleType("flask_login")
flask_login_module.current_user = types.SimpleNamespace(is_authenticated=True)
sys.modules["flask_login"] = flask_login_module

redis_module = types.ModuleType("redis")
redis_module.Redis = object
sys.modules["redis"] = redis_module

tasks_package = types.ModuleType("tasks")
tasks_package.__path__ = []
sys.modules["tasks"] = tasks_package
sys.modules["tasks.pcap_tasks"] = types.ModuleType("tasks.pcap_tasks")

utils_package = types.ModuleType("utils")
utils_package.__path__ = []
sys.modules["utils"] = utils_package

archive_extraction = types.ModuleType("utils.archive_extraction")
archive_extraction.extract_zip_archive = lambda *args, **kwargs: {}
sys.modules["utils.archive_extraction"] = archive_extraction

event_analyst_state = types.ModuleType("utils.event_analyst_state")
event_analyst_state.build_analyst_projection = lambda *args, **kwargs: {}
event_analyst_state.ensure_event_analyst_state_table = lambda *args, **kwargs: None
sys.modules["utils.event_analyst_state"] = event_analyst_state

event_ioc_state = types.ModuleType("utils.event_ioc_state")
event_ioc_state.build_effective_has_ioc_clause = lambda *args, **kwargs: "1"
event_ioc_state.ensure_event_ioc_state_tables = lambda *args, **kwargs: None
sys.modules["utils.event_ioc_state"] = event_ioc_state

event_noise_state = types.ModuleType("utils.event_noise_state")
event_noise_state.build_effective_not_noise_clause = lambda *args, **kwargs: "1"
event_noise_state.ensure_event_noise_state_tables = lambda *args, **kwargs: None
event_noise_state.replace_legacy_noise_filter = lambda *args, **kwargs: ""
sys.modules["utils.event_noise_state"] = event_noise_state

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

    def filter_by(self, **_kwargs):
        return self

    def first(self):
        return self.obj


class _FakeDbSession:
    def commit(self):
        pass

    def rollback(self):
        pass


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
                "utils": types.ModuleType("utils"),
                "utils.clickhouse": types.SimpleNamespace(
                    get_fresh_client=lambda: (_ for _ in ()).throw(RuntimeError("clickhouse down"))
                ),
                "utils.event_ioc_state": types.SimpleNamespace(
                    build_effective_has_ioc_clause=lambda *args, **kwargs: "1",
                    ensure_event_ioc_state_tables=lambda *args, **kwargs: None,
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
                "models.database": types.SimpleNamespace(db=types.SimpleNamespace(session=_FakeDbSession())),
                "models.ioc_enhancement": types.SimpleNamespace(
                    CaseIOCEnhancementRun=types.SimpleNamespace(query=_FakeQuery(None)),
                    IOCEnhancementStatus=types.SimpleNamespace(PENDING="pending"),
                ),
                "utils.ioc_extractor": types.SimpleNamespace(
                    get_report_preview=lambda text, _limit: text[:20],
                    process_extraction_for_import=lambda **_kwargs: {},
                    run_deterministic_ioc_extraction=lambda _text: (_ for _ in ()).throw(RuntimeError("extract boom")),
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

    def test_extract_iocs_task_returns_deterministic_results_without_ai(self):
        fake_redis = _FakeRedis()
        fake_case = types.SimpleNamespace(id=5, uuid="case-uuid", edr_report="report one")
        calls = {"ai": 0, "deterministic": 0}

        def deterministic(_text):
            calls["deterministic"] += 1
            return {"iocs": {}, "raw_artifacts": {}, "extraction_summary": {}}

        def forbidden_ai(_text):
            calls["ai"] += 1
            raise AssertionError("AI should not run in the deterministic modal task")

        with patch.object(celery_tasks, "get_flask_app", return_value=_FakeApp()), patch.dict(
            sys.modules,
            {
                "redis": types.SimpleNamespace(Redis=lambda **_kwargs: fake_redis),
                "models.case": types.SimpleNamespace(Case=types.SimpleNamespace(query=_FakeQuery(fake_case))),
                "models.database": types.SimpleNamespace(db=types.SimpleNamespace(session=_FakeDbSession())),
                "models.ioc_enhancement": types.SimpleNamespace(
                    CaseIOCEnhancementRun=types.SimpleNamespace(query=_FakeQuery(None)),
                    IOCEnhancementStatus=types.SimpleNamespace(PENDING="pending"),
                ),
                "utils.ioc_extractor": types.SimpleNamespace(
                    extract_iocs_with_ai=forbidden_ai,
                    get_report_preview=lambda text, _limit: text[:20],
                    process_extraction_for_import=lambda **_kwargs: {
                        "extraction_summary": {"method": "regex_only"},
                        "iocs_to_import": [{"value": "evil.example", "ioc_type": "Domain"}],
                        "known_systems_results": [],
                        "known_users_results": [],
                        "mitre_indicators": [],
                    },
                    run_deterministic_ioc_extraction=deterministic,
                    split_edr_reports=lambda _text: ["report one"],
                ),
            },
        ):
            result = celery_tasks.extract_iocs_from_report_task(
                types.SimpleNamespace(request=types.SimpleNamespace(id="extract-task-2")),
                5,
                "case-uuid",
                0,
            )

        self.assertEqual(calls["deterministic"], 1)
        self.assertEqual(calls["ai"], 0)
        self.assertFalse(result["used_ai"])
        self.assertEqual(result["extraction_method"], "regex_only")
        self.assertEqual(result["iocs_to_import"][0]["value"], "evil.example")

    def test_enhance_iocs_task_stages_ai_only_candidates(self):
        fake_case = types.SimpleNamespace(id=5, uuid="case-uuid", edr_report="report one")

        class FakeRun:
            id = 99
            case_id = 5
            report_index = 0
            status = "pending"
            progress_percent = 0
            current_phase = ""
            model = None
            staged_candidates = []
            summary = {}

            def update_progress(self, phase, percent, status=None):
                self.current_phase = phase
                self.progress_percent = percent
                if status:
                    self.status = status

            def mark_completed(self, candidates, summary=None):
                self.status = "completed"
                self.progress_percent = 100
                self.staged_candidates = candidates
                self.summary = summary or {}

            def mark_failed(self, message):
                self.status = "failed"
                self.error_message = message

            def to_dict(self):
                return {
                    "id": self.id,
                    "status": self.status,
                    "staged_candidates": self.staged_candidates,
                    "summary": self.summary,
                }

        fake_run = FakeRun()

        def process_extraction_for_import(extraction, **_kwargs):
            if extraction.get("source") == "deterministic":
                return {"iocs_to_import": [{"value": "base.example", "ioc_type": "Domain"}]}
            return {
                "iocs_to_import": [
                    {"value": "base.example", "ioc_type": "Domain"},
                    {"value": "ai-only.example", "ioc_type": "Domain", "context": "AI review"},
                ]
            }

        with patch.object(celery_tasks, "get_flask_app", return_value=_FakeApp()), patch.dict(
            sys.modules,
            {
                "models.case": types.SimpleNamespace(Case=types.SimpleNamespace(query=_FakeQuery(fake_case))),
                "models.database": types.SimpleNamespace(db=types.SimpleNamespace(session=_FakeDbSession())),
                "models.ioc_enhancement": types.SimpleNamespace(
                    CaseIOCEnhancementRun=types.SimpleNamespace(query=_FakeQuery(fake_run)),
                    IOCEnhancementStatus=types.SimpleNamespace(RUNNING="running"),
                ),
                "utils.feature_availability": types.SimpleNamespace(
                    FeatureAvailability=types.SimpleNamespace(is_ai_enabled=lambda: True)
                ),
                "utils.ioc_extractor": types.SimpleNamespace(
                    extract_iocs_with_ai=lambda _text: (
                        {"source": "ai", "extraction_summary": {"method": "deterministic_plus_semantic", "model": "test-model"}},
                        True,
                    ),
                    process_extraction_for_import=process_extraction_for_import,
                    run_deterministic_ioc_extraction=lambda _text: {"source": "deterministic"},
                    split_edr_reports=lambda _text: ["report one"],
                ),
            },
        ):
            result = celery_tasks.enhance_iocs_from_report_task(
                types.SimpleNamespace(
                    request=types.SimpleNamespace(id="enhance-task-1"),
                    update_state=lambda **_kwargs: None,
                ),
                99,
                5,
                "case-uuid",
                0,
            )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(len(result["staged_candidates"]), 1)
        self.assertEqual(result["staged_candidates"][0]["value"], "ai-only.example")
        self.assertEqual(result["staged_candidates"][0]["review_status"], "pending")

    def test_run_case_analysis_raises_instead_of_returning_failed_payload(self):
        fake_case = types.SimpleNamespace(id=17)

        class FakeAnalysisError(Exception):
            pass

        class FakeAnalysisCancelled(Exception):
            pass

        class FakeAnalyzer:
            def __init__(self, _case_id, _progress_callback):
                self.failure_persisted = True
                self.analysis_id = "analysis-1"

            def run_full_analysis(self):
                raise FakeAnalysisError("analysis exploded")

        with patch.object(rag_tasks, "get_flask_app", return_value=_FakeApp()), patch.dict(
            sys.modules,
            {
                "models.case": types.SimpleNamespace(Case=types.SimpleNamespace(query=_FakeQuery(fake_case))),
                "models.database": types.SimpleNamespace(db=types.SimpleNamespace(session=types.SimpleNamespace())),
                "utils.case_analyzer": types.SimpleNamespace(
                    CaseAnalyzer=FakeAnalyzer,
                    AnalysisCancelled=FakeAnalysisCancelled,
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
