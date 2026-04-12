import importlib.util
import os
import sys
import types
import unittest


os.environ.setdefault('SECRET_KEY', 'test-secret')

REPO_ROOT = os.path.dirname(os.path.dirname(__file__))


class _DummyCeleryApp:
    def task(self, *args, **kwargs):
        def decorator(func):
            return func
        return decorator


tasks_package = types.ModuleType('tasks')
celery_tasks_module = types.ModuleType('tasks.celery_tasks')
celery_tasks_module.celery_app = _DummyCeleryApp()
celery_tasks_module.get_flask_app = lambda: None
tasks_package.celery_tasks = celery_tasks_module
sys.modules.setdefault('tasks', tasks_package)
sys.modules['tasks.celery_tasks'] = celery_tasks_module

utils_package = types.ModuleType('utils')
utils_package.__path__ = []
hunting_logger_module = types.ModuleType('utils.hunting_logger')
hunting_logger_module.HuntingLogger = object
hunting_logger_module.get_hunting_logger = lambda *args, **kwargs: None
finding_contract_module = types.ModuleType('utils.finding_contract')
finding_contract_module.build_deterministic_analysis_artifacts = lambda **kwargs: {}
finding_contract_module.finalize_deterministic_package = lambda *args, **kwargs: {}
finding_contract_module.severity_from_confidence = lambda value: 'medium'
attack_pattern_loader_module = types.ModuleType('utils.attack_pattern_loader')
attack_pattern_loader_module.OPENCTI_ATTACK_PATTERN_UPDATE_FIELDS = ()
attack_pattern_loader_module.SYNC_ATTACK_PATTERN_UPDATE_FIELDS = ()
attack_pattern_loader_module.apply_pattern_sync_result = lambda stats, **kwargs: None
attack_pattern_loader_module.build_attack_pattern_payload = lambda pattern, **kwargs: dict(pattern)
attack_pattern_loader_module.normalize_mitre_attack_pattern = lambda pattern: dict(pattern)
attack_pattern_loader_module.normalize_opencti_attack_pattern = lambda pattern: dict(pattern)
attack_pattern_loader_module.normalize_opencti_sigma_indicator = lambda indicator: dict(indicator)
attack_pattern_loader_module.persist_attack_pattern_payload = (
    lambda existing, payload, **kwargs: (existing is None, existing or payload)
)
attack_pattern_loader_module.resolve_attack_pattern_lookup = lambda pattern: dict(pattern)
pattern_sync_reporting_module = types.ModuleType('utils.pattern_sync_reporting')
pattern_sync_reporting_module.apply_external_source_sync_result = lambda stats, **kwargs: None
pattern_sync_reporting_module.append_sync_error = lambda stats, **kwargs: None
pattern_sync_reporting_module.build_external_source_summary_message = lambda **kwargs: ''
pattern_sync_reporting_module.build_mitre_sync_response = lambda stats: {'success': True, 'stats': stats}
pattern_sync_reporting_module.build_multi_source_sync_response = lambda **kwargs: {'success': True, **kwargs}
pattern_sync_reporting_module.build_opencti_sync_response = lambda stats: {'success': True, 'synced': stats}
pattern_sync_reporting_module.build_sync_progress_meta = lambda **kwargs: dict(kwargs)
pattern_sync_reporting_module.finalize_rag_sync_log = lambda sync_log, **kwargs: None
pattern_sync_reporting_module.summarize_sync_errors = lambda errors, **kwargs: None
utils_package.hunting_logger = hunting_logger_module
utils_package.finding_contract = finding_contract_module
utils_package.attack_pattern_loader = attack_pattern_loader_module
utils_package.pattern_sync_reporting = pattern_sync_reporting_module
sys.modules.setdefault('utils', utils_package)
sys.modules['utils.hunting_logger'] = hunting_logger_module
sys.modules['utils.finding_contract'] = finding_contract_module
sys.modules['utils.attack_pattern_loader'] = attack_pattern_loader_module
sys.modules['utils.pattern_sync_reporting'] = pattern_sync_reporting_module

module_path = os.path.join(REPO_ROOT, 'tasks', 'rag_tasks.py')
spec = importlib.util.spec_from_file_location('rag_tasks_under_test', module_path)
rag_tasks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rag_tasks)


class RAGAutoEmbeddingRegressionTestCase(unittest.TestCase):
    def test_high_priority_scope_includes_crit_normalization(self):
        conditions, parameters = rag_tasks._build_event_embedding_conditions('high_priority')

        self.assertEqual(parameters, {})
        self.assertEqual(len(conditions), 1)
        self.assertIn("'crit'", conditions[0])
        self.assertIn("'critical'", conditions[0])
        self.assertIn("'high'", conditions[0])

    def test_time_range_scope_builds_bounded_timestamp_filters(self):
        conditions, parameters = rag_tasks._build_event_embedding_conditions(
            'time_range',
            time_start='2026-04-02T00:00:00Z',
            time_end='2026-04-02T01:00:00Z',
        )

        self.assertEqual(len(conditions), 2)
        self.assertIn('timestamp_utc >= parseDateTimeBestEffort({time_start:String})', conditions)
        self.assertIn('timestamp_utc <= parseDateTimeBestEffort({time_end:String})', conditions)
        self.assertEqual(parameters['time_start'], '2026-04-02T00:00:00Z')
        self.assertEqual(parameters['time_end'], '2026-04-02T01:00:00Z')

    def test_event_point_ids_are_stable_and_scope_specific(self):
        first = rag_tasks._build_event_vector_point_id(7, 'ioc_tagged', 12345)
        second = rag_tasks._build_event_vector_point_id(7, 'ioc_tagged', 12345)
        other_scope = rag_tasks._build_event_vector_point_id(7, 'high_priority', 12345)

        self.assertEqual(first, second)
        self.assertNotEqual(first, other_scope)
        self.assertIsInstance(first, int)

    def test_rag_task_uses_scope_cleanup_instead_of_collection_rebuild(self):
        task_path = os.path.join(REPO_ROOT, 'tasks', 'rag_tasks.py')
        with open(task_path, 'r', encoding='utf-8') as handle:
            content = handle.read()

        self.assertIn('_delete_scope_event_vectors(qdrant_client, collection_name, scope)', content)
        self.assertIn("multiIf(rule_level IN ('crit', 'critical'), 1, rule_level = 'high', 2, 3)", content)
        self.assertNotIn('qdrant_client.delete_collection(collection_name)', content)

    def test_celery_tasks_queue_ioc_and_post_ingest_auto_embedding(self):
        task_path = os.path.join(REPO_ROOT, 'tasks', 'celery_tasks.py')
        with open(task_path, 'r', encoding='utf-8') as handle:
            content = handle.read()

        self.assertIn("scope='ioc_tagged'", content)
        self.assertIn("source='ioc_tagging'", content)
        self.assertIn("scope='high_priority'", content)
        self.assertIn("source='post_ingest_completion'", content)


if __name__ == '__main__':
    unittest.main()
