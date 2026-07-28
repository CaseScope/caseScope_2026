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
attack_pattern_loader_module.save_synced_attack_pattern = lambda pattern, **kwargs: True
pattern_sync_execution_module = types.ModuleType('utils.pattern_sync_execution')
pattern_sync_execution_module.build_external_sync_source_stage_runners = lambda **kwargs: {}
pattern_sync_execution_module.ensure_git_checkout = lambda *args, **kwargs: None
pattern_sync_execution_module.load_opencti_sigma_indicators = lambda **kwargs: {'status': 'disabled', 'indicators': [], 'error_message': None}
pattern_sync_execution_module.run_pattern_vector_update_stage = lambda **kwargs: None
pattern_sync_execution_module.sync_repo_backed_patterns = lambda *args, **kwargs: None
pattern_sync_execution_module.sync_opencti_sigma_indicators = lambda *args, **kwargs: None
pattern_sync_execution_module.sync_patterns_from_directories = lambda *args, **kwargs: None
pattern_sync_reporting_module = types.ModuleType('utils.pattern_sync_reporting')
pattern_sync_reporting_module.begin_external_sync_stage = lambda source_name, **kwargs: {'stage': source_name, 'source_key': source_name, 'source_label': source_name}
pattern_sync_reporting_module.get_default_external_sync_sources = lambda: ['hayabusa', 'opencti_sigma']
pattern_sync_reporting_module.get_external_sync_source_config = lambda source_name: {'stage': source_name}
pattern_sync_reporting_module.initialize_external_sync_stats = lambda: {'errors': [], 'total_added': 0, 'total_updated': 0}
pattern_sync_reporting_module.apply_external_source_sync_result = lambda stats, **kwargs: None
pattern_sync_reporting_module.append_external_sync_stage_error = lambda stats, sync_config, **kwargs: None
pattern_sync_reporting_module.append_sync_error = lambda stats, **kwargs: None
pattern_sync_reporting_module.build_external_source_summary_message = lambda **kwargs: ''
pattern_sync_reporting_module.build_mitre_sync_response = lambda stats: {'success': True, 'stats': stats}
pattern_sync_reporting_module.build_multi_source_sync_response = lambda **kwargs: {'success': True, **kwargs}
pattern_sync_reporting_module.build_opencti_sync_response = lambda stats: {'success': True, 'synced': stats}
pattern_sync_reporting_module.build_sync_progress_meta = lambda **kwargs: dict(kwargs)
pattern_sync_reporting_module.finalize_rag_sync_log = lambda sync_log, **kwargs: None
pattern_sync_reporting_module.log_external_sync_stage_summary = lambda sync_config, stats, **kwargs: None
pattern_sync_reporting_module.run_external_sync_stage = lambda source_name, **kwargs: {'stage': source_name}
pattern_sync_reporting_module.summarize_sync_errors = lambda errors, **kwargs: None
pattern_suppression_module = types.ModuleType('utils.pattern_suppression')
pattern_suppression_module.PATTERN_SUPPRESSION_PRIORITY = {}
pattern_suppression_module.build_confirmed_pattern_entry = lambda *args, **kwargs: {}
pattern_suppression_module.get_pattern_suppression_matches = lambda *args, **kwargs: []
pattern_suppression_module.should_track_pattern_for_suppression = lambda *args, **kwargs: False
stateful_detectors_module = types.ModuleType('utils.stateful_detectors')
stateful_detectors_module.GapDetectionManager = object
utils_package.hunting_logger = hunting_logger_module
utils_package.finding_contract = finding_contract_module
utils_package.attack_pattern_loader = attack_pattern_loader_module
utils_package.pattern_sync_execution = pattern_sync_execution_module
utils_package.pattern_sync_reporting = pattern_sync_reporting_module
utils_package.pattern_suppression = pattern_suppression_module
utils_package.stateful_detectors = stateful_detectors_module
sys.modules.setdefault('utils', utils_package)
sys.modules['utils.hunting_logger'] = hunting_logger_module
sys.modules['utils.finding_contract'] = finding_contract_module
sys.modules['utils.attack_pattern_loader'] = attack_pattern_loader_module
sys.modules['utils.pattern_sync_execution'] = pattern_sync_execution_module
sys.modules['utils.pattern_sync_reporting'] = pattern_sync_reporting_module
sys.modules['utils.pattern_suppression'] = pattern_suppression_module
sys.modules['utils.stateful_detectors'] = stateful_detectors_module

module_path = os.path.join(REPO_ROOT, 'tasks', 'rag_tasks.py')
spec = importlib.util.spec_from_file_location('rag_tasks_under_test', module_path)
rag_tasks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rag_tasks)


class RAGAutoEmbeddingRegressionTestCase(unittest.TestCase):
    def test_high_priority_scope_includes_crit_normalization(self):
        conditions, parameters = rag_tasks._build_event_embedding_conditions('high_priority')

        self.assertEqual(parameters, {})
        level_condition = next(c for c in conditions if 'rule_level' in c)
        self.assertIn("'crit'", level_condition)
        self.assertIn("'critical'", level_condition)
        self.assertIn("'high'", level_condition)

    def test_every_scope_excludes_effective_noise(self):
        for scope in rag_tasks.EVENT_EMBEDDING_SCOPES:
            conditions, _ = rag_tasks._build_event_embedding_conditions(
                scope,
                time_start='2026-04-02T00:00:00Z',
                time_end='2026-04-02T01:00:00Z',
            )
            self.assertTrue(
                any('noise' in condition for condition in conditions),
                f'scope {scope} does not exclude noise',
            )

    def test_time_range_scope_builds_bounded_timestamp_filters(self):
        conditions, parameters = rag_tasks._build_event_embedding_conditions(
            'time_range',
            time_start='2026-04-02T00:00:00Z',
            time_end='2026-04-02T01:00:00Z',
        )

        normalized_conditions = [condition.replace('e.', '') for condition in conditions]
        self.assertIn('timestamp_utc >= parseDateTimeBestEffort({time_start:String})', normalized_conditions)
        self.assertIn('timestamp_utc <= parseDateTimeBestEffort({time_end:String})', normalized_conditions)
        self.assertEqual(parameters['time_start'], '2026-04-02T00:00:00Z')
        self.assertEqual(parameters['time_end'], '2026-04-02T01:00:00Z')

    def test_event_point_ids_are_stable_and_scope_specific(self):
        first = rag_tasks._build_event_vector_point_id(7, 'ioc_tagged', 'evtx:sec.evtx:12345')
        second = rag_tasks._build_event_vector_point_id(7, 'ioc_tagged', 'evtx:sec.evtx:12345')
        other_scope = rag_tasks._build_event_vector_point_id(7, 'high_priority', 'evtx:sec.evtx:12345')

        self.assertEqual(first, second)
        self.assertNotEqual(first, other_scope)
        self.assertIsInstance(first, int)

    def test_event_point_ids_separate_events_sharing_a_record_id(self):
        """record_id repeats across files and is null for non-EVTX artifacts.

        Keying points on it collapsed distinct events onto one vector, so the
        identity must come from selector_key instead.
        """
        first = rag_tasks._build_event_vector_point_id(7, 'high_priority', 'evtx:sec.evtx:100')
        second = rag_tasks._build_event_vector_point_id(7, 'high_priority', 'evtx:sys.evtx:100')

        self.assertNotEqual(first, second)

    def test_event_records_are_deduplicated_by_embedding_text(self):
        rows = [
            ('sel-1', 1, None, '4625', 'Security', 'HOST', 'user', 'Failed logon', 'high', None, None, [], []),
            ('sel-2', 2, None, '4625', 'Security', 'HOST', 'user', 'Failed logon', 'high', None, None, [], []),
            ('sel-3', 3, None, '4624', 'Security', 'HOST', 'user', 'Logon', 'high', None, None, [], []),
        ]

        events_data, event_texts = rag_tasks._build_event_embedding_records(
            rows,
            case_id=7,
            case_uuid='uuid-7',
            scope='high_priority',
            embedded_at='2026-04-02T00:00:00',
        )

        self.assertEqual(len(event_texts), 2)
        self.assertEqual(len(events_data), 2)
        self.assertEqual(events_data[0]['duplicate_event_count'], 2)
        self.assertEqual(events_data[1]['duplicate_event_count'], 1)
        self.assertEqual(events_data[0]['selector_key'], 'sel-1')

    def test_rag_task_uses_scope_cleanup_instead_of_collection_rebuild(self):
        task_path = os.path.join(REPO_ROOT, 'tasks', 'rag_tasks.py')
        with open(task_path, 'r', encoding='utf-8') as handle:
            content = handle.read()

        self.assertIn('_delete_scope_event_vectors(qdrant_client, collection_name, scope)', content)
        self.assertNotIn('qdrant_client.delete_collection(collection_name)', content)

    def test_rule_level_priority_accepts_hayabusa_abbreviations(self):
        """ClickHouse stores crit/med, not critical/medium."""
        sql = rag_tasks._build_rule_level_priority_sql('e')

        self.assertIn("e.rule_level IN ('crit', 'critical'), 1", sql)
        self.assertIn("e.rule_level = 'high', 2", sql)
        self.assertIn("e.rule_level IN ('med', 'medium'), 3", sql)

    def test_scope_refresh_writes_before_removing_superseded_vectors(self):
        """A failed upsert must not be able to leave a scope empty."""
        task_path = os.path.join(REPO_ROOT, 'tasks', 'rag_tasks.py')
        with open(task_path, 'r', encoding='utf-8') as handle:
            content = handle.read()

        body = content.split('def rag_embed_high_severity_events', 1)[1]
        upsert_position = body.index('Failed to upsert vectors')
        cleanup_position = body.index('_delete_superseded_scope_vectors(\n')

        self.assertLess(upsert_position, cleanup_position)

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
