import os
import sys
import types
import unittest
import importlib.util
from unittest.mock import Mock, patch

from flask import Flask

os.environ.setdefault('SECRET_KEY', 'test-secret')

if 'clickhouse_connect' not in sys.modules:
    clickhouse_stub = types.ModuleType('clickhouse_connect')
    clickhouse_stub.get_client = lambda *args, **kwargs: None
    sys.modules['clickhouse_connect'] = clickhouse_stub

REPO_ROOT = os.path.dirname(os.path.dirname(__file__))


def _load_module(module_name, relative_path):
    spec = importlib.util.spec_from_file_location(
        module_name,
        os.path.join(REPO_ROOT, relative_path),
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


clickhouse_utils = _load_module('test_clickhouse_utils', os.path.join('utils', 'clickhouse.py'))
event_deduplication = _load_module('test_event_deduplication', os.path.join('utils', 'event_deduplication.py'))

utils_package = types.ModuleType('utils')
utils_package.clickhouse = clickhouse_utils
utils_package.event_deduplication = event_deduplication
sys.modules.setdefault('utils', utils_package)
sys.modules['utils.clickhouse'] = clickhouse_utils
sys.modules['utils.event_deduplication'] = event_deduplication

ROUTE_IMPORT_ERROR = None
TASK_IMPORT_ERROR = None

try:
    from routes import case_files as case_files_routes
except ImportError as exc:
    ROUTE_IMPORT_ERROR = exc
    case_files_routes = None

try:
    from tasks import celery_tasks
except ImportError as exc:
    TASK_IMPORT_ERROR = exc
    celery_tasks = None


class _FakeClickHouseClient:
    def __init__(self, *, fail_buffer=False):
        self.fail_buffer = fail_buffer
        self.commands = []

    def command(self, sql):
        self.commands.append(sql)
        if self.fail_buffer and 'events_buffer' in sql:
            raise RuntimeError("Table engine Buffer doesn't support mutations")


class ClickHouseDeleteContractTestCase(unittest.TestCase):
    def test_delete_case_events_waits_for_main_mutation_when_requested(self):
        client = _FakeClickHouseClient(fail_buffer=True)

        with patch.object(clickhouse_utils, 'wait_for_mutation_completion') as wait_mock:
            result = clickhouse_utils.delete_case_events(17, wait=True, client=client)

        self.assertTrue(result)
        self.assertEqual(
            client.commands,
            [
                'ALTER TABLE events DELETE WHERE case_id = 17',
                'ALTER TABLE events_buffer DELETE WHERE case_id = 17',
            ],
        )
        wait_mock.assert_called_once_with(
            'events',
            'DELETE WHERE case_id = 17',
            client=client,
        )


class EventDeduplicationSafetyTestCase(unittest.TestCase):
    def test_deduplicate_artifact_type_skips_when_auto_threshold_exceeded(self):
        config = event_deduplication.ArtifactDeduplicationConfig(
            artifact_type='evtx',
            unique_fields=['source_host', 'source_file', 'record_id'],
            description='Windows Event Logs',
        )
        client = Mock()

        with patch.object(event_deduplication, 'count_eligible_events_for_artifact', return_value=250001):
            with patch.object(event_deduplication, 'count_duplicates_for_artifact', return_value=42):
                result = event_deduplication.deduplicate_artifact_type(
                    client,
                    7,
                    config,
                    max_eligible_events=250000,
                )

        self.assertTrue(result['success'])
        self.assertTrue(result['skipped'])
        self.assertEqual(result['duplicates_found'], 42)
        self.assertEqual(result['duplicates_deleted'], 0)
        self.assertFalse(result['mutation_submitted'])
        self.assertFalse(result['mutation_completed'])
        client.command.assert_not_called()

    def test_deduplicate_case_events_reports_skipped_artifact_details(self):
        skipped_config = event_deduplication.ArtifactDeduplicationConfig(
            artifact_type='mft',
            unique_fields=['source_host'],
            description='MFT',
        )
        threshold_config = event_deduplication.ArtifactDeduplicationConfig(
            artifact_type='evtx',
            unique_fields=['source_host'],
            description='EVTX',
        )

        fake_client = Mock()
        fake_client.query.return_value.result_rows = [('mft', 12), ('evtx', 24)]

        with patch.object(event_deduplication, 'ARTIFACT_DEDUP_CONFIGS', [skipped_config, threshold_config]):
            with patch('utils.clickhouse.get_fresh_client', return_value=fake_client):
                with patch.object(
                    event_deduplication,
                    'deduplicate_artifact_type',
                    return_value={
                        'artifact_type': 'evtx',
                        'description': 'EVTX',
                        'eligible_events': 500000,
                        'duplicates_found': 10,
                        'duplicates_deleted': 0,
                        'success': True,
                        'skipped': True,
                        'skip_reason': 'eligible event count 500000 exceeds auto-dedup safety threshold 250000',
                        'mutation_submitted': False,
                        'mutation_completed': False,
                    },
                ):
                    result = event_deduplication.deduplicate_case_events(
                        case_id=9,
                        track_progress=False,
                        max_eligible_events_per_artifact=250000,
                    )

        self.assertTrue(result['success'])
        self.assertEqual(result['artifact_types_checked'], 2)
        self.assertEqual(result['artifact_types_skipped'], 2)
        self.assertEqual(result['total_duplicates_found'], 10)
        self.assertEqual(result['total_duplicates_deleted'], 0)
        self.assertEqual(len(result['skipped_details']), 2)
        self.assertIn('Skipped duplicate removal', result['message'])


class CompletionTaskContractTestCase(unittest.TestCase):
    def test_case_indexing_complete_reports_skipped_buffer_flush_and_passes_auto_dedup_threshold(self):
        if TASK_IMPORT_ERROR is not None:
            self.skipTest(f'task module dependencies unavailable: {TASK_IMPORT_ERROR}')
        app = Flask(__name__)
        app.secret_key = 'test-secret'

        clickhouse_client = Mock()
        clickhouse_client.command.side_effect = RuntimeError('buffer table unavailable')

        dedup_result = {
            'success': True,
            'total_duplicates_deleted': 0,
            'details': [],
            'skipped_details': [
                {
                    'artifact_type': 'evtx',
                    'skipped': True,
                    'skip_reason': 'eligible event count 500000 exceeds auto-dedup safety threshold 250000',
                }
            ],
            'message': 'Skipped duplicate removal for 1 artifact types due to safety limits',
        }

        case_file_query = Mock()
        case_file_query.filter.return_value.count.return_value = 0
        case_file_query.filter_by.return_value.all.return_value = []

        db_session = Mock()
        db_session.query.return_value.filter.return_value.group_by.return_value.having.return_value.all.return_value = []

        fake_case = types.SimpleNamespace(id=3, uuid='case-uuid')

        with patch.object(celery_tasks, 'get_flask_app', return_value=app):
            with patch.object(celery_tasks.case_indexing_complete_task, 'update_state'):
                with patch('utils.clickhouse.get_fresh_client', return_value=clickhouse_client):
                    with patch('utils.progress.set_phase'):
                        with patch('utils.progress.clear_progress'):
                            with patch('utils.progress.clear_completion_trigger'):
                                with patch('utils.event_deduplication.deduplicate_case_events', return_value=dedup_result) as dedup_mock:
                                    with patch('utils.known_systems_discovery.discover_known_systems', return_value={'systems_created': 0, 'systems_updated': 0}):
                                        with patch('utils.known_users_discovery.discover_known_users', return_value={'users_created': 0, 'users_updated': 0}):
                                            with patch('models.case_file.CaseFile.query', case_file_query):
                                                with patch('models.database.db.session', db_session):
                                                    with patch('models.case.Case.get_by_uuid_unchecked', return_value=fake_case):
                                                        with patch.object(celery_tasks, '_build_case_ingest_summary', return_value={}):
                                                            with patch('models.audit_log.AuditLog.log'):
                                                                with patch.object(celery_tasks, '_queue_auto_event_embedding', return_value='embed-task'):
                                                                    result = celery_tasks.case_indexing_complete_task.run(
                                                                        case_id=3,
                                                                        case_uuid='case-uuid',
                                                                    )

        self.assertFalse(result['buffer_flushed'])
        self.assertEqual(result['buffer_flush_status'], 'skipped')
        self.assertEqual(result['dedup_skipped_details'], dedup_result['skipped_details'])
        self.assertEqual(result['dedup_message'], dedup_result['message'])
        dedup_mock.assert_called_once_with(
            case_id=3,
            case_uuid='case-uuid',
            track_progress=True,
            max_eligible_events_per_artifact=event_deduplication.AUTO_DEDUP_MAX_ELIGIBLE_EVENTS,
        )


class ManualDedupRouteContractTestCase(unittest.TestCase):
    def setUp(self):
        if ROUTE_IMPORT_ERROR is not None:
            self.skipTest(f'route module dependencies unavailable: {ROUTE_IMPORT_ERROR}')
        self.app = Flask(__name__)
        self.app.secret_key = 'test-secret'

    def test_remove_duplicate_events_returns_skipped_details(self):
        case = types.SimpleNamespace(id=7, uuid='case-uuid')
        result_payload = {
            'success': True,
            'artifact_types_checked': 2,
            'artifact_types_skipped': 1,
            'total_duplicates_found': 18,
            'total_duplicates_deleted': 12,
            'details': [{'artifact_type': 'evtx', 'duplicates_deleted': 12}],
            'skipped_details': [{'artifact_type': 'mft', 'skip_reason': 'artifact type is excluded from automatic deduplication due to high memory risk'}],
            'message': 'Removed 12 duplicate events across 1 artifact types; skipped 1 artifact types due to safety limits',
            'errors': None,
        }

        with self.app.test_request_context('/api/events/duplicates/remove/case-uuid', method='POST', json={}):
            with patch.object(case_files_routes, 'current_user', types.SimpleNamespace(permission_level='analyst')):
                with patch.object(case_files_routes.Case, 'get_by_uuid', return_value=case):
                    with patch.object(case_files_routes, '_require_case_write_access', return_value=None):
                        with patch('utils.event_deduplication.deduplicate_case_events', return_value=result_payload) as dedup_mock:
                            response = case_files_routes.remove_duplicate_events.__wrapped__('case-uuid')

        payload = response.get_json()
        self.assertTrue(payload['success'])
        self.assertEqual(payload['artifact_types_skipped'], 1)
        self.assertEqual(payload['skipped_details'], result_payload['skipped_details'])
        dedup_mock.assert_called_once_with(
            case_id=7,
            case_uuid='case-uuid',
            track_progress=False,
            max_eligible_events_per_artifact=None,
        )


if __name__ == '__main__':
    unittest.main()
