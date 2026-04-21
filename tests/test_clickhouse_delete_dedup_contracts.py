import os
import sys
import types
import unittest
import importlib.util
from contextlib import nullcontext
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

utils_package = types.ModuleType('utils')
utils_package.clickhouse = clickhouse_utils
sys.modules.setdefault('utils', utils_package)
sys.modules['utils.clickhouse'] = clickhouse_utils

event_deduplication = _load_module('test_event_deduplication', os.path.join('utils', 'event_deduplication.py'))
utils_package.event_deduplication = event_deduplication
sys.modules['utils.event_deduplication'] = event_deduplication

network_log_module = _load_module('test_network_log_model', os.path.join('models', 'network_log.py'))

ROUTE_IMPORT_ERROR = None
TASK_IMPORT_ERROR = None
PARSING_ROUTE_IMPORT_ERROR = None

try:
    from routes import case_files as case_files_routes
except ImportError as exc:
    ROUTE_IMPORT_ERROR = exc
    case_files_routes = None

try:
    from routes import parsing as parsing_routes
except ImportError as exc:
    PARSING_ROUTE_IMPORT_ERROR = exc
    parsing_routes = None

PCAP_ROUTE_IMPORT_ERROR = None
PCAP_TASK_IMPORT_ERROR = None

try:
    from tasks import celery_tasks
except ImportError as exc:
    TASK_IMPORT_ERROR = exc
    celery_tasks = None

try:
    from routes import pcap as pcap_routes
except ImportError as exc:
    PCAP_ROUTE_IMPORT_ERROR = exc
    pcap_routes = None

try:
    from tasks import pcap_tasks
except ImportError as exc:
    PCAP_TASK_IMPORT_ERROR = exc
    pcap_tasks = None


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

        with patch.object(clickhouse_utils, 'destructive_event_rewrite_guard', return_value=nullcontext()):
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

    def test_delete_case_logs_waits_for_network_log_mutation_when_requested(self):
        client = _FakeClickHouseClient()

        with patch.object(network_log_module, 'get_client', return_value=client):
            with patch.object(network_log_module, 'destructive_network_log_rewrite_guard', return_value=nullcontext()):
                with patch.object(network_log_module, '_list_case_log_types', return_value=['dns', 'conn']):
                    with patch.object(network_log_module, '_wait_for_case_log_absence') as wait_absence_mock:
                        with patch.object(network_log_module, 'wait_for_mutation_completion') as wait_mock:
                            result = network_log_module.delete_case_logs(22, wait=True)

        self.assertTrue(result)
        self.assertEqual(
            client.commands,
            [
                "ALTER TABLE network_logs DROP PARTITION tuple(22, 'dns')",
                "ALTER TABLE network_logs DROP PARTITION tuple(22, 'conn')",
            ],
        )
        wait_absence_mock.assert_called_once_with(client, 22)
        wait_mock.assert_not_called()

    def test_delete_case_logs_falls_back_to_mutation_when_partition_drop_fails(self):
        client = _FakeClickHouseClient()

        def _command(sql):
            client.commands.append(sql)
            if 'DROP PARTITION' in sql:
                raise RuntimeError('drop not supported')

        client.command = _command

        with patch.object(network_log_module, 'get_client', return_value=client):
            with patch.object(network_log_module, 'destructive_network_log_rewrite_guard', return_value=nullcontext()):
                with patch.object(network_log_module, '_list_case_log_types', return_value=['dns']):
                    with patch.object(network_log_module, 'wait_for_mutation_completion') as wait_mock:
                        result = network_log_module.delete_case_logs(22, wait=True)

        self.assertTrue(result)
        self.assertEqual(
            client.commands,
            [
                "ALTER TABLE network_logs DROP PARTITION tuple(22, 'dns')",
                'ALTER TABLE network_logs DELETE WHERE case_id = 22',
            ],
        )
        wait_mock.assert_called_once_with(
            'network_logs',
            'DELETE WHERE case_id = 22',
            client=client,
        )

    def test_delete_pcap_logs_waits_for_network_log_mutation_when_requested(self):
        client = _FakeClickHouseClient()

        with patch.object(network_log_module, 'get_client', return_value=client):
            with patch.object(network_log_module, 'destructive_network_log_rewrite_guard', return_value=nullcontext()):
                with patch.object(network_log_module, 'wait_for_mutation_completion') as wait_mock:
                    result = network_log_module.delete_pcap_logs(11, 22, wait=True)

        self.assertTrue(result)
        self.assertEqual(
            client.commands,
            ['ALTER TABLE network_logs DELETE WHERE pcap_id = 11 AND case_id = 22'],
        )
        wait_mock.assert_called_once_with(
            'network_logs',
            'DELETE WHERE pcap_id = 11 AND case_id = 22',
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
            with patch.object(event_deduplication, 'destructive_event_rewrite_guard', return_value=nullcontext()):
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

    def test_deduplicate_case_events_skips_when_guard_busy_for_auto_mode(self):
        with patch.object(
            event_deduplication,
            'destructive_event_rewrite_guard',
            side_effect=clickhouse_utils.ClickHouseMutationGuardActive(
                {'operation': 'case_event_delete', 'case_id': 44, 'started_at': '2026-04-21T12:00:00Z'}
            ),
        ):
            result = event_deduplication.deduplicate_case_events(
                case_id=9,
                track_progress=False,
                rewrite_guard_behavior='skip',
            )

        self.assertTrue(result['success'])
        self.assertEqual(result['artifact_types_checked'], 0)
        self.assertEqual(result['artifact_types_skipped'], 1)
        self.assertIn('another destructive event rewrite', result['message'])


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
            rewrite_guard_behavior='skip',
        )


class ManualDedupRouteContractTestCase(unittest.TestCase):
    def setUp(self):
        if ROUTE_IMPORT_ERROR is not None:
            self.skipTest(f'route module dependencies unavailable: {ROUTE_IMPORT_ERROR}')
        self.app = Flask(__name__)
        self.app.secret_key = 'test-secret'

    def test_remove_duplicate_events_queues_async_task(self):
        case = types.SimpleNamespace(id=7, uuid='case-uuid')
        queued_task = types.SimpleNamespace(id='dedup-task-7')

        with self.app.test_request_context('/api/events/duplicates/remove/case-uuid', method='POST', json={}):
            with patch.object(case_files_routes, 'current_user', types.SimpleNamespace(permission_level='analyst')):
                with patch.object(case_files_routes.Case, 'get_by_uuid', return_value=case):
                    with patch.object(case_files_routes, '_require_case_write_access', return_value=None):
                        with patch('tasks.celery_tasks.deduplicate_case_events_task.delay', return_value=queued_task) as task_mock:
                            response = case_files_routes.remove_duplicate_events.__wrapped__('case-uuid')

        payload = response.get_json()
        self.assertTrue(payload['success'])
        self.assertEqual(payload['status'], 'queued')
        self.assertEqual(payload['task_id'], 'dedup-task-7')
        self.assertFalse(payload['force_large_dedup'])
        task_mock.assert_called_once_with(case_id=7, case_uuid='case-uuid', force_large_dedup=False)

    def test_remove_duplicate_events_rejects_when_another_rewrite_is_active(self):
        case = types.SimpleNamespace(id=7, uuid='case-uuid')

        with self.app.test_request_context('/api/events/duplicates/remove/case-uuid', method='POST', json={}):
            with patch.object(case_files_routes, 'current_user', types.SimpleNamespace(permission_level='analyst')):
                with patch.object(case_files_routes.Case, 'get_by_uuid', return_value=case):
                    with patch.object(case_files_routes, '_require_case_write_access', return_value=None):
                        with patch('utils.clickhouse.get_active_destructive_event_rewrite', return_value={'operation': 'case_event_delete', 'case_id': 99}):
                            response, status_code = case_files_routes.remove_duplicate_events.__wrapped__('case-uuid')

        payload = response.get_json()
        self.assertEqual(status_code, 409)
        self.assertFalse(payload['success'])
        self.assertEqual(payload['active_rewrite']['case_id'], 99)


class ParsingDeleteRouteContractTestCase(unittest.TestCase):
    def setUp(self):
        if PARSING_ROUTE_IMPORT_ERROR is not None:
            self.skipTest(f'parsing route module dependencies unavailable: {PARSING_ROUTE_IMPORT_ERROR}')
        self.app = Flask(__name__)
        self.app.secret_key = 'test-secret'

    def test_delete_case_events_rejects_when_another_rewrite_is_active(self):
        case = types.SimpleNamespace(id=7, uuid='case-uuid')

        with self.app.test_request_context('/api/parsing/delete-events/case-uuid', method='DELETE', json={}):
            with patch.object(parsing_routes, 'current_user', types.SimpleNamespace(permission_level='analyst')):
                with patch.object(parsing_routes.Case, 'get_by_uuid', return_value=case):
                    with patch('utils.clickhouse.get_active_destructive_event_rewrite', return_value={'operation': 'case_event_deduplication', 'case_id': 33}):
                        response, status_code = parsing_routes.delete_case_events.__wrapped__('case-uuid')

        payload = response.get_json()
        self.assertEqual(status_code, 409)
        self.assertFalse(payload['success'])
        self.assertEqual(payload['active_rewrite']['case_id'], 33)


class CaseDeleteTaskContractTestCase(unittest.TestCase):
    def test_delete_case_events_task_waits_for_mutation_completion(self):
        if TASK_IMPORT_ERROR is not None:
            self.skipTest(f'task module dependencies unavailable: {TASK_IMPORT_ERROR}')

        client = Mock()
        client.query.return_value.result_rows = [(321,)]

        with patch('utils.clickhouse.get_fresh_client', return_value=client):
            with patch('utils.clickhouse.delete_case_events') as delete_mock:
                with patch.object(celery_tasks.delete_case_events_task, 'update_state'):
                    result = celery_tasks.delete_case_events_task.run(case_id=17, force_large_delete=False)

        self.assertTrue(result['success'])
        self.assertEqual(result['events_deleted'], 321)
        self.assertTrue(result['mutation_completed'])
        delete_mock.assert_called_once_with(17, wait=True, client=client)


class PcapDeleteContractTestCase(unittest.TestCase):
    def setUp(self):
        if PCAP_ROUTE_IMPORT_ERROR is not None:
            self.skipTest(f'pcap route module dependencies unavailable: {PCAP_ROUTE_IMPORT_ERROR}')
        self.app = Flask(__name__)
        self.app.secret_key = 'test-secret'

    def test_delete_pcap_file_waits_for_network_log_mutations(self):
        case = types.SimpleNamespace(id=14)
        pcap_file = types.SimpleNamespace(
            id=9,
            case_uuid='case-uuid',
            filename='capture.pcap',
            file_path=None,
            zeek_output_path=None,
            logs_indexed=12,
            is_archive=True,
            extracted_files=[
                types.SimpleNamespace(
                    id=10,
                    zeek_output_path=None,
                    file_path=None,
                ),
            ],
        )

        with self.app.test_request_context('/api/pcap/9/delete', method='POST'):
            with patch.object(pcap_routes, 'current_user', types.SimpleNamespace(permission_level='administrator', username='admin')):
                with patch.object(pcap_routes, '_get_pcap_for_user', return_value=pcap_file):
                    with patch.object(pcap_routes.Case, 'get_by_uuid', return_value=case):
                        with patch('models.network_log.delete_pcap_logs') as delete_logs_mock:
                            with patch.object(pcap_routes.db.session, 'delete'):
                                with patch.object(pcap_routes.db.session, 'commit'):
                                    response = pcap_routes.delete_pcap_file.__wrapped__(9)

        payload = response.get_json()
        self.assertTrue(payload['success'])
        self.assertEqual(delete_logs_mock.call_args_list, [
            unittest.mock.call(9, 14, wait=True),
            unittest.mock.call(10, 14, wait=True),
        ])

    def test_delete_pcap_file_fails_closed_when_clickhouse_delete_fails(self):
        case = types.SimpleNamespace(id=14)
        pcap_file = types.SimpleNamespace(
            id=9,
            case_uuid='case-uuid',
            filename='capture.pcap',
            file_path=None,
            zeek_output_path=None,
            logs_indexed=12,
            is_archive=False,
            extracted_files=[],
        )

        with self.app.test_request_context('/api/pcap/9/delete', method='POST'):
            with patch.object(pcap_routes, 'current_user', types.SimpleNamespace(permission_level='administrator', username='admin')):
                with patch.object(pcap_routes, '_get_pcap_for_user', return_value=pcap_file):
                    with patch.object(pcap_routes.Case, 'get_by_uuid', return_value=case):
                        with patch('models.network_log.delete_pcap_logs', side_effect=RuntimeError('mutation failed')):
                            with patch.object(pcap_routes.db.session, 'delete') as delete_mock:
                                with patch.object(pcap_routes.db.session, 'commit') as commit_mock:
                                    response, status_code = pcap_routes.delete_pcap_file.__wrapped__(9)

        payload = response.get_json()
        self.assertEqual(status_code, 500)
        self.assertFalse(payload['success'])
        delete_mock.assert_not_called()
        commit_mock.assert_not_called()

    def test_delete_pcap_file_returns_409_when_network_log_rewrite_active(self):
        active_rewrite = {'operation': 'pcap_network_log_delete', 'case_id': 14, 'pcap_id': 9}

        with self.app.test_request_context('/api/pcap/9/delete', method='POST'):
            with patch.object(pcap_routes, 'current_user', types.SimpleNamespace(permission_level='administrator', username='admin')):
                with patch('models.network_log.get_active_destructive_network_log_rewrite', return_value=active_rewrite):
                    response, status_code = pcap_routes.delete_pcap_file.__wrapped__(9)

        payload = response.get_json()
        self.assertEqual(status_code, 409)
        self.assertFalse(payload['success'])
        self.assertEqual(payload['active_rewrite'], active_rewrite)

    def test_rebuild_pcap_returns_409_when_network_log_rewrite_active(self):
        active_rewrite = {'operation': 'case_network_log_delete', 'case_id': 14}

        with self.app.test_request_context('/api/pcap/9/rebuild', method='POST'):
            with patch.object(pcap_routes, 'current_user', types.SimpleNamespace(permission_level='analyst', username='analyst')):
                with patch('models.network_log.get_active_destructive_network_log_rewrite', return_value=active_rewrite):
                    response, status_code = pcap_routes.rebuild_pcap.__wrapped__(9)

        payload = response.get_json()
        self.assertEqual(status_code, 409)
        self.assertFalse(payload['success'])
        self.assertEqual(payload['active_rewrite'], active_rewrite)

    def test_rebuild_all_pcaps_returns_409_when_network_log_rewrite_active(self):
        active_rewrite = {'operation': 'case_network_log_delete', 'case_id': 14}

        with self.app.test_request_context('/api/pcap/rebuild-all/case-uuid', method='POST'):
            with patch.object(pcap_routes, 'current_user', types.SimpleNamespace(permission_level='analyst', username='analyst')):
                with patch('models.network_log.get_active_destructive_network_log_rewrite', return_value=active_rewrite):
                    response, status_code = pcap_routes.rebuild_all_pcaps.__wrapped__('case-uuid')

        payload = response.get_json()
        self.assertEqual(status_code, 409)
        self.assertFalse(payload['success'])
        self.assertEqual(payload['active_rewrite'], active_rewrite)


class PcapReindexContractTestCase(unittest.TestCase):
    def test_reindex_waits_for_prior_network_log_delete(self):
        if PCAP_TASK_IMPORT_ERROR is not None:
            self.skipTest(f'pcap task module dependencies unavailable: {PCAP_TASK_IMPORT_ERROR}')

        app = Flask(__name__)
        app.secret_key = 'test-secret'
        pcap_record = types.SimpleNamespace(case_uuid='case-uuid')
        case = types.SimpleNamespace(id=77)

        with patch.object(pcap_tasks, 'get_flask_app', return_value=app):
            with patch.object(pcap_tasks.db.session, 'get', return_value=pcap_record):
                with patch.object(pcap_tasks, '_get_case_for_task', return_value=case):
                    with patch('models.network_log.delete_pcap_logs') as delete_logs_mock:
                        with patch.object(pcap_tasks.index_zeek_logs, 'run', return_value={'success': True}) as index_mock:
                            result = pcap_tasks.reindex_pcap_logs.run(pcap_id=41)

        self.assertTrue(result['success'])
        delete_logs_mock.assert_called_once_with(41, 77, wait=True)
        index_mock.assert_called_once_with(41)

    def test_delete_pcap_scope_raises_before_metadata_delete_when_clickhouse_delete_fails(self):
        if PCAP_TASK_IMPORT_ERROR is not None:
            self.skipTest(f'pcap task module dependencies unavailable: {PCAP_TASK_IMPORT_ERROR}')

        record = types.SimpleNamespace(
            id=5,
            logs_indexed=9,
            zeek_output_path=None,
            file_path=None,
        )

        with patch('models.network_log.delete_pcap_logs', side_effect=RuntimeError('mutation failed')):
            with patch.object(pcap_tasks.db.session, 'delete') as delete_mock:
                with patch.object(pcap_tasks.db.session, 'commit') as commit_mock:
                    with self.assertRaises(RuntimeError):
                        pcap_tasks._delete_pcap_scope('case-uuid', 7, [record])

        delete_mock.assert_not_called()
        commit_mock.assert_not_called()


class CaseFileDeleteFailureContractTestCase(unittest.TestCase):
    def setUp(self):
        if ROUTE_IMPORT_ERROR is not None:
            self.skipTest(f'case file route module dependencies unavailable: {ROUTE_IMPORT_ERROR}')
        self.app = Flask(__name__)
        self.app.secret_key = 'test-secret'

    def test_delete_case_file_fails_closed_when_clickhouse_delete_fails(self):
        case = types.SimpleNamespace(id=14, uuid='case-uuid')
        case_file = types.SimpleNamespace(
            id=9,
            case_uuid='case-uuid',
            filename='artifact.evtx',
            file_path=None,
            sha256_hash='abc',
            file_size=123,
        )
        query_mock = Mock()
        query_mock.get.return_value = case_file
        query_mock.filter_by.return_value.all.return_value = []

        with self.app.test_request_context('/api/files/delete/9', method='POST'):
            with patch.object(case_files_routes, 'current_user', types.SimpleNamespace(permission_level='administrator', username='admin')):
                with patch.object(case_files_routes.CaseFile, 'query', query_mock):
                    with patch.object(case_files_routes.Case, 'get_by_uuid', return_value=case):
                        with patch('utils.clickhouse.count_file_events', return_value=11):
                            with patch('utils.clickhouse.delete_file_events', side_effect=RuntimeError('mutation failed')):
                                with patch.object(case_files_routes.db.session, 'delete') as delete_mock:
                                    with patch.object(case_files_routes.db.session, 'commit') as commit_mock:
                                        response, status_code = case_files_routes.delete_case_file.__wrapped__(9)

        payload = response.get_json()
        self.assertEqual(status_code, 500)
        self.assertFalse(payload['success'])
        delete_mock.assert_not_called()
        commit_mock.assert_not_called()

    def test_delete_standard_case_file_scope_raises_before_metadata_delete_when_clickhouse_delete_fails(self):
        if TASK_IMPORT_ERROR is not None:
            self.skipTest(f'task module dependencies unavailable: {TASK_IMPORT_ERROR}')

        record = types.SimpleNamespace(id=5, events_indexed=9)

        with patch('utils.clickhouse.delete_file_events', side_effect=RuntimeError('mutation failed')):
            with patch('models.database.db.session.delete') as delete_mock:
                with patch('models.database.db.session.commit') as commit_mock:
                    with self.assertRaises(RuntimeError):
                        celery_tasks._delete_standard_case_file_scope('case-uuid', 7, [record])

        delete_mock.assert_not_called()
        commit_mock.assert_not_called()


if __name__ == '__main__':
    unittest.main()
