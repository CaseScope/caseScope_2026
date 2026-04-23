import io
import importlib.util
import json
import os
import sys
import types
import unittest
from contextlib import ExitStack
from unittest.mock import Mock, patch

from flask import Flask

try:
    from sqlalchemy.exc import IntegrityError
except ImportError:
    class IntegrityError(Exception):
        def __init__(self, statement=None, params=None, orig=None):
            super().__init__(statement)
            self.statement = statement
            self.params = params
            self.orig = orig

os.environ.setdefault('SECRET_KEY', 'test-secret')

spec = importlib.util.spec_from_file_location(
    'route_security_route_helpers',
    '/opt/casescope/routes/route_helpers.py',
)
route_helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(route_helpers)

ROUTE_IMPORT_ERROR = None

try:
    import routes.activation as activation_routes
    import routes.ai as ai_routes
    import routes.analysis as analysis_routes
    import routes.case_files as case_files_routes
    import routes.chat as chat_routes
    import routes.findings as findings_routes
    import routes.hunting as hunting_routes
    import routes.iocs as ioc_routes
    import routes.main as main_routes
    import routes.known_systems as known_systems_routes
    import routes.known_users as known_users_routes
    import routes.parsing as parsing_routes
    import routes.rag as rag_routes
except ImportError as exc:
    ROUTE_IMPORT_ERROR = exc
    activation_routes = None
    ai_routes = None
    analysis_routes = None
    case_files_routes = None
    chat_routes = None
    findings_routes = None
    hunting_routes = None
    ioc_routes = None
    main_routes = None
    known_systems_routes = None
    known_users_routes = None
    parsing_routes = None
    rag_routes = None


class _DummyUser:
    def __init__(self, is_admin=False, permission_level='analyst'):
        self.is_administrator = is_admin
        self.permission_level = permission_level
        self.username = 'tester'
        self.is_authenticated = True

    def can_access_case(self, _case_id):
        return self.permission_level != 'viewer'


class RouteSecurityRegressionTestCase(unittest.TestCase):
    def setUp(self):
        if ROUTE_IMPORT_ERROR is not None:
            self.skipTest(f'route module dependencies unavailable: {ROUTE_IMPORT_ERROR}')
        self.app = Flask(__name__)
        self.app.secret_key = 'test-secret'

    def _normalize_response(self, result):
        if isinstance(result, tuple):
            return result
        return result, result.status_code

    def _assert_viewer_case_write_denied(
        self,
        *,
        module,
        path,
        route_callable,
        args=(),
        json=None,
        data=None,
        patchers=(),
        content_type=None,
    ):
        with self.app.test_request_context(
            path,
            method='POST',
            json=json,
            data=data,
            content_type=content_type,
        ):
            with ExitStack() as stack:
                stack.enter_context(
                    patch.object(module, 'current_user', _DummyUser(permission_level='viewer'))
                )
                for patcher in patchers:
                    stack.enter_context(patcher)
                result = route_callable.__wrapped__(*args)

        response, status = self._normalize_response(result)
        self.assertEqual(status, 403)
        self.assertEqual(response.get_json()['error'], 'Viewers cannot modify case data')

    def test_activation_fingerprint_requires_admin(self):
        with self.app.test_request_context('/activation/api/fingerprint'):
            with patch.object(activation_routes, 'current_user', _DummyUser(is_admin=False)):
                response, status = activation_routes.api_fingerprint.__wrapped__()

        self.assertEqual(status, 403)
        self.assertEqual(response.get_json()['error'], 'Administrator access required')

    def test_parsing_task_status_only_allows_tracked_tasks(self):
        with self.app.test_request_context('/api/parsing/task/demo-task'):
            parsing_routes._remember_task_access('demo-task', case_uuid='case-123')

            self.assertTrue(parsing_routes._task_access_allowed('demo-task'))
            self.assertFalse(parsing_routes._task_access_allowed('other-task'))

    def test_parsing_delete_events_blocks_large_delete_without_force(self):
        case = Mock(id=7, uuid='case-uuid')

        with self.app.test_request_context(
            '/api/parsing/delete-events/case-uuid',
            method='DELETE',
            json={},
        ):
            with patch.object(parsing_routes, 'current_user', _DummyUser()):
                with patch.object(parsing_routes.Case, 'get_by_uuid', return_value=case):
                    with patch('utils.clickhouse.count_events', return_value=600001):
                        with patch('tasks.celery_tasks.INTERACTIVE_CASE_DELETE_MAX_EVENTS', 500000):
                            response, status = parsing_routes.delete_case_events.__wrapped__('case-uuid')

        self.assertEqual(status, 409)
        payload = response.get_json()
        self.assertFalse(payload['success'])
        self.assertTrue(payload['requires_force'])
        self.assertEqual(payload['event_count'], 600001)
        self.assertEqual(payload['safety_threshold_events'], 500000)

    def test_parsing_delete_events_queues_forced_large_delete(self):
        case = Mock(id=7, uuid='case-uuid')
        queued_task = types.SimpleNamespace(id='delete-task-7')
        task_mock = Mock()
        task_mock.delay.return_value = queued_task

        with self.app.test_request_context(
            '/api/parsing/delete-events/case-uuid',
            method='DELETE',
            json={'force_large_delete': True},
        ):
            with patch.object(parsing_routes, 'current_user', _DummyUser()):
                with patch.object(parsing_routes.Case, 'get_by_uuid', return_value=case):
                    with patch('utils.clickhouse.count_events', return_value=600001):
                        with patch('tasks.celery_tasks.INTERACTIVE_CASE_DELETE_MAX_EVENTS', 500000):
                            with patch.dict(sys.modules, {'tasks': types.SimpleNamespace(delete_case_events_task=task_mock)}):
                                response = parsing_routes.delete_case_events.__wrapped__('case-uuid')

            payload = response.get_json()
            self.assertTrue(payload['success'])
            self.assertEqual(payload['task_id'], 'delete-task-7')
            self.assertTrue(payload['force_large_delete'])
            task_mock.delay.assert_called_once_with(case_id=7, force_large_delete=True)

    def test_api_task_tracking_enforces_case_scope(self):
        with self.app.test_request_context('/api/hunting/noise/status/demo-task'):
            route_helpers._remember_task_access('demo-task', case_id=7)

            self.assertTrue(route_helpers._task_access_allowed('demo-task', case_id=7))
            self.assertFalse(route_helpers._task_access_allowed('demo-task', case_id=8))
            self.assertFalse(route_helpers._task_access_allowed('unknown-task'))

    def test_noise_tagging_rejects_viewers(self):
        with self.app.test_request_context('/api/hunting/noise/tag/1', method='POST'):
            with patch.object(hunting_routes, 'current_user', _DummyUser(permission_level='viewer')):
                response, status = hunting_routes.start_noise_tagging.__wrapped__(1)

        self.assertEqual(status, 403)
        self.assertEqual(response.get_json()['error'], 'Viewers cannot modify hunting state')

    def test_hunting_event_tag_rejects_viewers(self):
        with self.app.test_request_context('/api/hunting/event/tag/1', method='POST'):
            with patch.object(hunting_routes, 'current_user', _DummyUser(permission_level='viewer')):
                response, status = hunting_routes.update_analyst_tag.__wrapped__(1)

        self.assertEqual(status, 403)
        self.assertEqual(response.get_json()['error'], 'Viewers cannot modify hunting state')

    def test_hunting_event_tag_writes_overlay_state_instead_of_mutating_events(self):
        with self.app.test_request_context(
            '/api/hunting/event/tag/7',
            method='POST',
            json={
                'event_id': '4624',
                'record_id': 99,
                'source_file': 'Security.evtx',
                'source_host': 'HOST1',
                'analyst_tagged': True,
                'analyst_tags': ['credential-access'],
                'analyst_notes': 'reviewed',
            },
        ):
            with patch.object(hunting_routes, 'current_user', _DummyUser()):
                with patch.object(hunting_routes.Case, 'get_by_id', return_value=object()):
                    with patch('utils.clickhouse.get_client', return_value=Mock()) as get_client_mock:
                        with patch.object(hunting_routes, 'ensure_event_analyst_state_table') as ensure_mock:
                            with patch.object(hunting_routes, 'upsert_event_analyst_state_rows', return_value=1) as upsert_mock:
                                response = hunting_routes.update_analyst_tag.__wrapped__(7)

        payload = response.get_json()
        self.assertTrue(payload['success'])
        ensure_mock.assert_called_once_with(get_client_mock.return_value)
        upsert_mock.assert_called_once()
        self.assertEqual(upsert_mock.call_args.args[0], 7)
        self.assertEqual(upsert_mock.call_args.args[1][0]['selector_key'], 'record:99|file:Security.evtx|host:HOST1')
        self.assertEqual(upsert_mock.call_args.kwargs['updated_by'], 'tester')

    def test_bulk_noise_tag_rejects_viewers(self):
        with self.app.test_request_context('/api/hunting/events/bulk-noise/1', method='POST'):
            with patch.object(hunting_routes, 'current_user', _DummyUser(permission_level='viewer')):
                response, status = hunting_routes.bulk_noise_tag.__wrapped__(1)

        self.assertEqual(status, 403)
        self.assertEqual(response.get_json()['error'], 'Viewers cannot modify hunting state')

    def test_analysis_write_routes_reject_viewers(self):
        route_cases = [
            {
                'name': 'start analysis',
                'path': '/api/case/7/analysis/run',
                'callable': analysis_routes.start_analysis,
                'args': (7,),
                'json': {},
                'patchers': [patch.object(analysis_routes.Case, 'get_by_id', return_value=object())],
            },
            {
                'name': 'save finding verdict',
                'path': '/api/case/7/analysis/findings/gap/9/verdict',
                'callable': analysis_routes.save_finding_verdict,
                'args': (7, 'gap', 9),
                'json': {'verdict': 'confirmed'},
                'patchers': [patch.object(analysis_routes.Case, 'get_by_id', return_value=object())],
            },
            {
                'name': 'handle suggested action',
                'path': '/api/case/7/analysis/suggested-actions/3',
                'callable': analysis_routes.handle_suggested_action,
                'args': (7, 3),
                'json': {'status': 'accepted'},
                'patchers': [patch.object(analysis_routes.Case, 'get_by_id', return_value=object())],
            },
        ]

        for route_case in route_cases:
            with self.subTest(route_case['name']):
                self._assert_viewer_case_write_denied(
                    module=analysis_routes,
                    path=route_case['path'],
                    route_callable=route_case['callable'],
                    args=route_case['args'],
                    json=route_case['json'],
                    patchers=route_case['patchers'],
                )

    def test_ioc_write_routes_reject_viewers(self):
        case = Mock(id=7, uuid='case-uuid', edr_report='Report one\n\nReport two')
        route_cases = [
            {
                'name': 'create ioc',
                'path': '/api/iocs/create/case-uuid',
                'callable': ioc_routes.create_ioc,
                'args': ('case-uuid',),
                'json': {'ioc_type': 'Domain', 'value': 'example.com'},
                'patchers': [patch.object(ioc_routes.Case, 'get_by_uuid', return_value=case)],
            },
            {
                'name': 'bulk create iocs',
                'path': '/api/iocs/bulk-create/case-uuid',
                'callable': ioc_routes.bulk_create_iocs,
                'args': ('case-uuid',),
                'json': {'iocs': [{'ioc_type': 'Domain', 'value': 'example.com'}]},
                'patchers': [patch.object(ioc_routes.Case, 'get_by_uuid', return_value=case)],
            },
            {
                'name': 'update ioc',
                'path': '/api/iocs/5/update',
                'callable': ioc_routes.update_ioc,
                'args': (5,),
                'json': {'field': 'notes', 'value': 'updated'},
                'patchers': [],
            },
            {
                'name': 'delete ioc',
                'path': '/api/iocs/5/delete',
                'callable': ioc_routes.delete_ioc_from_case,
                'args': (5,),
                'json': {'case_uuid': 'case-uuid'},
                'patchers': [patch.object(ioc_routes.Case, 'get_by_uuid', return_value=case)],
            },
            {
                'name': 'extract iocs from report',
                'path': '/api/iocs/extraction/extract/case-uuid',
                'callable': ioc_routes.extract_iocs_from_report,
                'args': ('case-uuid',),
                'json': {'report_index': 0},
                'patchers': [patch.object(ioc_routes.Case, 'get_by_uuid', return_value=case)],
            },
            {
                'name': 'save extracted iocs',
                'path': '/api/iocs/extraction/save/case-uuid',
                'callable': ioc_routes.save_extracted_iocs_api,
                'args': ('case-uuid',),
                'json': {'iocs': []},
                'patchers': [patch.object(ioc_routes.Case, 'get_by_uuid', return_value=case)],
            },
            {
                'name': 'start find iocs in events',
                'path': '/api/iocs/find-in-events/start/case-uuid',
                'callable': ioc_routes.start_find_iocs_in_events,
                'args': ('case-uuid',),
                'json': {},
                'patchers': [patch.object(ioc_routes.Case, 'get_by_uuid', return_value=case)],
            },
            {
                'name': 'save find iocs results',
                'path': '/api/iocs/find-in-events/save/case-uuid',
                'callable': ioc_routes.save_find_iocs_results,
                'args': ('case-uuid',),
                'json': {'iocs': []},
                'patchers': [patch.object(ioc_routes.Case, 'get_by_uuid', return_value=case)],
            },
            {
                'name': 'tag artifacts synchronously',
                'path': '/api/iocs/tag-artifacts/case-uuid',
                'callable': ioc_routes.tag_artifacts_for_case,
                'args': ('case-uuid',),
                'json': {},
                'patchers': [patch.object(ioc_routes.Case, 'get_by_uuid', return_value=case)],
            },
            {
                'name': 'start tag artifacts',
                'path': '/api/iocs/tag-artifacts/start/case-uuid',
                'callable': ioc_routes.start_tag_artifacts_for_case,
                'args': ('case-uuid',),
                'json': {},
                'patchers': [patch.object(ioc_routes.Case, 'get_by_uuid', return_value=case)],
            },
            {
                'name': 'enrich ioc',
                'path': '/api/ioc/5/enrich',
                'callable': ioc_routes.enrich_ioc,
                'args': (5,),
                'json': {},
                'patchers': [],
            },
            {
                'name': 'bulk enrich iocs',
                'path': '/api/iocs/bulk-enrich',
                'callable': ioc_routes.bulk_enrich_iocs,
                'args': (),
                'json': {'ioc_ids': [1, 2]},
                'patchers': [],
            },
            {
                'name': 'bulk update iocs',
                'path': '/api/iocs/bulk-update',
                'callable': ioc_routes.bulk_update_iocs,
                'args': (),
                'json': {'ioc_ids': [1], 'updates': {'active': False}},
                'patchers': [],
            },
            {
                'name': 'bulk delete iocs',
                'path': '/api/iocs/bulk-delete/case-uuid',
                'callable': ioc_routes.bulk_delete_iocs,
                'args': ('case-uuid',),
                'json': {'ioc_ids': [1]},
                'patchers': [patch.object(ioc_routes.Case, 'get_by_uuid', return_value=case)],
            },
        ]

        for route_case in route_cases:
            with self.subTest(route_case['name']):
                self._assert_viewer_case_write_denied(
                    module=ioc_routes,
                    path=route_case['path'],
                    route_callable=route_case['callable'],
                    args=route_case['args'],
                    json=route_case['json'],
                    patchers=route_case['patchers'],
                )

    def test_find_iocs_start_routes_to_ioc_queue_and_tracks_task_access(self):
        case = Mock(id=7, uuid='case-uuid')
        queued_task = types.SimpleNamespace(id='find-task-7')
        task_mock = Mock()
        task_mock.apply_async.return_value = queued_task

        with self.app.test_request_context(
            '/api/iocs/find-in-events/start/case-uuid',
            method='POST',
            json={},
        ):
            with patch.object(ioc_routes, 'current_user', _DummyUser()):
                with patch.object(ioc_routes.Case, 'get_by_uuid', return_value=case):
                    with patch.dict(sys.modules, {'tasks.celery_tasks': types.SimpleNamespace(find_iocs_in_events_task=task_mock)}):
                        response = ioc_routes.start_find_iocs_in_events.__wrapped__('case-uuid')

            payload = response.get_json()
            self.assertTrue(payload['success'])
            self.assertEqual(payload['task_id'], 'find-task-7')
            self.assertEqual(payload['queue'], 'ioc')
            self.assertEqual(payload['status'], 'queued')
            task_mock.apply_async.assert_called_once_with(args=(7, 'tester'), queue='ioc')
            self.assertTrue(ioc_routes._task_access_allowed('find-task-7', case_id=7))

    def test_find_iocs_progress_rejects_untracked_task(self):
        case = Mock(id=7, uuid='case-uuid')

        with self.app.test_request_context('/api/iocs/find-in-events/progress/case-uuid/task-1'):
            with patch.object(ioc_routes.Case, 'get_by_uuid', return_value=case):
                response, status = ioc_routes.get_find_iocs_progress.__wrapped__('case-uuid', 'task-1')

        self.assertEqual(status, 403)
        self.assertEqual(response.get_json()['error'], 'Task not accessible')

    def test_find_iocs_results_rejects_untracked_task(self):
        case = Mock(id=7, uuid='case-uuid')

        with self.app.test_request_context('/api/iocs/find-in-events/results/case-uuid/task-1'):
            with patch.object(ioc_routes.Case, 'get_by_uuid', return_value=case):
                response, status = ioc_routes.get_find_iocs_results.__wrapped__('case-uuid', 'task-1')

        self.assertEqual(status, 403)
        self.assertEqual(response.get_json()['error'], 'Task not accessible')

    def test_tag_artifacts_start_routes_to_ioc_queue_and_tracks_task_access(self):
        case = Mock(id=11, uuid='case-uuid')
        queued_task = types.SimpleNamespace(id='tag-task-11')
        task_mock = Mock()
        task_mock.apply_async.return_value = queued_task

        with self.app.test_request_context(
            '/api/iocs/tag-artifacts/start/case-uuid',
            method='POST',
            json={},
        ):
            with patch.object(ioc_routes, 'current_user', _DummyUser()):
                with patch.object(ioc_routes.Case, 'get_by_uuid', return_value=case):
                    with patch.dict(sys.modules, {'tasks.celery_tasks': types.SimpleNamespace(tag_iocs_for_case=task_mock)}):
                        response = ioc_routes.start_tag_artifacts_for_case.__wrapped__('case-uuid')

            payload = response.get_json()
            self.assertTrue(payload['success'])
            self.assertEqual(payload['task_id'], 'tag-task-11')
            self.assertEqual(payload['queue'], 'ioc')
            self.assertEqual(payload['status'], 'queued')
            task_mock.apply_async.assert_called_once_with(args=(11,), queue='ioc')
            self.assertTrue(ioc_routes._task_access_allowed('tag-task-11', case_id=11))

    def test_tag_artifacts_results_rejects_untracked_task(self):
        case = Mock(id=11, uuid='case-uuid')

        with self.app.test_request_context('/api/iocs/tag-artifacts/results/case-uuid/task-1'):
            with patch.object(ioc_routes.Case, 'get_by_uuid', return_value=case):
                response, status = ioc_routes.get_tag_artifacts_results.__wrapped__('case-uuid', 'task-1')

        self.assertEqual(status, 403)
        self.assertEqual(response.get_json()['error'], 'Task not accessible')

    def test_tag_artifacts_results_normalize_total_iocs_field_for_async_payload(self):
        case = Mock(id=11, uuid='case-uuid')
        async_result = types.SimpleNamespace(
            state='SUCCESS',
            result={
                'success': True,
                'total_iocs': 4,
                'iocs_with_matches': 2,
                'total_artifact_matches': 49,
                'details': [
                    {
                        'ioc_id': 7,
                        'ioc_type': 'File Name',
                        'value': 'voiceaccess.exe',
                        'match_count': 49,
                        'artifact_types': {'evtx': 49},
                    }
                ],
            },
            ready=lambda: True,
        )

        with self.app.test_request_context('/api/iocs/tag-artifacts/results/case-uuid/tag-task-11'):
            ioc_routes._remember_task_access('tag-task-11', case_id=11)
            with patch.object(ioc_routes.Case, 'get_by_uuid', return_value=case):
                with patch.dict(
                    sys.modules,
                    {
                        'celery.result': types.SimpleNamespace(AsyncResult=lambda task_id, app=None: async_result),
                        'tasks.celery_tasks': types.SimpleNamespace(celery_app=object()),
                    },
                ):
                    response, status = ioc_routes.get_tag_artifacts_results.__wrapped__('case-uuid', 'tag-task-11')

        self.assertEqual(status, 200)
        payload = response.get_json()
        self.assertTrue(payload['success'])
        self.assertEqual(payload['total_iocs'], 4)
        self.assertEqual(payload['total_iocs_searched'], 4)
        self.assertEqual(payload['iocs_with_matches'], 2)
        self.assertEqual(len(payload['details']), 1)
        self.assertEqual(payload['details'][0]['value'], 'voiceaccess.exe')

    def test_known_user_write_routes_reject_viewers(self):
        route_cases = [
            {
                'name': 'discover known users',
                'path': '/api/known-users/discover/case-uuid',
                'callable': known_users_routes.discover_users,
                'args': ('case-uuid',),
                'json': {},
                'data': None,
                'content_type': None,
                'patchers': [patch.object(known_users_routes.Case, 'get_by_uuid', return_value=object())],
            },
            {
                'name': 'update known user',
                'path': '/api/known-users/4/update',
                'callable': known_users_routes.update_known_user,
                'args': (4,),
                'json': {'field': 'compromised', 'value': True},
                'data': None,
                'content_type': None,
                'patchers': [],
            },
            {
                'name': 'add user alias',
                'path': '/api/known-users/4/add-alias',
                'callable': known_users_routes.add_user_alias,
                'args': (4,),
                'json': {'alias': 'alias1'},
                'data': None,
                'content_type': None,
                'patchers': [],
            },
            {
                'name': 'add user email',
                'path': '/api/known-users/4/add-email',
                'callable': known_users_routes.add_user_email,
                'args': (4,),
                'json': {'email': 'alias@example.com'},
                'data': None,
                'content_type': None,
                'patchers': [],
            },
            {
                'name': 'upload known users csv',
                'path': '/api/known-users/upload/case-uuid',
                'callable': known_users_routes.upload_known_users_csv,
                'args': ('case-uuid',),
                'json': None,
                'data': {'file': (io.BytesIO(b'username\nalice\n'), 'users.csv')},
                'content_type': 'multipart/form-data',
                'patchers': [patch.object(known_users_routes.Case, 'get_by_uuid', return_value=object())],
            },
            {
                'name': 'bulk update known users',
                'path': '/api/known-users/bulk-update',
                'callable': known_users_routes.bulk_update_known_users,
                'args': (),
                'json': {'user_ids': [4], 'updates': {'compromised': True}},
                'data': None,
                'content_type': None,
                'patchers': [],
            },
            {
                'name': 'bulk delete known users',
                'path': '/api/known-users/bulk-delete',
                'callable': known_users_routes.bulk_delete_known_users,
                'args': (),
                'json': {'user_ids': [4]},
                'data': None,
                'content_type': None,
                'patchers': [],
            },
        ]

        for route_case in route_cases:
            with self.subTest(route_case['name']):
                self._assert_viewer_case_write_denied(
                    module=known_users_routes,
                    path=route_case['path'],
                    route_callable=route_case['callable'],
                    args=route_case['args'],
                    json=route_case['json'],
                    data=route_case['data'],
                    patchers=route_case['patchers'],
                    content_type=route_case['content_type'],
                )

    def test_known_system_write_routes_reject_viewers(self):
        route_cases = [
            {
                'name': 'discover known systems',
                'path': '/api/known-systems/discover/case-uuid',
                'callable': known_systems_routes.discover_systems,
                'args': ('case-uuid',),
                'json': {},
                'data': None,
                'content_type': None,
                'patchers': [patch.object(known_systems_routes.Case, 'get_by_uuid', return_value=object())],
            },
            {
                'name': 'update known system',
                'path': '/api/known-systems/4/update',
                'callable': known_systems_routes.update_known_system,
                'args': (4,),
                'json': {'field': 'compromised', 'value': True},
                'data': None,
                'content_type': None,
                'patchers': [],
            },
            {
                'name': 'add system ip',
                'path': '/api/known-systems/4/add-ip',
                'callable': known_systems_routes.add_system_ip,
                'args': (4,),
                'json': {'ip_address': '10.0.0.5'},
                'data': None,
                'content_type': None,
                'patchers': [],
            },
            {
                'name': 'add system share',
                'path': '/api/known-systems/4/add-share',
                'callable': known_systems_routes.add_system_share,
                'args': (4,),
                'json': {'share_name': 'share'},
                'data': None,
                'content_type': None,
                'patchers': [],
            },
            {
                'name': 'upload known systems csv',
                'path': '/api/known-systems/upload/case-uuid',
                'callable': known_systems_routes.upload_known_systems_csv,
                'args': ('case-uuid',),
                'json': None,
                'data': {'file': (io.BytesIO(b'hostname\nhost1\n'), 'systems.csv')},
                'content_type': 'multipart/form-data',
                'patchers': [patch.object(known_systems_routes.Case, 'get_by_uuid', return_value=object())],
            },
            {
                'name': 'bulk update known systems',
                'path': '/api/known-systems/bulk-update',
                'callable': known_systems_routes.bulk_update_known_systems,
                'args': (),
                'json': {'system_ids': [4], 'updates': {'compromised': True}},
                'data': None,
                'content_type': None,
                'patchers': [],
            },
            {
                'name': 'bulk delete known systems',
                'path': '/api/known-systems/bulk-delete',
                'callable': known_systems_routes.bulk_delete_known_systems,
                'args': (),
                'json': {'system_ids': [4]},
                'data': None,
                'content_type': None,
                'patchers': [],
            },
        ]

        for route_case in route_cases:
            with self.subTest(route_case['name']):
                self._assert_viewer_case_write_denied(
                    module=known_systems_routes,
                    path=route_case['path'],
                    route_callable=route_case['callable'],
                    args=route_case['args'],
                    json=route_case['json'],
                    data=route_case['data'],
                    patchers=route_case['patchers'],
                    content_type=route_case['content_type'],
                )

    def test_case_file_write_routes_reject_viewers(self):
        route_cases = [
            {
                'name': 'reindex case files',
                'path': '/api/files/reindex/case-uuid',
                'callable': case_files_routes.reindex_case_files,
                'args': ('case-uuid',),
                'json': {},
                'patchers': [patch.object(case_files_routes.Case, 'get_by_uuid', return_value=object())],
            },
            {
                'name': 'repair case completion',
                'path': '/api/files/repair-completion/case-uuid',
                'callable': case_files_routes.repair_case_completion,
                'args': ('case-uuid',),
                'json': {},
                'patchers': [patch.object(case_files_routes.Case, 'get_by_uuid', return_value=object())],
            },
            {
                'name': 'remove duplicate events',
                'path': '/api/events/duplicates/remove/case-uuid',
                'callable': case_files_routes.remove_duplicate_events,
                'args': ('case-uuid',),
                'json': {},
                'patchers': [patch.object(case_files_routes.Case, 'get_by_uuid', return_value=object())],
            },
            {
                'name': 'import staging orphans',
                'path': '/api/files/staging/import/case-uuid',
                'callable': case_files_routes.import_staging_orphans,
                'args': ('case-uuid',),
                'json': {},
                'patchers': [patch.object(case_files_routes.Case, 'get_by_uuid', return_value=object())],
            },
            {
                'name': 'recover stuck files',
                'path': '/api/files/recover-stuck/case-uuid',
                'callable': case_files_routes.recover_stuck_files,
                'args': ('case-uuid',),
                'json': {'requeue': False},
                'patchers': [patch.object(case_files_routes.Case, 'get_by_uuid', return_value=object())],
            },
        ]

        for route_case in route_cases:
            with self.subTest(route_case['name']):
                self._assert_viewer_case_write_denied(
                    module=case_files_routes,
                    path=route_case['path'],
                    route_callable=route_case['callable'],
                    args=route_case['args'],
                    json=route_case['json'],
                    patchers=route_case['patchers'],
                )

    def test_duplicate_removal_start_tracks_task_access(self):
        case = Mock(id=7, uuid='case-uuid')
        queued_task = types.SimpleNamespace(id='dedup-task-7')
        task_mock = Mock()
        task_mock.delay.return_value = queued_task

        with self.app.test_request_context(
            '/api/events/duplicates/remove/case-uuid',
            method='POST',
            json={},
        ):
            with patch.object(case_files_routes, 'current_user', _DummyUser()):
                with patch.object(case_files_routes.Case, 'get_by_uuid', return_value=case):
                    with patch.object(case_files_routes, '_require_case_write_access', return_value=None):
                        with patch.dict(sys.modules, {'tasks.celery_tasks': types.SimpleNamespace(deduplicate_case_events_task=task_mock)}):
                            response = case_files_routes.remove_duplicate_events.__wrapped__('case-uuid')

            payload = response.get_json()
            self.assertTrue(payload['success'])
            self.assertEqual(payload['task_id'], 'dedup-task-7')
            self.assertEqual(payload['status'], 'queued')
            self.assertFalse(payload['force_large_dedup'])
            task_mock.delay.assert_called_once_with(case_id=7, case_uuid='case-uuid', force_large_dedup=False)
            self.assertTrue(route_helpers._task_access_allowed('dedup-task-7', case_id=7))

    def test_duplicate_removal_status_rejects_untracked_task(self):
        case = Mock(id=7, uuid='case-uuid')

        with self.app.test_request_context('/api/events/duplicates/status/case-uuid/task-1'):
            with patch.object(case_files_routes.Case, 'get_by_uuid', return_value=case):
                response, status = case_files_routes.get_duplicate_event_removal_status.__wrapped__('case-uuid', 'task-1')

        self.assertEqual(status, 404)
        self.assertEqual(response.get_json()['error'], 'Task not found')

    def test_bulk_noise_tag_writes_noise_overlay_state(self):
        client = Mock()
        client.query.return_value = None

        with self.app.test_request_context(
            '/api/hunting/events/bulk-noise/7',
            method='POST',
            json={
                'events': [
                    {
                        'event_id': '4624',
                    }
                ]
            },
        ):
            with patch.object(hunting_routes, 'current_user', _DummyUser()):
                with patch.object(hunting_routes.Case, 'get_by_id', return_value=object()):
                    with patch('utils.clickhouse.get_client', return_value=client):
                        with patch.object(hunting_routes, 'ensure_noise_overlay_case') as ensure_mock:
                            with patch.object(hunting_routes, 'upsert_manual_noise_state_rows', return_value=1) as upsert_mock:
                                response = hunting_routes.bulk_noise_tag.__wrapped__(7)

        self.assertEqual(response.get_json()['success'], True)
        self.assertTrue(ensure_mock.called)
        self.assertTrue(upsert_mock.called)

    def test_admin_client_create_handles_duplicate_code_integrity_error(self):
        duplicate_error = IntegrityError(
            statement='INSERT INTO clients ...',
            params={'code': 'CM'},
            orig=Exception('duplicate key value violates unique constraint "ix_clients_code"'),
        )

        with self.app.test_request_context(
            '/admin/clients/new',
            method='POST',
            data={
                'name': 'DaCruz',
                'code': 'CM',
                'timezone': 'America/New_York',
                'contact_name': '',
                'contact_email': '',
                'notes': '',
            },
        ):
            with patch.object(main_routes, 'current_user', _DummyUser(is_admin=True)):
                with patch('models.client.Client.get_by_code', return_value=None):
                    with patch.object(main_routes.db.session, 'add'):
                        with patch.object(main_routes.db.session, 'commit', side_effect=duplicate_error):
                            with patch.object(main_routes.db.session, 'rollback') as rollback_mock:
                                with patch.object(main_routes, 'flash') as flash_mock:
                                    with patch.object(main_routes, 'render_template', return_value='rendered') as render_mock:
                                        result = main_routes.admin_client_create.__wrapped__.__wrapped__()

        self.assertEqual(result, 'rendered')
        rollback_mock.assert_called_once()
        flash_mock.assert_any_call('Client code "CM" already exists', 'error')
        render_mock.assert_called_once()

    def test_chat_stream_fails_closed_when_ai_disabled(self):
        with self.app.test_request_context(
            '/api/chat/stream',
            method='POST',
            json={'case_id': 7, 'message': 'hello'},
        ):
            with patch.object(chat_routes, 'current_user', _DummyUser()):
                with patch.object(chat_routes.FeatureAvailability, 'is_ai_enabled', return_value=False):
                    response, status = chat_routes.chat_stream.__wrapped__()

        self.assertEqual(status, 400)
        self.assertEqual(response.get_json()['error'], 'AI features are not currently available')

    def test_chat_stream_rejects_non_integer_case_id(self):
        with self.app.test_request_context(
            '/api/chat/stream',
            method='POST',
            json={'case_id': 'abc', 'message': 'hello'},
        ):
            with patch.object(chat_routes, 'current_user', _DummyUser()):
                response, status = chat_routes.chat_stream.__wrapped__()

        self.assertEqual(status, 400)
        self.assertEqual(response.get_json()['error'], 'case_id must be an integer')

    def test_chat_route_rejects_conversation_case_mismatch(self):
        with self.app.test_request_context(
            '/api/chat/stream',
            method='POST',
            json={'case_id': 7, 'message': 'hello', 'conversation_id': 'conv-1'},
        ):
            with patch.object(chat_routes, 'current_user', _DummyUser()):
                with patch.object(chat_routes.FeatureAvailability, 'is_ai_enabled', return_value=True):
                    with patch.object(chat_routes.Case, 'get_by_id', return_value=object()):
                        with patch.object(
                            chat_routes,
                            '_load_or_create_chat_session',
                            return_value=(None, False, 'conversation_mismatch'),
                        ):
                            response, status = chat_routes.chat_stream.__wrapped__()

        self.assertEqual(status, 409)
        payload = response.get_json()
        self.assertEqual(payload['error_code'], 'conversation_mismatch')

    def test_chat_session_loader_flags_cross_user_or_case_reuse(self):
        class _Session:
            def __init__(self, case_id, user_id):
                self.case_id = case_id
                self.user_id = user_id

        with patch.object(
            chat_routes.ChatConversationSession,
            'get_by_conversation_id',
            return_value=_Session(case_id=8, user_id='other-user'),
        ):
            session, created, error = chat_routes._load_or_create_chat_session(
                case_id=7,
                user_id='tester',
                conversation_id='conv-1',
            )

        self.assertIsNone(session)
        self.assertFalse(created)
        self.assertEqual(error, 'conversation_mismatch')

    def test_clear_conversation_requires_case_id(self):
        with self.app.test_request_context('/api/chat/conversation/conv-1', method='DELETE'):
            with patch.object(chat_routes, 'current_user', _DummyUser()):
                response, status = chat_routes.clear_conversation.__wrapped__('conv-1')

        self.assertEqual(status, 400)
        self.assertEqual(response.get_json()['error'], 'case_id required')

    def test_clear_conversation_deletes_owned_session(self):
        session = object()
        with self.app.test_request_context(
            '/api/chat/conversation/conv-1?case_id=7',
            method='DELETE',
        ):
            with patch.object(chat_routes, 'current_user', _DummyUser()):
                with patch.object(chat_routes.Case, 'get_by_id', return_value=object()):
                    with patch.object(
                        chat_routes.ChatConversationSession,
                        'get_for_user_case',
                        return_value=session,
                    ):
                        with patch.object(chat_routes.db.session, 'delete') as delete_mock:
                            with patch.object(chat_routes.db.session, 'commit') as commit_mock:
                                response = chat_routes.clear_conversation.__wrapped__('conv-1')

        self.assertEqual(response.get_json()['success'], True)
        delete_mock.assert_called_once_with(session)
        commit_mock.assert_called_once()

    def test_fetch_models_requires_admin(self):
        with self.app.test_request_context(
            '/api/settings/ai/fetch-models',
            method='POST',
            json={'provider_type': 'openai'},
        ):
            with patch.object(ai_routes, 'current_user', _DummyUser(is_admin=False)):
                response, status = ai_routes.fetch_models_for_provider.__wrapped__()

        self.assertEqual(status, 403)
        self.assertEqual(response.get_json()['error'], 'Administrator access required')

    def test_rag_campaigns_route_uses_resolved_case_id(self):
        case = Mock(id=11)
        query = Mock()
        query.filter_by.return_value.order_by.return_value.all.return_value = []

        with self.app.test_request_context('/api/rag/campaigns/7'):
            with patch.object(rag_routes, '_load_case_or_404', return_value=(case, None)):
                with patch('models.rag.AttackCampaign.query', query):
                    response = rag_routes.get_campaigns.__wrapped__(7)

        self.assertEqual(response.get_json()['success'], True)
        query.filter_by.assert_called_once_with(case_id=11)

    def test_rag_campaigns_route_short_circuits_missing_case(self):
        missing_response = (self.app.response_class(
            response='{"success": false, "error": "Case not found"}',
            status=404,
            mimetype='application/json',
        ), 404)
        query = Mock()

        with self.app.test_request_context('/api/rag/campaigns/7'):
            with patch.object(rag_routes, '_load_case_or_404', return_value=(None, missing_response)):
                with patch('models.rag.AttackCampaign.query', query):
                    response, status = rag_routes.get_campaigns.__wrapped__(7)

        self.assertEqual(status, 404)
        self.assertEqual(response.get_json()['error'], 'Case not found')
        query.filter_by.assert_not_called()

    def test_canonical_findings_route_uses_shared_payload_builder(self):
        case = Mock(id=17)

        with self.app.test_request_context('/api/findings/list/case-uuid?limit=5'):
            with patch.object(findings_routes.Case, 'get_by_uuid', return_value=case):
                with patch(
                    'routes.findings._build_unified_findings_payload',
                    return_value={'success': True, 'findings': [], 'summary': {'total': 0}},
                ) as payload_mock:
                    response = findings_routes.get_case_findings.__wrapped__('case-uuid')

        self.assertEqual(response.get_json()['success'], True)
        payload_mock.assert_called_once_with(17)

    def test_chat_stream_uses_supplied_conversation_id(self):
        session = types.SimpleNamespace(conversation_id='conv-1', messages=[])

        with self.app.test_request_context(
            '/api/chat/stream',
            method='POST',
            json={'case_id': 7, 'message': 'hello', 'conversation_id': 'conv-1'},
        ):
            with patch.object(chat_routes, 'current_user', _DummyUser()):
                with patch.object(chat_routes.FeatureAvailability, 'is_ai_enabled', return_value=True):
                    with patch.object(chat_routes.Case, 'get_by_id', return_value=object()):
                        with patch.object(
                            chat_routes,
                            '_load_or_create_chat_session',
                            return_value=(session, False, None),
                        ) as session_loader:
                            with patch(
                                'utils.chat_agent.chat_stream',
                                return_value=iter(['data: {"type": "done"}\n\n']),
                            ):
                                response = chat_routes.chat_stream.__wrapped__()
                                payload = b''.join(response.response).decode()

        self.assertIn('"type": "done"', payload)
        session_loader.assert_called_once_with(
            case_id=7,
            user_id='tester',
            conversation_id='conv-1',
        )

    def test_chat_stream_generates_server_conversation_id_when_missing(self):
        session = types.SimpleNamespace(conversation_id='server-conv', messages=[])

        with self.app.test_request_context(
            '/api/chat/stream',
            method='POST',
            json={'case_id': 7, 'message': 'hello'},
        ):
            with patch.object(chat_routes, 'current_user', _DummyUser()):
                with patch.object(chat_routes.FeatureAvailability, 'is_ai_enabled', return_value=True):
                    with patch.object(chat_routes.Case, 'get_by_id', return_value=object()):
                        with patch.object(
                            chat_routes,
                            '_load_or_create_chat_session',
                            return_value=(session, True, None),
                        ) as session_loader:
                            with patch(
                                'utils.chat_agent.chat_stream',
                                return_value=iter([f'data: {json.dumps({"conversation_id": session.conversation_id})}\n\n']),
                            ):
                                response = chat_routes.chat_stream.__wrapped__()
                                payload = b''.join(response.response).decode()

        self.assertIn(session.conversation_id, payload)
        called_conversation_id = session_loader.call_args.kwargs['conversation_id']
        self.assertTrue(isinstance(called_conversation_id, str) and called_conversation_id)


if __name__ == '__main__':
    unittest.main()
