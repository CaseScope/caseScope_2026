import os
import unittest
from unittest.mock import Mock, patch
from pathlib import Path

from flask import Flask
from sqlalchemy.exc import IntegrityError

os.environ.setdefault('SECRET_KEY', 'test-secret')

import routes.activation as activation_routes
import routes.ai as ai_routes
import routes.chat as chat_routes
import routes.hunting as hunting_routes
import routes.main as main_routes
import routes.parsing as parsing_routes
import routes.rag as rag_routes
import routes.route_helpers as route_helpers


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
        self.app = Flask(__name__)
        self.app.secret_key = 'test-secret'

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

    def test_bulk_noise_tag_rejects_viewers(self):
        with self.app.test_request_context('/api/hunting/events/bulk-noise/1', method='POST'):
            with patch.object(hunting_routes, 'current_user', _DummyUser(permission_level='viewer')):
                response, status = hunting_routes.bulk_noise_tag.__wrapped__(1)

        self.assertEqual(status, 403)
        self.assertEqual(response.get_json()['error'], 'Viewers cannot modify hunting state')

    def test_bulk_noise_tag_updates_noise_matched_column(self):
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
                        response = hunting_routes.bulk_noise_tag.__wrapped__(7)

        self.assertEqual(response.get_json()['success'], True)
        query_text = client.query.call_args.kwargs['parameters']
        self.assertEqual(query_text['case_id'], 7)
        self.assertIn('noise_matched = true', client.query.call_args.args[0])

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

    def test_rag_unified_findings_route_uses_shared_payload_builder(self):
        case = Mock(id=17)

        with self.app.test_request_context('/api/rag/unified-findings/7?limit=5'):
            with patch.object(rag_routes, '_load_case_or_404', return_value=(case, None)):
                with patch(
                    'routes.findings._build_unified_findings_payload',
                    return_value={'success': True, 'findings': [], 'summary': {'total': 0}},
                ) as payload_mock:
                    response = rag_routes.get_unified_findings_route.__wrapped__(7)

        self.assertEqual(response.get_json()['success'], True)
        payload_mock.assert_called_once_with(17)

    def test_chat_frontend_tracks_server_conversation_id(self):
        source = Path('/opt/casescope/static/templates/case_hunting.html').read_text()

        self.assertIn('let chatConversationId = null;', source)
        self.assertIn('conversation_id: chatConversationId', source)
        self.assertIn('/api/chat/conversation/', source)


if __name__ == '__main__':
    unittest.main()
