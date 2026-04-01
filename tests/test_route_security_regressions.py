import os
import unittest
from unittest.mock import patch

from flask import Flask
from sqlalchemy.exc import IntegrityError

os.environ.setdefault('SECRET_KEY', 'test-secret')

import routes.activation as activation_routes
import routes.api as api_routes
import routes.main as main_routes
import routes.parsing as parsing_routes


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
            api_routes._remember_task_access('demo-task', case_id=7)

            self.assertTrue(api_routes._task_access_allowed('demo-task', case_id=7))
            self.assertFalse(api_routes._task_access_allowed('demo-task', case_id=8))
            self.assertFalse(api_routes._task_access_allowed('unknown-task'))

    def test_noise_tagging_rejects_viewers(self):
        with self.app.test_request_context('/api/hunting/noise/tag/1', method='POST'):
            with patch.object(api_routes, 'current_user', _DummyUser(permission_level='viewer')):
                response, status = api_routes.start_noise_tagging.__wrapped__(1)

        self.assertEqual(status, 403)
        self.assertEqual(response.get_json()['error'], 'Viewers cannot modify hunting state')

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


if __name__ == '__main__':
    unittest.main()
