import os
import sys
import types
import unittest
from pathlib import Path

os.environ.setdefault('SECRET_KEY', 'test-secret')

import tasks.archive_tasks as archive_tasks
import tasks.celery_tasks as celery_tasks
import tasks.memory_tasks as memory_tasks
import tasks.pcap_tasks as pcap_tasks


class StartupHardeningRegressionTestCase(unittest.TestCase):
    def _assert_worker_app_bootstrap_disabled(self, module):
        fake_app = object()
        calls = []

        fake_app_module = types.ModuleType('app')

        def fake_create_app(**kwargs):
            calls.append(kwargs)
            return fake_app

        fake_app_module.create_app = fake_create_app
        original = sys.modules.get('app')
        sys.modules['app'] = fake_app_module
        module._flask_app = None

        try:
            returned = module.get_flask_app()
        finally:
            module._flask_app = None
            if original is not None:
                sys.modules['app'] = original
            else:
                del sys.modules['app']

        self.assertIs(returned, fake_app)
        self.assertEqual(calls, [{
            'run_startup_bootstrap': False,
            'register_blueprints': False,
        }])

    def test_celery_tasks_use_worker_safe_app_init(self):
        self._assert_worker_app_bootstrap_disabled(celery_tasks)

    def test_pcap_tasks_use_worker_safe_app_init(self):
        self._assert_worker_app_bootstrap_disabled(pcap_tasks)

    def test_memory_tasks_use_worker_safe_app_init(self):
        self._assert_worker_app_bootstrap_disabled(memory_tasks)

    def test_archive_tasks_use_worker_safe_app_init(self):
        self._assert_worker_app_bootstrap_disabled(archive_tasks)

    def test_case_scope_backfill_only_updates_rows_with_junction_matches(self):
        app_source = Path('/opt/casescope/app.py').read_text()

        self.assertIn('def _populate_case_id_from_junction(', app_source)
        self.assertIn('WHERE case_id IS NULL', app_source)
        self.assertIn('AND EXISTS (', app_source)
        self.assertEqual(app_source.count('_populate_case_id_from_junction('), 4)

    def test_case_scope_backfill_helper_is_used_for_all_three_tables(self):
        app_source = Path('/opt/casescope/app.py').read_text()

        self.assertIn("'iocs',\n                        'id',\n                        'ioc_cases',\n                        'ioc_id'", app_source)
        self.assertIn("'known_systems',\n                        'id',\n                        'known_system_cases',\n                        'system_id'", app_source)
        self.assertIn("'known_users',\n                        'id',\n                        'known_user_cases',\n                        'user_id'", app_source)


if __name__ == '__main__':
    unittest.main()
