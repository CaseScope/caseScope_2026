import os
import sys
import types
import unittest

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


if __name__ == '__main__':
    unittest.main()
