import ast
import os
import unittest
from pathlib import Path

os.environ.setdefault('SECRET_KEY', 'test-secret')


class StartupHardeningRegressionTestCase(unittest.TestCase):
    def _load_app_tree(self):
        return ast.parse(Path('/opt/casescope/app.py').read_text())

    def _case_scope_backfill_specs(self):
        tree = self._load_app_tree()
        specs = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not (
                isinstance(node.func, ast.Name)
                and node.func.id == '_populate_case_id_from_junction'
                and len(node.args) >= 4
                and all(isinstance(arg, ast.Constant) and isinstance(arg.value, str) for arg in node.args[:4])
            ):
                continue
            target_table, primary_key_column, junction_table, junction_column = [
                arg.value for arg in node.args[:4]
            ]
            specs.append(
                (
                    target_table,
                    primary_key_column,
                    junction_table,
                    junction_column,
                    f'UPDATE {target_table} FROM {junction_table} '
                    f'WHERE case_id IS NULL AND EXISTS (SELECT 1 ...) '
                    f'AND {junction_column} = {target_table}.{primary_key_column}',
                )
            )
        return specs

    def _get_flask_app_create_app_kwargs(self, relative_path):
        tree = ast.parse(Path('/opt/casescope', relative_path).read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not (
                isinstance(node.func, ast.Name)
                and node.func.id == 'create_app'
            ):
                continue
            kwargs = {}
            for keyword in node.keywords:
                if isinstance(keyword.value, ast.Constant):
                    kwargs[keyword.arg] = keyword.value.value
            if kwargs:
                return kwargs
        self.fail(f'No create_app(...) call found in {relative_path}')

    def test_celery_tasks_use_worker_safe_app_init(self):
        self.assertEqual(
            self._get_flask_app_create_app_kwargs('tasks/celery_tasks.py'),
            {
                'run_startup_bootstrap': False,
                'register_blueprints': False,
            },
        )

    def test_pcap_tasks_use_worker_safe_app_init(self):
        self.assertEqual(
            self._get_flask_app_create_app_kwargs('tasks/pcap_tasks.py'),
            {
                'run_startup_bootstrap': False,
                'register_blueprints': False,
            },
        )

    def test_memory_tasks_use_worker_safe_app_init(self):
        self.assertEqual(
            self._get_flask_app_create_app_kwargs('tasks/memory_tasks.py'),
            {
                'run_startup_bootstrap': False,
                'register_blueprints': False,
            },
        )

    def test_archive_tasks_use_worker_safe_app_init(self):
        self.assertEqual(
            self._get_flask_app_create_app_kwargs('tasks/archive_tasks.py'),
            {
                'run_startup_bootstrap': False,
                'register_blueprints': False,
            },
        )

    def test_case_scope_backfill_only_updates_rows_with_junction_matches(self):
        update_queries = [query for *_parts, query in self._case_scope_backfill_specs()]

        self.assertEqual(len(update_queries), 3)
        for query in update_queries:
            with self.subTest(query=query):
                self.assertIn('WHERE case_id IS NULL', query)
                self.assertIn('AND EXISTS (', query)

    def test_case_scope_backfill_helper_is_used_for_all_three_tables(self):
        specs = {
            (target_table, junction_table, junction_column)
            for target_table, _pk, junction_table, junction_column, _query in self._case_scope_backfill_specs()
        }
        self.assertIn(('iocs', 'ioc_cases', 'ioc_id'), specs)
        self.assertIn(('known_systems', 'known_system_cases', 'system_id'), specs)
        self.assertIn(('known_users', 'known_user_cases', 'user_id'), specs)


if __name__ == '__main__':
    unittest.main()
