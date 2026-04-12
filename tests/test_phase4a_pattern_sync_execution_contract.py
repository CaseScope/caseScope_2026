import importlib.util
import sys
import types
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
UTILS_DIR = REPO_ROOT / 'utils'


def _load_module(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f'Unable to load module from {path}')
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


utils_pkg = sys.modules.setdefault('utils', types.ModuleType('utils'))
utils_pkg.__path__ = [str(UTILS_DIR)]

pattern_sync_execution = _load_module(
    'utils.pattern_sync_execution',
    UTILS_DIR / 'pattern_sync_execution.py',
)


class Phase4aPatternSyncExecutionContractTestCase(unittest.TestCase):
    def test_ensure_git_checkout_pulls_existing_repo_or_clones_missing_repo(self):
        commands = []

        def _run_command(command, **kwargs):
            commands.append((command, kwargs))

        pattern_sync_execution.ensure_git_checkout(
            '/tmp/existing',
            'https://example.com/repo.git',
            path_exists=lambda path: True,
            run_command=_run_command,
        )
        pattern_sync_execution.ensure_git_checkout(
            '/tmp/missing',
            'https://example.com/repo.git',
            path_exists=lambda path: False,
            run_command=_run_command,
        )

        self.assertEqual(
            commands[0][0],
            ['git', '-C', '/tmp/existing', 'pull', '--ff-only'],
        )
        self.assertEqual(commands[0][1]['timeout'], 120)
        self.assertEqual(
            commands[1][0],
            ['git', 'clone', '--depth', '1', 'https://example.com/repo.git', '/tmp/missing'],
        )
        self.assertEqual(commands[1][1]['timeout'], 300)

    def test_sync_patterns_from_directories_processes_existing_paths_only(self):
        converted_paths = []
        saved_patterns = []
        applied_results = []
        stats = {'source_count': 0, 'total_added': 0, 'total_updated': 0}

        pattern_sync_execution.sync_patterns_from_directories(
            ['/tmp/exists', '/tmp/missing'],
            source_key='source_count',
            stats=stats,
            convert_directory=lambda path: converted_paths.append(path) or [{'id': path}],
            save_pattern=lambda pattern: saved_patterns.append(pattern) or True,
            apply_sync_result=lambda stats, **kwargs: applied_results.append(kwargs),
            path_exists=lambda path: path.endswith('exists'),
        )

        self.assertEqual(converted_paths, ['/tmp/exists'])
        self.assertEqual(saved_patterns, [{'id': '/tmp/exists'}])
        self.assertEqual(
            applied_results,
            [{'source_key': 'source_count', 'created': True}],
        )

    def test_sync_repo_backed_patterns_checks_out_repo_then_processes_directories(self):
        checkout_calls = []
        sync_calls = []

        pattern_sync_execution.sync_repo_backed_patterns(
            repo_dir='/tmp/repo',
            repo_url='https://example.com/repo.git',
            directory_paths=['/tmp/repo/rules'],
            source_key='sigma_github',
            stats={'sigma_github': 0, 'total_added': 0, 'total_updated': 0},
            convert_directory=lambda path: [],
            save_pattern=lambda pattern: True,
            apply_sync_result=lambda stats, **kwargs: None,
            checkout_repo=lambda repo_dir, repo_url: checkout_calls.append((repo_dir, repo_url)),
            sync_directories=lambda directory_paths, **kwargs: sync_calls.append((directory_paths, kwargs)),
        )

        self.assertEqual(checkout_calls, [('/tmp/repo', 'https://example.com/repo.git')])
        self.assertEqual(sync_calls[0][0], ['/tmp/repo/rules'])
        self.assertEqual(sync_calls[0][1]['source_key'], 'sigma_github')

    def test_sync_opencti_sigma_indicators_converts_filters_and_records_results(self):
        converted = []
        saved = []
        applied = []
        errors = []
        stats = {'opencti_sigma': 0, 'total_added': 0, 'total_updated': 0}

        def _convert_indicator(indicator):
            converted.append(indicator['opencti_id'])
            if indicator['opencti_id'] == 'bad':
                raise ValueError('boom')
            if indicator['opencti_id'] == 'skip':
                return {'source_id': 'skip'}
            return {
                'source_id': indicator['opencti_id'],
                'required_event_ids': ['4688'],
            }

        pattern_sync_execution.sync_opencti_sigma_indicators(
            [
                {'opencti_id': 'good'},
                {'opencti_id': 'skip'},
                {'opencti_id': 'bad'},
            ],
            source_key='opencti_sigma',
            stats=stats,
            convert_indicator=_convert_indicator,
            save_pattern=lambda pattern: saved.append(pattern) or True,
            apply_sync_result=lambda stats, **kwargs: applied.append(kwargs),
            on_indicator_error=lambda indicator, exc: errors.append((indicator['opencti_id'], str(exc))),
        )

        self.assertEqual(converted, ['good', 'skip', 'bad'])
        self.assertEqual(saved, [{'source_id': 'good', 'required_event_ids': ['4688']}])
        self.assertEqual(applied, [{'source_key': 'opencti_sigma', 'created': True}])
        self.assertEqual(errors, [('bad', 'boom')])

    def test_load_opencti_sigma_indicators_projects_disabled_unavailable_and_ready_states(self):
        disabled = pattern_sync_execution.load_opencti_sigma_indicators(
            feature_activated=False,
            opencti_enabled=True,
            rag_sync_enabled=True,
            get_client=lambda: object(),
        )
        self.assertEqual(disabled['status'], 'disabled')
        self.assertEqual(disabled['indicators'], [])

        unavailable = pattern_sync_execution.load_opencti_sigma_indicators(
            feature_activated=True,
            opencti_enabled=True,
            rag_sync_enabled=True,
            get_client=lambda: types.SimpleNamespace(init_error='boom'),
        )
        self.assertEqual(unavailable['status'], 'unavailable')
        self.assertEqual(unavailable['error_message'], 'Client not available')

        ready = pattern_sync_execution.load_opencti_sigma_indicators(
            feature_activated=True,
            opencti_enabled=True,
            rag_sync_enabled=True,
            get_client=lambda: types.SimpleNamespace(
                init_error=None,
                get_sigma_indicators=lambda limit: [{'opencti_id': f'id-{limit}'}],
            ),
            indicator_limit=25,
        )
        self.assertEqual(ready['status'], 'ready')
        self.assertEqual(ready['indicators'], [{'opencti_id': 'id-25'}])

    def test_rag_tasks_use_shared_pattern_sync_execution_helpers(self):
        source = (REPO_ROOT / 'tasks' / 'rag_tasks.py').read_text()
        self.assertIn('from utils.pattern_sync_execution import (', source)
        self.assertIn('load_opencti_sigma_indicators(', source)
        self.assertIn('sync_repo_backed_patterns(', source)
        self.assertIn('sync_opencti_sigma_indicators(', source)
        self.assertIn('sync_patterns_from_directories(', source)
        self.assertIn('source_stage_runners = _build_external_sync_source_stage_runners(', source)
        self.assertIn('def _build_external_sync_source_stage_runners(', source)
        self.assertIn('for source_name in sources:', source)


if __name__ == '__main__':
    unittest.main()
