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

    def test_rag_tasks_use_shared_pattern_sync_execution_helpers(self):
        source = (REPO_ROOT / 'tasks' / 'rag_tasks.py').read_text()
        self.assertIn('from utils.pattern_sync_execution import (', source)
        self.assertIn('ensure_git_checkout(', source)
        self.assertIn('sync_patterns_from_directories(', source)


if __name__ == '__main__':
    unittest.main()
