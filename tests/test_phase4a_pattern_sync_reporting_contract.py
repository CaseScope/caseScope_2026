import importlib.util
import sys
import types
import unittest
from pathlib import Path
from types import SimpleNamespace


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

pattern_sync_reporting = _load_module(
    'utils.pattern_sync_reporting',
    UTILS_DIR / 'pattern_sync_reporting.py',
)


class Phase4aPatternSyncReportingContractTestCase(unittest.TestCase):
    def test_finalize_rag_sync_log_applies_normalized_completion_fields(self):
        sync_log = SimpleNamespace(
            patterns_added=0,
            patterns_updated=0,
            success=False,
            completed_at=None,
            error_message=None,
        )

        pattern_sync_reporting.finalize_rag_sync_log(
            sync_log,
            patterns_added=5,
            patterns_updated=2,
            success=True,
            error_message='partial warning',
            completed_at='2026-04-11T13:00:00',
        )

        self.assertEqual(sync_log.patterns_added, 5)
        self.assertEqual(sync_log.patterns_updated, 2)
        self.assertTrue(sync_log.success)
        self.assertEqual(sync_log.completed_at, '2026-04-11T13:00:00')
        self.assertEqual(sync_log.error_message, 'partial warning')

    def test_build_opencti_sync_response_projects_expected_summary(self):
        stats = {
            'attack_patterns': 4,
            'indicators': 2,
            'updated': 3,
            'overlays_added': 5,
            'overlays_updated': 1,
        }
        response = pattern_sync_reporting.build_opencti_sync_response(stats)

        self.assertTrue(response['success'])
        self.assertEqual(response['synced'], stats)
        self.assertIn('Synced 4 patterns, 2 indicators', response['message'])

    def test_build_mitre_and_multi_source_responses_project_expected_summary(self):
        mitre_response = pattern_sync_reporting.build_mitre_sync_response(
            {
                'new_patterns': 7,
                'updated_patterns': 3,
                'errors': 1,
            }
        )
        self.assertTrue(mitre_response['success'])
        self.assertIn('Synced 7 new patterns, updated 3, 1 errors', mitre_response['message'])

        multi_source_response = pattern_sync_reporting.build_multi_source_sync_response(
            stats={'total_added': 11, 'total_updated': 4},
            sources=['hayabusa', 'opencti_sigma'],
            total_patterns=120,
            executable_patterns=90,
        )
        self.assertTrue(multi_source_response['success'])
        self.assertEqual(multi_source_response['sources_synced'], ['hayabusa', 'opencti_sigma'])
        self.assertEqual(multi_source_response['total_patterns'], 120)
        self.assertEqual(multi_source_response['executable_patterns'], 90)
        self.assertIn('Synced 11 new patterns from 2 sources', multi_source_response['message'])

    def test_rag_tasks_use_shared_pattern_sync_reporting_helpers(self):
        source = (REPO_ROOT / 'tasks' / 'rag_tasks.py').read_text()
        self.assertIn('from utils.pattern_sync_reporting import (', source)
        self.assertIn('finalize_rag_sync_log(', source)
        self.assertIn('build_opencti_sync_response(', source)
        self.assertIn('build_mitre_sync_response(', source)
        self.assertIn('build_multi_source_sync_response(', source)


if __name__ == '__main__':
    unittest.main()
