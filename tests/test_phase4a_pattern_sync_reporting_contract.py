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
    def test_get_external_sync_source_config_returns_normalized_metadata(self):
        sigma_github = pattern_sync_reporting.get_external_sync_source_config('sigma_github')
        self.assertEqual(
            sigma_github,
            {
                'stage': 'sigma_github',
                'progress': 30,
                'status': 'Syncing SigmaHQ rules from GitHub...',
                'source_key': 'sigma_github',
                'source_label': 'SigmaHQ',
            },
        )

        opencti_sigma = pattern_sync_reporting.get_external_sync_source_config('opencti_sigma')
        self.assertEqual(opencti_sigma['source_label'], 'OpenCTI Sigma')
        self.assertEqual(opencti_sigma['error_label'], 'OpenCTI')

        with self.assertRaises(KeyError):
            pattern_sync_reporting.get_external_sync_source_config('unknown')

    def test_begin_log_and_error_helpers_use_shared_stage_metadata(self):
        progress_calls = []
        sync_config = pattern_sync_reporting.begin_external_sync_stage(
            'sigma_github',
            update_state=lambda **kwargs: progress_calls.append(kwargs),
        )
        self.assertEqual(sync_config['source_key'], 'sigma_github')
        self.assertEqual(
            progress_calls,
            [{
                'state': 'PROGRESS',
                'meta': {
                    'stage': 'sigma_github',
                    'progress': 30,
                    'status': 'Syncing SigmaHQ rules from GitHub...',
                },
            }],
        )

        messages = []
        pattern_sync_reporting.log_external_sync_stage_summary(
            sync_config,
            {'sigma_github': 9},
            log_info=messages.append,
        )
        self.assertEqual(messages, ['[RAG] SigmaHQ: Added 9 patterns'])

        stats = {'errors': []}
        pattern_sync_reporting.append_external_sync_stage_error(
            stats,
            pattern_sync_reporting.get_external_sync_source_config('opencti_sigma'),
            message='Client not available',
        )
        self.assertEqual(stats['errors'], ['OpenCTI: Client not available'])

    def test_run_external_sync_stage_wraps_success_timeout_and_error_paths(self):
        progress_calls = []
        info_messages = []
        error_messages = []
        stats = {'sigma_github': 4, 'errors': []}

        pattern_sync_reporting.run_external_sync_stage(
            'sigma_github',
            stats=stats,
            update_state=lambda **kwargs: progress_calls.append(kwargs),
            run_stage=lambda sync_config: True,
            log_info=info_messages.append,
            log_error=lambda exc: error_messages.append(str(exc)),
        )
        self.assertEqual(len(progress_calls), 1)
        self.assertEqual(info_messages, ['[RAG] SigmaHQ: Added 4 patterns'])
        self.assertEqual(error_messages, [])

        class FakeTimeoutError(Exception):
            pass

        pattern_sync_reporting.run_external_sync_stage(
            'sigma_github',
            stats=stats,
            update_state=lambda **kwargs: None,
            run_stage=lambda sync_config: (_ for _ in ()).throw(FakeTimeoutError('boom')),
            log_info=info_messages.append,
            log_error=lambda exc: error_messages.append(str(exc)),
            timeout_error_type=FakeTimeoutError,
            timeout_message='Git clone timed out',
        )
        self.assertIn('SigmaHQ: Git clone timed out', stats['errors'])

        pattern_sync_reporting.run_external_sync_stage(
            'opencti_sigma',
            stats=stats,
            update_state=lambda **kwargs: None,
            run_stage=lambda sync_config: (_ for _ in ()).throw(ValueError('bad stage')),
            log_info=info_messages.append,
            log_error=lambda exc: error_messages.append(str(exc)),
        )
        self.assertIn('OpenCTI: bad stage', stats['errors'])
        self.assertIn('bad stage', error_messages)

    def test_default_external_sources_and_stats_derive_from_shared_catalog(self):
        self.assertEqual(
            pattern_sync_reporting.get_default_external_sync_sources(),
            ['hayabusa', 'opencti_sigma'],
        )

        stats = pattern_sync_reporting.initialize_external_sync_stats()
        self.assertEqual(stats['hayabusa'], 0)
        self.assertEqual(stats['sigma_github'], 0)
        self.assertEqual(stats['mdecrevoisier'], 0)
        self.assertEqual(stats['opencti_sigma'], 0)
        self.assertEqual(stats['car'], 0)
        self.assertEqual(stats['total_added'], 0)
        self.assertEqual(stats['total_updated'], 0)
        self.assertEqual(stats['errors'], [])
        self.assertNotIn('vectorizing', stats)

    def test_apply_external_source_sync_result_updates_source_and_totals(self):
        stats = {'hayabusa': 1, 'total_added': 3, 'total_updated': 4}

        pattern_sync_reporting.apply_external_source_sync_result(
            stats,
            source_key='hayabusa',
            created=True,
        )
        pattern_sync_reporting.apply_external_source_sync_result(
            stats,
            source_key='hayabusa',
            created=False,
        )

        self.assertEqual(stats['hayabusa'], 2)
        self.assertEqual(stats['total_added'], 4)
        self.assertEqual(stats['total_updated'], 5)

    def test_build_progress_and_summary_messages_project_normalized_shapes(self):
        progress_meta = pattern_sync_reporting.build_sync_progress_meta(
            stage='sigma_github',
            progress=30,
            status='Syncing SigmaHQ rules from GitHub...',
        )
        self.assertEqual(
            progress_meta,
            {
                'stage': 'sigma_github',
                'progress': 30,
                'status': 'Syncing SigmaHQ rules from GitHub...',
            },
        )
        self.assertEqual(
            pattern_sync_reporting.build_external_source_summary_message(
                source_label='SigmaHQ',
                added_count=12,
            ),
            '[RAG] SigmaHQ: Added 12 patterns',
        )

    def test_append_and_summarize_sync_errors_project_normalized_messages(self):
        stats = {'errors': []}

        pattern_sync_reporting.append_sync_error(
            stats,
            source_label='SigmaHQ',
            message='Git clone timed out',
        )
        pattern_sync_reporting.append_sync_error(
            stats,
            source_label='OpenCTI',
            error=ValueError('x' * 120),
        )

        self.assertEqual(stats['errors'][0], 'SigmaHQ: Git clone timed out')
        self.assertEqual(len(stats['errors'][1]), len('OpenCTI: ') + 100)
        self.assertEqual(
            pattern_sync_reporting.summarize_sync_errors(
                ['one', 'two', 'three', 'four', 'five', 'six'],
            ),
            'one; two; three; four; five',
        )
        self.assertIsNone(pattern_sync_reporting.summarize_sync_errors([]))

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
        self.assertIn('get_default_external_sync_sources(', source)
        self.assertIn('initialize_external_sync_stats(', source)
        self.assertIn('apply_external_source_sync_result', source)
        self.assertIn('run_external_sync_stage(', source)
        self.assertIn('finalize_rag_sync_log(', source)
        self.assertIn('summarize_sync_errors(', source)
        self.assertIn('build_opencti_sync_response(', source)
        self.assertIn('build_mitre_sync_response(', source)
        self.assertIn('build_multi_source_sync_response(', source)


if __name__ == '__main__':
    unittest.main()
