import importlib.util
import os
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault('SECRET_KEY', 'test-secret')

REPO_ROOT = Path(__file__).resolve().parents[1]
UTILS_DIR = REPO_ROOT / 'utils'

from tests.phase7_rag_tasks_loader import load_rag_tasks_with_stubs


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

pattern_check_definitions = _load_module(
    'utils.pattern_check_definitions',
    UTILS_DIR / 'pattern_check_definitions.py',
)
pattern_overlay = _load_module(
    'utils.pattern_overlay',
    UTILS_DIR / 'pattern_overlay.py',
)

PatternOverlayEnhancer = pattern_overlay.PatternOverlayEnhancer
build_opencti_mitre_overlay_payload = pattern_overlay.build_opencti_mitre_overlay_payload
build_opencti_sigma_companion_queries = pattern_overlay.build_opencti_sigma_companion_queries
build_opencti_sigma_overlay_payload = pattern_overlay.build_opencti_sigma_overlay_payload
apply_overlay_sync_summary = pattern_overlay.apply_overlay_sync_summary
compute_overlay_score_adjustment = pattern_overlay.compute_overlay_score_adjustment
match_external_pattern_to_builtins = pattern_overlay.match_external_pattern_to_builtins
summarize_overlay_sync_results = pattern_overlay.summarize_overlay_sync_results
sync_external_pattern_overlays = pattern_overlay.sync_external_pattern_overlays
EvidencePackage = pattern_check_definitions.EvidencePackage


class PatternOverlayTestCase(unittest.TestCase):
    def test_match_external_pattern_prefers_exact_mitre_overlap(self):
        matches = match_external_pattern_to_builtins(
            'Remote Service Execution via PsExec',
            mitre_techniques=['T1021.002'],
            aliases=['psexec'],
        )

        self.assertTrue(matches)
        self.assertEqual(matches[0]['pattern_id'], 'psexec_execution')
        self.assertIn('mitre_technique', matches[0]['match_reasons'])

    def test_overlay_boost_is_bounded_for_weak_and_strong_scores(self):
        overlays = [{
            'confidence_boost': 7.0,
            'freshness_score': 92.0,
        }]

        self.assertEqual(compute_overlay_score_adjustment(20, overlays), 0.0)
        self.assertEqual(compute_overlay_score_adjustment(38, overlays), 2.0)
        self.assertEqual(compute_overlay_score_adjustment(48, overlays), 4.0)
        self.assertEqual(compute_overlay_score_adjustment(72, overlays), 7.0)

    def test_overlay_enhancer_applies_context_without_overpromoting(self):
        enhancer = PatternOverlayEnhancer(overlays_by_pattern={
            'psexec_execution': [{
                'source': 'opencti_sigma',
                'confidence_boost': 6.0,
                'freshness_score': 90.0,
                'matched_mitre_techniques': ['T1021.002'],
            }]
        })
        package = EvidencePackage(
            anchor={},
            pattern_id='psexec_execution',
            pattern_name='PsExec/SMB Lateral Movement',
            correlation_key='demo',
            deterministic_score=42,
            mitre_techniques=['T1021.002'],
        )

        context = enhancer.apply_to_package(package)

        self.assertIsNotNone(context)
        self.assertEqual(context['authority'], 'metadata_only')
        self.assertEqual(package.overlay_score_adjustment, 4.0)
        self.assertEqual(package.deterministic_score, 42)
        self.assertEqual(context['sources'], ['opencti_sigma'])

    def test_build_opencti_mitre_overlay_payload_projects_shared_fields(self):
        payload = build_opencti_mitre_overlay_payload(
            {
                'name': 'Credential Dumping',
                'opencti_id': 'opencti--123',
                'mitre_id': 'T1003',
                'description': 'General description',
                'detection': 'Review LSASS access telemetry.',
                'kill_chain_phases': ['credential-access'],
                'platforms': ['Windows'],
            },
            {
                'matched_mitre_techniques': ['T1003'],
                'match_reasons': ['mitre_technique', 'alias_exact'],
            },
        )

        self.assertEqual(payload['source'], 'opencti')
        self.assertEqual(payload['source_id'], 'opencti--123')
        self.assertEqual(payload['overlay_type'], 'mitre_context')
        self.assertEqual(payload['source_mitre_techniques'], ['T1003'])
        self.assertEqual(payload['aliases'], ['Credential Dumping'])
        self.assertIn('match_reasons', payload['overlay_data'])
        self.assertGreater(payload['confidence_boost'], 0)

    def test_build_opencti_sigma_overlay_payload_projects_companion_context(self):
        companion_queries = build_opencti_sigma_companion_queries(
            {
                'name': 'Suspicious Service Creation',
                'clickhouse_query': 'SELECT * FROM events',
            }
        )
        payload = build_opencti_sigma_overlay_payload(
            {
                'name': 'Suspicious Service Creation',
                'opencti_id': 'indicator--123',
                'score': 88,
                'valid_from': '2026-04-01T00:00:00Z',
                'valid_until': '2026-05-01T00:00:00Z',
                'labels': ['sigma', 'windows'],
                'kill_chain_phases': ['persistence'],
            },
            {
                'matched_mitre_techniques': ['T1543.003'],
                'match_reasons': ['mitre_technique'],
            },
            sigma_techniques=['T1543.003'],
            companion_queries=companion_queries,
        )

        self.assertEqual(payload['source'], 'opencti_sigma')
        self.assertEqual(payload['source_id'], 'indicator--123')
        self.assertEqual(payload['overlay_type'], 'sigma_companion')
        self.assertEqual(payload['source_mitre_techniques'], ['T1543.003'])
        self.assertEqual(payload['companion_queries'], companion_queries)
        self.assertEqual(payload['overlay_data']['indicator_score'], 88)
        self.assertGreater(payload['freshness_score'], 0)

    def test_sync_external_pattern_overlays_reuses_shared_match_and_upsert_flow(self):
        with patch.object(
            pattern_overlay,
            'match_external_pattern_to_builtins',
            return_value=[
                {'pattern_id': 'psexec_execution', 'matched_mitre_techniques': ['T1021.002'], 'match_reasons': ['mitre_technique']},
                {'pattern_id': 'wmi_lateral', 'matched_mitre_techniques': [], 'match_reasons': ['alias_exact']},
            ],
        ) as match_mock:
            with patch.object(
                pattern_overlay,
                'upsert_pattern_overlay',
                side_effect=[True, False],
            ) as upsert_mock:
                results = sync_external_pattern_overlays(
                    external_name='PsExec',
                    mitre_techniques=['T1021.002'],
                    payload_builder=lambda match: {
                        'source': 'opencti_sigma',
                        'source_id': 'indicator--123',
                        'overlay_type': 'sigma_companion',
                        'source_pattern_name': 'PsExec',
                        'matched_mitre_techniques': match['matched_mitre_techniques'],
                    },
                )

        self.assertEqual(results, [True, False])
        match_mock.assert_called_once()
        self.assertEqual(upsert_mock.call_count, 2)
        self.assertEqual(
            upsert_mock.call_args_list[0].kwargs['pattern_id'],
            'psexec_execution',
        )

    def test_summarize_overlay_sync_results_counts_added_and_updated(self):
        summary = summarize_overlay_sync_results([True, False, True, False, False])
        self.assertEqual(summary, {'added': 2, 'updated': 3})

    def test_apply_overlay_sync_summary_accumulates_into_stats_dict(self):
        stats = {'overlays_added': 1, 'overlays_updated': 4}
        apply_overlay_sync_summary(stats, {'added': 2, 'updated': 3})
        self.assertEqual(stats['overlays_added'], 3)
        self.assertEqual(stats['overlays_updated'], 7)

    def test_rag_tasks_use_shared_overlay_helpers(self):
        rag_tasks, restore_modules = load_rag_tasks_with_stubs(
            'pattern_overlay_rag_tasks_under_test'
        )
        try:
            recorded = {
                'overlay_sync_calls': [],
                'overlay_summaries': [],
                'overlay_stats': [],
            }

            class FakeClient:
                init_error = None

                def get_attack_patterns(self, limit=500):
                    return [
                        {'name': 'PsExec', 'mitre_id': 'T1021.002'},
                    ]

                def get_indicators_with_patterns(self, limit=500):
                    return [
                        {
                            'name': 'Suspicious Service Creation',
                            'pattern_type': 'sigma',
                            'pattern': 'title: Suspicious Service Creation',
                            'labels': ['sigma'],
                        }
                    ]

            class FakeAttackPatternQuery:
                def filter_by(self, **_kwargs):
                    return types.SimpleNamespace(first=lambda: None)

            class FakeAttackPattern:
                query = FakeAttackPatternQuery()

            class FakeRAGSyncLog:
                def __init__(self, **kwargs):
                    self.kwargs = kwargs

            fake_opencti = types.ModuleType('utils.opencti')
            fake_opencti.get_opencti_client = lambda: FakeClient()

            fake_database = types.ModuleType('models.database')
            fake_database.db = types.SimpleNamespace(
                session=types.SimpleNamespace(add=lambda _obj: None, commit=lambda: None)
            )

            fake_settings = types.ModuleType('models.system_settings')
            fake_settings.SettingKeys = types.SimpleNamespace(
                OPENCTI_ENABLED='opencti_enabled',
                OPENCTI_RAG_SYNC='opencti_rag_sync',
            )
            fake_settings.SystemSettings = types.SimpleNamespace(
                get=lambda key, default=None: True if key in {
                    fake_settings.SettingKeys.OPENCTI_ENABLED,
                    fake_settings.SettingKeys.OPENCTI_RAG_SYNC,
                } else default
            )

            fake_license = types.ModuleType('utils.licensing.license_manager')
            fake_license.LicenseManager = types.SimpleNamespace(
                is_feature_activated=lambda feature: feature == 'opencti'
            )

            fake_rag_models = types.ModuleType('models.rag')
            fake_rag_models.AttackPattern = FakeAttackPattern
            fake_rag_models.RAGSyncLog = FakeRAGSyncLog

            fake_pattern_overlay = types.ModuleType('utils.pattern_overlay')
            fake_pattern_overlay.build_opencti_mitre_overlay_payload = (
                lambda pattern, match: {'kind': 'mitre', 'pattern': pattern['name'], 'match': match}
            )
            fake_pattern_overlay.build_opencti_sigma_companion_queries = (
                lambda converted_sigma: {'query': converted_sigma.get('mitre_technique')}
            )
            fake_pattern_overlay.build_opencti_sigma_overlay_payload = (
                lambda indicator, match, **kwargs: {
                    'kind': 'sigma',
                    'indicator': indicator['name'],
                    'match': match,
                    'companion_queries': kwargs['companion_queries'],
                }
            )
            fake_pattern_overlay.sync_external_pattern_overlays = (
                lambda **kwargs: recorded['overlay_sync_calls'].append(kwargs) or [True, False]
            )
            fake_pattern_overlay.summarize_overlay_sync_results = (
                lambda results: recorded['overlay_summaries'].append(list(results)) or {'added': 1, 'updated': 1}
            )
            fake_pattern_overlay.apply_overlay_sync_summary = (
                lambda stats, summary: recorded['overlay_stats'].append((dict(stats), dict(summary)))
            )

            fake_sigma_converter = types.ModuleType('utils.sigma_converter')

            class FakeSigmaToPatternConverter:
                def convert_sigma_rule(self, pattern, source=None):
                    return {'mitre_technique': 'T1543.003'}

            fake_sigma_converter.SigmaToPatternConverter = FakeSigmaToPatternConverter

            runtime_modules = {
                'utils.opencti': fake_opencti,
                'models.database': fake_database,
                'models.system_settings': fake_settings,
                'utils.licensing.license_manager': fake_license,
                'models.rag': fake_rag_models,
                'utils.pattern_overlay': fake_pattern_overlay,
                'utils.sigma_converter': fake_sigma_converter,
            }

            task_self = types.SimpleNamespace(update_state=lambda **_kwargs: None)
            original_persist = rag_tasks.persist_attack_pattern_payload
            original_opencti_response = rag_tasks.build_opencti_sync_response
            original_finalize_log = rag_tasks.finalize_rag_sync_log
            original_vector_update = rag_tasks._update_pattern_vectors
            rag_tasks.persist_attack_pattern_payload = lambda *args, **kwargs: (True, {})
            rag_tasks.build_opencti_sync_response = (
                lambda stats: {'success': True, 'stats': dict(stats)}
            )
            rag_tasks.finalize_rag_sync_log = lambda *args, **kwargs: None
            rag_tasks._update_pattern_vectors = lambda: None
            try:
                with patch.dict(sys.modules, runtime_modules):
                    result = rag_tasks.rag_sync_opencti_patterns(task_self, triggered_by='tester')
            finally:
                rag_tasks.persist_attack_pattern_payload = original_persist
                rag_tasks.build_opencti_sync_response = original_opencti_response
                rag_tasks.finalize_rag_sync_log = original_finalize_log
                rag_tasks._update_pattern_vectors = original_vector_update

            self.assertTrue(result['success'])
            self.assertEqual(len(recorded['overlay_sync_calls']), 2)
            self.assertEqual(
                recorded['overlay_sync_calls'][0]['mitre_techniques'],
                ['T1021.002'],
            )
            self.assertEqual(
                recorded['overlay_sync_calls'][1]['mitre_techniques'],
                ['T1543.003'],
            )
            self.assertEqual(recorded['overlay_summaries'], [[True, False], [True, False]])
            self.assertEqual(len(recorded['overlay_stats']), 2)
        finally:
            restore_modules()


if __name__ == '__main__':
    unittest.main()
