import importlib.util
import os
import sys
import types
import unittest
from pathlib import Path

os.environ.setdefault('SECRET_KEY', 'test-secret')

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
compute_overlay_score_adjustment = pattern_overlay.compute_overlay_score_adjustment
match_external_pattern_to_builtins = pattern_overlay.match_external_pattern_to_builtins
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
        self.assertEqual(package.overlay_score_adjustment, 4.0)
        self.assertEqual(package.deterministic_score, 46.0)
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

    def test_rag_tasks_use_shared_overlay_helpers(self):
        source = Path('/opt/casescope/tasks/rag_tasks.py').read_text()
        self.assertIn('build_opencti_mitre_overlay_payload', source)
        self.assertIn('build_opencti_sigma_companion_queries', source)
        self.assertIn('build_opencti_sigma_overlay_payload', source)


if __name__ == '__main__':
    unittest.main()
