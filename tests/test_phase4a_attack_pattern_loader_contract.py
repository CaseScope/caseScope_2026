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

attack_pattern_loader = _load_module(
    'utils.attack_pattern_loader',
    UTILS_DIR / 'attack_pattern_loader.py',
)


class Phase4aAttackPatternLoaderContractTestCase(unittest.TestCase):
    def test_resolve_attack_pattern_lookup_prefers_source_id(self):
        lookup = attack_pattern_loader.resolve_attack_pattern_lookup(
            {
                'name': 'Sigma Rule',
                'source': 'sigma',
                'source_id': 'rule-123',
            }
        )

        self.assertEqual(
            lookup,
            {
                'source': 'sigma',
                'source_id': 'rule-123',
            },
        )

    def test_resolve_attack_pattern_lookup_falls_back_to_name_and_source(self):
        lookup = attack_pattern_loader.resolve_attack_pattern_lookup(
            {
                'name': 'Builtin Pattern',
                'source': 'builtin',
            }
        )

        self.assertEqual(
            lookup,
            {
                'name': 'Builtin Pattern',
                'source': 'builtin',
            },
        )

    def test_build_attack_pattern_payload_applies_shared_defaults(self):
        payload = attack_pattern_loader.build_attack_pattern_payload(
            {
                'name': 'Sigma Rule',
                'source': 'sigma',
                'pattern_definition': {'type': 'single'},
                'detection_guidance': 'Review related process ancestry.',
                'procedure_examples': [{'name': 'APT demo'}],
                'required_artifact_types': ['evtx'],
            },
            created_by='system',
            enabled=False,
            last_synced_at='2026-04-11T12:00:00',
        )

        self.assertEqual(payload['name'], 'Sigma Rule')
        self.assertEqual(payload['source'], 'sigma')
        self.assertEqual(payload['pattern_type'], 'single')
        self.assertEqual(payload['severity'], 'medium')
        self.assertEqual(payload['confidence_weight'], 0.7)
        self.assertEqual(payload['created_by'], 'system')
        self.assertFalse(payload['enabled'])
        self.assertEqual(payload['last_synced_at'], '2026-04-11T12:00:00')
        self.assertEqual(payload['detection_guidance'], 'Review related process ancestry.')
        self.assertEqual(payload['procedure_examples'], [{'name': 'APT demo'}])
        self.assertEqual(payload['required_artifact_types'], ['evtx'])

    def test_normalize_opencti_attack_pattern_projects_shared_shape(self):
        normalized = attack_pattern_loader.normalize_opencti_attack_pattern(
            {
                'name': 'Credential Dumping',
                'description': 'General description',
                'detection': 'Prefer LSASS access telemetry.',
                'mitre_id': 'T1003',
                'opencti_id': 'opencti--123',
                'kill_chain_phases': ['credential-access'],
                'platforms': ['Windows'],
            }
        )

        self.assertEqual(normalized['source'], 'opencti')
        self.assertEqual(normalized['source_id'], 'opencti--123')
        self.assertEqual(normalized['mitre_tactic'], 'credential-access')
        self.assertEqual(normalized['mitre_technique'], 'T1003')
        self.assertEqual(normalized['required_artifact_types'], ['evtx'])
        self.assertEqual(normalized['pattern_definition']['platforms'], ['Windows'])

    def test_normalize_opencti_sigma_indicator_projects_shared_shape(self):
        normalized = attack_pattern_loader.normalize_opencti_sigma_indicator(
            {
                'name': 'Suspicious Service Creation',
                'opencti_id': 'indicator--123',
                'pattern': 'title: Demo',
                'score': 88,
                'kill_chain_phases': ['persistence'],
            }
        )

        self.assertEqual(normalized['source'], 'opencti_sigma')
        self.assertEqual(normalized['source_id'], 'indicator--123')
        self.assertEqual(normalized['pattern_type'], 'sigma')
        self.assertEqual(normalized['mitre_tactic'], 'persistence')
        self.assertEqual(normalized['pattern_definition']['raw_pattern'], 'title: Demo')
        self.assertEqual(normalized['pattern_definition']['score'], 88)

    def test_normalize_mitre_attack_pattern_projects_shared_shape(self):
        normalized = attack_pattern_loader.normalize_mitre_attack_pattern(
            {
                'id': 'attack-pattern--123',
                'name': 'Suspicious WMI',
                'description': 'Detect WMI execution.',
                'detection_guidance': 'Review WMI provider logs.',
                'procedure_examples': [{'name': 'APT 1'}],
                'mitre_tactics': ['execution'],
                'mitre_techniques': ['T1047'],
                'detection_query': 'SELECT * FROM events',
                'severity': 'high',
                'indicators': ['wmic.exe'],
                'event_ids': ['4688'],
                'data_components': ['Process Creation'],
                'thresholds': {'count': 1},
            }
        )

        self.assertEqual(normalized['source'], 'mitre_attack_v18')
        self.assertEqual(normalized['source_id'], 'attack-pattern--123')
        self.assertEqual(normalized['mitre_tactic'], 'execution')
        self.assertEqual(normalized['mitre_technique'], 'T1047')
        self.assertEqual(normalized['required_artifact_types'], ['evtx'])
        self.assertEqual(normalized['pattern_definition']['indicators'], ['wmic.exe'])
        self.assertEqual(normalized['detection_guidance'], 'Review WMI provider logs.')

    def test_loader_call_sites_use_shared_helper(self):
        rag_tasks_source = (REPO_ROOT / 'tasks' / 'rag_tasks.py').read_text()
        models_source = (REPO_ROOT / 'models' / 'rag.py').read_text()

        self.assertIn('from utils.attack_pattern_loader import (', rag_tasks_source)
        self.assertIn('resolve_attack_pattern_lookup(pattern)', rag_tasks_source)
        self.assertIn('build_attack_pattern_payload(', rag_tasks_source)
        self.assertIn('SYNC_ATTACK_PATTERN_UPDATE_FIELDS', rag_tasks_source)
        self.assertIn('normalize_opencti_attack_pattern(pattern)', rag_tasks_source)
        self.assertIn('normalize_opencti_sigma_indicator(ind)', rag_tasks_source)
        self.assertIn('normalize_mitre_attack_pattern(pattern_data)', rag_tasks_source)

        self.assertIn('from utils.attack_pattern_loader import (', models_source)
        self.assertIn('resolve_attack_pattern_lookup(pattern_data)', models_source)
        self.assertIn('build_attack_pattern_payload(', models_source)


if __name__ == '__main__':
    unittest.main()
