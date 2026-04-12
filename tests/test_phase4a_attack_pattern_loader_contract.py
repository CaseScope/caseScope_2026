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

    def test_loader_call_sites_use_shared_helper(self):
        rag_tasks_source = (REPO_ROOT / 'tasks' / 'rag_tasks.py').read_text()
        models_source = (REPO_ROOT / 'models' / 'rag.py').read_text()

        self.assertIn('from utils.attack_pattern_loader import (', rag_tasks_source)
        self.assertIn('resolve_attack_pattern_lookup(pattern)', rag_tasks_source)
        self.assertIn('build_attack_pattern_payload(', rag_tasks_source)
        self.assertIn('SYNC_ATTACK_PATTERN_UPDATE_FIELDS', rag_tasks_source)
        self.assertIn("**resolve_attack_pattern_lookup(normalized_pattern)", rag_tasks_source)
        self.assertIn("**resolve_attack_pattern_lookup(normalized_indicator)", rag_tasks_source)
        self.assertIn("'source': 'opencti'", rag_tasks_source)
        self.assertIn("'source': 'opencti_sigma'", rag_tasks_source)
        self.assertIn("'source': 'mitre_attack_v18'", rag_tasks_source)

        self.assertIn('from utils.attack_pattern_loader import (', models_source)
        self.assertIn('resolve_attack_pattern_lookup(pattern_data)', models_source)
        self.assertIn('build_attack_pattern_payload(', models_source)


if __name__ == '__main__':
    unittest.main()
