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

pattern_event_mappings = _load_module(
    'utils.pattern_event_mappings',
    UTILS_DIR / 'pattern_event_mappings.py',
)


class Phase4aPatternEventMappingContractTestCase(unittest.TestCase):
    def test_get_pattern_by_id_materializes_canonical_id_without_mutating_source(self):
        source = pattern_event_mappings.PATTERN_EVENT_MAPPINGS['pass_the_hash']

        pattern = pattern_event_mappings.get_pattern_by_id('pass_the_hash')

        self.assertEqual(pattern['id'], 'pass_the_hash')
        self.assertEqual(pattern['name'], source['name'])
        self.assertNotIn('id', source)

    def test_category_and_mitre_accessors_share_materialized_pattern_contract(self):
        credential_access = pattern_event_mappings.get_patterns_by_category('Credential Access')
        mitre_matches = pattern_event_mappings.get_patterns_by_mitre('T1550.002')

        self.assertIn('pass_the_hash', credential_access)
        self.assertEqual(credential_access['pass_the_hash']['id'], 'pass_the_hash')
        self.assertIn('pass_the_hash', mitre_matches)
        self.assertEqual(mitre_matches['pass_the_hash']['id'], 'pass_the_hash')

    def test_all_and_selected_pattern_accessors_share_materialized_contract(self):
        all_patterns = pattern_event_mappings.get_all_patterns()
        selected_patterns = pattern_event_mappings.get_patterns_by_ids(
            ['pass_the_hash', 'not_real', 'password_spraying']
        )

        self.assertIn('pass_the_hash', all_patterns)
        self.assertEqual(all_patterns['pass_the_hash']['id'], 'pass_the_hash')
        self.assertEqual(
            set(selected_patterns),
            {'pass_the_hash', 'password_spraying'},
        )
        self.assertEqual(
            selected_patterns['password_spraying']['id'],
            'password_spraying',
        )

    def test_rag_tasks_pattern_selection_uses_shared_mapping_helpers(self):
        rag_tasks_source = (REPO_ROOT / 'tasks' / 'rag_tasks.py').read_text()

        self.assertIn(
            'from utils.pattern_event_mappings import get_all_patterns, get_patterns_by_ids',
            rag_tasks_source,
        )
        self.assertIn('pattern_configs = get_patterns_by_ids(patterns)', rag_tasks_source)
        self.assertIn('pattern_configs = get_all_patterns()', rag_tasks_source)
        self.assertNotIn("pattern_configs = {pid: get_pattern_by_id(pid) for pid in patterns if get_pattern_by_id(pid)}", rag_tasks_source)


if __name__ == '__main__':
    unittest.main()
