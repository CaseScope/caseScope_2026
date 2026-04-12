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

pattern_suppression = _load_module(
    'utils.pattern_suppression',
    UTILS_DIR / 'pattern_suppression.py',
)


class Phase4aPatternSuppressionContractTestCase(unittest.TestCase):
    def test_build_confirmed_pattern_entry_normalizes_shape(self):
        entry = pattern_suppression.build_confirmed_pattern_entry(
            correlation_key='host-a|alice',
            score=74,
            anchor={'source_host': 'HOST-A'},
        )

        self.assertEqual(entry['correlation_key'], 'host-a|alice')
        self.assertEqual(entry['score'], 74)
        self.assertEqual(entry['anchor'], {'source_host': 'HOST-A'})

    def test_anchors_overlap_matches_case_insensitive_shared_fields(self):
        self.assertTrue(
            pattern_suppression.anchors_overlap(
                {'source_host': ' HOST-A ', 'username': 'Alice'},
                {'source_host': 'host-a', 'username': 'alice'},
                [('source_host', 'username')],
            )
        )
        self.assertFalse(
            pattern_suppression.anchors_overlap(
                {'source_host': 'HOST-A'},
                {'source_host': 'HOST-B'},
                [('source_host',)],
            )
        )

    def test_get_pattern_suppression_matches_honors_shared_fields_and_thresholds(self):
        confirmed_patterns = {
            'dcsync': [
                pattern_suppression.build_confirmed_pattern_entry(
                    correlation_key='host-a|alice',
                    score=80,
                    anchor={'source_host': 'HOST-A', 'username': 'alice'},
                ),
                pattern_suppression.build_confirmed_pattern_entry(
                    correlation_key='host-b|bob',
                    score=40,
                    anchor={'source_host': 'HOST-B', 'username': 'bob'},
                ),
            ]
        }

        matches = pattern_suppression.get_pattern_suppression_matches(
            'bloodhound_sharphound',
            {'source_host': 'host-a', 'username': 'Alice'},
            confirmed_patterns,
        )

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]['suppressor'], 'dcsync')
        self.assertEqual(matches[0]['mode'], 'hard')
        self.assertEqual(matches[0]['adjustment'], 100)

    def test_should_track_pattern_for_suppression_uses_shared_registry(self):
        self.assertTrue(pattern_suppression.should_track_pattern_for_suppression('dcsync'))
        self.assertFalse(pattern_suppression.should_track_pattern_for_suppression('password_spraying'))


if __name__ == '__main__':
    unittest.main()
