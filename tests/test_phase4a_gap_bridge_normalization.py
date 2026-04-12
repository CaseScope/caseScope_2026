import os
import sys
import unittest
import importlib.util
import types
from pathlib import Path
from types import SimpleNamespace

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
gap_detector_bridge = _load_module(
    'utils.gap_detector_bridge',
    UTILS_DIR / 'gap_detector_bridge.py',
)

GAP_FINDING_CHECK_REGISTRY = pattern_check_definitions.GAP_FINDING_CHECK_REGISTRY
get_check_for_pattern = pattern_check_definitions.get_check_for_pattern
get_check_bindings_for_gap_finding = pattern_check_definitions.get_check_bindings_for_gap_finding
get_checks_for_pattern = pattern_check_definitions.get_checks_for_pattern
get_gap_finding_check_binding = pattern_check_definitions.get_gap_finding_check_binding
get_gap_finding_types_for_check = pattern_check_definitions.get_gap_finding_types_for_check
get_pattern_id_for_gap_finding = pattern_check_definitions.get_pattern_id_for_gap_finding
map_gap_finding_to_check_results = gap_detector_bridge.map_gap_finding_to_check_results


class Phase4aGapBridgeNormalizationTestCase(unittest.TestCase):
    def test_gap_findings_reference_canonical_check_ids(self):
        for finding_type in GAP_FINDING_CHECK_REGISTRY:
            binding = get_gap_finding_check_binding(finding_type)
            self.assertIsNotNone(binding)

            canonical_check_ids = {
                check.id for check in get_checks_for_pattern(binding['pattern_id'])
            }
            bound_check_ids = {
                check_binding['check_id'] for check_binding in binding['checks']
            }

            with self.subTest(finding_type=finding_type):
                self.assertTrue(bound_check_ids.issubset(canonical_check_ids))

    def test_gap_findings_bind_directly_to_canonical_check_objects(self):
        for finding_type in GAP_FINDING_CHECK_REGISTRY:
            binding = get_gap_finding_check_binding(finding_type)
            check_bindings = get_check_bindings_for_gap_finding(finding_type)
            self.assertIsNotNone(binding)
            self.assertEqual(check_bindings, binding['checks'])
            self.assertEqual(
                get_pattern_id_for_gap_finding(finding_type),
                binding['pattern_id'],
            )

            for check_binding in check_bindings:
                canonical = get_check_for_pattern(
                    binding['pattern_id'],
                    check_binding['check_id'],
                )
                with self.subTest(
                    finding_type=finding_type,
                    check_id=check_binding['check_id'],
                ):
                    self.assertIs(check_binding['check'], canonical)

    def test_gap_finding_types_can_be_resolved_by_check(self):
        self.assertEqual(
            get_gap_finding_types_for_check('password_spraying', 'spray_distinct_users'),
            ('PASSWORD_SPRAYING',),
        )
        self.assertEqual(
            get_gap_finding_types_for_check('brute_force', 'brute_high_failures'),
            ('BRUTE_FORCE', 'DISTRIBUTED_BRUTE_FORCE'),
        )
        self.assertEqual(
            get_gap_finding_types_for_check('password_spraying', 'spray_total_failures'),
            (),
        )

    def test_password_spraying_gap_mapping_uses_canonical_binding(self):
        finding = SimpleNamespace(
            finding_type='password_spraying',
            confidence=72,
            event_count=14,
            evidence={'unique_users': 12, 'max_attempts_per_user': 2},
            details={},
        )

        results = map_gap_finding_to_check_results(finding)

        self.assertEqual(
            [result.check_id for result in results],
            ['spray_distinct_users', 'spray_low_per_account'],
        )
        self.assertTrue(all(result.status == 'PASS' for result in results))
        self.assertTrue(all(result.source == 'gap_detector' for result in results))
        self.assertIn('12 distinct usernames targeted', results[0].detail)
        self.assertIn('max 2 attempts per account', results[1].detail)
        self.assertEqual(
            get_pattern_id_for_gap_finding(finding.finding_type),
            'password_spraying',
        )

    def test_distributed_bruteforce_maps_to_bruteforce_pattern(self):
        finding = SimpleNamespace(
            finding_type='DISTRIBUTED_BRUTE_FORCE',
            confidence=45,
            event_count=9,
            evidence={'total_failures': 9},
            details={'successes': 0},
        )

        results = map_gap_finding_to_check_results(finding)

        self.assertEqual(
            [result.check_id for result in results],
            ['brute_high_failures', 'brute_bad_password', 'brute_mssql_failures'],
        )
        self.assertTrue(all(result.status == 'INCONCLUSIVE' for result in results))
        self.assertEqual(
            get_pattern_id_for_gap_finding(finding.finding_type),
            'brute_force',
        )


if __name__ == '__main__':
    unittest.main()
