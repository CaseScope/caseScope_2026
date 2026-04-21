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
finding_contract = _load_module(
    'utils.finding_contract',
    UTILS_DIR / 'finding_contract.py',
)
gap_detector_bridge = _load_module(
    'utils.gap_detector_bridge',
    UTILS_DIR / 'gap_detector_bridge.py',
)

GAP_FINDING_CHECK_REGISTRY = pattern_check_definitions.GAP_FINDING_CHECK_REGISTRY
get_check_for_pattern = pattern_check_definitions.get_check_for_pattern
get_check_bindings_for_gap_finding = pattern_check_definitions.get_check_bindings_for_gap_finding
get_checks_for_pattern = pattern_check_definitions.get_checks_for_pattern
build_gap_finding_check_detail = finding_contract.build_gap_finding_check_detail
get_gap_finding_check_binding = pattern_check_definitions.get_gap_finding_check_binding
get_gap_finding_types_for_check = pattern_check_definitions.get_gap_finding_types_for_check
get_gap_finding_result_status = finding_contract.get_gap_finding_result_status
iter_pattern_checks = pattern_check_definitions.iter_pattern_checks
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

    def test_gap_binding_accessor_returns_materialized_binding_copy(self):
        first = get_gap_finding_check_binding('PASSWORD_SPRAYING')
        second = get_gap_finding_check_binding('PASSWORD_SPRAYING')

        self.assertIsNotNone(first)
        self.assertIsNot(first, second)
        self.assertEqual(first, second)
        self.assertIsNot(first['checks'], second['checks'])

    def test_gap_finding_result_status_uses_canonical_confidence_thresholds(self):
        self.assertEqual(get_gap_finding_result_status(72), 'PASS')
        self.assertEqual(get_gap_finding_result_status(60), 'PASS')
        self.assertEqual(get_gap_finding_result_status(59), 'INCONCLUSIVE')
        self.assertEqual(get_gap_finding_result_status(30), 'INCONCLUSIVE')
        self.assertEqual(get_gap_finding_result_status(29), 'FAIL')

    def test_gap_finding_detail_helper_uses_canonical_extractors(self):
        finding = SimpleNamespace(
            event_count=9,
            evidence={'unique_users': 12, 'max_attempts_per_user': 2, 'total_failures': 9},
            details={
                'successes': 1,
                'anomalies': {
                    'off_hours': {'z_score': 4.2},
                    'daily_logons': {'z_score': 5.1},
                    'unique_hosts': {'z_score': 3.7},
                },
            },
            entity_value='alice',
            summary='Anomalous behavior for user alice',
        )

        self.assertEqual(
            build_gap_finding_check_detail(finding, 'distinct_users'),
            '12 distinct usernames targeted',
        )
        self.assertEqual(
            build_gap_finding_check_detail(finding, 'low_per_account'),
            'max 2 attempts per account',
        )
        self.assertEqual(
            build_gap_finding_check_detail(finding, 'failure_count'),
            '9 failed logon attempts',
        )
        self.assertEqual(
            build_gap_finding_check_detail(finding, 'success_count'),
            '1 successful logons after failures',
        )
        self.assertEqual(
            build_gap_finding_check_detail(finding, 'behavioral_off_hours'),
            'Off-hours peer deviation for alice (z=4.2)',
        )
        self.assertEqual(
            build_gap_finding_check_detail(finding, 'behavioral_volume_spike'),
            'Behavioral volume spike for alice (z=5.1)',
        )
        self.assertEqual(
            build_gap_finding_check_detail(finding, 'behavioral_new_target_access'),
            'Behavioral new-target access for alice (z=3.7)',
        )
        self.assertEqual(
            build_gap_finding_check_detail(finding, 'behavioral_anomalous_user'),
            'User alice deviated across daily_logons, off_hours, unique_hosts',
        )

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
        self.assertEqual(
            get_gap_finding_types_for_check(
                'behavioral_off_hours_activity',
                'behavioral_off_hours_signal',
            ),
            ('OFF_HOURS_ACTIVITY',),
        )

    def test_get_checks_for_pattern_returns_materialized_list_copy(self):
        first = get_checks_for_pattern('password_spraying')
        second = get_checks_for_pattern('password_spraying')

        self.assertIsNot(first, second)
        self.assertEqual(
            [check.id for check in first],
            [check.id for check in second],
        )
        first.pop()
        self.assertGreater(len(second), len(first))

    def test_iter_pattern_checks_returns_materialized_check_lists(self):
        first = dict(iter_pattern_checks())
        second = dict(iter_pattern_checks())

        self.assertIn('password_spraying', first)
        self.assertIsNot(first['password_spraying'], second['password_spraying'])
        self.assertEqual(
            [check.id for check in first['password_spraying']],
            [check.id for check in second['password_spraying']],
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

    def test_behavioral_gap_findings_map_into_canonical_behavioral_patterns(self):
        finding = SimpleNamespace(
            finding_type='OFF_HOURS_ACTIVITY',
            confidence=68,
            entity_type='user',
            entity_value='alice',
            event_count=4,
            details={'anomalies': {'off_hours': {'z_score': 4.2}}},
            evidence={},
        )

        results = map_gap_finding_to_check_results(finding)

        self.assertEqual(
            [result.check_id for result in results],
            ['behavioral_off_hours_signal'],
        )
        self.assertEqual(results[0].status, 'PASS')
        self.assertEqual(
            get_pattern_id_for_gap_finding(finding.finding_type),
            'behavioral_off_hours_activity',
        )


if __name__ == '__main__':
    unittest.main()
