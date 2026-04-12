import importlib.util
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_module(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


inventory_checks = _load_module(
    'phase4a_inventory_checks',
    REPO_ROOT / 'scripts' / 'refactor' / 'inventory_checks.py',
)


class Phase4aInventoryGeneratorTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pattern_checks = inventory_checks.load_module(
            'phase4a_inventory_pattern_checks',
            inventory_checks.PATTERN_CHECKS_PATH,
        )
        cls.pattern_mappings = inventory_checks.load_module(
            'phase4a_inventory_pattern_mappings',
            inventory_checks.PATTERN_MAPPINGS_PATH,
        )
        cls.rows = inventory_checks.build_inventory_rows(
            cls.pattern_checks,
            cls.pattern_mappings,
        )
        cls.rows_by_key = {
            (row['pattern_id'], row['check_id']): row
            for row in cls.rows
        }

    def test_gap_bound_checks_are_annotated_in_inventory_rows(self):
        spray_distinct = self.rows_by_key[('password_spraying', 'spray_distinct_users')]
        brute_high = self.rows_by_key[('brute_force', 'brute_high_failures')]
        brute_success = self.rows_by_key[('brute_force', 'brute_followed_by_success')]

        self.assertTrue(spray_distinct['has_gap_binding'])
        self.assertEqual(spray_distinct['gap_finding_count'], 1)
        self.assertEqual(spray_distinct['gap_finding_types'], 'PASSWORD_SPRAYING')

        self.assertTrue(brute_high['has_gap_binding'])
        self.assertEqual(brute_high['gap_finding_count'], 2)
        self.assertEqual(
            brute_high['gap_finding_types'],
            'BRUTE_FORCE,DISTRIBUTED_BRUTE_FORCE',
        )

        self.assertTrue(brute_success['has_gap_binding'])
        self.assertEqual(brute_success['gap_finding_count'], 1)
        self.assertEqual(brute_success['gap_finding_types'], 'BRUTE_FORCE')

    def test_non_gap_bound_checks_remain_unannotated(self):
        spray_total = self.rows_by_key[('password_spraying', 'spray_total_failures')]
        brute_lockout = self.rows_by_key[('brute_force', 'brute_account_lockout')]

        self.assertFalse(spray_total['has_gap_binding'])
        self.assertEqual(spray_total['gap_finding_count'], 0)
        self.assertEqual(spray_total['gap_finding_types'], '')

        self.assertFalse(brute_lockout['has_gap_binding'])
        self.assertEqual(brute_lockout['gap_finding_count'], 0)
        self.assertEqual(brute_lockout['gap_finding_types'], '')

    def test_inventory_builder_uses_shared_pattern_mapping_accessor(self):
        inventory_source = (
            REPO_ROOT / 'scripts' / 'refactor' / 'inventory_checks.py'
        ).read_text()
        sample_row = self.rows_by_key[('pass_the_hash', 'pth_ntlm_validation')]

        self.assertIn('get_pattern_by_id = getattr(pattern_mappings, "get_pattern_by_id", None)', inventory_source)
        self.assertIn('meta = get_pattern_by_id(pattern_id) if get_pattern_by_id else {}', inventory_source)
        self.assertNotIn('pattern_mappings.PATTERN_EVENT_MAPPINGS.get(pattern_id, {})', inventory_source)
        self.assertEqual(sample_row['mitre'], 'T1550.002')
        self.assertIn('4624', sample_row['anchor_events'])

    def test_inventory_builder_uses_check_level_gap_binding_helper(self):
        inventory_source = (
            REPO_ROOT / 'scripts' / 'refactor' / 'inventory_checks.py'
        ).read_text()
        brute_high = self.rows_by_key[('brute_force', 'brute_high_failures')]

        self.assertIn('get_gap_finding_types_for_check = getattr(', inventory_source)
        self.assertIn('get_gap_finding_types_for_check(', inventory_source)
        self.assertNotIn('build_gap_binding_index(', inventory_source)
        self.assertEqual(
            brute_high['gap_finding_types'],
            'BRUTE_FORCE,DISTRIBUTED_BRUTE_FORCE',
        )


if __name__ == '__main__':
    unittest.main()
