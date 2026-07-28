"""The event-time guard must exclude corrupt timestamps at both ends.

The guard was one-sided: it excluded the epoch and nothing else. That left two
families of corrupt timestamps in every baseline. Across the indexed corpus 21,775
events are dated in the future, as far ahead as the year 2299, including 18,865
kernel boot events dated 2101 written before the clock synchronised - which
produced a profile period running from 2010 to 2101. Another 389,480 events fall
before the year 2000, and none of them are event log records: 150,203 sit on
1980-01-01 and 87,282 on 1985-10-26, both filesystem epoch defaults.
"""

import importlib.util
import re
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _load(name, relative_path):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


event_time_window = _load('event_time_window_under_test', 'utils/event_time_window.py')


class BoundsTestCase(unittest.TestCase):
    def setUp(self):
        self.predicate = event_time_window.event_time_bounds_sql()

    def test_both_ends_are_bounded(self):
        self.assertIn('>', self.predicate)
        self.assertIn('<=', self.predicate)

    def test_the_lower_bound_is_a_bound_parameter(self):
        self.assertIn('{min_time:String}', self.predicate)
        self.assertEqual(
            event_time_window.event_time_parameters()['min_time'],
            event_time_window.MIN_VALID_EVENT_TIME,
        )

    def test_the_upper_bound_is_evaluated_by_the_database(self):
        """Baked in, it would go stale and start rejecting current events."""
        self.assertIn('now()', self.predicate)

    def test_the_upper_bound_tolerates_clock_skew(self):
        self.assertIn('INTERVAL 1 DAY', self.predicate)

    def test_the_floor_excludes_the_filesystem_epoch_defaults(self):
        floor = event_time_window.MIN_VALID_EVENT_TIME
        self.assertGreater(floor, '1985-10-26')
        self.assertGreater(floor, '1980-01-01')

    def test_the_floor_does_not_exclude_credible_event_records(self):
        self.assertLess(event_time_window.MIN_VALID_EVENT_TIME, '2001-01-01')

    def test_the_column_can_be_chosen(self):
        predicate = event_time_window.event_time_bounds_sql('timestamp')
        self.assertIn('timestamp >', predicate)
        self.assertNotIn('timestamp_utc', predicate)

    def test_the_default_column_is_the_normalised_one(self):
        self.assertIn('timestamp_utc', event_time_window.event_time_bounds_sql())


class CallerContractTestCase(unittest.TestCase):
    """Every stage that reads event times must use the shared bounds."""

    SOURCES = (
        'utils/behavioral_profiler.py',
        'utils/stateful_detectors/auth_events.py',
        'utils/temporal_baseline.py',
    )

    def test_stages_import_the_shared_bounds(self):
        for relative_path in self.SOURCES:
            with self.subTest(source=relative_path):
                source = (REPO_ROOT / relative_path).read_text()
                self.assertIn(
                    'event_time_bounds_sql',
                    source,
                    msg=f'{relative_path} must bound event times through the shared helper',
                )

    def test_no_stage_keeps_its_own_one_sided_epoch_guard(self):
        """Two copies of a 1970 floor existed, and neither had an upper bound."""
        for relative_path in self.SOURCES:
            with self.subTest(source=relative_path):
                source = (REPO_ROOT / relative_path).read_text()
                self.assertNotIn('1970-01-02', source)

    def test_no_stage_hardcodes_a_bare_lower_bound_comparison(self):
        """A lone `timestamp_utc >` would mean the upper bound was forgotten."""
        pattern = re.compile(r'timestamp_utc\s*>\s*toDateTime64')
        for relative_path in self.SOURCES:
            with self.subTest(source=relative_path):
                source = (REPO_ROOT / relative_path).read_text()
                # The helper itself is the only place this may appear.
                self.assertIsNone(
                    pattern.search(source),
                    msg=(
                        f'{relative_path} builds its own lower-bound comparison instead '
                        'of using event_time_bounds_sql, so the upper bound is missing'
                    ),
                )


if __name__ == '__main__':
    unittest.main()
