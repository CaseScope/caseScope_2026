"""Tests for sliding-window detection over pre-aggregated activity slots.

Both detectors grouped events straight into detection-sized buckets with
`toStartOfInterval`, which made the window boundaries arbitrary. An attack that
straddles a boundary is split in half, and each half can fall below the
thresholds even though the attack as a whole clears them comfortably.
"""

import importlib.util
import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _load(name, relative_path):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


sliding_window = _load(
    'sliding_window_under_test', 'utils/stateful_detectors/sliding_window.py'
)
ActivitySlot = sliding_window.ActivitySlot


BASE = datetime(2026, 5, 8, 1, 0, 0)


def _slot(minutes_from_base, failures=0, successes=0, peers=(), sample=()):
    start = BASE + timedelta(minutes=minutes_from_base)
    return ActivitySlot(
        slot_start=start,
        failures=failures,
        successes=successes,
        attempts=failures + successes,
        peers=frozenset(peers),
        first_event=start,
        last_event=start + timedelta(minutes=14),
        sample=sample,
    )


class BoundaryStraddlingTestCase(unittest.TestCase):
    """The defect that fixed buckets caused."""

    # An attack from 01:50 to 02:10: six failures either side of the hour.
    STRADDLING_SLOTS = [
        _slot(45, failures=6),   # 01:45 slot
        _slot(60, failures=6),   # 02:00 slot
    ]

    def test_fixed_hour_buckets_would_split_the_attack(self):
        """Documents the old behaviour: each half falls under a minimum of 8."""
        for slot in self.STRADDLING_SLOTS:
            self.assertLess(slot.failures, 8)

    def test_sliding_window_sees_the_whole_attack(self):
        candidates = sliding_window.find_window_candidates(
            key='jdoe',
            slots=self.STRADDLING_SLOTS,
            window=timedelta(hours=1),
            min_failures=8,
            min_failure_rate=0.9,
        )

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].failures, 12)

    def test_activity_spread_too_thin_is_not_detected(self):
        """Six failures an hour apart is not a burst."""
        slots = [_slot(0, failures=6), _slot(120, failures=6)]
        candidates = sliding_window.find_window_candidates(
            key='jdoe',
            slots=slots,
            window=timedelta(hours=1),
            min_failures=8,
            min_failure_rate=0.9,
        )
        self.assertEqual(candidates, [])


class ThresholdTestCase(unittest.TestCase):
    def test_failure_rate_is_computed_over_decided_attempts(self):
        slots = [_slot(0, failures=9, successes=1)]
        candidate = sliding_window.find_window_candidates(
            key='jdoe', slots=slots, window=timedelta(hours=1),
            min_failures=8, min_failure_rate=0.9,
        )[0]
        self.assertAlmostEqual(candidate.failure_rate, 0.9)

    def test_high_success_rate_disqualifies(self):
        slots = [_slot(0, failures=9, successes=9)]
        self.assertEqual(
            sliding_window.find_window_candidates(
                key='jdoe', slots=slots, window=timedelta(hours=1),
                min_failures=8, min_failure_rate=0.9,
            ),
            [],
        )

    def test_unique_peers_are_counted_across_the_window(self):
        slots = [
            _slot(0, failures=5, peers=('a', 'b', 'c', 'd', 'e')),
            _slot(15, failures=5, peers=('f', 'g', 'h', 'i', 'j')),
        ]
        candidates = sliding_window.find_window_candidates(
            key='10.0.0.5', slots=slots, window=timedelta(hours=2),
            min_peers=10, min_failure_rate=0.9,
        )
        self.assertEqual(len(candidates), 1)
        self.assertEqual(len(candidates[0].peers), 10)

    def test_no_slots_yields_no_candidates(self):
        self.assertEqual(
            sliding_window.find_window_candidates(
                key='jdoe', slots=[], window=timedelta(hours=1), min_failures=1,
            ),
            [],
        )


class OverlapCollapsingTestCase(unittest.TestCase):
    def test_one_burst_yields_one_candidate(self):
        """Every window position over a burst qualifies; they must not all report."""
        slots = [_slot(offset, failures=10) for offset in (0, 15, 30, 45)]
        candidates = sliding_window.find_window_candidates(
            key='jdoe', slots=slots, window=timedelta(hours=1),
            min_failures=8, min_failure_rate=0.9,
        )
        self.assertEqual(len(candidates), 1)

    def test_overlapping_windows_do_not_inflate_counts(self):
        slots = [_slot(offset, failures=10) for offset in (0, 15, 30, 45)]
        candidate = sliding_window.find_window_candidates(
            key='jdoe', slots=slots, window=timedelta(hours=1),
            min_failures=8, min_failure_rate=0.9,
        )[0]

        self.assertEqual(
            candidate.failures,
            40,
            msg='summing overlapping windows would count shared slots repeatedly',
        )

    def test_separate_bursts_stay_separate(self):
        slots = [_slot(0, failures=10), _slot(600, failures=10)]
        candidates = sliding_window.find_window_candidates(
            key='jdoe', slots=slots, window=timedelta(hours=1),
            min_failures=8, min_failure_rate=0.9,
        )
        self.assertEqual(len(candidates), 2)


class CollapseToStrongestTestCase(unittest.TestCase):
    def test_strongest_burst_is_selected_and_others_counted(self):
        slots = [
            _slot(0, failures=10),
            _slot(600, failures=40),
            _slot(1200, failures=15),
        ]
        candidates = sliding_window.find_window_candidates(
            key='veeam', slots=slots, window=timedelta(hours=1),
            min_failures=8, min_failure_rate=0.9,
        )
        strongest = sliding_window.collapse_to_strongest(candidates)

        self.assertEqual(strongest.failures, 40)
        self.assertEqual(strongest.burst_count, 3)
        self.assertEqual(strongest.failures_all_bursts, 65)

    def test_no_candidates_collapses_to_none(self):
        self.assertIsNone(sliding_window.collapse_to_strongest([]))

    def test_single_burst_reports_one(self):
        candidates = sliding_window.find_window_candidates(
            key='veeam', slots=[_slot(0, failures=10)], window=timedelta(hours=1),
            min_failures=8, min_failure_rate=0.9,
        )
        strongest = sliding_window.collapse_to_strongest(candidates)
        self.assertEqual(strongest.burst_count, 1)


class OrderedIntervalsTestCase(unittest.TestCase):
    """Timing analysis used two aggregates with no shared ordering."""

    def test_intervals_are_computed_in_time_order(self):
        sample = [
            (BASE + timedelta(seconds=30), 'a'),
            (BASE, 'b'),
            (BASE + timedelta(seconds=10), 'c'),
            (BASE + timedelta(seconds=20), 'd'),
        ]
        self.assertEqual(sliding_window.ordered_intervals(sample), [10.0, 10.0, 10.0])

    def test_scripted_attack_shows_a_low_spread(self):
        sample = [
            (BASE + timedelta(seconds=index * 5), f'user{index}')
            for index in range(10)
        ]
        intervals = sliding_window.ordered_intervals(sample)
        self.assertEqual(set(intervals), {5.0})

    def test_gaps_beyond_an_hour_are_excluded(self):
        sample = [(BASE, 'a'), (BASE + timedelta(hours=5), 'b')]
        self.assertEqual(sliding_window.ordered_intervals(sample), [])

    def test_empty_sample_yields_no_intervals(self):
        self.assertEqual(sliding_window.ordered_intervals([]), [])

    def test_peers_are_returned_in_time_order(self):
        sample = [
            (BASE + timedelta(seconds=20), 'third'),
            (BASE, 'first'),
            (BASE + timedelta(seconds=10), 'second'),
        ]
        self.assertEqual(
            sliding_window.peers_from_sample(sample),
            ['first', 'second', 'third'],
        )


class GroupSlotsTestCase(unittest.TestCase):
    def test_rows_are_grouped_by_key_in_query_column_order(self):
        rows = [
            ('10.0.0.5', BASE, 5, 0, 5, ['a', 'b'], BASE, BASE, [(BASE, 'a')]),
            ('10.0.0.5', BASE + timedelta(minutes=15), 3, 1, 4, ['c'], BASE, BASE, []),
            ('10.0.0.9', BASE, 1, 0, 1, ['d'], BASE, BASE, []),
        ]
        grouped = sliding_window.group_slots_by_key(rows)

        self.assertEqual(set(grouped), {'10.0.0.5', '10.0.0.9'})
        self.assertEqual(len(grouped['10.0.0.5']), 2)
        self.assertEqual(grouped['10.0.0.5'][0].failures, 5)
        self.assertEqual(grouped['10.0.0.5'][0].peers, frozenset({'a', 'b'}))

    def test_empty_peer_values_are_dropped(self):
        rows = [('10.0.0.5', BASE, 1, 0, 1, ['a', '', None], BASE, BASE, [])]
        grouped = sliding_window.group_slots_by_key(rows)
        self.assertEqual(grouped['10.0.0.5'][0].peers, frozenset({'a'}))


if __name__ == '__main__':
    unittest.main()
