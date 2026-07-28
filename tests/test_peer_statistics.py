"""Tests for peer deviation statistics.

The behavioral anomaly detector never produced a finding in part because a
deviation of 3.0 is arithmetically unreachable in a small group. These tests pin
the three properties that fix: leave-one-out comparison, a consistent robust
centre and spread, and a threshold the group size can express.
"""

import importlib.util
import statistics
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_module(name, relative_path):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    # Dataclass field resolution reads the module back out of sys.modules, so it
    # has to be registered before the module body executes.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


peer_statistics = _load_module('peer_statistics_under_test', 'utils/peer_statistics.py')


class AttainableScoreTestCase(unittest.TestCase):
    def test_small_groups_cannot_reach_a_deviation_of_three(self):
        """Documents the ceiling that made the old threshold unreachable."""
        for member_count in (2, 3, 4, 5, 6, 7):
            self.assertLess(
                peer_statistics.max_attainable_score(member_count),
                3.0,
                msg=f'a group of {member_count} cannot express a deviation of 3.0',
            )

    def test_larger_groups_can_reach_three(self):
        self.assertGreaterEqual(peer_statistics.max_attainable_score(9), 3.0)

    def test_threshold_is_capped_to_what_the_group_can_express(self):
        threshold = peer_statistics.resolve_threshold(3, configured_threshold=3.0)
        self.assertIsNotNone(threshold)
        self.assertLess(threshold, 3.0)

    def test_threshold_uses_configured_value_when_group_is_large(self):
        self.assertEqual(
            peer_statistics.resolve_threshold(60, configured_threshold=3.0),
            3.0,
        )

    def test_no_threshold_without_any_peers(self):
        self.assertIsNone(peer_statistics.resolve_threshold(1, configured_threshold=3.0))


class LeaveOneOutTestCase(unittest.TestCase):
    def test_entity_is_excluded_from_its_own_baseline(self):
        """A lone outlier must not drag the median toward itself."""
        peers = [10.0] * 9
        deviation = peer_statistics.compute_peer_deviation(
            metric='daily_logons',
            value=500.0,
            peer_values=peers,
            configured_threshold=3.0,
        )

        self.assertEqual(deviation.peer_median, 10.0)
        self.assertTrue(deviation.exceeded)

    def test_group_helper_leaves_the_selected_member_out(self):
        values = [10.0, 10.0, 10.0, 10.0, 10.0, 900.0]
        deviations = peer_statistics.compute_group_deviations(
            metric_values={'daily_logons': values},
            entity_index=5,
            configured_threshold=3.0,
        )

        self.assertEqual(deviations['daily_logons'].peer_median, 10.0)
        self.assertTrue(deviations['daily_logons'].exceeded)

    def test_typical_member_of_a_healthy_group_is_not_flagged(self):
        values = [9.0, 10.0, 11.0, 10.0, 12.0, 9.0, 10.0, 11.0, 10.0, 10.0]
        for index in range(len(values)):
            deviation = peer_statistics.compute_group_deviations(
                metric_values={'daily_logons': values},
                entity_index=index,
                configured_threshold=3.0,
            )['daily_logons']
            self.assertFalse(
                deviation.exceeded,
                msg=f'member {index} of a tightly grouped population was flagged',
            )


class ConsistentSpreadTestCase(unittest.TestCase):
    def test_one_extreme_peer_does_not_mask_every_other_member(self):
        """The median/stdev pairing let a single huge peer hide real deviation.

        Peers sit at 10 with one service account at 5000. Under the old
        (value - median) / stdev this member scored about 0.2 because the
        standard deviation was in the thousands, so it was never flagged.
        """
        peers = [10.0, 10.0, 10.0, 10.0, 10.0, 10.0, 5000.0]
        old_style_score = (120.0 - 10.0) / statistics.stdev(peers + [120.0])
        self.assertLess(old_style_score, 3.0, msg='sanity check on the old formula')

        deviation = peer_statistics.compute_peer_deviation(
            metric='daily_logons',
            value=120.0,
            peer_values=peers,
            configured_threshold=3.0,
        )

        self.assertTrue(
            deviation.exceeded,
            msg='a twelvefold deviation from the peer median must be reachable',
        )

    def test_spread_estimate_is_used_when_peers_actually_vary(self):
        peers = [8.0, 9.0, 10.0, 11.0, 12.0, 10.0, 9.0]
        deviation = peer_statistics.compute_peer_deviation(
            metric='daily_logons',
            value=60.0,
            peer_values=peers,
            configured_threshold=3.0,
        )

        self.assertEqual(deviation.method, peer_statistics.METHOD_MODIFIED_ZSCORE)
        self.assertTrue(deviation.exceeded)

    def test_identical_peers_fall_back_to_a_ratio(self):
        peers = [4.0] * 8
        deviation = peer_statistics.compute_peer_deviation(
            metric='daily_logons',
            value=40.0,
            peer_values=peers,
            configured_threshold=3.0,
        )

        self.assertEqual(deviation.method, peer_statistics.METHOD_RATIO)
        self.assertTrue(deviation.exceeded)

    def test_zero_spread_and_matching_value_is_not_flagged(self):
        peers = [4.0] * 8
        deviation = peer_statistics.compute_peer_deviation(
            metric='daily_logons',
            value=4.0,
            peer_values=peers,
            configured_threshold=3.0,
        )

        self.assertFalse(deviation.exceeded)
        self.assertEqual(deviation.score, 0.0)


class SmallGroupFallbackTestCase(unittest.TestCase):
    def test_small_group_uses_the_ratio_fallback(self):
        deviation = peer_statistics.compute_peer_deviation(
            metric='unique_hosts',
            value=30.0,
            peer_values=[2.0, 3.0],
            configured_threshold=3.0,
        )

        self.assertEqual(deviation.method, peer_statistics.METHOD_RATIO)
        self.assertTrue(
            deviation.exceeded,
            msg='a tenfold deviation in a three-member group must be reachable',
        )

    def test_small_group_ordinary_variation_is_not_flagged(self):
        deviation = peer_statistics.compute_peer_deviation(
            metric='unique_hosts',
            value=4.0,
            peer_values=[3.0, 3.0],
            configured_threshold=3.0,
        )

        self.assertFalse(deviation.exceeded)

    def test_single_member_group_yields_no_comparison(self):
        deviation = peer_statistics.compute_peer_deviation(
            metric='unique_hosts',
            value=99.0,
            peer_values=[],
            configured_threshold=3.0,
        )

        self.assertEqual(deviation.method, peer_statistics.METHOD_NO_COMPARISON)
        self.assertFalse(deviation.exceeded)


class AbsoluteFloorTestCase(unittest.TestCase):
    """Statistical significance is not the same as practical significance."""

    # A tightly grouped population: the robust spread is half a host, so
    # reaching a couple more than the median scores as a large deviation.
    TIGHT_PEERS = [1.0, 1.0, 2.0, 2.0, 3.0, 1.0, 2.0, 2.0]

    def test_trivial_difference_in_a_tight_group_is_not_flagged(self):
        without_floor = peer_statistics.compute_peer_deviation(
            metric='unique_hosts',
            value=5.0,
            peer_values=self.TIGHT_PEERS,
            configured_threshold=3.0,
        )
        with_floor = peer_statistics.compute_peer_deviation(
            metric='unique_hosts',
            value=5.0,
            peer_values=self.TIGHT_PEERS,
            configured_threshold=3.0,
            min_absolute_difference=4.0,
        )

        self.assertTrue(without_floor.exceeded, msg='sanity check on the tight spread')
        self.assertFalse(with_floor.exceeded)
        self.assertEqual(with_floor.method, peer_statistics.METHOD_BELOW_FLOOR)

    def test_floor_does_not_suppress_a_real_deviation(self):
        deviation = peer_statistics.compute_peer_deviation(
            metric='unique_hosts',
            value=40.0,
            peer_values=self.TIGHT_PEERS,
            configured_threshold=3.0,
            min_absolute_difference=4.0,
        )

        self.assertTrue(deviation.exceeded)

    def test_floors_are_applied_per_metric(self):
        deviations = peer_statistics.compute_group_deviations(
            metric_values={
                'unique_hosts': [1.0, 1.0, 1.0, 2.0, 1.0, 2.0],
                'failure_rate': [0.0, 0.0, 0.0, 0.0, 0.0, 95.0],
            },
            entity_index=5,
            configured_threshold=3.0,
            absolute_floors={'unique_hosts': 3.0, 'failure_rate': 10.0},
        )

        self.assertFalse(deviations['unique_hosts'].exceeded)
        self.assertTrue(deviations['failure_rate'].exceeded)


class LogScaleTestCase(unittest.TestCase):
    """Counts are lognormal across a population, so the upper tail is not all anomalous."""

    LOGNORMAL_LOGONS = [
        19.0, 24.0, 31.0, 38.0, 45.0, 52.0, 61.0, 70.0, 80.0, 94.0,
        99.0, 110.0, 128.0, 150.0, 175.0, 205.0, 240.0, 290.0, 341.0, 400.0,
    ]

    def test_linear_scale_flags_more_of_the_tail_than_log_scale(self):
        """Documents why log scaling is needed for count metrics."""
        self.assertGreater(
            self._count_flagged(log_scale=False),
            self._count_flagged(log_scale=True),
            msg='on a lognormal population the linear scale flags the ordinary tail',
        )

    def test_log_scale_does_not_flag_the_ordinary_tail(self):
        self.assertEqual(self._count_flagged(log_scale=True), 0)

    def test_log_scale_still_flags_a_genuine_outlier(self):
        values = self.LOGNORMAL_LOGONS + [5498.0]
        deviation = peer_statistics.compute_peer_deviation(
            metric='daily_logons',
            value=5498.0,
            peer_values=self.LOGNORMAL_LOGONS,
            configured_threshold=3.0,
            log_scale=True,
        )
        self.assertTrue(deviation.exceeded, msg=f'outlier in {len(values)} values missed')

    def _count_flagged(self, log_scale):
        values = list(self.LOGNORMAL_LOGONS)
        flagged = 0
        for index in range(len(values)):
            peers = [v for i, v in enumerate(values) if i != index]
            deviation = peer_statistics.compute_peer_deviation(
                metric='daily_logons',
                value=values[index],
                peer_values=peers,
                configured_threshold=3.0,
                min_absolute_difference=5.0,
                log_scale=log_scale,
            )
            if deviation.exceeded:
                flagged += 1
        return flagged


class MetricScopeTestCase(unittest.TestCase):
    """A member the metric does not describe must not shape its baseline."""

    # Half of these accounts never authenticated, which is close to the real
    # proportion: 37 of 118 profiled accounts on a live case have no logon or
    # failure events at all.
    PEERS_WITH_NO_AUTH_MEMBERS = [None, None, None, None, None, 10.0, 11.0, 9.0, 10.0, 12.0]

    def test_baseline_is_drawn_only_from_members_the_metric_describes(self):
        deviation = peer_statistics.compute_peer_deviation(
            metric='daily_logons',
            value=14.0,
            peer_values=self.PEERS_WITH_NO_AUTH_MEMBERS,
            configured_threshold=3.0,
        )

        self.assertEqual(deviation.peer_median, 10.0)
        self.assertEqual(deviation.peer_count, 5)

    def test_counting_absent_members_as_zero_masks_a_real_deviation(self):
        """Their zeros inflate the spread, so genuine deviation stops clearing it."""
        scoped = peer_statistics.compute_peer_deviation(
            metric='daily_logons',
            value=14.0,
            peer_values=self.PEERS_WITH_NO_AUTH_MEMBERS,
            configured_threshold=3.0,
        )
        counted_as_zero = peer_statistics.compute_peer_deviation(
            metric='daily_logons',
            value=14.0,
            peer_values=[
                0.0 if peer is None else peer for peer in self.PEERS_WITH_NO_AUTH_MEMBERS
            ],
            configured_threshold=3.0,
        )

        self.assertGreater(
            counted_as_zero.peer_spread,
            scoped.peer_spread,
            msg='sanity check: the zeros inflate the spread',
        )
        self.assertTrue(scoped.exceeded)
        self.assertFalse(
            counted_as_zero.exceeded,
            msg='the inflated spread hid a deviation the scoped baseline catches',
        )

    def test_entity_without_the_metric_is_not_scored(self):
        deviation = peer_statistics.compute_peer_deviation(
            metric='daily_logons',
            value=None,
            peer_values=[10.0, 11.0, 9.0, 10.0, 12.0],
            configured_threshold=3.0,
        )

        self.assertEqual(deviation.method, peer_statistics.METHOD_NO_COMPARISON)
        self.assertFalse(deviation.exceeded)

    def test_baseline_ignores_members_the_metric_does_not_describe(self):
        baseline = peer_statistics.build_metric_baseline(
            'daily_logons', [None, None, 10.0, 10.0, 12.0]
        )

        self.assertEqual(baseline.median, 10.0)
        self.assertEqual(len(baseline.values), 3)


class ScoreBoundsTestCase(unittest.TestCase):
    def test_scores_are_capped(self):
        deviation = peer_statistics.compute_peer_deviation(
            metric='daily_logons',
            value=10_000_000.0,
            peer_values=[1.0, 1.0, 2.0, 1.0, 2.0, 1.0],
            configured_threshold=3.0,
        )

        self.assertLessEqual(abs(deviation.score), peer_statistics.MAX_DEVIATION_SCORE)

    def test_low_side_deviation_is_signed_negative(self):
        deviation = peer_statistics.compute_peer_deviation(
            metric='daily_logons',
            value=0.0,
            peer_values=[100.0, 110.0, 90.0, 105.0, 95.0, 100.0],
            configured_threshold=3.0,
        )

        self.assertLess(deviation.score, 0)
        self.assertEqual(deviation.as_details()['direction'], 'low')


if __name__ == '__main__':
    unittest.main()
