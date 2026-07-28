"""Contract tests for peer group construction.

Clusters were being built from raw heavy-tailed counts and were summarized with
a median paired with a standard deviation, which produced groups whose stored
median activity was zero and whose spread was in the hundreds. Empty profiles
were also never excluded, because the guard tested a feature sum that a neutral
encoding value kept permanently non-zero.
"""

import importlib.util
import sys
import types
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_module(name, relative_path, stubs=None):
    stubs = stubs or {}
    previous = {key: sys.modules.get(key) for key in stubs}
    sys.modules.update(stubs)
    try:
        spec = importlib.util.spec_from_file_location(name, REPO_ROOT / relative_path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        for key, original in previous.items():
            if original is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = original


peer_statistics = _load_module('peer_statistics_for_clustering_test', 'utils/peer_statistics.py')


def _load_clustering():
    stubs = {
        'models.database': types.SimpleNamespace(db=types.SimpleNamespace(session=None)),
        'models.behavioral_profiles': types.SimpleNamespace(
            UserBehaviorProfile=object,
            SystemBehaviorProfile=object,
            PeerGroup=object,
            PeerGroupMember=object,
        ),
        'utils.peer_statistics': peer_statistics,
    }
    return _load_module('peer_clustering_under_test', 'utils/peer_clustering.py', stubs)


clustering_module = _load_clustering()
PeerGroupBuilder = clustering_module.PeerGroupBuilder


def _user_profile(**overrides):
    defaults = {
        'id': 1,
        'user_id': 1,
        'total_events': 100,
        'total_logons': 100,
        'avg_daily_logons': 10.0,
        'avg_daily_failures': 0.0,
        'failure_rate': 0.0,
        'unique_hosts_accessed': 2,
        'off_hours_percentage': 5.0,
        'auth_types': {'KERBEROS': 100.0},
        'peer_group_id': None,
    }
    defaults.update(overrides)
    return types.SimpleNamespace(**defaults)


class EmptyProfileExclusionTestCase(unittest.TestCase):
    def setUp(self):
        self.builder = PeerGroupBuilder(7, 'analysis-under-test')

    def test_profile_with_no_activity_is_excluded(self):
        empty = _user_profile(
            total_events=0,
            avg_daily_logons=0,
            failure_rate=0,
            unique_hosts_accessed=0,
            off_hours_percentage=0,
            auth_types=None,
        )
        self.assertFalse(self.builder._user_profile_has_activity(empty))

    def test_profile_with_activity_is_kept(self):
        self.assertTrue(self.builder._user_profile_has_activity(_user_profile()))

    def test_empty_profiles_are_not_turned_into_features(self):
        profiles = [
            _user_profile(id=1),
            _user_profile(
                id=2,
                total_events=0,
                avg_daily_logons=0,
                failure_rate=0,
                unique_hosts_accessed=0,
                off_hours_percentage=0,
                auth_types=None,
            ),
            _user_profile(id=3, avg_daily_logons=40.0),
        ]
        features, profile_ids = self.builder._extract_user_features(profiles)

        self.assertEqual(
            profile_ids,
            [1, 3],
            msg='the neutral auth encoding must not keep an empty profile in the matrix',
        )
        self.assertEqual(len(features), 2)


class FeatureCompressionTestCase(unittest.TestCase):
    def setUp(self):
        self.builder = PeerGroupBuilder(7, 'analysis-under-test')

    def test_counts_are_log_compressed(self):
        """A service account two orders of magnitude above its peers must not
        flatten every other member into one indistinguishable band."""
        modest = self.builder._compress_count(10)
        heavy = self.builder._compress_count(10_000)

        self.assertLess(heavy / modest, 10, msg='raw counts were not compressed')
        self.assertGreater(heavy, modest)

    def test_compression_handles_none_and_negatives(self):
        self.assertEqual(self.builder._compress_count(None), 0.0)
        self.assertEqual(self.builder._compress_count(-5), 0.0)


class PeerStatisticsTestCase(unittest.TestCase):
    def setUp(self):
        self.builder = PeerGroupBuilder(7, 'analysis-under-test')

    def test_spread_is_robust_not_a_standard_deviation(self):
        """One extreme member must not inflate the stored spread."""
        values = {'daily_logons': [10.0, 10.0, 11.0, 9.0, 10.0, 5000.0]}
        stats = self.builder._calculate_peer_statistics(values, 'user')

        self.assertEqual(stats['median_daily_logons'], 10.0)
        self.assertLess(
            stats['std_daily_logons'],
            10.0,
            msg='a standard deviation here would be in the thousands',
        )

    def test_system_statistics_reuse_the_shared_columns(self):
        values = {'auth_volume': [5.0, 6.0, 7.0], 'unique_users': [2.0, 3.0, 4.0]}
        stats = self.builder._calculate_peer_statistics(values, 'system')

        self.assertEqual(stats['median_daily_logons'], 6.0)
        self.assertEqual(stats['median_unique_hosts'], 3.0)

    def test_metric_values_are_collected_in_member_order(self):
        profiles = [
            _user_profile(id=1, avg_daily_logons=1.0),
            _user_profile(id=2, avg_daily_logons=2.0),
        ]
        values = self.builder._metric_values(profiles, 'user')

        self.assertEqual(values['daily_logons'], [1.0, 2.0])
        self.assertIn('failure_rate', values)
        self.assertIn('unique_hosts', values)
        self.assertIn('off_hours', values)


class DeviationScoreTestCase(unittest.TestCase):
    def setUp(self):
        self.builder = PeerGroupBuilder(7, 'analysis-under-test')

    def test_scores_leave_the_scored_member_out(self):
        values = {'daily_logons': [10.0, 10.0, 10.0, 10.0, 10.0, 400.0]}
        scores = self.builder._calculate_deviation_scores(values, entity_index=5)

        self.assertGreater(scores['daily_logons'], 3.0)

    def test_typical_member_scores_near_zero(self):
        values = {'daily_logons': [10.0, 10.0, 10.0, 10.0, 10.0, 400.0]}
        scores = self.builder._calculate_deviation_scores(values, entity_index=0)

        self.assertLess(abs(scores['daily_logons']), 3.0)

    def test_every_metric_is_scored(self):
        values = {
            'daily_logons': [1.0, 2.0, 3.0],
            'failure_rate': [0.0, 0.0, 50.0],
            'unique_hosts': [1.0, 1.0, 9.0],
            'off_hours': [5.0, 6.0, 7.0],
        }
        scores = self.builder._calculate_deviation_scores(values, entity_index=2)

        self.assertEqual(set(scores), set(values))


if __name__ == '__main__':
    unittest.main()
