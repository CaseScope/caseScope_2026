"""The composite anomaly score must weight exactly the metrics that exist.

The single weight table named two metrics nothing ever computed, `new_targets`
at 20 percent and `auth_method_change` at 10, so thirty percent of the declared
weight was inert. It also omitted `unique_hosts` and `unique_users`, which are
computed and flagged, so an entity anomalous only on one of those scored zero on
the composite - reachable in principle, and it would have looked like a scoring
bug rather than a missing weight.

These tests pin both directions: no weight without a producer, and no producer
without a weight.
"""

import ast
import importlib.util
import sys
import types
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _load(name, relative_path, stubs=None):
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


def _load_anomaly_detector():
    base = types.ModuleType('utils.stateful_detectors')

    class _BaseGapDetector:
        def __init__(self, case_id, analysis_id):
            self.case_id = case_id
            self.analysis_id = analysis_id
            self.ch_client = None

    base.BaseGapDetector = _BaseGapDetector

    stubs = {
        'models.database': types.SimpleNamespace(db=types.SimpleNamespace(session=None)),
        'models.behavioral_profiles': types.SimpleNamespace(
            GapDetectionFinding=object,
            GapFindingType=types.SimpleNamespace(
                VOLUME_SPIKE='volume_spike',
                OFF_HOURS_ACTIVITY='off_hours_activity',
                NEW_TARGET_ACCESS='new_target_access',
                AUTH_METHOD_CHANGE='auth_method_change',
                ANOMALOUS_USER='anomalous_user',
                ANOMALOUS_SYSTEM='anomalous_system',
            ),
            UserBehaviorProfile=types.SimpleNamespace(query=None),
            SystemBehaviorProfile=types.SimpleNamespace(query=None),
            PeerGroup=types.SimpleNamespace(query=None),
            PeerGroupMember=types.SimpleNamespace(query=None),
        ),
        'models.known_user': types.SimpleNamespace(KnownUser=object),
        'models.known_system': types.SimpleNamespace(KnownSystem=object),
        'utils.peer_statistics': types.SimpleNamespace(
            resolve_threshold=lambda member_count, configured_threshold: configured_threshold
        ),
        'utils.stateful_detectors': base,
        'config': types.SimpleNamespace(Config=type('Config', (), {})),
    }
    module = _load(
        'behavioral_anomaly_under_test',
        'utils/stateful_detectors/behavioral_anomaly.py',
        stubs,
    )
    return module.BehavioralAnomalyDetector


Detector = _load_anomaly_detector()
temporal_baseline = _load('temporal_baseline_weights_under_test', 'utils/temporal_baseline.py')


def _peer_metric_names():
    """Metric names peer clustering emits, read from its source.

    Taken from the source rather than by importing, because the clustering module
    pulls in numpy, scikit-learn and the model layer.
    """
    tree = ast.parse((REPO_ROOT / 'utils' / 'peer_clustering.py').read_text())

    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) or node.name != '_metric_values':
            continue
        names = set()
        for inner in ast.walk(node):
            if isinstance(inner, ast.Dict):
                for key in inner.keys:
                    if isinstance(key, ast.Constant) and isinstance(key.value, str):
                        names.add(key.value)
        return names

    raise AssertionError('_metric_values not found in utils/peer_clustering.py')


def _temporal_metric_names():
    """Metric names the temporal baseline emits."""
    signals = temporal_baseline.TemporalSignals(
        key='someone',
        baseline_days=5,
        recent_days=2,
        new_targets=['A', 'B', 'C'],
        baseline_target_count=4,
        recent_target_count=4,
        weak_auth_shift_points=40.0,
    )
    return set(signals.deviation_scores(3.0))


class WeightCoverageTestCase(unittest.TestCase):
    def setUp(self):
        self.peer_metrics = _peer_metric_names()
        self.temporal_metrics = _temporal_metric_names()
        self.producible = self.peer_metrics | self.temporal_metrics

    def test_every_weighted_metric_is_actually_produced(self):
        weighted = set(Detector.USER_ANOMALY_WEIGHTS) | set(Detector.SYSTEM_ANOMALY_WEIGHTS)
        inert = weighted - self.producible

        self.assertEqual(
            inert,
            set(),
            msg=(
                f'{sorted(inert)} carry weight in the composite score but nothing '
                'computes them, so that share of the weight does nothing'
            ),
        )

    def test_every_produced_metric_carries_weight(self):
        weighted = set(Detector.USER_ANOMALY_WEIGHTS) | set(Detector.SYSTEM_ANOMALY_WEIGHTS)
        unweighted = self.producible - weighted

        self.assertEqual(
            unweighted,
            set(),
            msg=(
                f'{sorted(unweighted)} are computed and flagged as anomalies but '
                'carry no weight, so an entity anomalous only on one of them '
                'scores zero on the composite'
            ),
        )

    def test_temporal_metrics_are_the_two_that_were_missing(self):
        self.assertEqual(self.temporal_metrics, {'new_targets', 'auth_method_change'})

    def test_user_and_system_weights_each_sum_to_one(self):
        self.assertAlmostEqual(sum(Detector.USER_ANOMALY_WEIGHTS.values()), 1.0, places=6)
        self.assertAlmostEqual(sum(Detector.SYSTEM_ANOMALY_WEIGHTS.values()), 1.0, places=6)

    def test_user_weights_cover_the_user_metrics_only(self):
        """Systems have no failure rate and accounts have no unique_users."""
        self.assertIn('daily_logons', Detector.USER_ANOMALY_WEIGHTS)
        self.assertIn('unique_hosts', Detector.USER_ANOMALY_WEIGHTS)
        self.assertNotIn('unique_users', Detector.USER_ANOMALY_WEIGHTS)
        self.assertIn('unique_users', Detector.SYSTEM_ANOMALY_WEIGHTS)
        self.assertIn('auth_volume', Detector.SYSTEM_ANOMALY_WEIGHTS)


class CompositeScoreTestCase(unittest.TestCase):
    def setUp(self):
        self.detector = Detector(case_id=1, analysis_id='test')

    def _score(self, z_scores, weights, threshold=3.0):
        return self.detector._calculate_composite_anomaly_score(z_scores, weights, threshold)

    def test_a_single_flagged_metric_still_scores(self):
        """Previously zero for unique_users, because it carried no weight."""
        for metric, weights in (
            ('unique_users', Detector.SYSTEM_ANOMALY_WEIGHTS),
            ('unique_hosts', Detector.USER_ANOMALY_WEIGHTS),
            ('new_targets', Detector.USER_ANOMALY_WEIGHTS),
            ('auth_method_change', Detector.USER_ANOMALY_WEIGHTS),
        ):
            with self.subTest(metric=metric):
                self.assertGreater(self._score({metric: 3.0}, weights), 0)

    def test_a_deviation_on_the_threshold_scores_fifty(self):
        self.assertAlmostEqual(
            self._score({'daily_logons': 3.0}, Detector.USER_ANOMALY_WEIGHTS, 3.0),
            50.0,
            places=6,
        )

    def test_scale_follows_the_group_threshold(self):
        """A group whose threshold had to be lowered still scores on the same scale."""
        self.assertAlmostEqual(
            self._score({'daily_logons': 1.5}, Detector.USER_ANOMALY_WEIGHTS, 1.5),
            50.0,
            places=6,
        )

    def test_absent_metrics_do_not_dilute_the_score(self):
        one = self._score({'daily_logons': 6.0}, Detector.USER_ANOMALY_WEIGHTS, 3.0)
        both = self._score(
            {'daily_logons': 6.0, 'failure_rate': 6.0}, Detector.USER_ANOMALY_WEIGHTS, 3.0
        )
        self.assertAlmostEqual(one, both, places=6)

    def test_no_recognised_metric_scores_zero(self):
        self.assertEqual(self._score({'unrelated': 9.0}, Detector.USER_ANOMALY_WEIGHTS), 0)

    def test_score_is_capped_at_one_hundred(self):
        self.assertLessEqual(
            self._score({'daily_logons': 50.0}, Detector.USER_ANOMALY_WEIGHTS, 3.0), 100
        )


class AnomalyTypeMappingTestCase(unittest.TestCase):
    def setUp(self):
        self.detector = Detector(case_id=1, analysis_id='test')

    def test_temporal_metrics_map_to_their_own_finding_types(self):
        self.assertEqual(
            self.detector._identify_anomaly_type({'new_targets': 9.0}, ['new_targets']),
            'new_target_access',
        )
        self.assertEqual(
            self.detector._identify_anomaly_type(
                {'auth_method_change': 9.0}, ['auth_method_change']
            ),
            'auth_method_change',
        )

    def test_the_strongest_metric_decides_the_type(self):
        self.assertEqual(
            self.detector._identify_anomaly_type(
                {'off_hours': 3.1, 'auth_method_change': 9.0},
                ['off_hours', 'auth_method_change'],
            ),
            'auth_method_change',
        )


if __name__ == '__main__':
    unittest.main()
