"""Contract tests for the behavioral anomaly detector.

This detector had never produced a finding. Beyond the phase-ordering defect,
its threshold and confidence tiers were absolute deviations of 3, 4 and 5 that
a small peer group cannot arithmetically reach, so every group of fewer than
about nine members was permanently silent. These tests pin the sizes and shapes
that must now yield a finding.
"""

import importlib.util
import sys
import types
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_with_stubs(name, relative_path, stubs):
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


peer_statistics = _load_with_stubs(
    'peer_statistics_for_anomaly_test', 'utils/peer_statistics.py', {}
)


class _GapFindingType:
    VOLUME_SPIKE = 'volume_spike'
    OFF_HOURS_ACTIVITY = 'off_hours_activity'
    NEW_TARGET_ACCESS = 'new_target_access'
    AUTH_METHOD_CHANGE = 'auth_method_change'
    ANOMALOUS_USER = 'anomalous_user'
    ANOMALOUS_SYSTEM = 'anomalous_system'


class _Finding:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


def _load_detector():
    base_module = types.ModuleType('utils.stateful_detectors')

    class _BaseGapDetector:
        def __init__(self, case_id, analysis_id):
            self.case_id = case_id
            self.analysis_id = analysis_id

        def _create_finding(self, **kwargs):
            return _Finding(**kwargs)

    base_module.BaseGapDetector = _BaseGapDetector

    stubs = {
        'models.database': types.SimpleNamespace(db=types.SimpleNamespace(session=None)),
        'models.behavioral_profiles': types.SimpleNamespace(
            GapDetectionFinding=_Finding,
            GapFindingType=_GapFindingType,
            UserBehaviorProfile=object,
            SystemBehaviorProfile=object,
            PeerGroup=object,
            PeerGroupMember=object,
        ),
        'models.known_user': types.SimpleNamespace(KnownUser=object),
        'models.known_system': types.SimpleNamespace(KnownSystem=object),
        'utils.stateful_detectors': base_module,
        'utils.peer_statistics': peer_statistics,
    }
    return _load_with_stubs(
        'behavioral_anomaly_under_test',
        'utils/stateful_detectors/behavioral_anomaly.py',
        stubs,
    )


anomaly_module = _load_detector()
BehavioralAnomalyDetector = anomaly_module.BehavioralAnomalyDetector

# Users and systems are scored against different metrics, so the weight table
# is now passed in rather than being a single attribute on the detector.
USER_WEIGHTS = BehavioralAnomalyDetector.USER_ANOMALY_WEIGHTS


def _peer_group(member_count, name='user_cluster_1'):
    return types.SimpleNamespace(
        id=1,
        group_name=name,
        member_count=member_count,
        profile_data={'daily_logons': {'median': 10, 'mad': 1}},
        median_daily_logons=10,
        median_failure_rate=0,
        median_off_hours_pct=5,
    )


def _user_profile():
    return types.SimpleNamespace(
        username='svc_backup',
        user_id=42,
        total_events=5000,
        avg_daily_logons=400,
        failure_rate=0,
        off_hours_percentage=90,
        profile_period_start=None,
        profile_period_end=None,
    )


class ThresholdReachabilityTestCase(unittest.TestCase):
    def setUp(self):
        self.detector = BehavioralAnomalyDetector(7, 'analysis-under-test')

    def test_small_group_threshold_is_reachable(self):
        threshold = self.detector._effective_threshold(_peer_group(3))
        self.assertIsNotNone(threshold)
        self.assertLess(
            threshold,
            3.0,
            msg='a three-member group must not be held to a deviation it cannot reach',
        )

    def test_large_group_keeps_the_configured_threshold(self):
        self.assertEqual(self.detector._effective_threshold(_peer_group(68)), 3.0)

    def test_single_member_group_yields_no_analysis(self):
        self.assertIsNone(self.detector._effective_threshold(_peer_group(1)))

    def test_group_of_three_can_produce_a_finding(self):
        """The case that was previously impossible."""
        scores = {'daily_logons': 1.7, 'failure_rate': 0.0, 'off_hours': 0.2, 'unique_hosts': 0.1}
        result = self.detector._analyze_deviation_scores(
            _peer_group(3), scores, USER_WEIGHTS
        )

        self.assertIsNotNone(result, msg='a clear deviation in a small group must be flagged')
        self.assertIn('daily_logons', result['anomalies_detected'])

    def test_ordinary_variation_in_a_small_group_is_not_flagged(self):
        scores = {'daily_logons': 0.3, 'failure_rate': 0.1, 'off_hours': 0.2, 'unique_hosts': 0.0}
        self.assertIsNone(self.detector._analyze_deviation_scores(
            _peer_group(3), scores, USER_WEIGHTS
        ))

    def test_large_group_still_requires_the_full_threshold(self):
        scores = {'daily_logons': 2.4, 'failure_rate': 0.0, 'off_hours': 0.0, 'unique_hosts': 0.0}
        self.assertIsNone(
            self.detector._analyze_deviation_scores(_peer_group(68), scores, USER_WEIGHTS)
        )


class ConfidenceScalingTestCase(unittest.TestCase):
    def setUp(self):
        self.detector = BehavioralAnomalyDetector(7, 'analysis-under-test')

    def test_finding_is_created_for_a_small_group_deviation(self):
        scores = {'daily_logons': 1.8, 'failure_rate': 0.0, 'off_hours': 1.5, 'unique_hosts': 0.0}
        result = self.detector._analyze_deviation_scores(
            _peer_group(4), scores, USER_WEIGHTS
        )
        self.assertIsNotNone(result)

        finding = self.detector._create_user_anomaly_finding(
            _user_profile(), _peer_group(4), result
        )
        self.assertIsNotNone(
            finding,
            msg='confidence tiers must scale to the threshold or small groups stay silent',
        )
        self.assertGreaterEqual(finding.confidence, 35)

    def test_confidence_boundaries_match_the_old_scale_at_full_threshold(self):
        """At a threshold of 3.0 the tiers must land where they always did."""
        for max_z, expected_floor in ((5.0, 70), (4.0, 55), (3.0, 40)):
            confidence = self.detector._confidence_from_deviation({
                'max_z_score': max_z,
                'composite_score': 0,
                'threshold': 3.0,
            })
            self.assertEqual(confidence, expected_floor)

    def test_deviation_below_threshold_scores_the_lowest_tier(self):
        confidence = self.detector._confidence_from_deviation({
            'max_z_score': 1.0,
            'composite_score': 0,
            'threshold': 3.0,
        })
        self.assertEqual(confidence, 30)


class CompositeScoreTestCase(unittest.TestCase):
    def setUp(self):
        self.detector = BehavioralAnomalyDetector(7, 'analysis-under-test')

    def test_deviation_on_threshold_scores_about_fifty(self):
        scores = {'daily_logons': 3.0, 'failure_rate': 3.0, 'off_hours': 3.0}
        composite = self.detector._calculate_composite_anomaly_score(
            scores, USER_WEIGHTS, threshold=3.0
        )
        self.assertAlmostEqual(composite, 50.0, places=1)

    def test_small_group_threshold_rescales_the_composite(self):
        """A deviation on a lowered threshold must not score as though it were tiny."""
        scores = {'daily_logons': 1.0, 'failure_rate': 1.0, 'off_hours': 1.0}
        composite = self.detector._calculate_composite_anomaly_score(
            scores, USER_WEIGHTS, threshold=1.0
        )
        self.assertAlmostEqual(composite, 50.0, places=1)

    def test_composite_is_capped_at_one_hundred(self):
        scores = {'daily_logons': 10.0, 'failure_rate': 10.0, 'off_hours': 10.0}
        composite = self.detector._calculate_composite_anomaly_score(
            scores, USER_WEIGHTS, threshold=3.0
        )
        self.assertLessEqual(composite, 100)


if __name__ == '__main__':
    unittest.main()
