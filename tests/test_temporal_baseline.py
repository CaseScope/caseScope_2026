"""Tests for comparing an entity's recent behaviour to its own earlier baseline.

This supplies the two signals the anomaly detector weighted but never computed.
Real case data constrains the design in two ways that these tests pin down: the
window has to be anchored at the most recent activity because the earliest
timestamp is unreliable, and the split has to be counted in days that actually
saw authentication because authentication records cover a far shorter period than
the artifacts around them.
"""

import importlib.util
import sys
import types
import unittest
from datetime import date
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _load(name, relative_path):
    package = sys.modules.setdefault('utils', types.ModuleType('utils'))
    package.__path__ = [str(REPO_ROOT / 'utils')]

    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_load('utils.event_time_window', 'utils/event_time_window.py')
temporal = _load('utils.temporal_baseline', 'utils/temporal_baseline.py')


def _row(entity, day, targets=(), packages=(), attempts=1):
    """A row in the column order build_activity_day_query selects."""
    return (entity, day, list(targets), list(packages), attempts)


def _days(count, start_day=1):
    return [date(2026, 5, start_day + offset) for offset in range(count)]


class HistorySplitTestCase(unittest.TestCase):
    def test_recent_window_is_taken_from_the_end(self):
        """The latest timestamp is the collection date; the earliest is not trusted."""
        days = [(day, None) for day in _days(8)]
        baseline, recent = temporal.split_entity_history(days)

        self.assertEqual(baseline[0][0], date(2026, 5, 1))
        self.assertEqual(recent[-1][0], date(2026, 5, 8))
        self.assertLess(baseline[-1][0], recent[0][0])

    def test_history_too_short_to_divide_is_skipped(self):
        """Better no comparison than one against a baseline of nothing."""
        for day_count in (0, 1, 2, 3):
            with self.subTest(days=day_count):
                days = [(day, None) for day in _days(day_count)]
                self.assertIsNone(temporal.split_entity_history(days))

    def test_the_shortest_usable_history_is_divided(self):
        days = [(day, None) for day in _days(4)]
        split = temporal.split_entity_history(days)

        self.assertIsNotNone(split)
        baseline, recent = split
        self.assertEqual(len(baseline), 3)
        self.assertEqual(len(recent), 1)

    def test_recent_window_never_eats_the_minimum_baseline(self):
        days = [(day, None) for day in _days(5)]
        baseline, _recent = temporal.split_entity_history(
            days, recent_fraction=0.9, min_baseline_days=3
        )
        self.assertGreaterEqual(len(baseline), 3)

    def test_longer_history_splits_by_fraction(self):
        days = [(day, None) for day in _days(20)]
        baseline, recent = temporal.split_entity_history(days, recent_fraction=0.25)

        self.assertEqual(len(recent), 5)
        self.assertEqual(len(baseline), 15)


class NewTargetTestCase(unittest.TestCase):
    def _signals(self, rows, **options):
        return temporal.compute_temporal_signals(rows, **options)

    def test_hosts_absent_from_the_baseline_are_reported(self):
        rows = [_row('jdoe', day, targets=['WS1']) for day in _days(4)]
        rows += [_row('jdoe', date(2026, 5, 5), targets=['SRV1', 'SRV2', 'SRV3'])]

        signal = self._signals(rows)['jdoe']

        self.assertEqual(signal.new_targets, ['SRV1', 'SRV2', 'SRV3'])
        self.assertEqual(signal.baseline_target_count, 1)

    def test_familiar_hosts_are_not_new(self):
        rows = [_row('jdoe', day, targets=['WS1', 'SRV1']) for day in _days(4)]
        rows += [_row('jdoe', date(2026, 5, 5), targets=['WS1', 'SRV1'])]

        self.assertEqual(self._signals(rows)['jdoe'].new_targets, [])

    def test_an_empty_baseline_cannot_establish_novelty(self):
        """No recorded destination means nothing can be shown to be new."""
        rows = [_row('jdoe', day, targets=[]) for day in _days(4)]
        rows += [_row('jdoe', date(2026, 5, 5), targets=['SRV1', 'SRV2'])]

        self.assertEqual(self._signals(rows)['jdoe'].new_targets, [])

    def test_a_few_unfamiliar_hosts_among_many_do_not_score(self):
        """A service account reaching dozens of hosts always picks up a few.

        What distinguishes lateral movement is that most of where it went is new.
        """
        familiar = [f'SRV{index}' for index in range(20)]
        rows = [_row('svc', day, targets=familiar) for day in _days(4)]
        rows += [_row('svc', date(2026, 5, 5), targets=familiar + ['NEW1', 'NEW2'])]

        signal = self._signals(rows)['svc']

        self.assertEqual(len(signal.new_targets), 2)
        self.assertNotIn(
            'new_targets',
            signal.deviation_scores(3.0),
            msg='two new hosts out of twenty-two is ordinary drift',
        )

    def test_mostly_unfamiliar_hosts_do_score(self):
        rows = [_row('jdoe', day, targets=['WS1']) for day in _days(4)]
        rows += [_row('jdoe', date(2026, 5, 5), targets=['SRV1', 'SRV2', 'SRV3'])]

        scores = self._signals(rows)['jdoe'].deviation_scores(3.0)
        self.assertIn('new_targets', scores)


class AuthMethodChangeTestCase(unittest.TestCase):
    def _signal(self, baseline_packages, recent_packages):
        rows = [_row('jdoe', day, packages=baseline_packages) for day in _days(4)]
        rows += [_row('jdoe', date(2026, 5, 5), packages=recent_packages)]
        return temporal.compute_temporal_signals(rows)['jdoe']

    def test_a_move_toward_ntlm_is_reported(self):
        signal = self._signal(['KERBEROS'], ['NTLM'])

        self.assertGreater(signal.weak_auth_shift_points, 0)
        self.assertIn('auth_method_change', signal.deviation_scores(3.0))

    def test_a_move_away_from_ntlm_is_not_reported(self):
        """Strengthening authentication is not an anomaly."""
        signal = self._signal(['NTLM'], ['KERBEROS'])

        self.assertEqual(signal.weak_auth_shift_points, 0)
        self.assertNotIn('auth_method_change', signal.deviation_scores(3.0))

    def test_a_steady_mix_is_not_reported(self):
        signal = self._signal(['KERBEROS', 'NTLM'], ['KERBEROS', 'NTLM'])
        self.assertEqual(signal.weak_auth_shift_points, 0)

    def test_the_mix_is_recorded_as_evidence(self):
        evidence = self._signal(['KERBEROS'], ['NTLM']).evidence()

        self.assertIn('baseline_auth_mix', evidence)
        self.assertIn('recent_auth_mix', evidence)
        self.assertIn('weak_auth_shift_points', evidence)


class DeviationScaleTestCase(unittest.TestCase):
    def _signals(self, **kwargs):
        defaults = dict(
            key='jdoe', baseline_days=5, recent_days=2,
            baseline_target_count=4, recent_target_count=4,
        )
        defaults.update(kwargs)
        return temporal.TemporalSignals(**defaults)

    def test_the_significance_amount_lands_on_the_threshold(self):
        """One scale has to carry both temporal and peer evidence."""
        signal = self._signals(
            new_targets=['A', 'B', 'C'], recent_target_count=3,
        )
        self.assertAlmostEqual(signal.deviation_scores(3.0)['new_targets'], 3.0, places=6)

    def test_an_auth_shift_at_the_significance_amount_lands_on_the_threshold(self):
        signal = self._signals(weak_auth_shift_points=25.0)
        self.assertAlmostEqual(
            signal.deviation_scores(3.0)['auth_method_change'], 3.0, places=6
        )

    def test_the_scale_follows_the_threshold_it_is_given(self):
        signal = self._signals(new_targets=['A', 'B', 'C'], recent_target_count=3)
        self.assertAlmostEqual(signal.deviation_scores(1.5)['new_targets'], 1.5, places=6)

    def test_no_single_signal_can_swamp_the_composite(self):
        """Nineteen unfamiliar hosts is not six times worse than three."""
        signal = self._signals(
            new_targets=[f'H{index}' for index in range(40)], recent_target_count=40,
        )
        score = signal.deviation_scores(3.0)['new_targets']

        self.assertLessEqual(score, 3.0 * temporal.MAX_SIGNAL_MULTIPLE)

    def test_a_quiet_entity_produces_no_scores(self):
        self.assertEqual(self._signals().deviation_scores(3.0), {})


class QueryContractTestCase(unittest.TestCase):
    def setUp(self):
        self.query = temporal.build_activity_day_query()

    def test_kerberos_events_do_not_contribute_a_destination(self):
        """A ticket request is logged by the domain controller, not the target.

        Counting its source_host as a destination would name the DC as a target
        for every account in the domain.
        """
        self.assertIn("event_id IN ('4624', '4625')", self.query)

    def test_kerberos_events_still_contribute_their_package(self):
        for event_id in ('4768', '4771', '4776'):
            self.assertIn(event_id, self.query)

    def test_builtin_accounts_are_excluded(self):
        """SYSTEM alone is the noisiest name in the corpus at 164,070 logons."""
        self.assertIn("'system'", self.query)
        self.assertIn("lower(username) LIKE 'dwm-%'", self.query)
        self.assertIn("lower(username) LIKE 'umfd-%'", self.query)

    def test_machine_accounts_are_excluded(self):
        self.assertIn("username NOT LIKE '%$'", self.query)

    def test_the_case_id_is_bound_as_a_parameter(self):
        self.assertIn('{case_id:UInt32}', self.query)

    def test_the_event_time_window_is_applied(self):
        self.assertIn('{min_time:String}', self.query)
        self.assertIn('now() + INTERVAL 1 DAY', self.query)

    def test_rows_are_one_per_account_per_day(self):
        self.assertIn('GROUP BY entity, activity_day', self.query)


class BuiltinAccountTestCase(unittest.TestCase):
    def test_the_local_system_account_is_named(self):
        self.assertIn('system', temporal.BUILTIN_ACCOUNT_NAMES)
        self.assertIn('anonymous logon', temporal.BUILTIN_ACCOUNT_NAMES)

    def test_per_session_desktop_accounts_are_matched_by_prefix(self):
        self.assertIn('dwm-', temporal.BUILTIN_ACCOUNT_PREFIXES)
        self.assertIn('umfd-', temporal.BUILTIN_ACCOUNT_PREFIXES)


if __name__ == '__main__':
    unittest.main()
