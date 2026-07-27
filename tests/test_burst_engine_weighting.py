"""Phase 7: a burst check must be able to earn the weight it declares.

Burst contribution was a flat three points per burst capped at ten, regardless
of the check's declared weight. A weight-20 check could never earn more than
half its weight, and in the legacy path a burst check contributed nothing at
all while its weight still counted against the maximum, and the burst engine
added a second term for the same signal.
"""

import unittest

from utils.deterministic_evidence_engine import DeterministicEvidenceEngine
from utils.finding_contract import (
    DEFAULT_BURST_ENGINE_WEIGHT,
    get_burst_engine_contribution,
    get_burst_engine_max_possible,
)
from utils.pattern_check_definitions import PATTERN_CHECKS, CheckResult


def bursts(count):
    """Bursts for contribution maths, where only the count matters."""
    return [object()] * count


def burst_results(count):
    """Real BurstResult rows, for paths that serialise burst detail."""
    from utils.pattern_check_definitions import BurstResult

    return [
        BurstResult(
            username='alice',
            source_host='host-a',
            src_ip='10.0.0.5',
            events_in_bucket=9 + index,
            distinct_event_types=1,
            span_seconds=12,
            bucket_start='2026-04-11T10:0%d:00' % index,
            bucket_end='2026-04-11T10:0%d:12' % index,
        )
        for index in range(count)
    ]


class GraduatedContributionTests(unittest.TestCase):
    def test_contribution_scales_with_the_declared_weight(self):
        self.assertEqual(get_burst_engine_contribution(bursts(3), weight=20), 20.0)
        self.assertEqual(get_burst_engine_contribution(bursts(2), weight=20), 14.0)
        self.assertEqual(get_burst_engine_contribution(bursts(1), weight=20), 8.0)

    def test_full_weight_is_reachable_for_every_declared_burst_weight(self):
        for weight in (10, 15, 20):
            with self.subTest(weight=weight):
                self.assertEqual(
                    get_burst_engine_contribution(bursts(5), weight=weight),
                    float(weight),
                )

    def test_no_bursts_earns_nothing(self):
        self.assertEqual(get_burst_engine_contribution([], weight=20), 0.0)
        self.assertEqual(get_burst_engine_contribution(None, weight=20), 0.0)

    def test_omitted_weight_keeps_the_engine_default(self):
        self.assertEqual(
            get_burst_engine_contribution(bursts(5)), float(DEFAULT_BURST_ENGINE_WEIGHT)
        )
        self.assertEqual(
            get_burst_engine_max_possible(), float(DEFAULT_BURST_ENGINE_WEIGHT)
        )

    def test_max_possible_follows_the_declared_weight(self):
        self.assertEqual(get_burst_engine_max_possible(weight=15), 15.0)


class PlaceholderFillTests(unittest.TestCase):
    def _placeholder(self, weight=15):
        return CheckResult(
            check_id='netscan_burst', status='FAIL', weight=weight,
            contribution=0.0, detail='Evaluated via burst engine',
            source='burst_engine',
        )

    def test_placeholder_is_filled_in_when_bursts_are_found(self):
        checks = [self._placeholder()]
        DeterministicEvidenceEngine._apply_burst_results_to_checks(checks, bursts(3))

        self.assertEqual(checks[0].status, 'PASS')
        self.assertEqual(checks[0].contribution, 15.0)
        self.assertIn('3 burst(s)', checks[0].detail)

    def test_placeholder_stays_failed_with_no_bursts(self):
        checks = [self._placeholder()]
        DeterministicEvidenceEngine._apply_burst_results_to_checks(checks, [])

        self.assertEqual(checks[0].status, 'FAIL')
        self.assertEqual(checks[0].contribution, 0.0)
        self.assertIn('No bursts', checks[0].detail)

    def test_non_burst_checks_are_untouched(self):
        other = CheckResult(
            check_id='kerb_volume', status='PASS', weight=15,
            contribution=15.0, detail='ok', source='query',
        )
        DeterministicEvidenceEngine._apply_burst_results_to_checks([other], bursts(3))
        self.assertEqual(other.contribution, 15.0)
        self.assertEqual(other.detail, 'ok')


class LegacyDoubleCountTests(unittest.TestCase):
    def _score(self, checks, burst_list):
        return DeterministicEvidenceEngine._compute_legacy_score(
            DeterministicEvidenceEngine.__new__(DeterministicEvidenceEngine),
            checks,
            burst_list,
            [],
        )

    def test_burst_check_is_counted_once(self):
        checks = [
            CheckResult(
                check_id='netscan_anchor', status='PASS', weight=20,
                contribution=20.0, detail='', source='query',
            ),
            CheckResult(
                check_id='netscan_burst', status='FAIL', weight=15,
                contribution=0.0, detail='', source='burst_engine',
            ),
        ]
        DeterministicEvidenceEngine._apply_burst_results_to_checks(checks, bursts(3))
        score, max_possible = self._score(checks, bursts(3))

        # 20 anchor + 15 burst, against a maximum of 20 + 15.
        self.assertEqual(score, 35.0)
        self.assertEqual(max_possible, 35.0)

    def test_pattern_without_a_burst_check_still_gets_the_engine_term(self):
        checks = [
            CheckResult(
                check_id='spray_anchor', status='PASS', weight=20,
                contribution=20.0, detail='', source='query',
            ),
        ]
        score, max_possible = self._score(checks, bursts(3))

        self.assertEqual(score, 30.0)
        self.assertEqual(max_possible, 30.0)

    def test_burst_check_with_no_bursts_earns_nothing_but_keeps_its_weight(self):
        checks = [
            CheckResult(
                check_id='netscan_anchor', status='PASS', weight=20,
                contribution=20.0, detail='', source='query',
            ),
            CheckResult(
                check_id='netscan_burst', status='FAIL', weight=15,
                contribution=0.0, detail='', source='burst_engine',
            ),
        ]
        DeterministicEvidenceEngine._apply_burst_results_to_checks(checks, [])
        score, max_possible = self._score(checks, [])

        self.assertEqual(score, 20.0)
        self.assertEqual(max_possible, 35.0)


class ProducerInputWeightTests(unittest.TestCase):
    """Provenance must report the points the burst actually earned."""

    def test_weight_lookup_finds_the_declared_burst_check(self):
        self.assertEqual(
            DeterministicEvidenceEngine._burst_check_weight('pass_the_ticket'), 20
        )
        self.assertEqual(
            DeterministicEvidenceEngine._burst_check_weight('kerberoasting'), 15
        )

    def test_pattern_without_a_burst_check_has_no_weight(self):
        self.assertIsNone(
            DeterministicEvidenceEngine._burst_check_weight('psexec_execution')
        )

    def test_producer_input_uses_the_declared_weight(self):
        engine = DeterministicEvidenceEngine.__new__(DeterministicEvidenceEngine)
        inputs = engine._build_burst_producer_inputs('pass_the_ticket', burst_results(3))

        self.assertEqual(inputs[0]['contribution'], 20.0)
        self.assertEqual(inputs[0]['max_possible'], 20.0)

    def test_producer_input_falls_back_to_the_engine_default(self):
        engine = DeterministicEvidenceEngine.__new__(DeterministicEvidenceEngine)
        inputs = engine._build_burst_producer_inputs('psexec_execution', burst_results(3))

        self.assertEqual(inputs[0]['contribution'], 10.0)
        self.assertEqual(inputs[0]['max_possible'], 10.0)


class DeclaredBurstWeightTests(unittest.TestCase):
    def test_every_burst_check_weight_is_now_reachable(self):
        unreachable = []
        for pattern_id, checks in PATTERN_CHECKS.items():
            for check in checks:
                if check.check_type != 'burst':
                    continue
                earned = get_burst_engine_contribution(bursts(5), weight=check.weight)
                if earned < float(check.weight):
                    unreachable.append((pattern_id, check.id, check.weight, earned))
        self.assertEqual(
            unreachable, [], f'burst checks that cannot earn their weight: {unreachable}'
        )


if __name__ == '__main__':
    unittest.main()
