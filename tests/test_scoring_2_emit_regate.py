"""Phase 5: every score mutation must re-ask the emit question.

Emission is decided once during scoring, but the score is mutated afterwards
by noise reduction, spread bonuses, MITRE corroboration and soft suppression.
Each of those used to re-implement the comparison, or skip it entirely, so a
package could be marked eligible at a score it no longer had.
"""

import unittest

from utils.finding_contract import (
    SCORE_EMIT_BLOCK_REASON,
    recompute_emit_block_reasons,
    recompute_emit_eligibility,
)


class FakePackage:
    def __init__(self, score, reasons, scoring_version='2.1'):
        self.deterministic_score = score
        self.emit_block_reasons = list(reasons)
        self.eligible_to_emit = not reasons
        self.scoring_version = scoring_version


CONFIG = {'emit_score_threshold': 50, 'emit_threshold_mode': 'score_only'}


class ReGateAfterScoreDropTests(unittest.TestCase):
    def test_soft_suppression_below_threshold_blocks_emission(self):
        package = FakePackage(55.0, [])
        package.deterministic_score = 35.0  # 20-point soft suppression
        recompute_emit_eligibility(package, CONFIG)

        self.assertFalse(package.eligible_to_emit)
        self.assertIn(SCORE_EMIT_BLOCK_REASON, package.emit_block_reasons)

    def test_noise_reduction_below_threshold_blocks_emission(self):
        package = FakePackage(58.0, [])
        package.deterministic_score = 43.0  # 15-point noise reduction
        recompute_emit_eligibility(package, CONFIG)

        self.assertFalse(package.eligible_to_emit)

    def test_score_still_above_threshold_stays_eligible(self):
        package = FakePackage(90.0, [])
        package.deterministic_score = 70.0
        recompute_emit_eligibility(package, CONFIG)

        self.assertTrue(package.eligible_to_emit)
        self.assertEqual(package.emit_block_reasons, [])


class ReGateAfterScoreRiseTests(unittest.TestCase):
    def test_spread_bonus_over_threshold_clears_the_score_block(self):
        package = FakePackage(40.0, [SCORE_EMIT_BLOCK_REASON])
        package.deterministic_score = 55.0
        recompute_emit_eligibility(package, CONFIG)

        self.assertTrue(package.eligible_to_emit)
        self.assertEqual(package.emit_block_reasons, [])


class NonScoreBlockReasonTests(unittest.TestCase):
    """A disqualifier is not a score problem and must survive re-gating."""

    def test_disqualifier_survives_a_score_rise(self):
        package = FakePackage(40.0, ['disqualifier:kerb_service_account'])
        package.deterministic_score = 95.0
        recompute_emit_eligibility(package, CONFIG)

        self.assertFalse(package.eligible_to_emit)
        self.assertEqual(
            package.emit_block_reasons, ['disqualifier:kerb_service_account']
        )

    def test_all_non_score_reasons_survive(self):
        reasons = [
            'disqualifier:x',
            'required_checks_not_met',
            'anchor_only_not_allowed',
            'missing_lateral_signal',
        ]
        package = FakePackage(20.0, list(reasons) + [SCORE_EMIT_BLOCK_REASON])
        package.deterministic_score = 99.0
        recompute_emit_eligibility(package, CONFIG)

        self.assertEqual(package.emit_block_reasons, reasons)
        self.assertFalse(package.eligible_to_emit)


class ThresholdModeTests(unittest.TestCase):
    def test_required_only_mode_ignores_the_score(self):
        package = FakePackage(5.0, [])
        recompute_emit_eligibility(
            package,
            {'emit_score_threshold': 50, 'emit_threshold_mode': 'required_only'},
        )
        self.assertTrue(package.eligible_to_emit)

    def test_score_and_required_mode_still_gates_on_score(self):
        package = FakePackage(5.0, [])
        recompute_emit_eligibility(
            package,
            {'emit_score_threshold': 50, 'emit_threshold_mode': 'score_and_required'},
        )
        self.assertFalse(package.eligible_to_emit)

    def test_custom_threshold_is_honoured(self):
        package = FakePackage(65.0, [])
        recompute_emit_eligibility(
            package,
            {'emit_score_threshold': 70, 'emit_threshold_mode': 'score_only'},
        )
        self.assertFalse(package.eligible_to_emit)


class LegacyScoringTests(unittest.TestCase):
    """Scoring 1.0 predates per-pattern emit config and gates on a fixed 50."""

    def test_legacy_uses_fifty_regardless_of_pattern_config(self):
        package = FakePackage(55.0, [], scoring_version='1.0')
        recompute_emit_eligibility(
            package,
            {'emit_score_threshold': 90, 'emit_threshold_mode': 'score_only'},
        )
        self.assertTrue(package.eligible_to_emit)

    def test_legacy_blocks_below_fifty(self):
        package = FakePackage(49.9, [], scoring_version='1.0')
        recompute_emit_eligibility(package, {})
        self.assertFalse(package.eligible_to_emit)


class HelperPurityTests(unittest.TestCase):
    def test_reason_list_is_not_mutated_in_place(self):
        original = [SCORE_EMIT_BLOCK_REASON, 'disqualifier:x']
        result = recompute_emit_block_reasons(
            score=99.0,
            existing_reasons=original,
            pattern_config=CONFIG,
            scoring_version='2.1',
        )
        self.assertEqual(original, [SCORE_EMIT_BLOCK_REASON, 'disqualifier:x'])
        self.assertEqual(result, ['disqualifier:x'])

    def test_repeated_calls_do_not_duplicate_the_score_reason(self):
        package = FakePackage(10.0, [])
        for _ in range(3):
            recompute_emit_eligibility(package, CONFIG)
        self.assertEqual(package.emit_block_reasons, [SCORE_EMIT_BLOCK_REASON])


class CallSiteWiringTests(unittest.TestCase):
    """Each mutation site must route through the shared helper."""

    def test_engine_sites_call_the_helper(self):
        import inspect
        from utils import deterministic_evidence_engine as engine

        noise = inspect.getsource(
            engine.DeterministicEvidenceEngine.evaluate_pattern
        )
        self.assertIn('recompute_emit_eligibility(pkg, pattern_config)', noise)

        spread = inspect.getsource(
            engine.DeterministicEvidenceEngine._reconcile_spread_scoring_v2
        )
        self.assertIn('recompute_emit_eligibility(package, pattern_config)', spread)

        v2_1 = inspect.getsource(
            engine.DeterministicEvidenceEngine._compute_score_v2_1
        )
        self.assertIn('recompute_emit_block_reasons', v2_1)

    def test_pipeline_sites_call_the_helper(self):
        import inspect
        from pipeline import pattern_analysis

        boost = inspect.getsource(pattern_analysis.apply_mitre_corroboration_boost)
        self.assertIn('recompute_emit_eligibility(package, pattern_config)', boost)

        suppression = inspect.getsource(pattern_analysis.process_ai_pattern_packages)
        self.assertIn('recompute_emit_eligibility(package, pattern_config)', suppression)


if __name__ == '__main__':
    unittest.main()
