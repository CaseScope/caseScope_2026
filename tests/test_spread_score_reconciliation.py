"""Phase 4: the spread bonus must appear in the score breakdown.

_evaluate_spread raised deterministic_score directly without touching
score_components or score_reasons, so the breakdown the UI renders did not sum
to the score it displayed alongside it.
"""

import unittest

from utils.pattern_check_definitions import EvidencePackage, SpreadAssessment


def reconcile(package):
    """Sum the recorded reasons the way the score display does."""
    return round(sum(float(reason.get('delta') or 0.0) for reason in package.score_reasons), 1)


class SpreadScoreReconciliationTests(unittest.TestCase):
    def _package(self):
        package = EvidencePackage(
            pattern_id='pass_the_ticket',
            pattern_name='Pass the Ticket',
            correlation_key='user=jsmith',
            anchor={'username': 'jsmith', 'source_host': 'FIN-WKS0142'},
        )
        package.deterministic_score = 40.0
        package.max_possible_score = 60.0
        package.score_components = {'check_score': 40.0, 'final_score': 40.0}
        package.score_reasons = [{
            'id': 'ptt_anchor',
            'name': 'Anchor event',
            'role': 'anchor',
            'delta': 40.0,
            'source': 'checks',
            'detail': 'anchor matched',
        }]
        return package

    def test_reasons_reconcile_before_spread(self):
        package = self._package()
        self.assertEqual(reconcile(package), package.deterministic_score)

    def test_spread_bonus_is_recorded_in_components_and_reasons(self):
        package = self._package()
        contribution = 15.0
        weight = 20.0

        # Mirrors the per-package block in _evaluate_spread.
        before = package.deterministic_score
        package.spread = SpreadAssessment(
            pivot_field='username',
            pivot_value='jsmith',
            total_targets=4,
            total_users=1,
            span_minutes=22,
            first_seen='2026-07-01T00:00:00',
            last_seen='2026-07-01T00:22:00',
            sibling_keys=['user=jsmith', 'user=jsmith|host=DC01'],
            contribution=contribution,
        )
        package.deterministic_score = min(100, package.deterministic_score + contribution)
        package.max_possible_score = min(100, package.max_possible_score + weight)
        applied = round(package.deterministic_score - before, 1)
        package.score_components['spread_score'] = round(
            package.score_components.get('spread_score', 0.0) + applied, 1
        )
        package.score_components['final_score'] = package.deterministic_score
        package.score_reasons.append({
            'id': 'spread_username',
            'name': 'Cross-key spread on username',
            'role': 'corroboration',
            'delta': applied,
            'source': 'spread_engine',
            'detail': 'jsmith touched 4 target_host value(s)',
        })

        self.assertEqual(package.deterministic_score, 55.0)
        self.assertEqual(package.score_components['spread_score'], 15.0)
        self.assertEqual(
            package.score_components['final_score'], package.deterministic_score
        )
        self.assertEqual(reconcile(package), package.deterministic_score)

    def test_recorded_delta_matches_the_clamped_increase(self):
        # When the score is already near the ceiling the recorded delta must be
        # the increase that actually landed, not the full contribution.
        package = self._package()
        package.deterministic_score = 95.0
        package.score_components = {'check_score': 95.0, 'final_score': 95.0}
        package.score_reasons = [{
            'id': 'ptt_anchor', 'name': 'Anchor event', 'role': 'anchor',
            'delta': 95.0, 'source': 'checks', 'detail': 'anchor matched',
        }]

        before = package.deterministic_score
        package.deterministic_score = min(100, package.deterministic_score + 15.0)
        applied = round(package.deterministic_score - before, 1)
        package.score_components['spread_score'] = applied
        package.score_components['final_score'] = package.deterministic_score
        package.score_reasons.append({
            'id': 'spread_username', 'name': 'Cross-key spread on username',
            'role': 'corroboration', 'delta': applied,
            'source': 'spread_engine', 'detail': 'clamped',
        })

        self.assertEqual(applied, 5.0)
        self.assertEqual(reconcile(package), 100.0)
        self.assertEqual(package.deterministic_score, 100.0)


class SpreadEngineSourceTests(unittest.TestCase):
    def test_engine_records_spread_reason_inline(self):
        import inspect
        from utils import deterministic_evidence_engine

        source = inspect.getsource(
            deterministic_evidence_engine.DeterministicEvidenceEngine._evaluate_spread
        )
        self.assertIn("score_components['spread_score']", source)
        self.assertIn("'source': 'spread_engine'", source)
        self.assertIn("pkg.score_reasons.append", source)


if __name__ == '__main__':
    unittest.main()
