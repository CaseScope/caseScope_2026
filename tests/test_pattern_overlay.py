import os
import unittest

os.environ.setdefault('SECRET_KEY', 'test-secret')

from utils.pattern_overlay import (
    PatternOverlayEnhancer,
    compute_overlay_score_adjustment,
    match_external_pattern_to_builtins,
)
from utils.pattern_check_definitions import EvidencePackage


class PatternOverlayTestCase(unittest.TestCase):
    def test_match_external_pattern_prefers_exact_mitre_overlap(self):
        matches = match_external_pattern_to_builtins(
            'Remote Service Execution via PsExec',
            mitre_techniques=['T1021.002'],
            aliases=['psexec'],
        )

        self.assertTrue(matches)
        self.assertEqual(matches[0]['pattern_id'], 'psexec_execution')
        self.assertIn('mitre_technique', matches[0]['match_reasons'])

    def test_overlay_boost_is_bounded_for_weak_and_strong_scores(self):
        overlays = [{
            'confidence_boost': 7.0,
            'freshness_score': 92.0,
        }]

        self.assertEqual(compute_overlay_score_adjustment(20, overlays), 0.0)
        self.assertEqual(compute_overlay_score_adjustment(38, overlays), 2.0)
        self.assertEqual(compute_overlay_score_adjustment(48, overlays), 4.0)
        self.assertEqual(compute_overlay_score_adjustment(72, overlays), 7.0)

    def test_overlay_enhancer_applies_context_without_overpromoting(self):
        enhancer = PatternOverlayEnhancer(overlays_by_pattern={
            'psexec_execution': [{
                'source': 'opencti_sigma',
                'confidence_boost': 6.0,
                'freshness_score': 90.0,
                'matched_mitre_techniques': ['T1021.002'],
            }]
        })
        package = EvidencePackage(
            anchor={},
            pattern_id='psexec_execution',
            pattern_name='PsExec/SMB Lateral Movement',
            correlation_key='demo',
            deterministic_score=42,
            mitre_techniques=['T1021.002'],
        )

        context = enhancer.apply_to_package(package)

        self.assertIsNotNone(context)
        self.assertEqual(package.overlay_score_adjustment, 4.0)
        self.assertEqual(package.deterministic_score, 46.0)
        self.assertEqual(context['sources'], ['opencti_sigma'])


if __name__ == '__main__':
    unittest.main()
