import unittest

from utils.analysis_summary import severity_from_confidence, summarize_findings


class AnalysisSummaryRegressionTestCase(unittest.TestCase):
    def test_summary_counts_gap_pattern_and_storyline_findings_together(self):
        findings = [
            {
                'type': 'gap',
                'name': 'Gap A',
                'summary': 'Gap finding',
                'severity': 'critical',
                'confidence': 95,
                'entity_value': 'HOST-A',
            },
            {
                'type': 'pattern',
                'pattern_name': 'Pattern B',
                'final_confidence': 81,
                'summary': 'Pattern finding',
            },
            {
                'type': 'storyline',
                'name': 'Storyline C',
                'summary': 'Download led to execution',
                'severity': 'high',
                'confidence': 80,
                'entity_value': 'HOST-B',
            },
        ]

        summary = summarize_findings(findings)

        self.assertEqual(summary['total_findings'], 3)
        self.assertEqual(summary['high_confidence_findings'], 3)
        self.assertEqual(summary['critical_findings'], 1)
        self.assertEqual(summary['high_findings'], 2)
        self.assertEqual(len(summary['top_findings']), 3)

    def test_confidence_based_severity_mapping_is_stable(self):
        self.assertEqual(severity_from_confidence(95), 'critical')
        self.assertEqual(severity_from_confidence(80), 'high')
        self.assertEqual(severity_from_confidence(55), 'medium')
        self.assertEqual(severity_from_confidence(10), 'low')


if __name__ == '__main__':
    unittest.main()
