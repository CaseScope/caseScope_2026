import os
import unittest
from pathlib import Path


REPO_ROOT = os.path.dirname(os.path.dirname(__file__))


class Phase7CaseStageContractTestCase(unittest.TestCase):
    def test_case_pipeline_modules_exist_for_timeline_narrative_enrichment_and_actions(self):
        pipeline_init = Path(
            os.path.join(REPO_ROOT, 'pipeline', '__init__.py'),
        ).read_text(encoding='utf-8')
        case_analyzer_source = Path(
            os.path.join(REPO_ROOT, 'utils', 'case_analyzer.py'),
        ).read_text(encoding='utf-8')

        for export_name in (
            'run_ioc_timeline',
            'run_incident_storylines',
            'run_ai_triage',
            'run_ai_synthesis',
            'run_opencti_enrichment',
            'generate_suggested_actions',
        ):
            self.assertIn(export_name, pipeline_init)

        self.assertIn('from pipeline.case_timeline import run_ioc_timeline', case_analyzer_source)
        self.assertIn('from pipeline.case_timeline import run_incident_storylines', case_analyzer_source)
        self.assertIn('from pipeline.case_narrative import run_ai_triage', case_analyzer_source)
        self.assertIn('from pipeline.case_narrative import run_ai_synthesis', case_analyzer_source)
        self.assertIn('from pipeline.case_enrichment import run_opencti_enrichment', case_analyzer_source)
        self.assertIn('from pipeline.case_actions import generate_suggested_actions', case_analyzer_source)


if __name__ == '__main__':
    unittest.main()
