import importlib.util
import os
import sys
import types
import unittest
from unittest.mock import patch

from tests.phase7_case_analyzer_loader import load_case_analyzer_with_stubs

os.environ.setdefault('SECRET_KEY', 'test-secret')

REPO_ROOT = os.path.dirname(os.path.dirname(__file__))


def _load_module(name: str, relative_path: str):
    module_path = os.path.join(REPO_ROOT, relative_path)
    spec = importlib.util.spec_from_file_location(name, module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _load_pattern_overlay_module():
    fake_utils = types.ModuleType('utils')
    fake_utils.__path__ = []

    fake_pattern_event_mappings = types.ModuleType('utils.pattern_event_mappings')
    fake_pattern_event_mappings.PATTERN_EVENT_MAPPINGS = {
        'psexec_execution': {
            'name': 'PsExec/SMB Lateral Movement',
            'mitre_techniques': ['T1021.002'],
            'overlay_aliases': ['psexec'],
        }
    }

    previous_utils = sys.modules.get('utils')
    previous_mappings = sys.modules.get('utils.pattern_event_mappings')
    sys.modules['utils'] = fake_utils
    sys.modules['utils.pattern_event_mappings'] = fake_pattern_event_mappings

    try:
        return _load_module(
            'phase15_pattern_overlay',
            os.path.join('utils', 'pattern_overlay.py'),
        )
    finally:
        if previous_utils is not None:
            sys.modules['utils'] = previous_utils
        else:
            sys.modules.pop('utils', None)

        if previous_mappings is not None:
            sys.modules['utils.pattern_event_mappings'] = previous_mappings
        else:
            sys.modules.pop('utils.pattern_event_mappings', None)


pattern_overlay = _load_pattern_overlay_module()


class Phase15TiOverlaySeparationTestCase(unittest.TestCase):
    def test_ti_enrichment_helper_can_attach_metadata_without_mutating_finding_confidence(self):
        fake_ti = types.ModuleType('utils.ti')
        fake_ti.__path__ = []

        previous_ti = sys.modules.get('utils.ti')
        previous_overlay = sys.modules.get('utils.pattern_overlay')
        sys.modules['utils.ti'] = fake_ti
        sys.modules['utils.pattern_overlay'] = pattern_overlay

        try:
            ti_enrichment = _load_module(
                'phase4b_ti_enrichment',
                os.path.join('utils', 'ti', 'enrichment.py'),
            )
        finally:
            if previous_ti is not None:
                sys.modules['utils.ti'] = previous_ti
            else:
                sys.modules.pop('utils.ti', None)

            if previous_overlay is not None:
                sys.modules['utils.pattern_overlay'] = previous_overlay
            else:
                sys.modules.pop('utils.pattern_overlay', None)

        enhancer = pattern_overlay.PatternOverlayEnhancer(
            overlays_by_pattern={
                'psexec_execution': [{
                    'source': 'opencti_sigma',
                    'confidence_boost': 6.0,
                    'freshness_score': 90.0,
                    'matched_mitre_techniques': ['T1021.002'],
                }]
            }
        )
        finding = {
            'pattern_id': 'psexec_execution',
            'pattern_name': 'PsExec/SMB Lateral Movement',
            'correlation_key': 'demo',
            'deterministic_score': 42,
            'confidence': 46,
            'mitre_techniques': ['T1021.002'],
        }

        context = ti_enrichment.apply_ti_overlay_to_finding(
            finding,
            overlay_enhancer=enhancer,
        )

        self.assertIsNotNone(context)
        self.assertEqual(finding['confidence'], 46)
        self.assertEqual(finding['overlay_score_adjustment'], 4.0)
        self.assertEqual(finding['intel_overlay']['authority'], 'metadata_only')
        self.assertEqual(finding['intel_overlay']['sources'], ['opencti_sigma'])
        self.assertEqual(finding['ti_enrichment']['authority'], 'metadata_only')
        self.assertEqual(finding['ti_enrichment']['confidence_delta'], 4.0)
        self.assertEqual(finding['ti_enrichment']['authoritative_confidence'], 46.0)
        self.assertEqual(finding['ti_enrichment']['display_confidence_preview'], 50.0)

    def test_case_analyzer_uses_ti_enrichment_surface_for_overlay_application(self):
        case_analyzer, restore_modules = load_case_analyzer_with_stubs(
            'phase15_case_analyzer_under_test'
        )
        try:
            analyzer = case_analyzer.CaseAnalyzer(case_id=21, progress_callback=None, parallel=False)
            analyzer.analysis_id = 'analysis-21'
            analyzer._attack_chains = [{'chain_id': 'chain-1'}]
            recorded = {}

            fake_case_enrichment = types.ModuleType('pipeline.case_enrichment')

            def run_opencti_enrichment(**kwargs):
                recorded['kwargs'] = kwargs
                return ({'actors': ['APT Demo']}, [{'pattern_id': 'psexec_execution'}])

            fake_case_enrichment.run_opencti_enrichment = run_opencti_enrichment

            with patch.dict(sys.modules, {'pipeline.case_enrichment': fake_case_enrichment}):
                analyzer._enrich_with_opencti([{'id': 'finding-1'}])

            self.assertEqual(analyzer._opencti_context, {'actors': ['APT Demo']})
            self.assertEqual(recorded['kwargs']['case_id'], 21)
            self.assertEqual(recorded['kwargs']['analysis_id'], 'analysis-21')
            self.assertEqual(recorded['kwargs']['findings'], [{'id': 'finding-1'}])
            self.assertEqual(recorded['kwargs']['attack_chains'], [{'chain_id': 'chain-1'}])
            self.assertIs(recorded['kwargs']['progress_callback'].__self__, analyzer)
            self.assertEqual(recorded['kwargs']['progress_callback'].__func__.__name__, '_update_progress')
            self.assertIs(recorded['kwargs']['record_phase_outcome'].__self__, analyzer)
            self.assertEqual(
                recorded['kwargs']['record_phase_outcome'].__func__.__name__,
                '_record_phase_outcome',
            )
        finally:
            restore_modules()


if __name__ == '__main__':
    unittest.main()
