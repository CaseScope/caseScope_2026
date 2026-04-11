import importlib.util
import os
import sys
import types
import unittest
from pathlib import Path

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
    def test_overlay_can_attach_metadata_without_mutating_finding_confidence(self):
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

        context = enhancer.apply_to_finding(finding)

        self.assertIsNotNone(context)
        self.assertEqual(finding['confidence'], 46)
        self.assertEqual(finding['overlay_score_adjustment'], 4.0)
        self.assertEqual(finding['intel_overlay']['sources'], ['opencti_sigma'])
        self.assertEqual(finding['ti_enrichment']['confidence_delta'], 4.0)
        self.assertEqual(finding['ti_enrichment']['enriched_confidence'], 50.0)

    def test_case_analyzer_moves_overlay_application_out_of_detection_loop(self):
        source = Path('/opt/casescope/utils/case_analyzer.py').read_text()

        self.assertNotIn('overlay_enhancer = PatternOverlayEnhancer() if is_opencti_overlay_enabled() else None', source)
        self.assertNotIn('overlay_enhancer.apply_to_package(pkg)', source)
        self.assertIn('overlay_enhancer.apply_to_finding(finding)', source)
        self.assertIn('from utils.pattern_overlay import PatternOverlayEnhancer, is_opencti_overlay_enabled', source)


if __name__ == '__main__':
    unittest.main()
