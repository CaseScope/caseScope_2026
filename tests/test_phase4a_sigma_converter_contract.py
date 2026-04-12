import importlib.util
import sys
import types
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
UTILS_DIR = REPO_ROOT / 'utils'


def _load_module(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f'Unable to load module from {path}')
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


utils_pkg = sys.modules.setdefault('utils', types.ModuleType('utils'))
utils_pkg.__path__ = [str(UTILS_DIR)]

sigma_converter = _load_module(
    'utils.sigma_converter',
    UTILS_DIR / 'sigma_converter.py',
)


class Phase4aSigmaConverterContractTestCase(unittest.TestCase):
    def test_classify_sigma_pattern_type_distinguishes_single_sequence_and_aggregation(self):
        self.assertEqual(
            sigma_converter.classify_sigma_pattern_type(
                {'selection': {'EventID': 1}, 'condition': 'selection'},
                None,
            ),
            'single',
        )
        self.assertEqual(
            sigma_converter.classify_sigma_pattern_type(
                {
                    'selection1': {'EventID': 1},
                    'selection2': {'Channel': 'Security'},
                    'condition': 'selection1 and selection2',
                },
                None,
            ),
            'sequence',
        )
        self.assertEqual(
            sigma_converter.classify_sigma_pattern_type(
                {'selection': {'EventID': 1}, 'condition': 'selection | count() > 5'},
                '10m',
            ),
            'aggregation',
        )

    def test_build_sigma_pattern_payload_projects_shared_fields(self):
        payload = sigma_converter.build_sigma_pattern_payload(
            rule={
                'title': 'Suspicious Service Creation',
                'description': 'Detects suspicious service installation.',
                'id': 'rule-42',
                'references': ['https://example.com/rule-42'],
                'status': 'stable',
                'falsepositives': ['Admin software deployment'],
                'detection': {'condition': 'selection'},
            },
            source='hayabusa',
            pattern_type='single',
            severity='high',
            confidence_weight=0.85,
            time_window_minutes=60,
            required_event_ids=['7045'],
            required_channels=['System'],
            clickhouse_query='SELECT * FROM events',
            sanitized_detection={'selection': {'EventID': 7045}},
            sigma_level='high',
            mitre_tactic='Persistence',
            mitre_technique='T1543.003',
        )

        self.assertEqual(payload['name'], 'Suspicious Service Creation')
        self.assertEqual(payload['source'], 'hayabusa')
        self.assertEqual(payload['source_id'], 'rule-42')
        self.assertEqual(payload['source_url'], 'https://example.com/rule-42')
        self.assertEqual(payload['pattern_type'], 'single')
        self.assertEqual(payload['severity'], 'high')
        self.assertEqual(payload['confidence_weight'], 0.85)
        self.assertEqual(payload['required_event_ids'], ['7045'])
        self.assertEqual(payload['required_channels'], ['System'])
        self.assertEqual(payload['created_by'], 'hayabusa_import')
        self.assertEqual(payload['pattern_definition']['sigma_status'], 'stable')
        self.assertEqual(
            payload['pattern_definition']['false_positives'],
            ['Admin software deployment'],
        )

    def test_convert_sigma_rule_uses_shared_projection_helper(self):
        converter = sigma_converter.SigmaToPatternConverter()
        sigma_yaml = """
title: Suspicious Service Creation
id: rule-42
status: stable
description: Detects suspicious service installation.
references:
  - https://example.com/rule-42
tags:
  - attack.persistence
  - attack.t1543.003
logsource:
  product: windows
  service: system
detection:
  selection:
    EventID: 7045
    Channel: System
  condition: selection
level: high
falsepositives:
  - Admin software deployment
"""
        payload = converter.convert_sigma_rule(sigma_yaml, source='hayabusa')

        self.assertIsNotNone(payload)
        self.assertEqual(payload['source'], 'hayabusa')
        self.assertEqual(payload['pattern_type'], 'single')
        self.assertEqual(payload['mitre_technique'], 'T1543.003')
        self.assertEqual(payload['required_event_ids'], ['7045'])
        self.assertEqual(payload['required_channels'], ['System'])
        self.assertEqual(payload['created_by'], 'hayabusa_import')

        source = (REPO_ROOT / 'utils' / 'sigma_converter.py').read_text()
        self.assertIn('classify_sigma_pattern_type(', source)
        self.assertIn('build_sigma_pattern_payload(', source)


if __name__ == '__main__':
    unittest.main()
