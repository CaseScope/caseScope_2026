import importlib.util
import sys
import types
import unittest
from pathlib import Path
from types import SimpleNamespace


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

pattern_check_definitions = _load_module(
    'utils.pattern_check_definitions',
    UTILS_DIR / 'pattern_check_definitions.py',
)
gap_detector_bridge = _load_module(
    'utils.gap_detector_bridge',
    UTILS_DIR / 'gap_detector_bridge.py',
)
deterministic_evidence_engine = _load_module(
    'utils.deterministic_evidence_engine',
    UTILS_DIR / 'deterministic_evidence_engine.py',
)

EvidencePackage = pattern_check_definitions.EvidencePackage
DeterministicEvidenceEngine = deterministic_evidence_engine.DeterministicEvidenceEngine
map_gap_finding_to_check_results = gap_detector_bridge.map_gap_finding_to_check_results


class Phase4aProducerInputsNormalizationTestCase(unittest.TestCase):
    def test_evidence_package_exposes_canonical_and_legacy_gap_inputs(self):
        package = EvidencePackage(
            anchor={},
            pattern_id='password_spraying',
            pattern_name='Password Spraying',
            correlation_key='demo',
            producer_inputs=[
                {
                    'producer': 'gap_detector',
                    'producer_type': 'PASSWORD_SPRAYING',
                    'mapped_checks': [{'check_id': 'spray_distinct_users', 'status': 'PASS'}],
                },
                {
                    'producer': 'hayabusa',
                    'producer_type': 'sigma_chain',
                    'mapped_checks': [{'check_id': 'spray_off_hours', 'status': 'PASS'}],
                },
            ],
        )

        serialized = package.to_dict()

        self.assertEqual(len(serialized['producer_inputs']), 2)
        self.assertEqual(len(serialized['gap_detector_inputs']), 1)
        self.assertEqual(
            serialized['gap_detector_inputs'][0]['producer_type'],
            'PASSWORD_SPRAYING',
        )
        self.assertEqual(package.gap_inputs[0]['producer'], 'gap_detector')

        package.gap_inputs = [
            {
                'producer_type': 'BRUTE_FORCE',
                'mapped_checks': [{'check_id': 'brute_high_failures', 'status': 'PASS'}],
            }
        ]

        self.assertEqual(len(package.producer_inputs), 2)
        self.assertEqual(package.gap_inputs[0]['producer_type'], 'BRUTE_FORCE')
        self.assertEqual(package.gap_inputs[0]['producer'], 'gap_detector')

    def test_engine_builds_structured_gap_producer_inputs(self):
        finding = SimpleNamespace(
            finding_type='PASSWORD_SPRAYING',
            confidence=72,
            entity_type='source_ip',
            entity_value='10.0.0.5',
            event_count=14,
            evidence={
                'unique_users': 12,
                'max_attempts_per_user': 2,
                'source_ips': ['10.0.0.5', '10.0.0.6'],
            },
            details={},
        )
        check_results = map_gap_finding_to_check_results(finding)
        engine = DeterministicEvidenceEngine(case_id=1, analysis_id='phase4a-test')

        producer_inputs = engine._build_gap_producer_inputs(
            [(finding, check_result) for check_result in check_results]
        )

        self.assertEqual(len(producer_inputs), 1)
        producer_input = producer_inputs[0]
        self.assertEqual(producer_input['producer'], 'gap_detector')
        self.assertEqual(producer_input['producer_type'], 'PASSWORD_SPRAYING')
        self.assertEqual(producer_input['pattern_id'], 'password_spraying')
        self.assertEqual(producer_input['entity_type'], 'source_ip')
        self.assertEqual(producer_input['entity_value'], '10.0.0.5')
        self.assertEqual(producer_input['detector_metadata']['event_count'], 14)
        self.assertEqual(
            producer_input['detector_metadata']['source_ips'],
            ['10.0.0.5', '10.0.0.6'],
        )
        self.assertEqual(
            [item['check_id'] for item in producer_input['mapped_checks']],
            ['spray_distinct_users', 'spray_low_per_account'],
        )


if __name__ == '__main__':
    unittest.main()
