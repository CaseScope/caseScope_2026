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
finding_contract = _load_module(
    'utils.finding_contract',
    UTILS_DIR / 'finding_contract.py',
)
deterministic_evidence_engine = _load_module(
    'utils.deterministic_evidence_engine',
    UTILS_DIR / 'deterministic_evidence_engine.py',
)

EvidencePackage = pattern_check_definitions.EvidencePackage
BurstResult = pattern_check_definitions.BurstResult
CheckResult = pattern_check_definitions.CheckResult
SequenceResult = pattern_check_definitions.SequenceResult
DeterministicEvidenceEngine = deterministic_evidence_engine.DeterministicEvidenceEngine
build_burst_engine_producer_input = finding_contract.build_burst_engine_producer_input
build_gap_detector_producer_input = finding_contract.build_gap_detector_producer_input
build_sequence_engine_producer_input = finding_contract.build_sequence_engine_producer_input
get_burst_engine_contribution = finding_contract.get_burst_engine_contribution
get_burst_engine_max_possible = finding_contract.get_burst_engine_max_possible
get_sequence_engine_contribution = finding_contract.get_sequence_engine_contribution
get_sequence_engine_max_possible = finding_contract.get_sequence_engine_max_possible
sort_producer_inputs = finding_contract.sort_producer_inputs
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
                {
                    'producer': 'burst_engine',
                    'producer_type': 'temporal_burst',
                    'status': 'matched',
                },
            ],
        )

        serialized = package.to_dict()

        self.assertEqual(len(serialized['producer_inputs']), 3)
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

        self.assertEqual(len(package.producer_inputs), 3)
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

    def test_gap_detector_producer_helper_builds_canonical_contract(self):
        producer_input = build_gap_detector_producer_input(
            finding_type='PASSWORD_SPRAYING',
            pattern_id='password_spraying',
            confidence=72,
            entity_type='source_ip',
            entity_value='10.0.0.5',
            event_count=14,
            source_ips=['10.0.0.5', '10.0.0.6', '10.0.0.5'],
            evidence_keys={'source_ips', 'unique_users'},
            detail_keys=['window_start', 'window_end'],
        )

        self.assertEqual(producer_input['producer'], 'gap_detector')
        self.assertEqual(producer_input['producer_type'], 'PASSWORD_SPRAYING')
        self.assertEqual(producer_input['pattern_id'], 'password_spraying')
        self.assertEqual(producer_input['confidence'], 72)
        self.assertEqual(producer_input['entity_type'], 'source_ip')
        self.assertEqual(producer_input['entity_value'], '10.0.0.5')
        self.assertEqual(producer_input['mapped_checks'], [])
        self.assertEqual(producer_input['detector_metadata']['event_count'], 14)
        self.assertEqual(
            producer_input['detector_metadata']['source_ips'],
            ['10.0.0.5', '10.0.0.6'],
        )
        self.assertEqual(
            producer_input['detector_metadata']['evidence_keys'],
            ['source_ips', 'unique_users'],
        )
        self.assertEqual(
            producer_input['detector_metadata']['detail_keys'],
            ['window_end', 'window_start'],
        )

    def test_burst_and_sequence_producer_helpers_build_canonical_contracts(self):
        bursts = [
            BurstResult(
                username='alice',
                source_host='host-a',
                src_ip='10.0.0.5',
                events_in_bucket=12,
                distinct_event_types=2,
                span_seconds=18,
                bucket_start='2026-04-11T10:00:00',
                bucket_end='2026-04-11T10:00:18',
            ),
            BurstResult(
                username='alice',
                source_host='host-a',
                src_ip='10.0.0.5',
                events_in_bucket=9,
                distinct_event_types=1,
                span_seconds=12,
                bucket_start='2026-04-11T10:01:00',
                bucket_end='2026-04-11T10:01:12',
            ),
        ]
        sequence = SequenceResult(
            chain='logon -> share_access -> service_install',
            status='partial',
            steps=[{'label': 'logon', 'found': True}],
            missing_steps=['share_access'],
            evaluability='missing_telemetry',
            telemetry_gap_sources=['Security'],
        )

        burst_input = build_burst_engine_producer_input(
            pattern_id='psexec_execution',
            bursts=bursts,
        )
        sequence_input = build_sequence_engine_producer_input(
            pattern_id='psexec_execution',
            sequence=sequence,
        )

        self.assertEqual(burst_input['producer'], 'burst_engine')
        self.assertEqual(burst_input['producer_type'], 'temporal_burst')
        self.assertEqual(burst_input['pattern_id'], 'psexec_execution')
        self.assertEqual(burst_input['contribution'], 6)
        self.assertEqual(burst_input['max_possible'], 10)
        self.assertEqual(burst_input['detector_metadata']['burst_count'], 2)
        self.assertEqual(burst_input['detector_metadata']['peak_events_in_bucket'], 12)
        self.assertEqual(burst_input['detector_metadata']['distinct_usernames'], ['alice'])

        self.assertEqual(sequence_input['producer'], 'sequence_engine')
        self.assertEqual(sequence_input['producer_type'], 'ordered_event_chain')
        self.assertEqual(sequence_input['pattern_id'], 'psexec_execution')
        self.assertEqual(sequence_input['status'], 'partial')
        self.assertEqual(sequence_input['contribution'], 2)
        self.assertEqual(sequence_input['max_possible'], 5)
        self.assertEqual(
            sequence_input['detector_metadata']['chain'],
            'logon -> share_access -> service_install',
        )
        self.assertEqual(
            sequence_input['detector_metadata']['missing_steps'],
            ['share_access'],
        )
        self.assertEqual(
            sequence_input['detector_metadata']['evaluability'],
            'missing_telemetry',
        )
        self.assertEqual(
            sequence_input['detector_metadata']['telemetry_gap_sources'],
            ['Security'],
        )

    def test_burst_and_sequence_contribution_helpers_match_engine_scoring(self):
        engine = DeterministicEvidenceEngine(case_id=1, analysis_id='phase4a-test')
        checks = [
            CheckResult(
                check_id='spray_distinct_users',
                status='PASS',
                weight=30,
                contribution=30,
                detail='12 distinct usernames',
                source='gap_detector',
            )
        ]
        bursts = [
            BurstResult(
                username='alice',
                source_host='host-a',
                src_ip='10.0.0.5',
                events_in_bucket=12,
                distinct_event_types=2,
                span_seconds=18,
                bucket_start='2026-04-11T10:00:00',
                bucket_end='2026-04-11T10:00:18',
            ),
            BurstResult(
                username='alice',
                source_host='host-a',
                src_ip='10.0.0.5',
                events_in_bucket=9,
                distinct_event_types=1,
                span_seconds=12,
                bucket_start='2026-04-11T10:01:00',
                bucket_end='2026-04-11T10:01:12',
            ),
        ]
        sequences = [
            SequenceResult(
                chain='logon -> share_access -> service_install',
                status='partial',
                steps=[{'label': 'logon', 'found': True}],
                missing_steps=['share_access'],
                evaluability='missing_telemetry',
                telemetry_gap_sources=['Security'],
            ),
            SequenceResult(
                chain='service_install -> remote_thread',
                status='complete',
                steps=[{'label': 'service_install', 'found': True}],
                missing_steps=[],
            ),
        ]

        score, max_possible = engine._compute_score(checks, bursts, sequences)

        self.assertEqual(get_burst_engine_contribution(bursts), 6)
        self.assertEqual(get_burst_engine_max_possible(), 10)
        self.assertEqual(get_sequence_engine_contribution('partial'), 2)
        self.assertEqual(get_sequence_engine_contribution('complete'), 5)
        self.assertEqual(get_sequence_engine_contribution('missing'), 0)
        self.assertEqual(get_sequence_engine_max_possible(), 5)
        self.assertEqual(score, 43.0)
        self.assertEqual(max_possible, 50.0)

    def test_sort_producer_inputs_applies_canonical_deterministic_order(self):
        sorted_inputs = sort_producer_inputs(
            [
                {
                    'producer': 'sequence_engine',
                    'producer_type': 'ordered_event_chain',
                    'entity_value': '',
                    'status': 'partial',
                },
                {
                    'producer': 'gap_detector',
                    'producer_type': 'PASSWORD_SPRAYING',
                    'entity_value': '10.0.0.5',
                    'status': '',
                },
                {
                    'producer': 'gap_detector',
                    'producer_type': 'PASSWORD_SPRAYING',
                    'entity_value': '10.0.0.5',
                    'status': 'matched',
                },
                {
                    'producer': 'burst_engine',
                    'producer_type': 'temporal_burst',
                    'entity_value': '',
                    'status': 'matched',
                },
            ]
        )

        self.assertEqual(
            [(item['producer'], item['producer_type'], item['entity_value'], item['status']) for item in sorted_inputs],
            [
                ('burst_engine', 'temporal_burst', '', 'matched'),
                ('gap_detector', 'PASSWORD_SPRAYING', '10.0.0.5', ''),
                ('gap_detector', 'PASSWORD_SPRAYING', '10.0.0.5', 'matched'),
                ('sequence_engine', 'ordered_event_chain', '', 'partial'),
            ],
        )

    def test_engine_builds_structured_burst_and_sequence_producer_inputs(self):
        engine = DeterministicEvidenceEngine(case_id=1, analysis_id='phase4a-test')
        bursts = [
            BurstResult(
                username='alice',
                source_host='host-a',
                src_ip='10.0.0.5',
                events_in_bucket=12,
                distinct_event_types=2,
                span_seconds=18,
                bucket_start='2026-04-11T10:00:00',
                bucket_end='2026-04-11T10:00:18',
            ),
            BurstResult(
                username='alice',
                source_host='host-a',
                src_ip='10.0.0.5',
                events_in_bucket=9,
                distinct_event_types=1,
                span_seconds=12,
                bucket_start='2026-04-11T10:01:00',
                bucket_end='2026-04-11T10:01:12',
            ),
        ]
        sequences = [
            SequenceResult(
                chain='logon -> share_access -> service_install',
                status='partial',
                steps=[{'label': 'logon', 'found': True}],
                missing_steps=['share_access'],
                evaluability='missing_telemetry',
                telemetry_gap_sources=['Security'],
            )
        ]

        producer_inputs = engine._build_deterministic_producer_inputs(
            pattern_id='psexec_execution',
            scoped_gap=[],
            bursts=bursts,
            sequences=sequences,
        )

        self.assertEqual([item['producer'] for item in producer_inputs], ['burst_engine', 'sequence_engine'])

        burst_input = producer_inputs[0]
        self.assertEqual(burst_input['producer_type'], 'temporal_burst')
        self.assertEqual(burst_input['contribution'], 6)
        self.assertEqual(burst_input['max_possible'], 10)
        self.assertEqual(burst_input['detector_metadata']['burst_count'], 2)
        self.assertEqual(burst_input['detector_metadata']['peak_events_in_bucket'], 12)
        self.assertEqual(burst_input['detector_metadata']['distinct_usernames'], ['alice'])

        sequence_input = producer_inputs[1]
        self.assertEqual(sequence_input['producer_type'], 'ordered_event_chain')
        self.assertEqual(sequence_input['status'], 'partial')
        self.assertEqual(sequence_input['contribution'], 2)
        self.assertEqual(sequence_input['max_possible'], 5)
        self.assertEqual(
            sequence_input['detector_metadata']['chain'],
            'logon -> share_access -> service_install',
        )
        self.assertEqual(
            sequence_input['detector_metadata']['missing_steps'],
            ['share_access'],
        )
        self.assertEqual(
            sequence_input['detector_metadata']['evaluability'],
            'missing_telemetry',
        )
        self.assertEqual(
            sequence_input['detector_metadata']['telemetry_gap_sources'],
            ['Security'],
        )


if __name__ == '__main__':
    unittest.main()
