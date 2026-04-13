import importlib.util
import os
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault('SECRET_KEY', 'test-secret')


REPO_ROOT = os.path.dirname(os.path.dirname(__file__))


def _load_module(name: str, relative_path: str):
    module_path = os.path.join(REPO_ROOT, relative_path)
    spec = importlib.util.spec_from_file_location(name, module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


finding_contract = _load_module(
    'phase1_finding_contract',
    os.path.join('utils', 'finding_contract.py'),
)
feature_availability = _load_module(
    'phase1_feature_availability',
    os.path.join('utils', 'feature_availability.py'),
)


class Phase1ContractSurfacesTestCase(unittest.TestCase):
    def test_build_finding_exposes_locked_contract_fields(self):
        finding = finding_contract.build_finding(
            rule_pack='pattern_rule',
            rule_id='password_spraying',
            name='Password Spraying',
            confidence=88,
            mitre_techniques=['T1110.003'],
            host='HOST-A',
            user='alice',
            process='winlogon.exe',
            first_seen='2026-04-11T10:00:00',
            last_seen='2026-04-11T10:05:00',
            detector_metadata={'event_count': 3},
        )

        for field in finding_contract.LOCKED_FINDING_FIELDS:
            self.assertIn(field, finding)
        self.assertEqual(finding['rule_pack'], 'pattern_rule')
        self.assertEqual(finding['rule_id'], 'password_spraying')
        self.assertEqual(finding['mitre_techniques'], ['T1110.003'])
        self.assertTrue(finding['dedup_key'])

    def test_canonicalize_finding_maps_legacy_shape(self):
        canonical = finding_contract.canonicalize_finding(
            {
                'source_system': 'ai_correlation',
                'pattern_id': 'pass_the_hash',
                'pattern_name': 'Pass the Hash',
                'final_confidence': 92,
                'source_host': 'HOST-B',
                'username': 'bob',
                'mitre_techniques': ['attack.t1550.002'],
                'first_seen': '2026-04-11T09:00:00',
                'events': [{'record_id': 'evt-1'}, {'record_id': 'evt-2'}],
            }
        )

        self.assertEqual(canonical['rule_pack'], 'ai_correlation')
        self.assertEqual(canonical['rule_id'], 'pass_the_hash')
        self.assertEqual(canonical['name'], 'Pass the Hash')
        self.assertEqual(canonical['host'], 'HOST-B')
        self.assertEqual(canonical['user'], 'bob')
        self.assertEqual(canonical['event_ids'], ['evt-1', 'evt-2'])
        self.assertEqual(canonical['mitre_techniques'], ['T1550.002'])

    def test_canonicalize_finding_reads_nested_evidence_package_context(self):
        canonical = finding_contract.canonicalize_finding(
            {
                'source_system': 'ai_correlation',
                'pattern_id': 'password_spraying',
                'pattern_name': 'Password Spraying',
                'final_confidence': 88,
                'evidence_package': {
                    'anchor': {
                        'source_host': 'HOST-C',
                        'username': 'charlie',
                        'process_name': 'winlogon.exe',
                        'record_id': 'evt-9',
                    },
                    'mitre_techniques': ['T1110.003'],
                    'producer_inputs': [
                        {'producer': 'gap_detector'},
                        {'producer': 'burst_engine'},
                    ],
                    'scoring_context': {
                        'deterministic_score': 86,
                    },
                },
            }
        )

        self.assertEqual(canonical['host'], 'HOST-C')
        self.assertEqual(canonical['user'], 'charlie')
        self.assertEqual(canonical['process'], 'winlogon.exe')
        self.assertEqual(canonical['event_ids'], ['evt-9'])
        self.assertEqual(canonical['mitre_techniques'], ['T1110.003'])
        self.assertTrue(canonical['detector_metadata']['evidence_package_present'])
        self.assertEqual(
            canonical['detector_metadata']['producer_types'],
            ['burst_engine', 'gap_detector'],
        )
        self.assertEqual(canonical['detector_metadata']['deterministic_score'], 86)

    def test_build_deterministic_analysis_finding_projects_canonical_fields(self):
        finding = finding_contract.build_deterministic_analysis_finding(
            source_system='ai_correlation',
            pattern_id='pass_the_hash',
            pattern_name='Pass the Hash',
            correlation_key='HOST-A|alice',
            confidence=91,
            summary='Pattern match: Pass the Hash (HOST-A|alice)',
            evidence_package={
                'anchor': {
                    'source_host': 'HOST-A',
                    'username': 'alice',
                    'process_name': 'sekurlsa.exe',
                    'record_id': 'evt-42',
                },
                'mitre_techniques': ['T1550.002'],
                'producer_inputs': [
                    {'producer': 'gap_detector'},
                    {'producer': 'sequence_engine'},
                ],
            },
            deterministic_score=89,
            coverage_quality=0.75,
            ai_adjustment=2,
            ai_escalated=False,
            ai_reasoning='Strong credential theft indicators.',
        )

        self.assertEqual(finding['rule_pack'], 'ai_correlation')
        self.assertEqual(finding['rule_id'], 'pass_the_hash')
        self.assertEqual(finding['host'], 'HOST-A')
        self.assertEqual(finding['user'], 'alice')
        self.assertEqual(finding['process'], 'sekurlsa.exe')
        self.assertEqual(finding['event_ids'], ['evt-42'])
        self.assertEqual(finding['entity_type'], 'system')
        self.assertEqual(finding['entity_value'], 'HOST-A')
        self.assertEqual(
            finding['detector_metadata']['producer_types'],
            ['gap_detector', 'sequence_engine'],
        )

    def test_build_ai_analysis_result_payload_projects_shared_record_fields(self):
        payload = finding_contract.build_ai_analysis_result_payload(
            case_id=7,
            analysis_id='analysis-1',
            pattern_id='pass_the_hash',
            pattern_name='Pass the Hash',
            correlation_key='HOST-A|alice',
            rule_based_confidence=82,
            ai_confidence=91,
            ai_reasoning='Strong credential theft indicators.',
            ai_false_positive_assessment='Unlikely benign.',
            final_confidence=91,
            deterministic_score=89,
            ai_adjustment=2,
            coverage_quality=0.75,
            evidence_package={'anchor': {'source_host': 'HOST-A'}},
            events_analyzed=4,
            model_used='deterministic',
            window_start='2026-04-11T09:00:00',
            window_end='2026-04-11T09:10:00',
        )

        self.assertEqual(payload['case_id'], 7)
        self.assertEqual(payload['analysis_id'], 'analysis-1')
        self.assertEqual(payload['pattern_id'], 'pass_the_hash')
        self.assertEqual(payload['correlation_key'], 'HOST-A|alice')
        self.assertEqual(payload['rule_based_confidence'], 82)
        self.assertEqual(payload['final_confidence'], 91)
        self.assertEqual(payload['deterministic_score'], 89)
        self.assertEqual(payload['evidence_package']['anchor']['source_host'], 'HOST-A')
        self.assertEqual(payload['events_analyzed'], 4)
        self.assertEqual(payload['model_used'], 'deterministic')

    def test_build_deterministic_analysis_artifacts_returns_paired_payloads(self):
        artifacts = finding_contract.build_deterministic_analysis_artifacts(
            case_id=7,
            analysis_id='analysis-1',
            source_system='ai_correlation',
            pattern_id='pass_the_hash',
            pattern_name='Pass the Hash',
            correlation_key='HOST-A|alice',
            confidence=91,
            summary='Pattern match: Pass the Hash (HOST-A|alice)',
            evidence_package={
                'anchor': {
                    'source_host': 'HOST-A',
                    'username': 'alice',
                    'process_name': 'sekurlsa.exe',
                    'record_id': 'evt-42',
                },
                'mitre_techniques': ['T1550.002'],
                'producer_inputs': [
                    {'producer': 'gap_detector'},
                    {'producer': 'sequence_engine'},
                ],
            },
            severity='critical',
            events_analyzed=4,
            deterministic_score=89,
            coverage_quality=0.75,
            ai_adjustment=2,
            ai_escalated=False,
            ai_reasoning='Strong credential theft indicators.',
            ai_false_positive_assessment='Unlikely benign.',
            mitre_techniques=['T1550.002'],
            extra_finding_fields={'intel_overlay': {'matched': True}},
            rule_based_confidence=82,
            model_used='deterministic',
            window_start='2026-04-11T09:00:00',
            window_end='2026-04-11T09:10:00',
        )

        payload = artifacts['analysis_result_payload']
        finding = artifacts['finding']

        self.assertEqual(payload['pattern_id'], 'pass_the_hash')
        self.assertEqual(payload['rule_based_confidence'], 82)
        self.assertEqual(payload['final_confidence'], 91)
        self.assertEqual(finding['rule_pack'], 'ai_correlation')
        self.assertEqual(finding['host'], 'HOST-A')
        self.assertEqual(finding['user'], 'alice')
        self.assertEqual(finding['intel_overlay'], {'matched': True})
        self.assertEqual(
            finding['detector_metadata']['producer_types'],
            ['gap_detector', 'sequence_engine'],
        )

    def test_finalize_deterministic_package_runs_full_analysis(self):
        package = SimpleNamespace(
            deterministic_score=45,
            ai_judgment=None,
            ai_escalated=False,
        )
        package.final_score = lambda: 91
        package.bounded_ai_adjustment = lambda: 3
        package.to_dict = lambda: {'anchor': {'source_host': 'HOST-A'}}

        finalized = finding_contract.finalize_deterministic_package(
            package,
            ai_full_threshold=40,
            ai_gray_threshold=20,
            run_full_analysis=lambda: {
                'reasoning': 'Strong evidence chain.',
                'false_positive_assessment': 'Unlikely benign.',
            },
        )

        self.assertEqual(package.ai_judgment['reasoning'], 'Strong evidence chain.')
        self.assertEqual(finalized['final_score'], 91)
        self.assertEqual(finalized['ai_adjustment'], 3)
        self.assertEqual(finalized['ai_reasoning'], 'Strong evidence chain.')
        self.assertEqual(finalized['ai_false_positive_assessment'], 'Unlikely benign.')
        self.assertTrue(finalized['ai_analyzed'])
        self.assertTrue(finalized['should_emit_finding'])

    def test_finalize_deterministic_package_handles_lightweight_escalation(self):
        package = SimpleNamespace(
            deterministic_score=25,
            ai_judgment=None,
            ai_escalated=False,
        )
        package.final_score = lambda: 48
        package.bounded_ai_adjustment = lambda: 0
        package.to_dict = lambda: {'anchor': {'source_host': 'HOST-B'}}

        finalized = finding_contract.finalize_deterministic_package(
            package,
            ai_full_threshold=40,
            ai_gray_threshold=20,
            run_light_analysis=lambda: {
                'escalate': True,
                'reasoning': 'Borderline evidence needs escalation.',
            },
        )

        self.assertTrue(package.ai_escalated)
        self.assertEqual(package.ai_judgment['reasoning'], 'Borderline evidence needs escalation.')
        self.assertFalse(finalized['ai_analyzed'])
        self.assertFalse(finalized['should_emit_finding'])

    def test_build_hayabusa_correlation_finding_projects_canonical_fields(self):
        finding = finding_contract.build_hayabusa_correlation_finding(
            correlation_key='alice|host-a',
            rule_titles=['Suspicious Lateral Movement'],
            combined_severity='high',
            chain_score=87,
            mitre_techniques=['T1021.001'],
            events=[{'record_id': 'evt-1'}, {'record_id': 'evt-2'}],
            source_hosts=['HOST-A'],
            usernames=['alice'],
            processes=['wsmprovhost.exe'],
            source_ips=['10.0.0.5'],
            remote_hosts=['HOST-B'],
            time_start='2026-04-11T09:00:00',
            time_end='2026-04-11T09:10:00',
            mitre_tactics=['lateral-movement'],
            kill_chain_phases=['execution'],
            rule_levels=['high', 'med'],
            rule_files=['rules/lateral.yml'],
            attack_chain_description='Suspicious remote execution chain',
            behavioral_context={'rare': True},
            anomaly_flags={'new_host': True},
        )

        self.assertEqual(finding['rule_pack'], 'hayabusa')
        self.assertEqual(finding['name'], 'Suspicious Lateral Movement')
        self.assertEqual(finding['host'], 'HOST-A')
        self.assertEqual(finding['user'], 'alice')
        self.assertEqual(finding['process'], 'wsmprovhost.exe')
        self.assertEqual(finding['event_ids'], ['evt-1', 'evt-2'])
        self.assertEqual(finding['detector_metadata']['producer'], 'hayabusa_correlator')
        self.assertEqual(finding['detector_metadata']['producer_type'], 'hayabusa_chain')
        self.assertEqual(finding['detector_metadata']['rule_level'], 'high')
        self.assertEqual(finding['detector_metadata']['rule_file'], 'rules/lateral.yml')
        self.assertEqual(
            finding['detector_metadata']['tactic_progression'],
            ['lateral-movement'],
        )
        self.assertTrue(finding['detector_metadata']['chain_id'])
        self.assertEqual(
            finding['detector_metadata']['entities']['remote_hosts'],
            ['HOST-B'],
        )

    def test_build_pattern_rule_finding_projects_canonical_fields(self):
        finding = finding_contract.build_pattern_rule_finding(
            pattern_id='password_spraying',
            pattern_name='Password Spraying',
            confidence=88,
            severity='high',
            mitre_techniques=['T1110.003'],
            source_host='HOST-A',
            username='alice',
            first_seen='2026-04-11T09:00:00',
            last_seen='2026-04-11T09:10:00',
            confidence_factors={'volume': 0.9},
            indicators=['multi-user failures'],
        )

        self.assertEqual(finding['rule_pack'], 'pattern_rule')
        self.assertEqual(finding['host'], 'HOST-A')
        self.assertEqual(finding['user'], 'alice')
        self.assertEqual(finding['detector_metadata']['producer'], 'pattern_rule')
        self.assertEqual(finding['detector_metadata']['producer_type'], 'rule_based_detection')
        self.assertEqual(finding['detector_metadata']['confidence_factors'], {'volume': 0.9})

    def test_build_rag_pattern_finding_projects_canonical_fields(self):
        finding = finding_contract.build_rag_pattern_finding(
            pattern_id='77',
            pattern_name='Rare Admin Tooling',
            confidence=74,
            severity='medium',
            mitre_techniques=['T1587'],
            source_host='HOST-B',
            first_seen='2026-04-11T09:00:00',
            last_seen='2026-04-11T09:15:00',
            raw_score=0.74,
            confidence_weight=0.6,
        )

        self.assertEqual(finding['rule_pack'], 'rag_pattern')
        self.assertEqual(finding['rule_id'], '77')
        self.assertEqual(finding['host'], 'HOST-B')
        self.assertEqual(finding['detector_metadata']['producer'], 'rag_pattern')
        self.assertEqual(finding['detector_metadata']['producer_type'], 'pattern_discovery')
        self.assertEqual(finding['detector_metadata']['raw_score'], 0.74)

    def test_feature_snapshot_is_frozen_and_serializable(self):
        with patch.object(
            feature_availability.FeatureAvailability,
            'get_activation_status',
            return_value={'status': 'activated'},
        ):
            with patch.object(
                feature_availability.FeatureAvailability,
                'get_analysis_mode',
                return_value='D',
            ):
                with patch.object(
                    feature_availability.FeatureAvailability,
                    'get_available_capabilities',
                    return_value={'ai_reasoning': True, 'threat_intel_enrichment': True},
                ):
                    with patch.object(
                        feature_availability.FeatureAvailability,
                        'is_opencti_enabled',
                        return_value=True,
                    ):
                        with patch.object(
                            feature_availability.FeatureAvailability,
                            'is_misp_enabled',
                            return_value=False,
                        ):
                            snapshot = feature_availability.FeatureAvailability.get_feature_snapshot()

        self.assertEqual(snapshot.mode, 'D')
        self.assertTrue(snapshot.ai_enabled)
        self.assertTrue(snapshot.opencti_enabled)
        self.assertFalse(snapshot.misp_enabled)
        self.assertTrue(snapshot.threat_intel_enabled)
        self.assertEqual(snapshot.to_dict()['activation_status'], 'activated')

    def test_case_analyzer_uses_snapshot_and_pipeline_wrappers(self):
        source = Path('/opt/casescope/utils/case_analyzer.py').read_text()
        self.assertIn('FeatureAvailability.get_feature_snapshot()', source)
        self.assertIn('from pipeline.pattern_analysis import (', source)
        self.assertIn('evaluate_ai_pattern,', source)
        self.assertIn('evaluate_rule_based_pattern,', source)
        self.assertIn('persist_ai_pattern_results,', source)
        self.assertIn('extractor = create_candidate_extractor(self.case_id, self.analysis_id)', source)
        self.assertIn('evidence_engine = create_evidence_engine(', source)
        self.assertIn('prep = prepare_pattern_analysis(self.case_id)', source)
        self.assertIn('processed = evaluate_ai_pattern(', source)
        self.assertIn('pattern_results = evaluate_rule_based_pattern(', source)
        self.assertIn('pattern_confirmed = persist_ai_pattern_results(', source)
        self.assertIn('from utils.pattern_suppression import (', source)
        self.assertIn('build_confirmed_pattern_entry(', source)

    def test_hayabusa_exports_canonical_finding_method(self):
        source = Path('/opt/casescope/utils/hayabusa_correlator.py').read_text()
        self.assertIn('def to_finding(self) -> Dict[str, Any]:', source)
        self.assertIn('build_hayabusa_correlation_finding(', source)
        self.assertIn('return [group.to_dict() for group in groups]', source)

    def test_rag_tasks_use_deterministic_finding_projection(self):
        source = Path('/opt/casescope/tasks/rag_tasks.py').read_text()
        self.assertIn('from pipeline.pattern_analysis import (', source)
        self.assertIn('evaluate_ai_pattern,', source)
        self.assertIn('persist_ai_pattern_results,', source)
        self.assertIn('processed = evaluate_ai_pattern(', source)
        self.assertIn('pattern_confirmed = persist_ai_pattern_results(', source)
        self.assertIn('from utils.pattern_suppression import (', source)
        self.assertIn('PATTERN_SUPPRESSION_PRIORITY.get(item[0], 999)', source)


if __name__ == '__main__':
    unittest.main()
