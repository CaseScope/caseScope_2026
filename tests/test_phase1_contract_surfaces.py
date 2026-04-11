import importlib.util
import os
import unittest
from pathlib import Path
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
        self.assertIn('from pipeline.pattern_analysis import create_candidate_extractor, create_evidence_engine', source)
        self.assertIn('extractor = create_candidate_extractor(self.case_id, self.analysis_id)', source)
        self.assertIn('evidence_engine = create_evidence_engine(', source)

    def test_hayabusa_exports_canonical_finding_method(self):
        source = Path('/opt/casescope/utils/hayabusa_correlator.py').read_text()
        self.assertIn('def to_finding(self) -> Dict[str, Any]:', source)
        self.assertIn("rule_pack='hayabusa'", source)


if __name__ == '__main__':
    unittest.main()
