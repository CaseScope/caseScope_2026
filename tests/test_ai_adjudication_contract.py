import importlib.util
import json
import os
import unittest


REPO_ROOT = os.path.dirname(os.path.dirname(__file__))


def _load_module(name: str, relative_path: str):
    module_path = os.path.join(REPO_ROOT, relative_path)
    spec = importlib.util.spec_from_file_location(name, module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


contract = _load_module(
    'ai_adjudication_contract_under_test',
    os.path.join('utils', 'ai_adjudication_contract.py'),
)


class AIAdjudicationContractTestCase(unittest.TestCase):
    def test_each_contract_object_serializes_independently(self):
        objects = [
            contract.AdjudicationContextEvidenceItem(
                evidence_id='evidence:1',
                evidence_type='anchor',
                summary='Anchor matched',
            ),
            contract.AdjudicationContextCheck(
                check_id='check:1',
                status='PASS',
                name='Check one',
                detail='Check detail',
            ),
            contract.AdjudicationContextEntity(
                entity_id='entity:host:1',
                entity_type='host',
                value='HOST-A',
            ),
            contract.AdjudicationContextFact.unknown(
                context_id='context:source_role',
                category='source_role',
            ),
            contract.ScoringPolicy(),
            contract.AIAdjudicationResult(
                confidence_adjustment=0,
                reasoning='Neutral adjudication.',
                false_positive_assessment='No mitigating context cited.',
                investigation_priority='medium',
            ),
            contract.AIAdjudicationValidationResult(is_valid=True),
        ]

        for obj in objects:
            with self.subTest(contract=obj.__class__.__name__):
                payload = json.loads(obj.to_json())
                self.assertIsInstance(payload, dict)

    def test_adjudication_context_serializes_to_json(self):
        context = contract.AdjudicationContext(
            case_id=7,
            pattern_id='pass_the_hash',
            pattern_name='Pass the Hash',
            mitre_technique='T1550.002',
            deterministic_score=82,
            max_possible_score=100,
            coverage_status='partial',
            coverage_limitations=['Sysmon missing'],
            checks=[
                contract.AdjudicationContextCheck(
                    check_id='pth_anchor',
                    status='PASS',
                    name='NTLM logon anchor',
                    detail='Event 4624 with NTLM',
                    weight=40,
                    contribution=40,
                    source='anchor_match',
                )
            ],
            evidence_items=[
                contract.AdjudicationContextEvidenceItem(
                    evidence_id='evidence:anchor:1',
                    evidence_type='anchor',
                    summary='Anchor event matched',
                    source='deterministic_engine',
                    detail={'event_id': '4624'},
                )
            ],
            entities=[
                contract.AdjudicationContextEntity(
                    entity_id='entity:user:alice',
                    entity_type='user',
                    value='alice',
                    role='interactive_user',
                    status='known',
                    facts=['User observed in event stream'],
                )
            ],
            context_facts=[
                contract.AdjudicationContextFact(
                    context_id='context:business_hours',
                    category='business_hours',
                    status='known',
                    statement='Anchor occurred outside business hours.',
                    source='case_timezone',
                    value={'local_hour': 22},
                )
            ],
        )

        payload = context.to_dict()
        encoded = context.to_json()
        decoded = json.loads(encoded)

        self.assertEqual(payload['case_id'], 7)
        self.assertEqual(decoded['pattern_id'], 'pass_the_hash')
        self.assertEqual(decoded['checks'][0]['check_id'], 'pth_anchor')
        self.assertEqual(decoded['evidence_items'][0]['evidence_id'], 'evidence:anchor:1')
        self.assertEqual(decoded['context_facts'][0]['context_id'], 'context:business_hours')
        self.assertEqual(decoded['scoring_policy']['min_adjustment'], -20.0)

    def test_required_context_fields_are_enforced(self):
        with self.assertRaises(ValueError):
            contract.AdjudicationContext(
                pattern_id='',
                pattern_name='Pass the Hash',
                deterministic_score=82,
                max_possible_score=100,
            )

        with self.assertRaises(ValueError):
            contract.AdjudicationContextCheck(
                check_id='check-1',
                status='MAYBE',
                name='Check',
                detail='Detail',
            )

        with self.assertRaises(ValueError):
            contract.AdjudicationContextFact(
                context_id='context:known_good',
                category='known_good',
                status='known',
            )

    def test_scoring_policy_matches_existing_bounds_and_serializes(self):
        policy = contract.ScoringPolicy()
        payload = json.loads(policy.to_json())

        self.assertEqual(payload['min_adjustment'], -20.0)
        self.assertEqual(payload['max_adjustment'], 10.0)
        self.assertEqual(payload['final_score_min'], 0.0)
        self.assertEqual(payload['final_score_max'], 100.0)
        self.assertEqual(payload['strong_detection_no_benign_min_score'], 85.0)
        self.assertEqual(payload['score_floor_adjustments']['80'], -2.0)
        self.assertIn('psexec_execution', payload['protected_remote_exec_patterns'])
        self.assertEqual(payload['confirmed_detection_final_score_floor'], 50.0)

    def test_ai_adjudication_result_enforces_adjustment_range_and_id_lists(self):
        result = contract.AIAdjudicationResult(
            confidence_adjustment=-4,
            reasoning='Evidence supports the detection with one limitation.',
            false_positive_assessment='No known benign workflow is cited.',
            investigation_priority='high',
            supporting_evidence_ids=['evidence:anchor:1', 'pth_anchor'],
            mitigating_evidence_ids=['context:known_good'],
            referenced_context_ids=['context:business_hours'],
            limitations=['Sysmon missing'],
            recommended_next_steps=['Review source host activity'],
        )

        payload = json.loads(result.to_json())
        self.assertEqual(payload['confidence_adjustment'], -4.0)
        self.assertEqual(
            payload['supporting_evidence_ids'],
            ['evidence:anchor:1', 'pth_anchor'],
        )
        self.assertEqual(payload['referenced_context_ids'], ['context:business_hours'])

        with self.assertRaises(ValueError):
            contract.AIAdjudicationResult(
                confidence_adjustment=11,
                reasoning='Too high.',
                false_positive_assessment='None.',
                investigation_priority='medium',
            )

        with self.assertRaises(ValueError):
            contract.AIAdjudicationResult(
                confidence_adjustment=-21,
                reasoning='Too low.',
                false_positive_assessment='None.',
                investigation_priority='medium',
            )

    def test_unknown_context_is_explicit_without_inventing_facts(self):
        unknown_known_good = contract.AdjudicationContextFact.unknown(
            context_id='context:known_good',
            category='known_good',
            source='known_good_lookup',
        )
        context = contract.AdjudicationContext(
            pattern_id='dcsync',
            pattern_name='DCSync',
            deterministic_score=70,
            max_possible_score=90,
            coverage_status='unknown',
            coverage_limitations=['Coverage unavailable'],
            context_facts=[
                unknown_known_good,
                contract.AdjudicationContextFact.unknown(
                    context_id='context:baseline:user',
                    category='baseline',
                    source='behavioral_profiles',
                ),
            ],
        )

        payload = context.to_dict()
        self.assertEqual(payload['context_facts'][0]['status'], 'unknown')
        self.assertEqual(payload['context_facts'][0]['value'], None)
        self.assertIn('Unknown', payload['context_facts'][0]['statement'])
        self.assertEqual(
            [fact['context_id'] for fact in payload['context_facts']],
            ['context:known_good', 'context:baseline:user'],
        )

    def test_validation_result_serializes_rejected_ids(self):
        validation = contract.AIAdjudicationValidationResult(
            is_valid=False,
            errors=['Unknown evidence ID'],
            warnings=['Unsupported claim removed'],
            invalid_evidence_ids=['evidence:not-real'],
            invalid_context_ids=['context:not-real'],
            unsupported_fact_claims=['The host is a domain controller'],
        )

        payload = json.loads(validation.to_json())
        self.assertFalse(payload['is_valid'])
        self.assertEqual(payload['invalid_evidence_ids'], ['evidence:not-real'])
        self.assertEqual(payload['invalid_context_ids'], ['context:not-real'])
        self.assertEqual(
            payload['unsupported_fact_claims'],
            ['The host is a domain controller'],
        )


if __name__ == '__main__':
    unittest.main()

