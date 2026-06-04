import importlib.util
import os
import sys
import types
import unittest


REPO_ROOT = os.path.dirname(os.path.dirname(__file__))


def _load_module(name: str, relative_path: str):
    module_path = os.path.join(REPO_ROOT, relative_path)
    spec = importlib.util.spec_from_file_location(name, module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


contract = _load_module(
    'validator_ai_adjudication_contract',
    os.path.join('utils', 'ai_adjudication_contract.py'),
)
pattern_defs = _load_module(
    'validator_pattern_check_definitions',
    os.path.join('utils', 'pattern_check_definitions.py'),
)

fake_utils = types.ModuleType('utils')
fake_utils.__path__ = []
previous_utils = sys.modules.get('utils')
previous_contract = sys.modules.get('utils.ai_adjudication_contract')
sys.modules['utils'] = fake_utils
sys.modules['utils.ai_adjudication_contract'] = contract
try:
    validator = _load_module(
        'validator_ai_adjudication_validator',
        os.path.join('utils', 'ai_adjudication_validator.py'),
    )
    builder = _load_module(
        'validator_ai_adjudication_context_builder',
        os.path.join('utils', 'ai_adjudication_context_builder.py'),
    )
finally:
    if previous_utils is None:
        sys.modules.pop('utils', None)
    else:
        sys.modules['utils'] = previous_utils
    if previous_contract is None:
        sys.modules.pop('utils.ai_adjudication_contract', None)
    else:
        sys.modules['utils.ai_adjudication_contract'] = previous_contract


AIAdjudicationResult = contract.AIAdjudicationResult
AdjudicationContext = contract.AdjudicationContext
AdjudicationContextCheck = contract.AdjudicationContextCheck
AdjudicationContextEntity = contract.AdjudicationContextEntity
AdjudicationContextEvidenceItem = contract.AdjudicationContextEvidenceItem
AdjudicationContextFact = contract.AdjudicationContextFact
AIAdjudicationValidator = validator.AIAdjudicationValidator
AdjudicationContextBuilder = builder.AdjudicationContextBuilder
CheckResult = pattern_defs.CheckResult
EvidencePackage = pattern_defs.EvidencePackage


class AIAdjudicationValidatorTestCase(unittest.TestCase):
    def _context(self, facts=None, entities=None):
        return AdjudicationContext(
            pattern_id='pass_the_hash',
            pattern_name='Pass the Hash',
            deterministic_score=75,
            max_possible_score=100,
            checks=[
                AdjudicationContextCheck(
                    check_id='check:anchor',
                    status='PASS',
                    name='Anchor',
                    detail='Event 4624 matched',
                ),
                AdjudicationContextCheck(
                    check_id='check:mitigating',
                    status='FAIL',
                    name='Mitigating check',
                    detail='Benign explanation not verified',
                ),
            ],
            evidence_items=[
                AdjudicationContextEvidenceItem(
                    evidence_id='evidence:anchor',
                    evidence_type='anchor',
                    summary='Anchor evidence',
                ),
            ],
            entities=entities or [
                AdjudicationContextEntity(
                    entity_id='entity:host:dc01',
                    entity_type='host',
                    value='DC01',
                )
            ],
            context_facts=facts or [
                AdjudicationContextFact.unknown('context:known_good', 'known_good'),
                AdjudicationContextFact.unknown('context:noise', 'noise'),
                AdjudicationContextFact.unknown('context:source_host_role', 'source_host_role'),
                AdjudicationContextFact.unknown('context:business_hours', 'business_hours'),
            ],
        )

    def _result(
        self,
        adjustment=0,
        supporting=None,
        mitigating=None,
        context_ids=None,
        reasoning='Evidence cited.',
        false_positive='No false-positive context cited.',
    ):
        return AIAdjudicationResult(
            confidence_adjustment=adjustment,
            reasoning=reasoning,
            false_positive_assessment=false_positive,
            investigation_priority='medium',
            supporting_evidence_ids=supporting or [],
            mitigating_evidence_ids=mitigating or [],
            referenced_context_ids=context_ids or [],
        )

    def test_valid_positive_result_with_known_supporting_evidence_passes(self):
        validation = AIAdjudicationValidator(self._context()).validate(
            self._result(adjustment=5, supporting=['evidence:anchor'])
        )

        self.assertTrue(validation.is_valid)
        self.assertEqual(validation.invalid_evidence_ids, [])

    def test_valid_negative_result_with_known_mitigating_evidence_and_context_passes(self):
        context = self._context(facts=[
            AdjudicationContextFact(
                context_id='context:known_good',
                category='known_good',
                status='known',
                statement='Approved admin workflow is documented.',
            )
        ])
        validation = AIAdjudicationValidator(context).validate(
            self._result(
                adjustment=-4,
                mitigating=['check:mitigating'],
                context_ids=['context:known_good'],
            )
        )

        self.assertTrue(validation.is_valid)

    def test_unknown_supporting_evidence_id_invalidates_result(self):
        validation = AIAdjudicationValidator(self._context()).validate(
            self._result(adjustment=4, supporting=['evidence:not-real'])
        )

        self.assertFalse(validation.is_valid)
        self.assertEqual(validation.invalid_evidence_ids, ['evidence:not-real'])

    def test_example_evidence_id_invalidates_with_diagnostic_warning(self):
        validation = AIAdjudicationValidator(self._context()).validate(
            self._result(adjustment=4, supporting=['example:check:remote_access_anchor'])
        )

        self.assertFalse(validation.is_valid)
        self.assertEqual(validation.invalid_evidence_ids, ['example:check:remote_access_anchor'])
        self.assertIn(
            validator.UNKNOWN_EVIDENCE_ID_WARNING,
            validation.warnings,
        )

    def test_check_name_instead_of_id_invalidates_with_diagnostic_warning(self):
        validation = AIAdjudicationValidator(self._context()).validate(
            self._result(adjustment=4, supporting=['Anchor'])
        )

        self.assertFalse(validation.is_valid)
        self.assertEqual(validation.invalid_evidence_ids, ['Anchor'])
        self.assertIn(
            validator.UNKNOWN_EVIDENCE_ID_WARNING,
            validation.warnings,
        )

    def test_context_id_in_supporting_evidence_invalidates_with_placement_warning(self):
        validation = AIAdjudicationValidator(self._context()).validate(
            self._result(adjustment=4, supporting=['context:noise'])
        )

        self.assertFalse(validation.is_valid)
        self.assertEqual(validation.invalid_evidence_ids, ['context:noise'])
        self.assertIn(
            validator.MISPLACED_CONTEXT_ID_WARNING,
            validation.warnings,
        )

    def test_context_id_in_mitigating_evidence_invalidates_with_placement_warning(self):
        validation = AIAdjudicationValidator(self._context()).validate(
            self._result(adjustment=-4, mitigating=['context:noise'])
        )

        self.assertFalse(validation.is_valid)
        self.assertEqual(validation.invalid_evidence_ids, ['context:noise'])
        self.assertIn(
            validator.MISPLACED_CONTEXT_ID_WARNING,
            validation.warnings,
        )

    def test_evidence_id_in_context_field_invalidates_with_placement_warning(self):
        validation = AIAdjudicationValidator(self._context()).validate(
            self._result(adjustment=-4, context_ids=['check:mitigating'])
        )

        self.assertFalse(validation.is_valid)
        self.assertEqual(validation.invalid_context_ids, ['check:mitigating'])
        self.assertIn(
            validator.MISPLACED_EVIDENCE_ID_WARNING,
            validation.warnings,
        )

    def test_unknown_mitigating_evidence_id_invalidates_result(self):
        validation = AIAdjudicationValidator(self._context()).validate(
            self._result(adjustment=-4, mitigating=['evidence:not-real'])
        )

        self.assertFalse(validation.is_valid)
        self.assertEqual(validation.invalid_evidence_ids, ['evidence:not-real'])

    def test_unknown_referenced_context_id_invalidates_result(self):
        validation = AIAdjudicationValidator(self._context()).validate(
            self._result(adjustment=-4, context_ids=['context:not-real'])
        )

        self.assertFalse(validation.is_valid)
        self.assertEqual(validation.invalid_context_ids, ['context:not-real'])

    def test_positive_adjustment_without_supporting_citation_invalidates_result(self):
        validation = AIAdjudicationValidator(self._context()).validate(
            self._result(adjustment=3)
        )

        self.assertFalse(validation.is_valid)
        self.assertIn('Positive confidence adjustment requires', validation.errors[0])

    def test_negative_adjustment_without_mitigating_or_context_citation_invalidates_result(self):
        validation = AIAdjudicationValidator(self._context()).validate(
            self._result(adjustment=-3)
        )

        self.assertFalse(validation.is_valid)
        self.assertIn('Negative confidence adjustment requires', validation.errors[0])

    def test_zero_adjustment_without_citations_passes(self):
        validation = AIAdjudicationValidator(self._context()).validate(
            self._result(adjustment=0)
        )

        self.assertTrue(validation.is_valid)

    def test_malformed_payload_falls_back_to_neutral_result(self):
        result, validation = AIAdjudicationValidator(self._context()).safe_result({
            'confidence_adjustment': 1,
            'reasoning': 'Missing required fields.',
        })

        self.assertFalse(validation.is_valid)
        self.assertEqual(result.confidence_adjustment, 0)
        self.assertEqual(result.reasoning, validator.NEUTRAL_REASONING)
        self.assertEqual(result.supporting_evidence_ids, [])
        self.assertTrue(result.limitations)

    def test_out_of_range_adjustment_falls_back_to_neutral_result(self):
        result, validation = AIAdjudicationValidator(self._context()).safe_result({
            'confidence_adjustment': 11,
            'reasoning': 'Too much boost.',
            'false_positive_assessment': 'None.',
            'investigation_priority': 'high',
        })

        self.assertFalse(validation.is_valid)
        self.assertEqual(result.confidence_adjustment, 0)

    def test_unsupported_known_good_claim_without_context_invalidates_result(self):
        validation = AIAdjudicationValidator(self._context()).validate(
            self._result(
                adjustment=-2,
                mitigating=['check:mitigating'],
                reasoning='This appears to be known-good administrative activity.',
            )
        )

        self.assertFalse(validation.is_valid)
        self.assertIn('known-good', validation.unsupported_fact_claims)

    def test_known_good_absence_wording_does_not_create_unsupported_claim(self):
        validation = AIAdjudicationValidator(self._context()).validate(
            self._result(
                adjustment=4,
                supporting=['evidence:anchor'],
                reasoning='No known-good context was provided, so there is no valid benign explanation.',
                false_positive='No verified admin workflow context is cited.',
            )
        )

        self.assertTrue(validation.is_valid)
        self.assertEqual(validation.unsupported_fact_claims, [])

    def test_unknown_context_reference_on_positive_adjustment_adds_warning(self):
        validation = AIAdjudicationValidator(self._context()).validate(
            self._result(
                adjustment=3,
                supporting=['evidence:anchor'],
                context_ids=['context:known_good'],
                reasoning='Evidence supports a modest increase.',
                false_positive='No validated context changes the deterministic assessment.',
            )
        )

        self.assertTrue(validation.is_valid)
        self.assertIn(
            validator.UNKNOWN_CONTEXT_LIMITATION_WARNING,
            validation.warnings,
        )

    def test_negative_adjustment_cannot_rely_only_on_unknown_context(self):
        validation = AIAdjudicationValidator(self._context()).validate(
            self._result(
                adjustment=-3,
                context_ids=['context:known_good'],
                reasoning='Relevant environment context is unknown.',
                false_positive='No validated context changes the deterministic assessment.',
            )
        )

        self.assertFalse(validation.is_valid)
        self.assertTrue(
            any('referenced known context fact' in error for error in validation.errors)
        )

    def test_unsupported_domain_controller_claim_without_host_role_invalidates_result(self):
        validation = AIAdjudicationValidator(self._context()).validate(
            self._result(
                adjustment=-2,
                mitigating=['check:mitigating'],
                reasoning='This is expected because DC01 is a domain controller.',
            )
        )

        self.assertFalse(validation.is_valid)
        self.assertIn('domain controller', validation.unsupported_fact_claims)

    def test_observed_entity_named_dc01_does_not_satisfy_domain_controller_context(self):
        context = self._context(entities=[
            AdjudicationContextEntity(
                entity_id='entity:host:dc01',
                entity_type='host',
                value='DC01',
                role='unknown',
                status='unknown',
            )
        ])
        validation = AIAdjudicationValidator(context).validate(
            self._result(
                adjustment=-2,
                mitigating=['check:mitigating'],
                reasoning='DC01 is a domain controller, so this is expected.',
            )
        )

        self.assertFalse(validation.is_valid)
        self.assertIn('domain controller', validation.unsupported_fact_claims)

    def test_domain_controller_claim_passes_with_known_host_role_context_reference(self):
        context = self._context(facts=[
            AdjudicationContextFact(
                context_id='context:source_host_role',
                category='source_host_role',
                status='known',
                statement='DC01 is a domain controller.',
            )
        ])
        validation = AIAdjudicationValidator(context).validate(
            self._result(
                adjustment=-2,
                mitigating=['check:mitigating'],
                context_ids=['context:source_host_role'],
                reasoning='DC01 is a domain controller, so this is lower risk.',
            )
        )

        self.assertTrue(validation.is_valid)

    def test_known_good_claim_passes_with_known_known_good_context_reference(self):
        context = self._context(facts=[
            AdjudicationContextFact(
                context_id='context:known_good',
                category='known_good',
                status='known',
                statement='This source process is allowlisted.',
            )
        ])
        validation = AIAdjudicationValidator(context).validate(
            self._result(
                adjustment=-2,
                mitigating=['check:mitigating'],
                context_ids=['context:known_good'],
                reasoning='The activity is known-good and allowlisted.',
            )
        )

        self.assertTrue(validation.is_valid)

    def test_noise_claim_passes_with_known_noise_context_reference(self):
        context = self._context(facts=[
            AdjudicationContextFact(
                context_id='context:noise',
                category='noise',
                status='known',
                statement=(
                    'Event matched explicit noise/known-good rule(s); '
                    'this may indicate a benign explanation but is not proof the activity is benign.'
                ),
                value={'noise_rules': ['Expected VPN logon']},
            )
        ])
        validation = AIAdjudicationValidator(context).validate(
            self._result(
                adjustment=-2,
                context_ids=['context:noise'],
                reasoning='The anchor is known-good because it matched a noise rule.',
            )
        )

        self.assertTrue(validation.is_valid)

    def test_noise_claim_with_unknown_noise_context_is_rejected(self):
        context = self._context(facts=[
            AdjudicationContextFact.unknown('context:noise', 'noise'),
        ])
        validation = AIAdjudicationValidator(context).validate(
            self._result(
                adjustment=-2,
                context_ids=['context:noise'],
                reasoning='The anchor is known-good because it matched a noise rule.',
            )
        )

        self.assertFalse(validation.is_valid)
        self.assertIn('known-good', validation.unsupported_fact_claims)
        self.assertIn('noise', validation.unsupported_fact_claims)

    def test_noise_claim_without_noise_context_is_rejected(self):
        validation = AIAdjudicationValidator(self._context(facts=[
            AdjudicationContextFact.unknown('context:known_good', 'known_good'),
        ])).validate(
            self._result(
                adjustment=-2,
                mitigating=['check:mitigating'],
                reasoning='The anchor is known-good because it matched a noise rule.',
            )
        )

        self.assertFalse(validation.is_valid)
        self.assertIn('known-good', validation.unsupported_fact_claims)
        self.assertIn('noise', validation.unsupported_fact_claims)

    def test_regex_extracted_entities_remain_unknown_without_explicit_metadata(self):
        package = EvidencePackage(
            anchor={'event_id': '4624'},
            pattern_id='demo',
            pattern_name='Demo',
            correlation_key='demo',
            checks=[
                CheckResult(
                    check_id='demo_check',
                    status='PASS',
                    weight=1,
                    contribution=1,
                    detail='source_host=DC01, username=alice',
                    source='field_match',
                    name='Demo check',
                )
            ],
        )

        context = AdjudicationContextBuilder(package).build()
        dc01 = next(entity for entity in context.entities if entity.value == 'DC01')
        alice = next(entity for entity in context.entities if entity.value == 'alice')

        self.assertEqual(dc01.role, 'unknown')
        self.assertEqual(dc01.status, 'unknown')
        self.assertEqual(alice.role, 'unknown')
        self.assertEqual(alice.status, 'unknown')

    def test_safe_result_never_returns_nonzero_adjustment_when_validation_invalid(self):
        result, validation = AIAdjudicationValidator(self._context()).safe_result(
            self._result(adjustment=5)
        )

        self.assertFalse(validation.is_valid)
        self.assertEqual(result.confidence_adjustment, 0)


if __name__ == '__main__':
    unittest.main()

