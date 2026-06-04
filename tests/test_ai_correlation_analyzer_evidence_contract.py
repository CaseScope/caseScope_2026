import importlib.util
import os
import sys
import types
import unittest


REPO_ROOT = os.path.dirname(os.path.dirname(__file__))
UTILS_DIR = os.path.join(REPO_ROOT, 'utils')


def _load_module(name: str, relative_path: str):
    module_path = os.path.join(REPO_ROOT, relative_path)
    spec = importlib.util.spec_from_file_location(name, module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


utils_pkg = types.ModuleType('utils')
utils_pkg.__path__ = [UTILS_DIR]
models_pkg = types.ModuleType('models')
models_pkg.__path__ = []
fake_database = types.ModuleType('models.database')
fake_database.db = types.SimpleNamespace(session=None)
fake_settings = types.ModuleType('models.system_settings')
fake_settings.get_ai_max_tokens = lambda: 2048
fake_ai_router = types.ModuleType('utils.ai.router')
fake_ai_router.invoke_json = lambda **kwargs: {'success': True, 'data': {}}
fake_ai_training = types.ModuleType('utils.ai_training')
fake_ai_training.build_role_system_prompt = lambda _role, prompt: prompt
fake_privacy_aliases = types.ModuleType('utils.privacy_aliases')
fake_privacy_aliases.AIPrivacyContext = types.SimpleNamespace(
    case_content=lambda case_id: {'case_id': case_id}
)
fake_privacy_aliases.rehydrate_for_display = lambda _case_id, payload: payload

stubbed_modules = {
    'utils': utils_pkg,
    'models': models_pkg,
    'models.database': fake_database,
    'models.system_settings': fake_settings,
    'utils.ai.router': fake_ai_router,
    'utils.ai_training': fake_ai_training,
    'utils.privacy_aliases': fake_privacy_aliases,
}
previous_modules = {name: sys.modules.get(name) for name in stubbed_modules}
sys.modules.update(stubbed_modules)
try:
    analyzer_module = _load_module(
        'evidence_contract_ai_correlation_analyzer',
        os.path.join('utils', 'ai_correlation_analyzer.py'),
    )
    contract = sys.modules['utils.ai_adjudication_contract']
    pattern_defs = _load_module(
        'evidence_contract_pattern_check_definitions',
        os.path.join('utils', 'pattern_check_definitions.py'),
    )
finally:
    for name, previous in previous_modules.items():
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous


AICorrelationAnalyzer = analyzer_module.AICorrelationAnalyzer
AIAdjudicationResult = contract.AIAdjudicationResult
AdjudicationContext = contract.AdjudicationContext
AdjudicationContextCheck = contract.AdjudicationContextCheck
AdjudicationContextEvidenceItem = contract.AdjudicationContextEvidenceItem
AdjudicationContextFact = contract.AdjudicationContextFact
CheckResult = pattern_defs.CheckResult
CoverageAssessment = pattern_defs.CoverageAssessment
EvidencePackage = pattern_defs.EvidencePackage


class AICorrelationAnalyzerEvidenceContractTestCase(unittest.TestCase):
    def _package(
        self,
        *,
        pattern_id='pass_the_hash',
        deterministic_score=75,
        checks=None,
    ):
        if checks is None:
            checks = [
                CheckResult(
                    check_id='anchor',
                    status='PASS',
                    weight=40,
                    contribution=40,
                    detail='username=alice, source_host=DC01',
                    source='anchor_match',
                    name='Anchor check',
                ),
                CheckResult(
                    check_id='mitigating',
                    status='FAIL',
                    weight=20,
                    contribution=0,
                    detail='No benign workflow confirmed',
                    source='field_match',
                    name='Mitigating check',
                ),
            ]
        return EvidencePackage(
            anchor={
                'event_id': '4624',
                'source_host': 'DC01',
                'username': 'alice',
                'src_ip': '10.0.0.5',
            },
            pattern_id=pattern_id,
            pattern_name='Pattern Name',
            correlation_key='DC01|alice',
            checks=checks,
            coverage=CoverageAssessment(
                host='DC01',
                coverage_status='partial',
                present_sources=['Security'],
                missing_sources=['Sysmon'],
            ),
            deterministic_score=deterministic_score,
            max_possible_score=100,
            mitre_techniques=['T0000'],
        )

    def _analyzer(self, payload=None, raises=None):
        analyzer = object.__new__(AICorrelationAnalyzer)
        analyzer.case_id = 7
        analyzer.analysis_id = 'analysis-7'
        analyzer.model = 'test-model'
        analyzer._stats = {'ai_calls': 0, 'total_duration_ms': 0}
        analyzer.captured_prompt = None
        analyzer.captured_system = None

        def fake_invoke_json(**kwargs):
            analyzer.captured_prompt = kwargs.get('prompt')
            analyzer.captured_system = kwargs.get('system')
            if raises:
                raise raises
            return {
                'success': True,
                'data': payload or {
                    'confidence_adjustment': 0,
                    'reasoning': 'No adjustment.',
                    'false_positive_assessment': 'No validated benign context.',
                    'investigation_priority': 'Unchanged',
                    'supporting_evidence_ids': [],
                    'mitigating_evidence_ids': [],
                    'referenced_context_ids': [],
                    'limitations': [],
                    'recommended_next_steps': [],
                },
                'usage': {'prompt_tokens': 10, 'completion_tokens': 5, 'total_tokens': 15},
                'model': 'test-model',
            }

        analyzer._invoke_json = fake_invoke_json
        analyzer._rehydrate_ai_result = lambda payload: payload
        return analyzer

    def test_prompt_includes_context_json_ids_and_rules(self):
        analyzer = self._analyzer()

        result = analyzer.analyze_with_evidence(self._package(), {'name': 'Pattern Name'})

        self.assertEqual(result['adjustment'], 0)
        self.assertIn('ADJUDICATION_CONTEXT_JSON', analyzer.captured_prompt)
        self.assertIn('"pattern_id": "pass_the_hash"', analyzer.captured_prompt)
        self.assertIn('VALID_EVIDENCE_IDS', analyzer.captured_prompt)
        self.assertIn('evidence:anchor', analyzer.captured_prompt)
        self.assertIn('check:anchor', analyzer.captured_prompt)
        self.assertIn('VALID_CONTEXT_IDS', analyzer.captured_prompt)
        self.assertIn('Do not cite evidence IDs that are not in valid_evidence_ids', analyzer.captured_prompt)
        self.assertIn('Observed entities such as hostnames', analyzer.captured_prompt)
        self.assertIn('AI reasoning is not evidence', analyzer.captured_prompt)

    def test_valid_positive_payload_returns_nonzero_adjustment(self):
        analyzer = self._analyzer({
            'confidence_adjustment': 5,
            'reasoning': 'Anchor evidence supports a stronger finding.',
            'false_positive_assessment': 'No mitigating context cited.',
            'investigation_priority': 'High',
            'supporting_evidence_ids': ['evidence:anchor'],
            'mitigating_evidence_ids': [],
            'referenced_context_ids': [],
            'limitations': [],
            'recommended_next_steps': ['Review related logons'],
        })

        result = analyzer.analyze_with_evidence(self._package(), {'name': 'Pattern Name'})

        self.assertEqual(result['adjustment'], 5)
        self.assertTrue(result['adjudication_validation']['is_valid'])

    def test_valid_negative_payload_returns_negative_adjustment(self):
        analyzer = self._analyzer({
            'confidence_adjustment': -4,
            'reasoning': 'Mitigating check reduces confidence.',
            'false_positive_assessment': 'Mitigating deterministic check is relevant.',
            'investigation_priority': 'Medium',
            'supporting_evidence_ids': [],
            'mitigating_evidence_ids': ['check:mitigating'],
            'referenced_context_ids': [],
            'limitations': [],
            'recommended_next_steps': [],
        })

        result = analyzer.analyze_with_evidence(self._package(), {'name': 'Pattern Name'})

        self.assertEqual(result['adjustment'], -4)
        self.assertTrue(result['adjudication_validation']['is_valid'])

    def test_unknown_evidence_id_returns_adjustment_zero(self):
        analyzer = self._analyzer({
            'confidence_adjustment': 4,
            'reasoning': 'Unknown evidence supports this.',
            'false_positive_assessment': 'None.',
            'investigation_priority': 'High',
            'supporting_evidence_ids': ['evidence:not-real'],
        })

        result = analyzer.analyze_with_evidence(self._package(), {'name': 'Pattern Name'})

        self.assertEqual(result['adjustment'], 0)
        self.assertFalse(result['adjudication_validation']['is_valid'])
        self.assertEqual(
            result['adjudication_validation']['invalid_evidence_ids'],
            ['evidence:not-real'],
        )

    def test_unknown_context_id_returns_adjustment_zero(self):
        analyzer = self._analyzer({
            'confidence_adjustment': -4,
            'reasoning': 'Unknown context mitigates.',
            'false_positive_assessment': 'None.',
            'investigation_priority': 'Medium',
            'mitigating_evidence_ids': ['check:mitigating'],
            'referenced_context_ids': ['context:not-real'],
        })

        result = analyzer.analyze_with_evidence(self._package(), {'name': 'Pattern Name'})

        self.assertEqual(result['adjustment'], 0)
        self.assertFalse(result['adjudication_validation']['is_valid'])
        self.assertEqual(
            result['adjudication_validation']['invalid_context_ids'],
            ['context:not-real'],
        )

    def test_nonzero_without_citations_returns_adjustment_zero(self):
        analyzer = self._analyzer({
            'confidence_adjustment': 3,
            'reasoning': 'Looks suspicious.',
            'false_positive_assessment': 'None.',
            'investigation_priority': 'High',
        })

        result = analyzer.analyze_with_evidence(self._package(), {'name': 'Pattern Name'})

        self.assertEqual(result['adjustment'], 0)
        self.assertFalse(result['adjudication_validation']['is_valid'])

    def test_old_schema_nonzero_returns_adjustment_zero(self):
        analyzer = self._analyzer({
            'confidence_adjustment': 3,
            'reasoning': 'Old schema with no citations.',
            'false_positive_assessment': 'None.',
            'investigation_priority': 'High',
        })

        result = analyzer.analyze_with_evidence(self._package(), {'name': 'Pattern Name'})

        self.assertEqual(result['adjustment'], 0)

    def test_old_schema_zero_can_pass_without_score_change(self):
        analyzer = self._analyzer({
            'confidence_adjustment': 0,
            'reasoning': 'Old schema neutral.',
            'false_positive_assessment': 'No validated assessment.',
            'investigation_priority': 'Unchanged',
        })

        result = analyzer.analyze_with_evidence(self._package(), {'name': 'Pattern Name'})

        self.assertEqual(result['adjustment'], 0)
        self.assertTrue(result['adjudication_validation']['is_valid'])

    def test_unsupported_known_good_claim_without_context_returns_zero(self):
        analyzer = self._analyzer({
            'confidence_adjustment': -4,
            'reasoning': 'This is known-good activity.',
            'false_positive_assessment': 'Known-good source.',
            'investigation_priority': 'Low',
            'mitigating_evidence_ids': ['check:mitigating'],
        })

        result = analyzer.analyze_with_evidence(self._package(), {'name': 'Pattern Name'})

        self.assertEqual(result['adjustment'], 0)
        self.assertIn('known-good', result['adjudication_validation']['unsupported_fact_claims'])

    def test_unsupported_domain_controller_claim_from_observed_entity_returns_zero(self):
        analyzer = self._analyzer({
            'confidence_adjustment': -4,
            'reasoning': 'DC01 is a domain controller so this is expected.',
            'false_positive_assessment': 'Expected DC behavior.',
            'investigation_priority': 'Low',
            'mitigating_evidence_ids': ['check:mitigating'],
        })

        result = analyzer.analyze_with_evidence(self._package(), {'name': 'Pattern Name'})

        self.assertEqual(result['adjustment'], 0)
        self.assertIn('domain controller', result['adjudication_validation']['unsupported_fact_claims'])

    def test_known_good_claim_with_referenced_known_context_fact_can_pass(self):
        context = AdjudicationContext(
            pattern_id='pass_the_hash',
            pattern_name='Pattern Name',
            deterministic_score=75,
            max_possible_score=100,
            checks=[
                AdjudicationContextCheck(
                    check_id='check:mitigating',
                    status='FAIL',
                    name='Mitigating',
                    detail='Detail',
                )
            ],
            evidence_items=[
                AdjudicationContextEvidenceItem(
                    evidence_id='evidence:anchor',
                    evidence_type='anchor',
                    summary='Anchor',
                )
            ],
            context_facts=[
                AdjudicationContextFact(
                    context_id='context:known_good',
                    category='known_good',
                    status='known',
                    statement='Approved admin workflow.',
                )
            ],
        )
        analyzer = self._analyzer({
            'confidence_adjustment': -4,
            'reasoning': 'This is known-good activity.',
            'false_positive_assessment': 'Known-good source.',
            'investigation_priority': 'Low',
            'mitigating_evidence_ids': ['check:mitigating'],
            'referenced_context_ids': ['context:known_good'],
        })
        analyzer._build_adjudication_context = lambda _package: context

        result = analyzer.analyze_with_evidence(self._package(), {'name': 'Pattern Name'})

        self.assertEqual(result['adjustment'], -4)
        self.assertTrue(result['adjudication_validation']['is_valid'])

    def test_context_construction_failure_falls_back_to_deterministic_only(self):
        analyzer = self._analyzer()

        def fail_context(_package):
            raise RuntimeError('context boom')

        analyzer._build_adjudication_context = fail_context

        result = analyzer.analyze_with_evidence(self._package(), {'name': 'Pattern Name'})

        self.assertEqual(result['adjustment'], 0)
        self.assertIn('context construction failed', result['reasoning'])

    def test_llm_call_failure_falls_back_to_deterministic_only(self):
        analyzer = self._analyzer(raises=RuntimeError('llm boom'))

        result = analyzer.analyze_with_evidence(self._package(), {'name': 'Pattern Name'})

        self.assertEqual(result['adjustment'], 0)
        self.assertIn('AI analysis failed', result['reasoning'])

    def test_existing_low_score_more_fail_than_pass_clamp_still_works(self):
        checks = [
            CheckResult(
                check_id='anchor',
                status='PASS',
                weight=20,
                contribution=20,
                detail='anchor',
                source='anchor',
                name='Anchor',
            ),
            CheckResult(
                check_id='fail_one',
                status='FAIL',
                weight=20,
                contribution=0,
                detail='fail',
                source='query',
                name='Fail one',
            ),
            CheckResult(
                check_id='fail_two',
                status='FAIL',
                weight=20,
                contribution=0,
                detail='fail',
                source='query',
                name='Fail two',
            ),
        ]
        analyzer = self._analyzer({
            'confidence_adjustment': 5,
            'reasoning': 'Anchor supports a small boost.',
            'false_positive_assessment': 'None.',
            'investigation_priority': 'Medium',
            'supporting_evidence_ids': ['evidence:anchor'],
        })

        result = analyzer.analyze_with_evidence(
            self._package(deterministic_score=40, checks=checks),
            {'name': 'Pattern Name'},
        )

        self.assertEqual(result['adjustment'], 0)
        self.assertTrue(result['adjudication_validation']['is_valid'])

    def test_existing_remote_execution_negative_bound_still_works(self):
        analyzer = self._analyzer({
            'confidence_adjustment': -10,
            'reasoning': 'Mitigating check reduces confidence.',
            'false_positive_assessment': 'Mitigating evidence cited.',
            'investigation_priority': 'Medium',
            'mitigating_evidence_ids': ['check:mitigating'],
        })

        result = analyzer.analyze_with_evidence(
            self._package(pattern_id='psexec_execution', deterministic_score=60),
            {'name': 'PsExec Execution'},
        )

        self.assertEqual(result['adjustment'], -4)
        self.assertTrue(result['adjudication_validation']['is_valid'])

    def test_returned_dict_remains_backward_compatible(self):
        analyzer = self._analyzer()

        result = analyzer.analyze_with_evidence(self._package(), {'name': 'Pattern Name'})

        for key in [
            'adjustment',
            'reasoning',
            'false_positive_assessment',
            'investigation_priority',
            'model_used',
            'duration_ms',
        ]:
            self.assertIn(key, result)
        self.assertIn('adjudication_validation', result)
        self.assertIn('adjudication_context_summary', result)


if __name__ == '__main__':
    unittest.main()

