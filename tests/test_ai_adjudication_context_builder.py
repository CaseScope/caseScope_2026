import importlib.util
import json
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
    'builder_ai_adjudication_contract',
    os.path.join('utils', 'ai_adjudication_contract.py'),
)
pattern_defs = _load_module(
    'builder_pattern_check_definitions',
    os.path.join('utils', 'pattern_check_definitions.py'),
)

fake_utils = types.ModuleType('utils')
fake_utils.__path__ = []
previous_utils = sys.modules.get('utils')
previous_contract = sys.modules.get('utils.ai_adjudication_contract')
sys.modules['utils'] = fake_utils
sys.modules['utils.ai_adjudication_contract'] = contract
try:
    builder = _load_module(
        'builder_ai_adjudication_context_builder',
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

AdjudicationContext = contract.AdjudicationContext
AdjudicationContextFact = contract.AdjudicationContextFact
AdjudicationContextBuilder = builder.AdjudicationContextBuilder
BurstResult = pattern_defs.BurstResult
CheckResult = pattern_defs.CheckResult
CoverageAssessment = pattern_defs.CoverageAssessment
EvidencePackage = pattern_defs.EvidencePackage
SequenceResult = pattern_defs.SequenceResult
SpreadAssessment = pattern_defs.SpreadAssessment


class AdjudicationContextBuilderTestCase(unittest.TestCase):
    def _package(self, coverage=True):
        return EvidencePackage(
            anchor={
                'event_id': '4624',
                'source_host': 'DC01',
                'target_host': 'HOST-B',
                'username': 'administrator',
                'src_ip': '10.0.0.5',
                'dst_ip': '10.0.0.9',
                'process_name': 'sekurlsa.exe',
                'file_path': r'C:\Temp\artifact.bin',
            },
            pattern_id='pass_the_hash',
            pattern_name='Pass the Hash',
            correlation_key='DC01|administrator',
            checks=[
                CheckResult(
                    check_id='pth_anchor',
                    status='PASS',
                    weight=40,
                    contribution=40,
                    detail='username=administrator, source_host=DC01, src_ip=10.0.0.5',
                    source='anchor_match',
                    name='NTLM logon anchor',
                ),
                CheckResult(
                    check_id='pth_not_machine',
                    status='FAIL',
                    weight=20,
                    contribution=0,
                    detail='username=HOST-A$ (machine/system account)',
                    source='field_match',
                    name='Account is not a machine account',
                ),
                CheckResult(
                    check_id='pth_missing_sysmon',
                    status='INCONCLUSIVE',
                    weight=15,
                    contribution=4.5,
                    detail='Missing critical source: Sysmon',
                    source='coverage',
                    name='Sysmon corroboration',
                ),
            ],
            coverage=CoverageAssessment(
                host='DC01',
                coverage_status='partial',
                present_sources=['Security'],
                missing_sources=['Sysmon'],
                sysmon_fp_warning='Sysmon data not available.',
                coverage_score=40,
            ) if coverage else None,
            bursts=[
                BurstResult(
                    username='administrator',
                    source_host='DC01',
                    src_ip='10.0.0.5',
                    events_in_bucket=8,
                    distinct_event_types=2,
                    span_seconds=25,
                    bucket_start='2026-06-04T20:00:00',
                    bucket_end='2026-06-04T20:00:25',
                )
            ],
            sequences=[
                SequenceResult(
                    chain='logon -> share_access',
                    status='partial',
                    steps=[{'label': 'logon', 'found': True}],
                    missing_steps=['share_access'],
                )
            ],
            producer_inputs=[
                {
                    'producer': 'gap_detector',
                    'producer_type': 'PASSWORD_SPRAYING',
                    'mapped_checks': [{'check_id': 'spray_distinct_users'}],
                }
            ],
            spread=SpreadAssessment(
                pivot_field='src_ip',
                pivot_value='10.0.0.5',
                total_targets=3,
                total_users=2,
                span_minutes=5,
            ),
            deterministic_score=82,
            max_possible_score=100,
            mitre_techniques=['T1550.002'],
        )

    def test_builder_returns_context_and_preserves_core_scores(self):
        context = AdjudicationContextBuilder(
            self._package(),
            case_id=7,
        ).build()

        self.assertIsInstance(context, AdjudicationContext)
        self.assertEqual(context.case_id, 7)
        self.assertEqual(context.pattern_id, 'pass_the_hash')
        self.assertEqual(context.pattern_name, 'Pass the Hash')
        self.assertEqual(context.mitre_technique, 'T1550.002')
        self.assertEqual(context.deterministic_score, 82.0)
        self.assertEqual(context.max_possible_score, 100.0)

    def test_all_checks_are_included_with_stable_ids(self):
        context = AdjudicationContextBuilder(self._package()).build()

        self.assertEqual(
            [check.status for check in context.checks],
            ['PASS', 'FAIL', 'INCONCLUSIVE'],
        )
        self.assertEqual(
            [check.check_id for check in context.checks],
            ['check:pth_anchor', 'check:pth_not_machine', 'check:pth_missing_sysmon'],
        )

    def test_anchor_bursts_sequences_spread_and_producers_are_evidence_items(self):
        context = AdjudicationContextBuilder(self._package()).build()
        evidence_ids = [item.evidence_id for item in context.evidence_items]

        self.assertIn('evidence:anchor', evidence_ids)
        self.assertIn('evidence:burst:0', evidence_ids)
        self.assertIn('evidence:sequence:0', evidence_ids)
        self.assertIn('evidence:spread', evidence_ids)
        self.assertIn('evidence:producer:gap_detector:0', evidence_ids)

    def test_coverage_status_and_missing_sources_are_represented(self):
        context = AdjudicationContextBuilder(self._package()).build()
        facts = {fact.context_id: fact for fact in context.context_facts}

        self.assertEqual(context.coverage_status, 'partial')
        self.assertIn('Missing source: Sysmon', context.coverage_limitations)
        self.assertIn('Sysmon data not available.', context.coverage_limitations)
        self.assertEqual(facts['context:coverage:sysmon'].status, 'known')
        self.assertEqual(facts['context:coverage:sysmon'].value['source'], 'Sysmon')
        self.assertEqual(facts['context:coverage:present_sources'].status, 'known')

    def test_missing_coverage_creates_explicit_unknown_context(self):
        context = AdjudicationContextBuilder(self._package(coverage=False)).build()
        facts = {fact.context_id: fact for fact in context.context_facts}

        self.assertEqual(context.coverage_status, 'unknown')
        self.assertIn('Coverage unavailable', context.coverage_limitations)
        self.assertEqual(facts['context:coverage'].status, 'unknown')
        self.assertEqual(facts['context:coverage'].category, 'coverage')

    def test_unavailable_context_categories_are_unknown_without_invented_facts(self):
        context = AdjudicationContextBuilder(self._package()).build()
        facts = {fact.context_id: fact for fact in context.context_facts}

        for context_id in [
            'context:known_good',
            'context:source_host_role',
            'context:user_role',
            'context:business_hours',
            'context:baseline',
            'context:asset_criticality',
            'context:threat_intel',
        ]:
            self.assertIn(context_id, facts)
            self.assertEqual(facts[context_id].status, 'unknown')
            self.assertIsNone(facts[context_id].value)

        source_host = next(entity for entity in context.entities if entity.value == 'DC01')
        user = next(entity for entity in context.entities if entity.value == 'administrator')
        self.assertEqual(source_host.role, 'unknown')
        self.assertEqual(source_host.status, 'unknown')
        self.assertEqual(user.role, 'unknown')
        self.assertEqual(user.status, 'unknown')

    def test_explicit_metadata_context_is_used_without_inference(self):
        context = AdjudicationContextBuilder(
            self._package(),
            context_metadata={
                'known_good': {
                    'statement': 'Source process matched approved admin tooling.',
                    'source': 'known_good_lookup',
                    'value': {'matched': True},
                },
                'threat_intel': AdjudicationContextFact(
                    context_id='context:threat_intel',
                    category='threat_intel',
                    status='known',
                    statement='Technique is present in threat-intel context.',
                    source='opencti',
                    value={'technique': 'T1550.002'},
                ),
            },
        ).build()
        facts = {fact.context_id: fact for fact in context.context_facts}

        self.assertEqual(facts['context:known_good'].status, 'known')
        self.assertEqual(facts['context:known_good'].source, 'known_good_lookup')
        self.assertEqual(facts['context:threat_intel'].status, 'known')
        self.assertEqual(facts['context:user_role'].status, 'unknown')

    def test_entities_are_extracted_from_anchor_and_check_details(self):
        context = AdjudicationContextBuilder(self._package()).build()
        values = {entity.value for entity in context.entities}

        self.assertIn('administrator', values)
        self.assertIn('HOST-A$', values)
        self.assertIn('DC01', values)
        self.assertIn('HOST-B', values)
        self.assertIn('10.0.0.5', values)
        self.assertIn('10.0.0.9', values)
        self.assertIn('sekurlsa.exe', values)
        self.assertIn(r'C:\Temp\artifact.bin', values)

    def test_output_serializes_to_json(self):
        context = AdjudicationContextBuilder(self._package()).build()
        payload = json.loads(context.to_json())

        self.assertEqual(payload['pattern_id'], 'pass_the_hash')
        self.assertEqual(payload['evidence_items'][0]['evidence_id'], 'evidence:anchor')

    def test_evidence_package_final_score_behavior_is_unchanged(self):
        package = self._package()
        package.ai_judgment = {
            'adjustment': -20,
            'reasoning': 'Weak corroboration.',
            'false_positive_assessment': 'No benign context.',
        }
        before = package.final_score()

        AdjudicationContextBuilder(package).build()

        self.assertEqual(package.final_score(), before)
        self.assertEqual(package.final_score(), 80)


if __name__ == '__main__':
    unittest.main()

