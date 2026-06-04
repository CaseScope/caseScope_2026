import unittest

from tests import test_ai_correlation_analyzer_evidence_contract as base


AICorrelationAnalyzer = base.AICorrelationAnalyzer
AIAdjudicationResult = base.AIAdjudicationResult
AdjudicationContext = base.AdjudicationContext
AdjudicationContextCheck = base.AdjudicationContextCheck
AdjudicationContextEvidenceItem = base.AdjudicationContextEvidenceItem
AdjudicationContextFact = base.AdjudicationContextFact
AdjudicationContextBuilder = base.analyzer_module.AdjudicationContextBuilder
AIAdjudicationValidator = base.analyzer_module.AIAdjudicationValidator
CheckResult = base.CheckResult
CoverageAssessment = base.CoverageAssessment
EvidencePackage = base.EvidencePackage


class AIAdjudicationRegressionCasesTestCase(unittest.TestCase):
    def _check(self, check_id, status, name, detail, weight=20, contribution=None, source='field_match'):
        return CheckResult(
            check_id=check_id,
            status=status,
            weight=weight,
            contribution=float(weight if contribution is None and status == 'PASS' else (contribution or 0)),
            detail=detail,
            source=source,
            name=name,
        )

    def _coverage(self, status='partial', missing=None, present=None, warning=''):
        return CoverageAssessment(
            host='HOST-A',
            coverage_status=status,
            present_sources=present or ['Security'],
            missing_sources=missing or ['Sysmon'],
            sysmon_fp_warning=warning,
            coverage_score=40 if status == 'partial' else 85,
        )

    def _package(
        self,
        *,
        pattern_id,
        pattern_name,
        score,
        anchor,
        checks,
        coverage=None,
        mitre='T0000',
    ):
        return EvidencePackage(
            anchor=anchor,
            pattern_id=pattern_id,
            pattern_name=pattern_name,
            correlation_key=f"{anchor.get('source_host', 'HOST-A')}|{anchor.get('username', 'user')}",
            checks=checks,
            coverage=coverage if coverage is not None else self._coverage(),
            deterministic_score=score,
            max_possible_score=100,
            mitre_techniques=[mitre],
        )

    def rdp_lateral_package(self):
        return self._package(
            pattern_id='rdp_lateral',
            pattern_name='RDP Lateral Movement',
            score=58,
            mitre='T1021.001',
            anchor={
                'event_id': '4624',
                'source_host': 'WS-01',
                'target_host': 'SERVER-01',
                'username': 'alice',
                'src_ip': '10.0.0.10',
                'process_name': 'mstsc.exe',
            },
            checks=[
                self._check('rdp_logon_anchor', 'PASS', 'RDP logon anchor', 'logon_type=10, username=alice', 35),
                self._check('rdp_unusual_source', 'PASS', 'Unusual source host', 'source_host=WS-01, target_host=SERVER-01', 25),
                self._check('rdp_no_known_admin', 'FAIL', 'Known admin workflow not verified', 'No known admin workflow confirmed', 20, 0),
                self._check('rdp_missing_sysmon', 'INCONCLUSIVE', 'Endpoint telemetry missing', 'Missing critical source: Sysmon', 20, 6, 'coverage'),
            ],
        )

    def machine_account_package(self):
        return self._package(
            pattern_id='pass_the_ticket',
            pattern_name='Pass the Ticket',
            score=52,
            mitre='T1550.003',
            anchor={
                'event_id': '4624',
                'source_host': 'HOST-A',
                'target_host': 'DC01',
                'username': 'HOST-A$',
                'src_ip': '10.0.0.20',
            },
            checks=[
                self._check('ptt_logon_anchor', 'PASS', 'Kerberos logon anchor', 'username=HOST-A$', 30),
                self._check('ptt_machine_account', 'PASS', 'Account is a machine account', 'username=HOST-A$ (machine/system account)', 0, 0),
                self._check('ptt_sensitive_service', 'FAIL', 'Sensitive service not observed', 'No sensitive service indicators', 25, 0),
                self._check('ptt_missing_4769', 'INCONCLUSIVE', 'Ticket request telemetry missing', 'Missing critical source: Security', 20, 6, 'coverage'),
            ],
        )

    def dc_replication_package(self):
        return self._package(
            pattern_id='dcsync',
            pattern_name='DCSync',
            score=62,
            mitre='T1003.006',
            anchor={
                'event_id': '4662',
                'source_host': 'DC01',
                'target_host': 'DC02',
                'username': 'DC01$',
                'src_ip': '10.0.0.1',
            },
            checks=[
                self._check('dcsync_replication_guid', 'PASS', 'Replication GUID observed', 'replication GUID access', 35),
                self._check('dcsync_machine_account', 'PASS', 'Machine account observed', 'username=DC01$ (machine/system account)', 0, 0),
                self._check('dcsync_user_account', 'FAIL', 'Not a user account', 'username=DC01$ (machine/system account)', 25, 0),
                self._check('dcsync_logon_missing', 'INCONCLUSIVE', 'Prior logon missing', 'Missing critical source: Security', 20, 6, 'coverage'),
            ],
        )

    def user_dcsync_package(self):
        return self._package(
            pattern_id='dcsync',
            pattern_name='DCSync',
            score=86,
            mitre='T1003.006',
            anchor={
                'event_id': '4662',
                'source_host': 'DC01',
                'target_host': 'DC02',
                'username': 'alice',
                'src_ip': '10.0.0.1',
            },
            checks=[
                self._check('dcsync_replication_guid', 'PASS', 'Replication GUID observed', 'replication GUID access', 35),
                self._check('dcsync_user_account', 'PASS', 'Not a DC computer account', 'username=alice (user account)', 25),
                self._check('dcsync_no_machine_context', 'PASS', 'Privileged operation by user account', 'user account performed replication', 25),
                self._check('dcsync_no_benign_context', 'FAIL', 'Benign replication context not verified', 'No deterministic benign replication context', 10, 0),
                self._check('dcsync_tooling_missing', 'INCONCLUSIVE', 'Tooling not visible', 'Missing critical source: Sysmon', 15, 4.5, 'coverage'),
            ],
        )

    def rdp_tooling_package(self):
        return self._package(
            pattern_id='rdp_lateral',
            pattern_name='RDP Followed By Tooling',
            score=72,
            mitre='T1021.001',
            anchor={
                'event_id': '4624',
                'source_host': 'WS-09',
                'target_host': 'SERVER-09',
                'username': 'bob',
                'src_ip': '10.0.0.90',
                'process_name': 'mstsc.exe',
                'file_path': r'C:\Temp\adfind.exe',
            },
            checks=[
                self._check('rdp_logon_anchor', 'PASS', 'RDP logon anchor', 'logon_type=10, username=bob', 30),
                self._check('rdp_tooling_process', 'PASS', 'Suspicious tooling after RDP', 'process_name=adfind.exe, file_path=C:\\Temp\\adfind.exe', 35),
                self._check('rdp_no_known_good', 'FAIL', 'Known-good not verified', 'No known-good source confirmed', 15, 0),
                self._check('rdp_missing_edr', 'INCONCLUSIVE', 'EDR telemetry missing', 'Missing critical source: EDR', 20, 6, 'coverage'),
            ],
        )

    def rmm_package(self):
        return self._package(
            pattern_id='remote_admin_tool',
            pattern_name='Remote Admin Tool',
            score=55,
            mitre='T1219',
            anchor={
                'event_id': '1',
                'source_host': 'RMM01',
                'target_host': 'HOST-22',
                'username': 'tech',
                'process_name': 'screenconnect.client.exe',
            },
            checks=[
                self._check('rmm_process_anchor', 'PASS', 'Remote tool process observed', 'process_name=screenconnect.client.exe', 35),
                self._check('rmm_known_good_missing', 'FAIL', 'Known-good context missing', 'No allowlist context in deterministic evidence', 25, 0),
                self._check('rmm_missing_network', 'INCONCLUSIVE', 'Network telemetry missing', 'Missing critical source: Network', 15, 4.5, 'coverage'),
            ],
        )

    def strong_sparse_remote_exec_package(self):
        return self._package(
            pattern_id='psexec_execution',
            pattern_name='PsExec Execution',
            score=78,
            mitre='T1021.002',
            anchor={
                'event_id': '7045',
                'source_host': 'ADMIN-01',
                'target_host': 'SERVER-77',
                'username': 'admin',
                'process_name': 'psexesvc.exe',
            },
            checks=[
                self._check('psexec_service_anchor', 'PASS', 'Service install anchor', 'process_name=psexesvc.exe', 45),
                self._check('psexec_admin_share', 'PASS', 'Admin share access', 'target_host=SERVER-77', 25),
                self._check('psexec_no_known_good', 'FAIL', 'Known-good not verified', 'No known-good context', 10, 0),
                self._check('psexec_missing_sysmon', 'INCONCLUSIVE', 'Sysmon missing', 'Missing critical source: Sysmon', 20, 6, 'coverage'),
            ],
        )

    def missing_coverage_package(self):
        package = self.rdp_lateral_package()
        package.coverage = None
        package.deterministic_score = 50
        return package

    def _analyzer(self, payload):
        analyzer = object.__new__(AICorrelationAnalyzer)
        analyzer.case_id = 7
        analyzer.analysis_id = 'analysis-regression'
        analyzer.model = 'test-model'
        analyzer._stats = {'ai_calls': 0, 'total_duration_ms': 0}

        def fake_invoke_json(**kwargs):
            analyzer.prompt = kwargs.get('prompt')
            return {
                'success': True,
                'data': payload,
                'usage': {},
                'model': 'test-model',
            }

        analyzer._invoke_json = fake_invoke_json
        analyzer._rehydrate_ai_result = lambda payload: payload
        return analyzer

    def _run_ai(self, package, payload, context=None):
        before_score = package.deterministic_score
        before_final = package.final_score()
        analyzer = self._analyzer(payload)
        if context is not None:
            analyzer._build_adjudication_context = lambda _package: context
        result = analyzer.analyze_with_evidence(package, {'name': package.pattern_name})
        self._assert_common_result_contract(result)
        self.assertEqual(package.deterministic_score, before_score)
        self.assertEqual(package.final_score(), before_final)
        return result

    def _assert_common_result_contract(self, result):
        for key in [
            'adjustment',
            'reasoning',
            'false_positive_assessment',
            'investigation_priority',
            'model_used',
            'duration_ms',
            'adjudication_validation',
            'adjudication_context_summary',
        ]:
            self.assertIn(key, result)

    def _context(self, package, metadata=None):
        return AdjudicationContextBuilder(
            package,
            case_id=7,
            context_metadata=metadata or {},
        ).build()

    def _validator(self, package, metadata=None):
        return AIAdjudicationValidator(self._context(package, metadata))

    def _result(self, adjustment, support=None, mitigate=None, context=None, reasoning='Evidence cited.', fp='No FP context.'):
        return AIAdjudicationResult(
            confidence_adjustment=adjustment,
            reasoning=reasoning,
            false_positive_assessment=fp,
            investigation_priority='Medium',
            supporting_evidence_ids=support or [],
            mitigating_evidence_ids=mitigate or [],
            referenced_context_ids=context or [],
        )

    def assert_context_basics(self, package, metadata=None):
        context = self._context(package, metadata)
        statuses = {check.status for check in context.checks}
        self.assertIn('PASS', statuses)
        self.assertIn('FAIL', statuses)
        self.assertIn('INCONCLUSIVE', statuses)
        self.assertTrue(all(check.check_id.startswith('check:') for check in context.checks))
        self.assertIn('evidence:anchor', context.evidence_ids())
        for entity in context.entities:
            if not metadata or not metadata.get('entities'):
                self.assertEqual(entity.role, 'unknown')
                self.assertEqual(entity.status, 'unknown')
        for context_id in [
            'context:known_good',
            'context:source_host_role',
            'context:user_role',
            'context:business_hours',
            'context:baseline',
            'context:asset_criticality',
            'context:threat_intel',
        ]:
            self.assertIn(context_id, context.context_ids())
        return context

    def test_rdp_lateral_medium_score_calibration(self):
        package = self.rdp_lateral_package()
        self.assert_context_basics(package)
        valid = self._run_ai(package, {
            'confidence_adjustment': 4,
            'reasoning': 'RDP anchor and unusual source support a small increase.',
            'false_positive_assessment': 'No validated benign context is cited.',
            'investigation_priority': 'High',
            'supporting_evidence_ids': ['check:rdp_logon_anchor', 'check:rdp_unusual_source'],
        })
        self.assertEqual(valid['adjustment'], 4)

        known_good = self._run_ai(package, {
            'confidence_adjustment': -4,
            'reasoning': 'This is known-good expected admin workflow.',
            'false_positive_assessment': 'Known-good source.',
            'investigation_priority': 'Low',
            'mitigating_evidence_ids': ['check:rdp_no_known_admin'],
        })
        self.assertEqual(known_good['adjustment'], 0)

        old_schema = self._run_ai(package, {
            'confidence_adjustment': 5,
            'reasoning': 'Old schema boost.',
            'false_positive_assessment': 'None.',
            'investigation_priority': 'High',
        })
        self.assertEqual(old_schema['adjustment'], 0)

    def test_machine_account_benign_activity_calibration(self):
        package = self.machine_account_package()
        self.assert_context_basics(package)

        no_citation = self._run_ai(package, {
            'confidence_adjustment': -20,
            'reasoning': 'Machine account expected behavior.',
            'false_positive_assessment': 'Likely benign.',
            'investigation_priority': 'Low',
        })
        self.assertEqual(no_citation['adjustment'], 0)

        cited = self._run_ai(package, {
            'confidence_adjustment': -20,
            'reasoning': 'Machine account check supports benign interpretation.',
            'false_positive_assessment': 'Machine account activity cited.',
            'investigation_priority': 'Low',
            'mitigating_evidence_ids': ['check:ptt_machine_account'],
        })
        self.assertEqual(cited['adjustment'], -20)

        safe, validation = self._validator(package).safe_result(
            self._result(-20, mitigate=['check:ptt_machine_account'], reasoning='Machine account evidence cited.')
        )
        self.assertTrue(validation.is_valid)
        self.assertEqual(safe.confidence_adjustment, -20)

    def test_dc_to_dc_replication_requires_known_role_context(self):
        package = self.dc_replication_package()
        self.assert_context_basics(package)

        observed_only = self._run_ai(package, {
            'confidence_adjustment': -10,
            'reasoning': 'DC01 is a domain controller and replication is expected.',
            'false_positive_assessment': 'Domain controller activity.',
            'investigation_priority': 'Low',
            'mitigating_evidence_ids': ['check:dcsync_machine_account'],
        })
        self.assertEqual(observed_only['adjustment'], 0)

        metadata = {
            'source_host_role': {
                'statement': 'DC01 is a domain controller.',
                'source': 'asset_inventory',
                'value': {'role': 'domain_controller'},
            }
        }
        context = self.assert_context_basics(package, metadata)
        referenced = self._run_ai(package, {
            'confidence_adjustment': -10,
            'reasoning': 'Referenced context says DC01 is a domain controller.',
            'false_positive_assessment': 'Expected replication context is cited.',
            'investigation_priority': 'Low',
            'mitigating_evidence_ids': ['check:dcsync_machine_account'],
            'referenced_context_ids': ['context:source_host_role'],
        }, context=context)
        self.assertEqual(referenced['adjustment'], -10)

    def test_user_account_dcsync_like_behavior_protects_against_unsupported_benign_dc_claim(self):
        package = self.user_dcsync_package()
        self.assert_context_basics(package)

        positive = self._run_ai(package, {
            'confidence_adjustment': 5,
            'reasoning': 'User account replication evidence supports high confidence.',
            'false_positive_assessment': 'No benign context cited.',
            'investigation_priority': 'Critical',
            'supporting_evidence_ids': ['check:dcsync_replication_guid', 'check:dcsync_user_account'],
        })
        self.assertEqual(positive['adjustment'], 5)

        neutral = self._run_ai(package, {
            'confidence_adjustment': 0,
            'reasoning': 'Keep deterministic score.',
            'false_positive_assessment': 'No validated benign context.',
            'investigation_priority': 'Critical',
            'supporting_evidence_ids': ['check:dcsync_user_account'],
        })
        self.assertEqual(neutral['adjustment'], 0)

        benign_dc = self._run_ai(package, {
            'confidence_adjustment': -10,
            'reasoning': 'Source resembles a domain controller so this is benign.',
            'false_positive_assessment': 'Expected DC behavior.',
            'investigation_priority': 'Low',
            'mitigating_evidence_ids': ['check:dcsync_tooling_missing'],
        })
        self.assertEqual(benign_dc['adjustment'], 0)

    def test_rdp_followed_by_suspicious_tooling_allows_positive_with_tooling_citations(self):
        package = self.rdp_tooling_package()
        self.assert_context_basics(package)

        result = self._run_ai(package, {
            'confidence_adjustment': 5,
            'reasoning': 'RDP and tooling evidence support increased confidence.',
            'false_positive_assessment': 'No validated benign context cited.',
            'investigation_priority': 'High',
            'supporting_evidence_ids': ['check:rdp_logon_anchor', 'check:rdp_tooling_process', 'evidence:anchor'],
        })
        self.assertEqual(result['adjustment'], 5)
        self.assertGreaterEqual(result['adjustment'], -20)
        self.assertLessEqual(result['adjustment'], 10)

    def test_known_good_rmm_admin_source_requires_referenced_context(self):
        package = self.rmm_package()
        self.assert_context_basics(package)

        without_context = self._run_ai(package, {
            'confidence_adjustment': -6,
            'reasoning': 'ScreenConnect is known-good RMM.',
            'false_positive_assessment': 'Known-good RMM source.',
            'investigation_priority': 'Low',
            'mitigating_evidence_ids': ['check:rmm_known_good_missing'],
        })
        self.assertEqual(without_context['adjustment'], 0)

        metadata = {
            'known_good': {
                'statement': 'ScreenConnect on RMM01 is approved admin tooling.',
                'source': 'known_good_lookup',
                'value': {'tool': 'screenconnect', 'host': 'RMM01'},
            }
        }
        context = self.assert_context_basics(package, metadata)
        with_context = self._run_ai(package, {
            'confidence_adjustment': -6,
            'reasoning': 'Referenced known-good RMM context supports downranking.',
            'false_positive_assessment': 'Known-good RMM source is cited.',
            'investigation_priority': 'Low',
            'mitigating_evidence_ids': ['check:rmm_known_good_missing'],
            'referenced_context_ids': ['context:known_good'],
        }, context=context)
        self.assertEqual(with_context['adjustment'], -6)

    def test_sparse_telemetry_strong_remote_exec_uses_existing_negative_bound(self):
        package = self.strong_sparse_remote_exec_package()
        self.assert_context_basics(package)

        valid_heavy_downgrade = self._run_ai(package, {
            'confidence_adjustment': -12,
            'reasoning': 'Sparse telemetry limits confidence.',
            'false_positive_assessment': 'Mitigating deterministic check cited.',
            'investigation_priority': 'Medium',
            'mitigating_evidence_ids': ['check:psexec_no_known_good'],
        })
        self.assertEqual(valid_heavy_downgrade['adjustment'], -4)

        invalid = self._run_ai(package, {
            'confidence_adjustment': -12,
            'reasoning': 'Sparse telemetry, no citations.',
            'false_positive_assessment': 'None.',
            'investigation_priority': 'Medium',
        })
        self.assertEqual(invalid['adjustment'], 0)

    def test_missing_coverage_limitations_do_not_permit_invented_context(self):
        package = self.missing_coverage_package()
        context = self.assert_context_basics(package)
        facts = {fact.context_id: fact for fact in context.context_facts}
        self.assertEqual(context.coverage_status, 'unknown')
        self.assertEqual(facts['context:coverage'].status, 'unknown')

        coverage_limitation = self._run_ai(package, {
            'confidence_adjustment': 0,
            'reasoning': 'Coverage is unknown, so deterministic score is retained.',
            'false_positive_assessment': 'No validated benign context.',
            'investigation_priority': 'Unchanged',
            'referenced_context_ids': ['context:coverage'],
            'limitations': ['Coverage is unknown.'],
        })
        self.assertEqual(coverage_limitation['adjustment'], 0)

        invented = self._run_ai(package, {
            'confidence_adjustment': -4,
            'reasoning': 'Missing coverage means this was business hours and known-good.',
            'false_positive_assessment': 'Known-good business hours activity.',
            'investigation_priority': 'Low',
            'mitigating_evidence_ids': ['check:rdp_missing_sysmon'],
            'referenced_context_ids': ['context:coverage'],
        })
        self.assertEqual(invented['adjustment'], 0)
        self.assertIn('known-good', invented['adjudication_validation']['unsupported_fact_claims'])
        self.assertIn('business hours', invented['adjudication_validation']['unsupported_fact_claims'])

    def test_direct_validator_invalid_ids_and_missing_citations_are_neutral(self):
        package = self.rdp_lateral_package()
        validator = self._validator(package)

        for result in [
            self._result(4, support=['evidence:not-real']),
            self._result(-4, mitigate=['check:not-real']),
            self._result(-4, mitigate=['check:rdp_no_known_admin'], context=['context:not-real']),
            self._result(4),
            self._result(-4),
            self._result(-4, mitigate=['check:rdp_no_known_admin'], reasoning='known-good admin workflow'),
        ]:
            safe, validation = validator.safe_result(result)
            self.assertFalse(validation.is_valid)
            self.assertEqual(safe.confidence_adjustment, 0)

    def test_strong_deterministic_score_downrank_requires_valid_benign_context(self):
        package = self.user_dcsync_package()

        invalid = self._run_ai(package, {
            'confidence_adjustment': -8,
            'reasoning': 'This is a known administrative workflow.',
            'false_positive_assessment': 'Known administrative workflow.',
            'investigation_priority': 'Medium',
            'mitigating_evidence_ids': ['check:dcsync_tooling_missing'],
        })
        self.assertEqual(invalid['adjustment'], 0)

        metadata = {
            'known_good': {
                'statement': 'Documented known administrative workflow.',
                'source': 'change_ticket',
                'value': {'ticket': 'CHG-1'},
            }
        }
        context = self._context(package, metadata)
        valid = self._run_ai(package, {
            'confidence_adjustment': -8,
            'reasoning': 'Referenced known administrative workflow explains the event.',
            'false_positive_assessment': 'Known administrative workflow is cited.',
            'investigation_priority': 'Medium',
            'mitigating_evidence_ids': ['check:dcsync_tooling_missing'],
            'referenced_context_ids': ['context:known_good'],
        }, context=context)
        self.assertEqual(valid['adjustment'], -8)

    def test_invalid_ai_output_never_changes_final_score_behavior(self):
        package = self.rdp_lateral_package()
        package.ai_judgment = {'adjustment': 3, 'reasoning': 'existing'}
        before = package.final_score()

        result = self._run_ai(package, {
            'confidence_adjustment': 9,
            'reasoning': 'No citations.',
            'false_positive_assessment': 'None.',
            'investigation_priority': 'High',
        })

        self.assertEqual(result['adjustment'], 0)
        self.assertEqual(package.final_score(), before)

    def test_unknown_known_good_context_cited_as_benign_fails_closed(self):
        package = self.rdp_lateral_package()
        result = self._run_ai(package, {
            'confidence_adjustment': -4,
            'reasoning': 'The cited context shows a known-good expected admin workflow.',
            'false_positive_assessment': 'Known-good administrative source.',
            'investigation_priority': 'Low',
            'mitigating_evidence_ids': ['check:rdp_no_known_admin'],
            'referenced_context_ids': ['context:known_good'],
        })

        self.assertEqual(result['adjustment'], 0)
        self.assertFalse(result['adjudication_validation']['is_valid'])
        self.assertIn('known-good', result['adjudication_validation']['unsupported_fact_claims'])
        self.assertIn('expected admin', result['adjudication_validation']['unsupported_fact_claims'])

    def test_unknown_business_hours_context_cited_as_benign_fails_closed(self):
        package = self.rdp_lateral_package()
        result = self._run_ai(package, {
            'confidence_adjustment': -3,
            'reasoning': 'Business hours activity reduces risk.',
            'false_positive_assessment': 'Business hours makes this less suspicious.',
            'investigation_priority': 'Medium',
            'mitigating_evidence_ids': ['check:rdp_no_known_admin'],
            'referenced_context_ids': ['context:business_hours'],
        })

        self.assertEqual(result['adjustment'], 0)
        self.assertFalse(result['adjudication_validation']['is_valid'])
        self.assertIn('business hours', result['adjudication_validation']['unsupported_fact_claims'])

    def test_unknown_baseline_context_cited_as_normal_fails_closed(self):
        package = self.rdp_lateral_package()
        result = self._run_ai(package, {
            'confidence_adjustment': -3,
            'reasoning': 'The baseline indicates this is typical activity.',
            'false_positive_assessment': 'Typical baseline behavior.',
            'investigation_priority': 'Medium',
            'mitigating_evidence_ids': ['check:rdp_no_known_admin'],
            'referenced_context_ids': ['context:baseline'],
        })

        self.assertEqual(result['adjustment'], 0)
        self.assertFalse(result['adjudication_validation']['is_valid'])
        self.assertIn('baseline', result['adjudication_validation']['unsupported_fact_claims'])
        self.assertIn('typical', result['adjudication_validation']['unsupported_fact_claims'])

    def test_unknown_threat_intel_context_cited_as_threat_intel_fails_closed(self):
        package = self.rdp_tooling_package()
        result = self._run_ai(package, {
            'confidence_adjustment': 3,
            'reasoning': 'Threat intel links this tooling to a malware family.',
            'false_positive_assessment': 'Known malicious infrastructure is possible.',
            'investigation_priority': 'High',
            'supporting_evidence_ids': ['check:rdp_tooling_process'],
            'referenced_context_ids': ['context:threat_intel'],
        })

        self.assertEqual(result['adjustment'], 0)
        self.assertFalse(result['adjudication_validation']['is_valid'])
        self.assertIn('threat intel', result['adjudication_validation']['unsupported_fact_claims'])
        self.assertIn('malware family', result['adjudication_validation']['unsupported_fact_claims'])

    def test_unknown_context_can_be_cited_as_limitation_with_zero_adjustment(self):
        package = self.rdp_lateral_package()
        result = self._run_ai(package, {
            'confidence_adjustment': 0,
            'reasoning': 'Known-good, baseline, and business-hour context are unknown, so the deterministic score should stand.',
            'false_positive_assessment': 'False-positive likelihood is unchanged because trusted context is unknown.',
            'investigation_priority': 'Unchanged',
            'referenced_context_ids': [
                'context:known_good',
                'context:baseline',
                'context:business_hours',
            ],
            'limitations': [
                'Known-good context is unknown.',
                'Baseline context is unknown.',
                'Business-hour context is unknown.',
            ],
        })

        self.assertEqual(result['adjustment'], 0)
        self.assertTrue(result['adjudication_validation']['is_valid'])
        self.assertEqual(result['adjudication_validation']['unsupported_fact_claims'], [])

    def test_phase8_rdp_valid_positive_uses_deterministic_citations_without_trusted_claims(self):
        package = self.rdp_lateral_package()
        result = self._run_ai(package, {
            'confidence_adjustment': 3,
            'reasoning': 'RDP anchor and unusual source check support a modest increase.',
            'false_positive_assessment': 'Known-good and baseline context were not provided.',
            'investigation_priority': 'Medium',
            'supporting_evidence_ids': ['check:rdp_logon_anchor', 'check:rdp_unusual_source'],
            'mitigating_evidence_ids': [],
            'referenced_context_ids': [],
            'limitations': ['Known-good and baseline context were not provided.'],
            'recommended_next_steps': ['Review adjacent logons and process activity.'],
        })

        self.assertEqual(result['adjustment'], 3)
        self.assertTrue(result['adjudication_validation']['is_valid'])

    def test_phase8_dcsync_user_valid_positive_without_host_role_claim(self):
        package = self.user_dcsync_package()
        result = self._run_ai(package, {
            'confidence_adjustment': 6,
            'reasoning': 'The cited replication GUID and user-account checks support increased confidence.',
            'false_positive_assessment': 'Host role context is unknown.',
            'investigation_priority': 'Critical',
            'supporting_evidence_ids': ['check:dcsync_replication_guid', 'check:dcsync_user_account'],
            'mitigating_evidence_ids': [],
            'referenced_context_ids': [],
            'limitations': ['Host role context is unknown.'],
            'recommended_next_steps': ['Review replication permissions for the cited user account.'],
        })

        self.assertEqual(result['adjustment'], 6)
        self.assertTrue(result['adjudication_validation']['is_valid'])

    def test_phase8_rdp_negative_known_good_requires_known_context(self):
        package = self.rdp_lateral_package()
        result = self._run_ai(package, {
            'confidence_adjustment': -4,
            'reasoning': 'The cited known-good context indicates an expected admin workflow.',
            'false_positive_assessment': 'Known-good admin workflow.',
            'investigation_priority': 'Low',
            'mitigating_evidence_ids': ['check:rdp_no_known_admin'],
            'referenced_context_ids': ['context:known_good'],
        })

        self.assertEqual(result['adjustment'], 0)
        self.assertFalse(result['adjudication_validation']['is_valid'])
        self.assertIn('known-good', result['adjudication_validation']['unsupported_fact_claims'])

    def test_phase8_dcsync_domain_controller_wording_requires_known_role_context(self):
        package = self.user_dcsync_package()
        result = self._run_ai(package, {
            'confidence_adjustment': -4,
            'reasoning': 'The source is a domain controller and replication is expected.',
            'false_positive_assessment': 'Expected replication from a domain controller.',
            'investigation_priority': 'Low',
            'mitigating_evidence_ids': ['check:dcsync_no_benign_context'],
            'referenced_context_ids': ['context:source_host_role'],
        })

        self.assertEqual(result['adjustment'], 0)
        self.assertFalse(result['adjudication_validation']['is_valid'])
        self.assertIn('domain controller', result['adjudication_validation']['unsupported_fact_claims'])


if __name__ == '__main__':
    unittest.main()

