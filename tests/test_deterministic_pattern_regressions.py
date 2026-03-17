import os
import unittest

os.environ.setdefault('SECRET_KEY', 'test-secret')

from utils.pattern_check_definitions import EvidencePackage, get_checks_for_pattern
from utils.pattern_event_mappings import PATTERN_EVENT_MAPPINGS, get_pattern_by_id


class DeterministicPatternRegressionTestCase(unittest.TestCase):
    def test_missing_backlog_patterns_are_registered(self):
        expected = {
            'wmi_persistence',
            'dcom_lateral_movement',
            'security_tool_tampering',
            'token_manipulation',
            'named_pipe_impersonation',
            'winlogon_helper_dll',
            'smb_admin_shares',
            'lateral_tool_transfer',
            'timestomping',
            'amsi_bypass',
            'firewall_tampering',
            'dll_hijacking',
            'local_group_discovery',
            'domain_group_discovery',
            'evidence_deletion',
        }

        self.assertTrue(expected.issubset(PATTERN_EVENT_MAPPINGS.keys()))

    def test_each_new_pattern_has_evidence_checks(self):
        for pattern_id in (
            'wmi_persistence',
            'dcom_lateral_movement',
            'security_tool_tampering',
            'token_manipulation',
            'named_pipe_impersonation',
            'winlogon_helper_dll',
            'smb_admin_shares',
            'lateral_tool_transfer',
            'timestomping',
            'amsi_bypass',
            'firewall_tampering',
            'dll_hijacking',
            'local_group_discovery',
            'domain_group_discovery',
            'evidence_deletion',
        ):
            checks = get_checks_for_pattern(pattern_id)
            self.assertGreaterEqual(
                len(checks), 4, f'{pattern_id} should have concrete evidence checks'
            )

    def test_scheduled_task_persistence_supports_bits_variants(self):
        pattern = get_pattern_by_id('scheduled_task_persistence')

        self.assertIn('1', pattern['anchor_events'])
        self.assertIn('59', pattern['anchor_events'])
        self.assertIn('60', pattern['anchor_events'])
        self.assertEqual(pattern['required_sources']['Security'], 'critical')
        self.assertEqual(pattern['required_sources']['Sysmon'], 'supplementary')
        self.assertIn('bitsadmin', pattern['anchor_conditions']['1']['command_line_contains_any'])
        self.assertIn('setnotifycmdline', pattern['anchor_conditions']['1']['command_line_contains_any'])

        checks = {check.id for check in get_checks_for_pattern('scheduled_task_persistence')}
        self.assertIn('schtask_bits_tooling', checks)

    def test_uac_bypass_supports_cmstp_and_uacme_anchors(self):
        pattern = get_pattern_by_id('uac_bypass')
        cmd_terms = pattern['anchor_conditions']['1']['command_line_contains_any']

        self.assertIn('cmstp', cmd_terms)
        self.assertIn('uacme', cmd_terms)
        self.assertIn('12', pattern['anchor_events'])
        self.assertEqual(pattern['anchor_conditions']['12']['search_blob_contains'], ['mscfile'])

        checks = {check.id for check in get_checks_for_pattern('uac_bypass')}
        self.assertIn('uac_cmstp_or_uacme', checks)

    def test_network_scanning_and_password_spray_are_tuned_for_demo_samples(self):
        network_pattern = get_pattern_by_id('network_scanning')
        self.assertEqual(network_pattern['min_anchors_per_key'], 2)

        network_checks = {check.id: check for check in get_checks_for_pattern('network_scanning')}
        self.assertEqual(network_checks['netscan_multi_dest'].tiers[0][0], 2)
        self.assertEqual(network_checks['netscan_sequential_ports'].pass_condition, 'result >= 2')
        self.assertIn('netscan_smb_rdp_focus', network_checks)

        spray_checks = {check.id: check for check in get_checks_for_pattern('password_spraying')}
        self.assertIn('spray_total_failures', spray_checks)
        self.assertEqual(spray_checks['spray_distinct_users'].tiers[1][0], 8)
        self.assertEqual(spray_checks['spray_spread_pattern'].pass_condition, 'result >= 30')

    def test_remote_exec_and_log_clearing_weights_reflect_single_sample_reality(self):
        psexec_checks = {check.id: check for check in get_checks_for_pattern('psexec_execution')}
        self.assertEqual(psexec_checks['psexec_service_install'].weight, 25)
        self.assertEqual(psexec_checks['psexec_share_access'].weight, 25)
        self.assertIn('psexec_off_hours', psexec_checks)

        winrm_checks = {check.id: check for check in get_checks_for_pattern('winrm_lateral')}
        self.assertEqual(winrm_checks['winrm_logon_anchor'].weight, 25)
        self.assertEqual(winrm_checks['winrm_wsmprovhost'].weight, 25)

        log_checks = {check.id: check for check in get_checks_for_pattern('log_clearing')}
        self.assertEqual(log_checks['logclr_anchor'].weight, 45)
        self.assertIn('logclr_off_hours', log_checks)

    def test_strong_detections_reject_negative_ai_adjustments_without_benign_context(self):
        package = EvidencePackage(
            anchor={},
            pattern_id='comsvcs_minidump',
            pattern_name='comsvcs.dll MiniDump Credential Theft',
            correlation_key='demo',
            deterministic_score=90,
            ai_judgment={
                'adjustment': -7,
                'reasoning': 'Strong evidence chain for credential theft with core indicators corroborating.',
                'false_positive_assessment': 'Medium due to some non-specific failed checks.',
            },
        )

        self.assertEqual(package.bounded_ai_adjustment(), 0)
        self.assertEqual(package.final_score(), 90)

    def test_strong_detections_allow_negative_ai_adjustments_with_explicit_benign_context(self):
        package = EvidencePackage(
            anchor={},
            pattern_id='service_persistence',
            pattern_name='Service Persistence',
            correlation_key='demo',
            deterministic_score=90,
            ai_judgment={
                'adjustment': -7,
                'reasoning': 'This appears tied to a known administrative workflow on a domain controller.',
                'false_positive_assessment': 'Likely legitimate machine account service activity.',
            },
        )

        self.assertEqual(package.bounded_ai_adjustment(), -2)
        self.assertEqual(package.final_score(), 88)


if __name__ == '__main__':
    unittest.main()
