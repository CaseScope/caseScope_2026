import json
import os
import unittest
from datetime import datetime

os.environ.setdefault('SECRET_KEY', 'test-secret')

from utils.pattern_check_definitions import (
    EvidencePackage,
    has_unexpected_system_process_parent,
    has_unexpected_system_process_path,
    get_checks_for_pattern,
)
from utils.pattern_event_mappings import PATTERN_EVENT_MAPPINGS, get_pattern_by_id


LINEAGE_SQL_TEST_CASE_ID = 4294959000
LINEAGE_SQL_TEST_TS = datetime(2026, 6, 19, 20, 0, 0)


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
            'anomalous_process_lineage',
        }

        self.assertTrue(expected.issubset(PATTERN_EVENT_MAPPINGS.keys()))

    def test_anomalous_process_lineage_is_registered_for_normal_flow(self):
        pattern = get_pattern_by_id('anomalous_process_lineage')

        self.assertEqual(pattern['category'], 'Behavioral Anomaly')
        self.assertEqual(pattern['anchor_events'], ['1', '4688'])
        self.assertEqual(pattern['correlation_fields'], ['source_host'])

        checks = {check.id: check for check in get_checks_for_pattern('anomalous_process_lineage')}
        self.assertEqual(
            set(checks),
            {'plineage_unexpected_parent', 'plineage_unexpected_path'},
        )
        self.assertTrue(all(check.check_type == 'threshold' for check in checks.values()))
        self.assertIn('AND (noise_matched = false OR noise_matched IS NULL)', checks['plineage_unexpected_parent'].query_template)
        self.assertIn('AND (noise_matched = false OR noise_matched IS NULL)', checks['plineage_unexpected_path'].query_template)

    def test_anomalous_process_lineage_clean_tree_has_no_findings(self):
        self.assertFalse(
            has_unexpected_system_process_parent(
                r'C:\Windows\System32\lsass.exe',
                r'C:\Windows\System32\wininit.exe',
            )
        )
        self.assertFalse(
            has_unexpected_system_process_path(
                r'C:\Windows\System32\svchost.exe',
            )
        )

    def test_anomalous_process_lineage_flags_spoofed_parent(self):
        self.assertTrue(
            has_unexpected_system_process_parent(
                r'C:\Windows\System32\lsass.exe',
                r'C:\Windows\System32\cmd.exe',
            )
        )

    def test_anomalous_process_lineage_flags_masqueraded_path(self):
        self.assertTrue(
            has_unexpected_system_process_path(
                r'C:\Users\Public\svchost.exe',
            )
        )

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

    def test_refined_patterns_include_overlay_metadata_and_new_support_checks(self):
        pth = get_pattern_by_id('pass_the_hash')
        self.assertIn('5145', pth['supporting_events'])
        self.assertIn('4776', pth['context_events'])
        self.assertIn('pth', pth['overlay_aliases'])
        pth_checks = {check.id for check in get_checks_for_pattern('pass_the_hash')}
        self.assertIn('pth_ntlm_validation', pth_checks)

        spray = get_pattern_by_id('password_spraying')
        self.assertIn('4740', spray['supporting_events'])
        self.assertIn('password spray', spray['overlay_aliases'])
        spray_checks = {check.id for check in get_checks_for_pattern('password_spraying')}
        self.assertIn('spray_protocol_diversity', spray_checks)

        psexec = get_pattern_by_id('psexec_execution')
        self.assertIn('7036', psexec['supporting_events'])
        self.assertIn('psexec', psexec['overlay_aliases'])
        psexec_checks = {check.id for check in get_checks_for_pattern('psexec_execution')}
        self.assertIn('psexec_service_state_change', psexec_checks)

        wmi = get_pattern_by_id('wmi_lateral')
        self.assertIn('3', wmi['supporting_events'])
        self.assertIn('wmic remote exec', wmi['overlay_aliases'])
        wmi_checks = {check.id for check in get_checks_for_pattern('wmi_lateral')}
        self.assertIn('wmi_explicit_creds', wmi_checks)

        schtask = get_pattern_by_id('scheduled_task_persistence')
        self.assertIn('106', schtask['supporting_events'])
        self.assertIn('201', schtask['supporting_events'])
        schtask_checks = {check.id for check in get_checks_for_pattern('scheduled_task_persistence')}
        self.assertIn('schtask_operational_registration', schtask_checks)

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


class AnomalousProcessLineageSqlRegressionTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            from utils.clickhouse import get_fresh_client
        except Exception as exc:
            raise unittest.SkipTest(f'ClickHouse client unavailable: {exc}') from exc

        cls.client = get_fresh_client()
        cls.checks = {
            check.id: check for check in get_checks_for_pattern('anomalous_process_lineage')
        }
        cls._delete_fixture_rows()
        cls._insert_fixture_rows()

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, 'client', None) is not None:
            cls._delete_fixture_rows()

    @classmethod
    def _delete_fixture_rows(cls):
        cls.client.command(
            f'ALTER TABLE events DELETE WHERE case_id = {LINEAGE_SQL_TEST_CASE_ID} '
            'SETTINGS mutations_sync = 1'
        )

    @classmethod
    def _insert_fixture_rows(cls):
        column_names = [
            'case_id',
            'artifact_type',
            'timestamp',
            'timestamp_utc',
            'timestamp_source_tz',
            'source_file',
            'source_path',
            'source_host',
            'event_id',
            'channel',
            'provider',
            'process_name',
            'raw_json',
            'search_blob',
            'noise_matched',
        ]

        def row(source_host, event_id, channel, provider, process_name, event_data, search_blob):
            return [
                LINEAGE_SQL_TEST_CASE_ID,
                'evtx',
                LINEAGE_SQL_TEST_TS,
                LINEAGE_SQL_TEST_TS,
                'UTC',
                'lineage-regression.evtx',
                '/tmp/lineage-regression.evtx',
                source_host,
                event_id,
                channel,
                provider,
                process_name,
                json.dumps({'EventData': event_data}),
                search_blob,
                False,
            ]

        rows = [
            row(
                'LINEAGE-CLOUDSTORE',
                '1',
                'Microsoft-Windows-CloudStore/Operational',
                'Microsoft-Windows-CloudStore',
                'taskhostw.exe',
                {'ProcessName': 'taskhostw.exe', 'Type': '2'},
                'ProcessName:taskhostw.exe image taskhostw.exe with no process-creation fields',
            ),
            row(
                'LINEAGE-BAD-PARENT',
                '1',
                'Microsoft-Windows-Sysmon/Operational',
                'Microsoft-Windows-Sysmon',
                'lsass.exe',
                {
                    'Image': r'C:\Windows\System32\lsass.exe',
                    'ParentImage': r'C:\Windows\System32\cmd.exe',
                },
                'Sysmon process creation lsass.exe parent cmd.exe',
            ),
            row(
                'LINEAGE-BAD-PATH',
                '1',
                'Microsoft-Windows-Sysmon/Operational',
                'Microsoft-Windows-Sysmon',
                'svchost.exe',
                {
                    'Image': r'C:\Users\evil\svchost.exe',
                    'ParentImage': r'C:\Windows\System32\services.exe',
                },
                'Sysmon process creation svchost.exe from user profile',
            ),
            row(
                'LINEAGE-CLEAN-SYSMON',
                '1',
                'Microsoft-Windows-Sysmon/Operational',
                'Microsoft-Windows-Sysmon',
                'lsass.exe',
                {
                    'Image': r'C:\Windows\System32\lsass.exe',
                    'ParentImage': r'C:\Windows\System32\wininit.exe',
                },
                'Clean Sysmon process creation lsass.exe from system32',
            ),
            row(
                'LINEAGE-CLEAN-4688',
                '4688',
                'Security',
                'Microsoft-Windows-Security-Auditing',
                'lsass.exe',
                {
                    'NewProcessName': r'C:\Windows\System32\lsass.exe',
                    'ParentProcessName': r'C:\Windows\System32\wininit.exe',
                },
                'Clean Security 4688 process creation lsass.exe from system32',
            ),
        ]
        cls.client.insert('events', rows, column_names=column_names)

    def _lineage_count(self, check_id, source_host):
        result = self.client.query(
            self.checks[check_id].query_template,
            parameters={
                'case_id': LINEAGE_SQL_TEST_CASE_ID,
                'source_host': source_host,
            },
        )
        return result.result_rows[0][0] if result.result_rows else 0

    def test_cloudstore_event_id_1_without_process_fields_does_not_match(self):
        self.assertEqual(
            self._lineage_count('plineage_unexpected_parent', 'LINEAGE-CLOUDSTORE'),
            0,
        )
        self.assertEqual(
            self._lineage_count('plineage_unexpected_path', 'LINEAGE-CLOUDSTORE'),
            0,
        )

    def test_sysmon_id1_lsass_with_cmd_parent_matches_unexpected_parent(self):
        self.assertEqual(
            self._lineage_count('plineage_unexpected_parent', 'LINEAGE-BAD-PARENT'),
            1,
        )

    def test_sysmon_id1_svchost_from_user_path_matches_unexpected_path(self):
        self.assertEqual(
            self._lineage_count('plineage_unexpected_path', 'LINEAGE-BAD-PATH'),
            1,
        )

    def test_clean_sysmon_id1_lsass_tree_does_not_match(self):
        self.assertEqual(
            self._lineage_count('plineage_unexpected_parent', 'LINEAGE-CLEAN-SYSMON'),
            0,
        )
        self.assertEqual(
            self._lineage_count('plineage_unexpected_path', 'LINEAGE-CLEAN-SYSMON'),
            0,
        )

    def test_clean_security_4688_tree_does_not_match(self):
        self.assertEqual(
            self._lineage_count('plineage_unexpected_parent', 'LINEAGE-CLEAN-4688'),
            0,
        )
        self.assertEqual(
            self._lineage_count('plineage_unexpected_path', 'LINEAGE-CLEAN-4688'),
            0,
        )


if __name__ == '__main__':
    unittest.main()
