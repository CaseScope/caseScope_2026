"""Phase 6: checks must test the property they claim to test.

Four checks answered a different question than their name and definition
promised, and gap-finding corroboration was discarded for anchors that merely
had a source IP.
"""

import types
import unittest

from utils.deterministic_evidence_engine import (
    DC_HOST_TOKEN_RE,
    REQUIRED_SOURCE_CHANNELS,
    SERVER_HOST_TOKEN_RE,
    DeterministicEvidenceEngine,
)
from utils.pattern_check_definitions import (
    PATTERN_CHECKS,
    USERNAME_CANONICAL_SQL,
    USERNAME_CANONICAL_SQL_FOR,
)


def scope_matcher(finding, params):
    return DeterministicEvidenceEngine._finding_matches_scope(
        DeterministicEvidenceEngine.__new__(DeterministicEvidenceEngine),
        finding,
        params,
    )


def finding(entity_type, entity_value, source_ips=None):
    return types.SimpleNamespace(
        entity_type=entity_type,
        entity_value=entity_value,
        evidence={'source_ips': list(source_ips)} if source_ips else {},
    )


class GapFindingScopeTests(unittest.TestCase):
    """A user finding with no IP evidence makes no claim about IPs."""

    def test_user_finding_without_ip_evidence_matches_ip_bearing_anchor(self):
        self.assertTrue(
            scope_matcher(
                finding('user', 'jsmith'),
                {'username': 'jsmith', 'src_ip': '10.20.3.55'},
            )
        )

    def test_user_finding_without_ip_evidence_matches_anchor_without_ip(self):
        self.assertTrue(
            scope_matcher(finding('user', 'jsmith'), {'username': 'jsmith'})
        )

    def test_user_finding_with_ip_evidence_still_requires_a_match(self):
        self.assertTrue(
            scope_matcher(
                finding('user', 'jsmith', ['10.20.3.55']),
                {'username': 'jsmith', 'src_ip': '10.20.3.55'},
            )
        )
        self.assertFalse(
            scope_matcher(
                finding('user', 'jsmith', ['10.20.3.55']),
                {'username': 'jsmith', 'src_ip': '10.20.3.99'},
            )
        )

    def test_different_user_never_matches(self):
        self.assertFalse(
            scope_matcher(finding('user', 'bsmith'), {'username': 'jsmith'})
        )

    def test_source_ip_and_system_scoping_are_unchanged(self):
        self.assertTrue(
            scope_matcher(
                finding('source_ip', '10.20.3.55'), {'src_ip': '10.20.3.55'}
            )
        )
        self.assertFalse(
            scope_matcher(finding('source_ip', '10.20.3.55'), {'src_ip': ''})
        )
        self.assertTrue(
            scope_matcher(
                finding('system', 'dc01'), {'source_host': 'DC01'}
            )
        )


class RequiredSourceChannelTests(unittest.TestCase):
    def satisfies(self, source, channel):
        return DeterministicEvidenceEngine._channel_satisfies_source(source, channel)

    def test_security_is_satisfied_only_by_the_security_log(self):
        self.assertTrue(self.satisfies('Security', 'Security'))
        self.assertTrue(self.satisfies('Security', 'security'))

    def test_firewall_channel_does_not_satisfy_security(self):
        self.assertFalse(
            self.satisfies(
                'Security',
                'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall',
            )
        )

    def test_unrelated_channels_do_not_satisfy_system_or_application(self):
        self.assertFalse(
            self.satisfies('System', 'Microsoft-Windows-Kernel-Boot/Operational')
        )
        self.assertFalse(
            self.satisfies('Application', 'Microsoft-Windows-Application-Experience/Program-Telemetry')
        )

    def test_sysmon_and_powershell_map_to_their_real_channels(self):
        self.assertTrue(
            self.satisfies('Sysmon', 'Microsoft-Windows-Sysmon/Operational')
        )
        self.assertFalse(self.satisfies('Sysmon', 'Security'))
        self.assertTrue(
            self.satisfies('PowerShell', 'Microsoft-Windows-PowerShell/Operational')
        )
        self.assertTrue(self.satisfies('PowerShell', 'Windows PowerShell'))

    def test_every_declared_required_source_is_mapped(self):
        declared = set()
        for checks in PATTERN_CHECKS.values():
            for check in checks:
                for source in (getattr(check, 'required_sources', None) or {}):
                    declared.add(source)
        unmapped = sorted(declared - set(REQUIRED_SOURCE_CHANNELS))
        self.assertEqual(
            unmapped, [], f'required sources with no channel mapping: {unmapped}'
        )


class HostRoleHeuristicTests(unittest.TestCase):
    def test_dc_token_requires_a_boundary(self):
        for host in ('DC01', 'dc-01', 'corp-dc', 'AD01', 'domain-ctrl'):
            with self.subTest(host=host):
                self.assertTrue(DC_HOST_TOKEN_RE.search(host))

    def test_hosts_merely_containing_dc_are_not_domain_controllers(self):
        for host in ('MEDCENTER01', 'BROADCAST7', 'EDCSERVER'):
            with self.subTest(host=host):
                self.assertIsNone(DC_HOST_TOKEN_RE.search(host))

    def test_server_tokens_require_a_boundary(self):
        self.assertTrue(SERVER_HOST_TOKEN_RE.search('SQL01'))
        self.assertTrue(SERVER_HOST_TOKEN_RE.search('corp-srv-02'))
        self.assertIsNone(SERVER_HOST_TOKEN_RE.search('WKS-APPLETON'))
        self.assertIsNone(SERVER_HOST_TOKEN_RE.search('LAPTOP-WEBB'))


class ServiceAccountCheckTests(unittest.TestCase):
    """kerb_not_service_account must test for an SPN, not a machine account."""

    def _check(self):
        for check in PATTERN_CHECKS['kerberoasting']:
            if check.id == 'kerb_not_service_account':
                return check
        raise AssertionError('kerb_not_service_account is missing')

    def test_check_is_query_backed(self):
        check = self._check()
        self.assertEqual(check.check_type, 'threshold')
        self.assertEqual(check.pass_condition, 'result == 0')
        self.assertIn('payload_data1', check.query_template)
        self.assertIn('4769', check.query_template)

    def test_check_scopes_on_the_canonical_account_name(self):
        check = self._check()
        self.assertIn('{username_canonical:String}', check.query_template)

    def test_machine_account_branch_no_longer_claims_this_check(self):
        import inspect

        source = inspect.getsource(
            DeterministicEvidenceEngine._evaluate_field_match
        )
        self.assertNotIn("'not_service_account' in check_id", source)


class CanonicalUsernameScopingTests(unittest.TestCase):
    # Pinned literally rather than compared against the helper, so that a
    # change in backslash escaping cannot pass by matching itself. ClickHouse
    # needs a single escaped backslash here: splitByChar('\\', column).
    EXPECTED_USERNAME_SQL = (
        "lower(arrayElement(splitByChar('@', "
        "arrayElement(splitByChar('\\\\', username), -1)), 1))"
    )

    def test_canonical_sql_for_username_is_unchanged(self):
        self.assertEqual(USERNAME_CANONICAL_SQL, self.EXPECTED_USERNAME_SQL)
        self.assertEqual(
            USERNAME_CANONICAL_SQL_FOR('username'), self.EXPECTED_USERNAME_SQL
        )

    def test_canonical_sql_escapes_exactly_one_backslash(self):
        for column in ('username', 'payload_data1'):
            with self.subTest(column=column):
                sql = USERNAME_CANONICAL_SQL_FOR(column)
                self.assertEqual(sql.count('\\'), 2)
                self.assertIn("splitByChar('\\\\', " + column + ")", sql)

    def test_canonical_sql_strips_domain_and_realm(self):
        sql = USERNAME_CANONICAL_SQL_FOR('payload_data1')
        self.assertIn('payload_data1', sql)
        self.assertIn("splitByChar('@'", sql)
        self.assertIn('lower(', sql)

    def test_burst_scope_uses_the_canonical_username(self):
        import inspect

        source = inspect.getsource(DeterministicEvidenceEngine._detect_bursts)
        self.assertIn('USERNAME_CANONICAL_SQL', source)
        self.assertIn('{username_canonical:String}', source)


if __name__ == '__main__':
    unittest.main()
