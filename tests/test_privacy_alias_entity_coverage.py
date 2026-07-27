"""Phase 2: every entity type we declare protected must actually be produced.

The CMMC/CUI level advertised SID, TENANT_ID, OBJECT_ID, FILEPATH and
PERSON_NAME while no extractor ever emitted them, and IPv6 was never aliased
at any level. The reachability test at the bottom is the guard that stops that
gap from reopening.
"""

import unittest

from utils.privacy_aliases import (
    PRIVACY_ENTITY_TYPES_BY_LEVEL,
    PRIVACY_LEVEL_BASIC,
    PRIVACY_LEVEL_CMMC_CUI,
    PRIVACY_LEVEL_STRICT,
    extract_alias_candidates_from_text,
    is_well_known_sid,
)


def found(text, client_public_ips=None):
    return {
        (key.entity_type, key.normalized_value)
        for key in extract_alias_candidates_from_text(
            text, client_public_ips=client_public_ips
        )
    }


def types_found(text, client_public_ips=None):
    return {entity_type for entity_type, _ in found(text, client_public_ips)}


class SidExtractionTests(unittest.TestCase):
    def test_domain_sid_is_extracted(self):
        self.assertIn(
            ('SID', 's-1-5-21-1004336348-1177238915-682003330-1013'),
            found('SubjectUserSid: S-1-5-21-1004336348-1177238915-682003330-1013'),
        )

    def test_well_known_sids_are_preserved_not_aliased(self):
        for sid in ('S-1-5-18', 'S-1-5-19', 'S-1-5-20', 'S-1-1-0', 'S-1-5-32-544'):
            with self.subTest(sid=sid):
                self.assertTrue(is_well_known_sid(sid))
                self.assertNotIn('SID', types_found(f'SubjectUserSid: {sid}'))

    def test_domain_sid_with_admin_rid_is_still_aliased(self):
        # The RID is well known but the domain identifier in front of it is not.
        self.assertFalse(is_well_known_sid('S-1-5-21-1004336348-1177238915-682003330-500'))


class GuidExtractionTests(unittest.TestCase):
    GUID = '3f2504e0-4f89-11d3-9a0c-0305e82c3301'

    def test_tenant_context_routes_to_tenant_id(self):
        self.assertIn(
            ('TENANT_ID', self.GUID),
            found(f'TenantId={self.GUID}'),
        )

    def test_object_context_routes_to_object_id(self):
        self.assertIn(
            ('OBJECT_ID', self.GUID),
            found(f'ObjectId: {self.GUID}'),
        )

    def test_bare_guid_defaults_to_object_id(self):
        self.assertIn(('OBJECT_ID', self.GUID), found(f'correlation {self.GUID}'))


class FilePathExtractionTests(unittest.TestCase):
    def test_customer_segments_are_aliased_and_os_shape_is_preserved(self):
        result = found(
            r'C:\ProgramData\ClientProjects\Acme_Defense_Contract\payroll.xlsx'
        )
        values = {value for entity_type, value in result if entity_type == 'FILEPATH'}
        self.assertIn('clientprojects', values)
        self.assertIn('acme_defense_contract', values)
        # OS layout directories carry no customer identity and stay readable.
        self.assertNotIn('programdata', values)
        self.assertNotIn('c:', values)

    def test_system_paths_produce_no_filepath_aliases(self):
        result = found(r'C:\Windows\System32\svchost.exe')
        self.assertNotIn('FILEPATH', {entity_type for entity_type, _ in result})

    def test_temp_directory_signal_survives(self):
        result = found(r'C:\Users\jsmith\AppData\Local\Temp\dropper.exe')
        values = {value for entity_type, value in result if entity_type == 'FILEPATH'}
        self.assertNotIn('temp', values)
        self.assertNotIn('appdata', values)

    def test_executable_names_are_preserved_but_documents_are_aliased(self):
        executables = {
            value
            for entity_type, value in found(r'C:\Users\jsmith\AppData\Local\Temp\dropper.exe')
            if entity_type == 'FILEPATH'
        }
        self.assertNotIn('dropper.exe', executables)

        documents = {
            value
            for entity_type, value in found(r'D:\Contracts\Acme_Q3_ITAR_Export.xlsx')
            if entity_type == 'FILEPATH'
        }
        self.assertIn('acme_q3_itar_export.xlsx', documents)

    def test_script_payloads_stay_readable(self):
        for name in ('invoke-mimikatz.ps1', 'run.bat', 'payload.hta'):
            with self.subTest(name=name):
                values = {
                    value
                    for entity_type, value in found(rf'C:\Windows\Temp\{name}')
                    if entity_type == 'FILEPATH'
                }
                self.assertNotIn(name, values)


class PersonNameExtractionTests(unittest.TestCase):
    def test_first_last_email_yields_a_person_name(self):
        self.assertIn(
            ('PERSON_NAME', 'john smith'),
            found('john.smith@acme-defense.com'),
        )

    def test_opaque_username_yields_no_person_name(self):
        self.assertNotIn('PERSON_NAME', types_found('svc_backup@acme-defense.com'))


class IPv6ExtractionTests(unittest.TestCase):
    def test_public_ipv6_is_classified_external(self):
        self.assertIn(
            ('EXTERNAL_IPV6', '2606:4700:4700::1111'),
            found('src=2606:4700:4700:0000:0000:0000:0000:1111'),
        )

    def test_client_public_ipv6_is_classified_as_the_client(self):
        self.assertIn(
            ('CLIENT_PUBLIC_IPV6', '2606:4700:4700::1111'),
            found('src=2606:4700:4700::1111', {'2606:4700:4700::1111'}),
        )

    def test_client_public_ipv4_is_classified_as_the_client(self):
        self.assertIn(
            ('CLIENT_PUBLIC_IPV4', '203.0.113.9'),
            found('src=203.0.113.9', {'203.0.113.9'}),
        )

    def test_unique_local_ipv6_is_classified_internal(self):
        self.assertIn(('INTERNAL_IPV6', 'fd00::1'), found('gateway fd00::1'))

    def test_link_local_ipv6_is_classified_internal(self):
        self.assertIn(('INTERNAL_IPV6', 'fe80::1'), found('neighbour fe80::1'))

    def test_ipv4_classification_is_unchanged(self):
        self.assertIn(('INTERNAL_IPV4', '10.20.3.55'), found('src_ip=10.20.3.55'))


class UrlExtractionTests(unittest.TestCase):
    def test_url_and_its_host_are_both_recorded(self):
        result = found('exfil to https://portal.acme-defense.com/cases?id=7')
        self.assertIn(
            ('URL', 'https://portal.acme-defense.com/cases?id=7'), result
        )
        self.assertIn(('EXTERNAL_DOMAIN', 'portal.acme-defense.com'), result)

    def test_url_host_is_not_also_recorded_as_an_internal_domain(self):
        result = found('https://portal.acme-defense.com/cases')
        self.assertNotIn(('FQDN', 'portal.acme-defense.com'), result)

    def test_internal_fqdn_outside_a_url_is_still_a_domain(self):
        result = found('fileserver.corp.acme-defense.com')
        self.assertIn(('FQDN', 'fileserver.corp.acme-defense.com'), result)


class DeclaredEntityTypeReachabilityTests(unittest.TestCase):
    """Each declared type must be produced by some extractor."""

    CLIENT_IPS = {'198.51.100.7', '2606:4700:4700::1111'}
    SAMPLES = [
        'john.smith@acme-defense.com',
        'username=CORP\\jsmith',
        'host=FIN-WKS0142',
        'fileserver.corp.acme-defense.com',
        'src_ip=10.20.3.55 dst_ip=8.8.8.8',
        'src=2606:4700:4700::1112 gw=fd00::1',
        'client_ip=198.51.100.7 client_v6=2606:4700:4700::1111',
        'SubjectUserSid: S-1-5-21-1004336348-1177238915-682003330-1013',
        'TenantId=3f2504e0-4f89-11d3-9a0c-0305e82c3301',
        'ObjectId: 7c9e6679-7425-40de-944b-e07fc1f90ae7',
        r'\\FILESRV01\CUI_Share\report.docx',
        r'C:\ProgramData\ClientProjects\Acme_Defense_Contract\payroll.xlsx',
        'https://portal.acme-defense.com/cases',
    ]

    # Sourced from case and client records rather than event text.
    RECORD_SOURCED = {'CLIENT_NAME', 'COMPANY_NAME', 'CASE_NAME'}

    def test_every_declared_type_is_reachable(self):
        produced = set()
        for sample in self.SAMPLES:
            produced |= types_found(sample, self.CLIENT_IPS)

        for level in (PRIVACY_LEVEL_BASIC, PRIVACY_LEVEL_CMMC_CUI, PRIVACY_LEVEL_STRICT):
            declared = PRIVACY_ENTITY_TYPES_BY_LEVEL[level] - self.RECORD_SOURCED
            missing = sorted(declared - produced)
            self.assertEqual(
                missing,
                [],
                f'{level} declares entity types no extractor produces: {missing}',
            )


if __name__ == '__main__':
    unittest.main()
