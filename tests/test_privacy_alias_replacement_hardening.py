"""Phase 1 regressions for boundary-safe, case-insensitive alias replacement.

Covers two leaks that survived a fully populated alias vault:
  * case-sensitive substitution missed values that checks had case-folded
  * unbounded substring substitution corrupted longer identifiers, and path
    segments were vaulted as fake DOMAIN\\USERNAME accounts
"""

import unittest

from utils.privacy_aliases import (
    ALIAS_REPLACEMENT_STOPWORDS,
    MIN_ALIAS_REPLACEMENT_LENGTH,
    _replace_aliases_in_text,
    extract_alias_candidates_from_text,
)


class FakeAlias:
    """Stand-in for a PrivacyAlias row from a populated vault."""

    def __init__(self, entity_type, original_value, alias_value):
        self.entity_type = entity_type
        self.original_value = original_value
        self.alias_value = alias_value


HOST = FakeAlias('HOSTNAME', 'FIN-WKS0142', 'HOSTNAME_0003')
USER = FakeAlias('USERNAME', 'JSmith', 'USERNAME_0007')


class AliasReplacementCaseInsensitivityTests(unittest.TestCase):
    def test_replaces_regardless_of_case(self):
        for text in ('FIN-WKS0142', 'fin-wks0142', 'Fin-Wks0142'):
            with self.subTest(text=text):
                result, count, categories = _replace_aliases_in_text(text, [HOST])
                self.assertEqual(result, 'HOSTNAME_0003')
                self.assertEqual(count, 1)
                self.assertEqual(categories, {'HOSTNAME'})

    def test_case_folded_check_detail_no_longer_leaks(self):
        # These are the shapes _evaluate_field_match emits for not_dc_host,
        # from_workstation and non_admin.
        for text in (
            'host=fin-wks0142 (not a DC)',
            'host=FIN-WKS0142 (workstation)',
            'username=jsmith (non-admin)',
        ):
            with self.subTest(text=text):
                result, count, _ = _replace_aliases_in_text(text, [HOST, USER])
                self.assertEqual(count, 1)
                self.assertNotIn('fin-wks0142', result.lower())
                self.assertNotIn('jsmith', result.lower())


class AliasReplacementBoundaryTests(unittest.TestCase):
    def test_short_alias_does_not_match_inside_longer_identifier(self):
        dc1 = FakeAlias('HOSTNAME', 'DC1', 'HOSTNAME_0001')
        result, count, _ = _replace_aliases_in_text('DC10 rebooted', [dc1])
        self.assertEqual(result, 'DC10 rebooted')
        self.assertEqual(count, 0)

    def test_longest_original_wins_over_prefix(self):
        short = FakeAlias('HOSTNAME', 'FIN-WKS', 'HOSTNAME_0009')
        result, _, _ = _replace_aliases_in_text('FIN-WKS0142', [short, HOST])
        self.assertEqual(result, 'HOSTNAME_0003')

    def test_ip_prefix_does_not_match_inside_longer_ip(self):
        partial = FakeAlias('INTERNAL_IPV4', '10.20.3.5', 'INTERNAL_IPV4_0002')
        result, count, _ = _replace_aliases_in_text('src_ip=10.20.3.55', [partial])
        self.assertEqual(result, 'src_ip=10.20.3.55')
        self.assertEqual(count, 0)

    def test_trailing_sentence_period_still_matches(self):
        result, count, _ = _replace_aliases_in_text('Logon from FIN-WKS0142.', [HOST])
        self.assertEqual(result, 'Logon from HOSTNAME_0003.')
        self.assertEqual(count, 1)

    def test_machine_account_suffix_is_preserved_for_rehydration(self):
        result, count, _ = _replace_aliases_in_text('WKS01$ logged on', [
            FakeAlias('HOSTNAME', 'WKS01', 'HOSTNAME_0011'),
        ])
        self.assertEqual(result, 'HOSTNAME_0011$ logged on')
        self.assertEqual(count, 1)

    def test_stopword_and_short_aliases_are_never_substituted(self):
        rows = [
            FakeAlias('USERNAME', 'CUI', 'USERNAME_0042'),
            FakeAlias('USERNAME', 'ab', 'USERNAME_0043'),
        ]
        text = 'CUI marking on ab file'
        result, count, _ = _replace_aliases_in_text(text, rows)
        self.assertEqual(result, text)
        self.assertEqual(count, 0)

    def test_stopword_list_covers_the_cui_marker(self):
        self.assertIn('cui', ALIAS_REPLACEMENT_STOPWORDS)
        self.assertGreaterEqual(MIN_ALIAS_REPLACEMENT_LENGTH, 3)


class PathSegmentExtractionTests(unittest.TestCase):
    def _types_and_values(self, text):
        return {
            (key.entity_type, key.normalized_value)
            for key in extract_alias_candidates_from_text(text)
        }

    def test_user_profile_path_yields_only_the_real_username(self):
        found = self._types_and_values(
            r'C:\Users\jsmith\Documents\CUI\itar_export_list.docx'
        )
        self.assertIn(('USERNAME', 'jsmith'), found)
        self.assertNotIn(('USERNAME', 'cui'), found)
        self.assertNotIn(('DOMAIN', 'documents'), found)
        self.assertNotIn(('DOMAIN', 'users'), found)

    def test_programdata_path_is_not_read_as_an_account(self):
        found = self._types_and_values(
            r'C:\ProgramData\ClientProjects\Acme_Defense_Contract\payroll_2026.xlsx'
        )
        self.assertNotIn(('DOMAIN', 'programdata'), found)
        self.assertNotIn(('USERNAME', 'clientprojects'), found)
        self.assertNotIn(('USERNAME', 'payroll_2026.xlsx'), found)

    def test_real_domain_account_is_still_extracted(self):
        found = self._types_and_values('username=CORP\\jsmith logged on')
        self.assertIn(('ACCOUNT', 'corp\\jsmith'), found)
        self.assertIn(('USERNAME', 'jsmith'), found)
        self.assertIn(('DOMAIN', 'corp'), found)

    def test_unc_path_still_yields_host_and_share(self):
        found = self._types_and_values(r'\\FILESRV01\CUI_Share\program_data.xlsx')
        self.assertIn(('HOSTNAME', 'filesrv01'), found)
        self.assertIn(('SHARE', 'cui_share'), found)
        self.assertNotIn(('DOMAIN', 'filesrv01'), found)


if __name__ == '__main__':
    unittest.main()
