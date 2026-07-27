"""The alias vault has to stay small enough to substitute against.

A level-blind, uncapped scan produced 1.29 million rows across 16 cases, 60%
of them entity types the configured level never substitutes. Substitution is
linear in vault size, so that made AI requests on the largest cases unusable,
and a 2.8KB URL exceeded the btree limit on the unique index and aborted the
whole case.
"""

import unittest

from utils.privacy_aliases import (
    MAX_CASE_VAULT_CANDIDATES,
    MAX_VAULTED_VALUE_LENGTH,
    PRIVACY_ENTITY_TYPES_BY_LEVEL,
    PRIVACY_LEVEL_BASIC,
    PRIVACY_LEVEL_CMMC_CUI,
    PRIVACY_LEVEL_STRICT,
    SCANNED_TEXT_FIELDS,
    TEXT_FIELD_SCAN_LIMIT,
    TYPED_FIELD_SCAN_LIMIT,
    AliasCandidate,
    _candidate_is_vaultable,
)


class FakeAlias:
    def __init__(self, entity_type, original_value, alias_value):
        self.entity_type = entity_type
        self.original_value = original_value
        self.alias_value = alias_value


ALIAS = FakeAlias('HOSTNAME', 'FIN-WKS0142', 'HOSTNAME_0003')


def candidate(entity_type, normalized_value):
    return AliasCandidate(
        entity_type=entity_type,
        original_value=normalized_value,
        normalized_value=normalized_value,
        seen_count=1,
    )


class LevelScopingTests(unittest.TestCase):
    def test_external_address_is_rejected_at_cmmc_cui(self):
        allowed = PRIVACY_ENTITY_TYPES_BY_LEVEL[PRIVACY_LEVEL_CMMC_CUI]
        self.assertFalse(
            _candidate_is_vaultable(candidate('EXTERNAL_IPV4', '8.8.8.8'), allowed)
        )

    def test_external_address_is_accepted_at_strict(self):
        allowed = PRIVACY_ENTITY_TYPES_BY_LEVEL[PRIVACY_LEVEL_STRICT]
        self.assertTrue(
            _candidate_is_vaultable(candidate('EXTERNAL_IPV4', '8.8.8.8'), allowed)
        )

    def test_in_scope_type_survives_at_its_level(self):
        for level in (PRIVACY_LEVEL_BASIC, PRIVACY_LEVEL_CMMC_CUI, PRIVACY_LEVEL_STRICT):
            with self.subTest(level=level):
                allowed = PRIVACY_ENTITY_TYPES_BY_LEVEL[level]
                self.assertTrue(
                    _candidate_is_vaultable(candidate('USERNAME', 'jsmith'), allowed)
                )

    def test_sid_is_out_of_scope_at_basic_but_in_scope_at_cmmc(self):
        sid = candidate('SID', 's-1-5-21-1-2-3-1013')
        self.assertFalse(
            _candidate_is_vaultable(sid, PRIVACY_ENTITY_TYPES_BY_LEVEL[PRIVACY_LEVEL_BASIC])
        )
        self.assertTrue(
            _candidate_is_vaultable(sid, PRIVACY_ENTITY_TYPES_BY_LEVEL[PRIVACY_LEVEL_CMMC_CUI])
        )

    def test_no_allowed_types_means_no_filtering(self):
        self.assertTrue(
            _candidate_is_vaultable(candidate('EXTERNAL_IPV4', '8.8.8.8'), None)
        )


class ValueLengthTests(unittest.TestCase):
    def test_oversized_url_is_refused(self):
        """The exact shape that aborted case 23: an OIDC callback with a JWT."""
        url = 'https://now.connectwise.com/oidc-callback#id_token=' + ('e' * 2800)
        self.assertGreater(len(url), MAX_VAULTED_VALUE_LENGTH)
        self.assertFalse(
            _candidate_is_vaultable(
                candidate('URL', url),
                PRIVACY_ENTITY_TYPES_BY_LEVEL[PRIVACY_LEVEL_STRICT],
            )
        )

    def test_value_at_the_limit_is_kept(self):
        allowed = PRIVACY_ENTITY_TYPES_BY_LEVEL[PRIVACY_LEVEL_STRICT]
        self.assertTrue(
            _candidate_is_vaultable(
                candidate('URL', 'h' * MAX_VAULTED_VALUE_LENGTH), allowed
            )
        )
        self.assertFalse(
            _candidate_is_vaultable(
                candidate('URL', 'h' * (MAX_VAULTED_VALUE_LENGTH + 1)), allowed
            )
        )

    def test_limit_stays_under_the_btree_index_bound(self):
        """PostgreSQL rejects a btree index row above roughly 2704 bytes."""
        self.assertLess(MAX_VAULTED_VALUE_LENGTH * 4, 2704 * 4)
        self.assertLessEqual(MAX_VAULTED_VALUE_LENGTH, 2704)


class MatcherReuseTests(unittest.TestCase):
    """The alternation is compiled once per payload, not once per string.

    Compiling against a 50,000 alias vault costs about three seconds. Rebuilding
    it for every string leaf turned a 30-message payload into 87 seconds of
    regex compilation before the request could even be sent.
    """

    def _payload(self, leaves):
        return {
            'messages': [
                {'role': 'user', 'content': f'Logon {i} from FIN-WKS0142'}
                for i in range(leaves)
            ]
        }

    def test_matcher_is_built_once_regardless_of_leaf_count(self):
        from utils import privacy_aliases

        calls = []
        original = privacy_aliases._build_alias_matcher

        def counting_builder(aliases):
            calls.append(1)
            return original(aliases)

        privacy_aliases._build_alias_matcher = counting_builder
        try:
            for leaves in (1, 10, 50):
                calls.clear()
                privacy_aliases._apply_aliases(self._payload(leaves), [ALIAS])
                with self.subTest(leaves=leaves):
                    self.assertEqual(len(calls), 1)
        finally:
            privacy_aliases._build_alias_matcher = original

    def test_substitution_still_applies_to_every_leaf(self):
        from utils.privacy_aliases import _apply_aliases

        result, count, categories = _apply_aliases(self._payload(12), [ALIAS])
        self.assertEqual(count, 12)
        self.assertEqual(categories, {'HOSTNAME'})
        for message in result['messages']:
            self.assertIn('HOSTNAME_0003', message['content'])
            self.assertNotIn('FIN-WKS0142', message['content'])


class ScanCapTests(unittest.TestCase):
    def test_typed_fields_are_capped_like_text_fields(self):
        """The typed columns were the uncapped ones; dst_ip alone gave 769k rows."""
        self.assertGreater(TYPED_FIELD_SCAN_LIMIT, 0)
        self.assertGreater(TEXT_FIELD_SCAN_LIMIT, 0)

    def test_overall_cap_bounds_the_worst_case_field_product(self):
        """Per-field caps alone still multiply out; the case cap is the backstop."""
        worst_case_without_cap = (
            len(SCANNED_TEXT_FIELDS) * TEXT_FIELD_SCAN_LIMIT
            + 7 * TYPED_FIELD_SCAN_LIMIT
        )
        self.assertGreater(worst_case_without_cap, MAX_CASE_VAULT_CANDIDATES)
        self.assertLessEqual(MAX_CASE_VAULT_CANDIDATES, 50000)


if __name__ == '__main__':
    unittest.main()
