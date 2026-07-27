"""Phase 3: cloud egress must fail closed rather than send protected values.

Two fail-open paths existed. A sanitizer import failure returned the raw
payload and carried on to the provider, and a substitution that silently
failed to replace a value was never detected because nothing inspected the
sanitized result.
"""

import types
import unittest
from unittest import mock

from utils.privacy_aliases import (
    ALIAS_TOKEN_RE,
    PRIVACY_LEVEL_CMMC_CUI,
    PrivacyEgressLeakError,
    _find_residual_protected_values,
)


class FakeAlias:
    def __init__(self, entity_type, original_value, alias_value):
        self.entity_type = entity_type
        self.original_value = original_value
        self.alias_value = alias_value


class ResidualDetectionTests(unittest.TestCase):
    def test_fully_substituted_payload_has_no_residual(self):
        residual = _find_residual_protected_values(
            {'summary': 'Logon from HOSTNAME_0003 by USERNAME_0007'},
            [
                FakeAlias('HOSTNAME', 'FIN-WKS0142', 'HOSTNAME_0003'),
                FakeAlias('USERNAME', 'jsmith', 'USERNAME_0007'),
            ],
            PRIVACY_LEVEL_CMMC_CUI,
        )
        self.assertEqual(residual, set())

    def test_unsubstituted_hostname_is_reported(self):
        residual = _find_residual_protected_values(
            {'summary': 'Logon from FIN-WKS0142 by USERNAME_0007'},
            [
                FakeAlias('HOSTNAME', 'FIN-WKS0142', 'HOSTNAME_0003'),
                FakeAlias('USERNAME', 'jsmith', 'USERNAME_0007'),
            ],
            PRIVACY_LEVEL_CMMC_CUI,
        )
        self.assertIn('HOSTNAME', residual)

    def test_alias_tokens_are_not_mistaken_for_residual(self):
        residual = _find_residual_protected_values(
            {'summary': 'host=HOSTNAME_0003 user=USERNAME_0007 sid=SID_0011'},
            [],
            PRIVACY_LEVEL_CMMC_CUI,
        )
        self.assertEqual(residual, set())

    def test_deliberately_unsubstitutable_values_are_not_residual(self):
        # Short and stopword originals are vaulted but never swapped, so their
        # presence in the output is expected rather than a control failure.
        residual = _find_residual_protected_values(
            {'summary': 'marking CUI applies'},
            [FakeAlias('USERNAME', 'CUI', 'USERNAME_0042')],
            PRIVACY_LEVEL_CMMC_CUI,
        )
        self.assertEqual(residual, set())

    def test_alias_token_regex_matches_generated_tokens(self):
        for token in ('HOSTNAME_0003', 'CLIENT_PUBLIC_IPV4_0012', 'SID_0001'):
            with self.subTest(token=token):
                self.assertTrue(ALIAS_TOKEN_RE.fullmatch(token))

    def test_alias_token_regex_does_not_match_real_hostnames(self):
        for value in ('FIN-WKS0142', 'fin-wks0142', 'DC01'):
            with self.subTest(value=value):
                self.assertIsNone(ALIAS_TOKEN_RE.fullmatch(value))


class RouterFailClosedTests(unittest.TestCase):
    """A sanitizer that cannot load must not let cloud egress proceed."""

    def _router(self):
        from utils.ai import router
        return router

    def test_cloud_provider_is_blocked_when_sanitizer_cannot_import(self):
        router = self._router()
        provider = types.SimpleNamespace(provider_type=lambda: 'claude')

        with mock.patch.dict('sys.modules', {'utils.privacy_aliases': None}):
            with self.assertRaises(RuntimeError) as caught:
                router._sanitize_for_provider(
                    {'content': 'jsmith on FIN-WKS0142'},
                    privacy_context=None,
                    provider=provider,
                )
        self.assertIn('privacy sanitizer unavailable', str(caught.exception))

    def test_local_provider_may_continue_without_the_sanitizer(self):
        router = self._router()
        provider = types.SimpleNamespace(provider_type=lambda: 'local')
        payload = {'content': 'jsmith on FIN-WKS0142'}

        with mock.patch.dict('sys.modules', {'utils.privacy_aliases': None}):
            value, metadata = router._sanitize_for_provider(
                payload, privacy_context=None, provider=provider
            )
        self.assertEqual(value, payload)
        self.assertFalse(metadata['enabled'])

    def test_openai_compatible_is_treated_as_remote_without_the_sanitizer(self):
        # Confirming an openai_compatible endpoint is local needs the module
        # that just failed to import, so it must not be assumed local.
        router = self._router()
        provider = types.SimpleNamespace(provider_type=lambda: 'openai_compatible')

        with mock.patch.dict('sys.modules', {'utils.privacy_aliases': None}):
            with self.assertRaises(RuntimeError):
                router._sanitize_for_provider(
                    {'content': 'jsmith'}, privacy_context=None, provider=provider
                )


class LeakErrorTests(unittest.TestCase):
    def test_error_names_categories_but_never_values(self):
        error = PrivacyEgressLeakError({'HOSTNAME', 'SID'}, case_id=7)
        message = str(error)
        self.assertIn('HOSTNAME', message)
        self.assertIn('SID', message)
        self.assertEqual(error.categories, ['HOSTNAME', 'SID'])
        self.assertEqual(error.case_id, 7)
        self.assertEqual(error.error_code, 'privacy_egress_residual_leak')


if __name__ == '__main__':
    unittest.main()
