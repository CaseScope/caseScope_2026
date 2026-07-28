import importlib.util
import os
import sys
import types
import unittest


os.environ.setdefault("SECRET_KEY", "test-secret")


def _load_privacy_aliases():
    fake_models = types.ModuleType("models")
    fake_models.__path__ = []
    fake_database = types.ModuleType("models.database")
    fake_database.db = types.SimpleNamespace()
    fake_privacy_alias = types.ModuleType("models.privacy_alias")
    fake_privacy_alias.PrivacyAlias = type("PrivacyAlias", (), {})
    fake_privacy_alias.PrivacyAliasCounter = type("PrivacyAliasCounter", (), {})

    previous = {
        name: sys.modules.get(name)
        for name in ("models", "models.database", "models.privacy_alias")
    }
    sys.modules["models"] = fake_models
    sys.modules["models.database"] = fake_database
    sys.modules["models.privacy_alias"] = fake_privacy_alias
    try:
        spec = importlib.util.spec_from_file_location(
            "privacy_aliases_structural_test",
            "/opt/casescope/utils/privacy_aliases.py",
        )
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        sys.modules["privacy_aliases_structural_test"] = module
        spec.loader.exec_module(module)
        return module
    finally:
        for name, prior in previous.items():
            if prior is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = prior


class PrivacyAliasStructuralPayloadTestCase(unittest.TestCase):
    def test_apply_aliases_preserves_chat_protocol_fields(self):
        privacy_aliases = _load_privacy_aliases()
        alias = types.SimpleNamespace(
            original_value="jsmith",
            alias_value="USERNAME_0017",
            entity_type="USERNAME",
        )
        payload = [{
            "role": "assistant",
            "content": "User jsmith logged on.",
            "tool_calls": [{
                "id": "call-jsmith",
                "type": "function",
                "function": {
                    "name": "query_events",
                    "arguments": '{"username":"jsmith"}',
                },
            }],
        }]

        sanitized, replacements, categories = privacy_aliases._apply_aliases(payload, [alias])

        self.assertEqual(sanitized[0]["role"], "assistant")
        self.assertEqual(sanitized[0]["tool_calls"][0]["id"], "call-jsmith")
        self.assertEqual(sanitized[0]["tool_calls"][0]["type"], "function")
        self.assertEqual(sanitized[0]["tool_calls"][0]["function"]["name"], "query_events")
        self.assertIn("USERNAME_0017", sanitized[0]["content"])
        self.assertIn("USERNAME_0017", sanitized[0]["tool_calls"][0]["function"]["arguments"])
        self.assertGreaterEqual(replacements, 2)
        self.assertEqual(categories, {"USERNAME"})
        # Surrounding prose must survive intact; an unbounded substitution used
        # to corrupt any word that merely contained the alias original.
        self.assertEqual(sanitized[0]["content"], "User USERNAME_0017 logged on.")

    def test_apply_aliases_refuses_corrupting_single_character_alias(self):
        privacy_aliases = _load_privacy_aliases()
        alias = types.SimpleNamespace(
            original_value="n",
            alias_value="USERNAME_0017",
            entity_type="USERNAME",
        )

        sanitized, replacements, categories = privacy_aliases._apply_aliases(
            {"content": "User n logged on."}, [alias]
        )

        self.assertEqual(sanitized["content"], "User n logged on.")
        self.assertEqual(replacements, 0)
        self.assertEqual(categories, set())

    def _domain_alias(self):
        return types.SimpleNamespace(
            original_value="acmecorp",
            alias_value="DOMAIN_1021",
            entity_type="DOMAIN",
            sensitivity_classification=None,
        )

    def test_protected_value_in_a_structural_key_is_not_a_residual(self):
        """A vault value sitting in a protocol field must not block egress.

        Substitution skips structural keys by design, so anything there
        survives it. The verifier has to skip them too, or it reports a
        residual that no substitution pass can ever clear and every request
        for that case fails closed with no action available to the analyst.
        """
        privacy_aliases = _load_privacy_aliases()
        alias = self._domain_alias()
        payload = [{"role": "user", "name": "acmecorp", "content": "Nothing protected here."}]

        sanitized, _replacements, _categories = privacy_aliases._apply_aliases(payload, [alias])
        residual = privacy_aliases._find_residual_protected_values(
            sanitized, [alias], privacy_aliases.PRIVACY_LEVEL_CMMC_CUI
        )

        self.assertEqual(sanitized[0]["name"], "acmecorp")
        self.assertEqual(residual, set())

    def test_same_value_in_message_content_is_still_caught(self):
        """The relaxation is scoped to structural keys, never to content."""
        privacy_aliases = _load_privacy_aliases()

        residual = privacy_aliases._find_residual_protected_values(
            [{"role": "user", "content": "Logon came from acmecorp."}],
            [self._domain_alias()],
            privacy_aliases.PRIVACY_LEVEL_CMMC_CUI,
        )

        self.assertEqual(residual, {"DOMAIN"})

    def test_ordinary_words_are_neither_vaulted_nor_substituted(self):
        """Prose in a normalized username or domain column must stay prose."""
        privacy_aliases = _load_privacy_aliases()
        candidates = {}
        privacy_aliases._add_candidate(candidates, "DOMAIN", "assistant", "domain")
        privacy_aliases._add_candidate(candidates, "USERNAME", "logs", "username")
        self.assertEqual(candidates, {})

        already_vaulted = types.SimpleNamespace(
            original_value="assistant",
            alias_value="DOMAIN_1021",
            entity_type="DOMAIN",
            sensitivity_classification=None,
        )
        sanitized, replacements, _categories = privacy_aliases._apply_aliases(
            {"content": "You are a DFIR analyst assistant."}, [already_vaulted]
        )

        self.assertEqual(sanitized["content"], "You are a DFIR analyst assistant.")
        self.assertEqual(replacements, 0)

    def test_presanitized_message_is_skipped_and_marker_never_egresses(self):
        """A composer-sanitized message must not be aliased a second time.

        CaseScope's own instructions sit in that message, so a vault holding
        ordinary words would rewrite them, negations included.
        """
        privacy_aliases = _load_privacy_aliases()
        alias = types.SimpleNamespace(
            original_value="not",
            alias_value="HOSTNAME_80251",
            entity_type="HOSTNAME",
            sensitivity_classification=None,
        )
        payload = [
            {
                "role": "system",
                "content": "Do not narrate future actions.",
                privacy_aliases.PRESANITIZED_MESSAGE_KEY: True,
            },
            {"role": "user", "content": "Did not the host reboot?"},
        ]

        sanitized, _replacements, _categories = privacy_aliases._apply_aliases(payload, [alias])

        self.assertEqual(sanitized[0]["content"], "Do not narrate future actions.")
        self.assertEqual(sanitized[1]["content"], "Did HOSTNAME_80251 the host reboot?")
        self.assertEqual(
            privacy_aliases._find_residual_protected_values(
                sanitized, [alias], privacy_aliases.PRIVACY_LEVEL_CMMC_CUI
            ),
            set(),
        )

        stripped = privacy_aliases._strip_presanitized_markers(sanitized)
        self.assertNotIn(privacy_aliases.PRESANITIZED_MESSAGE_KEY, stripped[0])
        self.assertEqual(stripped[0]["content"], "Do not narrate future actions.")

    def test_real_netbios_domain_is_still_protected(self):
        """The prose rule must not reach identifiers that merely lack a dot."""
        privacy_aliases = _load_privacy_aliases()
        candidates = {}
        privacy_aliases._add_candidate(candidates, "DOMAIN", "ACMECORP", "domain")
        self.assertEqual(len(candidates), 1)

        alias = types.SimpleNamespace(
            original_value="ACMECORP",
            alias_value="DOMAIN_0007",
            entity_type="DOMAIN",
            sensitivity_classification=None,
        )
        sanitized, replacements, _categories = privacy_aliases._apply_aliases(
            {"content": "Logon to ACMECORP succeeded."}, [alias]
        )

        self.assertEqual(sanitized["content"], "Logon to DOMAIN_0007 succeeded.")
        self.assertEqual(replacements, 1)


if __name__ == "__main__":
    unittest.main()
