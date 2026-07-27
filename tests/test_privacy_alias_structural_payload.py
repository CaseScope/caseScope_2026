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

    def test_protocol_literal_colliding_with_vault_value_is_not_a_residual(self):
        """A vault value equal to a protocol literal must not block egress.

        Event logs vault dotless NetBIOS domains, so a case can hold a value
        such as 'assistant'. Substitution skips structural keys, so the word in
        a message role survives by design; the verifier must skip it too, or
        every request for that case fails closed with no way to clear it.
        """
        privacy_aliases = _load_privacy_aliases()
        alias = types.SimpleNamespace(
            original_value="assistant",
            alias_value="DOMAIN_1021",
            entity_type="DOMAIN",
            sensitivity_classification=None,
        )
        payload = [
            {"role": "user", "content": "Was there password spraying overnight?"},
            {"role": "assistant", "content": "No protected values here."},
        ]

        sanitized, _replacements, _categories = privacy_aliases._apply_aliases(payload, [alias])
        residual = privacy_aliases._find_residual_protected_values(
            sanitized, [alias], privacy_aliases.PRIVACY_LEVEL_CMMC_CUI
        )

        self.assertEqual(sanitized[1]["role"], "assistant")
        self.assertEqual(residual, set())

    def test_same_value_in_message_content_is_still_caught(self):
        """The relaxation is scoped to structural keys, not to content."""
        privacy_aliases = _load_privacy_aliases()
        alias = types.SimpleNamespace(
            original_value="assistant",
            alias_value="DOMAIN_1021",
            entity_type="DOMAIN",
            sensitivity_classification=None,
        )

        residual = privacy_aliases._find_residual_protected_values(
            [{"role": "user", "content": "Logon came from assistant."}],
            [alias],
            privacy_aliases.PRIVACY_LEVEL_CMMC_CUI,
        )

        self.assertEqual(residual, {"DOMAIN"})


if __name__ == "__main__":
    unittest.main()
