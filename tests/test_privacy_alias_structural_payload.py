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
            original_value="n",
            alias_value="USERNAME_0017",
            entity_type="USERNAME",
        )
        payload = [{
            "role": "assistant",
            "content": "User n logged on.",
            "tool_calls": [{
                "id": "call-n",
                "type": "function",
                "function": {
                    "name": "query_events",
                    "arguments": '{"username":"n"}',
                },
            }],
        }]

        sanitized, replacements, categories = privacy_aliases._apply_aliases(payload, [alias])

        self.assertEqual(sanitized[0]["role"], "assistant")
        self.assertEqual(sanitized[0]["tool_calls"][0]["id"], "call-n")
        self.assertEqual(sanitized[0]["tool_calls"][0]["type"], "function")
        self.assertEqual(sanitized[0]["tool_calls"][0]["function"]["name"], "query_events")
        self.assertIn("USERNAME_0017", sanitized[0]["content"])
        self.assertIn("USERNAME_0017", sanitized[0]["tool_calls"][0]["function"]["arguments"])
        self.assertGreaterEqual(replacements, 2)
        self.assertEqual(categories, {"USERNAME"})


if __name__ == "__main__":
    unittest.main()
