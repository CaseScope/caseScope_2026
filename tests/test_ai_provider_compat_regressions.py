import os
import sys
import types
import unittest
import importlib.util

os.environ.setdefault('SECRET_KEY', 'test-secret')


def _load_ai_providers_module():
    ai_adapters_spec = importlib.util.spec_from_file_location(
        'ai_adapters_for_provider_compat_test',
        '/opt/casescope/utils/ai_adapters.py',
    )
    ai_adapters_module = importlib.util.module_from_spec(ai_adapters_spec)
    assert ai_adapters_spec.loader is not None
    ai_adapters_spec.loader.exec_module(ai_adapters_module)

    fake_utils = types.ModuleType('utils')
    fake_utils.__path__ = []
    previous_utils = sys.modules.get('utils')
    previous_ai_adapters = sys.modules.get('utils.ai_adapters')
    sys.modules['utils'] = fake_utils
    sys.modules['utils.ai_adapters'] = ai_adapters_module

    spec = importlib.util.spec_from_file_location(
        'ai_providers_direct',
        '/opt/casescope/utils/ai_providers.py',
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    try:
        spec.loader.exec_module(module)
    finally:
        if previous_utils is not None:
            sys.modules['utils'] = previous_utils
        else:
            sys.modules.pop('utils', None)

        if previous_ai_adapters is not None:
            sys.modules['utils.ai_adapters'] = previous_ai_adapters
        else:
            sys.modules.pop('utils.ai_adapters', None)
    return module


ai_providers = _load_ai_providers_module()
BaseLLMProvider = ai_providers.BaseLLMProvider
get_model_profile = ai_providers.get_model_profile


class AIProviderCompatRegressionTestCase(unittest.TestCase):
    def test_gpt5_models_use_reasoning_token_semantics(self):
        self.assertTrue(BaseLLMProvider._is_reasoning_model('gpt-5.4'))
        self.assertTrue(BaseLLMProvider._is_reasoning_model('gpt-5.4-mini'))

    def test_codex_models_are_treated_as_completion_only(self):
        self.assertTrue(BaseLLMProvider._is_completion_only_model('gpt-5.3-codex'))
        self.assertFalse(BaseLLMProvider._is_completion_only_model('gpt-5.4-mini'))

    def test_json_object_extraction_salvages_wrapped_payloads(self):
        wrapped = 'Here is the result:\n{"ok": true, "items": [1, 2, 3]}\nDone.'
        self.assertEqual(
            BaseLLMProvider._extract_json_object(wrapped),
            '{"ok": true, "items": [1, 2, 3]}',
        )

    def test_local_model_profiles_include_gpt_oss(self):
        profile = get_model_profile('gpt-oss:20b')
        self.assertEqual(profile['tier'], 'local_large')
        self.assertEqual(profile['timeout'], 600)


if __name__ == '__main__':
    unittest.main()
