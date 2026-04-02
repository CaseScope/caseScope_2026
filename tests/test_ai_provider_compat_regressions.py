import os
import unittest
import importlib.util

os.environ.setdefault('SECRET_KEY', 'test-secret')


def _load_ai_providers_module():
    spec = importlib.util.spec_from_file_location(
        'ai_providers_direct',
        '/opt/casescope/utils/ai_providers.py',
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


BaseLLMProvider = _load_ai_providers_module().BaseLLMProvider


class AIProviderCompatRegressionTestCase(unittest.TestCase):
    def test_gpt5_models_use_reasoning_token_semantics(self):
        self.assertTrue(BaseLLMProvider._is_reasoning_model('gpt-5.4'))
        self.assertTrue(BaseLLMProvider._is_reasoning_model('gpt-5.4-mini'))

    def test_codex_models_are_treated_as_completion_only(self):
        self.assertTrue(BaseLLMProvider._is_completion_only_model('gpt-5.3-codex'))
        self.assertFalse(BaseLLMProvider._is_completion_only_model('gpt-5.4-mini'))


if __name__ == '__main__':
    unittest.main()
