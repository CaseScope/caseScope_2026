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

    def test_openai_compatible_local_json_payload_disables_thinking_and_adds_repetition_controls(self):
        provider = ai_providers.OpenAICompatibleProvider(
            api_url='http://127.0.0.1:11434',
            model='gpt-oss:20b',
        )

        payload = provider._build_payload(
            messages=[{'role': 'user', 'content': 'hello'}],
            temperature=0.0,
            max_tokens=1024,
            format='json',
        )

        self.assertEqual(payload['response_format'], {'type': 'json_object'})
        self.assertFalse(payload['think'])
        self.assertEqual(payload['options']['repeat_penalty'], 1.3)
        self.assertEqual(payload['options']['repeat_last_n'], 256)

    def test_generate_json_preserves_finish_reason_and_reasoning_metadata(self):
        provider = ai_providers.OpenAICompatibleProvider(
            api_url='http://127.0.0.1:11434',
            model='gpt-oss:20b',
        )

        class FakeResponse:
            status_code = 200
            headers = {}

            def raise_for_status(self):
                return None

            def json(self):
                return {
                    'model': 'gpt-oss:20b',
                    'choices': [
                        {
                            'finish_reason': 'length',
                            'message': {
                                'content': '{"ok": true}',
                                'reasoning': 'looped before truncation',
                            },
                        }
                    ],
                    'usage': {'prompt_tokens': 10, 'completion_tokens': 20},
                }

        original_post = ai_providers.requests.post
        ai_providers.requests.post = lambda *args, **kwargs: FakeResponse()
        try:
            result = provider.generate_json(
                prompt='Return JSON',
                system='You are a test helper',
                temperature=0.0,
                max_tokens=128,
            )
        finally:
            ai_providers.requests.post = original_post

        self.assertTrue(result['success'])
        self.assertEqual(result['data'], {'ok': True})
        self.assertEqual(result['finish_reason'], 'length')
        self.assertEqual(result['reasoning'], 'looped before truncation')
        self.assertEqual(result['usage']['completion_tokens'], 20)
        self.assertEqual(result['raw_response'], '{"ok": true}')


if __name__ == '__main__':
    unittest.main()
