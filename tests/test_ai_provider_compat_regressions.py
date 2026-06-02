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


class DummyFallbackProvider(BaseLLMProvider):
    def __init__(self):
        self.prompts = []

    def provider_type(self):
        return 'dummy'

    def generate(self, prompt: str, system: str = None, **kwargs):
        self.prompts.append({'prompt': prompt, 'system': system, 'kwargs': kwargs})
        return {'success': True, 'response': 'ok'}

    def generate_json(self, *args, **kwargs):
        return {'success': True, 'data': {}}

    def health_check(self):
        return {'status': 'healthy'}

    def list_models(self):
        return ['dummy']


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

    def test_provider_stream_error_message_hides_raw_http_details(self):
        class FakeResponse:
            status_code = 400
            text = '{"error":"Bad request details"}'

        exc = ai_providers.requests.HTTPError(
            '400 Client Error: Bad Request for url: https://api.example.test/chat'
        )
        exc.response = FakeResponse()

        message = ai_providers._format_provider_stream_error('OpenAI', exc)

        self.assertIn('HTTP 400', message)
        self.assertNotIn('https://api.example.test', message)
        self.assertNotIn('Client Error', message)

    def test_openai_done_chunk_flushes_pending_tool_calls(self):
        tool_call_state = []
        parsed = ai_providers._parse_openai_stream_chunk(
            ai_providers.json.dumps({
                'choices': [{
                    'delta': {
                        'tool_calls': [{
                            'index': 0,
                            'id': 'call-1',
                            'type': 'function',
                            'function': {
                                'name': 'count_events',
                                'arguments': '{"event_id":"4625"}',
                            },
                        }],
                    },
                    'finish_reason': None,
                }],
            }),
            tool_call_state,
        )

        self.assertIsNone(parsed)
        done_chunk = ai_providers._openai_done_chunk(tool_call_state)

        self.assertTrue(done_chunk['done'])
        tool_call = done_chunk['message']['tool_calls'][0]
        self.assertEqual(tool_call['id'], 'call-1')
        self.assertEqual(tool_call['function']['name'], 'count_events')
        self.assertEqual(tool_call['function']['arguments'], '{"event_id":"4625"}')

    def test_base_stream_chat_rejects_tools_explicitly(self):
        provider = DummyFallbackProvider()

        chunks = list(provider.stream_chat(
            messages=[{'role': 'user', 'content': 'Use a tool'}],
            tools=[{'type': 'function', 'function': {'name': 'count_events'}}],
        ))

        self.assertIn('does not support chat tools', chunks[0]['error'])
        self.assertEqual(provider.prompts, [])

    def test_base_stream_chat_preserves_multiturn_text_context(self):
        provider = DummyFallbackProvider()

        chunks = list(provider.stream_chat(messages=[
            {'role': 'system', 'content': 'System context'},
            {'role': 'user', 'content': 'First question'},
            {'role': 'assistant', 'content': 'First answer'},
            {'role': 'user', 'content': 'Follow up'},
        ]))

        self.assertEqual(chunks[0]['message']['content'], 'ok')
        self.assertEqual(provider.prompts[0]['system'], 'System context')
        self.assertIn('user: First question', provider.prompts[0]['prompt'])
        self.assertIn('assistant: First answer', provider.prompts[0]['prompt'])
        self.assertIn('user: Follow up', provider.prompts[0]['prompt'])

    def test_local_model_profiles_include_gpt_oss(self):
        profile = get_model_profile('gpt-oss:20b')
        self.assertEqual(profile['tier'], 'local_large')
        self.assertEqual(profile['timeout'], 600)

    def test_openai_compatible_local_gpt_oss_json_payload_uses_low_thinking_and_repetition_controls(self):
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
        self.assertEqual(payload['think'], 'low')
        self.assertEqual(payload['options']['repeat_penalty'], 1.3)
        self.assertEqual(payload['options']['repeat_last_n'], 256)

    def test_openai_compatible_local_non_gpt_oss_json_payload_still_disables_thinking(self):
        provider = ai_providers.OpenAICompatibleProvider(
            api_url='http://127.0.0.1:11434',
            model='qwen2.5:14b-instruct-q4_K_M',
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

    def test_claude_stream_chat_sends_tools_and_parses_tool_use(self):
        provider = ai_providers.ClaudeProvider(
            api_key='test-key',
            model='claude-sonnet-4',
        )
        tool = {
            'type': 'function',
            'function': {
                'name': 'search_memory',
                'description': 'Search memory',
                'parameters': {
                    'type': 'object',
                    'properties': {'search': {'type': 'string'}},
                    'required': ['search'],
                },
            },
        }
        captured = {}

        class FakeResponse:
            headers = {}

            def raise_for_status(self):
                return None

            def iter_lines(self):
                events = [
                    {'type': 'message_start', 'message': {}},
                    {
                        'type': 'content_block_start',
                        'index': 0,
                        'content_block': {
                            'type': 'tool_use',
                            'id': 'toolu_1',
                            'name': 'search_memory',
                            'input': {},
                        },
                    },
                    {
                        'type': 'content_block_delta',
                        'index': 0,
                        'delta': {
                            'type': 'input_json_delta',
                            'partial_json': '{"search":"powershell"}',
                        },
                    },
                    {'type': 'content_block_stop', 'index': 0},
                    {'type': 'message_stop'},
                ]
                for event in events:
                    yield ('data: ' + ai_providers.json.dumps(event)).encode('utf-8')

        original_post = ai_providers.requests.post

        def fake_post(*args, **kwargs):
            captured['json'] = kwargs.get('json')
            return FakeResponse()

        ai_providers.requests.post = fake_post
        try:
            chunks = list(provider.stream_chat(
                [{'role': 'user', 'content': 'Search memory'}],
                tools=[tool],
            ))
        finally:
            ai_providers.requests.post = original_post

        self.assertEqual(captured['json']['tools'][0]['name'], 'search_memory')
        self.assertEqual(
            captured['json']['tools'][0]['input_schema']['required'],
            ['search'],
        )
        tool_chunks = [
            chunk for chunk in chunks
            if chunk.get('message', {}).get('tool_calls')
        ]
        self.assertEqual(len(tool_chunks), 1)
        tool_call = tool_chunks[0]['message']['tool_calls'][0]
        self.assertEqual(tool_call['id'], 'toolu_1')
        self.assertEqual(tool_call['function']['name'], 'search_memory')
        self.assertEqual(tool_call['function']['arguments'], '{"search":"powershell"}')


if __name__ == '__main__':
    unittest.main()
