import importlib.util
import json
import os
import sys
import types
import unittest
from unittest.mock import patch

os.environ.setdefault('SECRET_KEY', 'test-secret')


def _load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class _FakeStreamResponse:
    def __init__(self, lines):
        self._lines = lines
        self.headers = {}

    def raise_for_status(self):
        return None

    def iter_lines(self):
        for line in self._lines:
            yield line


class ChatAgentGroundingTestCase(unittest.TestCase):
    def test_openai_compatible_stream_chat_sends_tools_and_parses_tool_calls(self):
        ai_providers = _load_module('ai_providers_stream_test', '/opt/casescope/utils/ai_providers.py')
        provider = ai_providers.OpenAICompatibleProvider(
            api_url='http://127.0.0.1:11435',
            model='casescope-global:latest',
        )

        request_payloads = []

        def fake_post(url, headers=None, json=None, stream=None, timeout=None):
            request_payloads.append(json)
            json_module = __import__('json')
            first_chunk = {
                "choices": [{
                    "delta": {
                        "tool_calls": [{
                            "index": 0,
                            "id": "call_1",
                            "type": "function",
                            "function": {
                                "name": "count",
                                "arguments": "{\"event_id\":\"",
                            },
                        }],
                    },
                    "finish_reason": None,
                }],
            }
            second_chunk = {
                "choices": [{
                    "delta": {
                        "tool_calls": [{
                            "index": 0,
                            "function": {
                                "name": "_events",
                                "arguments": "4625\",\"group_by\":\"source_host\"}",
                            },
                        }],
                    },
                    "finish_reason": None,
                }],
            }
            third_chunk = {
                "choices": [{
                    "delta": {},
                    "finish_reason": "tool_calls",
                }],
            }
            return _FakeStreamResponse([
                f"data: {json_module.dumps(first_chunk)}".encode(),
                f"data: {json_module.dumps(second_chunk)}".encode(),
                f"data: {json_module.dumps(third_chunk)}".encode(),
                b'data: [DONE]',
            ])

        with patch.object(ai_providers.requests, 'post', side_effect=fake_post):
            chunks = list(provider.stream_chat(
                messages=[{"role": "user", "content": "Show failed logins"}],
                tools=[{"type": "function", "function": {"name": "count_events"}}],
                temperature=0.3,
                max_tokens=500,
            ))

        self.assertTrue(request_payloads)
        self.assertIn('tools', request_payloads[0])
        self.assertEqual(request_payloads[0]['tool_choice'], 'auto')

        tool_chunks = [chunk for chunk in chunks if chunk.get('message', {}).get('tool_calls')]
        self.assertTrue(tool_chunks)
        tool_call = tool_chunks[-1]['message']['tool_calls'][0]
        self.assertEqual(tool_call['function']['name'], 'count_events')
        self.assertEqual(
            tool_call['function']['arguments'],
            '{"event_id":"4625","group_by":"source_host"}',
        )

    def test_chat_stream_executes_tool_calls_without_exposing_fake_query_narration(self):
        fake_utils = types.ModuleType('utils')
        fake_utils.__path__ = []
        fake_chat_tools = types.ModuleType('utils.chat_tools')
        fake_chat_tools.TOOL_DEFINITIONS = [
            {"type": "function", "function": {"name": "count_events"}}
        ]

        tool_invocations = []

        def fake_execute_tool(name, case_id, params):
            tool_invocations.append((name, case_id, params))
            return {
                "total": 6,
                "grouped_by": "source_host",
                "groups": [{"value": "ATN82406", "count": 6}],
            }

        fake_chat_tools.execute_tool = fake_execute_tool

        previous_utils = sys.modules.get('utils')
        previous_chat_tools = sys.modules.get('utils.chat_tools')
        sys.modules['utils'] = fake_utils
        sys.modules['utils.chat_tools'] = fake_chat_tools

        try:
            chat_agent = _load_module('chat_agent_grounding_test', '/opt/casescope/utils/chat_agent.py')
        finally:
            if previous_utils is not None:
                sys.modules['utils'] = previous_utils
            else:
                sys.modules.pop('utils', None)

            if previous_chat_tools is not None:
                sys.modules['utils.chat_tools'] = previous_chat_tools
            else:
                sys.modules.pop('utils.chat_tools', None)

        chat_agent.get_case_context = lambda case_id: {
            'case_id': case_id,
            'case_name': 'Invalid Login Case',
            'description': '',
            'hosts': ['ATN82406'],
            'timezone': 'America/New_York',
            'analysis_summary': {},
            'ai_synthesis': {},
        }

        stream_round = {'count': 0}

        def fake_stream(messages, tools=None):
            if stream_round['count'] == 0:
                stream_round['count'] += 1
                yield {
                    'message': {
                        'role': 'assistant',
                        'content': 'I will query the logs.',
                        'tool_calls': [{
                            'id': 'call_1',
                            'type': 'function',
                            'function': {
                                'name': 'count_events',
                                'arguments': '{"event_id":"4625","group_by":"source_host"}',
                            },
                        }],
                    },
                    'done': True,
                }
                return

            yield {
                'message': {
                    'role': 'assistant',
                    'content': 'I found 6 failed logon events on host ATN82406.',
                },
                'done': True,
            }

        chat_agent._stream_llm_chat = fake_stream

        events = []
        for raw_event in chat_agent.chat_stream(
            37,
            [{'role': 'user', 'content': 'Do you see invalid logins?'}],
            'conv-1',
        ):
            if raw_event.startswith('data: '):
                events.append(json.loads(raw_event[6:].strip()))

        tool_start = [event for event in events if event.get('type') == 'tool_start']
        tool_result = [event for event in events if event.get('type') == 'tool_result']
        token_text = ''.join(event.get('content', '') for event in events if event.get('type') == 'token')

        self.assertTrue(tool_start)
        self.assertTrue(tool_result)
        self.assertEqual(tool_invocations[0][0], 'count_events')
        self.assertEqual(tool_invocations[0][1], 37)
        self.assertEqual(
            tool_invocations[0][2],
            {'event_id': '4625', 'group_by': 'source_host'},
        )
        self.assertNotIn('I will query the logs.', token_text)
        self.assertIn('I found 6 failed logon events on host ATN82406.', token_text)

    def test_build_system_prompt_includes_grounding_rules(self):
        fake_utils = types.ModuleType('utils')
        fake_utils.__path__ = []
        fake_chat_tools = types.ModuleType('utils.chat_tools')
        fake_chat_tools.TOOL_DEFINITIONS = []
        fake_chat_tools.execute_tool = lambda *args, **kwargs: {}

        previous_utils = sys.modules.get('utils')
        previous_chat_tools = sys.modules.get('utils.chat_tools')
        sys.modules['utils'] = fake_utils
        sys.modules['utils.chat_tools'] = fake_chat_tools

        try:
            chat_agent = _load_module('chat_agent_prompt_test', '/opt/casescope/utils/chat_agent.py')
        finally:
            if previous_utils is not None:
                sys.modules['utils'] = previous_utils
            else:
                sys.modules.pop('utils', None)

            if previous_chat_tools is not None:
                sys.modules['utils.chat_tools'] = previous_chat_tools
            else:
                sys.modules.pop('utils.chat_tools', None)

        prompt = chat_agent.build_system_prompt({
            'case_name': 'Test Case',
            'case_id': 99,
            'description': '',
            'hosts': ['ATN82406'],
            'timezone': 'America/New_York',
            'analysis_summary': {},
            'ai_synthesis': {},
        })

        self.assertIn('Never fabricate events, timestamps, usernames, hosts, IPs, or findings', prompt)
        self.assertIn('Do not narrate future actions like "I will query"', prompt)
        self.assertIn('feel like a case-aware investigative copilot', prompt)
        self.assertIn('browser downloads for downloaded files and URLs', prompt)
        self.assertIn('network tools for PCAP/Zeek questions', prompt)


if __name__ == '__main__':
    unittest.main()
