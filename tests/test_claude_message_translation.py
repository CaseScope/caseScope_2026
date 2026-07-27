"""Contract tests for the OpenAI to Anthropic message translation.

The chat agent speaks OpenAI's message shape. Anthropic rejects unknown message
keys outright, carries tool calls and tool results as typed content blocks, and
takes system text out of the message list, so every request must be translated
rather than forwarded.
"""

import json
import os
import unittest

os.environ.setdefault("SECRET_KEY", "test-secret")

from utils.ai_providers import _anthropic_messages_from_openai


class AnthropicMessageTranslationTestCase(unittest.TestCase):
    def test_cache_control_moves_onto_a_content_block(self):
        system, messages = _anthropic_messages_from_openai([
            {"role": "system", "content": "You are a DFIR assistant.",
             "cache_control": {"type": "ephemeral"}},
            {"role": "user", "content": "What happened?"},
        ])

        # The live failure was 'messages.0.cache_control: Extra inputs are not
        # permitted' because the key was left on the message.
        for message in messages:
            self.assertNotIn("cache_control", message)
        self.assertEqual(system[0]["cache_control"], {"type": "ephemeral"})

    def test_no_message_carries_keys_anthropic_rejects(self):
        _, messages = _anthropic_messages_from_openai([
            {"role": "system", "content": "system"},
            {"role": "user", "content": "question"},
            {"role": "assistant", "content": "", "tool_calls": [{
                "id": "call_1", "type": "function",
                "function": {"name": "count_events", "arguments": '{"event_id":"4625"}'}}]},
            {"role": "tool", "tool_call_id": "call_1", "name": "count_events",
             "content": '{"total": 6}'},
        ])

        for message in messages:
            self.assertEqual(set(message.keys()), {"role", "content"})

    def test_system_messages_are_collected_in_order_not_overwritten(self):
        system, messages = _anthropic_messages_from_openai([
            {"role": "system", "content": "role block"},
            {"role": "system", "content": "token budget block"},
            {"role": "user", "content": "question"},
            {"role": "system", "content": "SYNTHESIS_REQUIRED"},
        ])

        self.assertEqual([block["text"] for block in system],
                         ["role block", "token budget block", "SYNTHESIS_REQUIRED"])
        self.assertTrue(all(message["role"] != "system" for message in messages))

    def test_tool_calls_become_tool_use_blocks(self):
        _, messages = _anthropic_messages_from_openai([
            {"role": "user", "content": "question"},
            {"role": "assistant", "content": "", "tool_calls": [{
                "id": "call_1", "type": "function",
                "function": {"name": "count_events", "arguments": '{"event_id":"4625"}'}}]},
        ])

        block = messages[-1]["content"][0]
        self.assertEqual(messages[-1]["role"], "assistant")
        self.assertEqual(block["type"], "tool_use")
        self.assertEqual(block["id"], "call_1")
        self.assertEqual(block["name"], "count_events")
        self.assertEqual(block["input"], {"event_id": "4625"})

    def test_tool_results_become_user_tool_result_blocks(self):
        _, messages = _anthropic_messages_from_openai([
            {"role": "user", "content": "question"},
            {"role": "assistant", "content": "", "tool_calls": [{
                "id": "call_1", "type": "function",
                "function": {"name": "count_events", "arguments": "{}"}}]},
            {"role": "tool", "tool_call_id": "call_1", "name": "count_events",
             "content": '{"total": 6}'},
        ])

        result_message = messages[-1]
        self.assertEqual(result_message["role"], "user")
        self.assertEqual(result_message["content"][0]["type"], "tool_result")
        self.assertEqual(result_message["content"][0]["tool_use_id"], "call_1")

    def test_parallel_tool_results_share_one_user_turn(self):
        _, messages = _anthropic_messages_from_openai([
            {"role": "user", "content": "question"},
            {"role": "assistant", "content": "", "tool_calls": [
                {"id": "call_1", "type": "function",
                 "function": {"name": "count_events", "arguments": "{}"}},
                {"id": "call_2", "type": "function",
                 "function": {"name": "query_events", "arguments": "{}"}},
            ]},
            {"role": "tool", "tool_call_id": "call_1", "name": "count_events", "content": "{}"},
            {"role": "tool", "tool_call_id": "call_2", "name": "query_events", "content": "{}"},
        ])

        self.assertEqual(messages[-1]["role"], "user")
        self.assertEqual(len(messages[-1]["content"]), 2)
        self.assertEqual(
            [block["tool_use_id"] for block in messages[-1]["content"]],
            ["call_1", "call_2"],
        )

    def test_turns_alternate_and_open_on_the_user(self):
        _, messages = _anthropic_messages_from_openai([
            {"role": "system", "content": "system"},
            {"role": "assistant", "content": "resuming after an approval"},
            {"role": "tool", "tool_call_id": "call_1", "name": "count_events", "content": "{}"},
            {"role": "user", "content": "and then?"},
        ])

        self.assertEqual(messages[0]["role"], "user")
        roles = [message["role"] for message in messages]
        for earlier, later in zip(roles, roles[1:]):
            self.assertNotEqual(earlier, later, f"consecutive {earlier} turns: {roles}")

    def test_empty_assistant_turns_are_dropped(self):
        _, messages = _anthropic_messages_from_openai([
            {"role": "user", "content": "question"},
            {"role": "assistant", "content": ""},
            {"role": "user", "content": "still there?"},
        ])

        self.assertTrue(all(message["content"] for message in messages))
        self.assertEqual(len(messages), 1)
        self.assertEqual(len(messages[0]["content"]), 2)

    def test_malformed_tool_arguments_do_not_raise(self):
        _, messages = _anthropic_messages_from_openai([
            {"role": "user", "content": "question"},
            {"role": "assistant", "content": "", "tool_calls": [{
                "id": "call_1", "type": "function",
                "function": {"name": "count_events", "arguments": "{not json"}}]},
        ])

        self.assertEqual(messages[-1]["content"][0]["input"], {})

    def test_a_full_agent_turn_is_json_serializable(self):
        system, messages = _anthropic_messages_from_openai([
            {"role": "system", "content": "role", "cache_control": {"type": "ephemeral"}},
            {"role": "system", "content": "TOKEN_BUDGET"},
            {"role": "user", "content": "does this look like password spraying?"},
            {"role": "assistant", "content": "", "tool_calls": [{
                "id": "call_1", "type": "function",
                "function": {"name": "count_events", "arguments": '{"event_id":"4625"}'}}]},
            {"role": "tool", "tool_call_id": "call_1", "name": "count_events",
             "content": '{"total": 412}'},
            {"role": "assistant", "content": "412 failed logons across 60 accounts."},
        ])

        payload = {"model": "claude-sonnet-4-6", "system": system,
                   "messages": messages, "max_tokens": 4096}
        self.assertIsInstance(json.dumps(payload), str)
        self.assertEqual([m["role"] for m in messages], ["user", "assistant", "user", "assistant"])


if __name__ == "__main__":
    unittest.main()
