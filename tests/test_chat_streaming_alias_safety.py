"""Contract tests for alias-safe token streaming.

Chat streams the answer as it arrives. Two things must never break: an alias
token must not be split across frames (which would leak an unrehydrated alias to
the browser), and text the model narrated before calling a tool must not remain
on screen.
"""

import importlib.util
import json
import os
import sys
import types
import unittest

os.environ.setdefault("SECRET_KEY", "test-secret")

ALIASES = {
    "HOSTNAME_0001": "FIN-WKSTN-07",
    "USERNAME_0012": "jdoe.admin",
    "EXTERNAL_IPV4_0003": "203.0.113.44",
    "HOSTNAME_0002$": "DC01$",
}


def _load_chat_agent():
    fake_utils = types.ModuleType("utils")
    fake_utils.__path__ = []
    fake_chat_tools = types.ModuleType("utils.chat_tools")
    fake_chat_tools.TOOL_DEFINITIONS = [{
        "type": "function",
        "function": {
            "name": "count_events",
            "description": "Count case events.",
            "parameters": {"type": "object", "properties": {"event_id": {"type": "string"}},
                           "required": []},
        },
    }]
    fake_chat_tools.execute_tool = lambda name, case_id, params: {
        "total": 6, "_provenance": {"emitted_provenance": "SYSTEM_DERIVED"}
    }

    previous = {key: sys.modules.get(key) for key in ("utils", "utils.chat_tools")}
    sys.modules["utils"] = fake_utils
    sys.modules["utils.chat_tools"] = fake_chat_tools
    try:
        spec = importlib.util.spec_from_file_location(
            "chat_agent_streaming_test", "/opt/casescope/utils/chat_agent.py"
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules["chat_agent_streaming_test"] = module
        spec.loader.exec_module(module)
    finally:
        for key, value in previous.items():
            if value is not None:
                sys.modules[key] = value
            else:
                sys.modules.pop(key, None)

    def fake_rehydrator(_case_id):
        def rehydrate(text):
            for alias, original in sorted(ALIASES.items(), key=lambda kv: -len(kv[0])):
                text = text.replace(alias, original)
            return text
        return rehydrate

    module.build_display_rehydrator = fake_rehydrator
    module.get_provider_descriptor = lambda function: {
        "provider_type": "openai", "provider_display": "OpenAI",
        "model": "unit-test-model", "is_local": False,
    }
    module.get_case_context = lambda case_id: {
        "case_id": case_id, "case_name": "Streaming Case", "description": "",
        "hosts": ["FIN-WKSTN-07"], "timezone": "UTC",
        "analysis_summary": {}, "ai_synthesis": {},
    }
    module._capture_conversation_context = lambda case_context: module.ConversationContext(
        license_tier="activated", enabled_features=("ai_reasoning",), enabled_ti_sources=(),
        available_agents=("count_events",), model_selection="unit-test-model",
    )
    return module


def _chunks(text, size):
    return [text[index:index + size] for index in range(0, len(text), size)]


class AliasSafeStreamTestCase(unittest.TestCase):
    def setUp(self):
        self.chat_agent = _load_chat_agent()

    def _stream_text(self, text, chunk_size):
        stream = self.chat_agent._AliasSafeDisplayStream(1)
        released = [stream.feed(chunk) for chunk in _chunks(text, chunk_size)]
        released.append(stream.flush())
        return [part for part in released if part], "".join(released)

    def test_aliases_are_rehydrated_at_every_chunk_size(self):
        text = ("Logon failures on HOSTNAME_0001 from EXTERNAL_IPV4_0003 "
                "by USERNAME_0012, plus machine account HOSTNAME_0002$ activity.")
        expected = ("Logon failures on FIN-WKSTN-07 from 203.0.113.44 "
                    "by jdoe.admin, plus machine account DC01$ activity.")

        for chunk_size in range(1, 25):
            with self.subTest(chunk_size=chunk_size):
                _, rendered = self._stream_text(text, chunk_size)
                self.assertEqual(rendered, expected)

    def test_no_frame_ever_contains_a_partial_alias(self):
        text = "Host HOSTNAME_0001 and user USERNAME_0012 were involved."
        for chunk_size in range(1, 25):
            with self.subTest(chunk_size=chunk_size):
                frames, _ = self._stream_text(text, chunk_size)
                for frame in frames:
                    for alias in ALIASES:
                        # A frame may contain the rehydrated value, never a
                        # fragment of the alias token itself.
                        for cut in range(3, len(alias)):
                            self.assertNotIn(
                                alias[:cut] + "|", frame + "|",
                                f"frame {frame!r} ends inside alias {alias}",
                            )

    def test_text_without_aliases_streams_progressively(self):
        frames, rendered = self._stream_text("The evidence shows lateral movement.", 4)
        self.assertEqual(rendered, "The evidence shows lateral movement.")
        self.assertGreater(len(frames), 1, "output should arrive in multiple frames")

    def test_discard_drops_held_back_text(self):
        stream = self.chat_agent._AliasSafeDisplayStream(1)
        stream.feed("I will check HOSTNAME_000")
        stream.discard()
        self.assertEqual(stream.flush(), "")


class StreamingTurnContractTestCase(unittest.TestCase):
    def setUp(self):
        self.chat_agent = _load_chat_agent()

    def _run(self, stream_fn, **kwargs):
        self.chat_agent._stream_llm_chat = stream_fn
        events = list(self.chat_agent.chat_stream(
            1, [{"role": "user", "content": "what happened?"}], "conv-stream", **kwargs
        ))
        return [json.loads(event[6:]) for event in events if event.startswith("data: ")]

    def test_an_answer_arrives_in_multiple_frames_and_is_committed(self):
        answer = "Six failed logons on HOSTNAME_0001 between 03:00 and 03:20, all from USERNAME_0012."

        def stream(messages, tools=None, case_id=None):
            for chunk in _chunks(answer, 7):
                yield {"message": {"role": "assistant", "content": chunk}}
            yield {"message": {"role": "assistant", "content": ""}, "done": True}

        events = self._run(stream)
        tokens = [event for event in events if event["type"] == "token"]

        self.assertGreater(len(tokens), 1, "the answer should stream, not arrive at once")
        self.assertTrue(all(token["provisional"] for token in tokens))
        self.assertEqual(
            "".join(token["content"] for token in tokens),
            "Six failed logons on FIN-WKSTN-07 between 03:00 and 03:20, all from jdoe.admin.",
        )
        self.assertEqual(
            [event["type"] for event in events].count("token_commit"), 1
        )

    def test_narration_before_a_tool_call_is_retracted(self):
        rounds = {"count": 0}

        def stream(messages, tools=None, case_id=None):
            rounds["count"] += 1
            if rounds["count"] == 1:
                for chunk in _chunks("Let me query the logs for you. ", 6):
                    yield {"message": {"role": "assistant", "content": chunk}}
                yield {"message": {"role": "assistant", "content": "", "tool_calls": [{
                    "index": 0, "id": "c1", "type": "function",
                    "function": {"name": "count_events", "arguments": '{"event_id":"4625"}'}}]},
                    "done": True}
                return
            yield {"message": {"role": "assistant", "content": "There were 6 failed logons."},
                   "done": True}

        events = self._run(stream)
        types = [event["type"] for event in events]
        self.assertIn("token_retract", types)
        self.assertLess(types.index("token_retract"), types.index("tool_start"))

        retract_index = types.index("token_retract")
        narration = "".join(
            event["content"] for event in events[:retract_index] if event["type"] == "token"
        )
        self.assertIn("Let me query the logs", narration)

        # Everything after the retraction is the real answer.
        committed = "".join(
            event["content"] for event in events[retract_index:] if event["type"] == "token"
        )
        self.assertEqual(committed, "There were 6 failed logons.")

    def test_content_after_a_tool_call_in_the_same_round_is_not_streamed(self):
        rounds = {"count": 0}

        def stream(messages, tools=None, case_id=None):
            rounds["count"] += 1
            if rounds["count"] == 1:
                yield {"message": {"role": "assistant", "content": "", "tool_calls": [{
                    "index": 0, "id": "c1", "type": "function",
                    "function": {"name": "count_events", "arguments": '{"event_id":"4625"}'}}]}}
                yield {"message": {"role": "assistant", "content": "trailing narration"},
                       "done": True}
                return
            yield {"message": {"role": "assistant", "content": "Final answer."}, "done": True}

        events = self._run(stream)
        streamed = "".join(event["content"] for event in events if event["type"] == "token")
        self.assertNotIn("trailing narration", streamed)
        self.assertIn("Final answer.", streamed)


if __name__ == "__main__":
    unittest.main()
