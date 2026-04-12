import importlib.util
import json
import sys
import types
import unittest


def _load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class ChatAgentRuntimeFlowContractTestCase(unittest.TestCase):
    def _load_chat_agent(self):
        fake_utils = types.ModuleType("utils")
        fake_utils.__path__ = []
        fake_chat_tools = types.ModuleType("utils.chat_tools")
        fake_chat_tools.TOOL_DEFINITIONS = [
            {"type": "function", "function": {"name": "count_events"}},
            {"type": "function", "function": {"name": "search_logs"}},
        ]
        fake_chat_tools.execute_tool = lambda *args, **kwargs: {}

        previous_utils = sys.modules.get("utils")
        previous_chat_tools = sys.modules.get("utils.chat_tools")
        sys.modules["utils"] = fake_utils
        sys.modules["utils.chat_tools"] = fake_chat_tools

        try:
            return _load_module(
                "chat_agent_runtime_flow_test",
                "/opt/casescope/utils/chat_agent.py",
            )
        finally:
            if previous_utils is not None:
                sys.modules["utils"] = previous_utils
            else:
                sys.modules.pop("utils", None)

            if previous_chat_tools is not None:
                sys.modules["utils.chat_tools"] = previous_chat_tools
            else:
                sys.modules.pop("utils.chat_tools", None)

    def test_chat_stream_builds_ordered_attachments_and_single_cache_marker(self):
        chat_agent = self._load_chat_agent()
        chat_agent.get_case_context = lambda case_id: {
            "case_id": case_id,
            "case_name": "Attachment Case",
            "description": "Review suspicious browser downloads.",
            "hosts": ["WKSTN-01"],
            "timezone": "America/New_York",
            "analysis_summary": {
                "pattern_matches_found": 2,
                "attack_chains_found": 1,
                "ioc_timeline_entries": 7,
            },
            "ai_synthesis": {},
        }
        chat_agent._capture_conversation_context = lambda case_context: chat_agent.ConversationContext(
            license_tier="activated",
            enabled_features=("ai_reasoning", "threat_intel_enrichment"),
            enabled_ti_sources=("opencti",),
            available_agents=("count_events", "search_logs"),
            model_selection="unit-test-model",
        )

        captured_messages = []

        def fake_stream(messages, tools=None):
            captured_messages.extend(messages)
            yield {
                "message": {
                    "role": "assistant",
                    "content": "The downloads are isolated to WKSTN-01.",
                },
                "done": True,
            }

        chat_agent._stream_llm_chat = fake_stream

        list(chat_agent.chat_stream(
            88,
            [{"role": "user", "content": "What do the downloads show?"}],
            "conv-attachments",
        ))

        self.assertTrue(captured_messages)
        cache_markers = [message for message in captured_messages if message.get("cache_control")]
        self.assertEqual(len(cache_markers), 1)
        self.assertEqual(cache_markers[0]["cache_control"], {"type": "ephemeral"})

        user_message = next(
            message for message in reversed(captured_messages)
            if message.get("role") == "user"
        )
        content = user_message["content"]
        required_sections = [
            "[CASE_STATIC_CONTEXT]",
            "[LICENSE_CAPABILITIES]",
            "[AVAILABLE_ARTIFACTS]",
            "[FINDING_SUMMARY]",
            "[USER_QUERY]",
        ]
        for section in required_sections:
            self.assertIn(section, content)

        section_positions = [content.index(section) for section in required_sections]
        self.assertEqual(section_positions, sorted(section_positions))

    def test_build_request_messages_references_reused_tool_results(self):
        chat_agent = self._load_chat_agent()
        conversation_context = chat_agent.ConversationContext(
            license_tier="activated",
            enabled_features=("ai_reasoning",),
            enabled_ti_sources=("opencti",),
            available_agents=("count_events",),
            model_selection="unit-test-model",
        )
        case_context = {
            "case_id": 91,
            "case_name": "Cache Ref Case",
            "description": "",
            "hosts": ["WKSTN-02"],
            "timezone": "UTC",
            "analysis_summary": {},
            "ai_synthesis": {},
        }
        repeated_payload = json.dumps({"total": 4, "groups": [{"value": "WKSTN-02", "count": 4}]})
        full_messages = [
            {"role": "system", "content": "system"},
            {"role": "user", "content": "Summarize failed logons"},
            {
                "role": "tool",
                "tool_call_id": "call-1",
                "name": "count_events",
                "content": repeated_payload,
            },
            {
                "role": "tool",
                "tool_call_id": "call-2",
                "name": "count_events",
                "content": repeated_payload,
            },
            {"role": "assistant", "content": "Tool results received."},
        ]

        request_messages = chat_agent._build_request_messages(
            full_messages,
            case_context,
            conversation_context,
        )

        cache_refs = []
        for message in request_messages:
            if message.get("role") != "tool":
                continue
            payload = json.loads(message.get("content") or "{}")
            if "cache_reference" in payload:
                cache_refs.append(payload["cache_reference"])

        self.assertEqual(len(cache_refs), 1)
        self.assertEqual(cache_refs[0]["tool_name"], "count_events")
        self.assertEqual(cache_refs[0]["first_tool_call_id"], "call-1")

    def test_chat_stream_reuses_identical_tool_calls_with_stub_payload(self):
        chat_agent = self._load_chat_agent()
        chat_agent.get_case_context = lambda case_id: {
            "case_id": case_id,
            "case_name": "Reuse Stub Case",
            "description": "",
            "hosts": ["WKSTN-03"],
            "timezone": "UTC",
            "analysis_summary": {},
            "ai_synthesis": {},
        }
        chat_agent._capture_conversation_context = lambda case_context: chat_agent.ConversationContext(
            license_tier="activated",
            enabled_features=("ai_reasoning",),
            enabled_ti_sources=(),
            available_agents=("count_events",),
            model_selection="unit-test-model",
        )

        executed = []

        def fake_execute_tool(name, case_id, params):
            executed.append((name, case_id, params))
            return {"total": 3, "groups": [{"value": "WKSTN-03", "count": 3}]}

        chat_agent.execute_tool = fake_execute_tool
        chat_agent._TOOL_DISPATCHER = chat_agent.ToolDispatcher(chat_agent.execute_tool)

        stream_round = {"count": 0}

        def fake_stream(messages, tools=None):
            if stream_round["count"] == 0:
                stream_round["count"] += 1
                yield {
                    "message": {
                        "role": "assistant",
                        "tool_calls": [{
                            "id": "call-1",
                            "type": "function",
                            "function": {
                                "name": "count_events",
                                "arguments": '{"event_id":"4625"}',
                            },
                        }],
                    },
                    "done": True,
                }
                return

            if stream_round["count"] == 1:
                stream_round["count"] += 1
                yield {
                    "message": {
                        "role": "assistant",
                        "tool_calls": [{
                            "id": "call-2",
                            "type": "function",
                            "function": {
                                "name": "count_events",
                                "arguments": '{"event_id":"4625"}',
                            },
                        }],
                    },
                    "done": True,
                }
                return

            yield {
                "message": {
                    "role": "assistant",
                    "content": "Reused the earlier failed-logon count.",
                },
                "done": True,
            }

        chat_agent._stream_llm_chat = fake_stream

        events = []
        for raw_event in chat_agent.chat_stream(
            92,
            [{"role": "user", "content": "Check failed logons twice if needed."}],
            "conv-reuse-stub",
        ):
            if raw_event.startswith("data: "):
                events.append(json.loads(raw_event[6:].strip()))

        self.assertEqual(len(executed), 1)
        tool_results = [event for event in events if event.get("type") == "tool_result"]
        self.assertEqual(len(tool_results), 2)
        self.assertIn("Total: 3", tool_results[0]["result_preview"])
        self.assertIn("reused cached result", tool_results[1]["result_preview"])


if __name__ == "__main__":
    unittest.main()
