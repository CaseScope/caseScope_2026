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
            {
                "type": "function",
                "function": {
                    "name": "count_events",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "event_id": {"type": "string"},
                            "host": {"type": "string"},
                        },
                        "required": [],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "search_logs",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "search": {"type": "string"},
                        },
                        "required": [],
                    },
                },
            },
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

    def test_tool_policy_marks_sensitive_surfaces_and_model_provenance(self):
        chat_agent = self._load_chat_agent()

        safe_tier, safe_provenance = chat_agent._resolve_tool_policy("count_events")
        sensitive_tier, sensitive_provenance = chat_agent._resolve_tool_policy("search_memory")

        self.assertEqual(safe_tier, chat_agent.ToolTier.READ_SAFE)
        self.assertEqual(sensitive_tier, chat_agent.ToolTier.READ_SENSITIVE)
        self.assertEqual(safe_provenance, chat_agent.Provenance.MODEL_SYNTHESIZED)
        self.assertEqual(sensitive_provenance, chat_agent.Provenance.MODEL_SYNTHESIZED)

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

    def test_chat_stream_reused_stub_preserves_original_provenance(self):
        chat_agent = self._load_chat_agent()
        chat_agent.get_case_context = lambda case_id: {
            "case_id": case_id,
            "case_name": "Reuse Provenance Case",
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

        def fake_execute_tool(name, case_id, params):
            return {
                "total_matches": 1,
                "artifacts": [{"summary": "Suspicious browser artifact"}],
                "_provenance": {"emitted_provenance": "ELEVATED_RISK"},
            }

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
                    "content": "Reused the earlier artifact lookup.",
                },
                "done": True,
            }

        chat_agent._stream_llm_chat = fake_stream

        events = []
        for raw_event in chat_agent.chat_stream(
            97,
            [{"role": "user", "content": "Count 4625 events twice if needed."}],
            "conv-reuse-provenance",
        ):
            if raw_event.startswith("data: "):
                events.append(json.loads(raw_event[6:].strip()))

        tool_results = [event for event in events if event.get("type") == "tool_result"]
        self.assertEqual(len(tool_results), 2)
        self.assertEqual(tool_results[0]["provenance"], "ELEVATED_RISK")
        self.assertEqual(tool_results[1]["provenance"], "ELEVATED_RISK")

    def test_chat_stream_passes_conversation_id_to_dispatcher_session_scope(self):
        chat_agent = self._load_chat_agent()
        chat_agent.get_case_context = lambda case_id: {
            "case_id": case_id,
            "case_name": "Session Scope Case",
            "description": "",
            "hosts": ["WKSTN-04"],
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

        dispatcher_calls = []

        class RecordingDispatcher:
            def execute(self, **kwargs):
                dispatcher_calls.append(kwargs)
                return chat_agent.ToolResultBlock(
                    tool_name=kwargs["tool_name"],
                    payload={"total": 1},
                )

        chat_agent._TOOL_DISPATCHER = RecordingDispatcher()

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

            yield {
                "message": {
                    "role": "assistant",
                    "content": "Done.",
                },
                "done": True,
            }

        chat_agent._stream_llm_chat = fake_stream

        list(chat_agent.chat_stream(
            93,
            [{"role": "user", "content": "Check failed logons."}],
            "conv-session-scope",
        ))

        self.assertEqual(len(dispatcher_calls), 1)
        self.assertEqual(dispatcher_calls[0]["session_id"], "conv-session-scope")

    def test_chat_stream_stops_after_interrupt_tool_result(self):
        chat_agent = self._load_chat_agent()
        chat_agent.get_case_context = lambda case_id: {
            "case_id": case_id,
            "case_name": "Interrupt Case",
            "description": "",
            "hosts": ["WKSTN-05"],
            "timezone": "UTC",
            "analysis_summary": {},
            "ai_synthesis": {},
        }
        chat_agent._capture_conversation_context = lambda case_context: chat_agent.ConversationContext(
            license_tier="activated",
            enabled_features=("ai_reasoning",),
            enabled_ti_sources=(),
            available_agents=("search_memory",),
            model_selection="unit-test-model",
        )

        class InterruptingDispatcher:
            def execute(self, **kwargs):
                return chat_agent.ToolResultBlock.interrupt(
                    tool_name=kwargs["tool_name"],
                    tier=kwargs["tier"],
                    provenance=kwargs["provenance"],
                    permission=chat_agent.PermissionResult(
                        allowed=False,
                        category="interrupt",
                        reason="READ_SENSITIVE requires analyst approval",
                        cacheable=True,
                    ),
                )

        chat_agent._TOOL_DISPATCHER = InterruptingDispatcher()

        stream_calls = {"count": 0}

        def fake_stream(messages, tools=None):
            stream_calls["count"] += 1
            yield {
                "message": {
                    "role": "assistant",
                    "tool_calls": [{
                        "id": "call-1",
                        "type": "function",
                        "function": {
                            "name": "search_memory",
                            "arguments": '{"search":"powershell"}',
                        },
                    }],
                },
                "done": True,
            }

        chat_agent._stream_llm_chat = fake_stream

        events = []
        for raw_event in chat_agent.chat_stream(
            94,
            [{"role": "user", "content": "Search memory for powershell."}],
            "conv-interrupt",
        ):
            if raw_event.startswith("data: "):
                events.append(json.loads(raw_event[6:].strip()))

        self.assertEqual(stream_calls["count"], 1)
        tool_results = [event for event in events if event.get("type") == "tool_result"]
        self.assertEqual(len(tool_results), 1)
        self.assertEqual(tool_results[0]["status"], "interrupt")
        self.assertEqual(tool_results[0]["tier"], "READ_SENSITIVE")
        self.assertEqual(tool_results[0]["provenance"], "MODEL_SYNTHESIZED")
        self.assertEqual(tool_results[0]["permission"]["category"], "interrupt")
        self.assertEqual(tool_results[0]["pending_tool_approval"]["tool_name"], "search_memory")
        self.assertEqual(tool_results[0]["pending_tool_approval"]["tool_call_id"], "call-1")
        self.assertEqual(tool_results[0]["pending_tool_approval"]["params"], {"search": "powershell"})
        done_events = [event for event in events if event.get("type") == "done"]
        self.assertEqual(done_events[0]["pending_tool_approval"]["tool_name"], "search_memory")

    def test_chat_stream_executes_tool_approval_before_model_round(self):
        chat_agent = self._load_chat_agent()
        chat_agent.get_case_context = lambda case_id: {
            "case_id": case_id,
            "case_name": "Approval Resume Case",
            "description": "",
            "hosts": ["WKSTN-06"],
            "timezone": "UTC",
            "analysis_summary": {},
            "ai_synthesis": {},
        }
        chat_agent._capture_conversation_context = lambda case_context: chat_agent.ConversationContext(
            license_tier="activated",
            enabled_features=("ai_reasoning",),
            enabled_ti_sources=(),
            available_agents=("search_memory",),
            model_selection="unit-test-model",
        )

        dispatcher_calls = []

        class ApprovingDispatcher:
            def execute(self, **kwargs):
                dispatcher_calls.append(kwargs)
                return chat_agent.ToolResultBlock(
                    tool_name=kwargs["tool_name"],
                    payload={"total": 2, "groups": [{"value": "WKSTN-06", "count": 2}]},
                )

        chat_agent._TOOL_DISPATCHER = ApprovingDispatcher()

        stream_calls = {"count": 0}

        def fake_stream(messages, tools=None):
            stream_calls["count"] += 1
            yield {
                "message": {
                    "role": "assistant",
                    "content": "The memory search found two hits.",
                },
                "done": True,
            }

        chat_agent._stream_llm_chat = fake_stream

        events = []
        persisted = []
        for raw_event in chat_agent.chat_stream(
            95,
            [],
            "conv-approval-resume",
            tool_approval={
                "tool_name": "search_memory",
                "tool_call_id": "call-approve-1",
                "params": {"search": "powershell"},
                "decision": "allow",
                "reason": "Approved for this session",
            },
            on_complete=lambda history: persisted.extend(history),
        ):
            if raw_event.startswith("data: "):
                events.append(json.loads(raw_event[6:].strip()))

        self.assertEqual(stream_calls["count"], 1)
        self.assertEqual(len(dispatcher_calls), 1)
        self.assertEqual(dispatcher_calls[0]["analyst_decision"], "allow")
        self.assertEqual(dispatcher_calls[0]["session_id"], "conv-approval-resume")
        self.assertEqual(dispatcher_calls[0]["params"], {"search": "powershell"})
        tool_results = [event for event in events if event.get("type") == "tool_result"]
        self.assertEqual(tool_results[0]["status"], "completed")
        self.assertEqual(tool_results[0]["tier"], "READ_SAFE")
        self.assertEqual(tool_results[0]["provenance"], "ANALYST")
        done_events = [event for event in events if event.get("type") == "done"]
        self.assertIsNone(done_events[0]["pending_tool_approval"])
        self.assertTrue(any(message.get("role") == "user" and "[TOOL_APPROVAL]" in message.get("content", "") for message in persisted))

    def test_chat_stream_rejects_feature_gated_tool_with_structured_status(self):
        chat_agent = self._load_chat_agent()
        chat_agent.get_case_context = lambda case_id: {
            "case_id": case_id,
            "case_name": "Feature Gate Case",
            "description": "",
            "hosts": ["WKSTN-08"],
            "timezone": "UTC",
            "analysis_summary": {},
            "ai_synthesis": {},
        }
        chat_agent._capture_conversation_context = lambda case_context: chat_agent.ConversationContext(
            license_tier="activated",
            enabled_features=("ai_reasoning",),
            enabled_ti_sources=(),
            available_agents=("lookup_threat_intel",),
            model_selection="unit-test-model",
        )
        chat_agent._TOOL_DISPATCHER = chat_agent.ToolDispatcher(
            lambda tool_name, case_id, params: {"should_not_run": True},
            feature_gate=lambda tool_name, case_id, params: chat_agent.PermissionResult(
                allowed=False,
                category="feature unavailable",
                reason="Threat intelligence lookup is not currently available",
                cacheable=False,
            ) if tool_name == "lookup_threat_intel" else None,
        )

        stream_calls = {"count": 0}

        def fake_stream(messages, tools=None):
            stream_calls["count"] += 1
            yield {
                "message": {
                    "role": "assistant",
                    "tool_calls": [{
                        "id": "call-ti-1",
                        "type": "function",
                        "function": {
                            "name": "lookup_threat_intel",
                            "arguments": '{"query_type":"ioc","value":"1.2.3.4"}',
                        },
                    }],
                },
                "done": True,
            }

        chat_agent._stream_llm_chat = fake_stream

        events = []
        for raw_event in chat_agent.chat_stream(
            96,
            [{"role": "user", "content": "Check threat intel for 1.2.3.4"}],
            "conv-feature-gate",
        ):
            if raw_event.startswith("data: "):
                events.append(json.loads(raw_event[6:].strip()))

        self.assertEqual(stream_calls["count"], 1)
        tool_results = [event for event in events if event.get("type") == "tool_result"]
        self.assertEqual(len(tool_results), 1)
        self.assertEqual(tool_results[0]["status"], "rejected")
        self.assertEqual(tool_results[0]["tier"], "READ_SENSITIVE")
        self.assertEqual(tool_results[0]["provenance"], "MODEL_SYNTHESIZED")
        self.assertEqual(tool_results[0]["permission"]["category"], "feature unavailable")
        done_events = [event for event in events if event.get("type") == "done"]
        self.assertIsNone(done_events[0]["pending_tool_approval"])

    def test_chat_stream_rejects_unknown_tool_arguments_before_dispatch(self):
        chat_agent = self._load_chat_agent()
        chat_agent.get_case_context = lambda case_id: {
            "case_id": case_id,
            "case_name": "Schema Validation Case",
            "description": "",
            "hosts": ["WKSTN-09"],
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

        dispatcher_calls = []

        class RecordingDispatcher:
            def execute(self, **kwargs):
                dispatcher_calls.append(kwargs)
                return chat_agent.ToolResultBlock(
                    tool_name=kwargs["tool_name"],
                    payload={"total": 1},
                )

        chat_agent._TOOL_DISPATCHER = RecordingDispatcher()

        def fake_stream(messages, tools=None):
            yield {
                "message": {
                    "role": "assistant",
                    "tool_calls": [{
                        "id": "call-invalid-extra",
                        "type": "function",
                        "function": {
                            "name": "count_events",
                            "arguments": '{"event_id":"4625","bogus":"x"}',
                        },
                    }],
                },
                "done": True,
            }

        chat_agent._stream_llm_chat = fake_stream

        events = []
        for raw_event in chat_agent.chat_stream(
            98,
            [{"role": "user", "content": "Count failed logons."}],
            "conv-invalid-extra",
        ):
            if raw_event.startswith("data: "):
                events.append(json.loads(raw_event[6:].strip()))

        self.assertEqual(dispatcher_calls, [])
        tool_results = [event for event in events if event.get("type") == "tool_result"]
        self.assertEqual(len(tool_results), 1)
        self.assertEqual(tool_results[0]["status"], "rejected")
        self.assertEqual(tool_results[0]["provenance"], "MODEL_SYNTHESIZED")
        self.assertEqual(tool_results[0]["permission"]["category"], "invalid tool arguments")
        self.assertIn("bogus", tool_results[0]["result_preview"])

    def test_tool_approval_rejects_type_mismatched_arguments_before_dispatch(self):
        chat_agent = self._load_chat_agent()
        chat_agent.get_case_context = lambda case_id: {
            "case_id": case_id,
            "case_name": "Approval Schema Case",
            "description": "",
            "hosts": ["WKSTN-10"],
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

        dispatcher_calls = []

        class RecordingDispatcher:
            def execute(self, **kwargs):
                dispatcher_calls.append(kwargs)
                return chat_agent.ToolResultBlock(
                    tool_name=kwargs["tool_name"],
                    payload={"total": 1},
                )

        chat_agent._TOOL_DISPATCHER = RecordingDispatcher()
        chat_agent._stream_llm_chat = lambda messages, tools=None: iter([{
            "message": {"role": "assistant", "content": "Done."},
            "done": True,
        }])

        events = []
        for raw_event in chat_agent.chat_stream(
            99,
            [],
            "conv-approval-invalid",
            tool_approval={
                "tool_name": "count_events",
                "tool_call_id": "call-approval-invalid",
                "params": {"event_id": 4625},
                "decision": "allow",
                "reason": "Approved",
            },
        ):
            if raw_event.startswith("data: "):
                events.append(json.loads(raw_event[6:].strip()))

        self.assertEqual(dispatcher_calls, [])
        tool_results = [event for event in events if event.get("type") == "tool_result"]
        self.assertEqual(tool_results[0]["status"], "rejected")
        self.assertEqual(tool_results[0]["permission"]["category"], "invalid tool arguments")
        self.assertEqual(tool_results[0]["provenance"], "MODEL_SYNTHESIZED")
        done_events = [event for event in events if event.get("type") == "done"]
        self.assertIsNone(done_events[0]["pending_tool_approval"])


if __name__ == "__main__":
    unittest.main()
