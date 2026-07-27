"""Contract tests for chat tool-failure recovery.

A malformed or gated tool call must not end the analyst's turn. The model is
given the failure back with actionable guidance and a bounded retry budget,
while genuine human decisions (analyst denial, approval interrupt) stay
terminal.
"""

import importlib.util
import json
import os
import sys
import types
import unittest

os.environ.setdefault("SECRET_KEY", "test-secret")


def _load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _tool_call_chunk(name, arguments, call_id="call-1"):
    return {
        "message": {
            "role": "assistant",
            "content": "",
            "tool_calls": [{
                "index": 0,
                "id": call_id,
                "type": "function",
                "function": {"name": name, "arguments": json.dumps(arguments)},
            }],
        },
        "done": True,
    }


class _ChatAgentHarness:
    """Loads the chat agent against a small fake tool registry."""

    def _load_chat_agent(self, executor=None):
        fake_utils = types.ModuleType("utils")
        fake_utils.__path__ = []
        fake_chat_tools = types.ModuleType("utils.chat_tools")
        fake_chat_tools.TOOL_DEFINITIONS = [
            {
                "type": "function",
                "function": {
                    "name": "count_events",
                    "description": "Count case events.",
                    "parameters": {
                        "type": "object",
                        "properties": {"event_id": {"type": "string"}},
                        "required": [],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "search_memory",
                    "description": "Search memory artifacts.",
                    "parameters": {
                        "type": "object",
                        "properties": {"search": {"type": "string"}},
                        "required": ["search"],
                    },
                },
            },
        ]
        fake_chat_tools.execute_tool = executor or (
            lambda name, case_id, params: {
                "total": 42,
                "_provenance": {"emitted_provenance": "SYSTEM_DERIVED"},
            }
        )

        previous_utils = sys.modules.get("utils")
        previous_chat_tools = sys.modules.get("utils.chat_tools")
        sys.modules["utils"] = fake_utils
        sys.modules["utils.chat_tools"] = fake_chat_tools
        try:
            chat_agent = _load_module(
                "chat_agent_recovery_test",
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

        chat_agent.get_provider_descriptor = lambda function: {
            "provider_type": "openai",
            "provider_display": "OpenAI",
            "model": "unit-test-model",
            "is_local": False,
        }
        chat_agent.get_case_context = lambda case_id: {
            "case_id": case_id,
            "case_name": "Recovery Case",
            "description": "",
            "hosts": ["WKSTN-01"],
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
        return chat_agent

    @staticmethod
    def _run(chat_agent, case_id=1, messages=None, **kwargs):
        persisted = []
        events = list(chat_agent.chat_stream(
            case_id,
            messages if messages is not None else [{"role": "user", "content": "q"}],
            "conv-recovery",
            on_complete=lambda history: persisted.append(history),
            **kwargs,
        ))
        parsed = [json.loads(event[6:]) for event in events if event.startswith("data: ")]
        return parsed, (persisted[-1] if persisted else None)


class ChatToolRecoveryContractTestCase(_ChatAgentHarness, unittest.TestCase):
    def test_invalid_arguments_are_returned_to_the_model_for_correction(self):
        chat_agent = self._load_chat_agent()
        calls = {"count": 0}

        def stream(messages, tools=None, case_id=None):
            calls["count"] += 1
            if calls["count"] == 1:
                yield _tool_call_chunk("count_events", {"bogus": "x"})
            elif calls["count"] == 2:
                yield _tool_call_chunk("count_events", {"event_id": "4625"}, call_id="call-2")
            else:
                yield {"message": {"role": "assistant", "content": "There were 42 failed logons."},
                       "done": True}

        chat_agent._stream_llm_chat = stream
        events, history = self._run(chat_agent)

        tool_results = [event for event in events if event["type"] == "tool_result"]
        self.assertEqual(tool_results[0]["status"], "rejected")
        self.assertTrue(tool_results[0]["recoverable"])
        self.assertEqual(tool_results[1]["status"], "completed")

        tokens = [event["content"] for event in events if event["type"] == "token"]
        self.assertIn("There were 42 failed logons.", tokens)
        self.assertIn(
            "There were 42 failed logons.",
            [message["content"] for message in history if message["role"] == "assistant"],
        )

    def test_retry_guidance_names_the_allowed_arguments(self):
        chat_agent = self._load_chat_agent()
        result = {
            "status": "rejected",
            "permission": {"category": "invalid tool arguments"},
            "error": "Unknown arguments for 'count_events': bogus",
        }
        annotated = chat_agent._annotate_recoverable_result(
            result, tool_name="count_events", retries_remaining=2
        )

        self.assertTrue(annotated["recoverable"])
        self.assertIn("event_id", annotated["retry_guidance"])
        self.assertIn("count_events", annotated["retry_guidance"])

    def test_recovery_rounds_do_not_consume_the_productive_round_budget(self):
        chat_agent = self._load_chat_agent()
        calls = {"count": 0}

        def stream(messages, tools=None, case_id=None):
            calls["count"] += 1
            if calls["count"] == 1:
                yield _tool_call_chunk("count_events", {"bogus": "x"})
            elif calls["count"] == 2:
                yield _tool_call_chunk("count_events", {"event_id": "4625"}, call_id="call-2")
            else:
                yield {"message": {"role": "assistant", "content": "Answered."}, "done": True}

        chat_agent._stream_llm_chat = stream
        events, _ = self._run(chat_agent)

        done = next(event for event in events if event["type"] == "done")
        self.assertEqual(done["tool_rounds"], 1)

    def test_repeated_invalid_calls_are_bounded_by_the_retry_budget(self):
        chat_agent = self._load_chat_agent()
        calls = {"tool_enabled": 0, "synthesis": 0}

        def stream(messages, tools=None, case_id=None):
            if tools is None:
                calls["synthesis"] += 1
                yield {"message": {"role": "assistant", "content": "Could not run that tool."},
                       "done": True}
                return
            calls["tool_enabled"] += 1
            yield _tool_call_chunk("count_events", {"bogus": "x"})

        chat_agent._stream_llm_chat = stream
        events, _ = self._run(chat_agent)

        self.assertLessEqual(calls["tool_enabled"], chat_agent.MAX_TOOL_RECOVERY_ROUNDS)
        self.assertEqual(calls["synthesis"], 1)
        tool_results = [event for event in events if event["type"] == "tool_result"]
        self.assertIn("retry budget", tool_results[-1]["result_preview"])

    def test_structured_tool_error_is_not_treated_as_missing_provenance(self):
        chat_agent = self._load_chat_agent(
            executor=lambda name, case_id, params: {
                "success": False,
                "error": "time_start and time_end are required for search_network_logs",
                "logs": [],
                "total": 0,
                "coverage_status": "insufficient",
            }
        )
        calls = {"count": 0}

        def stream(messages, tools=None, case_id=None):
            calls["count"] += 1
            if calls["count"] == 1:
                yield _tool_call_chunk("count_events", {"event_id": "4625"})
            else:
                yield {"message": {"role": "assistant", "content": "I need a time window."},
                       "done": True}

        chat_agent._stream_llm_chat = stream
        events, _ = self._run(chat_agent)

        tool_result = next(event for event in events if event["type"] == "tool_result")
        self.assertEqual(tool_result["status"], "completed")
        self.assertIn("time_start and time_end are required", tool_result["result_preview"])

    def test_provider_error_still_persists_the_analyst_turn(self):
        chat_agent = self._load_chat_agent()
        chat_agent._stream_llm_chat = lambda messages, tools=None, case_id=None: iter([
            {"error": "Cannot connect to Ollama at http://localhost:11434"}
        ])

        events, history = self._run(
            chat_agent, messages=[{"role": "user", "content": "what happened?"}]
        )

        self.assertIn("error", [event["type"] for event in events])
        self.assertIsNotNone(history)
        self.assertIn(
            "what happened?",
            [message["content"] for message in history if message["role"] == "user"],
        )
        assistant_turns = [message["content"] for message in history if message["role"] == "assistant"]
        self.assertTrue(any("could not complete" in turn for turn in assistant_turns))

    def test_human_decisions_remain_terminal(self):
        chat_agent = self._load_chat_agent()
        terminal_cases = [
            {"status": "rejected", "permission": {"category": "reject"}},
            {"status": "rejected", "permission": {"category": "do-not-ask reject"}},
            {"status": "rejected", "permission": {"category": "cross-case denial"}},
            {"status": "interrupt", "permission": {"category": "interrupt"}},
        ]
        for result in terminal_cases:
            with self.subTest(category=result["permission"]["category"]):
                self.assertTrue(chat_agent._is_terminal_tool_result(result))
                self.assertFalse(chat_agent._is_recoverable_tool_result(result))

        recoverable_cases = [
            {"status": "rejected", "permission": {"category": "invalid tool arguments"}},
            {"status": "rejected", "permission": {"category": "feature unavailable"}},
            {"status": "rejected", "permission": {"category": "invalid provenance"}},
            {"status": "error", "permission": {"category": "allow"}},
        ]
        for result in recoverable_cases:
            with self.subTest(category=result["permission"]["category"]):
                self.assertFalse(chat_agent._is_terminal_tool_result(result))
                self.assertTrue(chat_agent._is_recoverable_tool_result(result))


class ChatFinalSynthesisContractTestCase(_ChatAgentHarness, unittest.TestCase):
    """A turn must never end without an answer, and must stay audited/aliased."""

    def test_exhausted_tool_budget_still_answers_the_analyst(self):
        chat_agent = self._load_chat_agent()
        tool_flags = []

        def stream(messages, tools=None, case_id=None):
            tool_flags.append(tools is not None)
            if tools is None:
                yield {"message": {"role": "assistant",
                                   "content": "42 failed logons; source IP unverified."},
                       "done": True}
                return
            yield _tool_call_chunk("count_events", {"event_id": "4625"})

        chat_agent._stream_llm_chat = stream
        events, history = self._run(chat_agent)

        done = next(event for event in events if event["type"] == "done")
        self.assertTrue(done["final_synthesis"])
        self.assertEqual(done["tool_rounds"], chat_agent.MAX_TOOL_ROUNDS)

        # The synthesis call must be made with tools disabled so it cannot loop.
        self.assertEqual(tool_flags[-1], False)
        self.assertEqual(tool_flags.count(False), 1)

        tokens = [event["content"] for event in events if event["type"] == "token"]
        self.assertEqual(tokens, ["42 failed logons; source IP unverified."])
        self.assertIn(
            "42 failed logons; source IP unverified.",
            [message["content"] for message in history if message["role"] == "assistant"],
        )

    def test_no_synthesis_when_the_model_already_answered(self):
        chat_agent = self._load_chat_agent()
        calls = {"count": 0}

        def stream(messages, tools=None, case_id=None):
            calls["count"] += 1
            yield {"message": {"role": "assistant", "content": "Direct answer."}, "done": True}

        chat_agent._stream_llm_chat = stream
        events, _ = self._run(chat_agent)

        self.assertEqual(calls["count"], 1)
        done = next(event for event in events if event["type"] == "done")
        self.assertFalse(done["final_synthesis"])

    def test_no_synthesis_after_a_pending_approval_interrupt(self):
        chat_agent = self._load_chat_agent()
        calls = {"count": 0}

        def stream(messages, tools=None, case_id=None):
            calls["count"] += 1
            yield _tool_call_chunk("search_memory", {"search": "lsass"})

        chat_agent._stream_llm_chat = stream
        events, _ = self._run(chat_agent)

        tool_result = next(event for event in events if event["type"] == "tool_result")
        self.assertEqual(tool_result["status"], "interrupt")

        # The analyst owns the next step; the model must not answer around them.
        self.assertEqual(calls["count"], 1)
        done = next(event for event in events if event["type"] == "done")
        self.assertFalse(done["final_synthesis"])

    def test_every_provider_call_including_synthesis_goes_through_the_router(self):
        chat_agent = self._load_chat_agent()
        router_calls = []

        def fake_router_stream_chat(*, function, messages, tools=None, privacy_context=None, **kwargs):
            router_calls.append({
                "function": function,
                "tools": tools,
                "privacy_context": privacy_context,
            })
            if tools is None:
                yield {"message": {"role": "assistant", "content": "Synthesized answer."},
                       "done": True}
                return
            yield _tool_call_chunk("count_events", {"event_id": "4625"})

        chat_agent.stream_chat = fake_router_stream_chat
        events, _ = self._run(chat_agent, case_id=77)

        self.assertTrue(router_calls)
        self.assertTrue(any(call["tools"] is None for call in router_calls),
                        "synthesis call did not reach the router")
        for call in router_calls:
            # Routing is what applies CUI alias egress and writes the AI audit record.
            self.assertEqual(call["function"], "chat")
            self.assertIsNotNone(call["privacy_context"])
            self.assertEqual(getattr(call["privacy_context"], "case_id", None), 77)

        tokens = [event["content"] for event in events if event["type"] == "token"]
        self.assertIn("Synthesized answer.", tokens)


class ChatLicenseGateContractTestCase(unittest.TestCase):
    """The license gate must stay enforced, disclosed, and non-terminal."""

    def test_declared_requirements_are_enforced_not_just_disclosed(self):
        from utils.chat.policy import REQUIRED_CHAT_TOOL_FEATURES, feature_gate_chat_tool
        from utils.feature_availability import FeatureAvailability

        self.assertIn("lookup_threat_intel", REQUIRED_CHAT_TOOL_FEATURES)
        self.assertIn("run_forensic_subagent", REQUIRED_CHAT_TOOL_FEATURES)

        for tool_name in REQUIRED_CHAT_TOOL_FEATURES:
            with self.subTest(tool=tool_name):
                original = FeatureAvailability.is_chat_tool_feature_enabled
                try:
                    FeatureAvailability.is_chat_tool_feature_enabled = classmethod(
                        lambda cls, name: False
                    )
                    gate = feature_gate_chat_tool(tool_name, 1, {})
                finally:
                    FeatureAvailability.is_chat_tool_feature_enabled = original

                self.assertIsNotNone(gate)
                self.assertFalse(gate.allowed)
                self.assertEqual(gate.category, "feature unavailable")

    def test_unlicensed_tools_are_gated_and_licensed_tools_are_not(self):
        from utils.chat.policy import feature_gate_chat_tool

        self.assertIsNone(feature_gate_chat_tool("count_events", 1, {}))
        self.assertIsNone(feature_gate_chat_tool("query_events", 1, {}))

    def test_provider_registry_discloses_the_same_requirements_it_enforces(self):
        from utils.chat.policy import REQUIRED_CHAT_TOOL_FEATURES
        from utils.chat.tool_providers import get_tool_provider

        for tool_name, feature in REQUIRED_CHAT_TOOL_FEATURES.items():
            with self.subTest(tool=tool_name):
                self.assertEqual(get_tool_provider(tool_name).required_feature, feature)


if __name__ == "__main__":
    unittest.main()
