"""Contract tests for chat prompt composition and token-aware compaction.

Conversation-stable context must be sent once, and history must be trimmed
against the model's token budget rather than a fixed message count, because a
single tool result can outweigh a dozen chat turns.
"""

import importlib.util
import json
import os
import sys
import types
import unittest

os.environ.setdefault("SECRET_KEY", "test-secret")


def _load_chat_agent():
    fake_utils = types.ModuleType("utils")
    fake_utils.__path__ = []
    fake_chat_tools = types.ModuleType("utils.chat_tools")
    fake_chat_tools.TOOL_DEFINITIONS = [{
        "type": "function",
        "function": {
            "name": "count_events",
            "description": "Count case events.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    }]
    fake_chat_tools.execute_tool = lambda name, case_id, params: {"total": 1}

    previous = {key: sys.modules.get(key) for key in ("utils", "utils.chat_tools")}
    sys.modules["utils"] = fake_utils
    sys.modules["utils.chat_tools"] = fake_chat_tools
    try:
        spec = importlib.util.spec_from_file_location(
            "chat_agent_budget_test", "/opt/casescope/utils/chat_agent.py"
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules["chat_agent_budget_test"] = module
        spec.loader.exec_module(module)
    finally:
        for key, value in previous.items():
            if value is not None:
                sys.modules[key] = value
            else:
                sys.modules.pop(key, None)
    return module


CASE_CONTEXT = {
    "case_id": 5,
    "case_name": "Operation Nightjar",
    "description": "Suspected ransomware staging on finance workstations.",
    "hosts": ["FIN-WKSTN-01", "FIN-WKSTN-02"],
    "timezone": "America/New_York",
    "analysis_summary": {
        "census_total_events": 4820117,
        "census_distinct_event_ids": 312,
        "pattern_matches_found": 47,
        "attack_chains_found": 6,
        "ioc_timeline_entries": 133,
    },
    "ai_synthesis": {"executive_summary": "Initial access via malicious ISO attachment."},
}


class ChatPromptCompositionTestCase(unittest.TestCase):
    def setUp(self):
        self.chat_agent = _load_chat_agent()
        self.conversation_context = self.chat_agent.ConversationContext(
            license_tier="activated",
            enabled_features=("ai_reasoning",),
            enabled_ti_sources=("opencti",),
            available_agents=("count_events",),
            model_selection="unit-test-model",
        )

    def _request(self, history):
        system_prompt = self.chat_agent.build_system_prompt(CASE_CONTEXT, self.conversation_context)
        messages = [{"role": "system", "content": system_prompt}, *history]
        return self.chat_agent._build_request_messages(
            messages, CASE_CONTEXT, self.conversation_context
        )

    def test_stable_context_is_sent_exactly_once(self):
        request = self._request([{"role": "user", "content": "What happened?"}])
        rendered = "\n".join(str(message.get("content") or "") for message in request)

        for marker in ("Operation Nightjar", "FIN-WKSTN-01", "License tier", "Total events"):
            with self.subTest(marker=marker):
                self.assertEqual(rendered.count(marker), 1)

    def test_the_analyst_question_is_sent_as_written(self):
        request = self._request([{"role": "user", "content": "Did anyone download an ISO?"}])
        user_message = next(m for m in reversed(request) if m.get("role") == "user")
        self.assertEqual(user_message["content"], "Did anyone download an ISO?")

    def test_prior_turns_are_not_replayed_into_the_current_turn(self):
        history = [
            {"role": "user", "content": "First question"},
            {"role": "assistant", "content": "A distinctive earlier answer about ISO files"},
            {"role": "user", "content": "Second question"},
        ]
        request = self._request(history)
        rendered = "\n".join(str(message.get("content") or "") for message in request)
        self.assertEqual(rendered.count("A distinctive earlier answer about ISO files"), 1)


class ChatTokenBudgetTestCase(unittest.TestCase):
    def setUp(self):
        self.chat_agent = _load_chat_agent()

    def test_budget_reserves_room_for_the_response(self):
        context = self.chat_agent.ConversationContext(model_selection="unit-test-model")
        window = self.chat_agent._model_context_window(context)
        budget = self.chat_agent._history_token_budget(context)

        self.assertLessEqual(
            budget + self.chat_agent.MAX_RESPONSE_TOKENS,
            window,
            "history budget must leave room for the model's reply",
        )
        self.assertGreaterEqual(budget, self.chat_agent.MIN_HISTORY_TOKENS)

    def test_a_few_huge_tool_results_are_compacted(self):
        system = {"role": "system", "content": "system"}
        huge = json.dumps({"events": [{"row": "x" * 200} for _ in range(200)]})
        history = [
            {"role": "user", "content": "question"},
            {"role": "tool", "name": "query_events", "tool_call_id": "a", "content": huge},
            {"role": "tool", "name": "query_events", "tool_call_id": "b", "content": huge},
            {"role": "tool", "name": "query_events", "tool_call_id": "c", "content": huge},
            {"role": "user", "content": "follow-up question"},
        ]

        compacted = self.chat_agent._compact_messages([system, *history], token_budget=2000)

        self.assertLess(len(compacted), len(history) + 1)
        self.assertEqual(compacted[0], system)
        self.assertTrue(
            any(self.chat_agent._is_compaction_summary(message) for message in compacted),
            "older turns must be summarized, not silently dropped",
        )
        self.assertEqual(compacted[-1]["content"], "follow-up question")

    def test_many_small_turns_are_retained_when_they_fit(self):
        system = {"role": "system", "content": "system"}
        history = [
            {"role": "user" if index % 2 == 0 else "assistant", "content": f"short turn {index}"}
            for index in range(40)
        ]

        compacted = self.chat_agent._compact_messages([system, *history], token_budget=20000)

        self.assertEqual(len(compacted), len(history) + 1)
        self.assertFalse(
            any(self.chat_agent._is_compaction_summary(message) for message in compacted)
        )

    def test_compacted_history_stays_inside_the_budget(self):
        system = {"role": "system", "content": "system"}
        history = [
            {"role": "assistant", "content": "y" * 4000}
            for _ in range(30)
        ]

        budget = 3000
        compacted = self.chat_agent._compact_messages([system, *history], token_budget=budget)
        retained = [
            message for message in compacted[1:]
            if not self.chat_agent._is_compaction_summary(message)
        ]

        self.assertTrue(retained)
        self.assertLessEqual(
            self.chat_agent._estimate_message_tokens(retained[1:]),
            budget,
            "retained history beyond the newest message must fit the budget",
        )

    def test_the_newest_message_is_always_retained(self):
        system = {"role": "system", "content": "system"}
        history = [{"role": "user", "content": "z" * 100000}]

        compacted = self.chat_agent._compact_messages([system, *history], token_budget=100)

        self.assertEqual(len(compacted), 2)
        self.assertEqual(compacted[-1]["content"], "z" * 100000)


if __name__ == "__main__":
    unittest.main()


class ChatToolResultTruncationTestCase(unittest.TestCase):
    """Trimming an oversized tool result must cost evidence rows, not reasoning."""

    def setUp(self):
        self.chat_agent = _load_chat_agent()

    @staticmethod
    def _row(index):
        return {
            "timestamp": f"2026-03-04T0{index % 9}:{index % 59:02d}:11",
            "host": f"FIN-WKSTN-{index % 12:02d}",
            "event_id": 4688,
            "process": f"C:\\\\Windows\\\\Temp\\\\stage_{index}.exe",
            "command_line": "powershell -enc " + "QQBB" * 20,
        }

    def _oversized_investigation(self):
        return {
            "answer_draft": "Staging consistent with pre-encryption preparation.",
            "key_findings": ["Archive created at 03:14", "Transfer to 10.44.7.9"],
            "caveats": ["No EDR telemetry for FIN-WKSTN-07"],
            "negative_checks": [{"check": "No shadow copy deletion", "result": "negative"}],
            "coverage": {"coverage_status": "partial", "missing_sources": ["proxy"]},
            "timeline": [self._row(i) for i in range(300)],
            "attributed_activity": [self._row(i) for i in range(200)],
            "related_activity": [self._row(i) for i in range(200)],
            "evidence_sections": [self._row(i) for i in range(150)],
            "status": "completed",
        }

    def test_conclusions_survive_and_evidence_is_sampled(self):
        payload = self._oversized_investigation()
        serialized = self.chat_agent._serialize_tool_result_for_history(payload)
        parsed = json.loads(serialized)

        self.assertLessEqual(len(serialized), self.chat_agent.MAX_TOOL_RESULT_CHARS)
        for field in ("answer_draft", "key_findings", "caveats", "negative_checks", "coverage"):
            with self.subTest(field=field):
                self.assertEqual(parsed[field], payload[field])

        for field in ("timeline", "attributed_activity", "related_activity"):
            with self.subTest(field=field):
                self.assertLess(len(parsed[field]), len(payload[field]))
                self.assertTrue(parsed[field], "a sample of each evidence list should remain")

    def test_what_was_dropped_is_disclosed(self):
        parsed = json.loads(
            self.chat_agent._serialize_tool_result_for_history(self._oversized_investigation())
        )
        notes = parsed["_trimmed_for_context"]
        self.assertIn("timeline", notes)
        self.assertRegex(notes["timeline"], r"kept \d+ of 300 items")

    def test_small_results_are_passed_through_untouched(self):
        payload = {"total": 42, "status": "completed", "events": [{"a": 1}]}
        parsed = json.loads(self.chat_agent._serialize_tool_result_for_history(payload))
        self.assertEqual(parsed, payload)

    def test_investigate_question_returns_conclusions_before_bulk_evidence(self):
        import re
        from pathlib import Path

        source = Path("/opt/casescope/utils/chat_tools.py").read_text()
        start = source.index('"answer_draft": answer_draft,')
        block = source[start:start + 2000]
        order = [
            key for key in re.findall(r'"(\w+)":', block)
            if key in {
                "answer_draft", "key_findings", "caveats", "negative_checks", "coverage",
                "timeline", "attributed_activity", "related_activity", "evidence_sections",
            }
        ]
        conclusions = {"answer_draft", "key_findings", "caveats", "negative_checks", "coverage"}
        bulk = {"timeline", "attributed_activity", "related_activity", "evidence_sections"}
        last_conclusion = max(index for index, key in enumerate(order) if key in conclusions)
        first_bulk = min(index for index, key in enumerate(order) if key in bulk)
        self.assertLess(last_conclusion, first_bulk)
