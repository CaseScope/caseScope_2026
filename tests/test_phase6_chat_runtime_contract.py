import importlib.util
import os
import sys
import unittest


REPO_ROOT = os.path.dirname(os.path.dirname(__file__))
os.environ.setdefault("SECRET_KEY", "test-secret")


def _load_module(name: str, relative_path: str):
    module_path = os.path.join(REPO_ROOT, relative_path)
    spec = importlib.util.spec_from_file_location(name, module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


chat_runtime = _load_module("phase6_chat_runtime", os.path.join("utils", "chat", "runtime.py"))
chat_dispatch = _load_module("phase6_chat_dispatch", os.path.join("utils", "chat", "dispatch.py"))
chat_policy = _load_module("phase6_chat_policy", os.path.join("utils", "chat", "policy.py"))


class Phase6ChatRuntimeContractTestCase(unittest.TestCase):
    def test_attachment_scheduler_keeps_locked_order(self):
        scheduler = chat_runtime.AttachmentScheduler()
        scheduler.add(chat_runtime.AttachmentOrder.USER_QUERY, "USER_QUERY", "What happened?")
        scheduler.add(chat_runtime.AttachmentOrder.CASE_STATIC_CONTEXT, "CASE_STATIC_CONTEXT", "Case A")
        scheduler.add(chat_runtime.AttachmentOrder.FINDING_SUMMARY, "FINDING_SUMMARY", "2 findings")

        rendered = scheduler.render()

        self.assertLess(rendered.index("[CASE_STATIC_CONTEXT]"), rendered.index("[FINDING_SUMMARY]"))
        self.assertLess(rendered.index("[FINDING_SUMMARY]"), rendered.index("[USER_QUERY]"))

    def test_add_cache_breakpoints_applies_exactly_one_marker(self):
        messages = [
            {"role": "system", "content": "system"},
            {"role": "user", "content": "question"},
            {"role": "assistant", "content": "answer"},
        ]

        marked = chat_runtime.add_cache_breakpoints(messages)

        self.assertEqual(sum(1 for message in marked if "cache_control" in message), 1)
        self.assertIn("cache_control", marked[-1])

    def test_inject_tool_result_cache_refs_replaces_repeated_tool_payload(self):
        messages = [
            {"role": "tool", "tool_call_id": "a1", "name": "query_events", "content": '{"rows": 1}'},
            {"role": "tool", "tool_call_id": "a2", "name": "query_events", "content": '{"rows": 1}'},
        ]

        rewritten = chat_runtime.inject_tool_result_cache_refs(messages)

        self.assertIn("cache_reference", rewritten[1]["content"])

    def test_dispatcher_returns_structured_tool_result(self):
        dispatcher = chat_dispatch.ToolDispatcher(
            executor=lambda tool_name, case_id, params: {
                "tool_name": tool_name,
                "case_id": case_id,
                "params": params,
                "_provenance": {"emitted_provenance": "ANALYST"},
            }
        )

        result = dispatcher.execute(
            tool_name="query_events",
            case_id=42,
            params={"event_id": "4625"},
            tier=chat_dispatch.ToolTier.READ_SAFE,
            provenance=chat_dispatch.Provenance.ANALYST,
        )

        payload = result.to_payload()
        self.assertEqual(payload["status"], "completed")
        self.assertEqual(payload["tool_name"], "query_events")
        self.assertTrue(payload["permission"]["allowed"])
        self.assertEqual(payload["tier"], "READ_SAFE")
        self.assertEqual(payload["provenance"], "ANALYST")

    def test_dispatcher_uses_producer_emitted_provenance_on_completed_results(self):
        dispatcher = chat_dispatch.ToolDispatcher(
            executor=lambda tool_name, case_id, params: {
                "total_matches": 1,
                "provenance_summary": {"highest_provenance": "ELEVATED_RISK"},
                "_provenance": {"emitted_provenance": "ELEVATED_RISK"},
            }
        )

        result = dispatcher.execute(
            tool_name="search_artifacts",
            case_id=42,
            params={"search": "evil.exe"},
            tier=chat_dispatch.ToolTier.READ_SAFE,
            provenance=chat_dispatch.Provenance.MODEL_SYNTHESIZED,
        )

        payload = result.to_payload()
        self.assertEqual(payload["status"], "completed")
        self.assertEqual(payload["provenance"], "ELEVATED_RISK")
        self.assertNotIn("_provenance", payload)
        self.assertEqual(
            payload["permission"]["reason"],
            "READ_SAFE auto-allow (ELEVATED_RISK)",
        )

    def test_dispatcher_rejects_data_payload_without_emitted_provenance(self):
        dispatcher = chat_dispatch.ToolDispatcher(
            executor=lambda tool_name, case_id, params: {"total_matches": 1}
        )

        result = dispatcher.execute(
            tool_name="search_artifacts",
            case_id=42,
            params={"search": "evil.exe"},
            tier=chat_dispatch.ToolTier.READ_SAFE,
            provenance=chat_dispatch.Provenance.MODEL_SYNTHESIZED,
        )

        payload = result.to_payload()
        self.assertEqual(payload["status"], "rejected")
        self.assertEqual(payload["permission"]["category"], "invalid provenance")
        self.assertEqual(payload["error"], "tool payload missing emitted provenance metadata")

    def test_dispatcher_rejects_invalid_emitted_provenance(self):
        dispatcher = chat_dispatch.ToolDispatcher(
            executor=lambda tool_name, case_id, params: {
                "total_matches": 1,
                "_provenance": {"emitted_provenance": "INVALID"},
            }
        )

        result = dispatcher.execute(
            tool_name="search_artifacts",
            case_id=42,
            params={"search": "evil.exe"},
            tier=chat_dispatch.ToolTier.READ_SAFE,
            provenance=chat_dispatch.Provenance.MODEL_SYNTHESIZED,
        )

        payload = result.to_payload()
        self.assertEqual(payload["status"], "rejected")
        self.assertEqual(payload["permission"]["category"], "invalid provenance")
        self.assertIn("INVALID", payload["error"])

    def test_shared_chat_policy_resolves_sensitive_tools(self):
        safe_tier, safe_provenance = chat_policy.resolve_chat_tool_policy("count_events")
        sensitive_tier, sensitive_provenance = chat_policy.resolve_chat_tool_policy("lookup_threat_intel")

        self.assertEqual(safe_tier, chat_dispatch.ToolTier.READ_SAFE)
        self.assertEqual(sensitive_tier, chat_dispatch.ToolTier.READ_SENSITIVE)
        self.assertEqual(safe_provenance, chat_dispatch.Provenance.MODEL_SYNTHESIZED)
        self.assertEqual(sensitive_provenance, chat_dispatch.Provenance.MODEL_SYNTHESIZED)

    def test_dispatcher_interrupts_sensitive_read_without_cached_approval(self):
        dispatcher = chat_dispatch.ToolDispatcher(
            executor=lambda tool_name, case_id, params: {"should_not_run": True}
        )

        result = dispatcher.execute(
            tool_name="search_memory",
            case_id=42,
            params={"search": "powershell"},
            tier=chat_dispatch.ToolTier.READ_SENSITIVE,
            provenance=chat_dispatch.Provenance.MODEL_SYNTHESIZED,
            session_id="session-1",
        )

        payload = result.to_payload()
        self.assertEqual(payload["status"], "interrupt")
        self.assertFalse(payload["permission"]["allowed"])
        self.assertEqual(payload["permission"]["category"], "interrupt")

    def test_dispatcher_can_reject_feature_unavailable_tools_before_execution(self):
        calls = []
        dispatcher = chat_dispatch.ToolDispatcher(
            executor=lambda tool_name, case_id, params: calls.append((tool_name, case_id, params)) or {
                "ok": True,
                "_provenance": {"emitted_provenance": "SYSTEM_DERIVED"},
            },
            feature_gate=lambda tool_name, case_id, params: chat_dispatch.PermissionResult(
                allowed=False,
                category="feature unavailable",
                reason="Threat intelligence lookup is not currently available",
                cacheable=False,
            ) if tool_name == "lookup_threat_intel" else None,
        )

        result = dispatcher.execute(
            tool_name="lookup_threat_intel",
            case_id=42,
            params={"query_type": "ioc", "value": "1.2.3.4"},
            tier=chat_dispatch.ToolTier.READ_SENSITIVE,
            provenance=chat_dispatch.Provenance.MODEL_SYNTHESIZED,
            session_id="session-1",
        )

        payload = result.to_payload()
        self.assertEqual(payload["status"], "rejected")
        self.assertEqual(payload["permission"]["category"], "feature unavailable")
        self.assertEqual(payload["tier"], "READ_SENSITIVE")
        self.assertEqual(payload["provenance"], "MODEL_SYNTHESIZED")
        self.assertEqual(calls, [])

    def test_dispatcher_caches_allow_for_same_sensitive_params(self):
        calls = []
        dispatcher = chat_dispatch.ToolDispatcher(
            executor=lambda tool_name, case_id, params: calls.append((tool_name, case_id, params)) or {
                "ok": True,
                "_provenance": {"emitted_provenance": "SYSTEM_DERIVED"},
            }
        )

        first = dispatcher.execute(
            tool_name="search_memory",
            case_id=42,
            params={"search": "powershell"},
            tier=chat_dispatch.ToolTier.READ_SENSITIVE,
            provenance=chat_dispatch.Provenance.MODEL_SYNTHESIZED,
            session_id="session-1",
            analyst_decision="allow",
            analyst_reason="approved for this session",
        )
        second = dispatcher.execute(
            tool_name="search_memory",
            case_id=42,
            params={"search": "powershell"},
            tier=chat_dispatch.ToolTier.READ_SENSITIVE,
            provenance=chat_dispatch.Provenance.MODEL_SYNTHESIZED,
            session_id="session-1",
        )

        self.assertEqual(first.to_payload()["status"], "completed")
        self.assertEqual(second.to_payload()["status"], "completed")
        self.assertEqual(len(calls), 2)
        self.assertTrue(second.to_payload()["permission"]["cacheable"])

    def test_dispatcher_requires_new_approval_for_different_sensitive_params(self):
        dispatcher = chat_dispatch.ToolDispatcher(
            executor=lambda tool_name, case_id, params: {
                "ok": True,
                "_provenance": {"emitted_provenance": "SYSTEM_DERIVED"},
            }
        )

        approved = dispatcher.execute(
            tool_name="search_memory",
            case_id=42,
            params={"search": "powershell"},
            tier=chat_dispatch.ToolTier.READ_SENSITIVE,
            provenance=chat_dispatch.Provenance.MODEL_SYNTHESIZED,
            session_id="session-1",
            analyst_decision="allow",
            analyst_reason="approved for powershell",
        )
        follow_up = dispatcher.execute(
            tool_name="search_memory",
            case_id=42,
            params={"search": "cmd.exe"},
            tier=chat_dispatch.ToolTier.READ_SENSITIVE,
            provenance=chat_dispatch.Provenance.MODEL_SYNTHESIZED,
            session_id="session-1",
        )

        self.assertEqual(approved.to_payload()["status"], "completed")
        self.assertEqual(follow_up.to_payload()["status"], "interrupt")

    def test_dispatcher_can_clear_cached_permissions_for_session(self):
        dispatcher = chat_dispatch.ToolDispatcher(
            executor=lambda tool_name, case_id, params: {
                "ok": True,
                "_provenance": {"emitted_provenance": "SYSTEM_DERIVED"},
            }
        )

        dispatcher.execute(
            tool_name="search_memory",
            case_id=42,
            params={"search": "powershell"},
            tier=chat_dispatch.ToolTier.READ_SENSITIVE,
            provenance=chat_dispatch.Provenance.MODEL_SYNTHESIZED,
            session_id="session-1",
            analyst_decision="allow",
            analyst_reason="approved for this session",
        )
        self.assertIsNotNone(
            dispatcher.get_cached_permission(
                tool_name="search_memory",
                case_id=42,
                session_id="session-1",
                params={"search": "powershell"},
            )
        )

        dispatcher.clear_session_permissions("session-1")

        self.assertIsNone(
            dispatcher.get_cached_permission(
                tool_name="search_memory",
                case_id=42,
                session_id="session-1",
                params={"search": "powershell"},
            )
        )

    def test_dispatcher_caches_reject_for_same_sensitive_params(self):
        dispatcher = chat_dispatch.ToolDispatcher(
            executor=lambda tool_name, case_id, params: {"should_not_run": True}
        )

        first = dispatcher.execute(
            tool_name="search_memory",
            case_id=42,
            params={"search": "powershell"},
            tier=chat_dispatch.ToolTier.READ_SENSITIVE,
            provenance=chat_dispatch.Provenance.MODEL_SYNTHESIZED,
            session_id="session-1",
            analyst_decision="do_not_ask_reject",
            analyst_reason="memory search denied",
        )
        second = dispatcher.execute(
            tool_name="search_memory",
            case_id=42,
            params={"search": "powershell"},
            tier=chat_dispatch.ToolTier.READ_SENSITIVE,
            provenance=chat_dispatch.Provenance.MODEL_SYNTHESIZED,
            session_id="session-1",
        )

        self.assertEqual(first.to_payload()["status"], "rejected")
        self.assertEqual(second.to_payload()["status"], "rejected")
        self.assertEqual(second.to_payload()["permission"]["category"], "do-not-ask reject")

    def test_dispatcher_does_not_apply_reject_to_different_sensitive_params(self):
        dispatcher = chat_dispatch.ToolDispatcher(
            executor=lambda tool_name, case_id, params: {"should_not_run": True}
        )

        first = dispatcher.execute(
            tool_name="search_memory",
            case_id=42,
            params={"search": "powershell"},
            tier=chat_dispatch.ToolTier.READ_SENSITIVE,
            provenance=chat_dispatch.Provenance.MODEL_SYNTHESIZED,
            session_id="session-1",
            analyst_decision="do_not_ask_reject",
            analyst_reason="memory search denied",
        )
        second = dispatcher.execute(
            tool_name="search_memory",
            case_id=42,
            params={"search": "cmd.exe"},
            tier=chat_dispatch.ToolTier.READ_SENSITIVE,
            provenance=chat_dispatch.Provenance.MODEL_SYNTHESIZED,
            session_id="session-1",
        )

        self.assertEqual(first.to_payload()["status"], "rejected")
        self.assertEqual(second.to_payload()["status"], "interrupt")

    def test_dispatcher_does_not_cache_write_committing_allow(self):
        dispatcher = chat_dispatch.ToolDispatcher(
            executor=lambda tool_name, case_id, params: {
                "ok": True,
                "_provenance": {"emitted_provenance": "SYSTEM_DERIVED"},
            }
        )

        allowed = dispatcher.execute(
            tool_name="commit_changes",
            case_id=42,
            params={"path": "/tmp/example"},
            tier=chat_dispatch.ToolTier.WRITE_COMMITTING,
            provenance=chat_dispatch.Provenance.MODEL_SYNTHESIZED,
            session_id="session-1",
            analyst_decision="allow",
            analyst_reason="one time approval",
        )
        follow_up = dispatcher.execute(
            tool_name="commit_changes",
            case_id=42,
            params={"path": "/tmp/example"},
            tier=chat_dispatch.ToolTier.WRITE_COMMITTING,
            provenance=chat_dispatch.Provenance.MODEL_SYNTHESIZED,
            session_id="session-1",
        )

        self.assertEqual(allowed.to_payload()["status"], "completed")
        self.assertEqual(follow_up.to_payload()["status"], "interrupt")

    def test_tool_result_block_can_emit_reused_result_stub(self):
        result = chat_dispatch.ToolResultBlock.reused_result(
            tool_name="query_events",
            first_tool_call_id="call-1",
            tier=chat_dispatch.ToolTier.READ_SAFE,
            provenance=chat_dispatch.Provenance.ANALYST,
        )

        payload = result.to_payload()
        self.assertTrue(payload["reused_result"])
        self.assertEqual(payload["cache_reference"]["tool_name"], "query_events")
        self.assertEqual(payload["cache_reference"]["first_tool_call_id"], "call-1")
        self.assertEqual(payload["tier"], "READ_SAFE")
        self.assertEqual(payload["provenance"], "ANALYST")

    def test_tool_result_block_can_emit_interrupt_and_reject(self):
        interrupt = chat_dispatch.ToolResultBlock.interrupt(
            tool_name="search_memory",
            permission=chat_dispatch.PermissionResult(
                allowed=False,
                category="interrupt",
                reason="READ_SENSITIVE requires analyst approval",
                cacheable=True,
            ),
        )
        reject = chat_dispatch.ToolResultBlock.reject(
            tool_name="search_memory",
            permission=chat_dispatch.PermissionResult(
                allowed=False,
                category="reject",
                reason="analyst denied request",
                cacheable=True,
            ),
        )

        self.assertEqual(interrupt.to_payload()["status"], "interrupt")
        self.assertEqual(reject.to_payload()["status"], "rejected")


if __name__ == "__main__":
    unittest.main()
