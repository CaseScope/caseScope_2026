import importlib.util
import os
import sys
import unittest


REPO_ROOT = os.path.dirname(os.path.dirname(__file__))


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


if __name__ == "__main__":
    unittest.main()
