import importlib.util
import sys
import types
import unittest
from unittest.mock import patch

from flask import Flask


def _load_chat_routes():
    fake_models = types.ModuleType("models")
    fake_models.__path__ = []
    fake_utils = types.ModuleType("utils")
    fake_utils.__path__ = []

    fake_case_module = types.ModuleType("models.case")
    fake_case_module.Case = type("Case", (), {"get_by_id": staticmethod(lambda case_id: object())})

    class _DummySessionOps:
        def add(self, *args, **kwargs):
            return None

        def commit(self):
            return None

        def rollback(self):
            return None

        def delete(self, *args, **kwargs):
            return None

    fake_database_module = types.ModuleType("models.database")
    fake_database_module.db = type("DB", (), {"session": _DummySessionOps()})()

    fake_rag_module = types.ModuleType("models.rag")
    fake_rag_module.ChatConversationSession = type(
        "ChatConversationSession",
        (),
        {
            "get_by_conversation_id": staticmethod(lambda conversation_id: None),
            "get_for_user_case": staticmethod(lambda case_id, user_id, conversation_id: None),
        },
    )

    fake_feature_module = types.ModuleType("utils.feature_availability")
    fake_feature_module.FeatureAvailability = type(
        "FeatureAvailability",
        (),
        {"is_ai_enabled": staticmethod(lambda: True)},
    )

    fake_chat_agent_module = types.ModuleType("utils.chat_agent")
    fake_chat_agent_module.chat_stream = lambda *args, **kwargs: iter(())
    fake_chat_agent_module.get_case_context = lambda case_id: {}

    fake_flask_login = types.ModuleType("flask_login")

    def login_required(func):
        func.__wrapped__ = func
        return func

    fake_flask_login.login_required = login_required
    fake_flask_login.current_user = type("User", (), {"username": "tester"})()

    installed_modules = {
        "models": fake_models,
        "models.case": fake_case_module,
        "models.database": fake_database_module,
        "models.rag": fake_rag_module,
        "utils": fake_utils,
        "utils.feature_availability": fake_feature_module,
        "utils.chat_agent": fake_chat_agent_module,
        "flask_login": fake_flask_login,
    }

    previous_modules = {
        name: sys.modules.get(name)
        for name in installed_modules
    }

    sys.modules.update(installed_modules)

    try:
        spec = importlib.util.spec_from_file_location(
            "phase6_chat_routes_test",
            "/opt/casescope/routes/chat.py",
        )
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        sys.modules["phase6_chat_routes_test"] = module
        spec.loader.exec_module(module)
        return module, fake_chat_agent_module, installed_modules
    finally:
        for name, previous in previous_modules.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous


class _DummyUser:
    username = "tester"
    is_authenticated = True


class _FakeSession:
    def __init__(self, conversation_id="conv-approval", messages=None):
        self.conversation_id = conversation_id
        self.messages = list(messages or [])
        self.persisted = None

    def replace_messages(self, messages):
        self.persisted = list(messages)


class Phase6ChatRouteApprovalContractTestCase(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.secret_key = "test-secret"
        self.chat_routes, self.fake_chat_agent_module, self.installed_modules = _load_chat_routes()
        self.module_patcher = patch.dict(sys.modules, self.installed_modules)
        self.module_patcher.start()

    def tearDown(self):
        self.module_patcher.stop()

    def test_chat_route_requires_message_or_tool_approval(self):
        with self.app.test_request_context(
            "/api/chat/stream",
            method="POST",
            json={"case_id": 7},
        ):
            with patch.object(self.chat_routes, "current_user", _DummyUser()):
                response, status = self.chat_routes.chat_stream.__wrapped__()

        self.assertEqual(status, 400)
        self.assertEqual(response.get_json()["error"], "message or tool_approval required")

    def test_chat_route_forwards_tool_approval_without_message(self):
        captured = {}
        session = _FakeSession()

        def fake_agent_stream(case_id, messages, conversation_id, tool_approval=None, on_complete=None):
            captured["case_id"] = case_id
            captured["messages"] = list(messages)
            captured["conversation_id"] = conversation_id
            captured["tool_approval"] = dict(tool_approval or {})
            if on_complete is not None:
                on_complete(list(messages))
            yield 'data: {"type":"done"}\n\n'

        self.fake_chat_agent_module.chat_stream = fake_agent_stream

        with self.app.test_request_context(
            "/api/chat/stream",
            method="POST",
            json={
                "case_id": 7,
                "conversation_id": "conv-approval",
                "tool_approval": {
                    "tool_name": "search_memory",
                    "decision": "allow",
                    "params": {"search": "powershell"},
                },
            },
        ):
            with patch.object(self.chat_routes, "current_user", _DummyUser()):
                with patch.object(self.chat_routes.FeatureAvailability, "is_ai_enabled", return_value=True):
                    with patch.object(self.chat_routes.Case, "get_by_id", return_value=object()):
                        with patch.object(
                            self.chat_routes,
                            "_load_or_create_chat_session",
                            return_value=(session, False, None),
                        ):
                            response = self.chat_routes.chat_stream.__wrapped__()
                            chunks = list(response.response)

        self.assertTrue(chunks)
        self.assertEqual(captured["case_id"], 7)
        self.assertEqual(captured["messages"], [])
        self.assertEqual(captured["conversation_id"], "conv-approval")
        self.assertEqual(captured["tool_approval"]["tool_name"], "search_memory")
        self.assertEqual(captured["tool_approval"]["decision"], "allow")


if __name__ == "__main__":
    unittest.main()
