import os
import types
import unittest
from unittest.mock import Mock, patch

from flask import Flask

os.environ.setdefault("SECRET_KEY", "test-secret")

import routes.chat as chat_routes
import routes.hunt as hunt_routes


class _DummyUser:
    username = "tester"
    is_authenticated = True


class _Query:
    def __init__(self, result):
        self.result = result

    def get(self, _id):
        return self.result

    def filter_by(self, **_kwargs):
        return self

    def order_by(self, *_args, **_kwargs):
        return self

    def limit(self, _limit):
        return self

    def all(self):
        return self.result if isinstance(self.result, list) else [self.result]

    def first(self):
        return self.result


class HuntRoutesContractTestCase(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.secret_key = "test-secret"

    def test_create_hunt_run_api_calls_trace_service(self):
        created_run = Mock()
        created_run.to_dict.return_value = {"id": 9, "case_id": 3, "objective": "check ScreenConnect"}

        with self.app.test_request_context(
            "/api/hunt-runs",
            method="POST",
            json={"case_id": 3, "objective": "check ScreenConnect"},
        ):
            with patch.object(hunt_routes, "current_user", _DummyUser()), \
                    patch.object(hunt_routes.Case, "get_by_id", return_value=object()), \
                    patch.object(hunt_routes.hunt_trace, "create_hunt_run", return_value=created_run) as create_mock:
                response, status = hunt_routes.create_hunt_run.__wrapped__()

        self.assertEqual(status, 201)
        self.assertEqual(response.get_json()["hunt_run"]["id"], 9)
        create_mock.assert_called_once()
        self.assertEqual(create_mock.call_args.kwargs["created_by"], "tester")

    def test_get_hunt_run_api_returns_readback_payload(self):
        run = Mock(case_id=3)
        run.to_dict.return_value = {
            "id": 9,
            "steps": [{"id": 1, "tool_name": "query_events"}],
        }

        with self.app.test_request_context("/api/hunt-runs/9"):
            with patch.object(hunt_routes.HuntRun, "query", _Query(run)), \
                    patch.object(hunt_routes.Case, "get_by_id", return_value=object()):
                response = hunt_routes.get_hunt_run.__wrapped__(9)

        self.assertEqual(response.get_json()["hunt_run"]["steps"][0]["tool_name"], "query_events")
        run.to_dict.assert_called_once_with(include_children=True)

    def test_chat_stream_passes_hunt_run_id_to_agent(self):
        session = types.SimpleNamespace(conversation_id="conv-1", messages=[])
        captured = {}

        def fake_agent_stream(*args, **kwargs):
            captured.update(kwargs)
            yield "data: {\"type\":\"done\"}\n\n"

        with self.app.test_request_context(
            "/api/chat/stream",
            method="POST",
            json={"case_id": 3, "message": "show events", "hunt_run_id": 9},
        ):
            with patch.object(chat_routes, "current_user", _DummyUser()), \
                    patch.object(chat_routes.FeatureAvailability, "is_ai_enabled", return_value=True), \
                    patch.object(chat_routes.Case, "get_by_id", return_value=object()), \
                    patch.object(chat_routes, "_load_or_create_chat_session", return_value=(session, False, None)), \
                    patch.object(chat_routes, "_persist_chat_session"), \
                    patch.object(chat_routes, "_resolve_pending_tool_approval", return_value=None), \
                    patch("utils.chat_agent.chat_stream", side_effect=fake_agent_stream), \
                    patch("models.hunt.HuntRun.query", _Query(object())):
                response = chat_routes.chat_stream.__wrapped__()
                list(response.response)

        self.assertEqual(captured["hunt_run_id"], 9)
        self.assertEqual(captured["actor_metadata"]["created_by"], "tester")


if __name__ == "__main__":
    unittest.main()
