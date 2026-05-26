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

    def test_ioc_review_requires_explicit_time_bounds(self):
        with self.app.test_request_context(
            "/api/hunt-runs/ioc-review",
            method="POST",
            json={"case_id": 3},
        ):
            with patch.object(hunt_routes.Case, "get_by_id", return_value=object()):
                response, status = hunt_routes.create_ioc_hunt_review.__wrapped__()

        self.assertEqual(status, 400)
        self.assertIn("time_start", response.get_json()["error"])

    def test_ioc_review_creates_hunt_run_and_traced_steps(self):
        case = Mock(id=3, uuid="case-uuid")
        run = Mock(id=9, case_id=3)
        run.to_dict.return_value = {"id": 9, "objective": "IOC-backed hunting review (1 IOCs)"}
        ioc = Mock(id=44, value="203.0.113.5", ioc_type="IP Address (IPv4)", category="Network")
        lookup_step = Mock(id=100)
        network_step = Mock(id=101)

        def trace_result(_run, *, tool_name, **_kwargs):
            return network_step if tool_name == "search_network_logs" else lookup_step

        with self.app.test_request_context(
            "/api/hunt-runs/ioc-review",
            method="POST",
            json={
                "case_id": 3,
                "time_start": "2026-05-14T00:00",
                "time_end": "2026-05-14T01:00",
            },
        ):
            with patch.object(hunt_routes, "current_user", _DummyUser()), \
                    patch.object(hunt_routes.Case, "get_by_id", return_value=case), \
                    patch.object(hunt_routes, "_load_iocs_for_review", return_value=[ioc]), \
                    patch.object(hunt_routes.hunt_trace, "create_hunt_run", return_value=run) as create_mock, \
                    patch.object(hunt_routes, "lookup_ioc", return_value={"event_matches": 2}), \
                    patch.object(hunt_routes, "search_network_logs_for_case", return_value={
                        "total": 3,
                        "returned_count": 3,
                        "truncated": False,
                        "network_query": {"search": "203.0.113.5"},
                    }) as network_mock, \
                    patch.object(hunt_routes, "_trace_tool_result", side_effect=trace_result) as trace_mock, \
                    patch.object(hunt_routes.db.session, "commit") as commit_mock:
                response, status = hunt_routes.create_ioc_hunt_review.__wrapped__()

        payload = response.get_json()
        self.assertEqual(status, 201)
        self.assertTrue(payload["success"])
        self.assertEqual(payload["summary"]["ioc_count"], 1)
        self.assertEqual(payload["summary"]["lookup_matches"], 2)
        self.assertEqual(payload["summary"]["network_searches"], 1)
        self.assertEqual(payload["summary"]["network_matches"], 3)
        self.assertEqual(payload["reviewed_iocs"][0]["lookup_step_id"], 100)
        self.assertEqual(payload["reviewed_iocs"][0]["network_step_id"], 101)
        self.assertEqual(run.status, "completed")
        self.assertEqual(create_mock.call_args.kwargs["time_scope_start"], "2026-05-14 00:00:00")
        self.assertEqual(network_mock.call_args.kwargs["time_start"], "2026-05-14 00:00:00")
        self.assertEqual(trace_mock.call_count, 2)
        commit_mock.assert_called()

    def test_create_hunt_decision_api_calls_trace_service_as_analyst(self):
        run = Mock(id=9, case_id=3)
        created_decision = Mock()
        created_decision.to_dict.return_value = {
            "id": 12,
            "decision_state": "accepted",
            "created_by_type": "analyst",
        }

        with self.app.test_request_context(
            "/api/hunt-runs/9/decisions",
            method="POST",
            json={
                "classification": "suspicious",
                "decision_scope": "host",
                "target_host": "ATN62288",
                "evidence_links": [{"hunt_step_id": 4, "support_role": "primary"}],
            },
        ):
            with patch.object(hunt_routes, "current_user", _DummyUser()), \
                    patch.object(hunt_routes.HuntRun, "query", _Query(run)), \
                    patch.object(hunt_routes.Case, "get_by_id", return_value=object()), \
                    patch.object(hunt_routes.hunt_trace, "create_decision", return_value=created_decision) as create_mock:
                response, status = hunt_routes.create_hunt_decision.__wrapped__(9)

        self.assertEqual(status, 201)
        self.assertEqual(response.get_json()["decision"]["id"], 12)
        self.assertEqual(create_mock.call_args.kwargs["decision_state"], "accepted")
        self.assertEqual(create_mock.call_args.kwargs["created_by_type"], "analyst")
        self.assertEqual(create_mock.call_args.kwargs["created_by"], "tester")
        self.assertEqual(create_mock.call_args.kwargs["target_host"], "ATN62288")

    def test_accept_hunt_decision_api_preserves_draft_and_creates_new_record(self):
        draft = Mock(case_id=3)
        accepted = Mock()
        accepted.to_dict.return_value = {
            "id": 13,
            "source_decision_id": 10,
            "decision_state": "accepted",
            "created_by_type": "analyst",
        }

        with self.app.test_request_context(
            "/api/hunt-decisions/10/accept",
            method="POST",
            json={"review_note": "looks right"},
        ):
            with patch.object(hunt_routes, "current_user", _DummyUser()), \
                    patch.object(hunt_routes.HuntDecision, "query", _Query(draft)), \
                    patch.object(hunt_routes.Case, "get_by_id", return_value=object()), \
                    patch.object(hunt_routes.hunt_trace, "accept_decision", return_value=accepted) as accept_mock:
                response, status = hunt_routes.accept_hunt_decision.__wrapped__(10)

        self.assertEqual(status, 201)
        self.assertEqual(response.get_json()["decision"]["source_decision_id"], 10)
        accept_mock.assert_called_once()
        self.assertIs(accept_mock.call_args.args[0], draft)
        self.assertEqual(accept_mock.call_args.kwargs["reviewed_by"], "tester")

    def test_list_hunt_decisions_api_separates_active_from_history(self):
        active = Mock()
        active.to_dict.return_value = {
            "id": 13,
            "decision_state": "accepted",
            "created_by_type": "analyst",
            "is_authoritative": True,
        }
        draft = Mock()
        draft.to_dict.return_value = {
            "id": 10,
            "decision_state": "draft",
            "created_by_type": "ai",
            "is_authoritative": False,
        }
        superseded = Mock()
        superseded.to_dict.return_value = {
            "id": 11,
            "decision_state": "superseded",
            "created_by_type": "analyst",
            "superseded_by_decision_id": 13,
            "is_authoritative": False,
        }
        run = Mock(id=9, case_id=3)
        run.decisions.order_by.return_value.all.return_value = [draft, superseded, active]

        with self.app.test_request_context("/api/hunt-runs/9/decisions?decision_scope=host&target_host=ATN62288"):
            with patch.object(hunt_routes.HuntRun, "query", _Query(run)), \
                    patch.object(hunt_routes.Case, "get_by_id", return_value=object()), \
                    patch.object(hunt_routes.hunt_trace, "active_authoritative_decisions", return_value=[active]) as active_mock:
                response = hunt_routes.list_hunt_decisions.__wrapped__(9)

        payload = response.get_json()
        self.assertEqual([decision["id"] for decision in payload["decisions"]], [10, 11, 13])
        self.assertEqual([decision["id"] for decision in payload["active_decisions"]], [13])
        self.assertEqual(payload["active_rule"]["decision_state"], "accepted")
        active_mock.assert_called_once()
        self.assertEqual(active_mock.call_args.kwargs["hunt_run_id"], 9)
        self.assertEqual(active_mock.call_args.kwargs["case_id"], 3)
        self.assertEqual(active_mock.call_args.kwargs["decision_scope"], "host")
        self.assertEqual(active_mock.call_args.kwargs["target_filters"]["target_host"], "ATN62288")

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
