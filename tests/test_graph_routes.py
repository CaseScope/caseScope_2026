import unittest
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import Mock, patch

from flask import Flask
from flask_login import LoginManager

from config import PermissionLevel
from models.case import Case
from models.case_file import CaseFile
from models.client import Client
from models.database import db
from models.graph import GraphEntity, GraphEntityObservation, GraphProjectionState, GraphRelationship, GraphRelationshipEvidence
from models.user import User
import routes.graph as graph_routes
from utils.graph_identity import GraphEntityType
from utils.graph_query import GraphNotFoundError, GraphQueryError


class GraphRoutesTestCase(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.secret_key = "test-secret"
        self.case = SimpleNamespace(id=7, uuid="case-uuid")

    def _json(self, response):
        return response.get_json()

    def test_graph_routes_are_login_protected(self):
        self.assertTrue(hasattr(graph_routes.graph_summary, "__wrapped__"))
        self.assertTrue(hasattr(graph_routes.graph_paths, "__wrapped__"))

    def test_authorized_analyst_can_read_summary(self):
        service = Mock()
        service.graph_summary.return_value = {"total_entities": 1}
        with self.app.test_request_context("/api/graph/case-uuid/summary"):
            with patch.object(graph_routes.Case, "get_by_uuid", return_value=self.case), \
                    patch.object(graph_routes, "_service", return_value=service):
                response = graph_routes.graph_summary.__wrapped__("case-uuid")

        self.assertEqual(self._json(response)["total_entities"], 1)
        service.graph_summary.assert_called_once_with(7)

    def test_viewer_is_not_blocked_from_post_path_search(self):
        service = Mock()
        service.path_search.return_value = {"paths": [], "nodes": [], "edges": []}
        with self.app.test_request_context(
            "/api/graph/case-uuid/paths",
            method="POST",
            json={"source_entity_id": 1, "target_entity_id": 2},
        ):
            with patch.object(graph_routes.Case, "get_by_uuid", return_value=self.case), \
                    patch.object(graph_routes, "_service", return_value=service):
                response = graph_routes.graph_paths.__wrapped__("case-uuid")

        self.assertTrue(self._json(response)["success"])
        service.path_search.assert_called_once()

    def test_inaccessible_case_returns_not_found_without_graph_lookup(self):
        service = Mock()
        with self.app.test_request_context("/api/graph/missing/summary"):
            with patch.object(graph_routes.Case, "get_by_uuid", return_value=None), \
                    patch.object(graph_routes, "_service", return_value=service):
                response, status = graph_routes.graph_summary.__wrapped__("missing")

        self.assertEqual(status, 404)
        self.assertFalse(self._json(response)["success"])
        service.graph_summary.assert_not_called()

    def test_cross_case_entity_id_returns_404(self):
        service = Mock()
        service.entity_detail.side_effect = GraphNotFoundError("Entity not found")
        with self.app.test_request_context("/api/graph/case-uuid/entities/99"):
            with patch.object(graph_routes.Case, "get_by_uuid", return_value=self.case), \
                    patch.object(graph_routes, "_service", return_value=service):
                response, status = graph_routes.graph_entity_detail.__wrapped__("case-uuid", 99)

        self.assertEqual(status, 404)
        self.assertEqual(self._json(response)["error"], "Entity not found")
        service.entity_detail.assert_called_once_with(7, 99)

    def test_cross_case_relationship_id_returns_404(self):
        service = Mock()
        service.relationship_detail.side_effect = GraphNotFoundError("Relationship not found")
        with self.app.test_request_context("/api/graph/case-uuid/relationships/99"):
            with patch.object(graph_routes.Case, "get_by_uuid", return_value=self.case), \
                    patch.object(graph_routes, "_service", return_value=service):
                response, status = graph_routes.graph_relationship_detail.__wrapped__("case-uuid", 99)

        self.assertEqual(status, 404)
        self.assertEqual(self._json(response)["error"], "Relationship not found")

    def test_malformed_filters_return_safe_400(self):
        service = Mock()
        service.search_entities.side_effect = GraphQueryError("Invalid entity type: BAD")
        with self.app.test_request_context("/api/graph/case-uuid/entities/search?q=x&type=BAD"):
            with patch.object(graph_routes.Case, "get_by_uuid", return_value=self.case), \
                    patch.object(graph_routes, "_service", return_value=service):
                response, status = graph_routes.graph_entity_search.__wrapped__("case-uuid")

        self.assertEqual(status, 400)
        self.assertEqual(self._json(response)["error"], "Invalid entity type: BAD")

    def test_evidence_route_scopes_by_resolved_case(self):
        service = Mock()
        service.exact_evidence.return_value = {"evidence_record_key": "erk:v2:" + ("a" * 64), "event": {}}
        key = "erk:v2:" + ("a" * 64)
        with self.app.test_request_context(f"/api/graph/case-uuid/evidence/{key}"):
            with patch.object(graph_routes.Case, "get_by_uuid", return_value=self.case), \
                    patch.object(graph_routes, "_service", return_value=service):
                response = graph_routes.graph_evidence_detail.__wrapped__("case-uuid", key)

        self.assertTrue(self._json(response)["success"])
        service.exact_evidence.assert_called_once_with(7, key)


class GraphRouteAuthorizationIntegrationTestCase(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config.update(
            SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            TESTING=True,
            SECRET_KEY="test-secret",
        )
        db.init_app(self.app)
        login_manager = LoginManager()
        login_manager.init_app(self.app)

        @login_manager.user_loader
        def load_user(user_id):
            return db.session.get(User, int(user_id))

        self.app.register_blueprint(graph_routes.graph_bp)
        self.ctx = self.app.app_context()
        self.ctx.push()
        for table in (
            Client.__table__,
            Case.__table__,
            CaseFile.__table__,
            User.__table__,
            GraphEntity.__table__,
            GraphEntityObservation.__table__,
            GraphRelationship.__table__,
            GraphRelationshipEvidence.__table__,
            GraphProjectionState.__table__,
        ):
            table.create(db.engine)
        self.case_a = Case(id=101, uuid="case-a", name="Case A", company="Client", created_by="tester")
        self.case_b = Case(id=202, uuid="case-b", name="Case B", company="Client", created_by="tester")
        self.viewer = User(
            id=1,
            username="viewer",
            full_name="Case Viewer",
            email="viewer@example.test",
            password_hash="not-used",
            permission_level=PermissionLevel.VIEWER,
            assigned_cases=[self.case_a.id],
            is_active=True,
        )
        self.analyst = User(
            id=2,
            username="analyst",
            full_name="Case Analyst",
            email="analyst@example.test",
            password_hash="not-used",
            permission_level=PermissionLevel.ANALYST,
            assigned_cases=[],
            is_active=True,
        )
        self.source = GraphEntity(
            case_id=self.case_a.id,
            entity_type=GraphEntityType.HOST,
            entity_key="host:a",
            display_value="A",
            canonical_value="A",
            first_seen_at=datetime(2026, 1, 1, 12, 0, 0),
            last_seen_at=datetime(2026, 1, 1, 12, 0, 0),
            metadata_json={},
        )
        self.target = GraphEntity(
            case_id=self.case_a.id,
            entity_type=GraphEntityType.HOST,
            entity_key="host:b",
            display_value="B",
            canonical_value="B",
            first_seen_at=datetime(2026, 1, 1, 12, 0, 0),
            last_seen_at=datetime(2026, 1, 1, 12, 0, 0),
            metadata_json={},
        )
        db.session.add_all([self.case_a, self.case_b, self.viewer, self.analyst, self.source, self.target])
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def _client_as_viewer(self):
        return self._client_as_user(self.viewer)

    def _client_as_analyst(self):
        return self._client_as_user(self.analyst)

    def _client_as_user(self, user):
        client = self.app.test_client()
        with client.session_transaction() as session:
            session["_user_id"] = str(user.id)
            session["_fresh"] = True
        return client

    def test_authorized_viewer_can_read_graph_summary_through_flask_login(self):
        response = self._client_as_viewer().get("/api/graph/case-a/summary")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["success"])
        self.assertEqual(response.get_json()["total_entities"], 2)

    def test_authorized_viewer_can_post_path_search_through_flask_login(self):
        response = self._client_as_viewer().post(
            "/api/graph/case-a/paths",
            json={
                "source_entity_id": self.source.id,
                "target_entity_id": self.target.id,
                "max_depth": 3,
                "max_paths": 3,
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["success"])
        self.assertEqual({node["id"] for node in response.get_json()["nodes"]}, {self.source.id, self.target.id})

    def test_malformed_path_limits_return_400_through_route(self):
        for field in ("max_depth", "max_paths"):
            payload = {
                "source_entity_id": self.source.id,
                "target_entity_id": self.target.id,
                "max_depth": 3,
                "max_paths": 3,
            }
            payload[field] = "banana"

            response = self._client_as_viewer().post("/api/graph/case-a/paths", json=payload)

            self.assertEqual(response.status_code, 400)
            self.assertFalse(response.get_json()["success"])
            self.assertIn(field, response.get_json()["error"])

    def test_viewer_assigned_to_another_case_cannot_access_graph_routes(self):
        response = self._client_as_viewer().get("/api/graph/case-b/summary")

        self.assertEqual(response.status_code, 403)

    def test_viewer_can_read_empty_graph_projection_status(self):
        GraphRelationshipEvidence.query.delete()
        GraphRelationship.query.delete()
        GraphEntity.query.delete()
        db.session.commit()

        response = self._client_as_viewer().get("/api/graph/case-a/status")

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["success"])
        self.assertEqual(payload["empty_state"], "not_built")
        self.assertFalse(payload["can_build"])

    def test_viewer_cannot_trigger_graph_build(self):
        GraphRelationshipEvidence.query.delete()
        GraphRelationship.query.delete()
        GraphEntity.query.delete()
        db.session.commit()

        response = self._client_as_viewer().post("/api/graph/case-a/build")

        self.assertEqual(response.status_code, 403)

    def test_analyst_build_queues_async_projection_for_empty_graph(self):
        GraphRelationshipEvidence.query.delete()
        GraphRelationship.query.delete()
        GraphEntity.query.delete()
        db.session.commit()
        queued = SimpleNamespace(id="task-1")

        with patch.object(graph_routes, "get_fresh_client", return_value=object()), \
                patch.object(graph_routes, "graph_eligible_probe", return_value=True), \
                patch("tasks.celery_tasks.materialize_case_graph_task.apply_async", return_value=queued) as apply_async:
            response = self._client_as_analyst().post("/api/graph/case-a/build")

        self.assertEqual(response.status_code, 202)
        payload = response.get_json()
        self.assertTrue(payload["success"])
        self.assertEqual(payload["task_id"], "task-1")
        state = GraphProjectionState.query.filter_by(case_id=self.case_a.id).one()
        self.assertEqual(state.status, "pending")
        self.assertEqual(state.mode, "manual_build")
        queued_kwargs = apply_async.call_args.kwargs["kwargs"]
        self.assertEqual(queued_kwargs["case_id"], self.case_a.id)
        self.assertEqual(queued_kwargs["case_uuid"], self.case_a.uuid)
        self.assertEqual(queued_kwargs["mode"], "manual_build")
        self.assertEqual(queued_kwargs["projection_state_id"], state.id)
        self.assertNotIn("args", apply_async.call_args.kwargs)

    def test_repeated_build_while_running_is_rejected(self):
        GraphRelationshipEvidence.query.delete()
        GraphRelationship.query.delete()
        GraphEntity.query.delete()
        db.session.add(GraphProjectionState(
            case_id=self.case_a.id,
            case_uuid=self.case_a.uuid,
            status="running",
            mode="manual_build",
            projection_version="graph_events_v1",
        ))
        db.session.commit()

        response = self._client_as_analyst().post("/api/graph/case-a/build")

        self.assertEqual(response.status_code, 409)
        self.assertIn("already queued or running", response.get_json()["error"])

    def test_failed_partial_projection_shows_retry_state(self):
        db.session.add(GraphProjectionState(
            case_id=self.case_a.id,
            case_uuid=self.case_a.uuid,
            status="failed",
            mode="historical_backfill",
            projection_version="graph_events_v1",
            last_error="stopped after checkpoint",
        ))
        db.session.commit()

        response = self._client_as_analyst().get("/api/graph/case-a/status")

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["empty_state"], "failed")
        self.assertTrue(payload["can_build"])

    def test_retry_failed_partial_projection_queues_resume(self):
        db.session.add(GraphProjectionState(
            case_id=self.case_a.id,
            case_uuid=self.case_a.uuid,
            status="failed",
            mode="historical_backfill",
            projection_version="graph_events_v1",
            last_error="stopped after checkpoint",
        ))
        db.session.commit()
        queued = SimpleNamespace(id="retry-task")

        with patch.object(graph_routes, "get_fresh_client", return_value=object()), \
                patch.object(graph_routes, "graph_eligible_probe", return_value=True), \
                patch("tasks.celery_tasks.materialize_case_graph_task.apply_async", return_value=queued) as apply_async:
            response = self._client_as_analyst().post("/api/graph/case-a/build")

        self.assertEqual(response.status_code, 202)
        kwargs = apply_async.call_args.kwargs["kwargs"]
        self.assertTrue(kwargs["resume"])
        self.assertEqual(kwargs["case_id"], self.case_a.id)
        self.assertEqual(kwargs["case_uuid"], self.case_a.uuid)
        self.assertEqual(kwargs["mode"], "manual_build")
        self.assertEqual(kwargs["projection_state_id"], GraphProjectionState.query.filter_by(case_id=self.case_a.id).one().id)

    def test_no_eligible_evidence_build_records_explanatory_state(self):
        GraphRelationshipEvidence.query.delete()
        GraphRelationship.query.delete()
        GraphEntity.query.delete()
        db.session.commit()

        with patch.object(graph_routes, "get_fresh_client", return_value=object()), \
                patch.object(graph_routes, "graph_eligible_probe", return_value=False):
            response = self._client_as_analyst().post("/api/graph/case-a/build")

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["empty_state"], "no_eligible_evidence")
        state = GraphProjectionState.query.filter_by(case_id=self.case_a.id).one()
        self.assertEqual(state.status, "no_eligible_evidence")


class GraphProducerKwargsAuditTests(unittest.TestCase):
    def test_current_materialize_case_graph_call_sites_supply_kwargs_case_id(self):
        import ast
        from pathlib import Path

        files = [
            Path("/opt/casescope/routes/graph.py"),
            Path("/opt/casescope/utils/completion_reconciler.py"),
            Path("/opt/casescope/tasks/celery_tasks.py"),
        ]
        found = 0
        for path in files:
            source = path.read_text(encoding="utf-8")
            self.assertNotIn('send_task("tasks.materialize_case_graph")', source)
            self.assertNotIn("send_task('tasks.materialize_case_graph')", source)
            tree = ast.parse(source, filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                    continue
                target = ast.unparse(node.func.value) if hasattr(ast, "unparse") else ""
                if "materialize_case_graph" not in target and "materialize_case_graph" not in ast.dump(node.func.value):
                    continue
                if node.func.attr == "delay":
                    self.fail(f"{path} queues materialize_case_graph via delay(); use apply_async(kwargs=...)")
                if node.func.attr != "apply_async":
                    continue
                found += 1
                kw_names = {keyword.arg for keyword in node.keywords}
                self.assertIn("kwargs", kw_names, f"{path} apply_async missing kwargs=")
                kwargs_node = next(keyword.value for keyword in node.keywords if keyword.arg == "kwargs")
                self.assertIsInstance(kwargs_node, ast.Dict)
                keys = [key.value for key in kwargs_node.keys if isinstance(key, ast.Constant)]
                self.assertIn("case_id", keys, f"{path} kwargs dict does not include case_id")
        self.assertGreaterEqual(found, 3)


if __name__ == "__main__":
    unittest.main()
