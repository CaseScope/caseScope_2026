import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from flask import Flask

import routes.graph as graph_routes
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


if __name__ == "__main__":
    unittest.main()
