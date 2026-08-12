from tests.phase0d_test_support import Phase0DSQLiteTestCase, actor
from utils.graph_saved_views import GraphSavedViewService


class GraphSavedViewRoutesTestCase(Phase0DSQLiteTestCase):
    include_users = True
    register_routes = True

    def setUp(self):
        super().setUp()
        self.service = GraphSavedViewService()
        self.analyst_actor = actor()

    def create_view(self, case_id=1):
        source, _target, relationship = self.make_relationship(case_id=case_id)
        return self.service.create_view(
            case_id,
            title=f"Case {case_id} view",
            view_payload={
                "root_entity_ids": [source.id],
                "expanded_entity_ids": [source.id],
                "visible_relationship_ids": [relationship.id],
                "selected_entity_id": source.id,
            },
            actor=self.analyst_actor,
        )

    def test_viewer_can_get_views_and_graph_summary(self):
        view = self.create_view()
        self.login_as("viewer_a")

        list_response = self.client.get("/api/graph/case-a/views")
        detail_response = self.client.get(f"/api/graph/case-a/views/{view['view']['uuid']}")
        summary_response = self.client.get("/api/graph/case-a/summary")

        self.assertEqual(list_response.status_code, 200)
        self.assertEqual(detail_response.status_code, 200)
        self.assertEqual(summary_response.status_code, 200)
        self.assertTrue(list_response.get_json()["success"])
        self.assertTrue(detail_response.get_json()["success"])
        self.assertGreaterEqual(summary_response.get_json()["total_entities"], 1)

    def test_viewer_write_view_routes_are_forbidden(self):
        view = self.create_view()
        source_id = view["live_resolution"]["entities"][view["view"]["root_entity_references"][0]["stable_reference_key"]]
        self.login_as("viewer_a")

        responses = [
            self.client.post("/api/graph/case-a/views", json={"title": "Denied", "view": {"root_entity_ids": [source_id]}}),
            self.client.put(
                f"/api/graph/case-a/views/{view['view']['uuid']}",
                json={"expected_version": 1, "title": "Denied"},
            ),
            self.client.delete(f"/api/graph/case-a/views/{view['view']['uuid']}?expected_version=1"),
        ]

        self.assertTrue(all(response.status_code == 403 for response in responses))

    def test_cross_case_viewer_cannot_access_other_case_view(self):
        view = self.create_view(case_id=2)
        self.login_as("viewer_a")

        response = self.client.get(f"/api/graph/case-b/views/{view['view']['uuid']}")

        self.assertIn(response.status_code, (403, 404))

    def test_guessed_view_uuid_cannot_bypass_case_auth(self):
        self.login_as("viewer_a")

        response = self.client.get("/api/graph/case-b/views/00000000-0000-4000-8000-000000000000")

        self.assertIn(response.status_code, (403, 404))

    def test_guessed_entity_id_cannot_bypass_case_auth(self):
        source, _target, _relationship = self.make_relationship(case_id=2)
        self.login_as("viewer_a")

        response = self.client.get(f"/api/graph/case-b/entities/{source.id}")

        self.assertIn(response.status_code, (403, 404))

    def test_stale_version_returns_409(self):
        view = self.create_view()
        self.login_as("analyst")
        first = self.client.put(
            f"/api/graph/case-a/views/{view['view']['uuid']}",
            json={"expected_version": 1, "title": "First update"},
        )
        stale = self.client.put(
            f"/api/graph/case-a/views/{view['view']['uuid']}",
            json={"expected_version": 1, "title": "Stale update"},
        )

        self.assertEqual(first.status_code, 200)
        self.assertEqual(stale.status_code, 409)
        self.assertTrue(stale.get_json()["stale_version"])


if __name__ == "__main__":
    import unittest

    unittest.main()
