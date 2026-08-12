from unittest.mock import patch

from tests.phase0d_test_support import Phase0DSQLiteTestCase, actor, evidence_key
from utils.investigation_threads import InvestigationThreadService


class InvestigationThreadRoutesTestCase(Phase0DSQLiteTestCase):
    include_users = True
    register_routes = True

    def setUp(self):
        super().setUp()
        self.service = InvestigationThreadService()
        self.analyst_actor = actor()

    def create_thread(self, case_id=1):
        return self.service.create_thread(case_id, title=f"Case {case_id} thread", actor=self.analyst_actor)

    def test_viewer_can_get_threads(self):
        thread = self.create_thread()
        self.login_as("viewer_a")

        list_response = self.client.get("/api/investigation-threads/case-a")
        detail_response = self.client.get(f"/api/investigation-threads/case-a/{thread['uuid']}")

        self.assertEqual(list_response.status_code, 200)
        self.assertEqual(detail_response.status_code, 200)
        self.assertTrue(list_response.get_json()["success"])
        self.assertEqual(detail_response.get_json()["thread"]["uuid"], thread["uuid"])

    def test_viewer_write_thread_routes_are_forbidden(self):
        source, _target, _relationship = self.make_relationship()
        thread = self.create_thread()
        self.login_as("viewer_a")

        responses = [
            self.client.post("/api/investigation-threads/case-a", json={"title": "Denied"}),
            self.client.patch(f"/api/investigation-threads/case-a/{thread['uuid']}", json={"expected_version": 1, "title": "Denied"}),
            self.client.post(
                f"/api/investigation-threads/case-a/{thread['uuid']}/selection",
                json={"expected_version": 1, "entity_ids": [source.id]},
            ),
            self.client.post(
                f"/api/investigation-threads/case-a/{thread['uuid']}/entities",
                json={"expected_version": 1, "entity_id": source.id},
            ),
            self.client.delete(
                f"/api/investigation-threads/case-a/{thread['uuid']}/entities/threadref:v1:{'a' * 64}",
                json={"expected_version": 1},
            ),
            self.client.post(
                f"/api/investigation-threads/case-a/{thread['uuid']}/notes",
                json={"expected_version": 1, "body": "Denied"},
            ),
        ]

        self.assertTrue(all(response.status_code == 403 for response in responses))

    def test_cross_case_viewer_cannot_access_other_case_thread(self):
        thread = self.create_thread(case_id=2)
        self.login_as("viewer_a")

        response = self.client.get(f"/api/investigation-threads/case-b/{thread['uuid']}")

        self.assertIn(response.status_code, (403, 404))

    def test_guessed_thread_uuid_cannot_bypass_case_auth(self):
        self.login_as("viewer_a")

        response = self.client.get("/api/investigation-threads/case-b/00000000-0000-4000-8000-000000000000")

        self.assertIn(response.status_code, (403, 404))

    def test_guessed_entity_membership_cannot_bypass_case_auth(self):
        source, _target, _relationship = self.make_relationship(case_id=2)
        thread = self.create_thread(case_id=2)
        self.login_as("viewer_a")

        response = self.client.post(
            f"/api/investigation-threads/case-b/{thread['uuid']}/entities",
            json={"expected_version": 1, "entity_id": source.id},
        )

        self.assertIn(response.status_code, (403, 404))

    def test_stale_version_returns_409(self):
        thread = self.create_thread()
        self.login_as("analyst")
        first = self.client.patch(
            f"/api/investigation-threads/case-a/{thread['uuid']}",
            json={"expected_version": 1, "title": "First update"},
        )

        stale = self.client.patch(
            f"/api/investigation-threads/case-a/{thread['uuid']}",
            json={"expected_version": 1, "title": "Stale update"},
        )

        self.assertEqual(first.status_code, 200)
        self.assertEqual(stale.status_code, 409)
        self.assertTrue(stale.get_json()["stale_version"])


if __name__ == "__main__":
    import unittest

    unittest.main()
