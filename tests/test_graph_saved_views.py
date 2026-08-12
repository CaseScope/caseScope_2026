from utils.graph_identity import GraphEntityType
from utils.graph_materializer import clear_case_graph
from utils.graph_saved_views import GraphSavedViewConflictError, GraphSavedViewError, GraphSavedViewService

from models.database import db
from models.graph_saved_view import GraphSavedView
from tests.phase0d_test_support import Phase0DSQLiteTestCase, actor


class GraphSavedViewsTestCase(Phase0DSQLiteTestCase):
    def setUp(self):
        super().setUp()
        self.service = GraphSavedViewService()
        self.actor = actor()

    def test_save_view_with_graph_ids_stores_stable_references(self):
        source, _target, relationship = self.make_relationship()

        result = self.service.create_view(
            1,
            title="View",
            view_payload={
                "root_entity_ids": [source.id],
                "expanded_entity_ids": [source.id],
                "visible_relationship_ids": [relationship.id],
                "node_coordinates_json": {str(source.id): {"x": 10, "y": 20}},
                "selected_entity_id": source.id,
                "selected_relationship_id": relationship.id,
            },
            actor=self.actor,
        )
        view = result["view"]

        self.assertEqual(view["root_entity_references"][0]["entity_key"], source.entity_key)
        self.assertTrue(view["root_entity_references"][0]["stable_reference_key"].startswith("threadref:v1:"))
        self.assertEqual(view["visible_relationship_references"][0]["relationship_type"], relationship.relationship_type)
        self.assertIn(view["root_entity_references"][0]["stable_reference_key"], view["node_coordinates_json"])

    def test_clear_graph_rematerialize_restore_resolves_new_ids(self):
        source, _target, relationship = self.make_relationship()
        old_source_id = source.id
        old_relationship_id = relationship.id
        created = self.service.create_view(
            1,
            title="Restorable",
            view_payload={
                "root_entity_ids": [source.id],
                "expanded_entity_ids": [source.id],
                "visible_relationship_ids": [relationship.id],
                "node_coordinates_json": {str(source.id): {"x": 10, "y": 20}},
                "selected_entity_id": source.id,
                "selected_relationship_id": relationship.id,
            },
            actor=self.actor,
        )

        clear_case_graph(1)
        db.session.flush()
        self.make_relationship(case_id=2)
        db.session.flush()
        self.make_relationship(case_id=1)
        db.session.commit()

        restored = self.service.restore_payload(1, created["view"]["uuid"])

        self.assertNotEqual(restored["resolved"]["root_entity_ids"], [old_source_id])
        self.assertNotEqual(restored["resolved"]["visible_relationship_ids"], [old_relationship_id])
        self.assertEqual(len(restored["resolved"]["root_entity_ids"]), 1)
        self.assertEqual(len(restored["resolved"]["visible_relationship_ids"]), 1)
        self.assertFalse(restored["resolved"]["unresolved_entity_references"])
        self.assertFalse(restored["resolved"]["unresolved_relationship_references"])

    def test_unresolved_refs_reported_and_stored_state_unchanged(self):
        source, _target, relationship = self.make_relationship()
        created = self.service.create_view(
            1,
            title="Unresolved later",
            view_payload={"root_entity_ids": [source.id], "visible_relationship_ids": [relationship.id]},
            actor=self.actor,
        )
        view_uuid = created["view"]["uuid"]
        original_state = created["view"]["view_state_json"]
        original_hash = created["view"]["view_state_sha256"]

        clear_case_graph(1)
        db.session.commit()
        restored = self.service.restore_payload(1, view_uuid)
        row = GraphSavedView.query.filter_by(uuid=view_uuid).one()

        self.assertTrue(restored["resolved"]["unresolved_entity_references"])
        self.assertTrue(restored["resolved"]["unresolved_relationship_references"])
        self.assertEqual(row.view_state_json, original_state)
        self.assertEqual(row.view_state_sha256, original_hash)

    def test_stale_version_update_conflicts(self):
        source, _target, _relationship = self.make_relationship()
        created = self.service.create_view(
            1,
            title="Versioned",
            view_payload={"root_entity_ids": [source.id]},
            actor=self.actor,
        )
        updated = self.service.update_view(
            1,
            created["view"]["uuid"],
            expected_version=1,
            title="Versioned updated",
            actor=self.actor,
        )

        self.assertEqual(updated["view"]["version"], 2)
        with self.assertRaises(GraphSavedViewConflictError):
            self.service.update_view(1, created["view"]["uuid"], expected_version=1, title="stale", actor=self.actor)

    def test_fingerprint_deterministic_for_equivalent_reference_sets(self):
        source, target, relationship = self.make_relationship()
        first = self.service.create_view(
            1,
            title="First",
            view_payload={
                "root_entity_ids": [source.id],
                "expanded_entity_ids": [target.id, source.id],
                "visible_relationship_ids": [relationship.id],
                "node_coordinates_json": {str(target.id): {"y": 2, "x": 1}, str(source.id): {"x": 3, "y": 4}},
            },
            actor=self.actor,
        )
        second = self.service.create_view(
            1,
            title="Second",
            view_payload={
                "expanded_entity_ids": [source.id, target.id],
                "root_entity_ids": [source.id],
                "visible_relationship_ids": [relationship.id],
                "node_coordinates_json": {str(source.id): {"y": 4, "x": 3}, str(target.id): {"x": 1, "y": 2}},
            },
            actor=self.actor,
        )

        self.assertEqual(first["view"]["evidence_set_fingerprint"], second["view"]["evidence_set_fingerprint"])

    def test_oversize_entity_refs_rejected(self):
        entity_ids = []
        for index in range(501):
            entity = self.make_entity(
                entity_type=GraphEntityType.HOST,
                entity_key=f"host:{index}",
                display=f"HOST-{index}",
            )
            entity_ids.append(entity.id)
        db.session.commit()

        with self.assertRaises(GraphSavedViewError):
            self.service.create_view(
                1,
                title="Too many",
                view_payload={"expanded_entity_ids": entity_ids},
                actor=self.actor,
            )


if __name__ == "__main__":
    import unittest

    unittest.main()
