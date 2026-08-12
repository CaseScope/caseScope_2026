import os
import tempfile
from unittest.mock import patch

from config import Config
from models.database import db
from models.graph import GraphRelationship
from models.graph_saved_view import GraphSavedView
from models.investigation_thread import InvestigationThreadReportSnapshot
from tests.phase0d_test_support import Phase0DSQLiteTestCase, actor
from utils.graph_identity import GraphDerivationType, GraphEntityType, GraphRelationshipType
from utils.graph_materializer import clear_case_graph
from utils.graph_saved_views import GraphSavedViewConflictError, GraphSavedViewService
from utils.investigation_thread_report_adapter import InvestigationThreadReportAdapter
from utils.investigation_thread_report_snapshots import InvestigationThreadReportSnapshotService
from utils.investigation_threads import InvestigationThreadConflictError, InvestigationThreadService


class InvestigationThreadReportSnapshotTestCase(Phase0DSQLiteTestCase):
    def setUp(self):
        super().setUp()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.storage_patch = patch.object(Config, "STORAGE_FOLDER", self.temp_dir.name)
        self.storage_patch.start()
        self.thread_service = InvestigationThreadService()
        self.view_service = GraphSavedViewService()
        self.snapshot_service = InvestigationThreadReportSnapshotService()
        self.actor = actor()

    def tearDown(self):
        self.storage_patch.stop()
        self.temp_dir.cleanup()
        super().tearDown()

    def _thread_with_view(self):
        source, target, relationship = self.make_relationship()
        view = self.view_service.create_view(
            1,
            title="Exact view",
            view_payload={
                "root_entity_ids": [source.id],
                "expanded_entity_ids": [source.id, target.id],
                "visible_relationship_ids": [relationship.id],
                "node_coordinates_json": {
                    str(source.id): {"x": 10, "y": 20},
                    str(target.id): {"x": 300, "y": 20},
                },
            },
            actor=self.actor,
        )["view"]
        thread = self.thread_service.create_thread(1, title="Thread", actor=self.actor)
        version = self.thread_service.link_entity(1, thread["uuid"], expected_version=1, entity_id=source.id, actor=self.actor)["version"]
        version = self.thread_service.link_relationship(1, thread["uuid"], expected_version=version, relationship_id=relationship.id, actor=self.actor)["version"]
        thread = self.thread_service.update_thread(
            1,
            thread["uuid"],
            expected_version=version,
            actor=self.actor,
            current_saved_view_uuid=view["uuid"],
            analyst_conclusion="Analyst conclusion v1",
            include_in_report=True,
        )
        return thread, view

    def test_snapshot_pins_thread_view_fingerprint_hash_and_adapter_is_deterministic(self):
        thread, view = self._thread_with_view()

        snapshot = self.snapshot_service.create_snapshot(
            1,
            thread_uuid=thread["uuid"],
            expected_thread_version=thread["version"],
            expected_saved_view_version=view["version"],
            report_generation_uuid="11111111-1111-4111-8111-111111111111",
            actor=self.actor,
        )
        context = InvestigationThreadReportAdapter().build_context([snapshot])

        self.assertEqual(snapshot["thread_version"], thread["version"])
        self.assertEqual(snapshot["saved_view_version"], view["version"])
        self.assertEqual(snapshot["evidence_set_fingerprint"], thread["evidence_set_fingerprint"])
        self.assertTrue(snapshot["snapshot_sha256"].startswith("report-snapshot:v1:"))
        self.assertTrue(snapshot["graph_render_sha256"].startswith("graph-render:v1:"))
        self.assertTrue(os.path.exists(snapshot["graph_render_path"]))
        self.assertIn("Analyst conclusion v1", context["investigation_thread_report_section"])
        self.assertIn(snapshot["snapshot_sha256"], context["investigation_thread_report_section"])

    def test_later_thread_view_and_graph_changes_do_not_change_old_snapshot(self):
        thread, view = self._thread_with_view()
        snapshot = self.snapshot_service.create_snapshot(
            1,
            thread_uuid=thread["uuid"],
            expected_thread_version=thread["version"],
            expected_saved_view_version=view["version"],
            report_generation_uuid="22222222-2222-4222-8222-222222222222",
            actor=self.actor,
        )
        row = InvestigationThreadReportSnapshot.query.filter_by(uuid=snapshot["uuid"]).one()
        original_json = row.snapshot_json
        original_hash = row.snapshot_sha256
        original_graph_hash = row.graph_render_sha256

        updated_thread = self.thread_service.update_thread(
            1,
            thread["uuid"],
            expected_version=thread["version"],
            actor=self.actor,
            analyst_conclusion="Changed v2",
        )
        self.view_service.update_view(
            1,
            view["uuid"],
            expected_version=view["version"],
            actor=self.actor,
            title="Changed view",
        )
        clear_case_graph(1)
        db.session.flush()
        self.make_relationship(case_id=1)
        db.session.commit()

        reloaded = InvestigationThreadReportSnapshot.query.filter_by(uuid=snapshot["uuid"]).one()
        self.assertEqual(reloaded.thread_version, thread["version"])
        self.assertEqual(reloaded.saved_view_version, view["version"])
        self.assertGreater(updated_thread["version"], thread["version"])
        self.assertEqual(reloaded.snapshot_json, original_json)
        self.assertEqual(reloaded.snapshot_sha256, original_hash)
        self.assertEqual(reloaded.graph_render_sha256, original_graph_hash)

    def test_stale_versions_conflict_and_thread_without_saved_view_reports(self):
        source, _target, _relationship = self.make_relationship()
        thread = self.thread_service.create_thread(1, title="No View", actor=self.actor)
        updated = self.thread_service.link_entity(1, thread["uuid"], expected_version=1, entity_id=source.id, actor=self.actor)

        with self.assertRaises(InvestigationThreadConflictError):
            self.snapshot_service.create_snapshot(1, thread_uuid=thread["uuid"], expected_thread_version=1, actor=self.actor)

        snapshot = self.snapshot_service.create_snapshot(
            1,
            thread_uuid=thread["uuid"],
            expected_thread_version=updated["version"],
            actor=self.actor,
        )
        section = InvestigationThreadReportAdapter().build_context([snapshot])["investigation_thread_report_section"]
        self.assertIsNone(snapshot["saved_view_uuid"])
        self.assertIn("No Saved Graph View was captured", section)

    def test_stale_saved_view_version_conflicts(self):
        thread, view = self._thread_with_view()
        self.view_service.update_view(1, view["uuid"], expected_version=view["version"], actor=self.actor, title="v2")

        with self.assertRaises(GraphSavedViewConflictError):
            self.snapshot_service.create_snapshot(
                1,
                thread_uuid=thread["uuid"],
                expected_thread_version=thread["version"],
                expected_saved_view_version=view["version"],
                actor=self.actor,
            )


if __name__ == "__main__":
    import unittest

    unittest.main()
