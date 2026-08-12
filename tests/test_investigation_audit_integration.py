import json
import unittest

from sqlalchemy import event

from models.audit_log import AuditAction, AuditEntityType, AuditLog
from models.database import db
from tests.phase0d_test_support import Phase0DSQLiteTestCase, actor, evidence_key
from tests.test_investigation_threads import exact_evidence_payload
from utils.audit_chain import verify_chain
from utils.graph_saved_views import GraphSavedViewService
from utils.investigation_threads import InvestigationThreadService
from unittest.mock import patch


_SQLITE_AUDIT_ID = 0


def _assign_sqlite_audit_id(_mapper, connection, target):
    global _SQLITE_AUDIT_ID
    if target.id is not None:
        return
    _SQLITE_AUDIT_ID += 1
    target.id = _SQLITE_AUDIT_ID


class InvestigationAuditIntegrationTestCase(Phase0DSQLiteTestCase):
    patch_audit = False

    def setUp(self):
        global _SQLITE_AUDIT_ID
        _SQLITE_AUDIT_ID = 0
        event.listen(AuditLog, "before_insert", _assign_sqlite_audit_id)
        super().setUp()
        self.actor = actor()
        self.thread_service = InvestigationThreadService()
        self.view_service = GraphSavedViewService()

    def tearDown(self):
        super().tearDown()
        event.remove(AuditLog, "before_insert", _assign_sqlite_audit_id)

    def _details(self, row):
        return json.loads(row.details or "{}")

    def test_thread_mutations_write_real_audit_rows_and_chain_validates(self):
        source, _target, _relationship = self.make_relationship()
        thread = self.thread_service.create_thread(1, title="Audited Thread", actor=self.actor)
        version = thread["version"]

        updated = self.thread_service.update_thread(
            1,
            thread["uuid"],
            expected_version=version,
            actor=self.actor,
            status="investigating",
            include_in_report=True,
        )
        version = updated["version"]

        linked_entity = self.thread_service.link_entity(
            1,
            thread["uuid"],
            expected_version=version,
            entity_id=source.id,
            actor=self.actor,
        )
        version = linked_entity["version"]

        with patch(
            "utils.investigation_threads.GraphQueryService.exact_evidence",
            side_effect=lambda case_id, key: exact_evidence_payload(case_id, key),
        ):
            linked_evidence = self.thread_service.link_evidence(
                1,
                thread["uuid"],
                expected_version=version,
                evidence_record_key=evidence_key("a"),
                actor=self.actor,
            )
        version = linked_evidence["version"]

        unlinked = self.thread_service.unlink_entity(
            1,
            thread["uuid"],
            expected_version=version,
            stable_reference_key=linked_entity["entity"]["stable_reference_key"],
            actor=self.actor,
        )
        version = unlinked["version"]

        note = self.thread_service.add_note(1, thread["uuid"], expected_version=version, body="Initial note", actor=self.actor)
        version = note["version"]
        edited = self.thread_service.update_note(
            1,
            thread["uuid"],
            note_uuid=note["note"]["uuid"],
            expected_version=version,
            body="Edited note",
            actor=self.actor,
        )
        version = edited["version"]
        self.thread_service.remove_note(
            1,
            thread["uuid"],
            note_uuid=note["note"]["uuid"],
            expected_version=version,
            actor=self.actor,
        )

        rows = AuditLog.query.filter_by(entity_type=AuditEntityType.INVESTIGATION_THREAD, entity_id=thread["uuid"]).all()
        actions = [row.action for row in rows]
        field_names = [row.field_name for row in rows]
        details = [self._details(row) for row in rows]

        self.assertIn(AuditAction.CREATED, actions)
        self.assertIn(AuditAction.UPDATED, actions)
        self.assertIn(AuditAction.LINKED, actions)
        self.assertIn(AuditAction.UNLINKED, actions)
        self.assertIn("status", field_names)
        self.assertIn("include_in_report", field_names)
        self.assertTrue(any(detail.get("membership_kind") == "evidence" for detail in details))
        self.assertTrue(any(row.action == AuditAction.CREATED and row.field_name == "note" for row in rows))
        self.assertTrue(any(row.action == AuditAction.UPDATED and row.field_name == "note" for row in rows))
        self.assertTrue(any(row.action == AuditAction.DELETED and row.field_name == "note" for row in rows))
        self.assertTrue(verify_chain()["valid"])

    def test_create_from_selection_uses_common_operation_id_in_real_audit_rows(self):
        source, _target, _relationship = self.make_relationship()
        with patch(
            "utils.investigation_threads.GraphQueryService.exact_evidence",
            side_effect=lambda case_id, key: exact_evidence_payload(case_id, key),
        ):
            created = self.thread_service.create_from_selection(
                1,
                title="Bulk audited",
                entity_ids=[source.id],
                evidence_record_keys=[evidence_key("b")],
                actor=self.actor,
            )

        rows = AuditLog.query.filter_by(entity_type=AuditEntityType.INVESTIGATION_THREAD, entity_id=created["thread"]["uuid"]).all()
        operation_ids = {row.operation_id for row in rows if row.operation_id}

        self.assertEqual(operation_ids, {created["operation_id"]})
        self.assertGreaterEqual(len(rows), 3)
        self.assertTrue(verify_chain()["valid"])

    def test_saved_view_mutations_write_real_audit_rows_and_chain_validates(self):
        source, _target, relationship = self.make_relationship()
        created = self.view_service.create_view(
            1,
            title="Audited View",
            view_payload={
                "root_entity_ids": [source.id],
                "visible_relationship_ids": [relationship.id],
            },
            actor=self.actor,
        )
        updated = self.view_service.update_view(
            1,
            created["view"]["uuid"],
            expected_version=1,
            title="Audited View Updated",
            actor=self.actor,
        )
        self.view_service.delete_view(
            1,
            created["view"]["uuid"],
            expected_version=updated["view"]["version"],
            actor=self.actor,
        )

        rows = AuditLog.query.filter_by(entity_type=AuditEntityType.GRAPH_SAVED_VIEW, entity_id=created["view"]["uuid"]).all()
        actions = [row.action for row in rows]
        details = [self._details(row) for row in rows]

        self.assertEqual(actions, [AuditAction.CREATED, AuditAction.UPDATED, AuditAction.DELETED])
        self.assertTrue(any(detail.get("changes", {}).get("title") for detail in details))
        self.assertTrue(any(detail.get("final_state", {}).get("uuid") == created["view"]["uuid"] for detail in details))
        self.assertTrue(verify_chain()["valid"])


if __name__ == "__main__":
    unittest.main()
