from types import SimpleNamespace
from unittest.mock import patch

from sqlalchemy.exc import OperationalError

from models.database import db
from models.graph import GraphEntity, GraphRelationship
from models.investigation_thread import (
    InvestigationThread,
    InvestigationThreadEntity,
    InvestigationThreadEvidence,
    InvestigationThreadFinding,
    InvestigationThreadIOC,
    InvestigationThreadNote,
    InvestigationThreadRelationship,
)
from tests.phase0d_test_support import Phase0DSQLiteTestCase, actor, evidence_key
from utils.case_deletion import _delete_many
from utils.graph_materializer import clear_case_graph
from utils.graph_query import GraphNotFoundError
from utils.investigation_threads import (
    InvestigationThreadConflictError,
    InvestigationThreadError,
    InvestigationThreadService,
)


def exact_evidence_payload(case_id, erk):
    return {
        "evidence_record_key": erk,
        "event": {
            "case_id": case_id,
            "timestamp_utc": "2026-01-01T12:00:00",
            "artifact_type": "evtx",
            "source_file": "Security.evtx",
            "source_host": "ALPHA",
            "event_id": "4688",
            "channel": "Security",
            "provider": "Microsoft-Windows-Security-Auditing",
            "process_name": "cmd.exe",
            "process_path": r"C:\Windows\System32\cmd.exe",
            "process_id": 4242,
            "selector_key": "selector-1",
            "evidence_identity_version": "v2",
            "evidence_identity_quality": "exact",
        },
    }


class InvestigationThreadsTestCase(Phase0DSQLiteTestCase):
    def setUp(self):
        super().setUp()
        self.service = InvestigationThreadService()
        self.actor = actor()

    def create_thread(self, title="Thread"):
        return self.service.create_thread(1, title=title, actor=self.actor)

    def test_graph_rebuild_survival_resolves_new_ids_and_preserves_snapshot_hash(self):
        _source, _target, relationship = self.make_relationship()
        thread = self.create_thread()
        entity_result = self.service.link_entity(1, thread["uuid"], expected_version=1, entity_id=relationship.source_entity_id, actor=self.actor)
        relationship_result = self.service.link_relationship(
            1,
            thread["uuid"],
            expected_version=entity_result["version"],
            relationship_id=relationship.id,
            actor=self.actor,
        )
        before = self.service.get_thread(1, thread["uuid"])
        old_entity_id = before["entities"][0]["live"]["id"]
        old_relationship_id = before["relationships"][0]["live"]["id"]
        entity_snapshot_hash = before["entities"][0]["snapshot_sha256"]
        relationship_snapshot_hash = before["relationships"][0]["snapshot_sha256"]

        clear_case_graph(1)
        db.session.flush()
        self.make_relationship(case_id=2)
        db.session.flush()
        self.make_relationship(case_id=1)
        db.session.commit()

        after = self.service.get_thread(1, thread["uuid"])

        self.assertEqual(after["counts"]["entities"], 1)
        self.assertEqual(after["counts"]["relationships"], 1)
        self.assertNotEqual(after["entities"][0]["live"]["id"], old_entity_id)
        self.assertNotEqual(after["relationships"][0]["live"]["id"], old_relationship_id)
        self.assertTrue(after["entities"][0]["live_available"])
        self.assertTrue(after["relationships"][0]["live_available"])
        self.assertEqual(after["entities"][0]["snapshot_sha256"], entity_snapshot_hash)
        self.assertEqual(after["relationships"][0]["snapshot_sha256"], relationship_snapshot_hash)
        self.assertEqual(after["thread"]["version"], relationship_result["version"])

    def test_source_unavailable_keeps_snapshot_and_hash(self):
        thread = self.create_thread()
        erk = evidence_key("a")
        with patch("utils.investigation_threads.GraphQueryService.exact_evidence", side_effect=lambda case_id, key: exact_evidence_payload(case_id, key)):
            linked = self.service.link_evidence(1, thread["uuid"], expected_version=1, evidence_record_key=erk, actor=self.actor)
        snapshot_hash = linked["evidence"]["snapshot_sha256"]

        with patch("utils.investigation_threads.GraphQueryService.exact_evidence", side_effect=GraphNotFoundError("Evidence not found")):
            payload = self.service.get_thread(1, thread["uuid"])

        self.assertTrue(payload["evidence"][0]["snapshot_available"])
        self.assertFalse(payload["evidence"][0]["live_source_available"])
        self.assertEqual(payload["evidence"][0]["snapshot_sha256"], snapshot_hash)

    def test_optimistic_concurrency_update(self):
        thread = self.create_thread()
        updated = self.service.update_thread(1, thread["uuid"], expected_version=1, actor=self.actor, title="Updated")

        self.assertEqual(updated["version"], 2)
        with self.assertRaises(InvestigationThreadConflictError):
            self.service.update_thread(1, thread["uuid"], expected_version=1, actor=self.actor, title="Stale")

    def test_membership_add_remove_and_note_stale_version_conflicts(self):
        source, _target, _relationship = self.make_relationship()
        thread = self.create_thread()
        added = self.service.link_entity(1, thread["uuid"], expected_version=1, entity_id=source.id, actor=self.actor)

        with self.assertRaises(InvestigationThreadConflictError):
            self.service.link_evidence(1, thread["uuid"], expected_version=1, evidence_record_key=evidence_key("b"), actor=self.actor)
        with self.assertRaises(InvestigationThreadConflictError):
            self.service.unlink_entity(1, thread["uuid"], expected_version=1, stable_reference_key=added["entity"]["stable_reference_key"], actor=self.actor)
        with self.assertRaises(InvestigationThreadConflictError):
            self.service.add_note(1, thread["uuid"], expected_version=1, body="stale note", actor=self.actor)

    def test_narrative_only_edit_does_not_change_fingerprint(self):
        source, _target, _relationship = self.make_relationship()
        thread = self.create_thread()
        linked = self.service.link_entity(1, thread["uuid"], expected_version=1, entity_id=source.id, actor=self.actor)
        before = linked["version"], linked["entity"]["stable_reference_key"]
        fingerprint = self.service.get_thread(1, thread["uuid"])["thread"]["evidence_set_fingerprint"]

        updated = self.service.update_thread(
            1,
            thread["uuid"],
            expected_version=before[0],
            actor=self.actor,
            description="Narrative only",
            analyst_conclusion="Conclusion only",
        )

        self.assertEqual(updated["evidence_set_fingerprint"], fingerprint)

    def test_membership_change_changes_fingerprint(self):
        source, _target, _relationship = self.make_relationship()
        thread = self.create_thread()
        before = thread["evidence_set_fingerprint"]
        linked = self.service.link_entity(1, thread["uuid"], expected_version=1, entity_id=source.id, actor=self.actor)

        self.assertNotEqual(linked["version"], thread["version"])
        self.assertNotEqual(linked["entity"]["stable_reference_key"], "")
        self.assertNotEqual(self.service.get_thread(1, thread["uuid"])["thread"]["evidence_set_fingerprint"], before)

    def test_duplicate_membership_is_idempotent(self):
        source, _target, _relationship = self.make_relationship()
        thread = self.create_thread()
        first = self.service.link_entity(1, thread["uuid"], expected_version=1, entity_id=source.id, actor=self.actor)
        duplicate = self.service.link_entity(1, thread["uuid"], expected_version=first["version"], entity_id=source.id, actor=self.actor)

        self.assertFalse(duplicate["added"])
        self.assertEqual(duplicate["version"], first["version"])
        self.assertEqual(InvestigationThreadEntity.query.count(), 1)

    def test_add_selection_duplicate_reports_already_present(self):
        source, _target, _relationship = self.make_relationship()
        thread = self.create_thread()
        first = self.service.add_selection(1, thread["uuid"], expected_version=1, entity_ids=[source.id], actor=self.actor)
        duplicate = self.service.add_selection(1, thread["uuid"], expected_version=first["version"], entity_ids=[source.id], actor=self.actor)

        self.assertEqual(duplicate["counts"]["entities"]["added"], 0)
        self.assertEqual(duplicate["counts"]["entities"]["already_present"], 1)

    def test_finding_pins_analysis_id_and_does_not_switch_to_latest(self):
        thread = self.create_thread()
        findings = {
            "analysis-old": {"title": "Old finding", "canonical": {"severity": "medium"}},
            "analysis-new": {"title": "New finding", "canonical": {"severity": "critical"}},
        }

        def load_finding(_case_id, analysis_id, _source_system, _dedup_key, _finding_id):
            return findings.get(analysis_id)

        with patch.object(InvestigationThreadService, "_load_unified_finding", side_effect=load_finding):
            linked = self.service.link_finding(
                1,
                thread["uuid"],
                expected_version=1,
                analysis_id="analysis-old",
                source_system="detector",
                dedup_key="dedup-1",
                finding_id="finding-1",
                actor=self.actor,
            )
            payload = self.service.get_thread(1, thread["uuid"])

        self.assertEqual(linked["finding"]["stable_reference"]["analysis_id"], "analysis-old")
        self.assertEqual(payload["findings"][0]["live"]["title"], "Old finding")

    def test_ai_actor_rejected(self):
        with self.assertRaises(InvestigationThreadError):
            self.service.create_thread(1, title="AI thread", actor=actor(actor_type="ai", is_ai=True))

    def test_case_deletion_removes_thread_tables(self):
        source, _target, relationship = self.make_relationship()
        ioc = self.make_ioc()
        thread = self.create_thread()
        version = thread["version"]
        version = self.service.link_entity(1, thread["uuid"], expected_version=version, entity_id=source.id, actor=self.actor)["version"]
        version = self.service.link_relationship(1, thread["uuid"], expected_version=version, relationship_id=relationship.id, actor=self.actor)["version"]
        version = self.service.link_ioc(1, thread["uuid"], expected_version=version, ioc_uuid=ioc.uuid, actor=self.actor)["version"]
        with patch("utils.investigation_threads.GraphQueryService.exact_evidence", side_effect=lambda case_id, key: exact_evidence_payload(case_id, key)):
            version = self.service.link_evidence(1, thread["uuid"], expected_version=version, evidence_record_key=evidence_key("c"), actor=self.actor)["version"]
        version = self.service.add_note(1, thread["uuid"], expected_version=version, body="note", actor=self.actor)["version"]
        with patch.object(InvestigationThreadService, "_load_unified_finding", return_value={"title": "Finding"}):
            self.service.link_finding(
                1,
                thread["uuid"],
                expected_version=version,
                analysis_id="analysis-1",
                source_system="detector",
                dedup_key="dedup-1",
                finding_id="finding-1",
                actor=self.actor,
            )

        for model in (
            InvestigationThreadEntity,
            InvestigationThreadRelationship,
            InvestigationThreadEvidence,
            InvestigationThreadIOC,
            InvestigationThreadFinding,
            InvestigationThreadNote,
            InvestigationThread,
        ):
            _delete_many(model, case_id=1)
        db.session.commit()

        self.assertEqual(InvestigationThread.query.filter_by(case_id=1).count(), 0)
        self.assertEqual(InvestigationThreadEntity.query.filter_by(case_id=1).count(), 0)
        self.assertEqual(InvestigationThreadRelationship.query.filter_by(case_id=1).count(), 0)
        self.assertEqual(InvestigationThreadEvidence.query.filter_by(case_id=1).count(), 0)
        self.assertEqual(InvestigationThreadIOC.query.filter_by(case_id=1).count(), 0)
        self.assertEqual(InvestigationThreadFinding.query.filter_by(case_id=1).count(), 0)
        self.assertEqual(InvestigationThreadNote.query.filter_by(case_id=1).count(), 0)


if __name__ == "__main__":
    import unittest

    unittest.main()
