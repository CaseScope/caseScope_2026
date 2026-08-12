import re
import unittest

from utils.graph_identity import GraphDerivationType, GraphEntityType, GraphRelationshipType
from utils.investigation_references import (
    InvestigationReferenceError,
    build_entity_reference,
    build_evidence_reference,
    build_ioc_reference,
    build_relationship_reference,
    build_unified_finding_reference,
    evidence_set_fingerprint,
    membership_fingerprint_entry,
    snapshot_sha256,
)


class InvestigationReferencesTestCase(unittest.TestCase):
    def test_stable_reference_keys_are_deterministic_sha256_keys(self):
        entity_a = build_entity_reference(case_id=1, entity_type=GraphEntityType.HOST, entity_key="host:alpha")
        entity_b = build_entity_reference(case_id=1, entity_type=GraphEntityType.HOST, entity_key="host:alpha")
        relationship = build_relationship_reference(
            case_id=1,
            source_entity_type=GraphEntityType.HOST,
            source_entity_key="host:alpha",
            relationship_type=GraphRelationshipType.RUNS_IMAGE,
            target_entity_type=GraphEntityType.FILE_PATH,
            target_entity_key=r"host:host:alpha:path:C:\TOOLS\CMD.EXE",
            derivation_type=GraphDerivationType.DETERMINISTIC,
        )
        evidence = build_evidence_reference(case_id=1, evidence_record_key="erk:v2:" + "a" * 64)
        ioc = build_ioc_reference(case_id=1, ioc_uuid="11111111-1111-4111-8111-111111111111")
        finding = build_unified_finding_reference(
            case_id=1,
            analysis_id="analysis-1",
            source_system="detector",
            dedup_key="dedup-1",
            finding_id="finding-1",
        )

        self.assertEqual(entity_a["stable_reference_key"], entity_b["stable_reference_key"])
        for reference in (entity_a, relationship, evidence, ioc, finding):
            self.assertRegex(reference["stable_reference_key"], r"^threadref:v1:[0-9a-f]{64}$")

    def test_mutable_display_labels_are_not_in_reference_hash_payload(self):
        original = build_entity_reference(case_id=1, entity_type=GraphEntityType.HOST, entity_key="host:alpha")
        renamed = build_entity_reference(case_id=1, entity_type=GraphEntityType.HOST, entity_key="host:alpha")
        renamed["display_value"] = "Mutable analyst label"

        self.assertEqual(original["stable_reference_key"], renamed["stable_reference_key"])
        self.assertNotIn("display", original)
        self.assertNotIn("label", original)

    def test_equivalent_snapshot_json_hashes_the_same(self):
        left = {"snapshot_version": "entity-snap:v1", "entity": {"type": "HOST", "key": "host:alpha"}, "tags": ["a", "b"]}
        right = {"tags": ["a", "b"], "entity": {"key": "host:alpha", "type": "HOST"}, "snapshot_version": "entity-snap:v1"}

        self.assertEqual(snapshot_sha256(left), snapshot_sha256(right))

    def test_changed_snapshot_field_changes_hash(self):
        baseline = {"snapshot_version": "entity-snap:v1", "entity_key": "host:alpha", "display_value": "ALPHA"}
        changed = {"snapshot_version": "entity-snap:v1", "entity_key": "host:alpha", "display_value": "BETA"}

        self.assertNotEqual(snapshot_sha256(baseline), snapshot_sha256(changed))

    def test_evidence_set_fingerprint_is_set_based(self):
        entries = [
            membership_fingerprint_entry(kind="entity", stable_reference_key="threadref:v1:" + "a" * 64, snapshot_sha256_value="1" * 64),
            membership_fingerprint_entry(kind="evidence", stable_reference_key="erk:v2:" + "b" * 64, snapshot_sha256_value="2" * 64),
        ]

        self.assertEqual(evidence_set_fingerprint(entries), evidence_set_fingerprint(reversed(entries)))
        self.assertNotEqual(evidence_set_fingerprint(entries), evidence_set_fingerprint(entries[:1]))
        self.assertRegex(evidence_set_fingerprint(entries), r"^evidence-set:v1:[0-9a-f]{64}$")

    def test_narrative_fields_are_not_fingerprint_helper_inputs(self):
        entry = membership_fingerprint_entry(
            kind="entity",
            stable_reference_key="threadref:v1:" + "a" * 64,
            snapshot_sha256_value="1" * 64,
        )

        self.assertEqual({"kind", "stable_reference_key", "snapshot_sha256"}, set(entry))
        self.assertNotIn("analyst_rationale", entry)
        self.assertNotIn("note", entry)

    def test_relationship_durable_identity_excludes_extractor_name_and_version(self):
        base_kwargs = dict(
            case_id=1,
            source_entity_type=GraphEntityType.HOST,
            source_entity_key="host:alpha",
            relationship_type=GraphRelationshipType.RUNS_IMAGE,
            target_entity_type=GraphEntityType.FILE_PATH,
            target_entity_key=r"host:host:alpha:path:C:\TOOLS\CMD.EXE",
            derivation_type=GraphDerivationType.DETERMINISTIC,
        )

        first = build_relationship_reference(**base_kwargs)
        second = build_relationship_reference(**base_kwargs)

        self.assertEqual(first["stable_reference_key"], second["stable_reference_key"])
        self.assertNotIn("extractor_name", first)
        self.assertNotIn("extractor_version", first)

    def test_invalid_erk_rejected(self):
        with self.assertRaises(InvestigationReferenceError):
            build_evidence_reference(case_id=1, evidence_record_key="erk:v2:not-valid")


if __name__ == "__main__":
    unittest.main()
