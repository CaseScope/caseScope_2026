"""Phase 0E support lifecycle acceptance tests."""
import unittest

from flask import Flask

from models.case import Case
from models.database import db
from models.graph import GraphEntity, GraphRelationship, GraphRelationshipEvidence
from models.ioc_evidence_match import IOCEvidenceMatch
from utils.graph_identity import (
    GraphDerivationType,
    GraphEntityType,
    GraphRelationshipType,
    GraphSourceRefType,
    GraphSupportState,
    GraphValidationState,
)
from utils.graph_support_lifecycle import GraphSupportLifecycleService


def erk(char):
    return 'erk:v2:' + (char * 64)


class GraphSupportLifecycleTestCase(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config.update(
            SQLALCHEMY_DATABASE_URI='sqlite:///:memory:',
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            TESTING=True,
            SECRET_KEY='test-secret',
        )
        db.init_app(self.app)
        self.ctx = self.app.app_context()
        self.ctx.push()
        for table in (
            Case.__table__,
            GraphEntity.__table__,
            GraphRelationship.__table__,
            GraphRelationshipEvidence.__table__,
            IOCEvidenceMatch.__table__,
        ):
            table.create(db.engine)
        self.case = Case(id=1, uuid='life-case', name='Lifecycle Case', company='Client', created_by='tester')
        other = Case(id=2, uuid='other-case', name='Other', company='Client', created_by='tester')
        db.session.add_all([self.case, other])
        db.session.commit()
        self.service = GraphSupportLifecycleService(session=db.session, batch_size=50)

        self.source = GraphEntity(
            case_id=self.case.id,
            entity_type=GraphEntityType.HOST,
            entity_key='known_system:1',
            display_value='HOST-A',
            canonical_value='HOST-A',
            metadata_json={},
        )
        self.target = GraphEntity(
            case_id=self.case.id,
            entity_type=GraphEntityType.IP_ADDRESS,
            entity_key='ip:1.2.3.4',
            display_value='1.2.3.4',
            canonical_value='1.2.3.4',
            metadata_json={},
        )
        db.session.add_all([self.source, self.target])
        db.session.flush()
        self.rel = GraphRelationship(
            case_id=self.case.id,
            source_entity_id=self.source.id,
            relationship_type=GraphRelationshipType.OWNS_IP,
            target_entity_id=self.target.id,
            derivation_type=GraphDerivationType.DETERMINISTIC,
            extractor_name='test',
            extractor_version='1',
            validation_state=GraphValidationState.ACTIVE,
            metadata_json={},
        )
        db.session.add(self.rel)
        db.session.flush()
        self.support_a = GraphRelationshipEvidence(
            case_id=self.case.id,
            relationship_id=self.rel.id,
            evidence_record_key=erk('a'),
            source_table='events',
            evidence_role='supporting_record',
            extractor_name='test',
            extractor_version='1',
            support_state=GraphSupportState.ACTIVE,
            source_ref_type=GraphSourceRefType.CASE_FILE,
            source_ref_id=101,
            metadata_json={},
        )
        self.support_b = GraphRelationshipEvidence(
            case_id=self.case.id,
            relationship_id=self.rel.id,
            evidence_record_key=erk('b'),
            source_table='events',
            evidence_role='supporting_record',
            extractor_name='test',
            extractor_version='1',
            support_state=GraphSupportState.ACTIVE,
            source_ref_type=GraphSourceRefType.CASE_FILE,
            source_ref_id=202,
            metadata_json={},
        )
        db.session.add_all([self.support_a, self.support_b])
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def test_remove_one_support_keeps_edge_active(self):
        self.service.begin_case_file_removal(case_id=self.case.id, case_file_id=101)
        self.service.finalize_case_file_removal(case_id=self.case.id, case_file_id=101)
        db.session.refresh(self.support_a)
        db.session.refresh(self.support_b)
        db.session.refresh(self.rel)
        self.assertEqual(self.support_a.support_state, GraphSupportState.UNAVAILABLE)
        self.assertEqual(self.support_b.support_state, GraphSupportState.ACTIVE)
        self.assertEqual(self.rel.validation_state, GraphValidationState.ACTIVE)
        self.assertEqual(self.service.active_support_count(self.case.id, self.rel.id), 1)

    def test_remove_last_support_marks_unsupported(self):
        self.service.begin_case_file_removal(case_id=self.case.id, case_file_id=101)
        self.service.finalize_case_file_removal(case_id=self.case.id, case_file_id=101)
        self.service.begin_case_file_removal(case_id=self.case.id, case_file_id=202)
        self.service.finalize_case_file_removal(case_id=self.case.id, case_file_id=202)
        db.session.refresh(self.rel)
        self.assertEqual(self.rel.validation_state, GraphValidationState.UNSUPPORTED)
        self.assertEqual(self.service.active_support_count(self.case.id, self.rel.id), 0)
        self.assertEqual(
            GraphRelationshipEvidence.query.filter_by(relationship_id=self.rel.id).count(),
            2,
        )

    def test_repeated_invalidation_is_idempotent(self):
        self.service.begin_case_file_removal(case_id=self.case.id, case_file_id=101)
        self.service.finalize_case_file_removal(case_id=self.case.id, case_file_id=101)
        again = self.service.finalize_case_file_removal(case_id=self.case.id, case_file_id=101)
        self.assertEqual(again['support_updated'], 0)
        db.session.refresh(self.support_a)
        self.assertEqual(self.support_a.support_state, GraphSupportState.UNAVAILABLE)

    def test_pending_hides_support_before_delete(self):
        self.service.begin_case_file_removal(case_id=self.case.id, case_file_id=101)
        db.session.refresh(self.support_a)
        db.session.refresh(self.rel)
        self.assertEqual(self.support_a.support_state, GraphSupportState.PENDING_REMOVAL)
        self.assertEqual(self.rel.validation_state, GraphValidationState.ACTIVE)
        self.assertEqual(self.service.active_support_count(self.case.id, self.rel.id), 1)

    def test_restore_after_failed_removal(self):
        self.service.begin_case_file_removal(case_id=self.case.id, case_file_id=101)
        restored = self.service.restore_case_file_support_if_source_remains(
            case_id=self.case.id,
            case_file_id=101,
        )
        self.assertEqual(restored['support_restored'], 1)
        db.session.refresh(self.support_a)
        self.assertEqual(self.support_a.support_state, GraphSupportState.ACTIVE)

    def test_reprocess_invalidates_old_then_rematerialize_reactivates(self):
        self.service.begin_case_file_revalidation(case_id=self.case.id, case_file_id=101)
        self.service.finalize_case_file_revalidation(case_id=self.case.id, case_file_id=101)
        db.session.refresh(self.support_a)
        self.assertEqual(self.support_a.support_state, GraphSupportState.INVALIDATED)
        self.support_a.support_state = GraphSupportState.ACTIVE
        self.support_a.support_state_reason = 'rematerialized'
        self.support_a.extractor_version = '2'
        db.session.commit()
        self.service.revalidate_relationships(self.case.id, [self.rel.id])
        db.session.refresh(self.rel)
        self.assertEqual(self.rel.validation_state, GraphValidationState.ACTIVE)

    def test_cross_case_isolation(self):
        other_id = 2
        other_entity_s = GraphEntity(
            case_id=other_id,
            entity_type=GraphEntityType.HOST,
            entity_key='known_system:9',
            display_value='HOST-B',
            canonical_value='HOST-B',
            metadata_json={},
        )
        other_entity_t = GraphEntity(
            case_id=other_id,
            entity_type=GraphEntityType.IP_ADDRESS,
            entity_key='ip:9.9.9.9',
            display_value='9.9.9.9',
            canonical_value='9.9.9.9',
            metadata_json={},
        )
        db.session.add_all([other_entity_s, other_entity_t])
        db.session.flush()
        other_rel = GraphRelationship(
            case_id=other_id,
            source_entity_id=other_entity_s.id,
            relationship_type=GraphRelationshipType.OWNS_IP,
            target_entity_id=other_entity_t.id,
            derivation_type=GraphDerivationType.DETERMINISTIC,
            extractor_name='test',
            extractor_version='1',
            validation_state=GraphValidationState.ACTIVE,
            metadata_json={},
        )
        db.session.add(other_rel)
        db.session.flush()
        other_support = GraphRelationshipEvidence(
            case_id=other_id,
            relationship_id=other_rel.id,
            evidence_record_key=erk('a'),
            source_table='events',
            evidence_role='supporting_record',
            extractor_name='test',
            extractor_version='1',
            support_state=GraphSupportState.ACTIVE,
            source_ref_type=GraphSourceRefType.CASE_FILE,
            source_ref_id=101,
            metadata_json={},
        )
        db.session.add(other_support)
        db.session.commit()

        self.service.finalize_case_file_removal(case_id=self.case.id, case_file_id=101)
        db.session.refresh(other_support)
        db.session.refresh(other_rel)
        self.assertEqual(other_support.support_state, GraphSupportState.ACTIVE)
        self.assertEqual(other_rel.validation_state, GraphValidationState.ACTIVE)


class GraphQueryActiveSupportFilterTestCase(unittest.TestCase):
    def test_support_counts_filter_uses_active_state(self):
        source = open('/opt/casescope/utils/graph_query.py', encoding='utf-8').read()
        identity = open('/opt/casescope/utils/graph_identity.py', encoding='utf-8').read()
        self.assertIn('GraphSupportState.ACTIVE', source)
        self.assertIn('active_support_count', source)
        self.assertIn("UNSUPPORTED = 'UNSUPPORTED'", identity)


if __name__ == '__main__':
    unittest.main()
