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

    def _add_graph_support(
        self,
        evidence_record_key,
        *,
        case_file_id=None,
        support_state=GraphSupportState.ACTIVE,
    ):
        support = GraphRelationshipEvidence(
            case_id=self.case.id,
            relationship_id=self.rel.id,
            evidence_record_key=evidence_record_key,
            source_table='events',
            evidence_role='supporting_record',
            extractor_name='test',
            extractor_version='1',
            support_state=support_state,
            source_ref_type=GraphSourceRefType.CASE_FILE if case_file_id is not None else None,
            source_ref_id=case_file_id,
            metadata_json={},
        )
        db.session.add(support)
        db.session.commit()
        return support

    def _add_ioc_match(
        self,
        evidence_record_key,
        *,
        case_file_id=None,
        support_state=GraphSupportState.ACTIVE,
        ioc_uuid='44444444-4444-4444-4444-444444444444',
    ):
        match = IOCEvidenceMatch(
            case_id=self.case.id,
            ioc_id=1,
            ioc_uuid=ioc_uuid,
            ioc_type='Domain',
            matched_value='example.test',
            matched_field='search_blob',
            evidence_record_key=evidence_record_key,
            source_table='events',
            source_ref_type=GraphSourceRefType.CASE_FILE if case_file_id is not None else None,
            source_ref_id=case_file_id,
            support_state=support_state,
            metadata_json={},
        )
        db.session.add(match)
        db.session.commit()
        return match

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

    def test_restore_after_failed_removal_restores_ioc_matches(self):
        match = IOCEvidenceMatch(
            case_id=self.case.id,
            ioc_id=1,
            ioc_uuid='11111111-1111-1111-1111-111111111111',
            ioc_type='Domain',
            matched_value='example.com',
            matched_field='search_blob',
            evidence_record_key=erk('a'),
            source_table='events',
            source_ref_type=GraphSourceRefType.CASE_FILE,
            source_ref_id=101,
            support_state=GraphSupportState.ACTIVE,
            metadata_json={},
        )
        db.session.add(match)
        db.session.commit()

        self.service.begin_case_file_removal(case_id=self.case.id, case_file_id=101)
        db.session.refresh(match)
        self.assertEqual(match.support_state, GraphSupportState.PENDING_REMOVAL)
        restored = self.service.restore_case_file_support_if_source_remains(
            case_id=self.case.id,
            case_file_id=101,
        )
        db.session.refresh(match)
        self.assertEqual(restored['ioc_matches_restored'], 1)
        self.assertEqual(match.support_state, GraphSupportState.ACTIVE)

    def test_graph_erk_fallback_does_not_claim_other_case_file_support(self):
        owned_by_other = self._add_graph_support(erk('c'), case_file_id=202)

        self.service.begin_case_file_removal(
            case_id=self.case.id,
            case_file_id=101,
            evidence_record_keys=[erk('c')],
        )
        db.session.refresh(owned_by_other)
        self.assertEqual(owned_by_other.support_state, GraphSupportState.ACTIVE)
        self.assertEqual(owned_by_other.source_ref_type, GraphSourceRefType.CASE_FILE)
        self.assertEqual(owned_by_other.source_ref_id, 202)

    def test_ioc_erk_fallback_does_not_claim_other_case_file_support(self):
        owned_by_other = self._add_ioc_match(
            erk('c'),
            case_file_id=202,
            ioc_uuid='55555555-5555-5555-5555-555555555555',
        )

        self.service.begin_case_file_removal(
            case_id=self.case.id,
            case_file_id=101,
            evidence_record_keys=[erk('c')],
        )
        db.session.refresh(owned_by_other)
        self.assertEqual(owned_by_other.support_state, GraphSupportState.ACTIVE)
        self.assertEqual(owned_by_other.source_ref_type, GraphSourceRefType.CASE_FILE)
        self.assertEqual(owned_by_other.source_ref_id, 202)

    def test_legacy_graph_erk_fallback_backfills_source_and_marks_pending(self):
        legacy = self._add_graph_support(erk('c'), case_file_id=None)

        self.service.begin_case_file_removal(
            case_id=self.case.id,
            case_file_id=303,
            evidence_record_keys=[erk('c')],
        )
        db.session.refresh(legacy)
        self.assertEqual(legacy.support_state, GraphSupportState.PENDING_REMOVAL)
        self.assertEqual(legacy.source_ref_type, GraphSourceRefType.CASE_FILE)
        self.assertEqual(legacy.source_ref_id, 303)

    def test_erk_fallback_ioc_match_backfills_source_and_restores(self):
        match = IOCEvidenceMatch(
            case_id=self.case.id,
            ioc_id=1,
            ioc_uuid='22222222-2222-2222-2222-222222222222',
            ioc_type='Domain',
            matched_value='example.net',
            matched_field='search_blob',
            evidence_record_key=erk('a'),
            source_table='events',
            source_ref_type=None,
            source_ref_id=None,
            support_state=GraphSupportState.ACTIVE,
            metadata_json={},
        )
        db.session.add(match)
        db.session.commit()

        self.service.begin_case_file_removal(
            case_id=self.case.id,
            case_file_id=101,
            evidence_record_keys=[erk('a')],
        )
        db.session.refresh(match)
        self.assertEqual(match.support_state, GraphSupportState.PENDING_REMOVAL)
        self.assertEqual(match.source_ref_type, GraphSourceRefType.CASE_FILE)
        self.assertEqual(match.source_ref_id, 101)

        self.service.restore_case_file_support_if_source_remains(
            case_id=self.case.id,
            case_file_id=101,
        )
        db.session.refresh(match)
        self.assertEqual(match.support_state, GraphSupportState.ACTIVE)

    def test_erk_fallback_ioc_match_backfills_source_and_finalizes(self):
        match = IOCEvidenceMatch(
            case_id=self.case.id,
            ioc_id=1,
            ioc_uuid='33333333-3333-3333-3333-333333333333',
            ioc_type='Domain',
            matched_value='example.org',
            matched_field='search_blob',
            evidence_record_key=erk('a'),
            source_table='events',
            source_ref_type=None,
            source_ref_id=None,
            support_state=GraphSupportState.ACTIVE,
            metadata_json={},
        )
        db.session.add(match)
        db.session.commit()

        self.service.begin_case_file_removal(
            case_id=self.case.id,
            case_file_id=101,
            evidence_record_keys=[erk('a')],
        )
        self.service.finalize_case_file_removal(case_id=self.case.id, case_file_id=101)
        db.session.refresh(match)
        self.assertEqual(match.source_ref_type, GraphSourceRefType.CASE_FILE)
        self.assertEqual(match.source_ref_id, 101)
        self.assertEqual(match.support_state, GraphSupportState.UNAVAILABLE)

    def test_case_file_begin_failure_rolls_back_partial_batched_removal(self):
        self.service.batch_size = 1
        legacy_supports = [
            self._add_graph_support(erk(char), case_file_id=None)
            for char in ('c', 'd', 'e')
        ]
        legacy_matches = [
            self._add_ioc_match(
                erk(char),
                case_file_id=None,
                ioc_uuid=f'66666666-6666-6666-6666-66666666666{idx}',
            )
            for idx, char in enumerate(('c', 'd', 'e'))
        ]

        self.service.begin_case_file_removal(case_id=self.case.id, case_file_id=101)
        db.session.refresh(self.support_a)
        self.assertEqual(self.support_a.support_state, GraphSupportState.PENDING_REMOVAL)

        def failing_keys():
            for char in ('c', 'd', 'e'):
                yield erk(char)
            raise RuntimeError('second case ERK stream failed')

        with self.assertRaisesRegex(RuntimeError, 'second case ERK stream failed'):
            self.service.begin_case_file_removal(
                case_id=self.case.id,
                case_file_id=202,
                evidence_record_keys=failing_keys(),
            )

        db.session.expire_all()
        self.assertEqual(
            GraphRelationshipEvidence.query.filter_by(
                case_id=self.case.id,
                source_ref_id=202,
                support_state=GraphSupportState.PENDING_REMOVAL,
            ).count(),
            0,
        )
        self.assertEqual(
            IOCEvidenceMatch.query.filter_by(
                case_id=self.case.id,
                source_ref_id=202,
                support_state=GraphSupportState.PENDING_REMOVAL,
            ).count(),
            0,
        )
        self.assertEqual(GraphRelationshipEvidence.query.get(self.support_b.id).support_state, GraphSupportState.ACTIVE)
        for support in legacy_supports:
            current = GraphRelationshipEvidence.query.get(support.id)
            self.assertEqual(current.support_state, GraphSupportState.ACTIVE)
            self.assertIsNone(current.source_ref_type)
            self.assertIsNone(current.source_ref_id)
        for match in legacy_matches:
            current = IOCEvidenceMatch.query.get(match.id)
            self.assertEqual(current.support_state, GraphSupportState.ACTIVE)
            self.assertIsNone(current.source_ref_type)
            self.assertIsNone(current.source_ref_id)

        self.service.restore_case_file_support_if_source_remains(
            case_id=self.case.id,
            case_file_id=101,
        )
        db.session.expire_all()
        self.assertEqual(GraphRelationshipEvidence.query.get(self.support_a.id).support_state, GraphSupportState.ACTIVE)
        self.assertEqual(GraphRelationshipEvidence.query.get(self.support_b.id).support_state, GraphSupportState.ACTIVE)
        for support in legacy_supports:
            self.assertEqual(GraphRelationshipEvidence.query.get(support.id).support_state, GraphSupportState.ACTIVE)

    def test_case_file_begin_failure_rolls_back_partial_batched_revalidation(self):
        self.service.batch_size = 1
        legacy_supports = [
            self._add_graph_support(erk(char), case_file_id=None)
            for char in ('f', 'g', 'h')
        ]
        legacy_matches = [
            self._add_ioc_match(
                erk(char),
                case_file_id=None,
                ioc_uuid=f'77777777-7777-7777-7777-77777777777{idx}',
            )
            for idx, char in enumerate(('f', 'g', 'h'))
        ]

        self.service.begin_case_file_revalidation(case_id=self.case.id, case_file_id=101)

        def failing_keys():
            for char in ('f', 'g', 'h'):
                yield erk(char)
            raise RuntimeError('revalidation ERK stream failed')

        with self.assertRaisesRegex(RuntimeError, 'revalidation ERK stream failed'):
            self.service.begin_case_file_revalidation(
                case_id=self.case.id,
                case_file_id=202,
                evidence_record_keys=failing_keys(),
            )

        db.session.expire_all()
        self.assertEqual(GraphRelationshipEvidence.query.get(self.support_b.id).support_state, GraphSupportState.ACTIVE)
        for support in legacy_supports:
            current = GraphRelationshipEvidence.query.get(support.id)
            self.assertEqual(current.support_state, GraphSupportState.ACTIVE)
            self.assertIsNone(current.source_ref_type)
        for match in legacy_matches:
            current = IOCEvidenceMatch.query.get(match.id)
            self.assertEqual(current.support_state, GraphSupportState.ACTIVE)
            self.assertIsNone(current.source_ref_type)

        self.service.restore_case_file_support_if_source_remains(
            case_id=self.case.id,
            case_file_id=101,
        )
        db.session.expire_all()
        self.assertEqual(GraphRelationshipEvidence.query.get(self.support_a.id).support_state, GraphSupportState.ACTIVE)

    def test_case_file_erk_batches_cover_all_legacy_support_once(self):
        self.service.batch_size = 1
        supports = [
            self._add_graph_support(erk(char), case_file_id=None)
            for char in ('i', 'j', 'k')
        ]
        matches = [
            self._add_ioc_match(
                erk(char),
                case_file_id=None,
                ioc_uuid=f'88888888-8888-8888-8888-88888888888{idx}',
            )
            for idx, char in enumerate(('i', 'j', 'k'))
        ]

        result = self.service.begin_case_file_removal(
            case_id=self.case.id,
            case_file_id=303,
            evidence_record_keys=[erk('i'), erk('j'), erk('k')],
        )

        self.assertEqual(result['support_updated'], 3)
        self.assertEqual(result['ioc_matches_updated'], 3)
        for support in supports:
            current = GraphRelationshipEvidence.query.get(support.id)
            self.assertEqual(current.support_state, GraphSupportState.PENDING_REMOVAL)
            self.assertEqual(current.source_ref_id, 303)
        for match in matches:
            current = IOCEvidenceMatch.query.get(match.id)
            self.assertEqual(current.support_state, GraphSupportState.PENDING_REMOVAL)
            self.assertEqual(current.source_ref_id, 303)

    def test_legacy_dns_extractor_support_invalidated_and_relationship_revalidated(self):
        dns_rel = GraphRelationship(
            case_id=self.case.id,
            source_entity_id=self.source.id,
            relationship_type=GraphRelationshipType.RESOLVED_TO,
            target_entity_id=self.target.id,
            derivation_type=GraphDerivationType.OBSERVED,
            extractor_name='zeek_dns_resolved_to_ip',
            extractor_version='1',
            validation_state=GraphValidationState.ACTIVE,
            metadata_json={},
        )
        db.session.add(dns_rel)
        db.session.flush()
        dns_support = GraphRelationshipEvidence(
            case_id=self.case.id,
            relationship_id=dns_rel.id,
            evidence_record_key='native:v1:zeek_dns:5:0:abcdef',
            source_table='network_logs',
            evidence_role='supporting_record',
            extractor_name='zeek_dns_resolved_to_ip',
            extractor_version='1',
            support_state=GraphSupportState.ACTIVE,
            source_ref_type=GraphSourceRefType.PCAP_FILE,
            source_ref_id=5,
            metadata_json={},
        )
        db.session.add(dns_support)
        db.session.commit()

        result = self.service.invalidate_support_by_extractor(
            extractor_name='zeek_dns_resolved_to_ip',
            reason='test dns disabled',
        )
        db.session.refresh(dns_support)
        db.session.refresh(dns_rel)
        self.assertEqual(result['support_updated'], 1)
        self.assertEqual(dns_support.support_state, GraphSupportState.INVALIDATED)
        self.assertEqual(dns_rel.validation_state, GraphValidationState.UNSUPPORTED)

    def test_legacy_dns_reconciliation_rerun_repairs_already_invalidated_support(self):
        other_source = GraphEntity(
            case_id=2,
            entity_type=GraphEntityType.DOMAIN,
            entity_key='domain:example.com',
            display_value='example.com',
            canonical_value='example.com',
            metadata_json={},
        )
        other_target = GraphEntity(
            case_id=2,
            entity_type=GraphEntityType.IP_ADDRESS,
            entity_key='ip:5.6.7.8',
            display_value='5.6.7.8',
            canonical_value='5.6.7.8',
            metadata_json={},
        )
        db.session.add_all([other_source, other_target])
        db.session.flush()
        stale_rel = GraphRelationship(
            case_id=2,
            source_entity_id=other_source.id,
            relationship_type=GraphRelationshipType.RESOLVED_TO,
            target_entity_id=other_target.id,
            derivation_type=GraphDerivationType.OBSERVED,
            extractor_name='zeek_dns_resolved_to_ip',
            extractor_version='1',
            validation_state=GraphValidationState.ACTIVE,
            metadata_json={},
        )
        db.session.add(stale_rel)
        db.session.flush()
        stale_support = GraphRelationshipEvidence(
            case_id=2,
            relationship_id=stale_rel.id,
            evidence_record_key='native:v1:zeek_dns:6:0:abcdef',
            source_table='network_logs',
            evidence_role='supporting_record',
            extractor_name='zeek_dns_resolved_to_ip',
            extractor_version='1',
            support_state=GraphSupportState.INVALIDATED,
            source_ref_type=GraphSourceRefType.PCAP_FILE,
            source_ref_id=6,
            metadata_json={},
        )
        db.session.add(stale_support)
        db.session.commit()

        result = self.service.invalidate_support_by_extractor(
            extractor_name='zeek_dns_resolved_to_ip',
            reason='rerun repair',
        )
        db.session.refresh(stale_rel)
        db.session.refresh(stale_support)
        self.assertEqual(stale_support.support_state, GraphSupportState.INVALIDATED)
        self.assertEqual(stale_rel.validation_state, GraphValidationState.UNSUPPORTED)
        self.assertIn(2, result['revalidation'])

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
