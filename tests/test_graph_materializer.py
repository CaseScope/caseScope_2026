import unittest
from datetime import datetime

from flask import Flask

from models.case import Case
from models.client import Client
from models.agent import Agent
from models.database import db
from models.graph import GraphEntity, GraphEntityObservation, GraphRelationship, GraphRelationshipEvidence
from models.known_system import KnownSystem, KnownSystemAlias
from utils.graph_extractors import extract_event_relationships
from utils.graph_materializer import GraphMaterializer, clear_case_graph
from utils.graph_identity import GraphRelationshipType


def evidence_key(char):
    return 'erk:v2:' + (char * 64)


def process_event(case_id=1, key=None, timestamp=None):
    return {
        'case_id': case_id,
        'artifact_type': 'evtx',
        'timestamp_utc': timestamp or datetime(2026, 1, 1, 12, 0, 0),
        'source_host': 'WKS-1',
        'case_file_id': 99,
        'source_file': 'Security.evtx',
        'source_path': '/evidence/Security.evtx',
        'event_id': '4688',
        'channel': 'Security',
        'provider': 'Microsoft-Windows-Security-Auditing',
        'process_name': 'cmd.exe',
        'process_path': r'C:\Windows\System32\cmd.exe',
        'process_id': 4242,
        'extra_fields': '{}',
        'evidence_record_key': key or evidence_key('a'),
    }


class GraphMaterializerTestCase(unittest.TestCase):
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
            Client.__table__,
            Case.__table__,
            KnownSystem.__table__,
            KnownSystemAlias.__table__,
            GraphEntity.__table__,
            GraphRelationship.__table__,
            GraphEntityObservation.__table__,
            GraphRelationshipEvidence.__table__,
        ):
            table.create(db.engine)
        db.session.add(Case(id=1, uuid='case-1', name='Case 1', company='Client', created_by='tester'))
        db.session.add(Case(id=2, uuid='case-2', name='Case 2', company='Client', created_by='tester'))
        db.session.add(KnownSystem(case_id=1, hostname='WKS-1'))
        db.session.add(KnownSystem(case_id=2, hostname='WKS-1'))
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def _materialize(self, event):
        candidates = extract_event_relationships(event)
        GraphMaterializer().materialize_candidates(event['case_id'], candidates)
        db.session.commit()
        return candidates

    def test_relationship_and_provenance_created(self):
        self._materialize(process_event())

        relationship = GraphRelationship.query.one()
        evidence = GraphRelationshipEvidence.query.one()

        self.assertEqual(relationship.relationship_type, GraphRelationshipType.RUNS_IMAGE)
        self.assertEqual(evidence.evidence_record_key, evidence_key('a'))
        self.assertEqual(evidence.extractor_name, 'events_process_runs_image')

    def test_same_evidence_reprocessed_does_not_duplicate(self):
        ev = process_event()
        self._materialize(ev)
        self._materialize(ev)

        self.assertEqual(GraphRelationship.query.count(), 1)
        self.assertEqual(GraphRelationshipEvidence.query.count(), 1)

    def test_different_evidence_supporting_same_edge_adds_provenance_only(self):
        self._materialize(process_event(key=evidence_key('a')))
        self._materialize(process_event(key=evidence_key('b')))

        self.assertEqual(GraphRelationship.query.count(), 1)
        self.assertEqual(GraphRelationshipEvidence.query.count(), 2)

    def test_cross_case_evidence_cannot_attach_to_other_case_relationship(self):
        self._materialize(process_event(case_id=1, key=evidence_key('a')))
        self._materialize(process_event(case_id=2, key=evidence_key('a')))

        self.assertEqual(GraphRelationship.query.count(), 2)
        self.assertEqual(GraphRelationshipEvidence.query.filter_by(case_id=1).count(), 1)
        self.assertEqual(GraphRelationshipEvidence.query.filter_by(case_id=2).count(), 1)

    def test_rebuild_by_clear_and_replay_is_deterministic(self):
        ev = process_event(key=evidence_key('a'))
        self._materialize(ev)
        before_edges = [
            (
                relationship.relationship_type,
                relationship.source_entity.entity_key,
                relationship.target_entity.entity_key,
            )
            for relationship in GraphRelationship.query.filter_by(case_id=1).all()
        ]

        clear_case_graph(1)
        db.session.commit()
        self.assertEqual(GraphRelationship.query.filter_by(case_id=1).count(), 0)
        self.assertEqual(GraphEntity.query.filter_by(case_id=1).count(), 0)

        self._materialize(ev)
        after_edges = [
            (
                relationship.relationship_type,
                relationship.source_entity.entity_key,
                relationship.target_entity.entity_key,
            )
            for relationship in GraphRelationship.query.filter_by(case_id=1).all()
        ]

        self.assertEqual(before_edges, after_edges)


if __name__ == '__main__':
    unittest.main()
