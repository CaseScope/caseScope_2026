import unittest
from dataclasses import replace
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import patch

from flask import Flask
from sqlalchemy.exc import OperationalError

from models.case import Case
from models.client import Client
from models.agent import Agent
from models.database import db
from models.graph import GraphEntity, GraphEntityObservation, GraphRelationship, GraphRelationshipEvidence
from models.known_system import KnownSystem, KnownSystemAlias
from utils.graph_extractors import GRAPH_EXTRACTOR_EVENT_COLUMNS, extract_event_relationships
from utils.graph_materializer import GraphMaterializer, clear_case_graph, materialize_events_for_case, rebuild_case_graph
from utils.graph_identity import GraphRelationshipType


def evidence_key(char):
    return 'erk:v2:' + (char * 64)


def process_event(case_id=1, key=None, timestamp=None, **overrides):
    data = {
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
    data.update(overrides)
    return data


class _Stream:
    def __init__(self, rows):
        self.rows = rows
        self.source = SimpleNamespace(column_names=GRAPH_EXTRACTOR_EVENT_COLUMNS)

    def __enter__(self):
        return iter(self.rows)

    def __exit__(self, exc_type, exc, tb):
        return False


class StreamingClient:
    def __init__(self, rows):
        self.rows = rows
        self.stream_called = False
        self.query_called = False
        self.last_query = ''
        self.last_parameters = {}
        self.stream_queries = []

    def query_rows_stream(self, query, parameters=None, settings=None):
        self.stream_called = True
        self.last_query = query
        self.stream_queries.append(query)
        self.last_parameters = parameters or {}
        timestamp_idx = GRAPH_EXTRACTOR_EVENT_COLUMNS.index('timestamp_utc')
        window_start = self.last_parameters.get('window_start')
        window_end = self.last_parameters.get('window_end')
        rows = self.rows
        if window_start and window_end:
            rows = [row for row in rows if window_start <= row[timestamp_idx] < window_end]
        return _Stream(rows)

    def query(self, query, parameters=None):
        self.query_called = True
        self.last_query = query
        self.last_parameters = parameters or {}
        if 'minOrNull(timestamp_utc)' in query:
            timestamp_idx = GRAPH_EXTRACTOR_EVENT_COLUMNS.index('timestamp_utc')
            after = self.last_parameters.get('after_timestamp') or datetime(1970, 1, 1)
            timestamps = sorted(row[timestamp_idx] for row in self.rows if row[timestamp_idx] >= after)
            return SimpleNamespace(result_rows=[(timestamps[0],)] if timestamps else [])
        return SimpleNamespace(result_rows=[])


def row_for_event(event):
    return tuple(event.get(column) for column in GRAPH_EXTRACTOR_EVENT_COLUMNS)


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

    def test_candidate_case_mismatch_is_rejected(self):
        candidate = extract_event_relationships(process_event(case_id=1))[0]

        with self.assertRaises(ValueError):
            GraphMaterializer().materialize_candidate(2, candidate)

    def test_invalid_evidence_record_key_is_rejected(self):
        candidate = extract_event_relationships(process_event(key='erk:v2:not-valid'))[0]

        with self.assertRaises(ValueError):
            GraphMaterializer().materialize_candidate(1, candidate)

    def test_same_canonical_edge_from_new_extractor_version_reuses_edge(self):
        candidate = extract_event_relationships(process_event(key=evidence_key('a')))[0]
        GraphMaterializer().materialize_candidate(1, candidate)
        GraphMaterializer().materialize_candidate(
            1,
            replace(candidate, evidence_record_key=evidence_key('b'), extractor_version='2'),
        )
        db.session.commit()

        self.assertEqual(GraphRelationship.query.count(), 1)
        self.assertEqual(GraphRelationshipEvidence.query.count(), 2)

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

    def test_materialize_events_for_case_uses_streaming_query(self):
        ev = process_event()
        row = row_for_event(ev)
        client = StreamingClient([row])

        result = materialize_events_for_case(1, client=client)

        self.assertTrue(client.stream_called)
        self.assertTrue(client.query_called)
        self.assertIn("event_id = '4624'", client.stream_queries[-1])
        self.assertIn('PREWHERE case_id = {case_id:UInt32}', client.stream_queries[-1])
        self.assertIn('timestamp_utc >= {window_start:DateTime64(3)}', client.stream_queries[-1])
        self.assertIn('timestamp_utc < {window_end:DateTime64(3)}', client.stream_queries[-1])
        self.assertNotIn('ORDER BY timestamp_utc, evidence_record_key', client.stream_queries[-1])
        self.assertNotIn('raw_json', client.stream_queries[-1])
        self.assertEqual(result['relationships_materialized'], 1)

    def test_bad_streamed_event_rolls_back_only_that_event(self):
        valid_a = process_event(key=evidence_key('a'), process_id=4242)
        invalid_b = process_event(
            key=evidence_key('b'),
            event_id='11',
            channel='Microsoft-Windows-Sysmon/Operational',
            process_path='',
            process_id=None,
            target_path=r'C:\Temp\bad.exe',
            file_hash_sha256='not-a-sha256',
        )
        valid_c = process_event(key=evidence_key('c'), process_id=4243)
        client = StreamingClient([row_for_event(valid_a), row_for_event(invalid_b), row_for_event(valid_c)])

        result = materialize_events_for_case(1, client=client, batch_size=5000)

        self.assertEqual(result['events_seen'], 3)
        self.assertEqual(result['errors'], 1)
        self.assertEqual(result['relationships_materialized'], 2)
        self.assertEqual(GraphRelationship.query.count(), 2)
        self.assertEqual(GraphRelationshipEvidence.query.count(), 2)

    def test_rebuild_with_bad_replay_row_does_not_restore_or_mix_stale_graph(self):
        stale = process_event(key=evidence_key('d'), process_id=1111)
        self._materialize(stale)
        self.assertEqual(GraphRelationship.query.count(), 1)

        invalid = process_event(
            key=evidence_key('e'),
            event_id='11',
            channel='Microsoft-Windows-Sysmon/Operational',
            process_path='',
            process_id=None,
            target_path=r'C:\Temp\bad.exe',
            file_hash_sha256='not-a-sha256',
        )
        valid = process_event(key=evidence_key('f'), process_id=2222)
        client = StreamingClient([row_for_event(invalid), row_for_event(valid)])

        result = rebuild_case_graph(1, client=client)
        source_keys = [relationship.source_entity.entity_key for relationship in GraphRelationship.query.all()]

        self.assertEqual(result['materialized']['errors'], 1)
        self.assertEqual(GraphRelationship.query.count(), 1)
        self.assertFalse(any('pid:1111' in key for key in source_keys))
        self.assertTrue(any('pid:2222' in key for key in source_keys))

    def test_h001_legitimate_known_system_miss_allows_observed_host_fallback(self):
        event = process_event(key=evidence_key('a'), source_host='WKS-UNKNOWN')

        self._materialize(event)

        relationship = GraphRelationship.query.one()
        source = GraphEntity.query.get(relationship.source_entity_id)
        target = GraphEntity.query.get(relationship.target_entity_id)
        self.assertIn('observed_host:', source.entity_key)
        self.assertIn('observed_host:', target.entity_key)
        self.assertEqual(GraphRelationshipEvidence.query.filter_by(evidence_record_key=evidence_key('a')).count(), 1)

    def test_h001_known_system_infrastructure_error_fails_closed_per_event(self):
        broken = process_event(key=evidence_key('b'), source_host='WKS-BROKEN', process_id=5000)
        valid = process_event(key=evidence_key('c'), source_host='WKS-1', process_id=5001)
        client = StreamingClient([row_for_event(broken), row_for_event(valid)])
        original_lookup = GraphMaterializer._lookup_known_system_id

        def lookup_side_effect(materializer, case_id, hostname):
            if hostname == 'WKS-BROKEN':
                raise OperationalError('stmt', {}, Exception('db down'))
            return original_lookup(materializer, case_id, hostname)

        with patch.object(GraphMaterializer, '_lookup_known_system_id', autospec=True, side_effect=lookup_side_effect):
            result = materialize_events_for_case(1, client=client, batch_size=5000)

        self.assertEqual(result['events_seen'], 2)
        self.assertEqual(result['errors'], 1)
        self.assertEqual(result['relationships_materialized'], 1)
        self.assertEqual(GraphRelationship.query.count(), 1)
        self.assertEqual(GraphRelationshipEvidence.query.filter_by(evidence_record_key=evidence_key('b')).count(), 0)
        self.assertEqual(GraphRelationshipEvidence.query.filter_by(evidence_record_key=evidence_key('c')).count(), 1)
        self.assertFalse(any('WKS-BROKEN' in (entity.canonical_value or '') for entity in GraphEntity.query.all()))


if __name__ == '__main__':
    unittest.main()
