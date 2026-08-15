import os
import random
import unittest
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import patch

from flask import Flask
from sqlalchemy import func

from models.case import Case
from models.client import Client
from models.database import db
from models.graph import (
    GraphEntity,
    GraphEntityObservation,
    GraphProjectionState,
    GraphRelationship,
    GraphRelationshipEvidence,
)
from models.graph_saved_view import GraphSavedView  # noqa: F401
from models.known_system import KnownSystem, KnownSystemAlias
from utils import graph_materializer as graph_materializer_module
from utils.graph_bulk_writer import GraphBulkWriter
from utils.graph_extractors import GRAPH_EXTRACTOR_EVENT_COLUMNS, extract_event_relationships
from utils.graph_identity import GraphSupportState, GraphValidationState
from utils.graph_materializer import materialize_events_for_case


def evidence_key(char):
    return "erk:v2:" + (char * 64)


def process_event(case_id, *, key=None, timestamp=None, pid=4242):
    return {
        "case_id": case_id,
        "artifact_type": "evtx",
        "timestamp_utc": timestamp or datetime(2026, 1, 1, 12, 0, 0),
        "source_host": "PG-WKS-1",
        "case_file_id": 990001,
        "source_file": "Security.evtx",
        "source_path": "/evidence/Security.evtx",
        "event_id": "4688",
        "channel": "Security",
        "provider": "Microsoft-Windows-Security-Auditing",
        "process_name": "cmd.exe",
        "process_path": r"C:\Windows\System32\cmd.exe",
        "process_id": pid,
        "parent_process": "",
        "parent_pid": None,
        "command_line": "",
        "target_path": "",
        "file_hash_md5": "",
        "file_hash_sha1": "",
        "file_hash_sha256": "",
        "extra_fields": "{}",
        "parser_version": "postgres-test",
        "evidence_record_key": key or evidence_key("a"),
        "evidence_identity_version": "2",
        "evidence_identity_quality": "native",
    }


def row_for_event(event):
    return tuple(event.get(column) for column in GRAPH_EXTRACTOR_EVENT_COLUMNS)


class _Stream:
    def __init__(self, rows):
        self.rows = rows

    def __enter__(self):
        return iter(self.rows)

    def __exit__(self, exc_type, exc, tb):
        return False


class StreamingClient:
    def __init__(self, rows):
        self.rows = list(rows)

    def query_rows_stream(self, query, parameters=None, settings=None):
        parameters = parameters or {}
        timestamp_idx = GRAPH_EXTRACTOR_EVENT_COLUMNS.index("timestamp_utc")
        window_start = parameters.get("window_start")
        window_end = parameters.get("window_end")
        rows = self.rows
        if window_start and window_end:
            rows = [row for row in rows if window_start <= row[timestamp_idx] < window_end]
        return _Stream(rows)

    def query(self, query, parameters=None):
        parameters = parameters or {}
        if "minOrNull(timestamp_utc)" in query:
            timestamp_idx = GRAPH_EXTRACTOR_EVENT_COLUMNS.index("timestamp_utc")
            after = parameters.get("after_timestamp") or datetime(1970, 1, 1)
            timestamps = sorted(row[timestamp_idx] for row in self.rows if row[timestamp_idx] >= after)
            return SimpleNamespace(result_rows=[(timestamps[0],)] if timestamps else [])
        return SimpleNamespace(result_rows=[])


class GraphBulkWriterPostgresRegressionTestCase(unittest.TestCase):
    """Regression coverage for PostgreSQL-only COPY/set-based graph replay paths."""

    @classmethod
    def setUpClass(cls):
        uri = os.environ.get("CASESCOPE_POSTGRES_TEST_DATABASE_URL") or os.environ.get("DATABASE_URL")
        if not uri or not uri.startswith(("postgresql://", "postgresql+")):
            raise unittest.SkipTest("PostgreSQL test database URL is not configured")
        cls.app = Flask(__name__)
        cls.app.config.update(
            SQLALCHEMY_DATABASE_URI=uri,
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            TESTING=True,
            SECRET_KEY="postgres-graph-test",
        )
        db.init_app(cls.app)
        cls.ctx = cls.app.app_context()
        cls.ctx.push()
        for table in (
            Client.__table__,
            Case.__table__,
            KnownSystem.__table__,
            KnownSystemAlias.__table__,
            GraphEntity.__table__,
            GraphEntityObservation.__table__,
            GraphRelationship.__table__,
            GraphRelationshipEvidence.__table__,
            GraphProjectionState.__table__,
        ):
            table.create(db.engine, checkfirst=True)
        if db.engine.dialect.name != "postgresql":
            raise unittest.SkipTest("GraphBulkWriter COPY regressions require PostgreSQL")

    @classmethod
    def tearDownClass(cls):
        db.session.remove()
        cls.ctx.pop()

    def setUp(self):
        self.case_id = random.randint(900_000_000, 999_999_999)
        self.case_uuid = f"pg-graph-{self.case_id}"
        self._cleanup_case()
        db.session.add(
            Case(
                id=self.case_id,
                uuid=self.case_uuid,
                name="PostgreSQL Graph Bulk Writer Regression",
                company="Regression",
                created_by="tester",
            )
        )
        db.session.add(KnownSystem(case_id=self.case_id, hostname="PG-WKS-1"))
        db.session.commit()

    def tearDown(self):
        self._cleanup_case()
        db.session.remove()

    def _cleanup_case(self):
        GraphRelationshipEvidence.query.filter_by(case_id=self.case_id).delete(synchronize_session=False)
        GraphRelationship.query.filter_by(case_id=self.case_id).delete(synchronize_session=False)
        GraphEntityObservation.query.filter_by(case_id=self.case_id).delete(synchronize_session=False)
        GraphEntity.query.filter_by(case_id=self.case_id).delete(synchronize_session=False)
        GraphProjectionState.query.filter_by(case_id=self.case_id).delete(synchronize_session=False)
        KnownSystem.query.filter_by(case_id=self.case_id).delete(synchronize_session=False)
        Case.query.filter_by(id=self.case_id).delete(synchronize_session=False)
        db.session.commit()

    def _duplicate_counts(self):
        entity_dupes = (
            db.session.query(
                GraphEntity.case_id,
                GraphEntity.entity_type,
                GraphEntity.entity_key,
                func.count(GraphEntity.id).label("count"),
            )
            .filter(GraphEntity.case_id == self.case_id)
            .group_by(GraphEntity.case_id, GraphEntity.entity_type, GraphEntity.entity_key)
            .having(func.count(GraphEntity.id) > 1)
            .count()
        )
        observation_dupes = (
            db.session.query(
                GraphEntityObservation.entity_id,
                GraphEntityObservation.evidence_record_key,
                GraphEntityObservation.observation_role,
                GraphEntityObservation.source_table,
                func.count(GraphEntityObservation.id).label("count"),
            )
            .filter(GraphEntityObservation.case_id == self.case_id)
            .group_by(
                GraphEntityObservation.entity_id,
                GraphEntityObservation.evidence_record_key,
                GraphEntityObservation.observation_role,
                GraphEntityObservation.source_table,
            )
            .having(func.count(GraphEntityObservation.id) > 1)
            .count()
        )
        relationship_dupes = (
            db.session.query(
                GraphRelationship.case_id,
                GraphRelationship.source_entity_id,
                GraphRelationship.relationship_type,
                GraphRelationship.target_entity_id,
                GraphRelationship.derivation_type,
                func.count(GraphRelationship.id).label("count"),
            )
            .filter(GraphRelationship.case_id == self.case_id)
            .group_by(
                GraphRelationship.case_id,
                GraphRelationship.source_entity_id,
                GraphRelationship.relationship_type,
                GraphRelationship.target_entity_id,
                GraphRelationship.derivation_type,
            )
            .having(func.count(GraphRelationship.id) > 1)
            .count()
        )
        support_dupes = (
            db.session.query(
                GraphRelationshipEvidence.relationship_id,
                GraphRelationshipEvidence.evidence_record_key,
                GraphRelationshipEvidence.evidence_role,
                GraphRelationshipEvidence.extractor_name,
                GraphRelationshipEvidence.extractor_version,
                func.count(GraphRelationshipEvidence.id).label("count"),
            )
            .filter(GraphRelationshipEvidence.case_id == self.case_id)
            .group_by(
                GraphRelationshipEvidence.relationship_id,
                GraphRelationshipEvidence.evidence_record_key,
                GraphRelationshipEvidence.evidence_role,
                GraphRelationshipEvidence.extractor_name,
                GraphRelationshipEvidence.extractor_version,
            )
            .having(func.count(GraphRelationshipEvidence.id) > 1)
            .count()
        )
        return {
            "entities": entity_dupes,
            "observations": observation_dupes,
            "relationships": relationship_dupes,
            "support": support_dupes,
        }

    def test_bulk_commit_checkpoint_failure_replays_without_duplicates(self):
        state = GraphProjectionState(
            case_id=self.case_id,
            case_uuid=self.case_uuid,
            status="pending",
            mode="historical_backfill",
            projection_version="graph_events_v2_windowed",
        )
        db.session.add(state)
        db.session.commit()
        rows = [
            row_for_event(process_event(self.case_id, key=evidence_key("a"), pid=4242)),
            row_for_event(
                process_event(
                    self.case_id,
                    key=evidence_key("b"),
                    pid=4243,
                    timestamp=datetime(2026, 1, 1, 12, 0, 1),
                )
            ),
        ]
        original_checkpoint = graph_materializer_module._checkpoint_projection_state
        calls = {"count": 0}

        def fail_first_checkpoint(*args, **kwargs):
            calls["count"] += 1
            if calls["count"] == 1:
                raise RuntimeError("deterministic checkpoint failure after bulk commit")
            return original_checkpoint(*args, **kwargs)

        with patch.object(
            graph_materializer_module,
            "_checkpoint_projection_state",
            side_effect=fail_first_checkpoint,
        ):
            with self.assertRaisesRegex(RuntimeError, "checkpoint failure"):
                materialize_events_for_case(
                    self.case_id,
                    client=StreamingClient(rows),
                    projection_state=state,
                    bulk_events=1,
                )

        db.session.rollback()
        self.assertEqual(GraphRelationshipEvidence.query.filter_by(case_id=self.case_id).count(), 1)
        state = GraphProjectionState.query.filter_by(case_id=self.case_id).one()
        self.assertNotEqual(state.status, "completed")
        state.status = "failed"
        state.last_error = "interrupted after bulk commit before checkpoint"
        db.session.commit()

        result = materialize_events_for_case(
            self.case_id,
            client=StreamingClient(rows),
            projection_state=state,
            resume=True,
            bulk_events=1,
        )

        db.session.expire_all()
        self.assertEqual(result["errors"], 0)
        self.assertEqual(GraphProjectionState.query.filter_by(case_id=self.case_id).one().status, "completed")
        self.assertEqual(GraphRelationshipEvidence.query.filter_by(case_id=self.case_id).count(), 2)
        self.assertEqual(self._duplicate_counts(), {"entities": 0, "observations": 0, "relationships": 0, "support": 0})
        self.assertEqual(
            GraphRelationshipEvidence.query.filter_by(case_id=self.case_id, evidence_record_key=evidence_key("a")).count(),
            1,
        )
        self.assertEqual(
            GraphRelationshipEvidence.query.filter_by(case_id=self.case_id, evidence_record_key=evidence_key("b")).count(),
            1,
        )

    def test_invalidated_support_bulk_replay_rematerializes_exact_support(self):
        event = process_event(self.case_id, key=evidence_key("c"))
        candidates = extract_event_relationships(event)

        first_stats = GraphBulkWriter().materialize_candidates(self.case_id, candidates, events_read=1)

        self.assertEqual(first_stats.events_read, 1)
        self.assertEqual(GraphRelationship.query.filter_by(case_id=self.case_id).count(), 1)
        self.assertEqual(GraphRelationshipEvidence.query.filter_by(case_id=self.case_id).count(), 1)
        relationship = GraphRelationship.query.filter_by(case_id=self.case_id).one()
        support = GraphRelationshipEvidence.query.filter_by(case_id=self.case_id).one()
        original_identity = (
            support.evidence_record_key,
            support.evidence_role,
            support.extractor_name,
            support.extractor_version,
        )
        support.support_state = GraphSupportState.INVALIDATED
        support.support_state_reason = "regression setup"
        relationship.validation_state = GraphValidationState.UNSUPPORTED
        db.session.commit()

        second_stats = GraphBulkWriter().materialize_candidates(self.case_id, candidates, events_read=1)

        db.session.expire_all()
        relationship = GraphRelationship.query.filter_by(case_id=self.case_id).one()
        support = GraphRelationshipEvidence.query.filter_by(case_id=self.case_id).one()
        self.assertEqual(second_stats.events_read, 1)
        self.assertEqual(relationship.validation_state, GraphValidationState.ACTIVE)
        self.assertEqual(support.support_state, GraphSupportState.ACTIVE)
        self.assertEqual(support.support_state_reason, "rematerialized")
        self.assertEqual(
            (
                support.evidence_record_key,
                support.evidence_role,
                support.extractor_name,
                support.extractor_version,
            ),
            original_identity,
        )
        self.assertEqual(GraphRelationship.query.filter_by(case_id=self.case_id).count(), 1)
        self.assertEqual(GraphRelationshipEvidence.query.filter_by(case_id=self.case_id).count(), 1)
        self.assertEqual(self._duplicate_counts(), {"entities": 0, "observations": 0, "relationships": 0, "support": 0})


if __name__ == "__main__":
    unittest.main()
