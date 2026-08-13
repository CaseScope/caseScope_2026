import unittest
from datetime import datetime, timedelta
from types import SimpleNamespace

from flask import Flask

from models.case import Case
from models.case_file import CaseFile, FileStatus
from models.client import Client
from models.database import db
from models.graph import (
    GraphEntity,
    GraphEntityObservation,
    GraphProjectionState,
    GraphRelationship,
    GraphRelationshipEvidence,
)
from models.known_system import KnownSystem, KnownSystemAlias
from utils.graph_extractors import GRAPH_EXTRACTOR_EVENT_COLUMNS
from utils.graph_identity import GraphEntityType, GraphRelationshipType
from utils.graph_materializer import materialize_events_for_case
from utils.graph_projection import classify_case_for_graph_backfill, ensure_projection_state


def evidence_key(char):
    return "erk:v2:" + (char * 64)


def event_row(**overrides):
    data = {
        "case_id": 1,
        "artifact_type": "evtx",
        "timestamp_utc": datetime(2026, 1, 1, 12, 0, 0),
        "source_file": "Security.evtx",
        "source_path": "/evidence/Security.evtx",
        "source_host": "LSG-DC01",
        "case_file_id": 10,
        "event_id": "4624",
        "channel": "Security",
        "provider": "Microsoft-Windows-Security-Auditing",
        "username": "Scan",
        "domain": "LSG",
        "sid": "S-1-5-21-1",
        "logon_type": 10,
        "logon_id": "0x123",
        "process_name": "",
        "process_path": "",
        "process_id": None,
        "parent_process": "",
        "parent_pid": None,
        "command_line": "",
        "target_path": "",
        "file_hash_md5": "",
        "file_hash_sha1": "",
        "file_hash_sha256": "",
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "extra_fields": "{}",
        "parser_version": "test",
        "evidence_record_key": evidence_key("a"),
        "evidence_identity_version": "2",
        "evidence_identity_quality": "native",
    }
    data.update(overrides)
    return tuple(data.get(column) for column in GRAPH_EXTRACTOR_EVENT_COLUMNS)


class _Stream:
    def __init__(self, rows):
        self.rows = rows

    def __enter__(self):
        return iter(self.rows)

    def __exit__(self, exc_type, exc, tb):
        return False


class StreamingClient:
    def __init__(self, rows, probe_rows=None):
        self.rows = list(rows)
        self.probe_rows = list(probe_rows if probe_rows is not None else rows[:1])
        self.last_query = ""
        self.last_parameters = None

    def query_rows_stream(self, query, parameters=None, settings=None):
        self.last_query = query
        self.last_parameters = parameters or {}
        rows = self.rows
        last_timestamp = self.last_parameters.get("last_timestamp")
        last_key = self.last_parameters.get("last_evidence_record_key")
        if last_timestamp and last_key:
            timestamp_idx = GRAPH_EXTRACTOR_EVENT_COLUMNS.index("timestamp_utc")
            key_idx = GRAPH_EXTRACTOR_EVENT_COLUMNS.index("evidence_record_key")
            rows = [
                row for row in rows
                if row[timestamp_idx] > last_timestamp or (row[timestamp_idx] == last_timestamp and row[key_idx] > last_key)
            ]
        return _Stream(rows)

    def query(self, query, parameters=None):
        self.last_query = query
        self.last_parameters = parameters or {}
        return SimpleNamespace(result_rows=self.probe_rows)


class HistoricalGraphBackfillTestCase(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config.update(
            SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            TESTING=True,
            SECRET_KEY="test-secret",
        )
        db.init_app(self.app)
        self.ctx = self.app.app_context()
        self.ctx.push()
        for table in (
            Client.__table__,
            Case.__table__,
            CaseFile.__table__,
            KnownSystem.__table__,
            KnownSystemAlias.__table__,
            GraphEntity.__table__,
            GraphEntityObservation.__table__,
            GraphRelationship.__table__,
            GraphRelationshipEvidence.__table__,
            GraphProjectionState.__table__,
        ):
            table.create(db.engine)
        db.session.add(Case(id=1, uuid="case-1", name="LSG", company="Client", created_by="tester"))
        db.session.add(Case(id=2, uuid="case-2", name="Other", company="Client", created_by="tester"))
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def test_historical_4624_backfill_creates_host_user_and_logon_session(self):
        state = ensure_projection_state(Case.get_by_id_unchecked(1), mode="historical_backfill", status="pending")

        result = materialize_events_for_case(1, client=StreamingClient([event_row()]), projection_state=state)

        self.assertEqual(result["errors"], 0)
        self.assertEqual(GraphEntity.query.filter_by(entity_type=GraphEntityType.HOST).count(), 1)
        self.assertEqual(GraphEntity.query.filter_by(entity_type=GraphEntityType.USER).count(), 1)
        self.assertEqual(GraphEntity.query.filter_by(entity_type=GraphEntityType.LOGON_SESSION).count(), 1)
        self.assertEqual(GraphRelationship.query.filter_by(relationship_type=GraphRelationshipType.LOGGED_ON_TO).count(), 1)
        self.assertEqual(GraphProjectionState.query.get(state.id).status, "completed")

    def test_duplicate_physical_erk_does_not_multiply_logical_support(self):
        state = ensure_projection_state(Case.get_by_id_unchecked(1), mode="historical_backfill", status="pending")

        materialize_events_for_case(1, client=StreamingClient([event_row(), event_row()]), projection_state=state)

        self.assertEqual(GraphRelationship.query.count(), 3)
        self.assertEqual(GraphRelationshipEvidence.query.count(), 3)

    def test_resume_uses_keyset_checkpoint_without_duplicate_edges(self):
        case = Case.get_by_id_unchecked(1)
        state = ensure_projection_state(case, mode="historical_backfill", status="pending")
        first = event_row(evidence_record_key=evidence_key("a"), timestamp_utc=datetime(2026, 1, 1, 12, 0, 0))
        second = event_row(evidence_record_key=evidence_key("b"), timestamp_utc=datetime(2026, 1, 1, 12, 0, 1), logon_id="0x124")
        materialize_events_for_case(1, client=StreamingClient([first]), projection_state=state, batch_size=1)

        state = GraphProjectionState.query.get(state.id)
        state.status = "pending"
        state.completed_at = None
        db.session.commit()
        resume_client = StreamingClient([first, second])
        materialize_events_for_case(1, client=resume_client, projection_state=state, resume=True, batch_size=1)

        self.assertIn("evidence_record_key > {last_evidence_record_key:String}", resume_client.last_query)
        self.assertEqual(GraphRelationship.query.count(), 5)
        self.assertEqual(GraphRelationshipEvidence.query.count(), 6)
        self.assertEqual(GraphProjectionState.query.get(state.id).status, "completed")

    def test_no_eligible_evidence_marks_state_without_graph_rows(self):
        state = ensure_projection_state(Case.get_by_id_unchecked(1), mode="historical_backfill", status="pending")

        result = materialize_events_for_case(1, client=StreamingClient([]), projection_state=state)

        self.assertEqual(result["events_seen"], 0)
        self.assertEqual(GraphEntity.query.count(), 0)
        self.assertEqual(GraphProjectionState.query.get(state.id).status, "no_eligible_evidence")

    def test_malformed_erk_fails_state_and_creates_no_support(self):
        state = ensure_projection_state(Case.get_by_id_unchecked(1), mode="historical_backfill", status="pending")

        result = materialize_events_for_case(1, client=StreamingClient([event_row(evidence_record_key="bad-key")]), projection_state=state)

        self.assertEqual(result["errors"], 1)
        self.assertEqual(GraphRelationshipEvidence.query.count(), 0)
        self.assertEqual(GraphProjectionState.query.get(state.id).status, "failed")

    def test_existing_graph_is_classified_without_rebuild(self):
        db.session.add(GraphEntity(case_id=1, entity_type=GraphEntityType.HOST, entity_key="host:a", display_value="A", canonical_value="A"))
        db.session.commit()

        row = classify_case_for_graph_backfill(Case.get_by_id_unchecked(1), client=StreamingClient([]), mutate=False)

        self.assertEqual(row["classification"], "existing_graph")
        self.assertEqual(row["planned_action"], "skip_existing_graph")
        self.assertEqual(GraphEntity.query.count(), 1)

    def test_active_ingest_is_deferred_before_clickhouse_probe(self):
        db.session.add(CaseFile(
            case_uuid="case-1",
            filename="Security.evtx",
            original_filename="Security.evtx",
            file_size=1,
            sha256_hash="a" * 64,
            status=FileStatus.INGESTING,
            uploaded_by="tester",
        ))
        db.session.commit()
        client = StreamingClient([event_row()])

        row = classify_case_for_graph_backfill(Case.get_by_id_unchecked(1), client=client, mutate=False)

        self.assertEqual(row["classification"], "active_ingest")
        self.assertEqual(client.last_query, "")


if __name__ == "__main__":
    unittest.main()
