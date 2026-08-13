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
from models.graph_saved_view import GraphSavedView  # noqa: F401
from models.known_system import KnownSystem, KnownSystemAlias
from utils.graph_extractors import GRAPH_EXTRACTOR_EVENT_COLUMNS
from utils.graph_identity import GraphEntityType, GraphRelationshipType
from utils.graph_materializer import materialize_events_for_case
from utils.graph_projection import classify_case_for_graph_backfill, ensure_projection_state, graph_eligible_probe


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
        self.stream_queries = []
        self.streamed_rows = []

    def _filtered_rows(self, parameters):
        parameters = parameters or {}
        rows = self.rows
        case_id = parameters.get("case_id")
        case_idx = GRAPH_EXTRACTOR_EVENT_COLUMNS.index("case_id")
        if case_id is not None:
            rows = [row for row in rows if row[case_idx] == case_id]
        case_file_ids = parameters.get("case_file_ids")
        if case_file_ids is not None:
            case_file_idx = GRAPH_EXTRACTOR_EVENT_COLUMNS.index("case_file_id")
            allowed = set(case_file_ids)
            rows = [row for row in rows if row[case_file_idx] in allowed]
        return rows

    def query_rows_stream(self, query, parameters=None, settings=None):
        self.last_query = query
        self.last_parameters = parameters or {}
        self.stream_queries.append(query)
        rows = self._filtered_rows(self.last_parameters)
        timestamp_idx = GRAPH_EXTRACTOR_EVENT_COLUMNS.index("timestamp_utc")
        window_start = self.last_parameters.get("window_start")
        window_end = self.last_parameters.get("window_end")
        if window_start and window_end:
            rows = [row for row in rows if window_start <= row[timestamp_idx] < window_end]
        self.streamed_rows.extend(rows)
        return _Stream(rows)

    def query(self, query, parameters=None):
        self.last_query = query
        self.last_parameters = parameters or {}
        if "minOrNull(timestamp_utc)" in query:
            timestamp_idx = GRAPH_EXTRACTOR_EVENT_COLUMNS.index("timestamp_utc")
            after = (parameters or {}).get("after_timestamp") or datetime(1970, 1, 1)
            timestamps = sorted(row[timestamp_idx] for row in self._filtered_rows(parameters) if row[timestamp_idx] >= after)
            return SimpleNamespace(result_rows=[(timestamps[0],)] if timestamps else [])
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

    def test_v1_failed_partial_replays_with_windowed_projection_without_duplicates(self):
        case = Case.get_by_id_unchecked(1)
        state = ensure_projection_state(case, mode="historical_backfill", status="pending")
        first = event_row(evidence_record_key=evidence_key("a"), timestamp_utc=datetime(2026, 1, 1, 12, 0, 0))
        second = event_row(evidence_record_key=evidence_key("b"), timestamp_utc=datetime(2026, 1, 1, 12, 0, 1), logon_id="0x124")
        materialize_events_for_case(1, client=StreamingClient([first]), projection_state=state, batch_size=1)

        state = GraphProjectionState.query.get(state.id)
        state.status = "failed"
        state.projection_version = "graph_events_v1"
        state.last_error = "stopped after checkpoint"
        state.completed_at = None
        db.session.commit()
        resume_client = StreamingClient([first, second])
        materialize_events_for_case(1, client=resume_client, projection_state=state, resume=True, batch_size=1)

        stream_sql = resume_client.stream_queries[-1]
        self.assertIn("PREWHERE case_id = {case_id:UInt32}", stream_sql)
        self.assertIn("timestamp_utc >= {window_start:DateTime64(3)}", stream_sql)
        self.assertIn("timestamp_utc < {window_end:DateTime64(3)}", stream_sql)
        self.assertNotIn("ORDER BY timestamp_utc, evidence_record_key", stream_sql)
        self.assertEqual(GraphRelationship.query.count(), 5)
        self.assertEqual(GraphRelationshipEvidence.query.count(), 6)
        state = GraphProjectionState.query.get(state.id)
        self.assertEqual(state.projection_version, "graph_events_v2_windowed")
        self.assertEqual(state.status, "completed")
        self.assertIsNone(state.last_error)
        self.assertEqual(state.events_seen, 3)
        self.assertGreaterEqual(state.windows_completed, 2)

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

    def test_failed_partial_graph_is_classified_as_resumable(self):
        case = Case.get_by_id_unchecked(1)
        db.session.add(GraphEntity(case_id=1, entity_type=GraphEntityType.HOST, entity_key="host:a", display_value="A", canonical_value="A"))
        db.session.add(GraphProjectionState(
            case_id=1,
            case_uuid=case.uuid,
            status="failed",
            mode="historical_backfill",
            projection_version="graph_events_v1",
            last_error="stopped",
        ))
        db.session.commit()

        row = classify_case_for_graph_backfill(case, client=StreamingClient([]), mutate=False)

        self.assertEqual(row["classification"], "resumable")
        self.assertEqual(row["planned_action"], "resume")

    def test_windowed_stream_and_probe_do_not_use_global_erk_sort(self):
        state = ensure_projection_state(Case.get_by_id_unchecked(1), mode="historical_backfill", status="pending")
        client = StreamingClient([event_row()])

        materialize_events_for_case(1, client=client, projection_state=state)
        stream_sql = client.stream_queries[-1]
        self.assertIn("PREWHERE case_id = {case_id:UInt32}", stream_sql)
        self.assertIn("timestamp_utc >= {window_start:DateTime64(3)}", stream_sql)
        self.assertIn("timestamp_utc < {window_end:DateTime64(3)}", stream_sql)
        self.assertNotIn("ORDER BY timestamp_utc, evidence_record_key", stream_sql)
        self.assertNotIn("ORDER BY", client.last_query)

        graph_eligible_probe(client, 1)
        self.assertIn("LIMIT 1", client.last_query)
        self.assertNotIn("ORDER BY", client.last_query)

    def test_incremental_case_file_scope_only_reads_new_source_and_preserves_existing_graph(self):
        for file_id, case_uuid, filename in (
            (10, "case-1", "old.evtx"),
            (11, "case-1", "new.evtx"),
            (20, "case-2", "other-case.evtx"),
        ):
            db.session.add(CaseFile(
                id=file_id,
                case_uuid=case_uuid,
                filename=filename,
                original_filename=filename,
                file_size=1,
                sha256_hash=str(file_id).zfill(64),
                status=FileStatus.DONE,
                uploaded_by="tester",
            ))
        db.session.commit()

        old = event_row(case_file_id=10, evidence_record_key=evidence_key("a"))
        other_case = event_row(
            case_id=2,
            case_file_id=20,
            evidence_record_key=evidence_key("b"),
            source_host="OTHER-DC01",
            username="Other",
            sid="S-1-5-21-2",
            logon_id="0x200",
        )
        materialize_events_for_case(1, client=StreamingClient([old, other_case]))

        old_entities = {
            entity.id: (
                entity.case_id,
                entity.entity_type,
                entity.entity_key,
                entity.display_value,
                entity.canonical_value,
                entity.first_seen_at,
                entity.last_seen_at,
                entity.metadata_json,
            )
            for entity in GraphEntity.query.filter_by(case_id=1).all()
        }
        old_relationships = {
            relationship.id: (
                relationship.case_id,
                relationship.source_entity_id,
                relationship.relationship_type,
                relationship.target_entity_id,
                relationship.first_seen_at,
                relationship.last_seen_at,
                relationship.derivation_type,
                relationship.extractor_name,
                relationship.extractor_version,
                relationship.validation_state,
                relationship.metadata_json,
            )
            for relationship in GraphRelationship.query.filter_by(case_id=1).all()
        }
        old_support_keys = {
            (
                evidence.relationship_id,
                evidence.evidence_record_key,
                evidence.evidence_role,
                evidence.extractor_name,
                evidence.extractor_version,
            )
            for evidence in GraphRelationshipEvidence.query.filter_by(case_id=1).all()
        }

        new = event_row(
            case_file_id=11,
            evidence_record_key=evidence_key("c"),
            timestamp_utc=datetime(2026, 1, 1, 12, 5, 0),
            source_host="NEW-DC01",
            username="NewUser",
            sid="S-1-5-21-3",
            logon_id="0x300",
        )
        old_unread = event_row(
            case_file_id=10,
            evidence_record_key=evidence_key("d"),
            timestamp_utc=datetime(2026, 1, 1, 12, 6, 0),
            logon_id="0x400",
        )
        client = StreamingClient([old_unread, new, other_case])

        result = materialize_events_for_case(1, case_file_ids=[11], client=client)

        self.assertEqual(result["events_seen"], 1)
        self.assertEqual(result["case_file_ids"], [11])
        self.assertIn("PREWHERE case_id = {case_id:UInt32}", client.stream_queries[-1])
        self.assertIn("case_file_id IN {case_file_ids:Array(UInt32)}", client.stream_queries[-1])
        self.assertEqual(client.last_parameters["case_id"], 1)
        self.assertEqual(client.last_parameters["case_file_ids"], [11])
        case_file_idx = GRAPH_EXTRACTOR_EVENT_COLUMNS.index("case_file_id")
        case_idx = GRAPH_EXTRACTOR_EVENT_COLUMNS.index("case_id")
        self.assertEqual({row[case_file_idx] for row in client.streamed_rows}, {11})
        self.assertEqual({row[case_idx] for row in client.streamed_rows}, {1})

        for entity_id, snapshot in old_entities.items():
            entity = GraphEntity.query.get(entity_id)
            self.assertEqual(
                (
                    entity.case_id,
                    entity.entity_type,
                    entity.entity_key,
                    entity.display_value,
                    entity.canonical_value,
                    entity.first_seen_at,
                    entity.last_seen_at,
                    entity.metadata_json,
                ),
                snapshot,
            )
        for relationship_id, snapshot in old_relationships.items():
            relationship = GraphRelationship.query.get(relationship_id)
            self.assertEqual(
                (
                    relationship.case_id,
                    relationship.source_entity_id,
                    relationship.relationship_type,
                    relationship.target_entity_id,
                    relationship.first_seen_at,
                    relationship.last_seen_at,
                    relationship.derivation_type,
                    relationship.extractor_name,
                    relationship.extractor_version,
                    relationship.validation_state,
                    relationship.metadata_json,
                ),
                snapshot,
            )

        self.assertGreater(GraphRelationship.query.filter_by(case_id=1).count(), len(old_relationships))
        self.assertGreater(GraphRelationshipEvidence.query.filter_by(case_id=1).count(), len(old_support_keys))
        self.assertEqual(GraphRelationship.query.filter_by(case_id=2).count(), 0)
        self.assertEqual(GraphRelationshipEvidence.query.filter_by(case_id=2).count(), 0)
        self.assertEqual(GraphRelationshipEvidence.query.filter_by(case_id=1, source_ref_id=11).count(), 3)
        self.assertEqual(GraphRelationshipEvidence.query.filter_by(case_id=1, source_ref_id=10).count(), 3)
        self.assertEqual(GraphRelationshipEvidence.query.filter_by(case_id=1, evidence_record_key=evidence_key("d")).count(), 0)

        support_keys = [
            (
                evidence.relationship_id,
                evidence.evidence_record_key,
                evidence.evidence_role,
                evidence.extractor_name,
                evidence.extractor_version,
            )
            for evidence in GraphRelationshipEvidence.query.filter_by(case_id=1).all()
        ]
        self.assertEqual(len(support_keys), len(set(support_keys)))

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
