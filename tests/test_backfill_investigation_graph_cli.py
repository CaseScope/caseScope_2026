import unittest
from types import SimpleNamespace
from unittest.mock import patch

from flask import Flask

from migrations import backfill_investigation_graph as backfill
from models.case import Case
from models.case_file import CaseFile
from models.client import Client
from models.database import db
from models.graph import GraphEntity, GraphEntityObservation, GraphRelationship, GraphRelationshipEvidence, GraphProjectionState
from utils.graph_identity import GraphEntityType
from utils.graph_materializer import DEFAULT_GRAPH_WINDOW_SECONDS


class BackfillInvestigationGraphCliTestCase(unittest.TestCase):
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
            GraphEntity.__table__,
            GraphEntityObservation.__table__,
            GraphRelationship.__table__,
            GraphRelationshipEvidence.__table__,
            GraphProjectionState.__table__,
        ):
            table.create(db.engine)
        self.case = Case(id=1, uuid="case-1", name="LSG", company="Client", created_by="tester")
        db.session.add(self.case)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def _args(self, *, resume=True):
        return SimpleNamespace(
            resume=resume,
            batch_size=5000,
            bulk_events=10000,
            progress_interval=50000,
            window_seconds=DEFAULT_GRAPH_WINDOW_SECONDS,
        )

    def test_resume_failed_partial_graph_does_not_skip_existing_rows(self):
        state = GraphProjectionState(
            case_id=self.case.id,
            case_uuid=self.case.uuid,
            status="failed",
            mode="historical_backfill",
            projection_version="graph_events_v1",
            last_error="stopped",
        )
        db.session.add(state)
        db.session.add(GraphEntity(
            case_id=self.case.id,
            entity_type=GraphEntityType.HOST,
            entity_key="host:lsg-dc01",
            display_value="LSG-DC01",
            canonical_value="LSG-DC01",
        ))
        db.session.commit()
        row = {
            "state": state,
            "qualifying_evidence": True,
        }

        with patch.object(backfill, "_audit"), patch.object(backfill, "materialize_events_for_case", return_value={
            "events_seen": 2,
            "relationships_materialized": 3,
            "errors": 0,
        }) as materialize:
            result = backfill._process_case(self.case, row, client=object(), args=self._args())

        self.assertTrue(result["success"])
        self.assertFalse(result.get("skipped", False))
        self.assertEqual(materialize.call_count, 1)
        self.assertTrue(materialize.call_args.kwargs["resume"])
        self.assertEqual(materialize.call_args.kwargs["window_seconds"], DEFAULT_GRAPH_WINDOW_SECONDS)
        self.assertEqual(materialize.call_args.kwargs["bulk_events"], 10000)

    def test_running_partial_graph_is_deferred(self):
        state = GraphProjectionState(
            case_id=self.case.id,
            case_uuid=self.case.uuid,
            status="running",
            mode="historical_backfill",
            projection_version="graph_events_v2_windowed",
        )
        db.session.add(state)
        db.session.add(GraphEntity(
            case_id=self.case.id,
            entity_type=GraphEntityType.HOST,
            entity_key="host:lsg-dc01",
            display_value="LSG-DC01",
            canonical_value="LSG-DC01",
        ))
        db.session.commit()

        result = backfill._process_case(self.case, {"state": state}, client=object(), args=self._args())

        self.assertTrue(result["deferred"])
        self.assertIn("already running", result["error"])


if __name__ == "__main__":
    unittest.main()
