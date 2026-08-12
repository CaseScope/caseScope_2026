import unittest

from flask import Flask
from sqlalchemy import inspect

from models.case import Case
from models.client import Client
from models.database import db
from models.graph_saved_view import GraphSavedView
from models.investigation_thread import (
    InvestigationThread,
    InvestigationThreadEntity,
    InvestigationThreadEvidence,
    InvestigationThreadFinding,
    InvestigationThreadIOC,
    InvestigationThreadNote,
    InvestigationThreadRelationship,
)


class InvestigationThreadMigrationTestCase(unittest.TestCase):
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
        Client.__table__.create(db.engine)
        Case.__table__.create(db.engine)

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def test_all_phase_0d_tables_can_be_created(self):
        tables = [
            GraphSavedView.__table__,
            InvestigationThread.__table__,
            InvestigationThreadEntity.__table__,
            InvestigationThreadRelationship.__table__,
            InvestigationThreadEvidence.__table__,
            InvestigationThreadIOC.__table__,
            InvestigationThreadFinding.__table__,
            InvestigationThreadNote.__table__,
        ]

        for table in tables:
            table.create(db.engine)

        table_names = set(inspect(db.engine).get_table_names())
        self.assertTrue({table.name for table in tables}.issubset(table_names))

    def test_cached_graph_ids_are_not_foreign_keys_to_transient_graph_tables(self):
        GraphSavedView.__table__.create(db.engine)
        InvestigationThread.__table__.create(db.engine)
        InvestigationThreadEntity.__table__.create(db.engine)
        InvestigationThreadRelationship.__table__.create(db.engine)

        inspector = inspect(db.engine)
        entity_columns = {column["name"] for column in inspector.get_columns("investigation_thread_entities")}
        relationship_columns = {column["name"] for column in inspector.get_columns("investigation_thread_relationships")}
        entity_fks = inspector.get_foreign_keys("investigation_thread_entities")
        relationship_fks = inspector.get_foreign_keys("investigation_thread_relationships")

        self.assertIn("current_graph_entity_id", entity_columns)
        self.assertIn("current_graph_relationship_id", relationship_columns)
        self.assertFalse(
            any(
                fk.get("referred_table") == "graph_entities"
                and "current_graph_entity_id" in (fk.get("constrained_columns") or [])
                for fk in entity_fks
            )
        )
        self.assertFalse(
            any(
                fk.get("referred_table") == "graph_relationships"
                and "current_graph_relationship_id" in (fk.get("constrained_columns") or [])
                for fk in relationship_fks
            )
        )


if __name__ == "__main__":
    unittest.main()
