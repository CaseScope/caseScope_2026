from __future__ import annotations

import unittest
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import patch

from flask import Flask
from flask_login import LoginManager, login_user

from config import PermissionLevel
from models.case import Case
from models.client import Client
from models.database import db
from models.graph import GraphEntity, GraphEntityObservation, GraphRelationship, GraphRelationshipEvidence
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
from models.ioc import IOC, IOCSystemSighting
from models.known_system import KnownSystem
from models.user import User
from utils.graph_identity import GraphDerivationType, GraphEntityType, GraphRelationshipType


def evidence_key(char: str = "a") -> str:
    return "erk:v2:" + (char * 64)


def actor(username: str = "analyst", user_id: int = 1, **overrides):
    payload = {"username": username, "user_id": user_id, "actor_type": "analyst", "is_ai": False}
    payload.update(overrides)
    return payload


def fake_log(cls, **kwargs):
    db.session.commit()
    return SimpleNamespace(**kwargs)


def fake_log_many(cls, records):
    db.session.commit()
    return records


class Phase0DSQLiteTestCase(unittest.TestCase):
    include_users = False
    register_routes = False

    def setUp(self):
        self.app = Flask(__name__)
        self.app.config.update(
            SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            TESTING=True,
            SECRET_KEY="test-secret",
            WTF_CSRF_ENABLED=False,
        )
        db.init_app(self.app)
        self.ctx = self.app.app_context()
        self.ctx.push()
        self._create_tables()
        self._seed_cases()
        self.audit_log_patch = patch("utils.investigation_threads.AuditLog.log", classmethod(fake_log))
        self.audit_log_many_patch = patch("utils.investigation_threads.AuditLog.log_many", classmethod(fake_log_many))
        self.view_audit_log_patch = patch("utils.graph_saved_views.AuditLog.log", classmethod(fake_log))
        self.audit_log_patch.start()
        self.audit_log_many_patch.start()
        self.view_audit_log_patch.start()
        if self.include_users:
            self._init_login()

    def tearDown(self):
        if hasattr(self, "client"):
            with self.client.session_transaction() as sess:
                sess.clear()
        self.view_audit_log_patch.stop()
        self.audit_log_many_patch.stop()
        self.audit_log_patch.stop()
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def _create_tables(self):
        for table in (
            Client.__table__,
            User.__table__,
            Case.__table__,
            KnownSystem.__table__,
            GraphSavedView.__table__,
            InvestigationThread.__table__,
            InvestigationThreadEntity.__table__,
            InvestigationThreadRelationship.__table__,
            InvestigationThreadEvidence.__table__,
            InvestigationThreadIOC.__table__,
            InvestigationThreadFinding.__table__,
            InvestigationThreadNote.__table__,
            GraphEntity.__table__,
            GraphRelationship.__table__,
            GraphEntityObservation.__table__,
            GraphRelationshipEvidence.__table__,
            IOC.__table__,
            IOCSystemSighting.__table__,
        ):
            table.create(db.engine)

    def _seed_cases(self):
        db.session.add(Client(id=1, uuid="client-1", name="Client", code="CLIENT"))
        db.session.add(Case(id=1, uuid="case-a", name="Case A", company="Client", client_id=1, created_by="tester"))
        db.session.add(Case(id=2, uuid="case-b", name="Case B", company="Client", client_id=1, created_by="tester"))
        db.session.commit()

    def _init_login(self):
        login_manager = LoginManager()
        login_manager.init_app(self.app)

        @login_manager.user_loader
        def load_user(user_id):
            return User.query.get(int(user_id))

        @self.app.route("/test-login/<int:user_id>")
        def test_login(user_id):
            login_user(User.query.get(user_id))
            return "ok"

        if self.register_routes:
            from routes.graph import graph_bp
            from routes.investigation_threads import investigation_threads_bp

            self.app.register_blueprint(graph_bp)
            self.app.register_blueprint(investigation_threads_bp)

        self.users = {
            "analyst": User(
                id=1,
                username="analyst",
                full_name="Analyst",
                email="analyst@example.test",
                password_hash="x",
                permission_level=PermissionLevel.ANALYST,
            ),
            "viewer_a": User(
                id=2,
                username="viewer-a",
                full_name="Viewer A",
                email="viewer-a@example.test",
                password_hash="x",
                permission_level=PermissionLevel.VIEWER,
                assigned_cases=[1],
            ),
            "viewer_b": User(
                id=3,
                username="viewer-b",
                full_name="Viewer B",
                email="viewer-b@example.test",
                password_hash="x",
                permission_level=PermissionLevel.VIEWER,
                assigned_cases=[2],
            ),
        }
        db.session.add_all(self.users.values())
        db.session.commit()
        self.client = self.app.test_client()

    def login_as(self, key: str):
        return self.client.get(f"/test-login/{self.users[key].id}")

    def make_entity(self, *, case_id=1, entity_type=GraphEntityType.HOST, entity_key="host:alpha", display="ALPHA"):
        entity = GraphEntity(
            case_id=case_id,
            entity_type=entity_type,
            entity_key=entity_key,
            display_value=display,
            canonical_value=display.upper(),
            first_seen_at=datetime(2026, 1, 1, 12, 0, 0),
            last_seen_at=datetime(2026, 1, 1, 12, 0, 0),
            metadata_json={},
        )
        db.session.add(entity)
        db.session.flush()
        return entity

    def make_relationship(self, *, case_id=1):
        source = self.make_entity(case_id=case_id, entity_key="host:alpha", display="ALPHA")
        target = self.make_entity(
            case_id=case_id,
            entity_type=GraphEntityType.FILE_PATH,
            entity_key=r"host:host:alpha:path:C:\TOOLS\CMD.EXE",
            display=r"C:\Tools\cmd.exe",
        )
        relationship = GraphRelationship(
            case_id=case_id,
            source_entity_id=source.id,
            relationship_type=GraphRelationshipType.RUNS_IMAGE,
            target_entity_id=target.id,
            first_seen_at=datetime(2026, 1, 1, 12, 0, 0),
            last_seen_at=datetime(2026, 1, 1, 12, 0, 0),
            confidence=1.0,
            derivation_type=GraphDerivationType.DETERMINISTIC,
            extractor_name="extractor-a",
            extractor_version="1",
            validation_state="ACTIVE",
            metadata_json={},
        )
        db.session.add(relationship)
        db.session.flush()
        return source, target, relationship

    def make_ioc(self, *, case_id=1, ioc_uuid="11111111-1111-4111-8111-111111111111"):
        ioc = IOC(
            case_id=case_id,
            uuid=ioc_uuid,
            category="Network",
            ioc_type="Hostname",
            value="evil.example",
            value_normalized="evil.example",
            created_by="analyst",
            sources=["manual"],
        )
        db.session.add(ioc)
        db.session.flush()
        return ioc
