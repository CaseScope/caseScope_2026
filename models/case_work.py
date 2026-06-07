"""Case work session models for analyst time tracking."""
import json
import uuid
from datetime import datetime

from models.database import db


class CaseWorkSessionStatus:
    """Status values for analyst work sessions."""

    ACTIVE = "active"
    COMPLETED = "completed"
    STALE = "stale"

    @classmethod
    def all(cls):
        return [cls.ACTIVE, cls.COMPLETED, cls.STALE]


class CaseWorkActivityType:
    """Standardized activity labels for case work logs."""

    WORK_STARTED = "work_started"
    WORK_ENDED = "work_ended"
    UPLOAD_STARTED = "upload_started"
    FILES_UPLOADED = "files_uploaded"
    INGEST_QUEUED = "ingest_queued"
    INGEST_SUMMARY = "ingest_summary"
    HUNTING_SEARCH = "hunting_search"
    IOC_ACTION = "ioc_action"
    ANALYSIS_RUN = "analysis_run"
    REPORT_ACTION = "report_action"
    CASE_ACTION = "case_action"


class CaseWorkSession(db.Model):
    """A manually started analyst time block for one case."""

    __tablename__ = "case_work_sessions"

    id = db.Column(db.BigInteger, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False, index=True, default=lambda: str(uuid.uuid4()))

    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=False, index=True)
    case_uuid = db.Column(db.String(36), nullable=False, index=True)
    client_id = db.Column(db.Integer, db.ForeignKey("clients.id"), nullable=True, index=True)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    username = db.Column(db.String(80), nullable=False, index=True)
    analyst_name = db.Column(db.String(255), nullable=False)

    started_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    ended_at = db.Column(db.DateTime, nullable=True, index=True)
    duration_seconds = db.Column(db.Integer, nullable=True)
    status = db.Column(db.String(20), nullable=False, default=CaseWorkSessionStatus.ACTIVE, index=True)

    start_note = db.Column(db.Text, nullable=True)
    end_note = db.Column(db.Text, nullable=True)
    close_reason = db.Column(db.String(80), nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    case = db.relationship("Case", backref=db.backref("work_sessions", lazy="dynamic"))
    user = db.relationship("User", backref=db.backref("case_work_sessions", lazy="dynamic"))
    client = db.relationship("Client", backref=db.backref("case_work_sessions", lazy="dynamic"))
    activities = db.relationship(
        "CaseWorkActivity",
        backref="work_session",
        lazy="dynamic",
        cascade="all, delete-orphan",
        order_by="CaseWorkActivity.timestamp",
    )

    __table_args__ = (
        db.Index("ix_case_work_session_case_started", "case_uuid", "started_at"),
        db.Index("ix_case_work_session_user_status", "user_id", "status"),
    )

    def complete(self, end_note=None, close_reason="manual"):
        """Close the session and calculate its duration."""
        self.ended_at = datetime.utcnow()
        self.status = CaseWorkSessionStatus.COMPLETED
        self.end_note = end_note or None
        self.close_reason = close_reason
        self.duration_seconds = max(0, int((self.ended_at - self.started_at).total_seconds()))

    def to_summary_dict(self):
        """Convert to a compact API payload."""
        return {
            "uuid": self.uuid,
            "case_uuid": self.case_uuid,
            "case_name": self.case.name if self.case else None,
            "client_id": self.client_id,
            "client_name": self.client.name if self.client else (self.case.company if self.case else None),
            "user_id": self.user_id,
            "username": self.username,
            "analyst_name": self.analyst_name,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "ended_at": self.ended_at.isoformat() if self.ended_at else None,
            "duration_seconds": self.duration_seconds,
            "status": self.status,
            "start_note": self.start_note,
            "end_note": self.end_note,
            "close_reason": self.close_reason,
        }

    def to_detail_dict(self):
        """Convert to an API payload with activity details."""
        data = self.to_summary_dict()
        data["activities"] = [activity.to_dict() for activity in self.activities.order_by(CaseWorkActivity.timestamp.asc()).all()]
        return data


class CaseWorkActivity(db.Model):
    """Append-only narrative activity within a work session."""

    __tablename__ = "case_work_activities"

    id = db.Column(db.BigInteger, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False, index=True, default=lambda: str(uuid.uuid4()))

    work_session_id = db.Column(db.BigInteger, db.ForeignKey("case_work_sessions.id"), nullable=False, index=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=False, index=True)
    case_uuid = db.Column(db.String(36), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    username = db.Column(db.String(80), nullable=False, index=True)

    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    activity_type = db.Column(db.String(80), nullable=False, index=True)
    summary = db.Column(db.String(500), nullable=False)
    details = db.Column(db.Text, nullable=True)

    __table_args__ = (
        db.Index("ix_case_work_activity_case_time", "case_uuid", "timestamp"),
        db.Index("ix_case_work_activity_session_time", "work_session_id", "timestamp"),
    )

    def details_dict(self):
        if not self.details:
            return None
        try:
            return json.loads(self.details)
        except (TypeError, json.JSONDecodeError):
            return {"raw": self.details}

    def to_dict(self):
        return {
            "uuid": self.uuid,
            "case_uuid": self.case_uuid,
            "user_id": self.user_id,
            "username": self.username,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "activity_type": self.activity_type,
            "summary": self.summary,
            "details": self.details_dict(),
        }
