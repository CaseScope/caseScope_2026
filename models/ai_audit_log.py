"""Tamper-evident AI prompt/response audit records."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import event

from models.database import db


class AIAuditStatus:
    """Terminal states for audited AI calls."""

    SUCCESS = "success"
    PROVIDER_ERROR = "provider_error"
    STREAM_INTERRUPTED = "stream_interrupted"
    CLIENT_DISCONNECTED = "client_disconnected"
    AUDIT_WRITE_FAILED = "audit_write_failed"

    @classmethod
    def all(cls):
        return [
            cls.SUCCESS,
            cls.PROVIDER_ERROR,
            cls.STREAM_INTERRUPTED,
            cls.CLIENT_DISCONNECTED,
            cls.AUDIT_WRITE_FAILED,
        ]


class AIAuditLog(db.Model):
    """Append-only evidence log of prompt payloads sent to configured AI models."""

    __tablename__ = "ai_audit_log"

    id = db.Column(db.BigInteger, primary_key=True)
    timestamp = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), index=True)

    client_id = db.Column(db.Integer, nullable=True, index=True)
    client_uuid = db.Column(db.String(36), nullable=True, index=True)
    client_name = db.Column(db.String(255), nullable=True)

    case_id = db.Column(db.Integer, nullable=True, index=True)
    case_uuid = db.Column(db.String(36), nullable=True, index=True)
    case_name = db.Column(db.String(255), nullable=True)

    user_id = db.Column(db.Integer, nullable=True, index=True)
    username = db.Column(db.String(80), nullable=False, default="system", index=True)

    function = db.Column(db.String(100), nullable=False, index=True)
    mode = db.Column(db.String(30), nullable=False, index=True)
    provider_type = db.Column(db.String(50), nullable=False, index=True)
    provider_display = db.Column(db.String(255), nullable=True)
    provider_path = db.Column(db.String(500), nullable=True)
    model = db.Column(db.String(255), nullable=False, index=True)

    request_payload = db.Column(db.Text, nullable=False)
    response_payload = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(40), nullable=False, index=True)
    response_complete = db.Column(db.Boolean, nullable=False, default=False)
    error_class = db.Column(db.String(255), nullable=True)
    error_message = db.Column(db.Text, nullable=True)
    duration_ms = db.Column(db.Integer, nullable=True)
    usage = db.Column(db.Text, nullable=True)
    privacy = db.Column(db.Text, nullable=True)

    hash_version = db.Column(db.String(10), nullable=False, default="v1")
    prompt_hash = db.Column(db.String(80), nullable=False)
    response_hash = db.Column(db.String(80), nullable=False)
    previous_record_hash = db.Column(db.String(80), nullable=True)
    record_hash = db.Column(db.String(80), nullable=False, unique=True, index=True)

    archive_job_id = db.Column(db.Integer, nullable=True, index=True)
    archived_at = db.Column(db.DateTime(timezone=True), nullable=True)

    __table_args__ = (
        db.Index("ix_ai_audit_case_time", "case_uuid", "timestamp"),
        db.Index("ix_ai_audit_function_time", "function", "timestamp"),
        db.Index("ix_ai_audit_model_time", "model", "timestamp"),
        db.Index("ix_ai_audit_status_time", "status", "timestamp"),
    )

    def __repr__(self):
        return f"<AIAuditLog {self.id}: {self.function}/{self.model} {self.status}>"

    def _json_field(self, value):
        if not value:
            return None
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return value

    def to_dict(self, include_payloads: bool = False):
        payload = {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "client_uuid": self.client_uuid,
            "client_name": self.client_name,
            "case_id": self.case_id,
            "case_uuid": self.case_uuid,
            "case_name": self.case_name,
            "user_id": self.user_id,
            "username": self.username,
            "function": self.function,
            "mode": self.mode,
            "provider_type": self.provider_type,
            "provider_display": self.provider_display,
            "provider_path": self.provider_path,
            "model": self.model,
            "status": self.status,
            "response_complete": self.response_complete,
            "error_class": self.error_class,
            "error_message": self.error_message,
            "duration_ms": self.duration_ms,
            "usage": self._json_field(self.usage),
            "privacy": self._json_field(self.privacy),
            "hash_version": self.hash_version,
            "prompt_hash": self.prompt_hash,
            "response_hash": self.response_hash,
            "previous_record_hash": self.previous_record_hash,
            "record_hash": self.record_hash,
            "archive_job_id": self.archive_job_id,
            "archived_at": self.archived_at.isoformat() if self.archived_at else None,
        }
        if include_payloads:
            payload["request_payload"] = self.request_payload
            payload["response_payload"] = self.response_payload
        return payload


def _prevent_ai_audit_modification(mapper, connection, target):
    raise ValueError("AI audit log entries are immutable and cannot be modified")


def _prevent_ai_audit_deletion(mapper, connection, target):
    raise ValueError("AI audit log entries are immutable and cannot be deleted")


event.listen(AIAuditLog, "before_update", _prevent_ai_audit_modification)
event.listen(AIAuditLog, "before_delete", _prevent_ai_audit_deletion)
