"""Models for background IOC AI enhancement review runs."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from models.database import db


class IOCEnhancementStatus:
    """Status values for AI enhancement runs."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

    @classmethod
    def active_statuses(cls) -> tuple[str, ...]:
        return (cls.PENDING, cls.RUNNING)


class CaseIOCEnhancementRun(db.Model):
    """Tracks a background AI pass that stages additional IOC candidates."""

    __tablename__ = "case_ioc_enhancement_runs"

    id = db.Column(db.Integer, primary_key=True)
    run_uuid = db.Column(db.String(36), nullable=False, unique=True, index=True, default=lambda: str(uuid.uuid4()))
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=False, index=True)
    report_index = db.Column(db.Integer, nullable=False, default=0)
    status = db.Column(db.String(20), nullable=False, default=IOCEnhancementStatus.PENDING, index=True)
    progress_percent = db.Column(db.Integer, nullable=False, default=0)
    current_phase = db.Column(db.String(255), nullable=True)
    celery_task_id = db.Column(db.String(100), nullable=True, index=True)
    model = db.Column(db.String(255), nullable=True)
    error_message = db.Column(db.Text, nullable=True)
    staged_candidates = db.Column(db.JSON, nullable=False, default=list)
    summary = db.Column(db.JSON, nullable=True)
    requested_by = db.Column(db.String(80), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    last_progress_at = db.Column(db.DateTime, nullable=True, index=True)

    case = db.relationship("Case", backref=db.backref("ioc_enhancement_runs", lazy="dynamic"))

    def is_active(self) -> bool:
        return self.status in IOCEnhancementStatus.active_statuses()

    def has_pending_candidates(self) -> bool:
        return any(
            str(candidate.get("review_status") or "pending") == "pending"
            for candidate in self.staged_candidates or []
            if isinstance(candidate, dict)
        )

    def is_stale(self, stale_after_minutes: int = 60) -> bool:
        if not self.is_active():
            return False
        reference = self.last_progress_at or self.started_at or self.created_at
        return bool(reference and reference < (datetime.utcnow() - timedelta(minutes=stale_after_minutes)))

    def update_progress(self, phase: str, percent: int, *, status: Optional[str] = None) -> None:
        if status:
            self.status = status
        self.current_phase = phase
        self.progress_percent = min(100, max(0, int(percent or 0)))
        self.last_progress_at = datetime.utcnow()
        if self.status == IOCEnhancementStatus.RUNNING and not self.started_at:
            self.started_at = self.last_progress_at

    def mark_failed(self, message: str) -> None:
        now = datetime.utcnow()
        self.status = IOCEnhancementStatus.FAILED
        self.progress_percent = 100
        self.current_phase = "AI enhancement failed"
        self.error_message = str(message or "Unknown error")
        self.completed_at = now
        self.last_progress_at = now

    def mark_completed(self, candidates: List[Dict[str, Any]], summary: Optional[Dict[str, Any]] = None) -> None:
        now = datetime.utcnow()
        self.status = IOCEnhancementStatus.COMPLETED
        self.progress_percent = 100
        self.current_phase = (
            f"{len(candidates)} AI candidates ready for review"
            if candidates
            else "AI enhancement complete; no additional candidates found"
        )
        self.staged_candidates = candidates
        self.summary = summary or {}
        self.completed_at = now
        self.last_progress_at = now

    def to_dict(self) -> Dict[str, Any]:
        candidates = self.staged_candidates or []
        pending_count = sum(
            1
            for candidate in candidates
            if isinstance(candidate, dict) and str(candidate.get("review_status") or "pending") == "pending"
        )
        return {
            "id": self.id,
            "run_uuid": self.run_uuid,
            "case_id": self.case_id,
            "report_index": self.report_index,
            "status": self.status,
            "progress_percent": self.progress_percent,
            "current_phase": self.current_phase,
            "celery_task_id": self.celery_task_id,
            "model": self.model,
            "error_message": self.error_message,
            "staged_candidates": candidates,
            "candidate_count": len(candidates),
            "pending_candidate_count": pending_count,
            "summary": self.summary or {},
            "requested_by": self.requested_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "last_progress_at": self.last_progress_at.isoformat() if self.last_progress_at else None,
        }
