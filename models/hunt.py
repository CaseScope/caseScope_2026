"""Hunt ledger models for auditable investigation traces."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict

from models.database import db


class HuntCoverageStatus:
    COMPLETE = "complete"
    PARTIAL = "partial"
    INSUFFICIENT = "insufficient"
    NOT_AVAILABLE = "not_available"
    UNKNOWN = "unknown"

    @classmethod
    def all(cls):
        return [
            cls.COMPLETE,
            cls.PARTIAL,
            cls.INSUFFICIENT,
            cls.NOT_AVAILABLE,
            cls.UNKNOWN,
        ]


class HuntCreatedByType:
    AI = "ai"
    ANALYST = "analyst"
    SYSTEM = "system"
    RULES_ENGINE = "rules_engine"

    @classmethod
    def all(cls):
        return [cls.AI, cls.ANALYST, cls.SYSTEM, cls.RULES_ENGINE]


class HuntStepStatus:
    STARTED = "started"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"

    @classmethod
    def all(cls):
        return [cls.STARTED, cls.COMPLETED, cls.FAILED, cls.SKIPPED]


class HuntDecisionState:
    DRAFT = "draft"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    SUPERSEDED = "superseded"

    @classmethod
    def all(cls):
        return [cls.DRAFT, cls.ACCEPTED, cls.REJECTED, cls.SUPERSEDED]


class HuntDecisionClassification:
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    BENIGN = "benign"
    INCONCLUSIVE = "inconclusive"
    NEEDS_MORE_REVIEW = "needs_more_review"

    @classmethod
    def all(cls):
        return [
            cls.SUSPICIOUS,
            cls.MALICIOUS,
            cls.BENIGN,
            cls.INCONCLUSIVE,
            cls.NEEDS_MORE_REVIEW,
        ]


class HuntDecisionEvidenceRole:
    PRIMARY = "primary"
    SUPPORTING = "supporting"
    CONTEXT = "context"

    @classmethod
    def all(cls):
        return [cls.PRIMARY, cls.SUPPORTING, cls.CONTEXT]


class HuntDecisionScope:
    CASE = "case"
    HOST = "host"
    USER = "user"
    IOC = "ioc"
    ARTIFACT = "artifact"
    PROCESS = "process"
    SERVICE = "service"
    NETWORK = "network"

    @classmethod
    def all(cls):
        return [
            cls.CASE,
            cls.HOST,
            cls.USER,
            cls.IOC,
            cls.ARTIFACT,
            cls.PROCESS,
            cls.SERVICE,
            cls.NETWORK,
        ]


class HuntRun(db.Model):
    """One investigation objective with append-friendly ledger records."""

    __tablename__ = "hunt_runs"

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=False, index=True)
    objective = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(40), nullable=False, default="active", index=True)

    created_by = db.Column(db.String(80), nullable=False, default="system", index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    model_provider = db.Column(db.String(80), nullable=True)
    model_name = db.Column(db.String(255), nullable=True)
    source_scope = db.Column(db.JSON, nullable=True)
    time_scope_start = db.Column(db.DateTime, nullable=True)
    time_scope_end = db.Column(db.DateTime, nullable=True)
    final_summary = db.Column(db.Text, nullable=True)

    case = db.relationship("Case", backref=db.backref("hunt_runs", lazy="dynamic"))

    __table_args__ = (
        db.Index("ix_hunt_runs_case_status", "case_id", "status"),
        db.Index("ix_hunt_runs_case_created", "case_id", "created_at"),
    )

    def to_dict(self, include_children: bool = False) -> Dict[str, Any]:
        payload = {
            "id": self.id,
            "case_id": self.case_id,
            "case_name": self.case.name if self.case else None,
            "objective": self.objective,
            "status": self.status,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "model_provider": self.model_provider,
            "model_name": self.model_name,
            "source_scope": self.source_scope or {},
            "time_scope_start": self.time_scope_start.isoformat() if self.time_scope_start else None,
            "time_scope_end": self.time_scope_end.isoformat() if self.time_scope_end else None,
            "final_summary": self.final_summary,
        }
        if include_children:
            payload["hypotheses"] = [h.to_dict() for h in self.hypotheses.order_by(HuntHypothesis.created_at.asc()).all()]
            payload["steps"] = [s.to_dict(include_evidence=True) for s in self.steps.order_by(HuntStep.step_number.asc(), HuntStep.id.asc()).all()]
            payload["decisions"] = [
                d.to_dict(include_evidence=True)
                for d in self.decisions.order_by(HuntDecision.created_at.asc(), HuntDecision.id.asc()).all()
            ]
        return payload


class HuntHypothesis(db.Model):
    """A hypothesis being tested during a hunt run."""

    __tablename__ = "hunt_hypotheses"

    id = db.Column(db.Integer, primary_key=True)
    hunt_run_id = db.Column(db.Integer, db.ForeignKey("hunt_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    hypothesis = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(40), nullable=False, default="open", index=True)
    confidence = db.Column(db.Float, nullable=True)
    rationale = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    resolved_at = db.Column(db.DateTime, nullable=True)

    hunt_run = db.relationship("HuntRun", backref=db.backref("hypotheses", lazy="dynamic", cascade="all, delete-orphan"))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "hunt_run_id": self.hunt_run_id,
            "hypothesis": self.hypothesis,
            "status": self.status,
            "confidence": self.confidence,
            "rationale": self.rationale,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
        }


class HuntStep(db.Model):
    """One traced tool call, check, or pivot within a hunt run."""

    __tablename__ = "hunt_steps"

    id = db.Column(db.Integer, primary_key=True)
    hunt_run_id = db.Column(db.Integer, db.ForeignKey("hunt_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    hypothesis_id = db.Column(db.Integer, db.ForeignKey("hunt_hypotheses.id", ondelete="SET NULL"), nullable=True, index=True)
    step_number = db.Column(db.Integer, nullable=False)

    tool_name = db.Column(db.String(120), nullable=False, index=True)
    tool_parameters_json = db.Column(db.JSON, nullable=False, default=dict)
    query_summary = db.Column(db.Text, nullable=True)

    started_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), nullable=False, default=HuntStepStatus.STARTED, index=True)

    result_count = db.Column(db.Integer, nullable=True)
    result_summary = db.Column(db.Text, nullable=True)
    coverage_status = db.Column(db.String(30), nullable=False, default=HuntCoverageStatus.UNKNOWN, index=True)
    coverage_detail_json = db.Column(db.JSON, nullable=True)
    error_message = db.Column(db.Text, nullable=True)
    metadata_json = db.Column(db.JSON, nullable=True)
    result_fingerprint = db.Column(db.String(80), nullable=True, index=True)

    created_by_type = db.Column(db.String(30), nullable=False, default=HuntCreatedByType.SYSTEM, index=True)
    created_by = db.Column(db.String(80), nullable=False, default="system", index=True)
    model_provider = db.Column(db.String(80), nullable=True)
    model_name = db.Column(db.String(255), nullable=True)
    prompt_version = db.Column(db.String(80), nullable=True)
    schema_version = db.Column(db.String(80), nullable=False, default="hunt-ledger-v1")

    hunt_run = db.relationship("HuntRun", backref=db.backref("steps", lazy="dynamic", cascade="all, delete-orphan"))
    hypothesis = db.relationship("HuntHypothesis", backref=db.backref("steps", lazy="dynamic"))

    __table_args__ = (
        db.Index("ix_hunt_steps_run_number", "hunt_run_id", "step_number"),
        db.Index("ix_hunt_steps_run_status", "hunt_run_id", "status"),
    )

    def to_dict(self, include_evidence: bool = False) -> Dict[str, Any]:
        payload = {
            "id": self.id,
            "hunt_run_id": self.hunt_run_id,
            "hypothesis_id": self.hypothesis_id,
            "step_number": self.step_number,
            "tool_name": self.tool_name,
            "tool_parameters_json": self.tool_parameters_json or {},
            "query_summary": self.query_summary,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "status": self.status,
            "result_count": self.result_count,
            "result_summary": self.result_summary,
            "coverage_status": self.coverage_status,
            "coverage_detail_json": self.coverage_detail_json or {},
            "error_message": self.error_message,
            "metadata_json": self.metadata_json or {},
            "result_fingerprint": self.result_fingerprint,
            "created_by_type": self.created_by_type,
            "created_by": self.created_by,
            "model_provider": self.model_provider,
            "model_name": self.model_name,
            "prompt_version": self.prompt_version,
            "schema_version": self.schema_version,
        }
        if include_evidence:
            payload["evidence_refs"] = [
                ref.to_dict()
                for ref in self.evidence_refs.order_by(HuntEvidenceRef.id.asc()).all()
            ]
        return payload


class HuntEvidenceRef(db.Model):
    """Durable selector for evidence returned by a traced step."""

    __tablename__ = "hunt_evidence_refs"

    id = db.Column(db.Integer, primary_key=True)
    hunt_step_id = db.Column(db.Integer, db.ForeignKey("hunt_steps.id", ondelete="CASCADE"), nullable=False, index=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=False, index=True)

    source_type = db.Column(db.String(80), nullable=True)
    source_table = db.Column(db.String(80), nullable=True, index=True)
    source_id = db.Column(db.String(255), nullable=True)
    source_file = db.Column(db.String(1024), nullable=True)
    artifact_type = db.Column(db.String(120), nullable=True, index=True)
    timestamp = db.Column(db.DateTime, nullable=True, index=True)
    host = db.Column(db.String(255), nullable=True, index=True)
    username = db.Column(db.String(255), nullable=True, index=True)
    artifact_path = db.Column(db.Text, nullable=True)
    event_id = db.Column(db.String(80), nullable=True, index=True)
    record_id = db.Column(db.String(120), nullable=True)
    ioc_value = db.Column(db.Text, nullable=True)
    row_uuid = db.Column(db.String(120), nullable=True)
    summary = db.Column(db.Text, nullable=True)
    provenance = db.Column(db.String(80), nullable=True)
    selector_json = db.Column(db.JSON, nullable=False, default=dict)
    selector_hash = db.Column(db.String(80), nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    step = db.relationship("HuntStep", backref=db.backref("evidence_refs", lazy="dynamic", cascade="all, delete-orphan"))
    case = db.relationship("Case", backref=db.backref("hunt_evidence_refs", lazy="dynamic"))

    __table_args__ = (
        db.Index("ix_hunt_evidence_case_hash", "case_id", "selector_hash"),
        db.Index("ix_hunt_evidence_step_hash", "hunt_step_id", "selector_hash"),
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "hunt_step_id": self.hunt_step_id,
            "case_id": self.case_id,
            "source_type": self.source_type,
            "source_table": self.source_table,
            "source_id": self.source_id,
            "source_file": self.source_file,
            "artifact_type": self.artifact_type,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "host": self.host,
            "username": self.username,
            "artifact_path": self.artifact_path,
            "event_id": self.event_id,
            "record_id": self.record_id,
            "ioc_value": self.ioc_value,
            "row_uuid": self.row_uuid,
            "summary": self.summary,
            "provenance": self.provenance,
            "selector_json": self.selector_json or {},
            "selector_hash": self.selector_hash,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class HuntDecision(db.Model):
    """Evidence-backed classification attached to a hunt run."""

    __tablename__ = "hunt_decisions"

    id = db.Column(db.Integer, primary_key=True)
    hunt_run_id = db.Column(db.Integer, db.ForeignKey("hunt_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    hypothesis_id = db.Column(db.Integer, db.ForeignKey("hunt_hypotheses.id", ondelete="SET NULL"), nullable=True, index=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=False, index=True)

    source_decision_id = db.Column(db.Integer, db.ForeignKey("hunt_decisions.id", ondelete="SET NULL"), nullable=True, index=True)
    supersedes_decision_id = db.Column(db.Integer, db.ForeignKey("hunt_decisions.id", ondelete="SET NULL"), nullable=True, index=True)
    superseded_by_decision_id = db.Column(db.Integer, db.ForeignKey("hunt_decisions.id", ondelete="SET NULL"), nullable=True, index=True)

    decision_state = db.Column(db.String(30), nullable=False, default=HuntDecisionState.DRAFT, index=True)
    classification = db.Column(db.String(40), nullable=False, index=True)
    decision_scope = db.Column(db.String(40), nullable=False, default=HuntDecisionScope.CASE, index=True)
    target_host = db.Column(db.String(255), nullable=True, index=True)
    target_user = db.Column(db.String(255), nullable=True, index=True)
    target_ioc = db.Column(db.Text, nullable=True)
    target_artifact_path = db.Column(db.Text, nullable=True)
    target_process = db.Column(db.Text, nullable=True)

    confidence = db.Column(db.Float, nullable=True)
    rationale = db.Column(db.Text, nullable=True)
    ai_rationale = db.Column(db.Text, nullable=True)
    evidence_fingerprint = db.Column(db.String(80), nullable=True, index=True)

    created_by_type = db.Column(db.String(30), nullable=False, default=HuntCreatedByType.SYSTEM, index=True)
    created_by = db.Column(db.String(80), nullable=False, default="system", index=True)
    reviewed_by = db.Column(db.String(80), nullable=True, index=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    review_note = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    accepted_at = db.Column(db.DateTime, nullable=True, index=True)
    superseded_at = db.Column(db.DateTime, nullable=True)
    metadata_json = db.Column(db.JSON, nullable=True)
    schema_version = db.Column(db.String(80), nullable=False, default="hunt-decision-v1")

    hunt_run = db.relationship("HuntRun", backref=db.backref("decisions", lazy="dynamic", cascade="all, delete-orphan"))
    hypothesis = db.relationship("HuntHypothesis", backref=db.backref("decisions", lazy="dynamic"))
    case = db.relationship("Case", backref=db.backref("hunt_decisions", lazy="dynamic"))
    source_decision = db.relationship("HuntDecision", remote_side=[id], foreign_keys=[source_decision_id], post_update=True)
    supersedes_decision = db.relationship("HuntDecision", remote_side=[id], foreign_keys=[supersedes_decision_id], post_update=True)
    superseded_by_decision = db.relationship("HuntDecision", remote_side=[id], foreign_keys=[superseded_by_decision_id], post_update=True)

    __table_args__ = (
        db.Index("ix_hunt_decisions_run_state", "hunt_run_id", "decision_state"),
        db.Index("ix_hunt_decisions_case_scope", "case_id", "decision_scope"),
        db.Index("ix_hunt_decisions_active", "case_id", "hunt_run_id", "decision_state", "created_by_type", "superseded_by_decision_id"),
    )

    @property
    def is_authoritative(self) -> bool:
        return (
            self.decision_state == HuntDecisionState.ACCEPTED
            and self.created_by_type == HuntCreatedByType.ANALYST
            and self.superseded_by_decision_id is None
        )

    def to_dict(self, include_evidence: bool = False) -> Dict[str, Any]:
        payload = {
            "id": self.id,
            "hunt_run_id": self.hunt_run_id,
            "hypothesis_id": self.hypothesis_id,
            "case_id": self.case_id,
            "source_decision_id": self.source_decision_id,
            "supersedes_decision_id": self.supersedes_decision_id,
            "superseded_by_decision_id": self.superseded_by_decision_id,
            "decision_state": self.decision_state,
            "classification": self.classification,
            "decision_scope": self.decision_scope,
            "target_host": self.target_host,
            "target_user": self.target_user,
            "target_ioc": self.target_ioc,
            "target_artifact_path": self.target_artifact_path,
            "target_process": self.target_process,
            "confidence": self.confidence,
            "rationale": self.rationale,
            "ai_rationale": self.ai_rationale,
            "evidence_fingerprint": self.evidence_fingerprint,
            "created_by_type": self.created_by_type,
            "created_by": self.created_by,
            "reviewed_by": self.reviewed_by,
            "reviewed_at": self.reviewed_at.isoformat() if self.reviewed_at else None,
            "review_note": self.review_note,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "accepted_at": self.accepted_at.isoformat() if self.accepted_at else None,
            "superseded_at": self.superseded_at.isoformat() if self.superseded_at else None,
            "metadata_json": self.metadata_json or {},
            "schema_version": self.schema_version,
            "is_authoritative": self.is_authoritative,
        }
        if include_evidence:
            payload["evidence_links"] = [
                link.to_dict(include_refs=True)
                for link in self.evidence_links.order_by(HuntDecisionEvidenceLink.id.asc()).all()
            ]
        return payload


class HuntDecisionEvidenceLink(db.Model):
    """Evidence support link for a hunt decision."""

    __tablename__ = "hunt_decision_evidence_links"

    id = db.Column(db.Integer, primary_key=True)
    hunt_decision_id = db.Column(db.Integer, db.ForeignKey("hunt_decisions.id", ondelete="CASCADE"), nullable=False, index=True)
    hunt_step_id = db.Column(db.Integer, db.ForeignKey("hunt_steps.id", ondelete="SET NULL"), nullable=True, index=True)
    hunt_evidence_ref_id = db.Column(db.Integer, db.ForeignKey("hunt_evidence_refs.id", ondelete="SET NULL"), nullable=True, index=True)
    support_role = db.Column(db.String(30), nullable=False, default=HuntDecisionEvidenceRole.SUPPORTING, index=True)
    note = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    decision = db.relationship("HuntDecision", backref=db.backref("evidence_links", lazy="dynamic", cascade="all, delete-orphan"))
    step = db.relationship("HuntStep", backref=db.backref("decision_evidence_links", lazy="dynamic"))
    evidence_ref = db.relationship("HuntEvidenceRef", backref=db.backref("decision_evidence_links", lazy="dynamic"))

    __table_args__ = (
        db.Index("ix_hunt_decision_links_decision_role", "hunt_decision_id", "support_role"),
        db.Index("ix_hunt_decision_links_step_ref", "hunt_step_id", "hunt_evidence_ref_id"),
    )

    def to_dict(self, include_refs: bool = False) -> Dict[str, Any]:
        payload = {
            "id": self.id,
            "hunt_decision_id": self.hunt_decision_id,
            "hunt_step_id": self.hunt_step_id,
            "hunt_evidence_ref_id": self.hunt_evidence_ref_id,
            "support_role": self.support_role,
            "note": self.note,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
        if include_refs:
            payload["step"] = self.step.to_dict() if self.step else None
            payload["evidence_ref"] = self.evidence_ref.to_dict() if self.evidence_ref else None
        return payload
