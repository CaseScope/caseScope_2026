"""Investigation Thread models — analyst-curated narratives over the evidence graph.

Authority boundary (Phase 0D):
- Canonical graph facts remain OBSERVED/DETERMINISTIC in graph_* tables.
- Thread membership means the analyst considers an object relevant; it does not
  create GraphRelationship rows or become graph authority.
- Stable references survive graph rebuild; graph row IDs are optional caches only.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from models.database import db


class InvestigationThreadStatus:
    DRAFT = "draft"
    INVESTIGATING = "investigating"
    SUPPORTED = "supported"
    REJECTED = "rejected"

    ALL = {DRAFT, INVESTIGATING, SUPPORTED, REJECTED}


class InvestigationThread(db.Model):
    """Named analyst-curated investigative narrative for one case."""

    __tablename__ = "investigation_threads"

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False, index=True, default=lambda: str(uuid.uuid4()))
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)

    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    analyst_conclusion = db.Column(db.Text, nullable=True)

    status = db.Column(db.String(32), nullable=False, default=InvestigationThreadStatus.DRAFT, index=True)

    owner_user_id = db.Column(db.Integer, nullable=True)
    owner_username = db.Column(db.String(80), nullable=True)

    time_start = db.Column(db.DateTime, nullable=True)
    time_end = db.Column(db.DateTime, nullable=True)

    include_in_report = db.Column(db.Boolean, nullable=False, default=False)

    current_saved_view_id = db.Column(
        db.Integer,
        db.ForeignKey("graph_saved_views.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    evidence_set_fingerprint = db.Column(db.String(96), nullable=False, default="")
    version = db.Column(db.Integer, nullable=False, default=1)

    created_by_user_id = db.Column(db.Integer, nullable=True)
    created_by_username = db.Column(db.String(80), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    updated_by_user_id = db.Column(db.Integer, nullable=True)
    updated_by_username = db.Column(db.String(80), nullable=True)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    case = db.relationship("Case", backref=db.backref("investigation_threads", lazy="dynamic"))
    current_saved_view = db.relationship(
        "GraphSavedView",
        foreign_keys=[current_saved_view_id],
        post_update=True,
    )

    __table_args__ = (
        db.Index("idx_investigation_thread_case_status", "case_id", "status"),
        db.Index("idx_investigation_thread_case_updated", "case_id", "updated_at"),
    )

    def __repr__(self):
        return f"<InvestigationThread {self.uuid} case={self.case_id}>"


class InvestigationThreadEntity(db.Model):
    """Typed Thread membership for a durable graph entity reference."""

    __tablename__ = "investigation_thread_entities"

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False, index=True, default=lambda: str(uuid.uuid4()))
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    thread_id = db.Column(
        db.Integer,
        db.ForeignKey("investigation_threads.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    entity_type = db.Column(db.String(50), nullable=False)
    entity_key = db.Column(db.String(512), nullable=False)

    stable_reference_key = db.Column(db.String(96), nullable=False, index=True)
    stable_reference_json = db.Column(db.JSON, nullable=False, default=dict)

    current_graph_entity_id = db.Column(db.Integer, nullable=True)

    frozen_display_value = db.Column(db.String(1024), nullable=True)
    frozen_canonical_value = db.Column(db.String(1024), nullable=True)

    snapshot_json = db.Column(db.JSON, nullable=False, default=dict)
    snapshot_sha256 = db.Column(db.String(64), nullable=False)
    snapshot_version = db.Column(db.String(32), nullable=False, default="entity-snap:v1")

    analyst_rationale = db.Column(db.Text, nullable=True)
    sequence_order = db.Column(db.Integer, nullable=False, default=0)

    added_by_user_id = db.Column(db.Integer, nullable=True)
    added_by_username = db.Column(db.String(80), nullable=True)
    added_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    thread = db.relationship(
        "InvestigationThread",
        backref=db.backref("entity_memberships", lazy="dynamic", cascade="all, delete-orphan"),
    )

    __table_args__ = (
        db.UniqueConstraint("thread_id", "stable_reference_key", name="uq_thread_entity_stable_ref"),
        db.Index("idx_thread_entity_case_key", "case_id", "entity_type", "entity_key"),
        db.Index("idx_thread_entity_thread_order", "thread_id", "sequence_order"),
    )


class InvestigationThreadRelationship(db.Model):
    """Typed Thread membership for a durable canonical relationship reference."""

    __tablename__ = "investigation_thread_relationships"

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False, index=True, default=lambda: str(uuid.uuid4()))
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    thread_id = db.Column(
        db.Integer,
        db.ForeignKey("investigation_threads.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    source_entity_type = db.Column(db.String(50), nullable=False)
    source_entity_key = db.Column(db.String(512), nullable=False)
    relationship_type = db.Column(db.String(80), nullable=False)
    target_entity_type = db.Column(db.String(50), nullable=False)
    target_entity_key = db.Column(db.String(512), nullable=False)
    derivation_type = db.Column(db.String(40), nullable=False)

    stable_reference_key = db.Column(db.String(96), nullable=False, index=True)
    stable_reference_json = db.Column(db.JSON, nullable=False, default=dict)

    current_graph_relationship_id = db.Column(db.Integer, nullable=True)

    frozen_source_display_value = db.Column(db.String(1024), nullable=True)
    frozen_source_canonical_value = db.Column(db.String(1024), nullable=True)
    frozen_target_display_value = db.Column(db.String(1024), nullable=True)
    frozen_target_canonical_value = db.Column(db.String(1024), nullable=True)

    snapshot_json = db.Column(db.JSON, nullable=False, default=dict)
    snapshot_sha256 = db.Column(db.String(64), nullable=False)
    snapshot_version = db.Column(db.String(32), nullable=False, default="rel-snap:v1")

    analyst_rationale = db.Column(db.Text, nullable=True)
    sequence_order = db.Column(db.Integer, nullable=False, default=0)

    added_by_user_id = db.Column(db.Integer, nullable=True)
    added_by_username = db.Column(db.String(80), nullable=True)
    added_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    thread = db.relationship(
        "InvestigationThread",
        backref=db.backref("relationship_memberships", lazy="dynamic", cascade="all, delete-orphan"),
    )

    __table_args__ = (
        db.UniqueConstraint("thread_id", "stable_reference_key", name="uq_thread_rel_stable_ref"),
        db.Index("idx_thread_rel_case_edge", "case_id", "relationship_type"),
        db.Index("idx_thread_rel_thread_order", "thread_id", "sequence_order"),
    )


class InvestigationThreadEvidence(db.Model):
    """Typed Thread membership for an exact Evidence Identity v2 record."""

    __tablename__ = "investigation_thread_evidence"

    id = db.Column(db.Integer, primary_key=True)
    snapshot_uuid = db.Column(db.String(36), unique=True, nullable=False, index=True, default=lambda: str(uuid.uuid4()))
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    thread_id = db.Column(
        db.Integer,
        db.ForeignKey("investigation_threads.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    evidence_record_key = db.Column(db.String(96), nullable=False, index=True)
    source_table = db.Column(db.String(80), nullable=False, default="events")

    frozen_snapshot_json = db.Column(db.JSON, nullable=False, default=dict)
    snapshot_sha256 = db.Column(db.String(64), nullable=False)
    snapshot_version = db.Column(db.String(32), nullable=False, default="evidence-snap:v1")

    analyst_visible_summary = db.Column(db.Text, nullable=True)
    source_available_at_addition = db.Column(db.Boolean, nullable=False, default=False)

    originating_relationship_reference_key = db.Column(db.String(96), nullable=True)
    originating_relationship_reference_json = db.Column(db.JSON, nullable=True)

    analyst_rationale = db.Column(db.Text, nullable=True)
    sequence_order = db.Column(db.Integer, nullable=False, default=0)

    added_by_user_id = db.Column(db.Integer, nullable=True)
    added_by_username = db.Column(db.String(80), nullable=True)
    added_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    thread = db.relationship(
        "InvestigationThread",
        backref=db.backref("evidence_memberships", lazy="dynamic", cascade="all, delete-orphan"),
    )

    __table_args__ = (
        db.UniqueConstraint("thread_id", "evidence_record_key", name="uq_thread_evidence_erk"),
        db.Index("idx_thread_evidence_case_erk", "case_id", "evidence_record_key"),
        db.Index("idx_thread_evidence_thread_order", "thread_id", "sequence_order"),
    )


class InvestigationThreadIOC(db.Model):
    """Typed Thread membership for a case-scoped IOC."""

    __tablename__ = "investigation_thread_iocs"

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False, index=True, default=lambda: str(uuid.uuid4()))
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    thread_id = db.Column(
        db.Integer,
        db.ForeignKey("investigation_threads.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    ioc_uuid = db.Column(db.String(36), nullable=False, index=True)
    stable_reference_key = db.Column(db.String(96), nullable=False, index=True)
    stable_reference_json = db.Column(db.JSON, nullable=False, default=dict)

    snapshot_json = db.Column(db.JSON, nullable=False, default=dict)
    snapshot_sha256 = db.Column(db.String(64), nullable=False)
    snapshot_version = db.Column(db.String(32), nullable=False, default="ioc-snap:v1")

    analyst_rationale = db.Column(db.Text, nullable=True)
    sequence_order = db.Column(db.Integer, nullable=False, default=0)

    added_by_user_id = db.Column(db.Integer, nullable=True)
    added_by_username = db.Column(db.String(80), nullable=True)
    added_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    thread = db.relationship(
        "InvestigationThread",
        backref=db.backref("ioc_memberships", lazy="dynamic", cascade="all, delete-orphan"),
    )

    __table_args__ = (
        db.UniqueConstraint("thread_id", "ioc_uuid", name="uq_thread_ioc_uuid"),
        db.Index("idx_thread_ioc_case_uuid", "case_id", "ioc_uuid"),
        db.Index("idx_thread_ioc_thread_order", "thread_id", "sequence_order"),
    )


class InvestigationThreadFinding(db.Model):
    """Typed Thread membership for a pinned finding identity."""

    __tablename__ = "investigation_thread_findings"

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False, index=True, default=lambda: str(uuid.uuid4()))
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    thread_id = db.Column(
        db.Integer,
        db.ForeignKey("investigation_threads.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    finding_kind = db.Column(db.String(40), nullable=False, default="unified_finding")
    stable_reference_key = db.Column(db.String(96), nullable=False, index=True)
    stable_reference_json = db.Column(db.JSON, nullable=False, default=dict)

    snapshot_json = db.Column(db.JSON, nullable=False, default=dict)
    snapshot_sha256 = db.Column(db.String(64), nullable=False)
    snapshot_version = db.Column(db.String(32), nullable=False, default="finding-snap:v1")

    analyst_rationale = db.Column(db.Text, nullable=True)
    sequence_order = db.Column(db.Integer, nullable=False, default=0)

    added_by_user_id = db.Column(db.Integer, nullable=True)
    added_by_username = db.Column(db.String(80), nullable=True)
    added_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    thread = db.relationship(
        "InvestigationThread",
        backref=db.backref("finding_memberships", lazy="dynamic", cascade="all, delete-orphan"),
    )

    __table_args__ = (
        db.UniqueConstraint("thread_id", "stable_reference_key", name="uq_thread_finding_stable_ref"),
        db.Index("idx_thread_finding_case_kind", "case_id", "finding_kind"),
        db.Index("idx_thread_finding_thread_order", "thread_id", "sequence_order"),
    )


class InvestigationThreadNote(db.Model):
    """Analyst notes attached to an Investigation Thread."""

    __tablename__ = "investigation_thread_notes"

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False, index=True, default=lambda: str(uuid.uuid4()))
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    thread_id = db.Column(
        db.Integer,
        db.ForeignKey("investigation_threads.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    body = db.Column(db.Text, nullable=False)
    sequence_order = db.Column(db.Integer, nullable=False, default=0)

    author_user_id = db.Column(db.Integer, nullable=True)
    author_username = db.Column(db.String(80), nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    thread = db.relationship(
        "InvestigationThread",
        backref=db.backref("notes", lazy="dynamic", cascade="all, delete-orphan"),
    )

    __table_args__ = (
        db.Index("idx_thread_note_thread_order", "thread_id", "sequence_order"),
    )


class InvestigationThreadReportSnapshot(db.Model):
    """Immutable report-time copy of one Investigation Thread section."""

    __tablename__ = "investigation_thread_report_snapshots"

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False, index=True, default=lambda: str(uuid.uuid4()))

    case_id = db.Column(db.Integer, db.ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    case_report_id = db.Column(
        db.Integer,
        db.ForeignKey("case_reports.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    report_generation_uuid = db.Column(db.String(36), nullable=False, index=True)

    thread_uuid = db.Column(db.String(36), nullable=False, index=True)
    thread_version = db.Column(db.Integer, nullable=False)

    saved_view_uuid = db.Column(db.String(36), nullable=True, index=True)
    saved_view_version = db.Column(db.Integer, nullable=True)

    evidence_set_fingerprint = db.Column(db.String(96), nullable=False)
    snapshot_schema_version = db.Column(db.Integer, nullable=False, default=1)
    snapshot_json = db.Column(db.JSON, nullable=False, default=dict)
    snapshot_sha256 = db.Column(db.String(96), nullable=False, index=True)

    graph_render_format = db.Column(db.String(20), nullable=True)
    graph_render_path = db.Column(db.String(1024), nullable=True)
    graph_render_sha256 = db.Column(db.String(96), nullable=True)

    ai_used = db.Column(db.Boolean, nullable=False, default=False)
    ai_provider = db.Column(db.String(120), nullable=True)
    ai_model = db.Column(db.String(200), nullable=True)
    ai_generated_at = db.Column(db.DateTime, nullable=True)
    ai_provenance_json = db.Column(db.JSON, nullable=False, default=dict)

    created_by_user_id = db.Column(db.Integer, nullable=True)
    created_by_username = db.Column(db.String(80), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    case = db.relationship("Case", backref=db.backref("thread_report_snapshots", lazy="dynamic"))
    case_report = db.relationship(
        "CaseReport",
        backref=db.backref("thread_snapshots", lazy="dynamic"),
    )

    __table_args__ = (
        db.Index("idx_thread_report_snapshot_case_uuid", "case_id", "uuid"),
        db.Index("idx_thread_report_snapshot_case_generation", "case_id", "report_generation_uuid"),
        db.Index("idx_thread_report_snapshot_case_thread_version", "case_id", "thread_uuid", "thread_version"),
    )

    def __repr__(self):
        return f"<InvestigationThreadReportSnapshot {self.uuid} thread={self.thread_uuid} v{self.thread_version}>"
