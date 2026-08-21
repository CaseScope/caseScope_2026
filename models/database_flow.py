"""Phase 1B database-flow control-plane models.

These tables are durable foundations for source generations, ingest attempts,
batch manifests, and per-source capability watermarks. Tranche A installs the
schema only; current ingest/read behavior remains unchanged.
"""
from datetime import datetime

from sqlalchemy import text

from models.database import db


class EvidenceGenerationState:
    BUILDING_INITIAL = "BUILDING_INITIAL"
    BUILDING_REPLACEMENT = "BUILDING_REPLACEMENT"
    ACTIVE = "ACTIVE"
    SUPERSEDED = "SUPERSEDED"
    INVALIDATED = "INVALIDATED"
    FAILED = "FAILED"

    @classmethod
    def all(cls):
        return [
            cls.BUILDING_INITIAL,
            cls.BUILDING_REPLACEMENT,
            cls.ACTIVE,
            cls.SUPERSEDED,
            cls.INVALIDATED,
            cls.FAILED,
        ]


class SourceRefType:
    CASE_FILE = "CASE_FILE"
    MEMORY_JOB = "MEMORY_JOB"
    PCAP_FILE = "PCAP_FILE"


class IngestBatchState:
    STAGED = "STAGED"
    DURABLE = "DURABLE"

    @classmethod
    def all(cls):
        return [cls.STAGED, cls.DURABLE]


class CapabilityWatermarkStatus:
    NOT_STARTED = "NOT_STARTED"
    IN_PROGRESS = "IN_PROGRESS"
    CONTIGUOUS_READY = "CONTIGUOUS_READY"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"
    INVALIDATED = "INVALIDATED"

    @classmethod
    def all(cls):
        return [
            cls.NOT_STARTED,
            cls.IN_PROGRESS,
            cls.CONTIGUOUS_READY,
            cls.COMPLETE,
            cls.FAILED,
            cls.INVALIDATED,
        ]


class CapabilityName:
    PRIVACY_ALIASES = "privacy_aliases"
    IOC_MATCHES = "ioc_matches"
    MITRE_MATCHES = "mitre_matches"
    GRAPH_EXTRACTION = "graph_extraction"
    KNOWN_PRINCIPAL_DISCOVERY = "known_principal_discovery"
    BEHAVIORAL_PROFILE_CONTRIBUTION = "behavioral_profile_contribution"
    PATTERN_DETECTION = "pattern_detection"
    EVENT_EMBEDDINGS = "event_embeddings"

    @classmethod
    def all(cls):
        return [
            cls.PRIVACY_ALIASES,
            cls.IOC_MATCHES,
            cls.MITRE_MATCHES,
            cls.GRAPH_EXTRACTION,
            cls.KNOWN_PRINCIPAL_DISCOVERY,
            cls.BEHAVIORAL_PROFILE_CONTRIBUTION,
            cls.PATTERN_DETECTION,
            cls.EVENT_EMBEDDINGS,
        ]


class CapabilityDerivationClass:
    ROW_LOCAL = "ROW_LOCAL"
    ADDITIVE_AGGREGATE = "ADDITIVE_AGGREGATE"
    WINDOWED_STATEFUL = "WINDOWED_STATEFUL"
    WHOLE_SOURCE = "WHOLE_SOURCE"
    WHOLE_CASE = "WHOLE_CASE"


class EvidenceSourceGeneration(db.Model):
    """PostgreSQL authority for one source interpretation generation."""

    __tablename__ = "evidence_source_generations"

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    source_ref_type = db.Column(db.String(40), nullable=False, index=True)
    source_ref_id = db.Column(db.String(128), nullable=False, index=True)
    source_generation = db.Column(db.Integer, nullable=False)
    visibility_state = db.Column(
        db.String(40),
        nullable=False,
        default=EvidenceGenerationState.BUILDING_INITIAL,
        index=True,
    )
    state_version = db.Column(db.BigInteger, nullable=False, default=1)

    parser_version = db.Column(db.String(128), nullable=False)
    normalization_version = db.Column(db.String(128), nullable=False)
    batching_contract_version = db.Column(db.String(64), nullable=False)
    configured_batch_size = db.Column(db.Integer, nullable=False)
    ordering_contract = db.Column(db.String(255), nullable=False)
    producer_version = db.Column(db.String(128), nullable=True)

    expected_rows = db.Column(db.BigInteger, nullable=True)
    landed_rows = db.Column(db.BigInteger, nullable=False, default=0)
    final_batch_ordinal = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    activated_at = db.Column(db.DateTime, nullable=True)
    superseded_at = db.Column(db.DateTime, nullable=True)
    superseded_by_generation = db.Column(db.Integer, nullable=True)
    failed_at = db.Column(db.DateTime, nullable=True)
    failure_reason = db.Column(db.Text, nullable=True)

    case = db.relationship("Case", backref=db.backref("evidence_source_generations", lazy="dynamic"))

    __table_args__ = (
        db.UniqueConstraint(
            "case_id",
            "source_ref_type",
            "source_ref_id",
            "source_generation",
            name="uq_evidence_source_generation_identity",
        ),
        db.CheckConstraint("source_generation >= 1", name="ck_evidence_source_generation_positive"),
        db.CheckConstraint("state_version >= 1", name="ck_evidence_source_generation_state_version_positive"),
        db.CheckConstraint("configured_batch_size > 0", name="ck_evidence_source_generation_batch_size_positive"),
        db.CheckConstraint("landed_rows >= 0", name="ck_evidence_source_generation_landed_rows_nonnegative"),
        db.CheckConstraint(
            "expected_rows IS NULL OR expected_rows >= 0",
            name="ck_evidence_source_generation_expected_rows_nonnegative",
        ),
        db.CheckConstraint(
            "final_batch_ordinal IS NULL OR final_batch_ordinal >= 0",
            name="ck_evidence_source_generation_final_batch_ordinal_nonnegative",
        ),
        db.CheckConstraint(
            "visibility_state IN ('BUILDING_INITIAL', 'BUILDING_REPLACEMENT', 'ACTIVE', "
            "'SUPERSEDED', 'INVALIDATED', 'FAILED')",
            name="ck_evidence_source_generation_visibility_state",
        ),
        db.Index("idx_evidence_source_generation_source_state", "case_id", "source_ref_type", "source_ref_id", "visibility_state"),
        db.Index(
            "uq_evidence_source_generation_open_building",
            "case_id",
            "source_ref_type",
            "source_ref_id",
            unique=True,
            postgresql_where=text("visibility_state IN ('BUILDING_INITIAL', 'BUILDING_REPLACEMENT')"),
            sqlite_where=text("visibility_state IN ('BUILDING_INITIAL', 'BUILDING_REPLACEMENT')"),
        ),
        db.Index(
            "uq_evidence_source_generation_active",
            "case_id",
            "source_ref_type",
            "source_ref_id",
            unique=True,
            postgresql_where=text("visibility_state = 'ACTIVE'"),
            sqlite_where=text("visibility_state = 'ACTIVE'"),
        ),
    )


class EvidenceGenerationAudit(db.Model):
    """Durable audit row for source-generation authority transitions."""

    __tablename__ = "evidence_generation_audit"

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    source_ref_type = db.Column(db.String(40), nullable=False, index=True)
    source_ref_id = db.Column(db.String(128), nullable=False, index=True)
    prior_active_generation = db.Column(db.Integer, nullable=True)
    new_active_generation = db.Column(db.Integer, nullable=True)
    actor = db.Column(db.String(255), nullable=False, default="system")
    reason = db.Column(db.Text, nullable=False, default="")
    transition = db.Column(db.String(80), nullable=False)
    occurred_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    case = db.relationship("Case", backref=db.backref("evidence_generation_audit", lazy="dynamic"))

    __table_args__ = (
        db.CheckConstraint(
            "prior_active_generation IS NULL OR prior_active_generation >= 1",
            name="ck_evidence_generation_audit_prior_positive",
        ),
        db.CheckConstraint(
            "new_active_generation IS NULL OR new_active_generation >= 1",
            name="ck_evidence_generation_audit_new_positive",
        ),
        db.Index("idx_evidence_generation_audit_source", "case_id", "source_ref_type", "source_ref_id", "occurred_at"),
    )


class IngestAttempt(db.Model):
    """Execution/audit identity for one attempt at a source generation."""

    __tablename__ = "ingest_attempts"

    id = db.Column(db.Integer, primary_key=True)
    ingest_attempt_id = db.Column(db.String(36), nullable=False, unique=True, index=True)
    generation_id = db.Column(
        db.Integer,
        db.ForeignKey("evidence_source_generations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    status = db.Column(db.String(40), nullable=False, default="STARTED", index=True)
    celery_task_id = db.Column(db.String(128), nullable=True, index=True)
    worker_name = db.Column(db.String(255), nullable=True)
    started_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    heartbeat_at = db.Column(db.DateTime, nullable=True)
    lease_expires_at = db.Column(db.DateTime, nullable=True, index=True)
    finished_at = db.Column(db.DateTime, nullable=True)
    error = db.Column(db.Text, nullable=True)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    generation = db.relationship("EvidenceSourceGeneration", backref=db.backref("ingest_attempts", lazy="dynamic"))


class IngestBatch(db.Model):
    """Per-batch manifest, not one row per event."""

    __tablename__ = "ingest_batches"

    id = db.Column(db.Integer, primary_key=True)
    ingest_batch_id = db.Column(db.String(96), nullable=False, unique=True, index=True)
    generation_id = db.Column(
        db.Integer,
        db.ForeignKey("evidence_source_generations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    batch_ordinal = db.Column(db.Integer, nullable=False)
    row_count = db.Column(db.Integer, nullable=False)
    batch_content_hash = db.Column(db.String(64), nullable=False)
    expected_ingest_row_hashes = db.Column(db.JSON, nullable=False, default=list)
    first_source_locator = db.Column(db.JSON, nullable=True)
    last_source_locator = db.Column(db.JSON, nullable=True)
    ingest_attempt_id = db.Column(db.String(36), db.ForeignKey("ingest_attempts.ingest_attempt_id"), nullable=True, index=True)
    state = db.Column(db.String(20), nullable=False, default=IngestBatchState.STAGED, index=True)
    state_version = db.Column(db.BigInteger, nullable=False, default=1)
    reconcile_owner = db.Column(db.String(64), nullable=True, index=True)
    reconcile_lease_expires_at = db.Column(db.DateTime, nullable=True, index=True)
    reconcile_attempt_count = db.Column(db.Integer, nullable=False, default=0)
    last_reconcile_at = db.Column(db.DateTime, nullable=True)
    last_reconcile_outcome = db.Column(db.String(80), nullable=True)
    last_reconcile_error = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    durable_at = db.Column(db.DateTime, nullable=True)

    generation = db.relationship("EvidenceSourceGeneration", backref=db.backref("ingest_batches", lazy="dynamic"))
    latest_attempt = db.relationship("IngestAttempt", foreign_keys=[ingest_attempt_id])

    __table_args__ = (
        db.UniqueConstraint("generation_id", "batch_ordinal", name="uq_ingest_batch_generation_ordinal"),
        db.CheckConstraint("batch_ordinal >= 0", name="ck_ingest_batch_ordinal_nonnegative"),
        db.CheckConstraint("row_count >= 0", name="ck_ingest_batch_row_count_nonnegative"),
        db.CheckConstraint("state_version >= 1", name="ck_ingest_batch_state_version_positive"),
        db.CheckConstraint("reconcile_attempt_count >= 0", name="ck_ingest_batch_reconcile_attempt_count_nonnegative"),
        db.CheckConstraint(
            "length(batch_content_hash) = 64 AND lower(batch_content_hash) = batch_content_hash",
            name="ck_ingest_batch_content_hash_lower_64",
        ),
        db.CheckConstraint("state IN ('STAGED', 'DURABLE')", name="ck_ingest_batch_state"),
        db.Index("idx_ingest_batch_generation_state", "generation_id", "state"),
        db.Index("idx_ingest_batch_staged_updated", "state", "updated_at", "id"),
        db.Index("idx_ingest_batch_reconcile_claim", "state", "reconcile_lease_expires_at", "id"),
    )


class IngestBatchReconciliationAudit(db.Model):
    """Append-only audit for stale STAGED batch reconciliation decisions."""

    __tablename__ = "ingest_batch_reconciliation_audit"

    id = db.Column(db.Integer, primary_key=True)
    ingest_batch_id = db.Column(db.String(96), nullable=False, index=True)
    generation_id = db.Column(
        db.Integer,
        db.ForeignKey("evidence_source_generations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    source_ref_type = db.Column(db.String(40), nullable=False, index=True)
    source_ref_id = db.Column(db.String(128), nullable=False, index=True)
    source_generation = db.Column(db.Integer, nullable=False)
    batch_ordinal = db.Column(db.Integer, nullable=False)
    prior_batch_state = db.Column(db.String(20), nullable=False)
    classification = db.Column(db.String(80), nullable=False, index=True)
    physical_row_count = db.Column(db.Integer, nullable=False, default=0)
    collapsed_row_count = db.Column(db.Integer, nullable=False, default=0)
    missing_ordinals = db.Column(db.JSON, nullable=False, default=list)
    extra_ordinals = db.Column(db.JSON, nullable=False, default=list)
    conflicting_ordinals = db.Column(db.JSON, nullable=False, default=list)
    hash_mismatch_ordinals = db.Column(db.JSON, nullable=False, default=list)
    expected_batch_content_hash = db.Column(db.String(64), nullable=True)
    actual_batch_content_hash = db.Column(db.String(64), nullable=True)
    action_taken = db.Column(db.String(80), nullable=False)
    recovery_attempt_id = db.Column(db.String(36), nullable=True, index=True)
    reason = db.Column(db.Text, nullable=True)
    reconcile_owner = db.Column(db.String(64), nullable=True)
    occurred_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    generation = db.relationship("EvidenceSourceGeneration", backref=db.backref("batch_reconciliation_audit", lazy="dynamic"))
    case = db.relationship("Case", backref=db.backref("ingest_batch_reconciliation_audit", lazy="dynamic"))

    __table_args__ = (
        db.CheckConstraint("physical_row_count >= 0", name="ck_ingest_batch_reconcile_physical_nonnegative"),
        db.CheckConstraint("collapsed_row_count >= 0", name="ck_ingest_batch_reconcile_collapsed_nonnegative"),
        db.CheckConstraint("source_generation >= 1", name="ck_ingest_batch_reconcile_generation_positive"),
        db.CheckConstraint("batch_ordinal >= 0", name="ck_ingest_batch_reconcile_batch_ordinal_nonnegative"),
        db.Index("idx_ingest_batch_reconcile_audit_source", "case_id", "source_ref_type", "source_ref_id", "source_generation"),
    )


class CaseCapabilitySourceState(db.Model):
    """Authoritative per-source contiguous capability watermark."""

    __tablename__ = "case_capability_source_state"

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    capability = db.Column(db.String(80), nullable=False, index=True)
    source_ref_type = db.Column(db.String(40), nullable=False, index=True)
    source_ref_id = db.Column(db.String(128), nullable=False, index=True)
    source_generation = db.Column(db.Integer, nullable=False)
    derivation_version = db.Column(db.String(128), nullable=False)
    contiguous_batch_ordinal = db.Column(db.Integer, nullable=True)
    highest_completed_batch_ordinal = db.Column(db.Integer, nullable=True)
    completed_batch_ordinals = db.Column(db.JSON, nullable=False, default=list)
    status = db.Column(
        db.String(40),
        nullable=False,
        default=CapabilityWatermarkStatus.NOT_STARTED,
        index=True,
    )
    state_version = db.Column(db.BigInteger, nullable=False, default=1)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    failure_reason = db.Column(db.Text, nullable=True)

    case = db.relationship("Case", backref=db.backref("case_capability_source_state", lazy="dynamic"))

    __table_args__ = (
        db.UniqueConstraint(
            "case_id",
            "capability",
            "source_ref_type",
            "source_ref_id",
            "source_generation",
            "derivation_version",
            name="uq_case_capability_source_state_identity",
        ),
        db.CheckConstraint("source_generation >= 1", name="ck_case_capability_source_generation_positive"),
        db.CheckConstraint(
            "contiguous_batch_ordinal IS NULL OR contiguous_batch_ordinal >= 0",
            name="ck_case_capability_contiguous_ordinal_nonnegative",
        ),
        db.CheckConstraint(
            "highest_completed_batch_ordinal IS NULL OR highest_completed_batch_ordinal >= 0",
            name="ck_case_capability_highest_ordinal_nonnegative",
        ),
        db.CheckConstraint("state_version >= 1", name="ck_case_capability_state_version_positive"),
        db.CheckConstraint(
            "status IN ('NOT_STARTED', 'IN_PROGRESS', 'CONTIGUOUS_READY', 'COMPLETE', 'FAILED', 'INVALIDATED')",
            name="ck_case_capability_status",
        ),
        db.Index("idx_case_capability_source_status", "case_id", "capability", "status"),
        db.Index("idx_case_capability_source_ref", "case_id", "source_ref_type", "source_ref_id", "source_generation"),
    )


class CaseCapabilityBatchCompletion(db.Model):
    """Normalized per-batch capability completion evidence.

    ``case_capability_source_state`` remains the authoritative current watermark
    row. This table is the durable completion set used to compute the hole-free
    contiguous prefix. The inherited ``completed_batch_ordinals`` JSON column is
    retained for additive compatibility and is not completion authority.
    """

    __tablename__ = "case_capability_batch_completions"

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    capability = db.Column(db.String(80), nullable=False, index=True)
    source_ref_type = db.Column(db.String(40), nullable=False, index=True)
    source_ref_id = db.Column(db.String(128), nullable=False, index=True)
    source_generation = db.Column(db.Integer, nullable=False)
    derivation_version = db.Column(db.String(128), nullable=False)
    ingest_batch_id = db.Column(db.String(96), nullable=False, index=True)
    batch_ordinal = db.Column(db.Integer, nullable=False)
    completed_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    case = db.relationship("Case", backref=db.backref("case_capability_batch_completions", lazy="dynamic"))

    __table_args__ = (
        db.UniqueConstraint(
            "case_id",
            "capability",
            "source_ref_type",
            "source_ref_id",
            "source_generation",
            "derivation_version",
            "ingest_batch_id",
            name="uq_capability_batch_completion_identity",
        ),
        db.UniqueConstraint(
            "case_id",
            "capability",
            "source_ref_type",
            "source_ref_id",
            "source_generation",
            "derivation_version",
            "batch_ordinal",
            name="uq_capability_batch_completion_ordinal",
        ),
        db.CheckConstraint("source_generation >= 1", name="ck_capability_batch_completion_generation_positive"),
        db.CheckConstraint("batch_ordinal >= 0", name="ck_capability_batch_completion_ordinal_nonnegative"),
        db.Index(
            "idx_capability_batch_completion_prefix",
            "case_id",
            "capability",
            "source_ref_type",
            "source_ref_id",
            "source_generation",
            "derivation_version",
            "batch_ordinal",
        ),
    )


class CaseIngestComposition:
    LEGACY_ONLY = "legacy_only"
    MANAGED_ONLY = "managed_only"
    MIXED = "mixed"

    @classmethod
    def all(cls):
        return [cls.LEGACY_ONLY, cls.MANAGED_ONLY, cls.MIXED]


class ReconciliationAssessment:
    RECONCILED = "reconciled"
    WORK_QUEUED = "work_queued"
    IN_PROGRESS = "in_progress"
    INCOMPLETE_INGEST = "incomplete_ingest"
    BLOCKED = "blocked"
    DEFERRED = "deferred"
    FAILED = "failed"

    @classmethod
    def all(cls):
        return [
            cls.RECONCILED,
            cls.WORK_QUEUED,
            cls.IN_PROGRESS,
            cls.INCOMPLETE_INGEST,
            cls.BLOCKED,
            cls.DEFERRED,
            cls.FAILED,
        ]


class CaseCompletionReconciliationAudit(db.Model):
    """Append-only durable audit for one case completion-reconciliation run.

    This is a snapshot/read-model audit, not a scalar readiness authority.
    """

    __tablename__ = "case_completion_reconciliation_audit"

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    case_uuid = db.Column(db.String(36), nullable=True, index=True)
    trigger_reason = db.Column(db.String(80), nullable=False, default="durable_authority")
    composition = db.Column(db.String(32), nullable=False)
    assessment = db.Column(db.String(40), nullable=False, index=True)
    generations_inspected = db.Column(db.JSON, nullable=False, default=list)
    batch_counts = db.Column(db.JSON, nullable=False, default=dict)
    d2_gaps = db.Column(db.JSON, nullable=False, default=list)
    capability_gaps = db.Column(db.JSON, nullable=False, default=list)
    derivations_checked = db.Column(db.JSON, nullable=False, default=list)
    work_queued = db.Column(db.JSON, nullable=False, default=list)
    unresolved_conflicts = db.Column(db.JSON, nullable=False, default=list)
    deferred = db.Column(db.JSON, nullable=False, default=list)
    errors = db.Column(db.JSON, nullable=False, default=list)
    metrics = db.Column(db.JSON, nullable=False, default=dict)
    authority_changed = db.Column(db.Boolean, nullable=False, default=False)
    duration_ms = db.Column(db.Float, nullable=False, default=0.0)
    occurred_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    case = db.relationship("Case", backref=db.backref("completion_reconciliation_audit", lazy="dynamic"))

    __table_args__ = (
        db.CheckConstraint(
            "composition IN ('legacy_only', 'managed_only', 'mixed')",
            name="ck_case_completion_reconcile_composition",
        ),
        db.CheckConstraint(
            "assessment IN ('reconciled', 'work_queued', 'in_progress', "
            "'incomplete_ingest', 'blocked', 'deferred', 'failed')",
            name="ck_case_completion_reconcile_assessment",
        ),
        db.Index("idx_case_completion_reconcile_case_occurred", "case_id", "occurred_at"),
    )
