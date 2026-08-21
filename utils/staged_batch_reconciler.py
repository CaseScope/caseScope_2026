"""Phase 1B Tranche D2 stale STAGED ingest-batch reconciler."""
from __future__ import annotations

import socket
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, Optional, Sequence, Tuple

from sqlalchemy.orm import joinedload

from models.database_flow import (
    EvidenceGenerationState,
    EvidenceSourceGeneration,
    IngestBatch,
    IngestBatchReconciliationAudit,
    IngestBatchState,
)
from utils.ingest_identity import batch_content_hash_for_ordinals, validate_sha256_hex
from utils.manifest_protocol import (
    BatchVerificationResult,
    create_ingest_attempt,
    mark_batch_durable,
    project_generation_control_state,
    purge_ingest_batch_rows,
    update_generation_ingest_accounting,
)


ATTEMPT_TERMINAL_STATUSES = {"SUCCEEDED", "FAILED", "CANCELLED", "REVOKED"}
RECOVERABLE_GENERATION_STATES = {
    EvidenceGenerationState.BUILDING_INITIAL,
    EvidenceGenerationState.BUILDING_REPLACEMENT,
}
FAIL_CLOSED_RECONCILE_OUTCOMES = {
    "malformed_manifest",
    "duplicate_different",
    "hash_mismatch",
    "extra_ordinal",
    "aggregate_mismatch",
    "active_generation_invariant_violation",
    "generation_not_recoverable",
    "manifest_changed",
}
DEFAULT_RECONCILE_LEASE_SECONDS = 900
DEFAULT_MAX_AUTO_RECOVERY_ATTEMPTS = 3


@dataclass(frozen=True)
class ClickHouseBatchGroup:
    ingest_row_ordinal: int
    ingest_row_hash: str
    physical_copies: int


@dataclass(frozen=True)
class ClickHouseBatchObservation:
    ingest_batch_id: str
    groups: Tuple[ClickHouseBatchGroup, ...]
    physical_row_count: int
    inspected_at: datetime
    latency_ms: float

    @property
    def by_ordinal(self) -> Dict[int, Dict[str, int]]:
        grouped: Dict[int, Dict[str, int]] = {}
        for group in self.groups:
            grouped.setdefault(group.ingest_row_ordinal, {})[group.ingest_row_hash] = group.physical_copies
        return grouped


@dataclass(frozen=True)
class BatchClassification:
    classification: str
    success: bool
    physical_row_count: int
    collapsed_row_count: int
    duplicate_physical_rows: int = 0
    missing_ordinals: Tuple[int, ...] = ()
    extra_ordinals: Tuple[int, ...] = ()
    conflicting_ordinals: Tuple[int, ...] = ()
    hash_mismatch_ordinals: Tuple[int, ...] = ()
    actual_batch_content_hash: Optional[str] = None
    reason: str = ""


@dataclass(frozen=True)
class StaleEligibility:
    stale: bool
    reason: str


@dataclass(frozen=True)
class ReconcileResult:
    ingest_batch_id: str
    action_taken: str
    classification: Optional[str] = None
    stale: bool = False
    recovery_attempt_id: Optional[str] = None
    physical_row_count: int = 0
    collapsed_row_count: int = 0
    reason: str = ""
    audit_id: Optional[int] = None
    retry_task_id: Optional[str] = None
    timings_ms: Dict[str, float] = field(default_factory=dict)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _owner_token(owner: Optional[str] = None) -> str:
    if owner:
        return str(owner)[:64]
    return f"{socket.gethostname()}:{uuid.uuid4().hex}"[:64]


def _normalize_hashes(values: Sequence[str]) -> Tuple[str, ...]:
    return tuple(validate_sha256_hex(str(value)) for value in values)


def inspect_batch(clickhouse_client, ingest_batch_id: str) -> ClickHouseBatchObservation:
    """Observe physical ClickHouse rows for exactly one deterministic batch ID."""
    started = time.perf_counter()
    result = clickhouse_client.query(
        """
        SELECT
            ingest_row_ordinal,
            ingest_row_hash,
            count() AS physical_copies
        FROM events
        WHERE ingest_batch_id = {id:String}
        GROUP BY ingest_row_ordinal, ingest_row_hash
        """,
        parameters={"id": ingest_batch_id},
    )
    groups = tuple(
        ClickHouseBatchGroup(
            ingest_row_ordinal=int(row[0]),
            ingest_row_hash=str(row[1]),
            physical_copies=int(row[2]),
        )
        for row in result.result_rows
    )
    return ClickHouseBatchObservation(
        ingest_batch_id=ingest_batch_id,
        groups=groups,
        physical_row_count=sum(group.physical_copies for group in groups),
        inspected_at=_utcnow(),
        latency_ms=(time.perf_counter() - started) * 1000.0,
    )


def classify_batch(batch: IngestBatch, observation: ClickHouseBatchObservation) -> BatchClassification:
    """Classify observed ClickHouse state using the frozen PostgreSQL manifest."""
    physical_count = int(observation.physical_row_count)
    by_ordinal = observation.by_ordinal
    collapsed_count = len(by_ordinal)
    duplicate_rows = sum(max(group.physical_copies - 1, 0) for group in observation.groups)

    try:
        expected_count = int(batch.row_count)
        if expected_count <= 0:
            raise ValueError("D1 does not create empty ingest batches")
        expected_hashes = _normalize_hashes(batch.expected_ingest_row_hashes or [])
        if len(expected_hashes) != expected_count:
            raise ValueError("expected hash manifest length does not match row_count")
    except ValueError as exc:
        return BatchClassification(
            "malformed_manifest",
            False,
            physical_count,
            collapsed_count,
            duplicate_physical_rows=duplicate_rows,
            reason=str(exc),
        )

    expected_ordinals = set(range(expected_count))
    observed_ordinals = set(by_ordinal)
    missing_ordinals = tuple(sorted(expected_ordinals - observed_ordinals))
    extra_ordinals = tuple(sorted(observed_ordinals - expected_ordinals))

    conflicting_ordinals = tuple(
        sorted(ordinal for ordinal, hashes in by_ordinal.items() if ordinal in expected_ordinals and len(hashes) > 1)
    )
    if conflicting_ordinals:
        return BatchClassification(
            "duplicate_different",
            False,
            physical_count,
            collapsed_count,
            duplicate_physical_rows=duplicate_rows,
            missing_ordinals=missing_ordinals,
            extra_ordinals=extra_ordinals,
            conflicting_ordinals=conflicting_ordinals,
            reason=f"conflicting hashes for ordinals {list(conflicting_ordinals)}",
        )

    hash_mismatch_ordinals = []
    for ordinal in sorted(expected_ordinals & observed_ordinals):
        only_hash = next(iter(by_ordinal[ordinal]))
        if only_hash != expected_hashes[ordinal]:
            hash_mismatch_ordinals.append(ordinal)
    if hash_mismatch_ordinals:
        return BatchClassification(
            "hash_mismatch",
            False,
            physical_count,
            collapsed_count,
            duplicate_physical_rows=duplicate_rows,
            missing_ordinals=missing_ordinals,
            extra_ordinals=extra_ordinals,
            hash_mismatch_ordinals=tuple(hash_mismatch_ordinals),
            reason=f"hash mismatch for ordinals {hash_mismatch_ordinals}",
        )

    if extra_ordinals:
        return BatchClassification(
            "extra_ordinal",
            False,
            physical_count,
            collapsed_count,
            duplicate_physical_rows=duplicate_rows,
            missing_ordinals=missing_ordinals,
            extra_ordinals=extra_ordinals,
            reason=f"extra ordinals {list(extra_ordinals)}",
        )

    if physical_count == 0:
        return BatchClassification("absent", False, physical_count, collapsed_count, reason="no ClickHouse rows")

    if len(expected_hashes) == expected_count:
        actual_hash = batch_content_hash_for_ordinals(tuple(enumerate(expected_hashes)))
        if actual_hash != batch.batch_content_hash:
            return BatchClassification(
                "aggregate_mismatch",
                False,
                physical_count,
                collapsed_count,
                duplicate_physical_rows=duplicate_rows,
                actual_batch_content_hash=actual_hash,
                reason="frozen aggregate hash does not match framed expected row hashes",
            )

    if missing_ordinals:
        return BatchClassification(
            "partial",
            False,
            physical_count,
            collapsed_count,
            duplicate_physical_rows=duplicate_rows,
            missing_ordinals=missing_ordinals,
            reason=f"missing ordinals {list(missing_ordinals)}",
        )

    if duplicate_rows:
        return BatchClassification(
            "duplicate_identical",
            True,
            physical_count,
            collapsed_count,
            duplicate_physical_rows=duplicate_rows,
            actual_batch_content_hash=batch.batch_content_hash,
            reason="retry-equivalent duplicate physical rows accepted by collapsed proof",
        )

    return BatchClassification(
        "exact",
        True,
        physical_count,
        collapsed_count,
        actual_batch_content_hash=batch.batch_content_hash,
        reason="ClickHouse rows exactly match manifest",
    )


def staged_batch_stale_eligibility(batch: IngestBatch, *, now: Optional[datetime] = None) -> StaleEligibility:
    """Return whether PostgreSQL proves the current producer is no longer entitled to write."""
    now = now or _utcnow()
    if batch.state != IngestBatchState.STAGED:
        return StaleEligibility(False, "batch is not STAGED")
    if batch.last_reconcile_outcome in FAIL_CLOSED_RECONCILE_OUTCOMES:
        return StaleEligibility(False, f"prior fail-closed outcome requires explicit recovery: {batch.last_reconcile_outcome}")
    attempt = batch.latest_attempt
    if attempt is None:
        return StaleEligibility(True, "STAGED batch has no producing attempt")
    status = str(attempt.status or "").upper()
    if status in ATTEMPT_TERMINAL_STATUSES:
        return StaleEligibility(True, f"producing attempt is terminal: {status}")
    if status == "STARTED" and attempt.lease_expires_at is not None and attempt.lease_expires_at <= now:
        return StaleEligibility(True, "producing attempt lease expired")
    return StaleEligibility(False, "producing attempt is still live or cannot be proven stale")


def discover_stale_staged_batch_ids(
    *,
    session,
    limit: int = 100,
    now: Optional[datetime] = None,
) -> Tuple[str, ...]:
    """Return a bounded, stable list of currently stale STAGED batch IDs."""
    now = now or _utcnow()
    candidates = (
        session.query(IngestBatch)
        .options(joinedload(IngestBatch.latest_attempt))
        .filter(IngestBatch.state == IngestBatchState.STAGED)
        .order_by(IngestBatch.updated_at.asc(), IngestBatch.id.asc())
        .limit(max(int(limit), 1) * 3)
        .with_for_update(of=IngestBatch, skip_locked=True)
        .all()
    )
    stale = []
    for batch in candidates:
        if staged_batch_stale_eligibility(batch, now=now).stale:
            stale.append(batch.ingest_batch_id)
        if len(stale) >= max(int(limit), 1):
            break
    return tuple(stale)


def _claim_batch(session, ingest_batch_id: str, *, owner: str, now: datetime, lease_seconds: int):
    batch = (
        session.query(IngestBatch)
        .options(joinedload(IngestBatch.latest_attempt), joinedload(IngestBatch.generation))
        .filter(IngestBatch.ingest_batch_id == ingest_batch_id)
        .with_for_update(of=IngestBatch)
        .one_or_none()
    )
    if batch is None:
        return None, StaleEligibility(False, "batch not found")
    if batch.reconcile_owner and batch.reconcile_lease_expires_at and batch.reconcile_lease_expires_at > now:
        return batch, StaleEligibility(False, "batch is already claimed by another reconciler")
    eligibility = staged_batch_stale_eligibility(batch, now=now)
    if not eligibility.stale:
        return batch, eligibility
    batch.reconcile_owner = owner
    batch.reconcile_lease_expires_at = now + timedelta(seconds=max(int(lease_seconds), 1))
    batch.last_reconcile_at = now
    batch.last_reconcile_outcome = "claimed"
    batch.last_reconcile_error = None
    session.flush()
    return batch, eligibility


def _manifest_snapshot(batch: IngestBatch) -> Tuple:
    return (
        batch.generation_id,
        batch.batch_ordinal,
        batch.row_count,
        batch.batch_content_hash,
        tuple(batch.expected_ingest_row_hashes or []),
        batch.first_source_locator or None,
        batch.last_source_locator or None,
    )


def _claim_still_valid(session, ingest_batch_id: str, *, owner: str, snapshot: Tuple, now: datetime):
    batch = (
        session.query(IngestBatch)
        .options(joinedload(IngestBatch.generation))
        .filter(IngestBatch.ingest_batch_id == ingest_batch_id)
        .with_for_update(of=IngestBatch)
        .one_or_none()
    )
    if batch is None:
        return None, "batch disappeared"
    if batch.reconcile_owner != owner:
        return batch, "reconcile claim lost"
    if batch.reconcile_lease_expires_at is None or batch.reconcile_lease_expires_at <= now:
        return batch, "reconcile claim expired"
    if batch.state != IngestBatchState.STAGED:
        return batch, f"batch state changed to {batch.state}"
    if _manifest_snapshot(batch) != snapshot:
        return batch, "manifest changed during reconciliation"
    return batch, None


def _clear_claim(batch: IngestBatch) -> None:
    batch.reconcile_owner = None
    batch.reconcile_lease_expires_at = None


def _audit(
    session,
    *,
    batch: IngestBatch,
    classification: BatchClassification,
    action_taken: str,
    recovery_attempt_id: Optional[str],
    owner: str,
    reason: str,
) -> IngestBatchReconciliationAudit:
    generation = batch.generation
    audit = IngestBatchReconciliationAudit(
        ingest_batch_id=batch.ingest_batch_id,
        generation_id=batch.generation_id,
        case_id=generation.case_id,
        source_ref_type=generation.source_ref_type,
        source_ref_id=generation.source_ref_id,
        source_generation=generation.source_generation,
        batch_ordinal=batch.batch_ordinal,
        prior_batch_state=batch.state,
        classification=classification.classification,
        physical_row_count=classification.physical_row_count,
        collapsed_row_count=classification.collapsed_row_count,
        missing_ordinals=list(classification.missing_ordinals),
        extra_ordinals=list(classification.extra_ordinals),
        conflicting_ordinals=list(classification.conflicting_ordinals),
        hash_mismatch_ordinals=list(classification.hash_mismatch_ordinals),
        expected_batch_content_hash=batch.batch_content_hash,
        actual_batch_content_hash=classification.actual_batch_content_hash,
        action_taken=action_taken,
        recovery_attempt_id=recovery_attempt_id,
        reason=reason,
        reconcile_owner=owner,
        occurred_at=_utcnow(),
    )
    session.add(audit)
    session.flush()
    return audit


def _count_batch_rows(clickhouse_client, ingest_batch_id: str) -> int:
    result = clickhouse_client.query(
        """
        SELECT count()
        FROM events
        WHERE ingest_batch_id = {id:String}
        """,
        parameters={"id": ingest_batch_id},
    )
    return int(result.result_rows[0][0]) if result.result_rows else 0


def _classification_as_verification(classification: BatchClassification) -> BatchVerificationResult:
    return BatchVerificationResult(
        classification.classification,
        classification.success,
        retry_equivalent_duplicate=(classification.classification == "duplicate_identical"),
        physical_rows=classification.physical_row_count,
        duplicate_physical_rows=classification.duplicate_physical_rows,
        message=classification.reason,
    )


def _fail_closed_result(
    session,
    *,
    batch: IngestBatch,
    classification: BatchClassification,
    owner: str,
    reason: str,
) -> ReconcileResult:
    batch.last_reconcile_at = _utcnow()
    batch.last_reconcile_outcome = classification.classification
    batch.last_reconcile_error = reason
    _clear_claim(batch)
    audit = _audit(
        session,
        batch=batch,
        classification=classification,
        action_taken="fail_closed",
        recovery_attempt_id=None,
        owner=owner,
        reason=reason,
    )
    session.commit()
    return ReconcileResult(
        ingest_batch_id=batch.ingest_batch_id,
        action_taken="fail_closed",
        classification=classification.classification,
        stale=True,
        physical_row_count=classification.physical_row_count,
        collapsed_row_count=classification.collapsed_row_count,
        reason=reason,
        audit_id=audit.id,
    )


def reconcile_staged_batch(
    *,
    session,
    clickhouse_client,
    ingest_batch_id: str,
    owner: Optional[str] = None,
    now: Optional[datetime] = None,
    reconcile_lease_seconds: int = DEFAULT_RECONCILE_LEASE_SECONDS,
    max_auto_recovery_attempts: int = DEFAULT_MAX_AUTO_RECOVERY_ATTEMPTS,
    retry_scheduler: Optional[Callable[[str, str], Optional[str]]] = None,
) -> ReconcileResult:
    """Reconcile one stale STAGED batch without trusting task status as evidence."""
    owner = _owner_token(owner)
    now = now or _utcnow()
    timings: Dict[str, float] = {}

    claim_started = time.perf_counter()
    batch, eligibility = _claim_batch(
        session,
        ingest_batch_id,
        owner=owner,
        now=now,
        lease_seconds=reconcile_lease_seconds,
    )
    if batch is None:
        session.rollback()
        return ReconcileResult(ingest_batch_id=ingest_batch_id, action_taken="skipped", reason=eligibility.reason)
    if not eligibility.stale:
        session.rollback()
        return ReconcileResult(
            ingest_batch_id=ingest_batch_id,
            action_taken="skipped_not_stale",
            stale=False,
            reason=eligibility.reason,
        )
    snapshot = _manifest_snapshot(batch)
    session.commit()
    timings["pg_claim_ms"] = (time.perf_counter() - claim_started) * 1000.0

    observation = inspect_batch(clickhouse_client, ingest_batch_id)
    timings["ch_inspection_ms"] = observation.latency_ms
    classification = classify_batch(batch, observation)

    validate_started = time.perf_counter()
    batch, invalid_reason = _claim_still_valid(session, ingest_batch_id, owner=owner, snapshot=snapshot, now=_utcnow())
    if invalid_reason:
        if batch is not None:
            replacement = BatchClassification(
                "manifest_changed" if invalid_reason == "manifest changed during reconciliation" else classification.classification,
                False,
                classification.physical_row_count,
                classification.collapsed_row_count,
                reason=invalid_reason,
            )
            return _fail_closed_result(session, batch=batch, classification=replacement, owner=owner, reason=invalid_reason)
        session.rollback()
        return ReconcileResult(ingest_batch_id=ingest_batch_id, action_taken="skipped", reason=invalid_reason)
    timings["pg_revalidate_ms"] = (time.perf_counter() - validate_started) * 1000.0

    generation: EvidenceSourceGeneration = batch.generation
    if generation.visibility_state == EvidenceGenerationState.ACTIVE:
        replacement = BatchClassification(
            "active_generation_invariant_violation",
            False,
            classification.physical_row_count,
            classification.collapsed_row_count,
            reason="ACTIVE generation contains a STAGED batch",
        )
        return _fail_closed_result(session, batch=batch, classification=replacement, owner=owner, reason=replacement.reason)
    if generation.visibility_state not in RECOVERABLE_GENERATION_STATES:
        replacement = BatchClassification(
            "generation_not_recoverable",
            False,
            classification.physical_row_count,
            classification.collapsed_row_count,
            reason=f"generation state {generation.visibility_state} cannot auto-recover or publish",
        )
        return _fail_closed_result(session, batch=batch, classification=replacement, owner=owner, reason=replacement.reason)

    if classification.classification in {"exact", "duplicate_identical"}:
        transition_started = time.perf_counter()
        mark_batch_durable(session=session, batch=batch, verification=_classification_as_verification(classification))
        update_generation_ingest_accounting(session=session, generation=generation)
        batch.last_reconcile_at = _utcnow()
        batch.last_reconcile_outcome = classification.classification
        batch.last_reconcile_error = None
        _clear_claim(batch)
        audit = _audit(
            session,
            batch=batch,
            classification=classification,
            action_taken="mark_durable",
            recovery_attempt_id=None,
            owner=owner,
            reason=classification.reason,
        )
        session.commit()
        timings["pg_transition_ms"] = (time.perf_counter() - transition_started) * 1000.0
        project_generation_control_state(clickhouse_client, session, generation)
        return ReconcileResult(
            ingest_batch_id=ingest_batch_id,
            action_taken="mark_durable",
            classification=classification.classification,
            stale=True,
            physical_row_count=classification.physical_row_count,
            collapsed_row_count=classification.collapsed_row_count,
            reason=classification.reason,
            audit_id=audit.id,
            timings_ms=timings,
        )

    if classification.classification == "partial":
        session.commit()
        purge_started = time.perf_counter()
        purge_ingest_batch_rows(clickhouse_client, ingest_batch_id)
        remaining = _count_batch_rows(clickhouse_client, ingest_batch_id)
        timings["ch_targeted_purge_ms"] = (time.perf_counter() - purge_started) * 1000.0
        if remaining != 0:
            batch, _invalid_reason = _claim_still_valid(session, ingest_batch_id, owner=owner, snapshot=snapshot, now=_utcnow())
            if batch is None:
                session.rollback()
                return ReconcileResult(ingest_batch_id=ingest_batch_id, action_taken="skipped", reason="batch disappeared")
            replacement = BatchClassification(
                "partial",
                False,
                remaining,
                0,
                missing_ordinals=classification.missing_ordinals,
                reason="targeted purge did not prove zero rows",
            )
            return _fail_closed_result(session, batch=batch, classification=replacement, owner=owner, reason=replacement.reason)
        batch, invalid_reason = _claim_still_valid(session, ingest_batch_id, owner=owner, snapshot=snapshot, now=_utcnow())
        if invalid_reason:
            session.rollback()
            return ReconcileResult(ingest_batch_id=ingest_batch_id, action_taken="skipped", reason=invalid_reason)

    if classification.classification in {"absent", "partial"}:
        if int(batch.reconcile_attempt_count or 0) >= int(max_auto_recovery_attempts):
            return _fail_closed_result(
                session,
                batch=batch,
                classification=classification,
                owner=owner,
                reason="maximum automatic recovery attempts reached",
            )
        transition_started = time.perf_counter()
        attempt = create_ingest_attempt(session=session, generation=generation)
        batch.state = IngestBatchState.STAGED
        batch.ingest_attempt_id = attempt.ingest_attempt_id
        batch.reconcile_attempt_count = int(batch.reconcile_attempt_count or 0) + 1
        batch.state_version = int(batch.state_version or 0) + 1
        batch.last_reconcile_at = _utcnow()
        batch.last_reconcile_outcome = classification.classification
        batch.last_reconcile_error = None
        _clear_claim(batch)
        action = "retry_same_batch" if classification.classification == "absent" else "purged_and_retry_same_batch"
        audit = _audit(
            session,
            batch=batch,
            classification=classification,
            action_taken=action,
            recovery_attempt_id=attempt.ingest_attempt_id,
            owner=owner,
            reason=classification.reason,
        )
        session.commit()
        timings["pg_transition_ms"] = (time.perf_counter() - transition_started) * 1000.0
        retry_task_id = retry_scheduler(ingest_batch_id, attempt.ingest_attempt_id) if retry_scheduler else None
        return ReconcileResult(
            ingest_batch_id=ingest_batch_id,
            action_taken=action,
            classification=classification.classification,
            stale=True,
            recovery_attempt_id=attempt.ingest_attempt_id,
            physical_row_count=classification.physical_row_count,
            collapsed_row_count=classification.collapsed_row_count,
            reason=classification.reason,
            audit_id=audit.id,
            retry_task_id=retry_task_id,
            timings_ms=timings,
        )

    return _fail_closed_result(
        session,
        batch=batch,
        classification=classification,
        owner=owner,
        reason=classification.reason or "classification is not automatically recoverable",
    )
