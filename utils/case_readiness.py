"""Phase 1B Tranche F2 PostgreSQL-authoritative case readiness read model.

This module is a presentation DTO. It is not new durable authority, not a
case-wide ready latch, and not an AI-egress authorization gate. Durable
dimensions are derived from existing F1 PostgreSQL snapshot/readiness
machinery. Redis may decorate live activity only.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Optional

from models.database_flow import (
    CapabilityName,
    CapabilityWatermarkStatus,
    CaseCompletionReconciliationAudit,
    CaseIngestComposition,
    EvidenceGenerationState,
    IngestBatchState,
    ReconciliationAssessment,
)
from utils.capability_watermarks import PRIVACY_ALIASES_V1
from utils.completion_reconciler import (
    CompletionCompositionUnknown,
    _generation_state_fingerprint,
    _zero_event_generation,
    build_case_reconciliation_readiness,
    snapshot_case_completion_authority,
)


logger = logging.getLogger(__name__)

READINESS_CLICKHOUSE_CALLS = 0
PRIVACY_INFORMATIONAL_ONLY = True
AUTHORIZES_AI_EGRESS = False

EXPANDING_HUNT_NOTE = (
    "Results cover currently published evidence. Ingest is still adding evidence."
)
FINALIZING_HUNT_NOTE = (
    "Results cover currently published evidence. Ingest is finalizing and is not yet fully published."
)
REPLACEMENT_HUNT_NOTE = "Replacement processing in background."
MIXED_HUNT_NOTE = (
    "Results include published managed evidence and untracked legacy evidence."
)
UNAVAILABLE_HUNT_NOTE = (
    "Evidence status is unavailable. Search remains enabled for currently published results."
)
LEGACY_HUNT_NOTE = (
    "This case has untracked legacy evidence. Search remains enabled."
)
PENDING_RECONCILIATION = "pending_reconciliation"
PROVEN_INSPECT_ASSESSMENTS = frozenset({
    ReconciliationAssessment.FAILED,
    ReconciliationAssessment.BLOCKED,
    ReconciliationAssessment.INCOMPLETE_INGEST,
    ReconciliationAssessment.IN_PROGRESS,
    ReconciliationAssessment.WORK_QUEUED,
})
LIVE_PRIVACY_GENERATION_STATES = frozenset({
    EvidenceGenerationState.ACTIVE,
    EvidenceGenerationState.BUILDING_INITIAL,
    EvidenceGenerationState.BUILDING_REPLACEMENT,
})

_PROCESSING_STATUSES = frozenset({
    "processing",
    "waiting_for_completion",
    "flushing_buffer",
    "deduplicating",
    "discovering_systems",
    "discovering_users",
    "completion_reconciliation",
})


def _fingerprint_as_lists(value: Any) -> list[list[Any]]:
    rows = list(value or [])
    normalized = []
    for item in rows:
        normalized.append(list(item) if not isinstance(item, list) else list(item))
    return normalized


def _current_batch_counts(snapshot: dict[str, Any]) -> dict[str, int]:
    return {
        "staged": sum(
            1 for batch in snapshot["batches"] if batch.state == IngestBatchState.STAGED
        ),
        "durable": sum(
            1 for batch in snapshot["batches"] if batch.state == IngestBatchState.DURABLE
        ),
        "generations": len(snapshot["generations"]),
    }


def _audit_matches_current_authority(
    audit: Optional[CaseCompletionReconciliationAudit],
    snapshot: dict[str, Any],
) -> bool:
    """A prior reconciled audit is not a latch once generation/batch authority moves."""
    if audit is None:
        return False
    stored_fp = _fingerprint_as_lists((audit.metrics or {}).get("generation_fingerprint"))
    current_fp = _fingerprint_as_lists(_generation_state_fingerprint(snapshot))
    if stored_fp != current_fp:
        return False
    stored_counts = dict(audit.batch_counts or {})
    current_counts = _current_batch_counts(snapshot)
    try:
        return (
            int(stored_counts.get("staged") or 0) == current_counts["staged"]
            and int(stored_counts.get("durable") or 0) == current_counts["durable"]
            and int(stored_counts.get("generations") or 0) == current_counts["generations"]
        )
    except (TypeError, ValueError):
        return False


def _load_latest_reconciliation_audit(session, case_id: int):
    return (
        session.query(CaseCompletionReconciliationAudit)
        .filter_by(case_id=int(case_id))
        .order_by(
            CaseCompletionReconciliationAudit.occurred_at.desc(),
            CaseCompletionReconciliationAudit.id.desc(),
        )
        .limit(1)
        .one_or_none()
    )


def _source_has_current_lifecycle(sources: list[dict[str, Any]], source_key: tuple[str, str]) -> bool:
    for source in sources:
        if (source["source_ref_type"], source["source_ref_id"]) != source_key:
            continue
        if source["visibility_state"] in {
            EvidenceGenerationState.ACTIVE,
            EvidenceGenerationState.BUILDING_INITIAL,
        }:
            return True
    return False


def inspect_reconciliation_from_snapshot(snapshot: dict[str, Any], sources: list[dict[str, Any]]) -> str:
    """Inspect-only F1-consistent assessment. Does not execute reconciliation.

    Inspect-only state must never certify ``RECONCILED``. Only a current F1
    audit whose fingerprint and batch counts still match PostgreSQL authority
    may present Current / Reconciled.
    """
    composition = snapshot["composition"]
    if composition == CaseIngestComposition.LEGACY_ONLY:
        return "legacy"

    failed_without_current = False
    for generation in snapshot["generations"]:
        key = (generation.source_ref_type, str(generation.source_ref_id))
        if generation.visibility_state == EvidenceGenerationState.FAILED:
            if not _source_has_current_lifecycle(sources, key):
                failed_without_current = True
        if generation.visibility_state == EvidenceGenerationState.ACTIVE:
            batches = snapshot["batches_by_generation"].get(int(generation.id), [])
            if any(batch.state == IngestBatchState.STAGED for batch in batches):
                return ReconciliationAssessment.BLOCKED

    if failed_without_current:
        return ReconciliationAssessment.FAILED

    for source in sources:
        if source["visibility_state"] == EvidenceGenerationState.BUILDING_INITIAL:
            if not source["eof_declared"] and not source["zero_event"]:
                return ReconciliationAssessment.INCOMPLETE_INGEST
        if source["visibility_state"] in {
            EvidenceGenerationState.BUILDING_INITIAL,
            EvidenceGenerationState.BUILDING_REPLACEMENT,
        } and source["batch_counts"]["staged"]:
            return ReconciliationAssessment.IN_PROGRESS

    default_ids = snapshot.get("default_ids") or set()
    for generation in snapshot["generations"]:
        if int(generation.id) not in default_ids:
            continue
        if generation.visibility_state in {
            EvidenceGenerationState.SUPERSEDED,
            EvidenceGenerationState.FAILED,
            EvidenceGenerationState.INVALIDATED,
        }:
            continue
        batches = snapshot["batches_by_generation"].get(int(generation.id), [])
        if _zero_event_generation(generation, batches):
            continue
        for batch in batches:
            if batch.state != IngestBatchState.DURABLE:
                continue
            if str(batch.ingest_batch_id) not in snapshot["privacy_completed_batch_ids"]:
                return ReconciliationAssessment.WORK_QUEUED
    return PENDING_RECONCILIATION


def _dimension(code: str, label: str, detail: str, **extra: Any) -> dict[str, Any]:
    payload = {
        "code": code,
        "label": label,
        "detail": detail,
    }
    payload.update(extra)
    return payload


def _generation_for_source(snapshot: dict[str, Any], source: dict[str, Any]):
    for generation in snapshot.get("generations") or []:
        if (
            generation.source_ref_type == source["source_ref_type"]
            and str(generation.source_ref_id) == str(source["source_ref_id"])
            and int(generation.source_generation) == int(source["source_generation"])
        ):
            return generation
    return None


def _activation_gaps_from_snapshot(snapshot: dict[str, Any], source: dict[str, Any]) -> list[str]:
    """Inspect already-loaded PG rows for activation incompleteness.

    EOF declaration is not activation completeness. This does not take row
    locks and does not call the activation writer.
    """
    generation = _generation_for_source(snapshot, source)
    if generation is None:
        return ["current generation is missing from PostgreSQL authority"]
    batches = snapshot.get("batches_by_generation", {}).get(int(generation.id), [])
    errors: list[str] = []
    if generation.expected_rows is None:
        errors.append("missing expected row count")
        return errors
    expected_rows = int(generation.expected_rows)
    final_batch_ordinal = generation.final_batch_ordinal
    if expected_rows == 0:
        if final_batch_ordinal is not None:
            errors.append("zero-event generation must not have a final batch ordinal")
        if batches:
            errors.append("zero-event generation must not have ingest batches")
        return errors
    if final_batch_ordinal is None:
        errors.append("missing final batch ordinal")
        return errors
    expected_ordinals = set(range(int(final_batch_ordinal) + 1))
    observed_ordinals = {int(batch.batch_ordinal) for batch in batches}
    missing = sorted(expected_ordinals - observed_ordinals)
    extra = sorted(observed_ordinals - expected_ordinals)
    if missing:
        errors.append(f"missing expected batch ordinals {missing}")
    if extra:
        errors.append(f"unexpected batch ordinals {extra}")
    required_batches = [batch for batch in batches if int(batch.batch_ordinal) in expected_ordinals]
    staged = [int(batch.batch_ordinal) for batch in required_batches if batch.state != IngestBatchState.DURABLE]
    if staged:
        errors.append(f"non-durable required batch ordinals {staged}")
    row_sum = sum(int(batch.row_count or 0) for batch in required_batches if batch.state == IngestBatchState.DURABLE)
    if row_sum != expected_rows:
        errors.append(f"durable row count {row_sum} does not match expected {expected_rows}")
    return errors


def _build_evidence_dimension(
    *,
    composition: str,
    sources: list[dict[str, Any]],
    snapshot: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    current = [source for source in sources if source.get("is_default_authority")]
    replacements = [
        source for source in sources
        if source.get("visibility_state") == EvidenceGenerationState.BUILDING_REPLACEMENT
    ]
    published_durable = sum(source["batch_counts"]["durable"] for source in current)
    expanding = any(
        source["visibility_state"] == EvidenceGenerationState.BUILDING_INITIAL
        and not source["eof_declared"]
        and not source["zero_event"]
        for source in current
    )
    ingesting_without_publish = expanding and published_durable == 0
    has_failed_current = False
    for source in sources:
        if source["visibility_state"] != EvidenceGenerationState.FAILED:
            continue
        key = (source["source_ref_type"], source["source_ref_id"])
        if not _source_has_current_lifecycle(sources, key):
            has_failed_current = True
    replacement_in_progress = bool(replacements) and any(
        source["visibility_state"] == EvidenceGenerationState.ACTIVE for source in current
    )
    snapshot = snapshot or {"generations": [], "batches_by_generation": {}}
    finalizing_sources = [
        source for source in current
        if source["visibility_state"] == EvidenceGenerationState.BUILDING_INITIAL
        and source["eof_declared"]
    ]
    finalizing = bool(finalizing_sources)
    activation_gaps = []
    for source in finalizing_sources:
        activation_gaps.extend(_activation_gaps_from_snapshot(snapshot, source))
    all_current_active = bool(current) and all(
        source["visibility_state"] == EvidenceGenerationState.ACTIVE for source in current
    )
    extra = {
        "published_durable_batches": published_durable,
        "expanding": expanding,
        "finalizing": finalizing,
        "activation_incomplete": bool(activation_gaps),
        "replacement_in_progress": replacement_in_progress,
        "final_percent": None,
        "has_legacy_untracked": composition in {
            CaseIngestComposition.LEGACY_ONLY,
            CaseIngestComposition.MIXED,
        },
    }

    if composition == CaseIngestComposition.LEGACY_ONLY:
        extra["finalizing"] = False
        return _dimension(
            "legacy",
            "Untracked",
            "Legacy evidence has no Phase 1B managed publication proof.",
            **extra,
        )
    if has_failed_current:
        return _dimension(
            "failed",
            "Ingest incomplete",
            "A current managed source did not finish ingest.",
            **extra,
        )
    if not current and any(
        source["visibility_state"] == EvidenceGenerationState.INVALIDATED for source in sources
    ) and not any(
        source["visibility_state"] in {
            EvidenceGenerationState.ACTIVE,
            EvidenceGenerationState.BUILDING_INITIAL,
            EvidenceGenerationState.BUILDING_REPLACEMENT,
        }
        for source in sources
    ):
        return _dimension(
            "withdrawn",
            "Withdrawn",
            "Managed evidence authority for this case has been withdrawn.",
            **extra,
        )
    if composition == CaseIngestComposition.MIXED:
        if expanding and published_durable:
            detail = (
                f"Published evidence is searchable; ingest is still expanding. "
                f"{published_durable} published batches. Untracked legacy evidence is also present."
            )
            return _dimension("mixed", "Published and untracked", detail, **extra)
        if expanding:
            return _dimension(
                "mixed",
                "Published and untracked",
                "Managed ingest is still expanding. Untracked legacy evidence is also present.",
                **extra,
            )
        if finalizing:
            detail = (
                "Searchable managed evidence is present; ingest is finalizing and is not yet fully published. "
                "Untracked legacy evidence is also present."
            )
            if activation_gaps:
                detail = (
                    "Managed ingest is finalizing with incomplete batch state. "
                    "Untracked legacy evidence is also present."
                )
            return _dimension("mixed", "Searchable and untracked", detail, **extra)
        if replacement_in_progress:
            return _dimension(
                "mixed",
                "Published and untracked",
                "Current published managed evidence remains searchable. Replacement processing. "
                "Untracked legacy evidence is also present.",
                **extra,
            )
        return _dimension(
            "mixed",
            "Published and untracked",
            "Published managed evidence is searchable. This case also has untracked legacy evidence.",
            **extra,
        )
    if ingesting_without_publish:
        return _dimension(
            "ingesting",
            "Ingest in progress",
            "Managed ingest has started. No published batches yet.",
            **extra,
        )
    if expanding:
        batch_phrase = (
            f"{published_durable} published batch"
            f"{'' if published_durable == 1 else 'es'}"
        )
        return _dimension(
            "expanding",
            "Searchable, still ingesting",
            f"Published evidence is searchable; ingest is still expanding. {batch_phrase}.",
            **extra,
        )
    if finalizing:
        if activation_gaps:
            return _dimension(
                "finalizing",
                "Searchable, finalizing ingest",
                "EOF is declared, but activation completeness is not proven. "
                "Search remains available for already published DURABLE batches.",
                **extra,
            )
        return _dimension(
            "finalizing",
            "Searchable, finalizing ingest",
            "EOF is declared. Current managed evidence is searchable and ingest is finalizing; "
            "it is not yet fully published.",
            **extra,
        )
    if replacement_in_progress:
        return _dimension(
            "published_with_replacement",
            "Published",
            "Current published evidence remains searchable. Replacement processing.",
            **extra,
        )
    if all_current_active:
        return _dimension(
            "published",
            "Published",
            "Current managed evidence is published. This is ingest completion, not analysis completion.",
            **extra,
        )
    if sources and all(
        source["visibility_state"] == EvidenceGenerationState.INVALIDATED for source in sources
    ):
        return _dimension(
            "withdrawn",
            "Withdrawn",
            "Managed evidence authority for this case has been withdrawn.",
            **extra,
        )
    return _dimension(
        "ingesting",
        "Ingest in progress",
        "Managed evidence is not yet fully published.",
        **extra,
    )


def _build_privacy_dimension(*, sources: list[dict[str, Any]], composition: str) -> dict[str, Any]:
    extra = {
        "informational_only": PRIVACY_INFORMATIONAL_ONLY,
        "authorizes_ai_egress": AUTHORIZES_AI_EGRESS,
        "derivation_version": PRIVACY_ALIASES_V1,
        "capability": CapabilityName.PRIVACY_ALIASES,
        "contiguous_batch_ordinal": None,
        "replacement_incomplete": False,
    }
    if composition == CaseIngestComposition.LEGACY_ONLY:
        return _dimension(
            "not_applicable",
            "Not tracked",
            "Privacy coverage is not a Phase 1B managed watermark on legacy-only evidence. "
            "This status does not authorize AI sending.",
            **extra,
        )
    current = [source for source in sources if source.get("is_default_authority")]
    replacements = [
        source for source in sources
        if source.get("visibility_state") == EvidenceGenerationState.BUILDING_REPLACEMENT
    ]
    extra["replacement_incomplete"] = any(
        row.get("privacy_aliases_v1_status") != CapabilityWatermarkStatus.COMPLETE
        for row in replacements
    )
    if not current:
        has_withdrawn = any(
            source["visibility_state"] == EvidenceGenerationState.INVALIDATED for source in sources
        )
        has_live = any(
            source["visibility_state"] in LIVE_PRIVACY_GENERATION_STATES for source in sources
        )
        if has_withdrawn and not has_live:
            return _dimension(
                "withdrawn",
                "Withdrawn",
                "Managed privacy coverage was withdrawn with the current evidence authority. "
                "This status does not authorize AI sending.",
                **extra,
            )
        return _dimension(
            "not_started",
            "Not started",
            "No current managed source privacy coverage. This status does not authorize AI sending.",
            **extra,
        )

    statuses = [source.get("privacy_aliases_v1_status") for source in current]
    if any(status == CapabilityWatermarkStatus.FAILED for status in statuses):
        return _dimension(
            "failed",
            "Privacy incomplete",
            "Privacy alias coverage failed for a current source. This status does not authorize AI sending.",
            **extra,
        )
    if any(status == CapabilityWatermarkStatus.INVALIDATED for status in statuses):
        return _dimension(
            "failed",
            "Privacy withdrawn",
            "Current privacy coverage was withdrawn. This status does not authorize AI sending.",
            **extra,
        )

    complete = all(
        source.get("privacy_aliases_v1_status") == CapabilityWatermarkStatus.COMPLETE
        or source.get("zero_event")
        for source in current
    )
    nonzero_current = [source for source in current if not source.get("zero_event")]
    replacement_note = ""
    if extra["replacement_incomplete"]:
        replacement_note = " Replacement privacy is still processing in the background."

    if complete:
        if len(nonzero_current) == 1:
            extra["contiguous_batch_ordinal"] = nonzero_current[0].get("privacy_contiguous_batch_ordinal")
        else:
            extra["contiguous_batch_ordinal"] = None
        return _dimension(
            "complete",
            "Covered",
            "Current published privacy-alias coverage is complete. "
            "This status does not authorize AI sending."
            + replacement_note,
            **extra,
        )

    covered_nonzero = [
        source for source in nonzero_current
        if source.get("privacy_contiguous_batch_ordinal") is not None
        or source.get("privacy_aliases_v1_status") in {
            CapabilityWatermarkStatus.CONTIGUOUS_READY,
            CapabilityWatermarkStatus.COMPLETE,
        }
    ]
    uncovered_nonzero = [source for source in nonzero_current if source not in covered_nonzero]

    if len(nonzero_current) == 1 and nonzero_current[0].get("privacy_contiguous_batch_ordinal") is not None:
        extra["contiguous_batch_ordinal"] = int(nonzero_current[0]["privacy_contiguous_batch_ordinal"])
        ordinal = extra["contiguous_batch_ordinal"]
        return _dimension(
            "contiguous",
            "Partial coverage",
            f"Safe privacy coverage through batch {ordinal}. Later batches are not yet a contiguous prefix. "
            "This status does not authorize AI sending."
            + replacement_note,
            **extra,
        )

    extra["contiguous_batch_ordinal"] = None
    if len(nonzero_current) > 1 and covered_nonzero and uncovered_nonzero:
        return _dimension(
            "partial_sources",
            "Partial coverage",
            "Partial coverage across current sources. Case-level batch coverage is not proven. "
            "This status does not authorize AI sending."
            + replacement_note,
            **extra,
        )
    if len(nonzero_current) > 1 and covered_nonzero:
        return _dimension(
            "contiguous",
            "Partial coverage",
            "Partial coverage across current sources. Case-level batch coverage is not a single ordinal. "
            "This status does not authorize AI sending."
            + replacement_note,
            **extra,
        )
    if any(status == CapabilityWatermarkStatus.CONTIGUOUS_READY for status in statuses):
        return _dimension(
            "contiguous",
            "Partial coverage",
            "Safe contiguous privacy coverage exists, but it is not complete. "
            "This status does not authorize AI sending."
            + replacement_note,
            **extra,
        )
    return _dimension(
        "not_started",
        "Not started",
        "Current privacy-alias coverage has not started. This status does not authorize AI sending.",
        **extra,
    )


_RECONCILIATION_LABELS = {
    ReconciliationAssessment.RECONCILED: ("Current", "Durable reconciliation matches current PostgreSQL authority."),
    ReconciliationAssessment.WORK_QUEUED: ("Work queued", "Reconciliation work is queued against current PostgreSQL authority."),
    ReconciliationAssessment.IN_PROGRESS: ("In progress", "Reconciliation work is in progress."),
    ReconciliationAssessment.INCOMPLETE_INGEST: ("Ingest incomplete", "Managed ingest has not declared completion."),
    ReconciliationAssessment.BLOCKED: ("Needs attention", "Reconciliation is blocked and needs attention."),
    ReconciliationAssessment.DEFERRED: ("Deferred", "Some completion work remains deferred and unverifiable."),
    ReconciliationAssessment.FAILED: ("Failed", "Completion reconciliation failed."),
    PENDING_RECONCILIATION: (
        "Needs reconciliation",
        "Durable F1 reconciliation has not certified the current PostgreSQL authority.",
    ),
    "legacy": ("Legacy completion", "This case uses the accepted legacy completion path."),
    "stale": ("Needs refresh", "A prior reconciliation result is stale because PostgreSQL authority changed."),
    "unavailable": ("Unavailable", "Completion status cannot be read from PostgreSQL."),
}


def _build_reconciliation_dimension(
    *,
    composition: str,
    snapshot: dict[str, Any],
    sources: list[dict[str, Any]],
    audit: Optional[CaseCompletionReconciliationAudit],
) -> dict[str, Any]:
    inspect_code = inspect_reconciliation_from_snapshot(snapshot, sources)
    audit_current = _audit_matches_current_authority(audit, snapshot)
    expanding = any(
        source.get("is_default_authority")
        and source["visibility_state"] == EvidenceGenerationState.BUILDING_INITIAL
        and not source["eof_declared"]
        and not source["zero_event"]
        for source in sources
    )
    if composition == CaseIngestComposition.LEGACY_ONLY:
        code = "legacy"
    elif audit_current:
        code = audit.assessment
    elif inspect_code in PROVEN_INSPECT_ASSESSMENTS:
        code = inspect_code
    elif audit is not None and audit.assessment == ReconciliationAssessment.RECONCILED:
        code = "stale"
    else:
        code = PENDING_RECONCILIATION

    label, default_detail = _RECONCILIATION_LABELS.get(code, ("Unknown", "Completion status is unknown."))
    detail = default_detail
    if code == "stale":
        detail = "A prior reconciled result is stale because generation or batch authority changed."
    repair_available = False
    repair_route = None
    if composition == CaseIngestComposition.LEGACY_ONLY:
        repair_route = "legacy"
        repair_available = False
    elif composition in {CaseIngestComposition.MANAGED_ONLY, CaseIngestComposition.MIXED}:
        repair_route = "f1"
        if code in {
            ReconciliationAssessment.BLOCKED,
            ReconciliationAssessment.FAILED,
            "stale",
            PENDING_RECONCILIATION,
        }:
            repair_available = True
        elif code == ReconciliationAssessment.WORK_QUEUED and not expanding:
            repair_available = True
        elif code == ReconciliationAssessment.IN_PROGRESS and not expanding:
            repair_available = True
    extra = {
        "audit_current": audit_current,
        "audit_id": None if audit is None else audit.id,
        "audit_assessment": None if audit is None else audit.assessment,
        "inspect_assessment": inspect_code,
        "repair_available": repair_available,
        "repair_route": repair_route,
    }
    return _dimension(code, label, detail, **extra)


def _build_live_activity_dimension(
    *,
    redis_available: bool,
    progress: Optional[dict[str, Any]],
) -> dict[str, Any]:
    if not redis_available:
        return _dimension(
            "unavailable",
            "Unavailable",
            "Live worker status is unavailable.",
            available=False,
            status=None,
            current_item=None,
            processing=False,
        )
    if not progress:
        return _dimension(
            "idle",
            "Idle",
            "No live ingest activity is reported.",
            available=True,
            status="idle",
            current_item=None,
            processing=False,
        )
    status = str(progress.get("status") or "idle")
    current_item = progress.get("current_item") or ""
    processing = status in _PROCESSING_STATUSES
    files = progress.get("files") or {}
    if processing:
        detail_parts = [f"Currently {status.replace('_', ' ')}."]
        if current_item:
            detail_parts.append(f"Current item: {current_item}.")
        completed = files.get("completed")
        total = files.get("total")
        if total:
            detail_parts.append(f"Files {completed or 0} of {total} (ephemeral progress, not durable completion).")
        return _dimension(
            "processing",
            "Processing",
            " ".join(detail_parts),
            available=True,
            status=status,
            current_item=current_item or None,
            processing=True,
        )
    return _dimension(
        "idle",
        "Idle",
        "No live ingest activity is reported.",
        available=True,
        status=status,
        current_item=current_item or None,
        processing=False,
    )


def _build_hunt_coverage(
    *,
    composition: str,
    evidence: dict[str, Any],
    authority_available: bool,
) -> dict[str, Any]:
    coverage = {
        "show": False,
        "note_kind": "quiet",
        "text": "",
        "search_enabled": True,
    }
    if not authority_available:
        coverage.update(show=True, note_kind="unavailable", text=UNAVAILABLE_HUNT_NOTE)
        return coverage
    if composition == CaseIngestComposition.LEGACY_ONLY:
        coverage.update(show=True, note_kind="legacy", text=LEGACY_HUNT_NOTE)
        return coverage
    expanding = bool(evidence.get("expanding"))
    finalizing = bool(evidence.get("finalizing"))
    mixed = composition == CaseIngestComposition.MIXED
    replacement = bool(evidence.get("replacement_in_progress"))
    if expanding:
        text = EXPANDING_HUNT_NOTE
        if mixed:
            text = f"{EXPANDING_HUNT_NOTE} Untracked legacy evidence may also appear."
        coverage.update(show=True, note_kind="expanding", text=text)
        return coverage
    if finalizing:
        text = FINALIZING_HUNT_NOTE
        if mixed:
            text = f"{FINALIZING_HUNT_NOTE} Untracked legacy evidence may also appear."
        coverage.update(show=True, note_kind="finalizing", text=text)
        return coverage
    if mixed:
        coverage.update(show=True, note_kind="mixed", text=MIXED_HUNT_NOTE)
        if replacement:
            coverage["text"] = f"{MIXED_HUNT_NOTE} {REPLACEMENT_HUNT_NOTE}"
            coverage["note_kind"] = "mixed"
        return coverage
    if replacement:
        coverage.update(show=True, note_kind="replacement_background", text=REPLACEMENT_HUNT_NOTE)
        return coverage
    return coverage


def _build_completion(
    *,
    composition: str,
    reconciliation: dict[str, Any],
    evidence: dict[str, Any],
    authority_available: bool,
) -> dict[str, Any]:
    del evidence
    if not authority_available:
        return {
            "repair_available": False,
            "repair_route": None,
            "fail_closed": True,
            "banner_kind": "unavailable",
            "banner_title": "Completion status unavailable",
            "banner_text": "PostgreSQL readiness authority cannot be read. Repair is blocked.",
        }
    if composition == CaseIngestComposition.LEGACY_ONLY:
        return {
            "repair_available": False,
            "repair_route": "legacy",
            "fail_closed": False,
            "banner_kind": "legacy_existing",
            "banner_title": None,
            "banner_text": None,
        }
    if not reconciliation.get("repair_available"):
        return {
            "repair_available": False,
            "repair_route": reconciliation.get("repair_route"),
            "fail_closed": False,
            "banner_kind": None,
            "banner_title": None,
            "banner_text": None,
        }
    title = "Completion Needs Attention"
    text = reconciliation.get("detail") or "Durable reconciliation needs attention."
    if reconciliation.get("code") == "stale":
        title = "Completion Is Out of Date"
        text = "PostgreSQL authority changed after the last reconciliation. Resume to reconcile the current evidence."
    elif reconciliation.get("code") == PENDING_RECONCILIATION:
        title = "Completion Needs Reconciliation"
        text = "Durable F1 reconciliation has not certified the current PostgreSQL authority."
    elif reconciliation.get("code") == ReconciliationAssessment.FAILED:
        title = "Completion Failed"
    elif reconciliation.get("code") == ReconciliationAssessment.BLOCKED:
        title = "Completion Blocked"
    return {
        "repair_available": True,
        "repair_route": "f1",
        "fail_closed": False,
        "banner_kind": reconciliation.get("code"),
        "banner_title": title,
        "banner_text": text,
    }


def load_redis_live_activity(case_uuid: Optional[str]) -> tuple[Optional[dict[str, Any]], bool, int]:
    """Return (progress, redis_available, redis_calls). Redis loss is not durable authority."""
    if not case_uuid:
        return None, False, 0
    try:
        from utils.progress import get_progress, get_redis_client
        client = get_redis_client()
        client.ping()
        progress = get_progress(case_uuid)
        return progress, True, 2
    except Exception:
        logger.info("Redis live-activity decoration unavailable for case %s", case_uuid)
        return None, False, 1


def _unavailable_dto(
    *,
    case_id: int,
    case_uuid: Optional[str],
    live_activity: dict[str, Any],
    redis_calls: int,
    latency_ms: float,
    pg_rows_loaded: int = 0,
    error: str = "postgresql_authority_unavailable",
) -> dict[str, Any]:
    evidence = _dimension(
        "unavailable",
        "Unavailable",
        "Evidence status cannot be read from PostgreSQL.",
        published_durable_batches=None,
        expanding=False,
        finalizing=False,
        activation_incomplete=False,
        replacement_in_progress=False,
        final_percent=None,
        has_legacy_untracked=False,
    )
    privacy = _dimension(
        "unavailable",
        "Unavailable",
        "Privacy status cannot be read from PostgreSQL. This status does not authorize AI sending.",
        informational_only=True,
        authorizes_ai_egress=False,
        derivation_version=PRIVACY_ALIASES_V1,
        capability=CapabilityName.PRIVACY_ALIASES,
        contiguous_batch_ordinal=None,
        replacement_incomplete=False,
    )
    reconciliation = _dimension(
        "unavailable",
        "Unavailable",
        "Completion status cannot be read from PostgreSQL.",
        audit_current=False,
        audit_id=None,
        audit_assessment=None,
        inspect_assessment="unavailable",
        repair_available=False,
        repair_route=None,
    )
    hunt_coverage = _build_hunt_coverage(
        composition="unknown",
        evidence=evidence,
        authority_available=False,
    )
    completion = _build_completion(
        composition="unknown",
        reconciliation=reconciliation,
        evidence=evidence,
        authority_available=False,
    )
    return {
        "success": True,
        "authority": "unavailable",
        "authority_available": False,
        "composition": "unknown",
        "case_id": int(case_id),
        "case_uuid": case_uuid,
        "error": error,
        "dimensions": {
            "evidence": evidence,
            "privacy": privacy,
            "reconciliation": reconciliation,
            "live_activity": live_activity,
        },
        "hunt_coverage": hunt_coverage,
        "completion": completion,
        "metrics": {
            "pg_rows_loaded": pg_rows_loaded,
            "redis_calls": redis_calls,
            "clickhouse_calls": READINESS_CLICKHOUSE_CALLS,
            "latency_ms": latency_ms,
        },
    }


def build_case_readiness_dto(
    session,
    *,
    case_id: int,
    case_uuid: Optional[str] = None,
    redis_progress: Optional[dict[str, Any]] = None,
    redis_available: Optional[bool] = None,
    redis_calls: int = 0,
) -> dict[str, Any]:
    """Cheap PostgreSQL readiness DTO. Issues 0 ClickHouse queries.

    Redis arguments decorate live activity only. When omitted, Redis is loaded
    here and cannot change Evidence, Privacy, or Reconciliation.
    """
    started = time.perf_counter()
    if redis_available is None:
        redis_progress, redis_available, redis_calls = load_redis_live_activity(case_uuid)
    live_activity = _build_live_activity_dimension(
        redis_available=bool(redis_available),
        progress=redis_progress,
    )
    try:
        snapshot = snapshot_case_completion_authority(
            session, case_id=int(case_id), case_uuid=case_uuid
        )
        f1_readiness = build_case_reconciliation_readiness(snapshot)
        sources = list(f1_readiness.get("sources") or [])
        audit = _load_latest_reconciliation_audit(session, int(case_id))
        pg_rows_loaded = int(snapshot.get("pg_rows_loaded") or 0) + (1 if audit is not None else 0)
        composition = snapshot["composition"]
        evidence = _build_evidence_dimension(
            composition=composition, sources=sources, snapshot=snapshot
        )
        privacy = _build_privacy_dimension(sources=sources, composition=composition)
        reconciliation = _build_reconciliation_dimension(
            composition=composition,
            snapshot=snapshot,
            sources=sources,
            audit=audit,
        )
        hunt_coverage = _build_hunt_coverage(
            composition=composition,
            evidence=evidence,
            authority_available=True,
        )
        completion = _build_completion(
            composition=composition,
            reconciliation=reconciliation,
            evidence=evidence,
            authority_available=True,
        )
        latency_ms = (time.perf_counter() - started) * 1000.0
        return {
            "success": True,
            "authority": "postgresql",
            "authority_available": True,
            "composition": composition,
            "case_id": int(case_id),
            "case_uuid": case_uuid,
            "error": None,
            "dimensions": {
                "evidence": evidence,
                "privacy": privacy,
                "reconciliation": reconciliation,
                "live_activity": live_activity,
            },
            "hunt_coverage": hunt_coverage,
            "completion": completion,
            "metrics": {
                "pg_rows_loaded": pg_rows_loaded,
                "redis_calls": redis_calls,
                "clickhouse_calls": READINESS_CLICKHOUSE_CALLS,
                "latency_ms": latency_ms,
            },
        }
    except CompletionCompositionUnknown as exc:
        logger.warning("Readiness composition unknown for case %s: %s", case_id, exc)
        return _unavailable_dto(
            case_id=case_id,
            case_uuid=case_uuid,
            live_activity=live_activity,
            redis_calls=redis_calls,
            latency_ms=(time.perf_counter() - started) * 1000.0,
            error="postgresql_authority_unavailable",
        )
    except Exception:
        logger.exception("Readiness PostgreSQL authority read failed for case %s", case_id)
        return _unavailable_dto(
            case_id=case_id,
            case_uuid=case_uuid,
            live_activity=live_activity,
            redis_calls=redis_calls,
            latency_ms=(time.perf_counter() - started) * 1000.0,
            error="postgresql_authority_unavailable",
        )
