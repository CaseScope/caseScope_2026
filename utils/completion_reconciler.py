"""Phase 1B Tranche F1 durable case completion reconciliation.

PostgreSQL generation/batch/watermark tables are authority. Redis may debounce
or decorate; it must not decide whether managed evidence, capabilities, or
readiness are complete. This module does not create a case-wide ready boolean.
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from models.database_flow import (
    CapabilityDerivationClass,
    CapabilityName,
    CapabilityWatermarkStatus,
    CaseCapabilityBatchCompletion,
    CaseCapabilitySourceState,
    CaseCompletionReconciliationAudit,
    CaseIngestComposition,
    EvidenceGenerationState,
    EvidenceSourceGeneration,
    IngestBatch,
    IngestBatchState,
    ReconciliationAssessment,
)
from utils.capability_watermarks import (
    PRIVACY_ALIASES_V1,
    get_capability_watermark,
    resolve_default_capability_generation,
)


logger = logging.getLogger(__name__)

RECONCILE_DEBOUNCE_TTL_SECONDS = 3
PUBLISHABLE_GENERATION_STATES = frozenset({
    EvidenceGenerationState.BUILDING_INITIAL,
    EvidenceGenerationState.ACTIVE,
})
RECONCILABLE_GENERATION_STATES = frozenset({
    EvidenceGenerationState.BUILDING_INITIAL,
    EvidenceGenerationState.BUILDING_REPLACEMENT,
    EvidenceGenerationState.ACTIVE,
})
TERMINAL_GENERATION_STATES = frozenset({
    EvidenceGenerationState.SUPERSEDED,
    EvidenceGenerationState.FAILED,
    EvidenceGenerationState.INVALIDATED,
})
WHOLE_CASE_TRANSITIONAL = frozenset({
    "mitre_matches",
    "event_embeddings",
    "known_principal_discovery",
    "graph_extraction",
})

COMPLETION_DERIVATION_INVENTORY = (
    {
        "name": "privacy_aliases",
        "class": CapabilityDerivationClass.ROW_LOCAL,
        "current_trigger": "DURABLE batch via maybe_queue_row_local_derivations_for_durable_batch; F1 gap repair",
        "current_input_surface": "Published physical observations for one ingest_batch_id",
        "current_durable_output_authority": "privacy_aliases rows + CaseCapabilityBatchCompletion",
        "current_durable_completion_marker": "case_capability_batch_completions / case_capability_source_state",
        "current_idempotency_boundary": "(ingest_batch_id, privacy-aliases:v1)",
        "f1_can_inspect_completion": True,
        "f1_can_safely_requeue": True,
        "capability_watermark_migration": True,
        "legacy_deferred": False,
    },
    {
        "name": "ioc_matches",
        "class": CapabilityDerivationClass.ROW_LOCAL,
        "current_trigger": "Manual analyst IOC tagging; not in completion tail",
        "current_input_surface": "Case-wide overlay tagging",
        "current_durable_output_authority": "IOC match tables (not generation-aware)",
        "current_durable_completion_marker": None,
        "current_idempotency_boundary": "Per-IOC artifact reset; not batch-local",
        "f1_can_inspect_completion": False,
        "f1_can_safely_requeue": False,
        "capability_watermark_migration": False,
        "legacy_deferred": True,
    },
    {
        "name": "mitre_matches",
        "class": CapabilityDerivationClass.ROW_LOCAL,
        "current_trigger": "Legacy completion tail _queue_post_ingest_mitre_mapping; Hayabusa per-file",
        "current_input_surface": "Case-wide procedure mapping",
        "current_durable_output_authority": "MITRE match tables",
        "current_durable_completion_marker": "mitre_mapping_case_{id} inflight marker (Redis) plus scan_version",
        "current_idempotency_boundary": "Case-wide rebuild",
        "f1_can_inspect_completion": False,
        "f1_can_safely_requeue": True,
        "capability_watermark_migration": False,
        "legacy_deferred": True,
    },
    {
        "name": "graph_extraction",
        "class": CapabilityDerivationClass.ADDITIVE_AGGREGATE,
        "current_trigger": "Legacy completion tail materialize_case_graph_task",
        "current_input_surface": "Published events / file scope",
        "current_durable_output_authority": "GraphEntity/Relationship PostgreSQL projection",
        "current_durable_completion_marker": "GraphProjectionState",
        "current_idempotency_boundary": "Per-case projection state",
        "f1_can_inspect_completion": True,
        "f1_can_safely_requeue": True,
        "capability_watermark_migration": False,
        "legacy_deferred": True,
    },
    {
        "name": "known_user_discovery",
        "class": CapabilityDerivationClass.ADDITIVE_AGGREGATE,
        "current_trigger": "Legacy completion tail discover_known_users",
        "current_input_surface": "Case-wide ClickHouse events + CaseFile metadata",
        "current_durable_output_authority": "KnownUser tables (not generation-aware)",
        "current_durable_completion_marker": None,
        "current_idempotency_boundary": "Whole-case upsert",
        "f1_can_inspect_completion": False,
        "f1_can_safely_requeue": True,
        "capability_watermark_migration": False,
        "legacy_deferred": True,
    },
    {
        "name": "known_system_discovery",
        "class": CapabilityDerivationClass.ADDITIVE_AGGREGATE,
        "current_trigger": "Legacy completion tail discover_known_systems",
        "current_input_surface": "Case-wide ClickHouse events + CaseFile host metadata",
        "current_durable_output_authority": "KnownSystem tables (not generation-aware)",
        "current_durable_completion_marker": None,
        "current_idempotency_boundary": "Whole-case upsert",
        "f1_can_inspect_completion": False,
        "f1_can_safely_requeue": True,
        "capability_watermark_migration": False,
        "legacy_deferred": True,
    },
    {
        "name": "behavioral_profiles",
        "class": CapabilityDerivationClass.ADDITIVE_AGGREGATE,
        "current_trigger": "Analyst-triggered case analysis; not in completion tail",
        "current_input_surface": "Published logical events",
        "current_durable_output_authority": "UserBehaviorProfile / SystemBehaviorProfile",
        "current_durable_completion_marker": "CaseAnalysisRun",
        "current_idempotency_boundary": "Case snapshot / analysis run",
        "f1_can_inspect_completion": False,
        "f1_can_safely_requeue": False,
        "capability_watermark_migration": False,
        "legacy_deferred": True,
    },
    {
        "name": "pattern_detection",
        "class": CapabilityDerivationClass.WINDOWED_STATEFUL,
        "current_trigger": "Analyst-triggered case analysis; not in completion tail",
        "current_input_surface": "Published logical events with overlay filters",
        "current_durable_output_authority": "GapDetectionFinding / pattern tables",
        "current_durable_completion_marker": None,
        "current_idempotency_boundary": "(window/checkpoint_id, derivation_version)",
        "f1_can_inspect_completion": False,
        "f1_can_safely_requeue": False,
        "capability_watermark_migration": False,
        "legacy_deferred": True,
    },
    {
        "name": "event_embeddings",
        "class": CapabilityDerivationClass.ROW_LOCAL,
        "current_trigger": "Legacy completion tail _queue_auto_event_embedding",
        "current_input_surface": "Published logical events (LEK-current)",
        "current_durable_output_authority": "Qdrant points (not Phase1B migrated)",
        "current_durable_completion_marker": "rag_auto_embed Redis marker / embedding lock",
        "current_idempotency_boundary": "Per-case scope rebuild",
        "f1_can_inspect_completion": False,
        "f1_can_safely_requeue": True,
        "capability_watermark_migration": False,
        "legacy_deferred": True,
    },
)


class CompletionReconciliationError(RuntimeError):
    """Raised when completion reconciliation cannot proceed safely."""


class CompletionCompositionUnknown(CompletionReconciliationError):
    """Raised when PostgreSQL composition authority cannot be determined.

    This is not a durable case state and must not be stored as a global
    readiness value. Callers must fail closed, defer, or retry.
    """


@dataclass
class ReconciliationHooks:
    """Optional executors/schedulers. None means inspect-only or production default."""

    privacy_executor: Optional[Callable[..., Any]] = None
    d2_invoker: Optional[Callable[..., Any]] = None
    graph_scheduler: Optional[Callable[..., Any]] = None
    mitre_scheduler: Optional[Callable[..., Any]] = None
    embedding_scheduler: Optional[Callable[..., Any]] = None
    known_systems_scheduler: Optional[Callable[..., Any]] = None
    known_users_scheduler: Optional[Callable[..., Any]] = None
    schedule_reconciliation: Optional[Callable[..., Any]] = None


@dataclass
class CaseReconciliationResult:
    assessment: str
    case_id: int
    case_uuid: Optional[str]
    trigger_reason: str
    composition: str
    generations_inspected: list[dict[str, Any]] = field(default_factory=list)
    batch_counts: dict[str, int] = field(default_factory=dict)
    d2_gaps: list[dict[str, Any]] = field(default_factory=list)
    capability_gaps: list[dict[str, Any]] = field(default_factory=list)
    derivations_checked: list[dict[str, Any]] = field(default_factory=list)
    work_queued: list[dict[str, Any]] = field(default_factory=list)
    unresolved_conflicts: list[dict[str, Any]] = field(default_factory=list)
    deferred: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    authority_changed: bool = False
    duration_ms: float = 0.0
    audit_id: Optional[int] = None
    readiness: Optional[dict[str, Any]] = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "assessment": self.assessment,
            "case_id": self.case_id,
            "case_uuid": self.case_uuid,
            "trigger_reason": self.trigger_reason,
            "composition": self.composition,
            "generations_inspected": list(self.generations_inspected),
            "batch_counts": dict(self.batch_counts),
            "d2_gaps": list(self.d2_gaps),
            "capability_gaps": list(self.capability_gaps),
            "derivations_checked": list(self.derivations_checked),
            "work_queued": list(self.work_queued),
            "unresolved_conflicts": list(self.unresolved_conflicts),
            "deferred": list(self.deferred),
            "errors": list(self.errors),
            "metrics": dict(self.metrics),
            "authority_changed": self.authority_changed,
            "duration_ms": self.duration_ms,
            "audit_id": self.audit_id,
            "readiness": self.readiness,
        }


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _in_pytest() -> bool:
    return bool(os.environ.get("PYTEST_CURRENT_TEST"))


def completion_derivation_inventory() -> tuple[dict[str, Any], ...]:
    return COMPLETION_DERIVATION_INVENTORY


def _require_composition_rows(session, *, case_id: int, description: str, query_fn):
    """Execute a composition-authority query. Failure is unknown, not empty."""
    try:
        rows = query_fn()
        if not isinstance(rows, (list, tuple)):
            rows = list(rows)
        return list(rows)
    except CompletionCompositionUnknown:
        raise
    except Exception as exc:
        try:
            session.rollback()
        except Exception:
            pass
        raise CompletionCompositionUnknown(
            f"cannot determine ingest composition for case {case_id}: {description}"
        ) from exc


def classify_case_ingest_composition(
    session,
    *,
    case_id: int,
    case_uuid: Optional[str] = None,
) -> str:
    """Classify a case as legacy-only, managed-only, or mixed from PG authority.

    Returns only a proven composition. Authority-read failure raises
    ``CompletionCompositionUnknown``. Query failure is never treated as
    an empty result or as ``legacy_only``.
    """
    generations = _require_composition_rows(
        session,
        case_id=case_id,
        description="evidence_source_generations query failed",
        query_fn=lambda: (
            session.query(EvidenceSourceGeneration)
            .filter_by(case_id=int(case_id))
            .all()
        ),
    )
    has_managed = bool(generations)
    managed_file_ids = {
        str(row.source_ref_id)
        for row in generations
        if row.source_ref_type == "CASE_FILE"
    }
    if not case_uuid:
        raise CompletionCompositionUnknown(
            f"cannot determine ingest composition for case {case_id}: "
            "case_uuid is required to classify CaseFile origins"
        )
    try:
        from models.case_file import CaseFile, IngestProtocolOrigin
    except Exception as exc:
        raise CompletionCompositionUnknown(
            f"cannot determine ingest composition for case {case_id}: "
            "CaseFile model unavailable"
        ) from exc
    files = _require_composition_rows(
        session,
        case_id=case_id,
        description="case_files query failed",
        query_fn=lambda: (
            session.query(CaseFile)
            .filter_by(case_uuid=str(case_uuid))
            .all()
        ),
    )
    has_legacy = False
    for case_file in files:
        if getattr(case_file, "is_archive", False):
            continue
        origin = getattr(case_file, "ingest_protocol_origin", None)
        if IngestProtocolOrigin is not None and origin == IngestProtocolOrigin.LEGACY_OR_UNKNOWN:
            has_legacy = True
            continue
        if origin == "legacy_or_unknown":
            has_legacy = True
            continue
        if IngestProtocolOrigin is not None and origin == IngestProtocolOrigin.MANIFEST_INITIAL:
            continue
        if origin == "manifest_initial":
            continue
        if str(case_file.id) not in managed_file_ids:
            has_legacy = True
    if has_managed and has_legacy:
        return CaseIngestComposition.MIXED
    if has_managed:
        return CaseIngestComposition.MANAGED_ONLY
    return CaseIngestComposition.LEGACY_ONLY


def resolve_case_completion_route(
    session,
    *,
    case_id: int,
    case_uuid: Optional[str] = None,
) -> str:
    """Return a proven completion route or raise.

    Proven results are only ``legacy_only``, ``managed_only``, and ``mixed``.
    Authority-read failures raise ``CompletionCompositionUnknown``.
    """
    return classify_case_ingest_composition(session, case_id=case_id, case_uuid=case_uuid)


def managed_destructive_completion_forbidden(composition: str) -> bool:
    return composition in {CaseIngestComposition.MANAGED_ONLY, CaseIngestComposition.MIXED}


def _generation_fingerprint(generation: EvidenceSourceGeneration) -> dict[str, Any]:
    return {
        "id": int(generation.id),
        "source_ref_type": generation.source_ref_type,
        "source_ref_id": str(generation.source_ref_id),
        "source_generation": int(generation.source_generation),
        "visibility_state": generation.visibility_state,
        "state_version": int(generation.state_version or 1),
        "expected_rows": generation.expected_rows,
        "final_batch_ordinal": generation.final_batch_ordinal,
        "completed_at": generation.completed_at.isoformat() if generation.completed_at else None,
        "activated_at": generation.activated_at.isoformat() if generation.activated_at else None,
    }


def _is_default_authority(session, generation: EvidenceSourceGeneration) -> bool:
    default = resolve_default_capability_generation(
        session,
        case_id=int(generation.case_id),
        source_ref_type=generation.source_ref_type,
        source_ref_id=generation.source_ref_id,
    )
    return default is not None and int(default.id) == int(generation.id)


def _zero_event_generation(generation: EvidenceSourceGeneration, batches: list[IngestBatch]) -> bool:
    return (
        generation.completed_at is not None
        and generation.expected_rows == 0
        and generation.final_batch_ordinal is None
        and not batches
    )


def snapshot_case_completion_authority(
    session,
    *,
    case_id: int,
    case_uuid: Optional[str] = None,
) -> dict[str, Any]:
    """Read-only PostgreSQL control-plane snapshot. Does not scan events."""
    generations = (
        session.query(EvidenceSourceGeneration)
        .filter_by(case_id=int(case_id))
        .order_by(
            EvidenceSourceGeneration.source_ref_type.asc(),
            EvidenceSourceGeneration.source_ref_id.asc(),
            EvidenceSourceGeneration.source_generation.asc(),
        )
        .all()
    )
    generation_ids = [int(row.id) for row in generations]
    batches = []
    if generation_ids:
        batches = (
            session.query(IngestBatch)
            .filter(IngestBatch.generation_id.in_(generation_ids))
            .order_by(IngestBatch.generation_id.asc(), IngestBatch.batch_ordinal.asc())
            .all()
        )
    completions = (
        session.query(CaseCapabilityBatchCompletion)
        .filter_by(case_id=int(case_id), capability=CapabilityName.PRIVACY_ALIASES)
        .all()
    )
    watermarks = (
        session.query(CaseCapabilitySourceState)
        .filter_by(case_id=int(case_id))
        .all()
    )
    batches_by_generation: dict[int, list[IngestBatch]] = {}
    for batch in batches:
        batches_by_generation.setdefault(int(batch.generation_id), []).append(batch)
    completion_ids = {
        (int(row.source_generation), str(row.ingest_batch_id), row.derivation_version)
        for row in completions
        if row.source_ref_type
    }
    privacy_completed_batch_ids = {
        str(row.ingest_batch_id)
        for row in completions
        if row.capability == CapabilityName.PRIVACY_ALIASES
        and row.derivation_version == PRIVACY_ALIASES_V1
    }
    return {
        "case_id": int(case_id),
        "case_uuid": case_uuid,
        "composition": classify_case_ingest_composition(
            session, case_id=case_id, case_uuid=case_uuid
        ),
        "generations": generations,
        "batches": batches,
        "batches_by_generation": batches_by_generation,
        "batch_states": {
            int(batch.id): batch.state
            for batch in batches
        },
        "privacy_completed_batch_ids": privacy_completed_batch_ids,
        "privacy_completion_keys": completion_ids,
        "watermarks": watermarks,
        "pg_rows_loaded": len(generations) + len(batches) + len(completions) + len(watermarks),
        "default_ids": {
            int(row.id)
            for row in generations
            if _is_default_authority(session, row)
        },
        "generation_versions": {
            (row.source_ref_type, str(row.source_ref_id), int(row.source_generation)): (
                row.visibility_state,
                int(row.state_version or 1),
            )
            for row in generations
        },
    }


def build_case_reconciliation_readiness(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Internal PG-derived readiness DTO. Not a correctness scalar."""
    sources: list[dict[str, Any]] = []
    for generation in snapshot["generations"]:
        batches = snapshot["batches_by_generation"].get(int(generation.id), [])
        staged = [batch for batch in batches if batch.state == IngestBatchState.STAGED]
        durable = [batch for batch in batches if batch.state == IngestBatchState.DURABLE]
        watermark = next(
            (
                row
                for row in snapshot["watermarks"]
                if row.capability == CapabilityName.PRIVACY_ALIASES
                and row.source_ref_type == generation.source_ref_type
                and str(row.source_ref_id) == str(generation.source_ref_id)
                and int(row.source_generation) == int(generation.source_generation)
                and row.derivation_version == PRIVACY_ALIASES_V1
            ),
            None,
        )
        sources.append({
            "source_ref_type": generation.source_ref_type,
            "source_ref_id": str(generation.source_ref_id),
            "source_generation": int(generation.source_generation),
            "visibility_state": generation.visibility_state,
            "is_default_authority": int(generation.id) in snapshot["default_ids"],
            "publishable": generation.visibility_state in PUBLISHABLE_GENERATION_STATES,
            "eof_declared": generation.completed_at is not None,
            "expected_rows": generation.expected_rows,
            "final_batch_ordinal": generation.final_batch_ordinal,
            "zero_event": _zero_event_generation(generation, batches),
            "batch_counts": {"staged": len(staged), "durable": len(durable)},
            "privacy_aliases_v1_status": watermark.status if watermark else CapabilityWatermarkStatus.NOT_STARTED,
            "privacy_contiguous_batch_ordinal": (
                watermark.contiguous_batch_ordinal if watermark else None
            ),
        })
    return {
        "case_id": snapshot["case_id"],
        "case_uuid": snapshot.get("case_uuid"),
        "composition": snapshot["composition"],
        "sources": sources,
        "authority": "postgresql",
    }


def _generation_is_self_default(snapshot: dict[str, Any], generation: EvidenceSourceGeneration) -> bool:
    return int(generation.id) in snapshot.get("default_ids", set())


def reconcile_case_ingest(
    session,
    snapshot: dict[str, Any],
    *,
    hooks: Optional[ReconciliationHooks] = None,
) -> dict[str, Any]:
    """Inspect generation/batch completeness and hand stale STAGED batches to D2."""
    hooks = hooks or ReconciliationHooks()
    d2_gaps: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    queued: list[dict[str, Any]] = []
    in_progress: list[dict[str, Any]] = []
    incomplete: list[dict[str, Any]] = []
    inspected: list[dict[str, Any]] = []

    from utils.staged_batch_reconciler import staged_batch_stale_eligibility

    for generation in snapshot["generations"]:
        batches = snapshot["batches_by_generation"].get(int(generation.id), [])
        record = _generation_fingerprint(generation)
        record["batch_counts"] = {
            "staged": sum(1 for batch in batches if batch.state == IngestBatchState.STAGED),
            "durable": sum(1 for batch in batches if batch.state == IngestBatchState.DURABLE),
        }
        record["is_default_authority"] = _generation_is_self_default(snapshot, generation)
        inspected.append(record)

        if generation.visibility_state in TERMINAL_GENERATION_STATES:
            continue

        if _zero_event_generation(generation, batches):
            continue

        staged = [batch for batch in batches if batch.state == IngestBatchState.STAGED]
        if generation.visibility_state == EvidenceGenerationState.ACTIVE and staged:
            for batch in staged:
                conflicts.append({
                    "kind": "active_generation_staged_batch",
                    "ingest_batch_id": batch.ingest_batch_id,
                    "source_generation": int(generation.source_generation),
                    "batch_ordinal": int(batch.batch_ordinal),
                    "reason": "ACTIVE generation contains a STAGED batch",
                })
            continue

        if generation.visibility_state not in RECONCILABLE_GENERATION_STATES:
            continue

        if generation.completed_at is None:
            incomplete.append({
                "kind": "eof_missing",
                "source_ref_type": generation.source_ref_type,
                "source_ref_id": str(generation.source_ref_id),
                "source_generation": int(generation.source_generation),
                "visibility_state": generation.visibility_state,
            })

        for batch in staged:
            eligibility = staged_batch_stale_eligibility(batch)
            gap = {
                "ingest_batch_id": batch.ingest_batch_id,
                "source_generation": int(generation.source_generation),
                "visibility_state": generation.visibility_state,
                "batch_ordinal": int(batch.batch_ordinal),
                "stale": bool(eligibility.stale),
                "reason": eligibility.reason,
            }
            d2_gaps.append(gap)
            if eligibility.stale:
                if hooks.d2_invoker is not None:
                    hooks.d2_invoker(batch.ingest_batch_id)
                    queued.append({
                        "kind": "d2_stale_batch",
                        "ingest_batch_id": batch.ingest_batch_id,
                    })
            else:
                in_progress.append(gap)
                incomplete.append({
                    "kind": "staged_batch",
                    "ingest_batch_id": batch.ingest_batch_id,
                    "source_generation": int(generation.source_generation),
                    "reason": eligibility.reason,
                })

    return {
        "generations_inspected": inspected,
        "d2_gaps": d2_gaps,
        "unresolved_conflicts": conflicts,
        "work_queued": queued,
        "in_progress": in_progress,
        "incomplete": incomplete,
    }


def reconcile_case_derivations(
    session,
    snapshot: dict[str, Any],
    *,
    hooks: Optional[ReconciliationHooks] = None,
) -> dict[str, Any]:
    """Reconcile migrated ROW_LOCAL work and report unverifiable leftovers."""
    hooks = hooks or ReconciliationHooks()
    gaps: list[dict[str, Any]] = []
    queued: list[dict[str, Any]] = []
    checked: list[dict[str, Any]] = []
    deferred: list[dict[str, Any]] = []

    for generation in snapshot["generations"]:
        batches = snapshot["batches_by_generation"].get(int(generation.id), [])
        if generation.visibility_state in {EvidenceGenerationState.FAILED, EvidenceGenerationState.INVALIDATED}:
            checked.append({
                "name": "privacy_aliases",
                "source_generation": int(generation.source_generation),
                "visibility_state": generation.visibility_state,
                "action": "skip_terminal",
            })
            continue
        if generation.visibility_state == EvidenceGenerationState.SUPERSEDED:
            checked.append({
                "name": "privacy_aliases",
                "source_generation": int(generation.source_generation),
                "visibility_state": generation.visibility_state,
                "action": "preserve_history",
            })
            continue

        if _zero_event_generation(generation, batches):
            watermark = get_capability_watermark(
                session,
                case_id=int(generation.case_id),
                capability=CapabilityName.PRIVACY_ALIASES,
                source_ref_type=generation.source_ref_type,
                source_ref_id=generation.source_ref_id,
                source_generation=int(generation.source_generation),
                derivation_version=PRIVACY_ALIASES_V1,
            )
            if watermark is None or watermark.status != CapabilityWatermarkStatus.COMPLETE:
                from utils.row_local_derivations import maybe_complete_zero_event_row_local_capabilities
                maybe_complete_zero_event_row_local_capabilities(session=session, generation=generation)
                queued.append({
                    "kind": "zero_event_privacy_complete",
                    "source_generation": int(generation.source_generation),
                })
            checked.append({
                "name": "privacy_aliases",
                "source_generation": int(generation.source_generation),
                "action": "zero_event",
                "status": CapabilityWatermarkStatus.COMPLETE,
            })
            continue

        for batch in batches:
            frozen_state = snapshot.get("batch_states", {}).get(int(batch.id), batch.state)
            if frozen_state == IngestBatchState.STAGED:
                checked.append({
                    "name": "privacy_aliases",
                    "ingest_batch_id": batch.ingest_batch_id,
                    "action": "skip_staged_d2_handoff",
                })
                continue
            if frozen_state != IngestBatchState.DURABLE:
                continue
            already = batch.ingest_batch_id in snapshot["privacy_completed_batch_ids"]
            checked.append({
                "name": "privacy_aliases",
                "ingest_batch_id": batch.ingest_batch_id,
                "batch_ordinal": int(batch.batch_ordinal),
                "source_generation": int(generation.source_generation),
                "visibility_state": generation.visibility_state,
                "action": "noop" if already else "queue_missing",
                "is_default_authority": _generation_is_self_default(snapshot, generation),
            })
            if already:
                continue
            gaps.append({
                "capability": CapabilityName.PRIVACY_ALIASES,
                "derivation_version": PRIVACY_ALIASES_V1,
                "ingest_batch_id": batch.ingest_batch_id,
                "batch_ordinal": int(batch.batch_ordinal),
                "source_generation": int(generation.source_generation),
                "visibility_state": generation.visibility_state,
            })
            if hooks.privacy_executor is not None:
                hooks.privacy_executor(session, batch.ingest_batch_id)
            queued.append({
                "kind": "privacy_aliases",
                "ingest_batch_id": batch.ingest_batch_id,
                "batch_ordinal": int(batch.batch_ordinal),
            })

    for item in COMPLETION_DERIVATION_INVENTORY:
        if item["name"] == "privacy_aliases":
            continue
        deferred.append({
            "name": item["name"],
            "class": item["class"],
            "reason": "not_migrated_to_phase1b_capability_watermarks",
            "capability_watermark_migration": False,
            "f1_can_inspect_completion": item["f1_can_inspect_completion"],
        })

    return {
        "capability_gaps": gaps,
        "work_queued": queued,
        "derivations_checked": checked,
        "deferred": deferred,
    }


def _prior_transitional_queued(session, case_id: int, fingerprint: tuple) -> set[str]:
    rows = (
        session.query(CaseCompletionReconciliationAudit)
        .filter_by(case_id=int(case_id))
        .order_by(CaseCompletionReconciliationAudit.id.desc())
        .limit(25)
        .all()
    )
    queued: set[str] = set()
    for row in rows:
        metrics = row.metrics or {}
        if tuple(metrics.get("generation_fingerprint") or ()) != fingerprint:
            continue
        for item in row.work_queued or []:
            kind = item.get("kind")
            if kind in WHOLE_CASE_TRANSITIONAL:
                queued.add(kind)
    return queued


def _generation_state_fingerprint(snapshot: dict[str, Any]) -> tuple:
    return tuple(
        (
            generation.source_ref_type,
            str(generation.source_ref_id),
            int(generation.source_generation),
            generation.visibility_state,
            int(generation.state_version or 1),
        )
        for generation in snapshot["generations"]
    )


def _any_building(snapshot: dict[str, Any]) -> bool:
    return any(
        generation.visibility_state
        in {EvidenceGenerationState.BUILDING_INITIAL, EvidenceGenerationState.BUILDING_REPLACEMENT}
        for generation in snapshot["generations"]
    )


def reconcile_graph_projection(
    session,
    *,
    case_id: int,
    hooks: Optional[ReconciliationHooks] = None,
    ingest_building: bool = False,
) -> dict[str, Any]:
    """Inspect GraphProjectionState and queue only retryable/missing work."""
    hooks = hooks or ReconciliationHooks()
    try:
        from models.graph import GraphProjectionState
        state = (
            session.query(GraphProjectionState)
            .filter_by(case_id=int(case_id))
            .one_or_none()
        )
    except Exception as exc:
        return {
            "checked": {"name": "graph_extraction", "action": "uninspectable", "reason": str(exc)},
            "queued": [],
        }

    if state is not None and state.status in {"completed", "no_eligible_evidence", "running"}:
        return {
            "checked": {
                "name": "graph_extraction",
                "action": "noop",
                "status": state.status,
            },
            "queued": [],
        }
    if ingest_building and (state is None or state.status not in {"failed", "pending"}):
        return {
            "checked": {
                "name": "graph_extraction",
                "action": "defer_building",
                "status": state.status if state else "untracked",
            },
            "queued": [],
        }
    if state is None or state.status in {"failed", "pending"}:
        if hooks.graph_scheduler is not None:
            hooks.graph_scheduler()
            return {
                "checked": {
                    "name": "graph_extraction",
                    "action": "queue_retryable",
                    "status": state.status if state else "untracked",
                },
                "queued": [{"kind": "graph_extraction", "status": state.status if state else "untracked"}],
            }
        return {
            "checked": {
                "name": "graph_extraction",
                "action": "gap_unscheduled",
                "status": state.status if state else "untracked",
            },
            "queued": [],
        }
    return {
        "checked": {"name": "graph_extraction", "action": "noop", "status": state.status},
        "queued": [],
    }


def _queue_transitional_whole_case(
    session,
    snapshot: dict[str, Any],
    *,
    hooks: ReconciliationHooks,
) -> list[dict[str, Any]]:
    if _any_building(snapshot):
        return []
    fingerprint = _generation_state_fingerprint(snapshot)
    already = _prior_transitional_queued(session, snapshot["case_id"], fingerprint)
    queued: list[dict[str, Any]] = []
    mapping = (
        ("mitre_matches", hooks.mitre_scheduler),
        ("event_embeddings", hooks.embedding_scheduler),
    )
    for kind, scheduler in mapping:
        if scheduler is None or kind in already:
            continue
        scheduler()
        queued.append({"kind": kind, "mode": "transitional_whole_case"})
    if "known_principal_discovery" not in already:
        scheduled_known = False
        if hooks.known_systems_scheduler is not None:
            hooks.known_systems_scheduler()
            scheduled_known = True
        if hooks.known_users_scheduler is not None:
            hooks.known_users_scheduler()
            scheduled_known = True
        if scheduled_known:
            queued.append({"kind": "known_principal_discovery", "mode": "transitional_whole_case"})
    return queued


def _choose_assessment(result: CaseReconciliationResult) -> str:
    if result.errors and not result.work_queued and result.unresolved_conflicts:
        return ReconciliationAssessment.FAILED
    if result.authority_changed or result.unresolved_conflicts:
        return ReconciliationAssessment.BLOCKED
    if any(item.get("kind") in {"eof_missing", "staged_batch"} for item in result.metrics.get("incomplete", [])):
        if result.work_queued:
            return ReconciliationAssessment.WORK_QUEUED
        return ReconciliationAssessment.INCOMPLETE_INGEST
    if result.work_queued:
        return ReconciliationAssessment.WORK_QUEUED
    if result.metrics.get("in_progress"):
        return ReconciliationAssessment.IN_PROGRESS
    if result.capability_gaps:
        return ReconciliationAssessment.WORK_QUEUED
    return ReconciliationAssessment.RECONCILED


def _write_reconciliation_audit(session, result: CaseReconciliationResult) -> CaseCompletionReconciliationAudit:
    audit = CaseCompletionReconciliationAudit(
        case_id=int(result.case_id),
        case_uuid=result.case_uuid,
        trigger_reason=result.trigger_reason,
        composition=result.composition,
        assessment=result.assessment,
        generations_inspected=list(result.generations_inspected),
        batch_counts=dict(result.batch_counts),
        d2_gaps=list(result.d2_gaps),
        capability_gaps=list(result.capability_gaps),
        derivations_checked=list(result.derivations_checked),
        work_queued=list(result.work_queued),
        unresolved_conflicts=list(result.unresolved_conflicts),
        deferred=list(result.deferred),
        errors=list(result.errors),
        metrics=dict(result.metrics),
        authority_changed=bool(result.authority_changed),
        duration_ms=float(result.duration_ms),
        occurred_at=_utcnow(),
    )
    session.add(audit)
    session.flush()
    result.audit_id = audit.id
    return audit


def _write_operator_reconciliation_logs(result: CaseReconciliationResult) -> None:
    """Best-effort operator logs after the durable F1 audit has been committed."""
    try:
        from models.audit_log import AuditAction, AuditEntityType, AuditLog
        AuditLog.log(
            entity_type=AuditEntityType.CASE,
            entity_id=result.case_uuid or str(result.case_id),
            entity_name="Case completion reconciliation",
            action=AuditAction.RECONCILED,
            case_uuid=result.case_uuid,
            username="system",
            details={
                "assessment": result.assessment,
                "trigger_reason": result.trigger_reason,
                "composition": result.composition,
                "batch_counts": result.batch_counts,
                "work_queued": result.work_queued,
                "unresolved_conflicts": result.unresolved_conflicts,
                "deferred_names": [item.get("name") for item in result.deferred],
                "duration_ms": result.duration_ms,
                "audit_id": result.audit_id,
            },
        )
    except Exception:
        logger.warning("AuditLog write failed for completion reconciliation", exc_info=True)
        try:
            from models.database import db
            db.session.rollback()
        except Exception:
            pass
    try:
        from models.case_work import CaseWorkActivityType
        from utils.case_work import safe_log_case_work_activity
        if result.case_uuid:
            safe_log_case_work_activity(
                result.case_uuid,
                CaseWorkActivityType.COMPLETION_RECONCILIATION,
                f"Completion reconciliation {result.assessment}",
                details={
                    "assessment": result.assessment,
                    "trigger_reason": result.trigger_reason,
                    "composition": result.composition,
                    "work_queued": result.work_queued,
                    "audit_id": result.audit_id,
                },
                username="system",
            )
    except Exception:
        logger.warning("CaseWork write failed for completion reconciliation", exc_info=True)


def reconcile_case_completion(
    session,
    *,
    case_id: int,
    case_uuid: Optional[str] = None,
    trigger_reason: str = "durable_authority",
    hooks: Optional[ReconciliationHooks] = None,
    clickhouse_client: Any = None,
) -> CaseReconciliationResult:
    """Idempotent PG-authoritative completion reconciliation for one case."""
    del clickhouse_client  # reserved for executors; inspection stays on PG
    started = time.perf_counter()
    hooks = hooks or ReconciliationHooks()
    result = CaseReconciliationResult(
        assessment=ReconciliationAssessment.RECONCILED,
        case_id=int(case_id),
        case_uuid=case_uuid,
        trigger_reason=str(trigger_reason or "durable_authority"),
        composition="",
    )
    try:
        snapshot = snapshot_case_completion_authority(
            session, case_id=case_id, case_uuid=case_uuid
        )
        result.composition = snapshot["composition"]
        result.readiness = build_case_reconciliation_readiness(snapshot)
        result.batch_counts = {
            "staged": sum(1 for batch in snapshot["batches"] if batch.state == IngestBatchState.STAGED),
            "durable": sum(1 for batch in snapshot["batches"] if batch.state == IngestBatchState.DURABLE),
            "generations": len(snapshot["generations"]),
        }
        result.metrics["pg_rows_loaded"] = snapshot["pg_rows_loaded"]
        result.metrics["ch_queries"] = 0
        result.metrics["generation_fingerprint"] = list(_generation_state_fingerprint(snapshot))

        if result.composition == CaseIngestComposition.LEGACY_ONLY:
            result.deferred.append({
                "name": "legacy_completion_tail",
                "reason": "legacy_only_case_preserves_existing_completion_behavior",
            })
            result.assessment = ReconciliationAssessment.RECONCILED
            result.duration_ms = (time.perf_counter() - started) * 1000.0
            _write_reconciliation_audit(session, result)
            session.commit()
            _write_operator_reconciliation_logs(result)
            return result

        ingest = reconcile_case_ingest(session, snapshot, hooks=hooks)
        derivations = reconcile_case_derivations(session, snapshot, hooks=hooks)
        graph = reconcile_graph_projection(
            session,
            case_id=case_id,
            hooks=hooks,
            ingest_building=_any_building(snapshot),
        )
        transitional = _queue_transitional_whole_case(session, snapshot, hooks=hooks)

        result.generations_inspected = ingest["generations_inspected"]
        result.d2_gaps = ingest["d2_gaps"]
        result.unresolved_conflicts = ingest["unresolved_conflicts"]
        result.capability_gaps = derivations["capability_gaps"]
        result.derivations_checked = derivations["derivations_checked"] + [graph["checked"]]
        result.deferred = derivations["deferred"]
        result.work_queued = (
            ingest["work_queued"] + derivations["work_queued"] + graph["queued"] + transitional
        )
        result.metrics["incomplete"] = ingest["incomplete"]
        result.metrics["in_progress"] = ingest["in_progress"]

        session.expire_all()
        refreshed = (
            session.query(EvidenceSourceGeneration)
            .filter_by(case_id=int(case_id))
            .all()
        )
        snap_versions = dict(snapshot["generation_versions"])
        for row in refreshed:
            key = (row.source_ref_type, str(row.source_ref_id), int(row.source_generation))
            prior = snap_versions.get(key)
            current = (row.visibility_state, int(row.state_version or 1))
            if prior is not None and prior != current:
                result.authority_changed = True
                result.unresolved_conflicts.append({
                    "kind": "authority_changed",
                    "source_ref_type": row.source_ref_type,
                    "source_ref_id": str(row.source_ref_id),
                    "source_generation": int(row.source_generation),
                    "snapshot_state": prior[0],
                    "current_state": row.visibility_state,
                    "reason": "generation authority changed during reconciliation",
                })
            if key not in snap_versions:
                result.unresolved_conflicts.append({
                    "kind": "new_source_during_reconciliation",
                    "source_ref_type": row.source_ref_type,
                    "source_ref_id": str(row.source_ref_id),
                    "source_generation": int(row.source_generation),
                    "reason": "new source/generation appeared after snapshot",
                })

        result.assessment = _choose_assessment(result)
        result.duration_ms = (time.perf_counter() - started) * 1000.0
        result.metrics["duration_ms"] = result.duration_ms
        _write_reconciliation_audit(session, result)
        session.commit()
        _write_operator_reconciliation_logs(result)
        return result
    except CompletionCompositionUnknown as exc:
        session.rollback()
        result.errors.append(str(exc))
        result.assessment = ReconciliationAssessment.FAILED
        result.composition = "unknown"
        result.duration_ms = (time.perf_counter() - started) * 1000.0
        logger.exception(
            "Case completion composition unknown for case %s; failing closed",
            case_id,
        )
        try:
            _write_reconciliation_audit(session, result)
            session.commit()
            _write_operator_reconciliation_logs(result)
        except Exception:
            session.rollback()
        raise
    except Exception as exc:
        session.rollback()
        result.errors.append(str(exc))
        result.assessment = ReconciliationAssessment.FAILED
        if result.composition not in CaseIngestComposition.all():
            result.composition = "unknown"
        result.duration_ms = (time.perf_counter() - started) * 1000.0
        logger.exception("Case completion reconciliation failed for case %s", case_id)
        try:
            _write_reconciliation_audit(session, result)
            session.commit()
            _write_operator_reconciliation_logs(result)
        except Exception:
            session.rollback()
        return result


def build_phase1b_ingest_summary(session, case_id: int, case_uuid: Optional[str] = None) -> dict[str, Any]:
    """Read-model Phase 1B fragment derived from PG generation/batch state."""
    snapshot = snapshot_case_completion_authority(session, case_id=case_id, case_uuid=case_uuid)
    readiness = build_case_reconciliation_readiness(snapshot)
    return {
        "authority": "postgresql",
        "composition": snapshot["composition"],
        "batch_counts": {
            "staged": sum(1 for batch in snapshot["batches"] if batch.state == IngestBatchState.STAGED),
            "durable": sum(1 for batch in snapshot["batches"] if batch.state == IngestBatchState.DURABLE),
            "generations": len(snapshot["generations"]),
        },
        "sources": readiness["sources"],
    }


def default_production_hooks(*, case_id: int, case_uuid: str) -> ReconciliationHooks:
    """Queue existing idempotent tasks. Does not invent capability COMPLETE."""

    def _privacy(session, ingest_batch_id: str):
        from tasks.celery_tasks import derive_row_local_capability_batch_task
        derive_row_local_capability_batch_task.delay(
            ingest_batch_id=ingest_batch_id,
            capability=CapabilityName.PRIVACY_ALIASES,
        )

    def _d2(ingest_batch_id: str):
        from tasks.celery_tasks import reconcile_stale_staged_ingest_batches_task

        del ingest_batch_id
        reconcile_stale_staged_ingest_batches_task.apply_async(
            kwargs={"batch_size": 20},
            countdown=1,
        )

    def _graph():
        from tasks.celery_tasks import materialize_case_graph_task
        materialize_case_graph_task.apply_async(
            kwargs={"case_id": case_id, "case_uuid": case_uuid, "mode": "ingest"}
        )

    def _mitre():
        from tasks.celery_tasks import _queue_post_ingest_mitre_mapping
        _queue_post_ingest_mitre_mapping(case_id)

    def _embed():
        from tasks.celery_tasks import _queue_auto_event_embedding
        _queue_auto_event_embedding(
            case_id=case_id,
            case_uuid=case_uuid,
            scope="high_priority",
            source="f1_completion_reconciliation",
        )

    def _systems():
        from tasks.celery_tasks import discover_known_systems_task
        discover_known_systems_task.delay(case_id, case_uuid)

    def _users():
        from tasks.celery_tasks import discover_known_users_task
        discover_known_users_task.delay(case_id, case_uuid)

    return ReconciliationHooks(
        privacy_executor=_privacy,
        d2_invoker=_d2,
        graph_scheduler=_graph,
        mitre_scheduler=_mitre,
        embedding_scheduler=_embed,
        known_systems_scheduler=_systems,
        known_users_scheduler=_users,
    )


def _debounce_allows_schedule(case_id: int, reason: str) -> bool:
    try:
        from utils.progress import get_redis_client
        client = get_redis_client()
        key = f"completion_reconcile_debounce:{int(case_id)}"
        return bool(client.set(key, reason, nx=True, ex=RECONCILE_DEBOUNCE_TTL_SECONDS))
    except Exception:
        return True


def maybe_schedule_case_completion_reconciliation(
    *,
    case_id: int,
    case_uuid: Optional[str] = None,
    reason: str = "durable_authority",
    force: bool = False,
    scheduler: Optional[Callable[..., Any]] = None,
) -> Optional[str]:
    """Debounced schedule of the bounded case reconciliation task.

    Redis loss must not suppress scheduling. Pytest auto-schedule is disabled
    unless ``force`` is set so existing tranche tests do not enqueue work.
    """
    if _in_pytest() and not force:
        return None
    if scheduler is None:
        try:
            from tasks.celery_tasks import reconcile_case_completion_task
            def scheduler(case_id, case_uuid, reason):
                task = reconcile_case_completion_task.delay(
                    case_id=case_id,
                    case_uuid=case_uuid,
                    trigger_reason=reason,
                )
                return task.id
        except Exception:
            logger.warning(
                "Completion reconciliation scheduler unavailable for case %s",
                case_id,
                exc_info=True,
            )
            return None
    if not force and not _debounce_allows_schedule(case_id, reason):
        return None
    try:
        return scheduler(case_id, case_uuid, reason)
    except Exception:
        logger.warning(
            "Completion reconciliation schedule failed for case %s",
            case_id,
            exc_info=True,
        )
        return None
