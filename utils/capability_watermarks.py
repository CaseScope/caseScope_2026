"""Phase 1B Tranche E1 durable per-source capability watermark authority.

``case_capability_source_state`` is the current watermark row.
``case_capability_batch_completions`` is the normalized completion set used to
compute the hole-free contiguous prefix. The inherited JSON
``completed_batch_ordinals`` column is not completion authority.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Optional, Sequence

from sqlalchemy import and_, text
from sqlalchemy.exc import IntegrityError, OperationalError, ProgrammingError

from models.database_flow import (
    CapabilityDerivationClass,
    CapabilityName,
    CapabilityWatermarkStatus,
    CaseCapabilityBatchCompletion,
    CaseCapabilitySourceState,
    EvidenceGenerationState,
    EvidenceSourceGeneration,
    IngestBatch,
    IngestBatchState,
)


PRIVACY_ALIASES_V1 = "privacy-aliases:v1"
IOC_ENGINE_V1 = "ioc-engine:v1"
MITRE_RULES_V1 = "mitre-rules:v1"
GRAPH_EVENTS_V1 = "graph-events:v1"
KNOWN_PRINCIPALS_V1 = "known-principals:v1"
BEHAVIORAL_PROFILE_V1 = "behavioral-profile:v1"
PATTERN_DETECTION_V1 = "pattern-detection:v1"
EMBEDDING_V1 = "embedding:v1"

LOCKED_CAPABILITY_NAMES = tuple(CapabilityName.all())

CAPABILITY_INVENTORY = {
    CapabilityName.PRIVACY_ALIASES: {
        "class": CapabilityDerivationClass.ROW_LOCAL,
        "derivation_version": PRIVACY_ALIASES_V1,
        "e1_migrated": True,
        "batch_local_completion": True,
    },
    CapabilityName.IOC_MATCHES: {
        "class": CapabilityDerivationClass.ROW_LOCAL,
        "derivation_version": IOC_ENGINE_V1,
        "e1_migrated": False,
        "batch_local_completion": False,
        "blocker": "Current tag_all_iocs_globally is case-wide overlay tagging that resets per-IOC artifact state.",
    },
    CapabilityName.MITRE_MATCHES: {
        "class": CapabilityDerivationClass.ROW_LOCAL,
        "derivation_version": MITRE_RULES_V1,
        "e1_migrated": False,
        "batch_local_completion": False,
        "blocker": "Hayabusa MITRE is file-level EVTX ingest; procedure mapping is case-wide.",
    },
    CapabilityName.GRAPH_EXTRACTION: {
        "class": CapabilityDerivationClass.ADDITIVE_AGGREGATE,
        "derivation_version": GRAPH_EVENTS_V1,
        "e1_migrated": False,
        "batch_local_completion": False,
        "blocker": "Graph extraction is ROW_LOCAL plus ADDITIVE_AGGREGATE; current materializer is file/case scoped.",
    },
    CapabilityName.KNOWN_PRINCIPAL_DISCOVERY: {
        "class": CapabilityDerivationClass.ADDITIVE_AGGREGATE,
        "derivation_version": KNOWN_PRINCIPALS_V1,
        "e1_migrated": False,
        "batch_local_completion": False,
        "blocker": "Known user/system discovery remains a whole-case completion-tail additive aggregate.",
    },
    CapabilityName.BEHAVIORAL_PROFILE_CONTRIBUTION: {
        "class": CapabilityDerivationClass.ADDITIVE_AGGREGATE,
        "derivation_version": BEHAVIORAL_PROFILE_V1,
        "e1_migrated": False,
        "batch_local_completion": False,
        "blocker": "Behavioral profiles are generation-scoped additive aggregates, not batch-local facts.",
    },
    CapabilityName.PATTERN_DETECTION: {
        "class": CapabilityDerivationClass.WINDOWED_STATEFUL,
        "derivation_version": PATTERN_DETECTION_V1,
        "e1_migrated": False,
        "batch_local_completion": False,
        "blocker": "Pattern detection is WINDOWED_STATEFUL and must not use batch boundaries as detection boundaries.",
    },
    CapabilityName.EVENT_EMBEDDINGS: {
        "class": CapabilityDerivationClass.ROW_LOCAL,
        "derivation_version": EMBEDDING_V1,
        "e1_migrated": False,
        "batch_local_completion": False,
        "blocker": "Qdrant event embeddings remain LEK-current and are deferred to later Qdrant lifecycle work.",
    },
}

MIGRATED_ROW_LOCAL_CAPABILITIES = frozenset(
    name for name, spec in CAPABILITY_INVENTORY.items() if spec.get("e1_migrated")
)


class CapabilityWatermarkError(RuntimeError):
    """Raised when capability completion or gating cannot proceed safely."""


@dataclass(frozen=True)
class CapabilityCoverageResult:
    covered: bool
    reason: str
    capability: str
    derivation_version: str
    source_generation: Optional[int] = None
    generation_state: Optional[str] = None
    status: Optional[str] = None
    contiguous_batch_ordinal: Optional[int] = None
    missing_batch_ids: tuple[str, ...] = ()
    missing_erks: tuple[str, ...] = ()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def incremental_row_local_enabled(config: Any = None) -> bool:
    if config is None:
        from config import Config
        config = Config
    return bool(getattr(config, "PHASE1B_INCREMENTAL_ROW_LOCAL_DERIVATIONS_ENABLED", False))


def require_locked_capability(capability: str) -> str:
    if capability not in LOCKED_CAPABILITY_NAMES:
        raise CapabilityWatermarkError(f"unknown capability {capability!r}")
    return capability


def _identity_filter(
    model,
    *,
    case_id: int,
    capability: str,
    source_ref_type: str,
    source_ref_id: str,
    source_generation: int,
    derivation_version: str,
):
    return and_(
        model.case_id == int(case_id),
        model.capability == capability,
        model.source_ref_type == source_ref_type,
        model.source_ref_id == str(source_ref_id),
        model.source_generation == int(source_generation),
        model.derivation_version == derivation_version,
    )


def _load_generation(
    session,
    *,
    case_id: int,
    source_ref_type: str,
    source_ref_id: str,
    source_generation: int,
    for_update: bool = False,
) -> Optional[EvidenceSourceGeneration]:
    query = session.query(EvidenceSourceGeneration).filter_by(
        case_id=int(case_id),
        source_ref_type=source_ref_type,
        source_ref_id=str(source_ref_id),
        source_generation=int(source_generation),
    )
    if for_update:
        query = query.with_for_update()
    return query.one_or_none()


def resolve_default_capability_generation(
    session,
    *,
    case_id: int,
    source_ref_type: str,
    source_ref_id: str,
) -> Optional[EvidenceSourceGeneration]:
    """Return the generation that satisfies default/current capability gates.

    ACTIVE is preferred. BUILDING_INITIAL is used only when no ACTIVE generation
    exists. BUILDING_REPLACEMENT, SUPERSEDED, FAILED, and INVALIDATED never
    become default authority.
    """
    rows = (
        session.query(EvidenceSourceGeneration)
        .filter_by(
            case_id=int(case_id),
            source_ref_type=source_ref_type,
            source_ref_id=str(source_ref_id),
        )
        .all()
    )
    active = [row for row in rows if row.visibility_state == EvidenceGenerationState.ACTIVE]
    if active:
        return active[0]
    initial = [row for row in rows if row.visibility_state == EvidenceGenerationState.BUILDING_INITIAL]
    if initial and not any(row.visibility_state == EvidenceGenerationState.BUILDING_REPLACEMENT for row in rows):
        return initial[0]
    return None


def generation_satisfies_default_gate(generation: Optional[EvidenceSourceGeneration]) -> bool:
    if generation is None:
        return False
    return generation.visibility_state in {
        EvidenceGenerationState.ACTIVE,
        EvidenceGenerationState.BUILDING_INITIAL,
    }


def _watermark_gates(status: Optional[str]) -> bool:
    return status not in {
        None,
        CapabilityWatermarkStatus.FAILED,
        CapabilityWatermarkStatus.INVALIDATED,
    }


def _lock_or_create_watermark(
    session,
    *,
    case_id: int,
    capability: str,
    source_ref_type: str,
    source_ref_id: str,
    source_generation: int,
    derivation_version: str,
) -> CaseCapabilitySourceState:
    row = (
        session.query(CaseCapabilitySourceState)
        .filter(
            _identity_filter(
                CaseCapabilitySourceState,
                case_id=case_id,
                capability=capability,
                source_ref_type=source_ref_type,
                source_ref_id=source_ref_id,
                source_generation=source_generation,
                derivation_version=derivation_version,
            )
        )
        .with_for_update()
        .one_or_none()
    )
    if row is not None:
        return row
    nested = session.begin_nested()
    row = CaseCapabilitySourceState(
        case_id=int(case_id),
        capability=capability,
        source_ref_type=source_ref_type,
        source_ref_id=str(source_ref_id),
        source_generation=int(source_generation),
        derivation_version=derivation_version,
        contiguous_batch_ordinal=None,
        highest_completed_batch_ordinal=None,
        completed_batch_ordinals=[],
        status=CapabilityWatermarkStatus.NOT_STARTED,
        state_version=1,
        updated_at=_utcnow(),
    )
    session.add(row)
    try:
        session.flush()
        nested.commit()
    except IntegrityError:
        nested.rollback()
        row = (
            session.query(CaseCapabilitySourceState)
            .filter(
                _identity_filter(
                    CaseCapabilitySourceState,
                    case_id=case_id,
                    capability=capability,
                    source_ref_type=source_ref_type,
                    source_ref_id=source_ref_id,
                    source_generation=source_generation,
                    derivation_version=derivation_version,
                )
            )
            .with_for_update()
            .one()
        )
        return row
    return (
        session.query(CaseCapabilitySourceState)
        .filter_by(id=row.id)
        .with_for_update()
        .one()
    )


def _completed_ordinals_from(
    session,
    *,
    case_id: int,
    capability: str,
    source_ref_type: str,
    source_ref_id: str,
    source_generation: int,
    derivation_version: str,
    start_ordinal: int,
) -> list[int]:
    rows = (
        session.query(CaseCapabilityBatchCompletion.batch_ordinal)
        .filter(
            _identity_filter(
                CaseCapabilityBatchCompletion,
                case_id=case_id,
                capability=capability,
                source_ref_type=source_ref_type,
                source_ref_id=source_ref_id,
                source_generation=source_generation,
                derivation_version=derivation_version,
            ),
            CaseCapabilityBatchCompletion.batch_ordinal >= int(start_ordinal),
        )
        .order_by(CaseCapabilityBatchCompletion.batch_ordinal.asc())
        .all()
    )
    return [int(row[0]) for row in rows]


def compute_contiguous_prefix(ordinals: Iterable[int]) -> Optional[int]:
    completed = {int(ordinal) for ordinal in ordinals}
    if 0 not in completed:
        return None
    current = 0
    while current + 1 in completed:
        current += 1
    return current


def _advance_contiguous_prefix(current: Optional[int], later_ordinals: Sequence[int]) -> Optional[int]:
    expected = 0 if current is None else int(current) + 1
    advanced = current
    for ordinal in later_ordinals:
        if int(ordinal) != expected:
            break
        advanced = int(ordinal)
        expected += 1
    return advanced


def _generation_fully_capability_complete(
    session,
    generation: EvidenceSourceGeneration,
    *,
    contiguous: Optional[int],
    capability: str,
    derivation_version: str,
) -> bool:
    if generation.completed_at is None or generation.expected_rows is None:
        return False
    if int(generation.expected_rows) == 0:
        if generation.final_batch_ordinal is not None:
            return False
        batch_count = session.query(IngestBatch).filter_by(generation_id=generation.id).count()
        return batch_count == 0 and contiguous is None
    if generation.final_batch_ordinal is None:
        return False
    final_ordinal = int(generation.final_batch_ordinal)
    if contiguous is None or int(contiguous) != final_ordinal:
        return False
    batches = (
        session.query(IngestBatch)
        .filter_by(generation_id=generation.id)
        .all()
    )
    expected = set(range(final_ordinal + 1))
    observed = {int(batch.batch_ordinal) for batch in batches}
    if observed != expected:
        return False
    if any(batch.state != IngestBatchState.DURABLE for batch in batches):
        return False
    completed = set(
        _completed_ordinals_from(
            session,
            case_id=generation.case_id,
            capability=capability,
            source_ref_type=generation.source_ref_type,
            source_ref_id=generation.source_ref_id,
            source_generation=generation.source_generation,
            derivation_version=derivation_version,
            start_ordinal=0,
        )
    )
    return completed == expected


def _compute_status(
    session,
    generation: Optional[EvidenceSourceGeneration],
    watermark: CaseCapabilitySourceState,
    *,
    contiguous: Optional[int],
    has_completion: bool,
) -> str:
    if watermark.status == CapabilityWatermarkStatus.INVALIDATED:
        return CapabilityWatermarkStatus.INVALIDATED
    if watermark.status == CapabilityWatermarkStatus.FAILED:
        return CapabilityWatermarkStatus.FAILED
    if generation is not None and generation.visibility_state == EvidenceGenerationState.INVALIDATED:
        return CapabilityWatermarkStatus.INVALIDATED
    if generation is not None and _generation_fully_capability_complete(
        session,
        generation,
        contiguous=contiguous,
        capability=watermark.capability,
        derivation_version=watermark.derivation_version,
    ):
        return CapabilityWatermarkStatus.COMPLETE
    if contiguous is not None:
        return CapabilityWatermarkStatus.CONTIGUOUS_READY
    if has_completion:
        return CapabilityWatermarkStatus.IN_PROGRESS
    return CapabilityWatermarkStatus.NOT_STARTED


def _refresh_watermark_row(
    session,
    watermark: CaseCapabilitySourceState,
    generation: Optional[EvidenceSourceGeneration],
    *,
    inserted: bool,
) -> CaseCapabilitySourceState:
    if watermark.status in {CapabilityWatermarkStatus.INVALIDATED, CapabilityWatermarkStatus.FAILED}:
        return watermark
    start = 0 if watermark.contiguous_batch_ordinal is None else int(watermark.contiguous_batch_ordinal) + 1
    later = _completed_ordinals_from(
        session,
        case_id=watermark.case_id,
        capability=watermark.capability,
        source_ref_type=watermark.source_ref_type,
        source_ref_id=watermark.source_ref_id,
        source_generation=watermark.source_generation,
        derivation_version=watermark.derivation_version,
        start_ordinal=start,
    )
    new_contiguous = _advance_contiguous_prefix(watermark.contiguous_batch_ordinal, later)
    highest_row = (
        session.query(CaseCapabilityBatchCompletion.batch_ordinal)
        .filter(
            _identity_filter(
                CaseCapabilityBatchCompletion,
                case_id=watermark.case_id,
                capability=watermark.capability,
                source_ref_type=watermark.source_ref_type,
                source_ref_id=watermark.source_ref_id,
                source_generation=watermark.source_generation,
                derivation_version=watermark.derivation_version,
            )
        )
        .order_by(CaseCapabilityBatchCompletion.batch_ordinal.desc())
        .first()
    )
    new_highest = None if highest_row is None else int(highest_row[0])
    if (
        new_contiguous is not None
        and watermark.contiguous_batch_ordinal is not None
        and int(new_contiguous) < int(watermark.contiguous_batch_ordinal)
    ):
        raise CapabilityWatermarkError("contiguous_batch_ordinal cannot regress")
    has_completion = new_highest is not None
    new_status = _compute_status(
        session,
        generation,
        watermark,
        contiguous=new_contiguous,
        has_completion=has_completion,
    )
    changed = (
        watermark.contiguous_batch_ordinal != new_contiguous
        or watermark.highest_completed_batch_ordinal != new_highest
        or watermark.status != new_status
    )
    if not changed and not inserted:
        return watermark
    if changed:
        watermark.contiguous_batch_ordinal = new_contiguous
        watermark.highest_completed_batch_ordinal = new_highest
        watermark.status = new_status
        watermark.state_version = int(watermark.state_version or 1) + 1
        watermark.updated_at = _utcnow()
        watermark.completed_batch_ordinals = []
    elif inserted:
        watermark.updated_at = _utcnow()
    session.flush()
    return watermark


def record_capability_batch_completion(
    *,
    session,
    case_id: int,
    capability: str,
    source_ref_type: str,
    source_ref_id: str,
    source_generation: int,
    derivation_version: str,
    ingest_batch_id: str,
) -> CaseCapabilitySourceState:
    """Record one durable-batch derivation completion and advance the prefix."""
    require_locked_capability(capability)
    batch = (
        session.query(IngestBatch)
        .filter_by(ingest_batch_id=str(ingest_batch_id))
        .one_or_none()
    )
    if batch is None:
        raise CapabilityWatermarkError(f"unknown ingest_batch_id {ingest_batch_id}")
    if batch.state != IngestBatchState.DURABLE:
        raise CapabilityWatermarkError(
            f"capability completion refused for non-DURABLE batch {ingest_batch_id}"
        )
    generation = session.query(EvidenceSourceGeneration).filter_by(id=batch.generation_id).one()
    if (
        int(generation.case_id) != int(case_id)
        or generation.source_ref_type != source_ref_type
        or str(generation.source_ref_id) != str(source_ref_id)
        or int(generation.source_generation) != int(source_generation)
    ):
        raise CapabilityWatermarkError("completion identity does not match ingest batch generation")
    if generation.visibility_state == EvidenceGenerationState.INVALIDATED:
        raise CapabilityWatermarkError("cannot record completion for an INVALIDATED generation")
    if generation.visibility_state == EvidenceGenerationState.FAILED:
        raise CapabilityWatermarkError("cannot record completion for a FAILED generation")

    existing = (
        session.query(CaseCapabilityBatchCompletion)
        .filter(
            _identity_filter(
                CaseCapabilityBatchCompletion,
                case_id=case_id,
                capability=capability,
                source_ref_type=source_ref_type,
                source_ref_id=source_ref_id,
                source_generation=source_generation,
                derivation_version=derivation_version,
            ),
            CaseCapabilityBatchCompletion.ingest_batch_id == str(ingest_batch_id),
        )
        .one_or_none()
    )
    inserted = False
    if existing is None:
        nested = session.begin_nested()
        session.add(
            CaseCapabilityBatchCompletion(
                case_id=int(case_id),
                capability=capability,
                source_ref_type=source_ref_type,
                source_ref_id=str(source_ref_id),
                source_generation=int(source_generation),
                derivation_version=derivation_version,
                ingest_batch_id=str(ingest_batch_id),
                batch_ordinal=int(batch.batch_ordinal),
                completed_at=_utcnow(),
            )
        )
        try:
            session.flush()
            nested.commit()
            inserted = True
        except IntegrityError:
            nested.rollback()
            inserted = False

    watermark = _lock_or_create_watermark(
        session,
        case_id=case_id,
        capability=capability,
        source_ref_type=source_ref_type,
        source_ref_id=source_ref_id,
        source_generation=source_generation,
        derivation_version=derivation_version,
    )
    if watermark.status == CapabilityWatermarkStatus.INVALIDATED:
        return watermark
    return _refresh_watermark_row(session, watermark, generation, inserted=inserted)


def record_zero_event_capability_completion(
    *,
    session,
    generation: EvidenceSourceGeneration,
    capability: str,
    derivation_version: str,
) -> CaseCapabilitySourceState:
    """Mark a legitimate zero-event generation COMPLETE without fake batches."""
    require_locked_capability(capability)
    if generation.completed_at is None or generation.expected_rows is None:
        raise CapabilityWatermarkError("zero-event capability completion requires durable ingest EOF")
    if int(generation.expected_rows) != 0 or generation.final_batch_ordinal is not None:
        raise CapabilityWatermarkError("generation is not a zero-event EOF declaration")
    if session.query(IngestBatch).filter_by(generation_id=generation.id).count():
        raise CapabilityWatermarkError("zero-event generation must not have ingest batches")
    watermark = _lock_or_create_watermark(
        session,
        case_id=generation.case_id,
        capability=capability,
        source_ref_type=generation.source_ref_type,
        source_ref_id=generation.source_ref_id,
        source_generation=generation.source_generation,
        derivation_version=derivation_version,
    )
    if watermark.status == CapabilityWatermarkStatus.INVALIDATED:
        return watermark
    if watermark.status == CapabilityWatermarkStatus.COMPLETE and watermark.contiguous_batch_ordinal is None:
        return watermark
    watermark.contiguous_batch_ordinal = None
    watermark.highest_completed_batch_ordinal = None
    watermark.completed_batch_ordinals = []
    watermark.status = CapabilityWatermarkStatus.COMPLETE
    watermark.state_version = int(watermark.state_version or 1) + 1
    watermark.updated_at = _utcnow()
    session.flush()
    return watermark


def mark_capability_failed(
    *,
    session,
    case_id: int,
    capability: str,
    source_ref_type: str,
    source_ref_id: str,
    source_generation: int,
    derivation_version: str,
    reason: str,
) -> CaseCapabilitySourceState:
    require_locked_capability(capability)
    watermark = _lock_or_create_watermark(
        session,
        case_id=case_id,
        capability=capability,
        source_ref_type=source_ref_type,
        source_ref_id=source_ref_id,
        source_generation=source_generation,
        derivation_version=derivation_version,
    )
    if watermark.status == CapabilityWatermarkStatus.FAILED:
        return watermark
    watermark.status = CapabilityWatermarkStatus.FAILED
    watermark.failure_reason = reason
    watermark.state_version = int(watermark.state_version or 1) + 1
    watermark.updated_at = _utcnow()
    session.flush()
    return watermark


def _watermark_control_plane_available(session) -> bool:
    """Return True only when the E1 watermark table exists on this connection.

    Uses the current session connection so SQLite ``:memory:`` fixtures that
    never created the control-plane tables stay on the same database. A
    savepoint keeps a missing-catalog failure from aborting the caller
    transaction.
    """
    nested = session.begin_nested()
    try:
        table = CaseCapabilitySourceState.__tablename__
        dialect = session.connection().dialect.name
        if dialect == "sqlite":
            found = session.execute(
                text("SELECT 1 FROM sqlite_master WHERE type='table' AND name=:n"),
                {"n": table},
            ).scalar()
        else:
            found = session.execute(
                text(
                    "SELECT 1 FROM information_schema.tables "
                    "WHERE table_schema = current_schema() AND table_name = :n"
                ),
                {"n": table},
            ).scalar()
        nested.commit()
        return bool(found)
    except (OperationalError, ProgrammingError):
        nested.rollback()
        return False


def refresh_generation_capability_watermarks(
    *,
    session,
    generation: EvidenceSourceGeneration,
) -> list[CaseCapabilitySourceState]:
    """Recompute stored status after D1 EOF or other generation completeness changes."""
    if not _watermark_control_plane_available(session):
        return []
    rows = (
        session.query(CaseCapabilitySourceState)
        .filter_by(
            case_id=generation.case_id,
            source_ref_type=generation.source_ref_type,
            source_ref_id=generation.source_ref_id,
            source_generation=generation.source_generation,
        )
        .with_for_update()
        .all()
    )
    refreshed = []
    for row in rows:
        if row.status in {CapabilityWatermarkStatus.INVALIDATED, CapabilityWatermarkStatus.FAILED}:
            continue
        refreshed.append(_refresh_watermark_row(session, row, generation, inserted=False))
    return refreshed


def invalidate_generation_capability_state(
    *,
    session,
    generation: EvidenceSourceGeneration,
) -> list[CaseCapabilitySourceState]:
    """Withdraw capability gates for one invalidated generation. History is kept."""
    if not _watermark_control_plane_available(session):
        return []
    rows = (
        session.query(CaseCapabilitySourceState)
        .filter_by(
            case_id=generation.case_id,
            source_ref_type=generation.source_ref_type,
            source_ref_id=generation.source_ref_id,
            source_generation=generation.source_generation,
        )
        .with_for_update()
        .all()
    )
    changed = []
    for row in rows:
        if row.status == CapabilityWatermarkStatus.INVALIDATED:
            continue
        row.status = CapabilityWatermarkStatus.INVALIDATED
        row.state_version = int(row.state_version or 1) + 1
        row.updated_at = _utcnow()
        changed.append(row)
    session.flush()
    return changed


def get_capability_watermark(
    session,
    *,
    case_id: int,
    capability: str,
    source_ref_type: str,
    source_ref_id: str,
    source_generation: int,
    derivation_version: str,
) -> Optional[CaseCapabilitySourceState]:
    return (
        session.query(CaseCapabilitySourceState)
        .filter(
            _identity_filter(
                CaseCapabilitySourceState,
                case_id=case_id,
                capability=capability,
                source_ref_type=source_ref_type,
                source_ref_id=source_ref_id,
                source_generation=source_generation,
                derivation_version=derivation_version,
            )
        )
        .one_or_none()
    )


def _coverage_for_watermark(
    session,
    *,
    generation: Optional[EvidenceSourceGeneration],
    watermark: Optional[CaseCapabilitySourceState],
    required_batch_ordinal: Optional[int],
) -> CapabilityCoverageResult:
    if generation is None:
        return CapabilityCoverageResult(
            covered=False,
            reason="generation_not_found",
            capability="",
            derivation_version="",
        )
    if generation.visibility_state in {
        EvidenceGenerationState.SUPERSEDED,
        EvidenceGenerationState.FAILED,
        EvidenceGenerationState.INVALIDATED,
    }:
        return CapabilityCoverageResult(
            covered=False,
            reason=f"generation_{generation.visibility_state.lower()}",
            capability=watermark.capability if watermark else "",
            derivation_version=watermark.derivation_version if watermark else "",
            source_generation=generation.source_generation,
            generation_state=generation.visibility_state,
            status=None if watermark is None else watermark.status,
            contiguous_batch_ordinal=None if watermark is None else watermark.contiguous_batch_ordinal,
        )
    if watermark is None:
        return CapabilityCoverageResult(
            covered=False,
            reason="watermark_not_started",
            capability="",
            derivation_version="",
            source_generation=generation.source_generation,
            generation_state=generation.visibility_state,
            status=CapabilityWatermarkStatus.NOT_STARTED,
        )
    if not _watermark_gates(watermark.status):
        return CapabilityCoverageResult(
            covered=False,
            reason=f"status_{watermark.status.lower()}",
            capability=watermark.capability,
            derivation_version=watermark.derivation_version,
            source_generation=generation.source_generation,
            generation_state=generation.visibility_state,
            status=watermark.status,
            contiguous_batch_ordinal=watermark.contiguous_batch_ordinal,
        )
    if required_batch_ordinal is None:
        live_complete = _generation_fully_capability_complete(
            session,
            generation,
            contiguous=watermark.contiguous_batch_ordinal,
            capability=watermark.capability,
            derivation_version=watermark.derivation_version,
        )
        covered = watermark.status == CapabilityWatermarkStatus.COMPLETE or live_complete
        return CapabilityCoverageResult(
            covered=covered,
            reason="complete" if covered else "not_complete",
            capability=watermark.capability,
            derivation_version=watermark.derivation_version,
            source_generation=generation.source_generation,
            generation_state=generation.visibility_state,
            status=watermark.status,
            contiguous_batch_ordinal=watermark.contiguous_batch_ordinal,
        )
    if watermark.contiguous_batch_ordinal is None:
        return CapabilityCoverageResult(
            covered=False,
            reason="no_contiguous_prefix",
            capability=watermark.capability,
            derivation_version=watermark.derivation_version,
            source_generation=generation.source_generation,
            generation_state=generation.visibility_state,
            status=watermark.status,
            contiguous_batch_ordinal=None,
        )
    covered = int(watermark.contiguous_batch_ordinal) >= int(required_batch_ordinal)
    return CapabilityCoverageResult(
        covered=covered,
        reason="contiguous_prefix" if covered else "contiguous_prefix_insufficient",
        capability=watermark.capability,
        derivation_version=watermark.derivation_version,
        source_generation=generation.source_generation,
        generation_state=generation.visibility_state,
        status=watermark.status,
        contiguous_batch_ordinal=watermark.contiguous_batch_ordinal,
    )


def is_source_capability_covered(
    session,
    *,
    case_id: int,
    capability: str,
    source_ref_type: str,
    source_ref_id: str,
    source_generation: int,
    derivation_version: str,
    required_batch_ordinal: Optional[int] = None,
) -> CapabilityCoverageResult:
    """Exact generation coverage. Does not fall back to another generation."""
    require_locked_capability(capability)
    generation = _load_generation(
        session,
        case_id=case_id,
        source_ref_type=source_ref_type,
        source_ref_id=source_ref_id,
        source_generation=source_generation,
    )
    watermark = get_capability_watermark(
        session,
        case_id=case_id,
        capability=capability,
        source_ref_type=source_ref_type,
        source_ref_id=source_ref_id,
        source_generation=source_generation,
        derivation_version=derivation_version,
    )
    return _coverage_for_watermark(
        session,
        generation=generation,
        watermark=watermark,
        required_batch_ordinal=required_batch_ordinal,
    )


def is_current_source_capability_covered(
    session,
    *,
    case_id: int,
    capability: str,
    source_ref_type: str,
    source_ref_id: str,
    derivation_version: str,
    required_batch_ordinal: Optional[int] = None,
) -> CapabilityCoverageResult:
    """Default-generation gate. Never uses BUILDING_REPLACEMENT or SUPERSEDED."""
    require_locked_capability(capability)
    generation = resolve_default_capability_generation(
        session,
        case_id=case_id,
        source_ref_type=source_ref_type,
        source_ref_id=source_ref_id,
    )
    if generation is None or not generation_satisfies_default_gate(generation):
        return CapabilityCoverageResult(
            covered=False,
            reason="no_default_generation",
            capability=capability,
            derivation_version=derivation_version,
        )
    return is_source_capability_covered(
        session,
        case_id=case_id,
        capability=capability,
        source_ref_type=source_ref_type,
        source_ref_id=source_ref_id,
        source_generation=generation.source_generation,
        derivation_version=derivation_version,
        required_batch_ordinal=required_batch_ordinal,
    )


def verify_capability_batch_coverage(
    session,
    *,
    capability: str,
    derivation_version: str,
    batch_ids: Sequence[str],
) -> CapabilityCoverageResult:
    """Fail if any frozen ingest_batch_id lacks durable capability completion."""
    require_locked_capability(capability)
    wanted = [str(batch_id) for batch_id in batch_ids]
    if not wanted:
        return CapabilityCoverageResult(
            covered=False,
            reason="empty_batch_set",
            capability=capability,
            derivation_version=derivation_version,
        )
    batches = (
        session.query(IngestBatch)
        .filter(IngestBatch.ingest_batch_id.in_(wanted))
        .all()
    )
    by_id = {batch.ingest_batch_id: batch for batch in batches}
    missing = [batch_id for batch_id in wanted if batch_id not in by_id]
    if missing:
        return CapabilityCoverageResult(
            covered=False,
            reason="unknown_batch_ids",
            capability=capability,
            derivation_version=derivation_version,
            missing_batch_ids=tuple(missing),
        )
    non_durable = [
        batch.ingest_batch_id
        for batch in batches
        if batch.state != IngestBatchState.DURABLE
    ]
    if non_durable:
        return CapabilityCoverageResult(
            covered=False,
            reason="non_durable_batches",
            capability=capability,
            derivation_version=derivation_version,
            missing_batch_ids=tuple(non_durable),
        )
    missing_completion = []
    for batch in batches:
        generation = batch.generation
        completion = (
            session.query(CaseCapabilityBatchCompletion)
            .filter(
                _identity_filter(
                    CaseCapabilityBatchCompletion,
                    case_id=generation.case_id,
                    capability=capability,
                    source_ref_type=generation.source_ref_type,
                    source_ref_id=generation.source_ref_id,
                    source_generation=generation.source_generation,
                    derivation_version=derivation_version,
                ),
                CaseCapabilityBatchCompletion.ingest_batch_id == batch.ingest_batch_id,
            )
            .one_or_none()
        )
        watermark = get_capability_watermark(
            session,
            case_id=generation.case_id,
            capability=capability,
            source_ref_type=generation.source_ref_type,
            source_ref_id=generation.source_ref_id,
            source_generation=generation.source_generation,
            derivation_version=derivation_version,
        )
        if completion is None or watermark is None or not _watermark_gates(watermark.status):
            missing_completion.append(batch.ingest_batch_id)
            continue
        if generation.visibility_state in {
            EvidenceGenerationState.SUPERSEDED,
            EvidenceGenerationState.FAILED,
            EvidenceGenerationState.INVALIDATED,
        }:
            missing_completion.append(batch.ingest_batch_id)
    if missing_completion:
        return CapabilityCoverageResult(
            covered=False,
            reason="uncovered_batches",
            capability=capability,
            derivation_version=derivation_version,
            missing_batch_ids=tuple(missing_completion),
        )
    return CapabilityCoverageResult(
        covered=True,
        reason="exact_batch_set_covered",
        capability=capability,
        derivation_version=derivation_version,
    )


def resolve_erk_ingest_batch_ids(
    clickhouse_client,
    *,
    case_id: int,
    evidence_record_keys: Sequence[str],
) -> dict[str, Optional[str]]:
    """Map ERKs to ingest_batch_id from published ClickHouse event rows."""
    keys = [str(key) for key in evidence_record_keys if str(key or "").strip()]
    mapping = {key: None for key in keys}
    if not keys:
        return mapping
    result = clickhouse_client.query(
        """
        SELECT
            evidence_record_key,
            any(ingest_batch_id) AS ingest_batch_id
        FROM events
        WHERE case_id = {case_id:UInt32}
          AND evidence_record_key IN {keys:Array(String)}
        GROUP BY evidence_record_key
        """,
        parameters={"case_id": int(case_id), "keys": keys},
    )
    for evidence_record_key, ingest_batch_id in result.result_rows:
        mapping[str(evidence_record_key)] = str(ingest_batch_id or "") or None
    return mapping


def verify_capability_erk_coverage(
    session,
    clickhouse_client,
    *,
    case_id: int,
    capability: str,
    derivation_version: str,
    evidence_record_keys: Sequence[str],
) -> CapabilityCoverageResult:
    """ERK coverage is batch-membership coverage, not per-ERK alias rows."""
    mapping = resolve_erk_ingest_batch_ids(
        clickhouse_client,
        case_id=case_id,
        evidence_record_keys=evidence_record_keys,
    )
    missing_erks = [key for key, batch_id in mapping.items() if not batch_id]
    if missing_erks:
        return CapabilityCoverageResult(
            covered=False,
            reason="erk_missing_ingest_batch",
            capability=capability,
            derivation_version=derivation_version,
            missing_erks=tuple(missing_erks),
        )
    return verify_capability_batch_coverage(
        session,
        capability=capability,
        derivation_version=derivation_version,
        batch_ids=tuple(batch_id for batch_id in mapping.values() if batch_id),
    )


def missing_activation_capability_requirements(
    session,
    generation: EvidenceSourceGeneration,
    required: Sequence[str],
) -> tuple[str, ...]:
    """Return declared activation-blocking capabilities that are not COMPLETE."""
    missing = []
    for item in required:
        if ":" in item:
            capability, derivation_version = item.split(":", 1)
        else:
            spec = CAPABILITY_INVENTORY.get(item, {})
            capability = item
            derivation_version = spec.get("derivation_version") or ""
        result = is_source_capability_covered(
            session,
            case_id=generation.case_id,
            capability=capability,
            source_ref_type=generation.source_ref_type,
            source_ref_id=generation.source_ref_id,
            source_generation=generation.source_generation,
            derivation_version=derivation_version,
        )
        if not result.covered:
            missing.append(item)
    return tuple(missing)
