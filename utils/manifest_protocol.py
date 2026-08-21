"""Phase 1B Tranche B manifest protocol engine.

This module implements the CASE_FILE BUILDING_INITIAL durable batch protocol
without enabling any production parser by default.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from sqlalchemy import func

from models.case_file import CaseFile, IngestProtocolOrigin
from models.database_flow import (
    EvidenceGenerationAudit,
    EvidenceGenerationState,
    EvidenceSourceGeneration,
    IngestAttempt,
    IngestBatch,
    IngestBatchState,
    SourceRefType,
)
from parsers.base import ParsedEvent
from utils.ingest_fence import exclusive_ingest_fence, shared_ingest_admission
from utils.ingest_identity import (
    BATCHING_CONTRACT_VERSION,
    batch_content_hash,
    batch_content_hash_for_ordinals,
    canonical_source_locator,
    deterministic_ingest_batch_id,
    ingest_row_hash,
    validate_zero_based_manifest_ordinals,
)
from utils.ingest_metrics import emit_metric, estimate_rows_bytes, timed_stage


MANIFEST_PROTOCOL_COLUMNS = (
    "source_ref_type",
    "source_ref_id",
    "source_generation",
    "ingest_batch_id",
    "ingest_row_ordinal",
    "ingest_row_hash",
    "ingest_attempt_id",
)

DEFAULT_INGEST_ATTEMPT_LEASE_SECONDS = 18_000

INGEST_MODE_LEGACY = "LEGACY"
INGEST_MODE_MANAGED_INITIAL = "MANAGED_INITIAL"
INGEST_MODE_MANAGED_REPLACEMENT = "MANAGED_REPLACEMENT"

PROTOCOL_CLICKHOUSE_COLUMNS = tuple(ParsedEvent.clickhouse_columns()) + MANIFEST_PROTOCOL_COLUMNS

VISIBLE_EVIDENCE_GENERATIONS_COLUMNS = (
    "case_id",
    "source_ref_type",
    "source_ref_id",
    "source_generation",
    "visibility_state",
    "state_version",
    "publishable",
    "updated_at",
)

DURABLE_INGEST_BATCHES_COLUMNS = (
    "ingest_batch_id",
    "case_id",
    "source_ref_type",
    "source_ref_id",
    "source_generation",
    "batch_ordinal",
    "expected_row_count",
    "batch_content_hash",
    "state",
    "state_version",
    "durable_at",
    "updated_at",
)


class ManifestProtocolError(RuntimeError):
    """Base error for managed manifest protocol failures."""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _schedule_completion_reconciliation(session, generation, *, reason: str) -> None:
    """Best-effort F1 trigger. Pytest auto-schedule is disabled inside the helper."""
    if generation is None:
        return
    try:
        from models.case import Case
        from utils.completion_reconciler import maybe_schedule_case_completion_reconciliation

        case = session.get(Case, int(generation.case_id))
        maybe_schedule_case_completion_reconciliation(
            case_id=int(generation.case_id),
            case_uuid=case.uuid if case is not None else None,
            reason=reason,
        )
    except Exception:
        return


class ManifestEligibilityError(ManifestProtocolError):
    """Raised when a source/parser is not eligible for managed ingest."""


class GenerationAllocationError(ManifestProtocolError):
    """Raised when CASE_FILE generation allocation cannot proceed safely."""


class FrozenGenerationMismatch(ManifestProtocolError):
    """Raised when retry inputs do not match the frozen generation contract."""


class ManifestMismatchError(ManifestProtocolError):
    """Raised when an existing STAGED manifest conflicts with expected input."""


class ManifestRoutingError(ManifestProtocolError):
    """Raised when an existing managed source cannot safely route."""


class ActivationCompletenessError(ManifestProtocolError):
    """Raised when a generation does not satisfy activation gates."""


class ReplacementInProgressError(ManifestProtocolError):
    """Raised when an explicit reprocess already has an open replacement."""


@dataclass(frozen=True)
class ManifestParserContract:
    parser_version: str
    normalization_version: str
    configured_batch_size: int
    ordering_contract: str
    producer_version: Optional[str] = None
    manifest_eligible: bool = False
    batching_contract_version: str = BATCHING_CONTRACT_VERSION


@dataclass(frozen=True)
class ProtocolRow:
    ordinal: int
    event: ParsedEvent
    clickhouse_row: Tuple[Any, ...]
    ingest_row_hash: str
    source_locator: Optional[dict]


@dataclass(frozen=True)
class ManagedBatch:
    ingest_batch_id: str
    generation: EvidenceSourceGeneration
    batch_ordinal: int
    rows: Tuple[ProtocolRow, ...]
    row_hashes: Tuple[str, ...]
    batch_content_hash: str
    first_source_locator: Optional[dict]
    last_source_locator: Optional[dict]
    ingest_attempt_id: str

    @property
    def row_count(self) -> int:
        return len(self.rows)

    @property
    def clickhouse_rows(self) -> Tuple[Tuple[Any, ...], ...]:
        return tuple(row.clickhouse_row for row in self.rows)


@dataclass(frozen=True)
class BatchVerificationResult:
    outcome: str
    success: bool
    retry_equivalent_duplicate: bool = False
    physical_rows: int = 0
    duplicate_physical_rows: int = 0
    message: str = ""


@dataclass(frozen=True)
class ActivationCompletenessResult:
    complete: bool
    errors: Tuple[str, ...] = ()
    required_derivations: Tuple[str, ...] = ()

    def require_complete(self) -> None:
        if not self.complete:
            raise ActivationCompletenessError("; ".join(self.errors) or "activation completeness failed")


def parser_manifest_eligible(parser: Any, config: Any = None) -> bool:
    enabled = bool(getattr(config, "PHASE1B_MANIFEST_PROTOCOL_ENABLED", False)) if config else False
    return (
        enabled
        and bool(getattr(parser, "supports_manifest_protocol", False))
        and bool(getattr(parser, "manifest_ordering_contract", None))
    )


def _parser_manifest_capable(parser: Any) -> bool:
    return bool(
        getattr(parser, "supports_manifest_protocol", False)
        and getattr(parser, "manifest_ordering_contract", None)
    )


def _case_file_case_id(case_file: Any) -> Optional[int]:
    if hasattr(case_file, "case_id"):
        value = getattr(case_file, "case_id", None)
        return int(value) if value is not None else None
    case_uuid = getattr(case_file, "case_uuid", None)
    if case_uuid:
        from models.case import Case

        case = Case.query.filter_by(uuid=case_uuid).first()
        return int(case.id) if case else None
    return None


def _existing_generations_for_case_file(session: Any, *, case_id: int, case_file_id: int) -> List[EvidenceSourceGeneration]:
    return (
        session.query(EvidenceSourceGeneration)
        .filter(
            EvidenceSourceGeneration.case_id == int(case_id),
            EvidenceSourceGeneration.source_ref_type == SourceRefType.CASE_FILE,
            EvidenceSourceGeneration.source_ref_id == str(case_file_id),
        )
        .order_by(EvidenceSourceGeneration.source_generation.asc())
        .all()
    )


def select_case_file_ingest_mode(*, parser: Any, case_file: Any, config: Any, session: Any = None) -> str:
    if not case_file or not getattr(case_file, "id", None):
        return INGEST_MODE_LEGACY
    if session is not None:
        case_id = _case_file_case_id(case_file)
        if case_id is None:
            return INGEST_MODE_LEGACY
        generations = _existing_generations_for_case_file(
            session,
            case_id=case_id,
            case_file_id=int(case_file.id),
        )
        if generations:
            building_initial = [
                generation
                for generation in generations
                if generation.visibility_state == EvidenceGenerationState.BUILDING_INITIAL
            ]
            active = [
                generation
                for generation in generations
                if generation.visibility_state == EvidenceGenerationState.ACTIVE
            ]
            building_replacement = [
                generation
                for generation in generations
                if generation.visibility_state == EvidenceGenerationState.BUILDING_REPLACEMENT
            ]
            if not _parser_manifest_capable(parser):
                raise ManifestRoutingError("Existing managed generation requires a manifest-capable parser")
            if building_initial:
                if len(building_initial) != 1 or len(generations) != 1:
                    raise ManifestRoutingError("Existing BUILDING_INITIAL source has unsupported companion generations")
                generation = building_initial[0]
                if getattr(parser, "manifest_ordering_contract", None) != generation.ordering_contract:
                    raise ManifestRoutingError("Existing managed generation ordering contract mismatch")
                if getattr(parser, "parser_version", None) != generation.parser_version:
                    raise ManifestRoutingError("Existing managed generation parser version mismatch")
                return INGEST_MODE_MANAGED_INITIAL
            if active:
                if len(active) != 1:
                    raise ManifestRoutingError("Existing managed source has multiple ACTIVE generations")
                if building_replacement:
                    if len(building_replacement) != 1:
                        raise ManifestRoutingError("Existing managed source has multiple replacement generations")
                    replacement = building_replacement[0]
                    if getattr(parser, "manifest_ordering_contract", None) != replacement.ordering_contract:
                        raise ManifestRoutingError("Existing replacement generation ordering contract mismatch")
                    if getattr(parser, "parser_version", None) != replacement.parser_version:
                        raise ManifestRoutingError("Existing replacement generation parser version mismatch")
                    return INGEST_MODE_MANAGED_REPLACEMENT
                active_generation = active[0]
                if getattr(parser, "manifest_ordering_contract", None) != active_generation.ordering_contract:
                    raise ManifestRoutingError("Existing ACTIVE generation ordering contract mismatch")
                if getattr(parser, "parser_version", None) != active_generation.parser_version:
                    raise ManifestRoutingError("Existing ACTIVE generation parser version mismatch")
                return INGEST_MODE_MANAGED_REPLACEMENT
            raise ManifestRoutingError("Existing managed generation state is unsupported")
    if parser_manifest_eligible(parser, config):
        if getattr(case_file, "ingest_protocol_origin", None) == "not_started":
            return INGEST_MODE_MANAGED_INITIAL
    return INGEST_MODE_LEGACY


def contract_from_parser(
    parser: Any,
    *,
    configured_batch_size: int,
    normalization_version: str,
    producer_version: Optional[str] = None,
    config: Any = None,
    require_global_flag: bool = True,
) -> ManifestParserContract:
    eligible = parser_manifest_eligible(parser, config) if require_global_flag else _parser_manifest_capable(parser)
    if not eligible:
        raise ManifestEligibilityError("parser/source is not manifest-protocol eligible")
    return ManifestParserContract(
        parser_version=str(getattr(parser, "parser_version")),
        normalization_version=str(normalization_version),
        configured_batch_size=int(configured_batch_size),
        ordering_contract=str(getattr(parser, "manifest_ordering_contract")),
        producer_version=producer_version,
        manifest_eligible=True,
    )


def _assert_frozen_contract_matches(generation: EvidenceSourceGeneration, contract: ManifestParserContract) -> None:
    expected = {
        "parser_version": contract.parser_version,
        "normalization_version": contract.normalization_version,
        "batching_contract_version": contract.batching_contract_version,
        "configured_batch_size": int(contract.configured_batch_size),
        "ordering_contract": contract.ordering_contract,
        "producer_version": contract.producer_version,
    }
    actual = {
        "parser_version": generation.parser_version,
        "normalization_version": generation.normalization_version,
        "batching_contract_version": generation.batching_contract_version,
        "configured_batch_size": int(generation.configured_batch_size),
        "ordering_contract": generation.ordering_contract,
        "producer_version": generation.producer_version,
    }
    if actual != expected:
        raise FrozenGenerationMismatch(f"frozen generation contract mismatch: expected {expected}, got {actual}")


def allocate_case_file_initial_generation(
    *,
    session,
    case_id: int,
    case_file_id: int,
    contract: ManifestParserContract,
) -> EvidenceSourceGeneration:
    if not contract.manifest_eligible:
        raise ManifestEligibilityError("manifest parser contract is not eligible")

    started = time.perf_counter()
    case_file = (
        session.query(CaseFile)
        .filter(CaseFile.id == int(case_file_id))
        .with_for_update()
        .one()
    )
    source_ref_id = str(case_file.id)
    generations = (
        session.query(EvidenceSourceGeneration)
        .filter_by(
            case_id=int(case_id),
            source_ref_type=SourceRefType.CASE_FILE,
            source_ref_id=source_ref_id,
        )
        .order_by(EvidenceSourceGeneration.source_generation.asc())
        .with_for_update()
        .populate_existing()
        .all()
    )

    building = [
        generation
        for generation in generations
        if generation.visibility_state in {
            EvidenceGenerationState.BUILDING_INITIAL,
            EvidenceGenerationState.BUILDING_REPLACEMENT,
        }
    ]
    active = [
        generation
        for generation in generations
        if generation.visibility_state == EvidenceGenerationState.ACTIVE
    ]
    if len(building) > 1:
        raise GenerationAllocationError("multiple open building generations exist for source")
    if active and not building:
        raise GenerationAllocationError("replacement generation allocation is Tranche D")
    if building and building[0].visibility_state == EvidenceGenerationState.BUILDING_REPLACEMENT:
        raise GenerationAllocationError("BUILDING_REPLACEMENT is unsupported in Tranche B")
    if building:
        generation = building[0]
        if generation.source_generation != 1:
            raise GenerationAllocationError("Tranche B only supports first generation BUILDING_INITIAL")
        if getattr(case_file, "ingest_protocol_origin", None) != IngestProtocolOrigin.MANIFEST_INITIAL:
            case_file.ingest_protocol_origin = IngestProtocolOrigin.MANIFEST_INITIAL
        _assert_frozen_contract_matches(generation, contract)
    elif generations:
        raise GenerationAllocationError("existing non-building generation cannot enter Tranche B initial path")
    else:
        if getattr(case_file, "ingest_protocol_origin", None) != IngestProtocolOrigin.NOT_STARTED:
            raise GenerationAllocationError("CaseFile is not eligible for first managed adoption")
        case_file.ingest_protocol_origin = IngestProtocolOrigin.MANIFEST_INITIAL
        generation = EvidenceSourceGeneration(
            case_id=int(case_id),
            source_ref_type=SourceRefType.CASE_FILE,
            source_ref_id=source_ref_id,
            source_generation=1,
            visibility_state=EvidenceGenerationState.BUILDING_INITIAL,
            state_version=1,
            parser_version=contract.parser_version,
            normalization_version=contract.normalization_version,
            batching_contract_version=contract.batching_contract_version,
            configured_batch_size=int(contract.configured_batch_size),
            ordering_contract=contract.ordering_contract,
            producer_version=contract.producer_version,
            started_at=_utcnow(),
        )
        session.add(generation)
        session.flush()

    emit_metric(
        "phase1b_generation_allocation",
        case_id=case_id,
        source_ref_type=SourceRefType.CASE_FILE,
        source_ref_id=source_ref_id,
        source_generation=generation.source_generation,
        duration_ms=(time.perf_counter() - started) * 1000.0,
    )
    return generation


def allocate_case_file_replacement_generation(
    *,
    session,
    case_id: int,
    case_file_id: int,
    contract: ManifestParserContract,
) -> EvidenceSourceGeneration:
    """Allocate a new hidden CASE_FILE replacement generation for an ACTIVE source."""
    if not contract.manifest_eligible:
        raise ManifestEligibilityError("manifest parser contract is not eligible")

    case_file = (
        session.query(CaseFile)
        .filter(CaseFile.id == int(case_file_id))
        .with_for_update()
        .one()
    )
    if getattr(case_file, "ingest_protocol_origin", None) != IngestProtocolOrigin.MANIFEST_INITIAL:
        raise GenerationAllocationError("CaseFile is not an existing managed source")

    source_ref_id = str(case_file.id)
    generations = (
        session.query(EvidenceSourceGeneration)
        .filter_by(
            case_id=int(case_id),
            source_ref_type=SourceRefType.CASE_FILE,
            source_ref_id=source_ref_id,
        )
        .order_by(EvidenceSourceGeneration.source_generation.asc())
        .with_for_update()
        .populate_existing()
        .all()
    )
    active = [generation for generation in generations if generation.visibility_state == EvidenceGenerationState.ACTIVE]
    building = [
        generation
        for generation in generations
        if generation.visibility_state in {
            EvidenceGenerationState.BUILDING_INITIAL,
            EvidenceGenerationState.BUILDING_REPLACEMENT,
        }
    ]
    if len(active) != 1:
        raise GenerationAllocationError("replacement allocation requires exactly one ACTIVE generation")
    if building:
        replacement = building[0]
        if replacement.visibility_state != EvidenceGenerationState.BUILDING_REPLACEMENT:
            raise ReplacementInProgressError("initial build is still in progress")
        _assert_frozen_contract_matches(replacement, contract)
        raise ReplacementInProgressError("replacement generation already in progress")

    prior_active = active[0]
    if prior_active.source_generation != max(generation.source_generation for generation in generations):
        # Failed generations may exist after the active one; numbering still uses max+1.
        pass
    next_generation = max(generation.source_generation for generation in generations) + 1
    replacement = EvidenceSourceGeneration(
        case_id=int(case_id),
        source_ref_type=SourceRefType.CASE_FILE,
        source_ref_id=source_ref_id,
        source_generation=next_generation,
        visibility_state=EvidenceGenerationState.BUILDING_REPLACEMENT,
        state_version=1,
        parser_version=contract.parser_version,
        normalization_version=contract.normalization_version,
        batching_contract_version=contract.batching_contract_version,
        configured_batch_size=int(contract.configured_batch_size),
        ordering_contract=contract.ordering_contract,
        producer_version=contract.producer_version,
        started_at=_utcnow(),
    )
    session.add(replacement)
    session.flush()
    emit_metric(
        "phase1b_replacement_generation_allocation",
        case_id=case_id,
        source_ref_type=SourceRefType.CASE_FILE,
        source_ref_id=source_ref_id,
        prior_active_generation=prior_active.source_generation,
        replacement_generation=replacement.source_generation,
    )
    return replacement


def create_ingest_attempt(
    *,
    session,
    generation: EvidenceSourceGeneration,
    celery_task_id: Optional[str] = None,
    worker_name: Optional[str] = None,
    lease_seconds: int = DEFAULT_INGEST_ATTEMPT_LEASE_SECONDS,
) -> IngestAttempt:
    now = _utcnow()
    attempt = IngestAttempt(
        ingest_attempt_id=str(uuid.uuid4()),
        generation_id=generation.id,
        status="STARTED",
        celery_task_id=celery_task_id,
        worker_name=worker_name,
        started_at=now,
        heartbeat_at=now,
        lease_expires_at=now + timedelta(seconds=max(int(lease_seconds), 1)),
        updated_at=now,
    )
    session.add(attempt)
    session.flush()
    return attempt


def refresh_ingest_attempt_lease(
    *,
    session,
    attempt: IngestAttempt,
    lease_seconds: int = DEFAULT_INGEST_ATTEMPT_LEASE_SECONDS,
) -> IngestAttempt:
    if attempt.status != "STARTED":
        raise ManifestProtocolError("only STARTED attempts can refresh a writer lease")
    now = _utcnow()
    attempt.heartbeat_at = now
    attempt.lease_expires_at = now + timedelta(seconds=max(int(lease_seconds), 1))
    attempt.updated_at = now
    session.flush()
    return attempt


def finish_ingest_attempt(session, attempt: IngestAttempt, *, status: str, error: Optional[str] = None) -> IngestAttempt:
    now = _utcnow()
    attempt.status = status
    attempt.finished_at = now
    attempt.heartbeat_at = now
    attempt.lease_expires_at = now
    attempt.updated_at = now
    attempt.error = error
    session.flush()
    return attempt


def _event_mapping_from_row(event: ParsedEvent, row: Tuple[Any, ...]) -> Dict[str, Any]:
    mapping = dict(zip(ParsedEvent.clickhouse_columns(), row))
    mapping["parser_provenance"] = {
        "parser_version": event.parser_version,
        "native_record_id_authoritative": bool(event.native_record_id_authoritative),
        "source_record_identifier_authoritative": bool(event.source_record_identifier_authoritative),
        "source_record_identifier_type": event.source_record_identifier_type or None,
        "source_record_identifier_value": event.source_record_identifier_value or None,
    }
    return mapping


def _source_locator_for_event(event: ParsedEvent, ordinal: int) -> Optional[dict]:
    try:
        return canonical_source_locator(
            parser_source_id=(
                event.source_record_identifier_value
                if event.source_record_identifier_authoritative and event.source_record_identifier_value
                else None
            ),
            native_record_id=event.record_id if event.native_record_id_authoritative and event.record_id is not None else None,
            deterministic_ordinal=ordinal,
        ).canonical()
    except ValueError:
        return None


def _protocol_row(
    *,
    event: ParsedEvent,
    generation: EvidenceSourceGeneration,
    ingest_batch_id: str,
    ingest_attempt_id: str,
    ingest_row_ordinal: int,
) -> ProtocolRow:
    base_row = event.to_clickhouse_row()
    mapping = _event_mapping_from_row(event, base_row)
    mapping.update(
        {
            "source_ref_type": generation.source_ref_type,
            "source_ref_id": generation.source_ref_id,
            "source_generation": int(generation.source_generation),
            "ingest_batch_id": ingest_batch_id,
            "ingest_row_ordinal": ingest_row_ordinal,
        }
    )
    row_hash = ingest_row_hash(mapping)
    protocol_values = (
        generation.source_ref_type,
        generation.source_ref_id,
        int(generation.source_generation),
        ingest_batch_id,
        ingest_row_ordinal,
        row_hash,
        ingest_attempt_id,
    )
    return ProtocolRow(
        ordinal=ingest_row_ordinal,
        event=event,
        clickhouse_row=tuple(base_row) + protocol_values,
        ingest_row_hash=row_hash,
        source_locator=_source_locator_for_event(event, ingest_row_ordinal),
    )


def construct_managed_batches(
    *,
    generation: EvidenceSourceGeneration,
    attempt: IngestAttempt,
    events: Sequence[ParsedEvent],
) -> Tuple[ManagedBatch, ...]:
    batch_size = int(generation.configured_batch_size)
    if batch_size <= 0:
        raise ManifestProtocolError("configured_batch_size must be positive")
    batches: List[ManagedBatch] = []
    for batch_ordinal, start in enumerate(range(0, len(events), batch_size)):
        batches.append(
            construct_managed_batch(
                generation=generation,
                attempt=attempt,
                events=tuple(events[start:start + batch_size]),
                batch_ordinal=batch_ordinal,
            )
        )
    return tuple(batches)


def construct_managed_batch(
    *,
    generation: EvidenceSourceGeneration,
    attempt: IngestAttempt,
    events: Sequence[ParsedEvent],
    batch_ordinal: int,
) -> ManagedBatch:
    """Construct one deterministic manifest batch from an already bounded slice."""
    if not events:
        raise ManifestProtocolError("managed batch cannot be empty")
    ingest_batch_id = deterministic_ingest_batch_id(
        case_id=generation.case_id,
        source_ref_type=generation.source_ref_type,
        source_ref_id=generation.source_ref_id,
        source_generation=generation.source_generation,
        batch_ordinal=int(batch_ordinal),
        batching_contract_version=generation.batching_contract_version,
    )
    rows = tuple(
        _protocol_row(
            event=event,
            generation=generation,
            ingest_batch_id=ingest_batch_id,
            ingest_attempt_id=attempt.ingest_attempt_id,
            ingest_row_ordinal=ordinal,
        )
        for ordinal, event in enumerate(tuple(events))
    )
    validate_zero_based_manifest_ordinals(row.ordinal for row in rows)
    row_hashes = tuple(row.ingest_row_hash for row in rows)
    return ManagedBatch(
        ingest_batch_id=ingest_batch_id,
        generation=generation,
        batch_ordinal=int(batch_ordinal),
        rows=rows,
        row_hashes=row_hashes,
        batch_content_hash=batch_content_hash(row_hashes),
        first_source_locator=rows[0].source_locator,
        last_source_locator=rows[-1].source_locator,
        ingest_attempt_id=attempt.ingest_attempt_id,
    )


def _manifest_matches(existing: IngestBatch, manifest: ManagedBatch) -> bool:
    return (
        existing.generation_id == manifest.generation.id
        and existing.batch_ordinal == manifest.batch_ordinal
        and existing.row_count == manifest.row_count
        and existing.batch_content_hash == manifest.batch_content_hash
        and list(existing.expected_ingest_row_hashes or []) == list(manifest.row_hashes)
        and (existing.first_source_locator or None) == manifest.first_source_locator
        and (existing.last_source_locator or None) == manifest.last_source_locator
    )


def reserve_staged_batch(*, session, manifest: ManagedBatch) -> IngestBatch:
    existing = (
        session.query(IngestBatch)
        .filter_by(ingest_batch_id=manifest.ingest_batch_id)
        .with_for_update()
        .one_or_none()
    )
    if existing:
        if not _manifest_matches(existing, manifest):
            raise ManifestMismatchError(f"existing manifest differs for {manifest.ingest_batch_id}")
        existing.ingest_attempt_id = manifest.ingest_attempt_id
        session.flush()
        return existing

    batch = IngestBatch(
        ingest_batch_id=manifest.ingest_batch_id,
        generation_id=manifest.generation.id,
        batch_ordinal=manifest.batch_ordinal,
        row_count=manifest.row_count,
        batch_content_hash=manifest.batch_content_hash,
        expected_ingest_row_hashes=list(manifest.row_hashes),
        first_source_locator=manifest.first_source_locator,
        last_source_locator=manifest.last_source_locator,
        ingest_attempt_id=manifest.ingest_attempt_id,
        state=IngestBatchState.STAGED,
        state_version=1,
    )
    session.add(batch)
    session.flush()
    return batch


def insert_managed_batch(clickhouse_client, manifest: ManagedBatch) -> None:
    rows = manifest.clickhouse_rows
    if not rows:
        return
    estimated_bytes = estimate_rows_bytes(rows)
    with timed_stage(
        "phase1b_clickhouse_insert",
        case_id=manifest.generation.case_id,
        ingest_batch_id=manifest.ingest_batch_id,
        row_count=len(rows),
    ):
        with shared_ingest_admission(
            "events_insert",
            case_id=manifest.generation.case_id,
            source_ref=f"ingest_batch:{manifest.ingest_batch_id}",
        ):
            clickhouse_client.insert("events", list(rows), column_names=list(PROTOCOL_CLICKHOUSE_COLUMNS))
    emit_metric(
        "phase1b_clickhouse_insert_summary",
        ingest_batch_id=manifest.ingest_batch_id,
        row_count=len(rows),
        estimated_bytes=estimated_bytes,
    )


def _grouped_batch_rows(clickhouse_client, ingest_batch_id: str) -> List[Tuple[int, str, int, int]]:
    result = clickhouse_client.query(
        """
        SELECT
            ingest_row_ordinal,
            ingest_row_hash,
            count() AS physical_copies,
            uniqExact(ingest_row_hash) AS distinct_hashes
        FROM events
        WHERE ingest_batch_id = {id:String}
        GROUP BY ingest_row_ordinal, ingest_row_hash
        """,
        parameters={"id": ingest_batch_id},
    )
    return [
        (int(row[0]), str(row[1]), int(row[2]), int(row[3]))
        for row in result.result_rows
    ]


def verify_ingest_batch(clickhouse_client, manifest: ManagedBatch) -> BatchVerificationResult:
    started = time.perf_counter()
    grouped = _grouped_batch_rows(clickhouse_client, manifest.ingest_batch_id)
    physical_rows = sum(row[2] for row in grouped)
    duplicate_physical_rows = sum(max(row[2] - 1, 0) for row in grouped)
    try:
        if not grouped:
            return BatchVerificationResult("absent", False, physical_rows=0, message="no ClickHouse rows")

        by_ordinal: Dict[int, List[Tuple[str, int, int]]] = {}
        for ordinal, row_hash, physical_copies, distinct_hashes in grouped:
            by_ordinal.setdefault(ordinal, []).append((row_hash, physical_copies, distinct_hashes))

        expected_ordinals = set(range(manifest.row_count))
        observed_ordinals = set(by_ordinal)
        missing = expected_ordinals - observed_ordinals
        extra = observed_ordinals - expected_ordinals
        if missing:
            return BatchVerificationResult("partial", False, physical_rows=physical_rows, message=f"missing ordinals {sorted(missing)}")
        if extra:
            return BatchVerificationResult("extra_ordinal", False, physical_rows=physical_rows, message=f"extra ordinals {sorted(extra)}")

        collapsed_hashes: List[str] = []
        retry_equivalent_duplicate = False
        for ordinal in range(manifest.row_count):
            entries = by_ordinal[ordinal]
            hashes = {entry[0] for entry in entries}
            distinct_counts = {entry[2] for entry in entries}
            if len(hashes) > 1 or any(count > 1 for count in distinct_counts):
                return BatchVerificationResult(
                    "duplicate_different",
                    False,
                    physical_rows=physical_rows,
                    duplicate_physical_rows=duplicate_physical_rows,
                    message=f"ordinal {ordinal} has conflicting hashes",
                )
            row_hash = entries[0][0]
            if row_hash != manifest.row_hashes[ordinal]:
                return BatchVerificationResult(
                    "hash_mismatch",
                    False,
                    physical_rows=physical_rows,
                    duplicate_physical_rows=duplicate_physical_rows,
                    message=f"ordinal {ordinal} hash mismatch",
                )
            if entries[0][1] > 1:
                retry_equivalent_duplicate = True
            collapsed_hashes.append(row_hash)

        if batch_content_hash_for_ordinals(tuple(enumerate(collapsed_hashes))) != manifest.batch_content_hash:
            return BatchVerificationResult(
                "aggregate_mismatch",
                False,
                physical_rows=physical_rows,
                duplicate_physical_rows=duplicate_physical_rows,
                message="batch_content_hash mismatch",
            )

        outcome = "duplicate_identical" if retry_equivalent_duplicate else "exact"
        return BatchVerificationResult(
            outcome,
            True,
            retry_equivalent_duplicate=retry_equivalent_duplicate,
            physical_rows=physical_rows,
            duplicate_physical_rows=duplicate_physical_rows,
        )
    finally:
        emit_metric(
            "phase1b_clickhouse_verify",
            ingest_batch_id=manifest.ingest_batch_id,
            row_count=manifest.row_count,
            physical_rows=physical_rows,
            duration_ms=(time.perf_counter() - started) * 1000.0,
        )


def purge_ingest_batch_rows(clickhouse_client, ingest_batch_id: str) -> None:
    from utils.clickhouse import clickhouse_string_literal, wait_for_mutation_completion

    command_fragment = f"DELETE WHERE ingest_batch_id = {clickhouse_string_literal(ingest_batch_id)}"
    with exclusive_ingest_fence("manifest_batch_purge", source_ref=f"ingest_batch:{ingest_batch_id}"):
        clickhouse_client.command(f"ALTER TABLE events {command_fragment}")
        wait_for_mutation_completion("events", command_fragment, client=clickhouse_client)


def mark_batch_durable(*, session, batch: IngestBatch, verification: BatchVerificationResult) -> IngestBatch:
    if not verification.success:
        raise ManifestProtocolError(f"verification did not authorize DURABLE: {verification.outcome}")
    if batch.state != IngestBatchState.DURABLE:
        batch.state = IngestBatchState.DURABLE
        batch.state_version = int(batch.state_version or 0) + 1
        batch.durable_at = _utcnow()
    session.flush()
    from utils.row_local_derivations import maybe_queue_row_local_derivations_for_durable_batch
    maybe_queue_row_local_derivations_for_durable_batch(session=session, batch=batch)
    generation = batch.generation
    if generation is None:
        generation = session.query(EvidenceSourceGeneration).filter_by(id=batch.generation_id).one()
    _schedule_completion_reconciliation(session, generation, reason="batch_durable")
    return batch


def update_generation_ingest_accounting(
    *,
    session,
    generation: EvidenceSourceGeneration,
    expected_rows: Optional[int] = None,
) -> EvidenceSourceGeneration:
    durable_rows = (
        session.query(func.coalesce(func.sum(IngestBatch.row_count), 0))
        .filter_by(generation_id=generation.id, state=IngestBatchState.DURABLE)
        .scalar()
    )
    if expected_rows is not None:
        generation.expected_rows = int(expected_rows)
    generation.landed_rows = int(durable_rows or 0)
    session.flush()
    return generation


def declare_generation_ingest_complete(
    *,
    session,
    generation: EvidenceSourceGeneration,
    expected_rows: int,
    final_batch_ordinal: Optional[int],
) -> EvidenceSourceGeneration:
    """Durably declare parser EOF for a generation after successful enumeration."""
    expected_rows = int(expected_rows)
    if expected_rows < 0:
        raise ManifestProtocolError("expected_rows must be nonnegative")
    if expected_rows == 0:
        if final_batch_ordinal is not None:
            raise ManifestProtocolError("zero-event generation must not declare a final batch ordinal")
    elif final_batch_ordinal is None or int(final_batch_ordinal) < 0:
        raise ManifestProtocolError("non-empty generation requires a nonnegative final batch ordinal")
    if generation.visibility_state not in {
        EvidenceGenerationState.BUILDING_INITIAL,
        EvidenceGenerationState.BUILDING_REPLACEMENT,
    }:
        raise ManifestProtocolError("only building generations can declare ingest completion")
    generation.expected_rows = expected_rows
    generation.final_batch_ordinal = None if final_batch_ordinal is None else int(final_batch_ordinal)
    generation.completed_at = _utcnow()
    update_generation_ingest_accounting(session=session, generation=generation)
    session.flush()
    from utils.capability_watermarks import refresh_generation_capability_watermarks
    refresh_generation_capability_watermarks(session=session, generation=generation)
    _schedule_completion_reconciliation(session, generation, reason="source_eof")
    return generation


def _declared_activation_requirements(_generation: EvidenceSourceGeneration) -> Tuple[str, ...]:
    """Return currently implemented activation-blocking derivation requirements."""
    return ()


def check_generation_activation_completeness(
    *,
    session,
    generation: EvidenceSourceGeneration,
) -> ActivationCompletenessResult:
    errors: List[str] = []
    required_derivations = _declared_activation_requirements(generation)
    if generation.completed_at is None:
        errors.append("missing durable ingest completion declaration")
    if generation.expected_rows is None:
        errors.append("missing expected row count")

    expected_rows = int(generation.expected_rows or 0)
    final_batch_ordinal = generation.final_batch_ordinal
    batches = (
        session.query(IngestBatch)
        .filter_by(generation_id=generation.id)
        .order_by(IngestBatch.batch_ordinal.asc())
        .with_for_update()
        .all()
    )

    if expected_rows == 0:
        if final_batch_ordinal is not None:
            errors.append("zero-event generation must not have a final batch ordinal")
        if batches:
            errors.append("zero-event generation must not have ingest batches")
    else:
        if final_batch_ordinal is None:
            errors.append("missing final batch ordinal")
        else:
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
            row_sum = sum(int(batch.row_count or 0) for batch in required_batches)
            if row_sum != expected_rows:
                errors.append(f"durable row count {row_sum} does not match expected {expected_rows}")

    if required_derivations:
        from utils.capability_watermarks import missing_activation_capability_requirements
        missing = missing_activation_capability_requirements(session, generation, required_derivations)
        if missing:
            errors.append(f"activation-blocking capabilities not complete: {list(missing)}")

    return ActivationCompletenessResult(
        complete=not errors,
        errors=tuple(errors),
        required_derivations=tuple(required_derivations),
    )


def _audit_generation_transition(
    *,
    session,
    case_id: int,
    source_ref_type: str,
    source_ref_id: str,
    prior_active_generation: Optional[int],
    new_active_generation: Optional[int],
    actor: str,
    reason: str,
    transition: str,
) -> EvidenceGenerationAudit:
    audit = EvidenceGenerationAudit(
        case_id=int(case_id),
        source_ref_type=source_ref_type,
        source_ref_id=source_ref_id,
        prior_active_generation=prior_active_generation,
        new_active_generation=new_active_generation,
        actor=str(actor or "system"),
        reason=str(reason or ""),
        transition=transition,
        occurred_at=_utcnow(),
    )
    session.add(audit)
    session.flush()
    return audit


def activate_initial_generation(
    *,
    session,
    generation: EvidenceSourceGeneration,
    actor: str = "system",
    reason: str = "initial_generation_complete",
) -> EvidenceSourceGeneration:
    locked = (
        session.query(EvidenceSourceGeneration)
        .filter_by(id=generation.id)
        .with_for_update()
        .one()
    )
    if locked.visibility_state == EvidenceGenerationState.ACTIVE:
        return locked
    if locked.visibility_state != EvidenceGenerationState.BUILDING_INITIAL:
        raise ActivationCompletenessError("initial activation requires BUILDING_INITIAL")
    check_generation_activation_completeness(session=session, generation=locked).require_complete()
    locked.visibility_state = EvidenceGenerationState.ACTIVE
    locked.state_version = int(locked.state_version or 0) + 1
    locked.activated_at = _utcnow()
    _audit_generation_transition(
        session=session,
        case_id=locked.case_id,
        source_ref_type=locked.source_ref_type,
        source_ref_id=locked.source_ref_id,
        prior_active_generation=None,
        new_active_generation=locked.source_generation,
        actor=actor,
        reason=reason,
        transition="BUILDING_INITIAL_TO_ACTIVE",
    )
    session.flush()
    _schedule_completion_reconciliation(session, locked, reason="initial_activation")
    return locked


def activate_replacement_generation(
    *,
    session,
    replacement: EvidenceSourceGeneration,
    actor: str = "system",
    reason: str = "replacement_generation_complete",
    inject_failure_after_supersede: bool = False,
) -> EvidenceSourceGeneration:
    rows = (
        session.query(EvidenceSourceGeneration)
        .filter(
            EvidenceSourceGeneration.case_id == int(replacement.case_id),
            EvidenceSourceGeneration.source_ref_type == replacement.source_ref_type,
            EvidenceSourceGeneration.source_ref_id == replacement.source_ref_id,
        )
        .order_by(EvidenceSourceGeneration.source_generation.asc())
        .with_for_update()
        .populate_existing()
        .all()
    )
    active = [row for row in rows if row.visibility_state == EvidenceGenerationState.ACTIVE]
    building_replacements = [row for row in rows if row.visibility_state == EvidenceGenerationState.BUILDING_REPLACEMENT]
    replacement_row = next((row for row in building_replacements if row.id == replacement.id), None)
    if replacement.visibility_state == EvidenceGenerationState.ACTIVE:
        return replacement
    active_replacement = next((row for row in active if row.id == replacement.id), None)
    if active_replacement is not None:
        return active_replacement
    if len(active) != 1 or replacement_row is None or len(building_replacements) != 1:
        raise ActivationCompletenessError("replacement activation requires one ACTIVE and one BUILDING_REPLACEMENT")
    prior = active[0]
    check_generation_activation_completeness(session=session, generation=replacement_row).require_complete()

    prior.visibility_state = EvidenceGenerationState.SUPERSEDED
    prior.state_version = int(prior.state_version or 0) + 1
    prior.superseded_at = _utcnow()
    prior.superseded_by_generation = int(replacement_row.source_generation)
    session.flush()
    if inject_failure_after_supersede:
        raise RuntimeError("injected failure after prior generation supersede")

    replacement_row.visibility_state = EvidenceGenerationState.ACTIVE
    replacement_row.state_version = int(replacement_row.state_version or 0) + 1
    replacement_row.activated_at = _utcnow()
    _audit_generation_transition(
        session=session,
        case_id=replacement_row.case_id,
        source_ref_type=replacement_row.source_ref_type,
        source_ref_id=replacement_row.source_ref_id,
        prior_active_generation=prior.source_generation,
        new_active_generation=replacement_row.source_generation,
        actor=actor,
        reason=reason,
        transition="BUILDING_REPLACEMENT_TO_ACTIVE",
    )
    session.flush()
    _schedule_completion_reconciliation(session, replacement_row, reason="replacement_activation")
    return replacement_row


def fail_generation_terminal(
    *,
    session,
    generation: EvidenceSourceGeneration,
    actor: str = "system",
    reason: str = "generation_failed",
) -> EvidenceSourceGeneration:
    locked = (
        session.query(EvidenceSourceGeneration)
        .filter_by(id=generation.id)
        .with_for_update()
        .one()
    )
    if locked.visibility_state not in {
        EvidenceGenerationState.BUILDING_INITIAL,
        EvidenceGenerationState.BUILDING_REPLACEMENT,
    }:
        raise ManifestProtocolError("only building generations can be terminally failed")
    prior_state = locked.visibility_state
    locked.visibility_state = EvidenceGenerationState.FAILED
    locked.state_version = int(locked.state_version or 0) + 1
    locked.failed_at = _utcnow()
    locked.failure_reason = reason
    _audit_generation_transition(
        session=session,
        case_id=locked.case_id,
        source_ref_type=locked.source_ref_type,
        source_ref_id=locked.source_ref_id,
        prior_active_generation=None,
        new_active_generation=None,
        actor=actor,
        reason=reason,
        transition=f"{prior_state}_TO_FAILED",
    )
    session.flush()
    return locked


def invalidate_source_generation(
    *,
    session,
    generation: EvidenceSourceGeneration,
    actor: str = "system",
    reason: str = "source_invalidated",
) -> EvidenceSourceGeneration:
    """Transition a generation to INVALIDATED and withdraw capability gates."""
    locked = (
        session.query(EvidenceSourceGeneration)
        .filter_by(id=generation.id)
        .with_for_update()
        .one()
    )
    if locked.visibility_state == EvidenceGenerationState.INVALIDATED:
        from utils.capability_watermarks import invalidate_generation_capability_state
        invalidate_generation_capability_state(session=session, generation=locked)
        return locked
    if locked.visibility_state not in {
        EvidenceGenerationState.BUILDING_INITIAL,
        EvidenceGenerationState.BUILDING_REPLACEMENT,
        EvidenceGenerationState.ACTIVE,
        EvidenceGenerationState.SUPERSEDED,
        EvidenceGenerationState.FAILED,
    }:
        raise ManifestProtocolError(f"cannot invalidate generation in state {locked.visibility_state}")
    prior_state = locked.visibility_state
    locked.visibility_state = EvidenceGenerationState.INVALIDATED
    locked.state_version = int(locked.state_version or 0) + 1
    _audit_generation_transition(
        session=session,
        case_id=locked.case_id,
        source_ref_type=locked.source_ref_type,
        source_ref_id=locked.source_ref_id,
        prior_active_generation=locked.source_generation if prior_state == EvidenceGenerationState.ACTIVE else None,
        new_active_generation=None,
        actor=actor,
        reason=reason,
        transition=f"{prior_state}_TO_INVALIDATED",
    )
    from utils.capability_watermarks import invalidate_generation_capability_state
    invalidate_generation_capability_state(session=session, generation=locked)
    session.flush()
    return locked


def project_generation_control_state(clickhouse_client, session, generation: EvidenceSourceGeneration) -> None:
    now = _utcnow()
    publishable = 1 if generation.visibility_state in {EvidenceGenerationState.BUILDING_INITIAL, EvidenceGenerationState.ACTIVE} else 0
    generation_row = (
        int(generation.case_id),
        generation.source_ref_type,
        generation.source_ref_id,
        int(generation.source_generation),
        generation.visibility_state,
        int(generation.state_version),
        publishable,
        now,
    )
    durable_batches = (
        session.query(IngestBatch)
        .filter_by(generation_id=generation.id, state=IngestBatchState.DURABLE)
        .order_by(IngestBatch.batch_ordinal.asc())
        .all()
    )
    batch_rows = [
        (
            batch.ingest_batch_id,
            int(generation.case_id),
            generation.source_ref_type,
            generation.source_ref_id,
            int(generation.source_generation),
            int(batch.batch_ordinal),
            int(batch.row_count),
            batch.batch_content_hash,
            batch.state,
            int(batch.state_version),
            batch.durable_at,
            now,
        )
        for batch in durable_batches
    ]
    with timed_stage(
        "phase1b_control_projection",
        case_id=generation.case_id,
        source_ref_type=generation.source_ref_type,
        source_ref_id=generation.source_ref_id,
        source_generation=generation.source_generation,
        durable_batch_count=len(batch_rows),
    ):
        clickhouse_client.insert(
            "visible_evidence_generations",
            [generation_row],
            column_names=list(VISIBLE_EVIDENCE_GENERATIONS_COLUMNS),
        )
        if batch_rows:
            clickhouse_client.insert(
                "durable_ingest_batches",
                batch_rows,
                column_names=list(DURABLE_INGEST_BATCHES_COLUMNS),
            )


def project_generation_authority_swap(
    clickhouse_client,
    session,
    *,
    prior_generation: EvidenceSourceGeneration,
    new_generation: EvidenceSourceGeneration,
) -> None:
    """Project an atomic PG authority swap without publishing replacement first."""
    project_generation_control_state(clickhouse_client, session, prior_generation)
    project_generation_control_state(clickhouse_client, session, new_generation)


def resolve_projected_visible_generation(
    clickhouse_client,
    *,
    case_id: int,
    source_ref_type: str,
    source_ref_id: str,
) -> Optional[int]:
    """Return the generation currently visible through the CH control projection."""
    result = clickhouse_client.query(
        """
        SELECT source_generation
        FROM visible_evidence_generations FINAL
        WHERE case_id = {case_id:UInt32}
          AND source_ref_type = {source_ref_type:String}
          AND source_ref_id = {source_ref_id:String}
          AND visibility_state = 'ACTIVE'
          AND publishable = 1
        ORDER BY source_generation DESC
        LIMIT 1
        """,
        parameters={
            "case_id": int(case_id),
            "source_ref_type": source_ref_type,
            "source_ref_id": source_ref_id,
        },
    )
    if not result.result_rows:
        return None
    return int(result.result_rows[0][0])


def batch_became_durable(*_args, **_kwargs) -> None:
    """Internal hook placeholder. Tranche B does not activate derivations."""
    return None


def handle_failed_verification(
    *,
    clickhouse_client,
    verification: BatchVerificationResult,
    manifest: ManagedBatch,
) -> None:
    if verification.outcome in {
        "partial",
        "extra_ordinal",
        "duplicate_different",
        "hash_mismatch",
        "aggregate_mismatch",
    }:
        purge_ingest_batch_rows(clickhouse_client, manifest.ingest_batch_id)
