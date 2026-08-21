"""Incremental ROW_LOCAL derivation runners for Phase 1B Tranche E1.

Production queueing is feature-gated and off by default. The existing
whole-case completion tail is preserved.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from models.database_flow import (
    CapabilityName,
    EvidenceGenerationState,
    EvidenceSourceGeneration,
    IngestBatch,
    IngestBatchState,
)
from utils.capability_watermarks import (
    CAPABILITY_INVENTORY,
    MIGRATED_ROW_LOCAL_CAPABILITIES,
    PRIVACY_ALIASES_V1,
    CapabilityWatermarkError,
    incremental_row_local_enabled,
    record_capability_batch_completion,
    record_zero_event_capability_completion,
    require_locked_capability,
)


logger = logging.getLogger(__name__)

PRIVACY_INCREMENTAL_SOURCE = "ingest_batch_row_local"


def derive_privacy_aliases_for_durable_batch(
    *,
    session,
    ingest_batch_id: str,
    derivation_version: str = PRIVACY_ALIASES_V1,
    privacy_level: str | None = None,
    clickhouse_client: Any = None,
) -> dict[str, Any]:
    """Run privacy-aliases:v1 for one DURABLE ingest batch and record completion."""
    batch = session.query(IngestBatch).filter_by(ingest_batch_id=str(ingest_batch_id)).one_or_none()
    if batch is None:
        raise CapabilityWatermarkError(f"unknown ingest_batch_id {ingest_batch_id}")
    if batch.state != IngestBatchState.DURABLE:
        raise CapabilityWatermarkError(
            f"privacy derivation refused for non-DURABLE batch {ingest_batch_id}"
        )
    generation: EvidenceSourceGeneration = batch.generation
    if generation.visibility_state in {
        EvidenceGenerationState.FAILED,
        EvidenceGenerationState.INVALIDATED,
    }:
        raise CapabilityWatermarkError(
            f"privacy derivation refused for {generation.visibility_state} generation"
        )

    from utils.privacy_aliases import populate_case_privacy_aliases

    case_file_id = None
    if generation.source_ref_type == "CASE_FILE":
        try:
            case_file_id = int(generation.source_ref_id)
        except (TypeError, ValueError):
            case_file_id = None

    populate = populate_case_privacy_aliases(
        int(generation.case_id),
        case_file_id=case_file_id,
        ingest_batch_id=str(ingest_batch_id),
        source_generation=int(generation.source_generation),
        source=PRIVACY_INCREMENTAL_SOURCE,
        privacy_level=privacy_level,
        client=clickhouse_client,
    )
    watermark = record_capability_batch_completion(
        session=session,
        case_id=int(generation.case_id),
        capability=CapabilityName.PRIVACY_ALIASES,
        source_ref_type=generation.source_ref_type,
        source_ref_id=generation.source_ref_id,
        source_generation=int(generation.source_generation),
        derivation_version=derivation_version,
        ingest_batch_id=str(ingest_batch_id),
    )
    return {
        "capability": CapabilityName.PRIVACY_ALIASES,
        "derivation_version": derivation_version,
        "ingest_batch_id": str(ingest_batch_id),
        "batch_ordinal": int(batch.batch_ordinal),
        "source_generation": int(generation.source_generation),
        "status": watermark.status,
        "contiguous_batch_ordinal": watermark.contiguous_batch_ordinal,
        "state_version": watermark.state_version,
        "populate": populate,
    }


def derive_row_local_capability_batch(
    *,
    session,
    ingest_batch_id: str,
    capability: str = CapabilityName.PRIVACY_ALIASES,
    derivation_version: Optional[str] = None,
    privacy_level: str | None = None,
    clickhouse_client: Any = None,
) -> dict[str, Any]:
    require_locked_capability(capability)
    spec = CAPABILITY_INVENTORY[capability]
    if capability not in MIGRATED_ROW_LOCAL_CAPABILITIES:
        raise CapabilityWatermarkError(
            f"{capability} is not an E1-migrated ROW_LOCAL capability: {spec.get('blocker')}"
        )
    version = derivation_version or spec["derivation_version"]
    if capability == CapabilityName.PRIVACY_ALIASES:
        return derive_privacy_aliases_for_durable_batch(
            session=session,
            ingest_batch_id=ingest_batch_id,
            derivation_version=version,
            privacy_level=privacy_level,
            clickhouse_client=clickhouse_client,
        )
    raise CapabilityWatermarkError(f"{capability} incremental runner is not implemented")


def maybe_complete_zero_event_row_local_capabilities(
    *,
    session,
    generation: EvidenceSourceGeneration,
) -> list[dict[str, Any]]:
    if generation.expected_rows != 0 or generation.final_batch_ordinal is not None:
        return []
    results = []
    for capability in MIGRATED_ROW_LOCAL_CAPABILITIES:
        spec = CAPABILITY_INVENTORY[capability]
        watermark = record_zero_event_capability_completion(
            session=session,
            generation=generation,
            capability=capability,
            derivation_version=spec["derivation_version"],
        )
        results.append({
            "capability": capability,
            "derivation_version": spec["derivation_version"],
            "status": watermark.status,
        })
    return results


def maybe_queue_row_local_derivations_for_durable_batch(
    *,
    session,
    batch: IngestBatch,
    enqueue: bool = True,
) -> list[str]:
    """Queue migrated ROW_LOCAL work after a batch becomes DURABLE.

    No-op unless PHASE1B_INCREMENTAL_ROW_LOCAL_DERIVATIONS_ENABLED is on.
    Does not mark capability completion itself.
    """
    if not incremental_row_local_enabled():
        return []
    if batch.state != IngestBatchState.DURABLE:
        return []
    generation = batch.generation
    if generation is None:
        generation = session.query(EvidenceSourceGeneration).filter_by(id=batch.generation_id).one()
    if generation.visibility_state in {
        EvidenceGenerationState.FAILED,
        EvidenceGenerationState.INVALIDATED,
        EvidenceGenerationState.SUPERSEDED,
    }:
        return []
    queued = []
    if enqueue:
        try:
            from tasks.celery_tasks import derive_row_local_capability_batch_task
            for capability in MIGRATED_ROW_LOCAL_CAPABILITIES:
                derive_row_local_capability_batch_task.delay(
                    ingest_batch_id=batch.ingest_batch_id,
                    capability=capability,
                )
                queued.append(capability)
        except Exception:
            logger.warning(
                "Incremental row-local queue failed for batch %s; durable ingest is unchanged",
                batch.ingest_batch_id,
                exc_info=True,
            )
    return queued
