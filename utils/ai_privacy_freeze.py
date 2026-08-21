"""Phase 1B Tranche E2 AI privacy freeze -> verify -> alias -> send.

Coverage belongs to the exact frozen evidence being sent, never to a
case-wide "AI ready" boolean. The shared router is the last enforcement
boundary; it does not retrieve or freeze evidence itself.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional, Sequence

from models.database_flow import (
    CapabilityName,
    CaseCapabilitySourceState,
    EvidenceGenerationState,
    EvidenceSourceGeneration,
    IngestBatch,
    IngestBatchState,
)
from utils.capability_watermarks import (
    PRIVACY_ALIASES_V1,
    generation_satisfies_default_gate,
    get_capability_watermark,
    resolve_default_capability_generation,
    verify_capability_batch_coverage,
)


REQUIRED_PRIVACY_CAPABILITY = CapabilityName.PRIVACY_ALIASES
DEFAULT_PRIVACY_DERIVATION_VERSION = PRIVACY_ALIASES_V1

CONTENT_CLASS_FORENSIC_EVENTS = "forensic_events"
CONTENT_CLASS_STATIC_ONLY = "static_only"
CONTENT_CLASS_USER_TEXT = "user_text"
CONTENT_CLASS_CASE_METADATA = "case_metadata"
CONTENT_CLASS_MIXED = "mixed"

REASON_MISSING_FROZEN_PROOF = "missing_frozen_evidence_proof"
REASON_UNCOVERED_BATCH = "uncovered_batch"
REASON_STAGED_BATCH = "staged_batch"
REASON_NON_DURABLE_BATCH = "non_durable_batch"
REASON_WRONG_DERIVATION_VERSION = "wrong_derivation_version"
REASON_LEGACY_UNPROVABLE = "legacy_unprovable_evidence"
REASON_GENERATION_AUTHORITY_CHANGED = "generation_authority_changed"
REASON_GENERATION_INVALIDATED = "generation_invalidated"
REASON_GENERATION_SUPERSEDED = "generation_superseded"
REASON_GENERATION_FAILED = "generation_failed"
REASON_GENERATION_NOT_CURRENT = "generation_not_current"
REASON_CROSS_CASE_OR_MALFORMED = "cross_case_or_malformed_freeze"
REASON_SANITIZER_FAILURE = "sanitizer_failure"
REASON_PROVIDER_LOCALITY_UNCERTAIN = "provider_locality_uncertain"
REASON_PAYLOAD_FINGERPRINT_MISMATCH = "payload_fingerprint_mismatch"
REASON_EMPTY_FORENSIC_BYPASS = "empty_forensic_universal_bypass"
REASON_NON_EVENT_UNSUPPORTED = "non_event_metadata_unsupported"
REASON_MIXED_GENERATIONS = "mixed_generations"
REASON_ERK_BATCH_INCONSISTENT = "erk_batch_inconsistent"
REASON_E2_ENFORCEMENT_UNAVAILABLE = "e2_enforcement_unavailable"
REASON_PREFLIGHT_INFRASTRUCTURE_FAILURE = "preflight_infrastructure_failure"
REASON_FOLLOWON_NEW_EVIDENCE = "followon_new_forensic_evidence"

FOLLOWON_KIND_SECOND_PASS_REVIEW = "second_pass_review"
_ALLOWED_FOLLOWON_KINDS = frozenset({FOLLOWON_KIND_SECOND_PASS_REVIEW})
_ERK_MARK_RE = re.compile(r"(?:^|[|\s])erk=([^\s|]+)")
_TOOL_MESSAGE_ROLES = frozenset({"tool", "function"})

_PROOF_TOKEN = object()

_DEFAULT_CH_PROJECTION = (
    "case_id",
    "evidence_record_key",
    "ingest_batch_id",
    "source_generation",
    "source_ref_type",
    "source_ref_id",
    "timestamp_utc",
    "source_host",
    "username",
    "event_id",
    "channel",
    "search_blob",
)


class AIPrivacyPreflightError(RuntimeError):
    """Typed privacy/preflight failure. Messages never include raw case content."""

    def __init__(self, reason: str, *, detail: str = ""):
        self.reason = str(reason)
        self.detail = str(detail or "")
        message = f"AI privacy preflight blocked remote egress: {self.reason}"
        if self.detail:
            message = f"{message} ({self.detail})"
        super().__init__(message)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def freeze_verify_enabled(config: Any = None) -> bool:
    if config is None:
        from config import Config
        config = Config
    return bool(getattr(config, "PHASE1B_AI_PRIVACY_FREEZE_VERIFY_ENABLED", False))


def canonical_fingerprint(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def _provider_type_name(provider: Any) -> str:
    if provider is None:
        return ""
    try:
        return str(provider.provider_type() or "").strip().lower()
    except Exception:
        return ""


def classify_provider_locality(provider: Any) -> str:
    """Return local, remote, or uncertain. Uncertainty fails closed as remote."""
    try:
        from utils.privacy_aliases import is_local_provider
    except Exception:
        provider_type = _provider_type_name(provider)
        if provider_type == "local":
            return "local"
        return "uncertain"
    try:
        if is_local_provider(provider):
            return "local"
    except Exception:
        return "uncertain"
    provider_type = _provider_type_name(provider)
    if provider_type in {"openai", "claude"}:
        return "remote"
    if provider_type == "openai_compatible":
        if hasattr(provider, "_is_local_endpoint"):
            try:
                return "local" if bool(provider._is_local_endpoint()) else "remote"
            except Exception:
                return "uncertain"
        return "uncertain"
    if provider_type == "local":
        return "local"
    if not provider_type:
        return "uncertain"
    return "remote"


def is_remote_case_content_boundary(provider: Any, privacy_context: Any) -> bool:
    locality = classify_provider_locality(provider)
    if locality == "local":
        return False
    scope = getattr(privacy_context, "content_scope", None)
    if scope in {"non_content_admin", "test_only"}:
        return False
    return True


@dataclass(frozen=True)
class FrozenEvidenceObservation:
    """One selected physical evidence observation. Payload stays request-local."""

    case_id: int
    evidence_record_key: str
    ingest_batch_id: Optional[str]
    source_ref_type: Optional[str]
    source_ref_id: Optional[str]
    source_generation: Optional[int]
    managed: bool
    payload_excerpt: str = ""

    def identity_tuple(self) -> tuple:
        return (
            int(self.case_id),
            str(self.evidence_record_key),
            str(self.ingest_batch_id or ""),
            str(self.source_ref_type or ""),
            str(self.source_ref_id or ""),
            int(self.source_generation) if self.source_generation is not None else None,
            bool(self.managed),
        )


@dataclass(frozen=True)
class FrozenGenerationAuthority:
    case_id: int
    source_ref_type: str
    source_ref_id: str
    source_generation: int
    visibility_state: str
    state_version: int
    watermark_state_version: Optional[int] = None


@dataclass(frozen=True)
class FrozenAIEvidenceSet:
    """Immutable request-scoped identity of the exact selected evidence."""

    case_id: int
    observations: tuple[FrozenEvidenceObservation, ...]
    generation_authorities: tuple[FrozenGenerationAuthority, ...]
    required_capability: str
    required_derivation_version: str
    content_class: str
    selected_evidence_count: int
    identity_fingerprint: str
    frozen_at: datetime
    user_text_present: bool = False
    non_event_case_content: bool = False
    ch_queries: int = 0
    pg_queries: int = 0
    construction_ms: float = 0.0

    @property
    def selected_erks(self) -> tuple[str, ...]:
        return tuple(item.evidence_record_key for item in self.observations)

    @property
    def selected_ingest_batch_ids(self) -> tuple[str, ...]:
        return tuple(
            item.ingest_batch_id
            for item in self.observations
            if item.ingest_batch_id
        )

    @property
    def managed_batch_ids(self) -> tuple[str, ...]:
        seen = []
        for item in self.observations:
            if item.managed and item.ingest_batch_id and item.ingest_batch_id not in seen:
                seen.append(item.ingest_batch_id)
        return tuple(seen)

    @property
    def has_legacy_evidence(self) -> bool:
        return any(not item.managed for item in self.observations)

    @property
    def forensic_event_count(self) -> int:
        return len(self.observations)

    def payload_from_frozen_excerpts(self) -> str:
        """Materialize outbound evidence text from the frozen set only."""
        lines = []
        for item in self.observations:
            excerpt = item.payload_excerpt or item.evidence_record_key
            lines.append(excerpt)
        return "\n".join(lines)


@dataclass(frozen=True)
class VerifiedFrozenEgressProof:
    """Coverage proof that callers cannot construct as verified=True."""

    frozen: FrozenAIEvidenceSet
    required_capability: str
    required_derivation_version: str
    raw_payload_fingerprint: str
    coverage_reason: str
    verified_at: datetime
    generation_authorities: tuple[FrozenGenerationAuthority, ...]
    verification_ms: float = 0.0
    pg_queries: int = 0
    _token: object = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        if self._token is not _PROOF_TOKEN:
            raise TypeError(
                "VerifiedFrozenEgressProof can only be created by "
                "verify_frozen_privacy_coverage"
            )


def is_verified_egress_proof(value: Any) -> bool:
    return isinstance(value, VerifiedFrozenEgressProof) and value._token is _PROOF_TOKEN


def _query_batches(session, batch_ids: Sequence[str]) -> dict[str, IngestBatch]:
    wanted = [str(batch_id) for batch_id in batch_ids if str(batch_id or "").strip()]
    if not wanted:
        return {}
    rows = session.query(IngestBatch).filter(IngestBatch.ingest_batch_id.in_(wanted)).all()
    return {row.ingest_batch_id: row for row in rows}


def _generation_key(generation: EvidenceSourceGeneration) -> tuple:
    return (
        int(generation.case_id),
        str(generation.source_ref_type),
        str(generation.source_ref_id),
        int(generation.source_generation),
    )


def _authority_from_generation(
    generation: EvidenceSourceGeneration,
    watermark: Optional[CaseCapabilitySourceState] = None,
) -> FrozenGenerationAuthority:
    return FrozenGenerationAuthority(
        case_id=int(generation.case_id),
        source_ref_type=str(generation.source_ref_type),
        source_ref_id=str(generation.source_ref_id),
        source_generation=int(generation.source_generation),
        visibility_state=str(generation.visibility_state),
        state_version=int(generation.state_version or 1),
        watermark_state_version=None if watermark is None else int(watermark.state_version or 1),
    )


def _excerpt_from_row(row: dict[str, Any]) -> str:
    parts = []
    for key in ("timestamp_utc", "source_host", "username", "event_id", "channel", "search_blob"):
        value = row.get(key)
        if value not in (None, ""):
            parts.append(f"{key}={value}")
    erk = row.get("evidence_record_key")
    if erk:
        parts.append(f"erk={erk}")
    return " | ".join(parts)


def _validate_observation_consistency(
    session,
    observation: FrozenEvidenceObservation,
    batch_by_id: dict[str, IngestBatch],
) -> None:
    if int(observation.case_id) <= 0 or not str(observation.evidence_record_key or "").strip():
        raise AIPrivacyPreflightError(REASON_CROSS_CASE_OR_MALFORMED, detail="missing_identity")
    if not observation.managed:
        return
    if not observation.ingest_batch_id:
        raise AIPrivacyPreflightError(REASON_LEGACY_UNPROVABLE, detail="managed_without_batch")
    batch = batch_by_id.get(str(observation.ingest_batch_id))
    if batch is None:
        raise AIPrivacyPreflightError(REASON_CROSS_CASE_OR_MALFORMED, detail="unknown_batch")
    generation = batch.generation
    if int(generation.case_id) != int(observation.case_id):
        raise AIPrivacyPreflightError(REASON_CROSS_CASE_OR_MALFORMED, detail="batch_case_mismatch")
    if observation.source_generation is not None and int(generation.source_generation) != int(observation.source_generation):
        raise AIPrivacyPreflightError(REASON_ERK_BATCH_INCONSISTENT, detail="generation_mismatch")
    if observation.source_ref_type and generation.source_ref_type != observation.source_ref_type:
        raise AIPrivacyPreflightError(REASON_ERK_BATCH_INCONSISTENT, detail="source_type_mismatch")
    if observation.source_ref_id and str(generation.source_ref_id) != str(observation.source_ref_id):
        raise AIPrivacyPreflightError(REASON_ERK_BATCH_INCONSISTENT, detail="source_id_mismatch")


def freeze_selected_observations(
    session,
    *,
    case_id: int,
    observations: Sequence[FrozenEvidenceObservation | dict[str, Any]],
    required_derivation_version: str = DEFAULT_PRIVACY_DERIVATION_VERSION,
    content_class: Optional[str] = None,
    user_text_present: bool = False,
    non_event_case_content: bool = False,
    retrieval_mode: str = "default",
    ch_queries: int = 0,
) -> FrozenAIEvidenceSet:
    """Freeze the exact selected physical observations. No later membership change."""
    started = time.perf_counter()
    pg_queries = 0
    normalized: list[FrozenEvidenceObservation] = []
    for item in observations:
        if isinstance(item, FrozenEvidenceObservation):
            row = item
        else:
            managed = bool(item.get("managed", bool(item.get("ingest_batch_id"))))
            row = FrozenEvidenceObservation(
                case_id=int(item.get("case_id") or case_id),
                evidence_record_key=str(item.get("evidence_record_key") or ""),
                ingest_batch_id=(str(item["ingest_batch_id"]) if item.get("ingest_batch_id") else None),
                source_ref_type=item.get("source_ref_type"),
                source_ref_id=str(item["source_ref_id"]) if item.get("source_ref_id") is not None else None,
                source_generation=int(item["source_generation"]) if item.get("source_generation") is not None else None,
                managed=managed,
                payload_excerpt=str(item.get("payload_excerpt") or ""),
            )
        if int(row.case_id) != int(case_id):
            raise AIPrivacyPreflightError(REASON_CROSS_CASE_OR_MALFORMED, detail="cross_case")
        normalized.append(row)

    batch_ids = [row.ingest_batch_id for row in normalized if row.ingest_batch_id]
    batch_by_id = _query_batches(session, batch_ids)
    pg_queries += 1
    for row in normalized:
        _validate_observation_consistency(session, row, batch_by_id)

    authorities: dict[tuple, FrozenGenerationAuthority] = {}
    for row in normalized:
        if not row.managed or not row.ingest_batch_id:
            continue
        batch = batch_by_id[str(row.ingest_batch_id)]
        generation = batch.generation
        key = _generation_key(generation)
        if key not in authorities:
            default = resolve_default_capability_generation(
                session,
                case_id=generation.case_id,
                source_ref_type=generation.source_ref_type,
                source_ref_id=generation.source_ref_id,
            )
            pg_queries += 1
            if retrieval_mode == "default":
                if default is None or not generation_satisfies_default_gate(default):
                    raise AIPrivacyPreflightError(REASON_GENERATION_NOT_CURRENT, detail="no_default_generation")
                if int(default.source_generation) != int(generation.source_generation):
                    raise AIPrivacyPreflightError(
                        REASON_GENERATION_NOT_CURRENT,
                        detail=generation.visibility_state.lower(),
                    )
            if generation.visibility_state == EvidenceGenerationState.INVALIDATED:
                raise AIPrivacyPreflightError(REASON_GENERATION_INVALIDATED)
            if generation.visibility_state == EvidenceGenerationState.FAILED:
                raise AIPrivacyPreflightError(REASON_GENERATION_FAILED)
            if generation.visibility_state == EvidenceGenerationState.SUPERSEDED:
                raise AIPrivacyPreflightError(REASON_GENERATION_SUPERSEDED)
            watermark = get_capability_watermark(
                session,
                case_id=generation.case_id,
                capability=REQUIRED_PRIVACY_CAPABILITY,
                source_ref_type=generation.source_ref_type,
                source_ref_id=generation.source_ref_id,
                source_generation=generation.source_generation,
                derivation_version=required_derivation_version,
            )
            pg_queries += 1
            authorities[key] = _authority_from_generation(generation, watermark)

    if len({item.source_generation for item in normalized if item.managed and item.source_generation is not None}) > 1:
        # Mixed generations across one source are fail-closed for default requests.
        source_keys = {
            (item.source_ref_type, item.source_ref_id, item.source_generation)
            for item in normalized
            if item.managed
        }
        collapsed = {(item[0], item[1]) for item in source_keys}
        if len(source_keys) != len(collapsed):
            raise AIPrivacyPreflightError(REASON_MIXED_GENERATIONS)

    if content_class is None:
        if normalized:
            content_class = CONTENT_CLASS_FORENSIC_EVENTS
            if user_text_present or non_event_case_content:
                content_class = CONTENT_CLASS_MIXED
        elif user_text_present and non_event_case_content:
            content_class = CONTENT_CLASS_MIXED
        elif user_text_present:
            content_class = CONTENT_CLASS_USER_TEXT
        elif non_event_case_content:
            content_class = CONTENT_CLASS_CASE_METADATA
        else:
            content_class = CONTENT_CLASS_STATIC_ONLY

    identity = {
        "case_id": int(case_id),
        "observations": [item.identity_tuple() for item in normalized],
        "required_capability": REQUIRED_PRIVACY_CAPABILITY,
        "required_derivation_version": required_derivation_version,
        "content_class": content_class,
    }
    frozen = FrozenAIEvidenceSet(
        case_id=int(case_id),
        observations=tuple(normalized),
        generation_authorities=tuple(authorities.values()),
        required_capability=REQUIRED_PRIVACY_CAPABILITY,
        required_derivation_version=str(required_derivation_version),
        content_class=content_class,
        selected_evidence_count=len(normalized),
        identity_fingerprint=canonical_fingerprint(identity),
        frozen_at=_utcnow(),
        user_text_present=bool(user_text_present),
        non_event_case_content=bool(non_event_case_content),
        ch_queries=int(ch_queries),
        pg_queries=pg_queries,
        construction_ms=(time.perf_counter() - started) * 1000.0,
    )
    return frozen


def select_current_generation_event_rows(
    session,
    clickhouse_client,
    *,
    case_id: int,
    source_ref_type: str,
    source_ref_id: str,
    evidence_record_keys: Optional[Sequence[str]] = None,
    limit: Optional[int] = None,
) -> tuple[list[dict[str, Any]], int]:
    """Select published/current-generation physical rows only. One batched CH query."""
    generation = resolve_default_capability_generation(
        session,
        case_id=int(case_id),
        source_ref_type=source_ref_type,
        source_ref_id=str(source_ref_id),
    )
    if generation is None or not generation_satisfies_default_gate(generation):
        return [], 0
    columns = ", ".join(_DEFAULT_CH_PROJECTION)
    clauses = [
        "case_id = {case_id:UInt32}",
        "source_generation = {source_generation:UInt32}",
        "source_ref_type = {source_ref_type:String}",
        "source_ref_id = {source_ref_id:String}",
    ]
    params: dict[str, Any] = {
        "case_id": int(case_id),
        "source_generation": int(generation.source_generation),
        "source_ref_type": source_ref_type,
        "source_ref_id": str(source_ref_id),
    }
    if evidence_record_keys:
        keys = [str(key) for key in evidence_record_keys if str(key or "").strip()]
        clauses.append("evidence_record_key IN {keys:Array(String)}")
        params["keys"] = keys
    query = f"""
        SELECT {columns}
        FROM events
        WHERE {' AND '.join(clauses)}
    """
    if limit is not None:
        query += " LIMIT {limit:UInt32}"
        params["limit"] = int(limit)
    result = clickhouse_client.query(query, parameters=params)
    rows = []
    for values in result.result_rows:
        row = dict(zip(_DEFAULT_CH_PROJECTION, values))
        rows.append(row)
    return rows, 1


def freeze_selected_clickhouse_rows(
    session,
    *,
    case_id: int,
    rows: Sequence[dict[str, Any]],
    required_derivation_version: str = DEFAULT_PRIVACY_DERIVATION_VERSION,
    user_text_present: bool = False,
    non_event_case_content: bool = False,
    ch_queries: int = 1,
) -> FrozenAIEvidenceSet:
    observations = []
    for row in rows:
        ingest_batch_id = str(row.get("ingest_batch_id") or "") or None
        source_generation = row.get("source_generation")
        observations.append(
            {
                "case_id": int(row.get("case_id") or case_id),
                "evidence_record_key": str(row.get("evidence_record_key") or ""),
                "ingest_batch_id": ingest_batch_id,
                "source_ref_type": row.get("source_ref_type"),
                "source_ref_id": row.get("source_ref_id"),
                "source_generation": int(source_generation) if source_generation is not None else None,
                "managed": bool(ingest_batch_id),
                "payload_excerpt": _excerpt_from_row(row),
            }
        )
    return freeze_selected_observations(
        session,
        case_id=case_id,
        observations=observations,
        required_derivation_version=required_derivation_version,
        user_text_present=user_text_present,
        non_event_case_content=non_event_case_content,
        ch_queries=ch_queries,
    )


def _map_coverage_reason(result) -> str:
    reason = str(getattr(result, "reason", "") or "")
    if reason == "non_durable_batches":
        return REASON_NON_DURABLE_BATCH
    if reason == "uncovered_batches":
        return REASON_UNCOVERED_BATCH
    if reason == "empty_batch_set":
        return REASON_EMPTY_FORENSIC_BYPASS
    if reason in {"unknown_batch_ids", "erk_missing_ingest_batch"}:
        return REASON_CROSS_CASE_OR_MALFORMED
    return reason or REASON_UNCOVERED_BATCH


def _classify_non_durable_reason(session, batch_ids: Sequence[str]) -> str:
    batches = _query_batches(session, batch_ids)
    if any(batch.state == IngestBatchState.STAGED for batch in batches.values()):
        return REASON_STAGED_BATCH
    return REASON_NON_DURABLE_BATCH


def verify_frozen_privacy_coverage(
    session,
    frozen: FrozenAIEvidenceSet,
    *,
    raw_payload: Any,
    required_derivation_version: Optional[str] = None,
) -> VerifiedFrozenEgressProof:
    """Verify exact frozen-batch coverage, then bind the raw payload fingerprint.

    Aliasing is not proof. This step only checks E1 watermark authority for the
    exact frozen managed batches. Callers must alias the same payload afterwards.
    """
    started = time.perf_counter()
    if not isinstance(frozen, FrozenAIEvidenceSet):
        raise AIPrivacyPreflightError(REASON_MISSING_FROZEN_PROOF)
    required_version = str(required_derivation_version or frozen.required_derivation_version)
    if required_version != frozen.required_derivation_version:
        raise AIPrivacyPreflightError(REASON_WRONG_DERIVATION_VERSION)
    if frozen.has_legacy_evidence:
        raise AIPrivacyPreflightError(REASON_LEGACY_UNPROVABLE)
    if frozen.forensic_event_count == 0:
        if frozen.content_class == CONTENT_CLASS_STATIC_ONLY and not frozen.user_text_present and not frozen.non_event_case_content:
            raise AIPrivacyPreflightError(
                REASON_EMPTY_FORENSIC_BYPASS,
                detail="static_only_is_not_case_content",
            )
        if frozen.non_event_case_content:
            raise AIPrivacyPreflightError(REASON_NON_EVENT_UNSUPPORTED)
        if not frozen.user_text_present:
            raise AIPrivacyPreflightError(REASON_EMPTY_FORENSIC_BYPASS)
        # User-text-only: no fabricated batch coverage. Sanitizer remains required.
        return VerifiedFrozenEgressProof(
            frozen=frozen,
            required_capability=frozen.required_capability,
            required_derivation_version=required_version,
            raw_payload_fingerprint=canonical_fingerprint(raw_payload),
            coverage_reason="user_text_only_no_forensic_batches",
            verified_at=_utcnow(),
            generation_authorities=frozen.generation_authorities,
            verification_ms=(time.perf_counter() - started) * 1000.0,
            pg_queries=0,
            _token=_PROOF_TOKEN,
        )

    authorities = []
    pg_queries = 0
    for authority in frozen.generation_authorities:
        generation = (
            session.query(EvidenceSourceGeneration)
            .filter_by(
                case_id=authority.case_id,
                source_ref_type=authority.source_ref_type,
                source_ref_id=authority.source_ref_id,
                source_generation=authority.source_generation,
            )
            .one_or_none()
        )
        pg_queries += 1
        if generation is None:
            raise AIPrivacyPreflightError(REASON_CROSS_CASE_OR_MALFORMED, detail="generation_missing")
        if generation.visibility_state == EvidenceGenerationState.INVALIDATED:
            raise AIPrivacyPreflightError(REASON_GENERATION_INVALIDATED)
        if generation.visibility_state == EvidenceGenerationState.FAILED:
            raise AIPrivacyPreflightError(REASON_GENERATION_FAILED)
        if generation.visibility_state == EvidenceGenerationState.SUPERSEDED:
            raise AIPrivacyPreflightError(REASON_GENERATION_SUPERSEDED)
        if int(generation.state_version or 1) != int(authority.state_version):
            raise AIPrivacyPreflightError(REASON_GENERATION_AUTHORITY_CHANGED)
        default = resolve_default_capability_generation(
            session,
            case_id=authority.case_id,
            source_ref_type=authority.source_ref_type,
            source_ref_id=authority.source_ref_id,
        )
        pg_queries += 1
        if default is None or int(default.source_generation) != int(authority.source_generation):
            raise AIPrivacyPreflightError(REASON_GENERATION_NOT_CURRENT)
        watermark = get_capability_watermark(
            session,
            case_id=authority.case_id,
            capability=frozen.required_capability,
            source_ref_type=authority.source_ref_type,
            source_ref_id=authority.source_ref_id,
            source_generation=authority.source_generation,
            derivation_version=required_version,
        )
        pg_queries += 1
        authorities.append(_authority_from_generation(generation, watermark))

    batch_ids = frozen.managed_batch_ids
    coverage = verify_capability_batch_coverage(
        session,
        capability=frozen.required_capability,
        derivation_version=required_version,
        batch_ids=batch_ids,
    )
    pg_queries += 1
    if not coverage.covered:
        reason = _map_coverage_reason(coverage)
        if reason == REASON_NON_DURABLE_BATCH:
            reason = _classify_non_durable_reason(session, coverage.missing_batch_ids or batch_ids)
        if required_version != DEFAULT_PRIVACY_DERIVATION_VERSION and coverage.reason in {
            "uncovered_batches",
            "watermark_not_started",
            "not_complete",
        }:
            reason = REASON_WRONG_DERIVATION_VERSION
        raise AIPrivacyPreflightError(reason)

    return VerifiedFrozenEgressProof(
        frozen=frozen,
        required_capability=frozen.required_capability,
        required_derivation_version=required_version,
        raw_payload_fingerprint=canonical_fingerprint(raw_payload),
        coverage_reason=coverage.reason,
        verified_at=_utcnow(),
        generation_authorities=tuple(authorities),
        verification_ms=(time.perf_counter() - started) * 1000.0,
        pg_queries=pg_queries,
        _token=_PROOF_TOKEN,
    )


def _walk_payload_forensic_identities(value: Any) -> tuple[set[str], set[str], bool]:
    """Collect ERK / ingest_batch_id identities and tool-retrieval shape."""
    erks: set[str] = set()
    batches: set[str] = set()
    has_tool_retrieval = False

    def walk(item: Any) -> None:
        nonlocal has_tool_retrieval
        if isinstance(item, dict):
            role = str(item.get("role") or "").strip().lower()
            if role in _TOOL_MESSAGE_ROLES:
                has_tool_retrieval = True
            erk = item.get("evidence_record_key")
            if erk:
                erks.add(str(erk))
            batch_id = item.get("ingest_batch_id")
            if batch_id:
                batches.add(str(batch_id))
            for child in item.values():
                walk(child)
            return
        if isinstance(item, (list, tuple)):
            for child in item:
                walk(child)
            return
        if isinstance(item, str):
            for match in _ERK_MARK_RE.finditer(item):
                erks.add(match.group(1))

    walk(value)
    return erks, batches, has_tool_retrieval


def inherit_verified_proof_for_followon_payload(
    session,
    proof: VerifiedFrozenEgressProof,
    *,
    raw_payload: Any,
    followon_kind: str = FOLLOWON_KIND_SECOND_PASS_REVIEW,
) -> VerifiedFrozenEgressProof:
    """Bind a later provider payload to the same frozen evidence identity.

    Production use is second-pass review of a draft derived from the same
    frozen set. This helper does not retrieve evidence and must not be used
    to attach newly retrieved forensic identities to an older proof.
    """
    if not is_verified_egress_proof(proof):
        raise AIPrivacyPreflightError(REASON_MISSING_FROZEN_PROOF)
    if str(followon_kind or "") not in _ALLOWED_FOLLOWON_KINDS:
        raise AIPrivacyPreflightError(
            REASON_FOLLOWON_NEW_EVIDENCE,
            detail="unsupported_followon_kind",
        )
    payload_erks, payload_batches, has_tool_retrieval = _walk_payload_forensic_identities(raw_payload)
    if has_tool_retrieval:
        raise AIPrivacyPreflightError(
            REASON_FOLLOWON_NEW_EVIDENCE,
            detail="tool_retrieval_requires_new_freeze",
        )
    frozen_erks = {str(erk) for erk in proof.frozen.selected_erks if erk}
    frozen_batches = {str(batch_id) for batch_id in proof.frozen.selected_ingest_batch_ids if batch_id}
    extra_erks = payload_erks - frozen_erks
    extra_batches = payload_batches - frozen_batches
    if extra_erks or extra_batches:
        raise AIPrivacyPreflightError(
            REASON_FOLLOWON_NEW_EVIDENCE,
            detail="new_forensic_identity_requires_new_freeze",
        )
    return verify_frozen_privacy_coverage(
        session,
        proof.frozen,
        raw_payload=raw_payload,
        required_derivation_version=proof.required_derivation_version,
    )


def revalidate_verified_proof(
    session,
    proof: VerifiedFrozenEgressProof,
    *,
    case_id: int,
    raw_payload: Any,
    required_derivation_version: Optional[str] = None,
) -> FrozenGenerationAuthority | tuple[FrozenGenerationAuthority, ...]:
    """Final provider-boundary revalidation. Never expands frozen membership."""
    if not is_verified_egress_proof(proof):
        raise AIPrivacyPreflightError(REASON_MISSING_FROZEN_PROOF)
    if int(proof.frozen.case_id) != int(case_id):
        raise AIPrivacyPreflightError(REASON_CROSS_CASE_OR_MALFORMED, detail="case_mismatch")
    required_version = str(required_derivation_version or proof.required_derivation_version)
    if required_version != proof.required_derivation_version:
        raise AIPrivacyPreflightError(REASON_WRONG_DERIVATION_VERSION)
    if canonical_fingerprint(raw_payload) != proof.raw_payload_fingerprint:
        raise AIPrivacyPreflightError(REASON_PAYLOAD_FINGERPRINT_MISMATCH)

    if proof.frozen.has_legacy_evidence:
        raise AIPrivacyPreflightError(REASON_LEGACY_UNPROVABLE)
    if proof.frozen.forensic_event_count == 0:
        if proof.frozen.non_event_case_content:
            raise AIPrivacyPreflightError(REASON_NON_EVENT_UNSUPPORTED)
        if proof.coverage_reason == "user_text_only_no_forensic_batches":
            return proof.generation_authorities
        raise AIPrivacyPreflightError(REASON_EMPTY_FORENSIC_BYPASS)

    refreshed = verify_frozen_privacy_coverage(
        session,
        proof.frozen,
        raw_payload=raw_payload,
        required_derivation_version=required_version,
    )
    for previous, current in zip(proof.generation_authorities, refreshed.generation_authorities):
        if int(previous.state_version) != int(current.state_version):
            raise AIPrivacyPreflightError(REASON_GENERATION_AUTHORITY_CHANGED)
        if previous.visibility_state != current.visibility_state:
            if current.visibility_state == EvidenceGenerationState.INVALIDATED:
                raise AIPrivacyPreflightError(REASON_GENERATION_INVALIDATED)
            if current.visibility_state == EvidenceGenerationState.SUPERSEDED:
                raise AIPrivacyPreflightError(REASON_GENERATION_SUPERSEDED)
            if current.visibility_state == EvidenceGenerationState.FAILED:
                raise AIPrivacyPreflightError(REASON_GENERATION_FAILED)
            raise AIPrivacyPreflightError(REASON_GENERATION_AUTHORITY_CHANGED)
        if (
            previous.watermark_state_version is not None
            and current.watermark_state_version is not None
            and int(previous.watermark_state_version) != int(current.watermark_state_version)
        ):
            # Watermark changed: coverage was revalidated above for the same IDs.
            # Invalidation is already fail-closed by verify_frozen_privacy_coverage.
            continue
    return refreshed.generation_authorities


def build_verified_privacy_context(case_id: int, proof: VerifiedFrozenEgressProof, **kwargs):
    from utils.privacy_aliases import AIPrivacyContext
    return AIPrivacyContext.verified_case_content(int(case_id), proof, **kwargs)


def prepare_verified_case_content(
    session,
    frozen: FrozenAIEvidenceSet,
    *,
    raw_payload: Any,
    required_derivation_version: Optional[str] = None,
    **kwargs,
):
    proof = verify_frozen_privacy_coverage(
        session,
        frozen,
        raw_payload=raw_payload,
        required_derivation_version=required_derivation_version,
    )
    return build_verified_privacy_context(frozen.case_id, proof, **kwargs), proof


def privacy_audit_metadata(
    *,
    privacy_context: Any,
    provider: Any,
    strict_enabled: bool,
    verification_passed: Optional[bool],
    failure_reason: Optional[str] = None,
    aliased: bool = False,
    aliases_applied: int = 0,
    outbound_payload_fingerprint: Optional[str] = None,
    provider_invoked: bool = False,
) -> dict[str, Any]:
    proof = getattr(privacy_context, "verified_egress", None)
    frozen = getattr(proof, "frozen", None) if proof is not None else None
    locality = classify_provider_locality(provider)
    generations = []
    if frozen is not None:
        generations = sorted({
            int(item.source_generation)
            for item in frozen.observations
            if item.source_generation is not None
        })
    return {
        "strict_e2_enabled": bool(strict_enabled),
        "provider_locality": locality,
        "frozen_evidence_fingerprint": None if frozen is None else frozen.identity_fingerprint,
        "erk_count": 0 if frozen is None else frozen.forensic_event_count,
        "batch_count": 0 if frozen is None else len(frozen.managed_batch_ids),
        "source_generations": generations,
        "required_capability": None if frozen is None else frozen.required_capability,
        "required_derivation_version": None if frozen is None else frozen.required_derivation_version,
        "verification_passed": verification_passed,
        "failure_reason": failure_reason,
        "aliased": bool(aliased),
        "aliases_applied": int(aliases_applied),
        "final_outbound_payload_fingerprint": outbound_payload_fingerprint,
        "provider_invoked": bool(provider_invoked),
        "occurred_at": _utcnow().isoformat(),
    }


def require_remote_case_content_preflight(
    *,
    session,
    provider: Any,
    privacy_context: Any,
    raw_payload: Any,
    function: str,
    mode: str,
) -> Optional[VerifiedFrozenEgressProof]:
    """Final router gate. Returns the proof when strict remote case-content applies."""
    if not freeze_verify_enabled():
        return None
    locality = classify_provider_locality(provider)
    if locality == "uncertain":
        if is_remote_case_content_boundary(provider, privacy_context):
            raise AIPrivacyPreflightError(REASON_PROVIDER_LOCALITY_UNCERTAIN)
        return None
    if locality == "local":
        return None
    if not is_remote_case_content_boundary(provider, privacy_context):
        return None
    proof = getattr(privacy_context, "verified_egress", None)
    case_id = getattr(privacy_context, "case_id", None)
    if not is_verified_egress_proof(proof) or not case_id:
        raise AIPrivacyPreflightError(REASON_MISSING_FROZEN_PROOF)
    if session is None:
        raise AIPrivacyPreflightError(REASON_MISSING_FROZEN_PROOF, detail="authority_session_unavailable")
    revalidate_verified_proof(
        session,
        proof,
        case_id=int(case_id),
        raw_payload=raw_payload,
    )
    return proof


def get_preflight_session():
    """Best-effort current PostgreSQL session for router preflight."""
    try:
        from flask import has_app_context
        if not has_app_context():
            return None
        from models.database import db
        return db.session
    except Exception:
        return None
