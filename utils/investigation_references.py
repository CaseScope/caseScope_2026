"""Stable reference contracts for Investigation Threads and Saved Graph Views.

Versioned reference keys are durable across graph rebuild/reprojection.
Transient GraphEntity.id / GraphRelationship.id are never the durable identity.

Reference format:
    threadref:v1:<sha256>

Canonical JSON rules:
- UTF-8
- sort_keys=True
- separators=(',', ':')
- no whitespace variance
- only identity fields (no mutable display labels in the hash input)

Evidence-set fingerprint format:
    evidence-set:v1:<sha256>
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import date, datetime
from typing import Any, Iterable, Optional

from models.graph import GraphEntity, GraphRelationship
from utils.graph_identity import GraphDerivationType, GraphEntityType, GraphRelationshipType
from utils.graph_query import EVIDENCE_RECORD_KEY_RE, GraphNotFoundError, GraphQueryError


THREADREF_PREFIX = "threadref:v1:"
EVIDENCE_SET_PREFIX = "evidence-set:v1:"
SNAPSHOT_HASH_ALGORITHM = "sha256"

ENTITY_REF_SCHEMA = "entity-ref:v1"
RELATIONSHIP_REF_SCHEMA = "relationship-ref:v1"
EVIDENCE_REF_SCHEMA = "evidence-ref:v1"
IOC_REF_SCHEMA = "ioc-ref:v1"
FINDING_REF_SCHEMA = "finding-ref:v1"

FINDING_KIND_UNIFIED = "unified_finding"
FINDING_KIND_PATTERN_MATCH = "pattern_match"
FINDING_KINDS = {FINDING_KIND_UNIFIED, FINDING_KIND_PATTERN_MATCH}

ENTITY_SNAP_VERSION = "entity-snap:v1"
RELATIONSHIP_SNAP_VERSION = "rel-snap:v1"
EVIDENCE_SNAP_VERSION = "evidence-snap:v1"
IOC_SNAP_VERSION = "ioc-snap:v1"
FINDING_SNAP_VERSION = "finding-snap:v1"


class InvestigationReferenceError(ValueError):
    """Client-correctable stable-reference / snapshot error."""


def canonical_json(value: Any) -> str:
    """Serialize value to deterministic canonical JSON."""
    return json.dumps(_json_safe(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_hex(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def snapshot_sha256(snapshot: dict[str, Any]) -> str:
    """Deterministic integrity hash for a frozen snapshot dict."""
    return sha256_hex(canonical_json(snapshot))


def threadref_key(payload: dict[str, Any]) -> str:
    return f"{THREADREF_PREFIX}{sha256_hex(canonical_json(payload))}"


def evidence_set_fingerprint(membership_refs: Iterable[dict[str, Any]]) -> str:
    """Fingerprint the exact selected stable reference set (not narrative state).

    Input entries must already be typed membership descriptors. Order of
    insertion does not matter; entries are sorted by canonical JSON before hash.
    """
    normalized = [canonical_json(_json_safe(item)) for item in membership_refs]
    normalized.sort()
    return f"{EVIDENCE_SET_PREFIX}{sha256_hex('[' + ','.join(normalized) + ']')}"


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]
    return str(value)


def build_entity_reference(*, case_id: int, entity_type: str, entity_key: str) -> dict[str, Any]:
    entity_type = str(entity_type or "").strip()
    entity_key = str(entity_key or "").strip()
    if int(case_id) < 1:
        raise InvestigationReferenceError("Invalid case_id")
    if entity_type not in GraphEntityType.ALL:
        raise InvestigationReferenceError(f"Invalid entity type: {entity_type}")
    if not entity_key:
        raise InvestigationReferenceError("entity_key is required")
    payload = {
        "schema": ENTITY_REF_SCHEMA,
        "case_id": int(case_id),
        "entity_type": entity_type,
        "entity_key": entity_key,
    }
    return {
        "schema": ENTITY_REF_SCHEMA,
        "case_id": int(case_id),
        "entity_type": entity_type,
        "entity_key": entity_key,
        "stable_reference_key": threadref_key(payload),
    }


def build_relationship_reference(
    *,
    case_id: int,
    source_entity_type: str,
    source_entity_key: str,
    relationship_type: str,
    target_entity_type: str,
    target_entity_key: str,
    derivation_type: str,
) -> dict[str, Any]:
    source_entity_type = str(source_entity_type or "").strip()
    source_entity_key = str(source_entity_key or "").strip()
    relationship_type = str(relationship_type or "").strip()
    target_entity_type = str(target_entity_type or "").strip()
    target_entity_key = str(target_entity_key or "").strip()
    derivation_type = str(derivation_type or "").strip()
    if int(case_id) < 1:
        raise InvestigationReferenceError("Invalid case_id")
    if source_entity_type not in GraphEntityType.ALL or target_entity_type not in GraphEntityType.ALL:
        raise InvestigationReferenceError("Invalid entity type in relationship reference")
    if relationship_type not in GraphRelationshipType.ALL:
        raise InvestigationReferenceError(f"Invalid relationship type: {relationship_type}")
    if derivation_type not in GraphDerivationType.AUTHORITATIVE_EXTRACTOR_TYPES:
        raise InvestigationReferenceError(f"Invalid derivation type for durable edge identity: {derivation_type}")
    if not source_entity_key or not target_entity_key:
        raise InvestigationReferenceError("source and target entity keys are required")
    payload = {
        "schema": RELATIONSHIP_REF_SCHEMA,
        "case_id": int(case_id),
        "source_entity_type": source_entity_type,
        "source_entity_key": source_entity_key,
        "relationship_type": relationship_type,
        "target_entity_type": target_entity_type,
        "target_entity_key": target_entity_key,
        "derivation_type": derivation_type,
    }
    return {
        **payload,
        "stable_reference_key": threadref_key(payload),
    }


def build_evidence_reference(*, case_id: int, evidence_record_key: str, source_table: str = "events") -> dict[str, Any]:
    evidence_record_key = str(evidence_record_key or "").strip()
    source_table = str(source_table or "events").strip() or "events"
    if int(case_id) < 1:
        raise InvestigationReferenceError("Invalid case_id")
    if not EVIDENCE_RECORD_KEY_RE.fullmatch(evidence_record_key):
        raise InvestigationReferenceError("Invalid evidence_record_key; expected ^erk:v2:[0-9a-f]{64}$")
    payload = {
        "schema": EVIDENCE_REF_SCHEMA,
        "case_id": int(case_id),
        "evidence_record_key": evidence_record_key,
        "source_table": source_table,
    }
    return {
        **payload,
        "stable_reference_key": threadref_key(payload),
    }


def build_ioc_reference(*, case_id: int, ioc_uuid: str) -> dict[str, Any]:
    ioc_uuid = str(ioc_uuid or "").strip()
    if int(case_id) < 1:
        raise InvestigationReferenceError("Invalid case_id")
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", ioc_uuid):
        raise InvestigationReferenceError("Invalid IOC UUID")
    payload = {
        "schema": IOC_REF_SCHEMA,
        "case_id": int(case_id),
        "ioc_uuid": ioc_uuid,
    }
    return {
        **payload,
        "stable_reference_key": threadref_key(payload),
    }


def build_unified_finding_reference(
    *,
    case_id: int,
    analysis_id: str,
    source_system: str,
    dedup_key: str,
    finding_id: str,
) -> dict[str, Any]:
    analysis_id = str(analysis_id or "").strip()
    source_system = str(source_system or "").strip()
    dedup_key = str(dedup_key or "").strip()
    finding_id = str(finding_id or "").strip()
    if int(case_id) < 1:
        raise InvestigationReferenceError("Invalid case_id")
    if not analysis_id or not source_system or not dedup_key or not finding_id:
        raise InvestigationReferenceError("unified finding reference requires analysis_id, source_system, dedup_key, finding_id")
    payload = {
        "schema": FINDING_REF_SCHEMA,
        "finding_kind": FINDING_KIND_UNIFIED,
        "case_id": int(case_id),
        "analysis_id": analysis_id,
        "source_system": source_system,
        "dedup_key": dedup_key,
        "finding_id": finding_id,
    }
    return {
        **payload,
        "stable_reference_key": threadref_key(payload),
    }


def build_pattern_match_reference(*, case_id: int, pattern_match_id: int) -> dict[str, Any]:
    if int(case_id) < 1:
        raise InvestigationReferenceError("Invalid case_id")
    try:
        pattern_match_id = int(pattern_match_id)
    except (TypeError, ValueError) as exc:
        raise InvestigationReferenceError("Invalid pattern_match_id") from exc
    if pattern_match_id < 1:
        raise InvestigationReferenceError("Invalid pattern_match_id")
    payload = {
        "schema": FINDING_REF_SCHEMA,
        "finding_kind": FINDING_KIND_PATTERN_MATCH,
        "case_id": int(case_id),
        "pattern_match_id": pattern_match_id,
    }
    return {
        **payload,
        "stable_reference_key": threadref_key(payload),
    }


def entity_reference_from_graph_entity(entity: GraphEntity) -> dict[str, Any]:
    return build_entity_reference(
        case_id=entity.case_id,
        entity_type=entity.entity_type,
        entity_key=entity.entity_key,
    )


def relationship_reference_from_graph_relationship(
    relationship: GraphRelationship,
    *,
    source_entity: GraphEntity,
    target_entity: GraphEntity,
) -> dict[str, Any]:
    if source_entity.id != relationship.source_entity_id or target_entity.id != relationship.target_entity_id:
        raise InvestigationReferenceError("Source/target entities do not match relationship endpoints")
    if source_entity.case_id != relationship.case_id or target_entity.case_id != relationship.case_id:
        raise InvestigationReferenceError("Relationship endpoints must share case scope")
    return build_relationship_reference(
        case_id=relationship.case_id,
        source_entity_type=source_entity.entity_type,
        source_entity_key=source_entity.entity_key,
        relationship_type=relationship.relationship_type,
        target_entity_type=target_entity.entity_type,
        target_entity_key=target_entity.entity_key,
        derivation_type=relationship.derivation_type,
    )


def resolve_entity_reference(case_id: int, reference: dict[str, Any]) -> tuple[Optional[GraphEntity], bool]:
    """Resolve durable entity ref to current live GraphEntity. Returns (entity, live_available)."""
    ref = build_entity_reference(
        case_id=case_id,
        entity_type=reference.get("entity_type"),
        entity_key=reference.get("entity_key"),
    )
    if int(reference.get("case_id") or 0) not in (0, int(case_id)) and int(reference.get("case_id") or 0) != int(case_id):
        raise InvestigationReferenceError("Entity reference case_id mismatch")
    entity = GraphEntity.query.filter_by(
        case_id=int(case_id),
        entity_type=ref["entity_type"],
        entity_key=ref["entity_key"],
    ).first()
    return entity, entity is not None


def resolve_relationship_reference(
    case_id: int,
    reference: dict[str, Any],
) -> tuple[Optional[GraphRelationship], bool, Optional[GraphEntity], Optional[GraphEntity]]:
    ref = build_relationship_reference(
        case_id=case_id,
        source_entity_type=reference.get("source_entity_type"),
        source_entity_key=reference.get("source_entity_key"),
        relationship_type=reference.get("relationship_type"),
        target_entity_type=reference.get("target_entity_type"),
        target_entity_key=reference.get("target_entity_key"),
        derivation_type=reference.get("derivation_type"),
    )
    source = GraphEntity.query.filter_by(
        case_id=int(case_id),
        entity_type=ref["source_entity_type"],
        entity_key=ref["source_entity_key"],
    ).first()
    target = GraphEntity.query.filter_by(
        case_id=int(case_id),
        entity_type=ref["target_entity_type"],
        entity_key=ref["target_entity_key"],
    ).first()
    if source is None or target is None:
        return None, False, source, target
    relationship = GraphRelationship.query.filter_by(
        case_id=int(case_id),
        source_entity_id=source.id,
        relationship_type=ref["relationship_type"],
        target_entity_id=target.id,
        derivation_type=ref["derivation_type"],
    ).first()
    return relationship, relationship is not None, source, target


def entity_snapshot_from_graph_entity(entity: GraphEntity) -> dict[str, Any]:
    snapshot = {
        "snapshot_version": ENTITY_SNAP_VERSION,
        "case_id": entity.case_id,
        "entity_type": entity.entity_type,
        "entity_key": entity.entity_key,
        "display_value": entity.display_value,
        "canonical_value": entity.canonical_value,
        "first_seen_at": entity.first_seen_at,
        "last_seen_at": entity.last_seen_at,
        "metadata": entity.metadata_json or {},
    }
    return _json_safe(snapshot)


def relationship_snapshot_from_graph(
    relationship: GraphRelationship,
    *,
    source_entity: GraphEntity,
    target_entity: GraphEntity,
) -> dict[str, Any]:
    snapshot = {
        "snapshot_version": RELATIONSHIP_SNAP_VERSION,
        "case_id": relationship.case_id,
        "relationship_type": relationship.relationship_type,
        "derivation_type": relationship.derivation_type,
        "confidence": relationship.confidence,
        "validation_state": relationship.validation_state,
        "first_seen_at": relationship.first_seen_at,
        "last_seen_at": relationship.last_seen_at,
        "source": {
            "entity_type": source_entity.entity_type,
            "entity_key": source_entity.entity_key,
            "display_value": source_entity.display_value,
            "canonical_value": source_entity.canonical_value,
        },
        "target": {
            "entity_type": target_entity.entity_type,
            "entity_key": target_entity.entity_key,
            "display_value": target_entity.display_value,
            "canonical_value": target_entity.canonical_value,
        },
        "metadata": relationship.metadata_json or {},
    }
    return _json_safe(snapshot)


def build_evidence_snapshot(
    *,
    case_id: int,
    evidence_record_key: str,
    event: Optional[dict[str, Any]],
    source_table: str = "events",
    source_available: bool,
    originating_relationship_reference: Optional[dict[str, Any]] = None,
    analyst_visible_summary: Optional[str] = None,
) -> dict[str, Any]:
    """Curated forensic snapshot — not a second event warehouse."""
    event = event or {}
    summary = analyst_visible_summary
    if not summary:
        parts = [
            str(event.get("timestamp_utc") or event.get("timestamp") or "").strip(),
            str(event.get("source_host") or "").strip(),
            str(event.get("event_id") or "").strip(),
            str(event.get("process_name") or event.get("process_path") or "").strip(),
            evidence_record_key,
        ]
        summary = " | ".join(p for p in parts if p)[:2000]

    snapshot = {
        "snapshot_version": EVIDENCE_SNAP_VERSION,
        "case_id": int(case_id),
        "evidence_record_key": evidence_record_key,
        "evidence_identity_version": event.get("evidence_identity_version"),
        "evidence_identity_quality": event.get("evidence_identity_quality"),
        "source_table": source_table,
        "source_available_at_addition": bool(source_available),
        "timestamp": event.get("timestamp"),
        "timestamp_utc": event.get("timestamp_utc"),
        "artifact_type": event.get("artifact_type"),
        "source_file": event.get("source_file"),
        "source_path": event.get("source_path"),
        "source_host": event.get("source_host"),
        "event_id": event.get("event_id"),
        "channel": event.get("channel"),
        "provider": event.get("provider"),
        "record_id": event.get("record_id"),
        "username": event.get("username"),
        "domain": event.get("domain"),
        "sid": event.get("sid"),
        "process_name": event.get("process_name"),
        "process_path": event.get("process_path"),
        "process_id": event.get("process_id"),
        "parent_process": event.get("parent_process"),
        "parent_pid": event.get("parent_pid"),
        "command_line": event.get("command_line"),
        "target_path": event.get("target_path"),
        "file_hash_md5": event.get("file_hash_md5"),
        "file_hash_sha1": event.get("file_hash_sha1"),
        "file_hash_sha256": event.get("file_hash_sha256"),
        "src_ip": event.get("src_ip"),
        "dst_ip": event.get("dst_ip"),
        "src_port": event.get("src_port"),
        "dst_port": event.get("dst_port"),
        "reg_key": event.get("reg_key"),
        "reg_value": event.get("reg_value"),
        "reg_data": event.get("reg_data"),
        "parser_version": event.get("parser_version"),
        "selector_key": event.get("selector_key"),
        "analyst_visible_summary": summary,
        "originating_relationship_reference": originating_relationship_reference,
    }
    return _json_safe(snapshot)


def ioc_snapshot_from_model(ioc) -> dict[str, Any]:
    snapshot = {
        "snapshot_version": IOC_SNAP_VERSION,
        "case_id": ioc.case_id,
        "ioc_uuid": ioc.uuid,
        "ioc_type": ioc.ioc_type,
        "category": getattr(ioc, "category", None),
        "value": ioc.value,
        "value_normalized": ioc.value_normalized,
        "match_type": getattr(ioc, "match_type", None),
        "malicious": getattr(ioc, "malicious", None),
        "false_positive": getattr(ioc, "false_positive", None),
        "active": getattr(ioc, "active", None),
        "notes": getattr(ioc, "notes", None),
        "sources": getattr(ioc, "sources", None),
    }
    return _json_safe(snapshot)


def unified_finding_snapshot(
    *,
    case_id: int,
    analysis_id: str,
    source_system: str,
    dedup_key: str,
    finding_id: str,
    finding: dict[str, Any],
) -> dict[str, Any]:
    canonical = finding.get("canonical") if isinstance(finding.get("canonical"), dict) else {}
    snapshot = {
        "snapshot_version": FINDING_SNAP_VERSION,
        "finding_kind": FINDING_KIND_UNIFIED,
        "case_id": int(case_id),
        "analysis_id": str(analysis_id),
        "source_system": str(source_system),
        "dedup_key": str(dedup_key),
        "finding_id": str(finding_id),
        "title": finding.get("title") or finding.get("name") or canonical.get("title"),
        "name": finding.get("name") or finding.get("title"),
        "category": finding.get("category") or canonical.get("category"),
        "severity": finding.get("severity") or canonical.get("severity"),
        "confidence": finding.get("confidence") or canonical.get("confidence"),
        "host": finding.get("host") or canonical.get("host"),
        "user": finding.get("user") or canonical.get("user"),
        "process": finding.get("process") or canonical.get("process"),
        "first_seen": finding.get("first_seen") or canonical.get("first_seen"),
        "last_seen": finding.get("last_seen") or canonical.get("last_seen"),
        "mitre_techniques": finding.get("mitre_techniques") or canonical.get("mitre_techniques"),
        "rule_pack": finding.get("rule_pack") or canonical.get("rule_pack"),
        "rule_id": finding.get("rule_id") or canonical.get("rule_id"),
        "bounded_canonical": {
            k: canonical.get(k)
            for k in (
                "title",
                "category",
                "severity",
                "confidence",
                "host",
                "user",
                "process",
                "dedup_key",
                "rule_pack",
                "rule_id",
            )
            if k in canonical
        },
    }
    return _json_safe(snapshot)


def pattern_match_snapshot(match) -> dict[str, Any]:
    snapshot = {
        "snapshot_version": FINDING_SNAP_VERSION,
        "finding_kind": FINDING_KIND_PATTERN_MATCH,
        "case_id": match.case_id,
        "pattern_match_id": match.id,
        "pattern_id": match.pattern_id,
        "confidence_score": match.confidence_score,
        "matched_event_count": match.matched_event_count,
        "first_event_time": match.first_event_time,
        "last_event_time": match.last_event_time,
        "source_host": match.source_host,
        "analyst_verdict": match.analyst_verdict,
        "include_in_timeline": match.include_in_timeline,
    }
    return _json_safe(snapshot)


def membership_fingerprint_entry(*, kind: str, stable_reference_key: str, snapshot_sha256_value: Optional[str] = None) -> dict[str, Any]:
    entry = {
        "kind": kind,
        "stable_reference_key": stable_reference_key,
    }
    if snapshot_sha256_value:
        entry["snapshot_sha256"] = snapshot_sha256_value
    return entry


def require_graph_entity(case_id: int, entity_id: int) -> GraphEntity:
    try:
        entity_id = int(entity_id)
    except (TypeError, ValueError) as exc:
        raise InvestigationReferenceError("Invalid entity_id") from exc
    entity = GraphEntity.query.filter_by(case_id=int(case_id), id=entity_id).first()
    if entity is None:
        raise GraphNotFoundError("Entity not found")
    return entity


def require_graph_relationship(case_id: int, relationship_id: int) -> tuple[GraphRelationship, GraphEntity, GraphEntity]:
    try:
        relationship_id = int(relationship_id)
    except (TypeError, ValueError) as exc:
        raise InvestigationReferenceError("Invalid relationship_id") from exc
    relationship = GraphRelationship.query.filter_by(case_id=int(case_id), id=relationship_id).first()
    if relationship is None:
        raise GraphNotFoundError("Relationship not found")
    source = GraphEntity.query.filter_by(case_id=int(case_id), id=relationship.source_entity_id).first()
    target = GraphEntity.query.filter_by(case_id=int(case_id), id=relationship.target_entity_id).first()
    if source is None or target is None:
        raise GraphQueryError("Relationship endpoints missing for case")
    return relationship, source, target
