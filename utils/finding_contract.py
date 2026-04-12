"""Canonical finding contract helpers for Phase 1 surfaces."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional


LOCKED_FINDING_FIELDS = (
    "rule_pack",
    "rule_id",
    "name",
    "severity",
    "confidence",
    "mitre_techniques",
    "event_ids",
    "host",
    "user",
    "process",
    "first_seen",
    "last_seen",
    "dedup_key",
    "detector_metadata",
    "ai_triage",
    "ti_enrichment",
)


def _stringify(value: Any) -> str:
    return str(value or "").strip()


def _first_non_empty(*values: Any) -> str:
    for value in values:
        if isinstance(value, str):
            cleaned = value.strip()
            if cleaned:
                return cleaned
        elif value not in (None, "", [], {}):
            return str(value).strip()
    return ""


def _first_list_value(values: Any) -> str:
    if isinstance(values, (list, tuple)):
        for value in values:
            cleaned = _stringify(value)
            if cleaned:
                return cleaned
    return ""


def normalize_string_list(values: Any) -> List[str]:
    """Normalize strings, preserving stable input order."""
    if values in (None, ""):
        return []
    if not isinstance(values, (list, tuple, set)):
        values = [values]

    normalized: List[str] = []
    seen = set()
    for value in values:
        cleaned = _stringify(value)
        if not cleaned:
            continue
        key = cleaned.lower()
        if key in seen:
            continue
        seen.add(key)
        normalized.append(cleaned)
    return normalized


def normalize_mitre_techniques(values: Any) -> List[str]:
    """Normalize MITRE technique IDs while preserving order."""
    techniques: List[str] = []
    for value in normalize_string_list(values):
        cleaned = value.upper()
        if cleaned.startswith("ATTACK."):
            cleaned = cleaned.split(".", 1)[1]
        if cleaned not in techniques:
            techniques.append(cleaned)
    return techniques


def isoformat_or_none(value: Any) -> Optional[str]:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return _stringify(value) or None


def severity_from_confidence(confidence: Optional[float]) -> str:
    confidence = float(confidence or 0)
    if confidence >= 90:
        return "critical"
    if confidence >= 75:
        return "high"
    if confidence >= 50:
        return "medium"
    return "low"


def slugify_rule_id(value: str, fallback: str = "finding") -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "_", _stringify(value).lower()).strip("_")
    return cleaned or fallback


def extract_event_ids(events: Any) -> List[str]:
    """Best-effort extraction of stable event identifiers."""
    if not isinstance(events, list):
        return []

    identifiers: List[str] = []
    for event in events:
        if isinstance(event, dict):
            raw_id = (
                event.get("record_id")
                or event.get("event_id")
                or event.get("id")
            )
        else:
            raw_id = event
        cleaned = _stringify(raw_id)
        if cleaned and cleaned not in identifiers:
            identifiers.append(cleaned)
    return identifiers


def build_dedup_key(
    *,
    rule_pack: str,
    rule_id: str,
    host: str = "",
    user: str = "",
    process: str = "",
    first_seen: Optional[str] = None,
    last_seen: Optional[str] = None,
) -> str:
    payload = "||".join(
        [
            _stringify(rule_pack).lower(),
            _stringify(rule_id).lower(),
            _stringify(host).lower(),
            _stringify(user).lower(),
            _stringify(process).lower(),
            _stringify(first_seen).lower(),
            _stringify(last_seen).lower(),
        ]
    )
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()


def build_finding(
    *,
    rule_pack: str,
    rule_id: str,
    name: str,
    confidence: Optional[float],
    severity: Optional[str] = None,
    mitre_techniques: Any = None,
    event_ids: Any = None,
    host: str = "",
    user: str = "",
    process: str = "",
    first_seen: Any = None,
    last_seen: Any = None,
    detector_metadata: Optional[Dict[str, Any]] = None,
    ai_triage: Optional[Dict[str, Any]] = None,
    ti_enrichment: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build the locked baseline finding contract."""
    normalized_first_seen = isoformat_or_none(first_seen)
    normalized_last_seen = isoformat_or_none(last_seen) or normalized_first_seen
    normalized_confidence = round(float(confidence or 0), 2)
    normalized_severity = _stringify(severity).lower() or severity_from_confidence(normalized_confidence)
    normalized_host = _stringify(host)
    normalized_user = _stringify(user)
    normalized_process = _stringify(process)
    normalized_rule_pack = _stringify(rule_pack)
    normalized_rule_id = _stringify(rule_id) or slugify_rule_id(name)

    return {
        "rule_pack": normalized_rule_pack,
        "rule_id": normalized_rule_id,
        "name": _stringify(name) or normalized_rule_id,
        "severity": normalized_severity,
        "confidence": normalized_confidence,
        "mitre_techniques": normalize_mitre_techniques(mitre_techniques),
        "event_ids": normalize_string_list(event_ids),
        "host": normalized_host,
        "user": normalized_user,
        "process": normalized_process,
        "first_seen": normalized_first_seen,
        "last_seen": normalized_last_seen,
        "dedup_key": build_dedup_key(
            rule_pack=normalized_rule_pack,
            rule_id=normalized_rule_id,
            host=normalized_host,
            user=normalized_user,
            process=normalized_process,
            first_seen=normalized_first_seen,
            last_seen=normalized_last_seen,
        ),
        "detector_metadata": detector_metadata or {},
        "ai_triage": ai_triage or {},
        "ti_enrichment": ti_enrichment or {},
    }


def canonicalize_finding(
    raw: Dict[str, Any],
    *,
    default_rule_pack: str = "legacy",
    default_rule_id: str = "",
) -> Dict[str, Any]:
    """Best-effort canonicalization for heterogeneous existing finding dicts."""
    raw = dict(raw or {})
    entities = raw.get("entities") if isinstance(raw.get("entities"), dict) else {}
    evidence_package = (
        raw.get("evidence_package")
        if isinstance(raw.get("evidence_package"), dict)
        else {}
    )
    anchor = evidence_package.get("anchor") if isinstance(evidence_package.get("anchor"), dict) else {}
    producer_inputs = (
        evidence_package.get("producer_inputs")
        if isinstance(evidence_package.get("producer_inputs"), list)
        else []
    )
    confidence = (
        raw.get("confidence")
        if raw.get("confidence") is not None
        else raw.get("final_confidence")
    )
    if confidence is None:
        confidence = raw.get("chain_score") or 0

    name = _first_non_empty(
        raw.get("name"),
        raw.get("pattern_name"),
        raw.get("finding_type"),
        raw.get("storyline_title"),
        _first_list_value(raw.get("rule_titles")),
        raw.get("pattern_id"),
        raw.get("correlation_key"),
        "Finding",
    )
    rule_id = _first_non_empty(
        raw.get("rule_id"),
        raw.get("pattern_id"),
        raw.get("correlation_key"),
        _first_list_value(raw.get("rule_titles")),
        default_rule_id,
    )
    host = _first_non_empty(
        raw.get("host"),
        raw.get("source_host"),
        anchor.get("source_host"),
        raw.get("entity_value") if raw.get("entity_type") == "system" else "",
        _first_list_value(entities.get("source_hosts")),
        _first_list_value(entities.get("remote_hosts")),
    )
    user = _first_non_empty(
        raw.get("user"),
        raw.get("username"),
        anchor.get("username"),
        _first_list_value(entities.get("usernames")),
    )
    process = _first_non_empty(
        raw.get("process"),
        raw.get("process_name"),
        anchor.get("process_name"),
        _first_list_value(entities.get("processes")),
    )
    first_seen = (
        raw.get("first_seen")
        or raw.get("window_start")
        or raw.get("time_start")
        or raw.get("timestamp")
        or raw.get("detected_at")
    )
    last_seen = raw.get("last_seen") or raw.get("window_end") or raw.get("time_end") or first_seen
    event_ids = raw.get("event_ids")
    if not event_ids and raw.get("events"):
        event_ids = extract_event_ids(raw.get("events"))
    if not event_ids and isinstance(anchor, dict):
        event_ids = extract_event_ids([anchor])

    detector_metadata = dict(raw.get("detector_metadata") or {})
    if evidence_package:
        detector_metadata.setdefault("evidence_package_present", True)
        producer_types = sorted(
            {
                _stringify(item.get("producer"))
                for item in producer_inputs
                if isinstance(item, dict) and _stringify(item.get("producer"))
            }
        )
        if producer_types:
            detector_metadata.setdefault("producer_types", producer_types)
        scoring_context = (
            evidence_package.get("scoring_context")
            if isinstance(evidence_package.get("scoring_context"), dict)
            else {}
        )
        if "deterministic_score" in scoring_context:
            detector_metadata.setdefault(
                "deterministic_score",
                scoring_context.get("deterministic_score"),
            )

    return build_finding(
        rule_pack=raw.get("rule_pack") or raw.get("source_system") or default_rule_pack,
        rule_id=rule_id or slugify_rule_id(name),
        name=name,
        confidence=confidence,
        severity=raw.get("severity") or raw.get("combined_severity"),
        mitre_techniques=raw.get("mitre_techniques") or evidence_package.get("mitre_techniques"),
        event_ids=event_ids,
        host=host,
        user=user,
        process=process,
        first_seen=first_seen,
        last_seen=last_seen,
        detector_metadata=detector_metadata,
        ai_triage=raw.get("ai_triage"),
        ti_enrichment=raw.get("ti_enrichment"),
    )
