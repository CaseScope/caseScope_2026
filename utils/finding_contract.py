"""Canonical finding contract helpers for Phase 1 surfaces."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from typing import Any, Callable, Dict, Iterable, List, Optional


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


def build_hayabusa_correlation_finding(
    *,
    correlation_key: str,
    rule_titles: List[str],
    combined_severity: str,
    chain_score: Optional[float],
    mitre_techniques: Any,
    events: List[Dict[str, Any]],
    source_hosts: Any = None,
    usernames: Any = None,
    processes: Any = None,
    source_ips: Any = None,
    remote_hosts: Any = None,
    time_start: Any = None,
    time_end: Any = None,
    mitre_tactics: Any = None,
    kill_chain_phases: Any = None,
    attack_chain_description: str = "",
    behavioral_context: Optional[Dict[str, Any]] = None,
    anomaly_flags: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build the canonical finding contract for a Hayabusa correlated chain."""
    primary_rule_title = rule_titles[0] if rule_titles else correlation_key
    normalized_source_hosts = normalize_string_list(source_hosts)
    normalized_usernames = normalize_string_list(usernames)
    normalized_processes = normalize_string_list(processes)
    normalized_source_ips = normalize_string_list(source_ips)
    normalized_remote_hosts = normalize_string_list(remote_hosts)

    return build_finding(
        rule_pack='hayabusa',
        rule_id=slugify_rule_id(primary_rule_title, fallback='hayabusa_chain'),
        name=primary_rule_title or 'Hayabusa Correlated Detection',
        severity=combined_severity,
        confidence=chain_score,
        mitre_techniques=mitre_techniques,
        event_ids=extract_event_ids(events),
        host=normalized_source_hosts[0] if normalized_source_hosts else '',
        user=normalized_usernames[0] if normalized_usernames else '',
        process=normalized_processes[0] if normalized_processes else '',
        first_seen=time_start,
        last_seen=time_end,
        detector_metadata={
            'producer': 'hayabusa_correlator',
            'producer_type': 'hayabusa_chain',
            'correlation_key': correlation_key,
            'event_count': len(events or []),
            'rule_titles': list(rule_titles or []),
            'mitre_tactics': normalize_string_list(mitre_tactics),
            'kill_chain_phases': normalize_string_list(kill_chain_phases),
            'attack_chain_description': attack_chain_description,
            'behavioral_context': behavioral_context or {},
            'anomaly_flags': anomaly_flags or {},
            'entities': {
                'usernames': normalized_usernames,
                'source_hosts': normalized_source_hosts,
                'source_ips': normalized_source_ips,
                'remote_hosts': normalized_remote_hosts,
                'processes': normalized_processes,
            },
        },
    )


def build_pattern_rule_finding(
    *,
    pattern_id: str,
    pattern_name: str,
    confidence: Optional[float],
    severity: Optional[str],
    mitre_techniques: Any,
    source_host: str = "",
    username: str = "",
    first_seen: Any = None,
    last_seen: Any = None,
    confidence_factors: Optional[Dict[str, Any]] = None,
    indicators: Any = None,
) -> Dict[str, Any]:
    """Build the canonical finding contract for a persisted pattern-rule match."""
    return build_finding(
        rule_pack='pattern_rule',
        rule_id=pattern_id or '',
        name=pattern_name or '',
        confidence=confidence or 0,
        severity=severity or 'medium',
        mitre_techniques=mitre_techniques or [],
        host=source_host or '',
        user=username or '',
        first_seen=first_seen,
        last_seen=last_seen,
        detector_metadata={
            'producer': 'pattern_rule',
            'producer_type': 'rule_based_detection',
            'confidence_factors': dict(confidence_factors or {}),
            'indicators': normalize_string_list(indicators),
        },
    )


def build_rag_pattern_finding(
    *,
    pattern_id: str,
    pattern_name: str,
    confidence: Optional[float],
    severity: Optional[str],
    mitre_techniques: Any,
    source_host: str = "",
    first_seen: Any = None,
    last_seen: Any = None,
    raw_score: Optional[float] = None,
    confidence_weight: Optional[float] = None,
) -> Dict[str, Any]:
    """Build the canonical finding contract for a RAG pattern-discovery match."""
    return build_finding(
        rule_pack='rag_pattern',
        rule_id=pattern_id or '',
        name=pattern_name or '',
        confidence=confidence or 0,
        severity=severity or 'medium',
        mitre_techniques=mitre_techniques or [],
        host=source_host or '',
        first_seen=first_seen,
        last_seen=last_seen,
        detector_metadata={
            'producer': 'rag_pattern',
            'producer_type': 'pattern_discovery',
            'raw_score': raw_score,
            'confidence_weight': confidence_weight,
        },
    )


def build_gap_detector_producer_input(
    *,
    finding_type: str,
    pattern_id: str,
    confidence: Any = 0,
    entity_type: str = "",
    entity_value: str = "",
    event_count: Any = 0,
    source_ips: Any = None,
    evidence_keys: Any = None,
    detail_keys: Any = None,
) -> Dict[str, Any]:
    """Build the canonical producer-input contract for a gap-detector finding."""
    return {
        'producer': 'gap_detector',
        'producer_type': _stringify(finding_type),
        'pattern_id': _stringify(pattern_id),
        'confidence': confidence or 0,
        'entity_type': _stringify(entity_type),
        'entity_value': _stringify(entity_value),
        'mapped_checks': [],
        'detector_metadata': {
            'event_count': event_count or 0,
            'source_ips': normalize_string_list(source_ips),
            'evidence_keys': sorted(evidence_keys or []),
            'detail_keys': sorted(detail_keys or []),
        },
    }


def get_gap_finding_result_status(confidence: Any) -> str:
    """Return canonical check-result status for a gap finding confidence."""
    normalized_confidence = float(confidence or 0)
    if normalized_confidence >= 60:
        return 'PASS'
    if normalized_confidence >= 30:
        return 'INCONCLUSIVE'
    return 'FAIL'


def get_burst_engine_contribution(bursts: Any) -> int:
    """Return canonical burst-engine contribution for a burst set."""
    return min(10, len(list(bursts or [])) * 3)


def get_burst_engine_max_possible() -> int:
    """Return canonical max possible score for burst-engine contribution."""
    return 10


def build_burst_engine_producer_input(
    *,
    pattern_id: str,
    bursts: Any,
) -> Dict[str, Any]:
    """Build the canonical producer-input contract for burst-engine output."""
    bursts = list(bursts or [])
    return {
        'producer': 'burst_engine',
        'producer_type': 'temporal_burst',
        'pattern_id': _stringify(pattern_id),
        'status': 'matched',
        'contribution': get_burst_engine_contribution(bursts),
        'max_possible': get_burst_engine_max_possible(),
        'detector_metadata': {
            'burst_count': len(bursts),
            'peak_events_in_bucket': max(
                (getattr(burst, 'events_in_bucket', 0) or 0)
                for burst in bursts
            ) if bursts else 0,
            'distinct_usernames': sorted(
                {
                    _stringify(getattr(burst, 'username', ''))
                    for burst in bursts
                    if _stringify(getattr(burst, 'username', ''))
                }
            ),
            'distinct_source_hosts': sorted(
                {
                    _stringify(getattr(burst, 'source_host', ''))
                    for burst in bursts
                    if _stringify(getattr(burst, 'source_host', ''))
                }
            ),
            'distinct_source_ips': sorted(
                {
                    _stringify(getattr(burst, 'src_ip', ''))
                    for burst in bursts
                    if _stringify(getattr(burst, 'src_ip', ''))
                }
            ),
            'buckets': [
                burst.to_dict() if hasattr(burst, 'to_dict') else dict(burst)
                for burst in bursts[:5]
            ],
        },
    }


def get_sequence_engine_contribution(status: str) -> int:
    """Return canonical sequence-engine contribution for a sequence status."""
    normalized_status = _stringify(status)
    if normalized_status == 'complete':
        return 5
    if normalized_status == 'partial':
        return 2
    return 0


def get_sequence_engine_max_possible() -> int:
    """Return canonical max possible score for sequence-engine contribution."""
    return 5


def build_sequence_engine_producer_input(
    *,
    pattern_id: str,
    sequence: Any,
) -> Dict[str, Any]:
    """Build the canonical producer-input contract for sequence-engine output."""
    status = _stringify(getattr(sequence, 'status', ''))
    contribution = get_sequence_engine_contribution(status)

    return {
        'producer': 'sequence_engine',
        'producer_type': 'ordered_event_chain',
        'pattern_id': _stringify(pattern_id),
        'status': status,
        'contribution': contribution,
        'max_possible': get_sequence_engine_max_possible(),
        'detector_metadata': {
            'chain': _stringify(getattr(sequence, 'chain', '')),
            'steps': list(getattr(sequence, 'steps', []) or []),
            'missing_steps': normalize_string_list(
                getattr(sequence, 'missing_steps', []) or []
            ),
        },
    }


def sort_producer_inputs(producer_inputs: Any) -> List[Dict[str, Any]]:
    """Return producer inputs in canonical deterministic order."""
    return sorted(
        list(producer_inputs or []),
        key=lambda item: (
            item.get('producer', ''),
            item.get('producer_type', ''),
            item.get('entity_value', ''),
            item.get('status', ''),
        ),
    )


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


def build_deterministic_analysis_finding(
    *,
    source_system: str,
    pattern_id: str,
    pattern_name: str,
    correlation_key: str,
    confidence: Optional[float],
    summary: str,
    evidence_package: Optional[Dict[str, Any]] = None,
    severity: Optional[str] = None,
    events_analyzed: int = 0,
    deterministic_score: Optional[float] = None,
    coverage_quality: Optional[float] = None,
    ai_adjustment: Optional[float] = None,
    ai_escalated: bool = False,
    ai_reasoning: str = "",
    mitre_techniques: Any = None,
    extra_fields: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a normalized deterministic finding payload from an evidence package."""
    raw: Dict[str, Any] = {
        "source_system": source_system,
        "type": "pattern",
        "detail_type": "pattern",
        "pattern_id": pattern_id,
        "pattern_name": pattern_name,
        "name": pattern_name,
        "title": pattern_name,
        "summary": summary,
        "description": summary,
        "correlation_key": correlation_key,
        "confidence": confidence,
        "final_confidence": confidence,
        "severity": severity or severity_from_confidence(confidence),
        "events_analyzed": events_analyzed,
        "event_count": events_analyzed,
        "deterministic_score": deterministic_score,
        "coverage_quality": coverage_quality,
        "ai_adjustment": ai_adjustment,
        "ai_escalated": ai_escalated,
        "ai_reasoning": ai_reasoning,
        "mitre_techniques": mitre_techniques or [],
        "evidence_package": evidence_package or {},
    }
    if extra_fields:
        raw.update(extra_fields)

    canonical = canonicalize_finding(
        raw,
        default_rule_pack=source_system,
        default_rule_id=pattern_id,
    )
    raw.setdefault(
        "entity_type",
        "system" if canonical.get("host") else ("user" if canonical.get("user") else ""),
    )
    raw.setdefault(
        "entity_value",
        canonical.get("host") or canonical.get("user") or correlation_key,
    )
    return {**raw, **canonical}


def build_ai_analysis_result_payload(
    *,
    case_id: int,
    analysis_id: str,
    pattern_id: str,
    pattern_name: str,
    correlation_key: str,
    rule_based_confidence: Optional[float] = None,
    ai_confidence: Optional[float] = None,
    ai_reasoning: Optional[str] = None,
    ai_false_positive_assessment: Optional[str] = None,
    final_confidence: Optional[float] = None,
    deterministic_score: Optional[float] = None,
    ai_adjustment: Optional[float] = None,
    coverage_quality: Optional[float] = None,
    evidence_package: Optional[Dict[str, Any]] = None,
    events_analyzed: int = 0,
    model_used: str = "",
    window_start: Any = None,
    window_end: Any = None,
) -> Dict[str, Any]:
    """Build a normalized AIAnalysisResult payload for deterministic pattern results."""
    return {
        "case_id": case_id,
        "analysis_id": analysis_id,
        "pattern_id": pattern_id,
        "pattern_name": pattern_name,
        "correlation_key": correlation_key,
        "window_start": window_start,
        "window_end": window_end,
        "rule_based_confidence": rule_based_confidence,
        "ai_confidence": ai_confidence,
        "ai_reasoning": ai_reasoning,
        "ai_false_positive_assessment": ai_false_positive_assessment,
        "final_confidence": final_confidence,
        "deterministic_score": deterministic_score,
        "ai_adjustment": ai_adjustment,
        "coverage_quality": coverage_quality,
        "evidence_package": evidence_package or {},
        "events_analyzed": events_analyzed,
        "model_used": model_used,
    }


def build_deterministic_analysis_artifacts(
    *,
    case_id: int,
    analysis_id: str,
    source_system: str,
    pattern_id: str,
    pattern_name: str,
    correlation_key: str,
    confidence: Optional[float],
    summary: str,
    evidence_package: Optional[Dict[str, Any]] = None,
    severity: Optional[str] = None,
    events_analyzed: int = 0,
    deterministic_score: Optional[float] = None,
    coverage_quality: Optional[float] = None,
    ai_adjustment: Optional[float] = None,
    ai_escalated: bool = False,
    ai_reasoning: Optional[str] = None,
    ai_false_positive_assessment: Optional[str] = None,
    mitre_techniques: Any = None,
    extra_finding_fields: Optional[Dict[str, Any]] = None,
    rule_based_confidence: Optional[float] = None,
    model_used: str = "",
    window_start: Any = None,
    window_end: Any = None,
) -> Dict[str, Dict[str, Any]]:
    """Build the paired persistence and finding payloads for deterministic analysis."""
    analysis_result_payload = build_ai_analysis_result_payload(
        case_id=case_id,
        analysis_id=analysis_id,
        pattern_id=pattern_id,
        pattern_name=pattern_name,
        correlation_key=correlation_key,
        rule_based_confidence=rule_based_confidence,
        ai_confidence=confidence,
        ai_reasoning=ai_reasoning,
        ai_false_positive_assessment=ai_false_positive_assessment,
        final_confidence=confidence,
        deterministic_score=deterministic_score,
        ai_adjustment=ai_adjustment,
        coverage_quality=coverage_quality,
        evidence_package=evidence_package,
        events_analyzed=events_analyzed,
        model_used=model_used,
        window_start=window_start,
        window_end=window_end,
    )
    finding = build_deterministic_analysis_finding(
        source_system=source_system,
        pattern_id=pattern_id,
        pattern_name=pattern_name,
        correlation_key=correlation_key,
        confidence=confidence,
        summary=summary,
        evidence_package=evidence_package,
        severity=severity,
        events_analyzed=events_analyzed,
        deterministic_score=deterministic_score,
        coverage_quality=coverage_quality,
        ai_adjustment=ai_adjustment,
        ai_escalated=ai_escalated,
        ai_reasoning=ai_reasoning or "",
        mitre_techniques=mitre_techniques,
        extra_fields=extra_finding_fields,
    )
    return {
        "analysis_result_payload": analysis_result_payload,
        "finding": finding,
    }


def finalize_deterministic_package(
    package: Any,
    *,
    ai_full_threshold: float,
    ai_gray_threshold: float,
    run_full_analysis: Optional[Callable[[], Dict[str, Any]]] = None,
    run_light_analysis: Optional[Callable[[], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Apply AI judgment to a deterministic package and return shared derived values."""
    if package.deterministic_score >= ai_full_threshold and run_full_analysis:
        package.ai_judgment = run_full_analysis() or {}
    elif package.deterministic_score >= ai_gray_threshold and run_light_analysis:
        escalation = run_light_analysis() or {}
        if escalation.get("escalate"):
            package.ai_escalated = True
            package.ai_judgment = {
                "adjustment": 0,
                "reasoning": escalation.get("reasoning", ""),
                "escalated": True,
            }

    ai_judgment = package.ai_judgment if isinstance(package.ai_judgment, dict) else {}
    final_score = package.final_score()
    ai_adjustment = package.bounded_ai_adjustment()
    evidence_package = package.to_dict()
    ai_analyzed = bool(ai_judgment) and not ai_judgment.get("escalated")

    return {
        "final_score": final_score,
        "ai_adjustment": ai_adjustment,
        "evidence_package": evidence_package,
        "ai_reasoning": ai_judgment.get("reasoning"),
        "ai_false_positive_assessment": ai_judgment.get("false_positive_assessment"),
        "ai_analyzed": ai_analyzed,
        "should_emit_finding": final_score >= 50
        or (ai_analyzed and package.deterministic_score >= ai_full_threshold),
    }
