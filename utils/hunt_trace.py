"""Single write path for hunt ledger trace records."""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple

from dateutil import parser as date_parser
from sqlalchemy import func

from models.database import db
from models.hunt import (
    HuntCoverageStatus,
    HuntCreatedByType,
    HuntEvidenceRef,
    HuntHypothesis,
    HuntRun,
    HuntStep,
    HuntStepStatus,
)

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "hunt-ledger-v1"
MAX_SUMMARY_CHARS = 1200
MAX_FIELD_CHARS = 2000

EVIDENCE_LIST_KEYS = (
    "events",
    "artifacts",
    "downloads",
    "processes",
    "process_tree",
    "memory_results",
    "network_logs",
    "connections",
    "results",
    "findings",
    "iocs",
)


def _utcnow() -> datetime:
    return datetime.utcnow()


def _json_safe(value: Any) -> Any:
    """Return a JSON-serializable copy with deterministic primitive values."""
    try:
        return json.loads(json.dumps(value, default=str, sort_keys=True))
    except Exception:
        return str(value)


def _stable_hash(payload: Any) -> str:
    serialized = json.dumps(_json_safe(payload), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _truncate(value: Any, limit: int = MAX_FIELD_CHARS) -> Optional[str]:
    if value is None:
        return None
    text = str(value)
    if not text:
        return None
    return text[:limit]


def _parse_timestamp(value: Any) -> Optional[datetime]:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=None) if value.tzinfo else value
    try:
        parsed = date_parser.parse(str(value))
        return parsed.replace(tzinfo=None) if parsed.tzinfo else parsed
    except Exception:
        return None


def _normalize_created_by_type(value: Optional[str]) -> str:
    normalized = str(value or HuntCreatedByType.SYSTEM).strip().lower()
    return normalized if normalized in HuntCreatedByType.all() else HuntCreatedByType.SYSTEM


def normalize_coverage_status(value: Optional[str]) -> str:
    normalized = str(value or HuntCoverageStatus.UNKNOWN).strip().lower()
    return normalized if normalized in HuntCoverageStatus.all() else HuntCoverageStatus.UNKNOWN


def _next_step_number(hunt_run_id: int) -> int:
    current = db.session.query(func.max(HuntStep.step_number)).filter_by(
        hunt_run_id=int(hunt_run_id)
    ).scalar()
    return int(current or 0) + 1


def create_hunt_run(
    *,
    case_id: int,
    objective: str,
    created_by: str = "system",
    status: str = "active",
    model_provider: Optional[str] = None,
    model_name: Optional[str] = None,
    source_scope: Optional[Dict[str, Any]] = None,
    time_scope_start: Any = None,
    time_scope_end: Any = None,
) -> HuntRun:
    """Create a hunt run objective."""
    run = HuntRun(
        case_id=int(case_id),
        objective=str(objective or "").strip(),
        status=str(status or "active").strip() or "active",
        created_by=str(created_by or "system"),
        model_provider=_truncate(model_provider, 80),
        model_name=_truncate(model_name, 255),
        source_scope=_json_safe(source_scope or {}),
        time_scope_start=_parse_timestamp(time_scope_start),
        time_scope_end=_parse_timestamp(time_scope_end),
    )
    db.session.add(run)
    db.session.commit()
    return run


def add_hypothesis(
    *,
    hunt_run_id: int,
    hypothesis: str,
    status: str = "open",
    confidence: Optional[float] = None,
    rationale: Optional[str] = None,
) -> HuntHypothesis:
    """Append a hypothesis to a hunt run."""
    item = HuntHypothesis(
        hunt_run_id=int(hunt_run_id),
        hypothesis=str(hypothesis or "").strip(),
        status=str(status or "open").strip() or "open",
        confidence=confidence,
        rationale=rationale,
    )
    db.session.add(item)
    db.session.commit()
    return item


def start_step(
    *,
    hunt_run_id: int,
    tool_name: str,
    tool_params: Optional[Dict[str, Any]] = None,
    case_id: Optional[int] = None,
    hypothesis_id: Optional[int] = None,
    query_summary: Optional[str] = None,
    created_by_type: str = HuntCreatedByType.SYSTEM,
    created_by: str = "system",
    model_provider: Optional[str] = None,
    model_name: Optional[str] = None,
    prompt_version: Optional[str] = None,
    schema_version: str = SCHEMA_VERSION,
) -> HuntStep:
    """Start a traced tool step."""
    run = HuntRun.query.get(int(hunt_run_id))
    if run is None:
        raise ValueError("hunt_run_id not found")
    if case_id is not None and int(case_id) != int(run.case_id):
        raise ValueError("hunt_run_id does not belong to case_id")
    step = HuntStep(
        hunt_run_id=int(hunt_run_id),
        hypothesis_id=int(hypothesis_id) if hypothesis_id else None,
        step_number=_next_step_number(int(hunt_run_id)),
        tool_name=str(tool_name or "unknown")[:120],
        tool_parameters_json=_json_safe(tool_params or {}),
        query_summary=query_summary,
        started_at=_utcnow(),
        status=HuntStepStatus.STARTED,
        coverage_status=HuntCoverageStatus.UNKNOWN,
        created_by_type=_normalize_created_by_type(created_by_type),
        created_by=str(created_by or "system")[:80],
        model_provider=_truncate(model_provider, 80),
        model_name=_truncate(model_name, 255),
        prompt_version=_truncate(prompt_version, 80),
        schema_version=schema_version or SCHEMA_VERSION,
    )
    db.session.add(step)
    db.session.commit()
    return step


def _get_step(step_or_id: HuntStep | int) -> Optional[HuntStep]:
    if isinstance(step_or_id, HuntStep):
        return step_or_id
    try:
        return HuntStep.query.get(int(step_or_id))
    except Exception:
        return None


def _infer_source_table(tool_name: str, key_path: str, row: Dict[str, Any]) -> str:
    lowered = f"{tool_name} {key_path} {row.get('source_table', '')}".lower()
    if "network" in lowered or row.get("log_type"):
        return "network_logs"
    if "memory" in lowered:
        return "memory"
    if "finding" in lowered:
        return "case_unified_findings"
    return str(row.get("source_table") or "events")


def _first_value(row: Dict[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        value = row.get(key)
        if value not in (None, "", []):
            return value
    return None


def normalize_evidence_selector(
    *,
    case_id: int,
    row: Dict[str, Any],
    tool_name: str = "",
    key_path: str = "",
) -> Dict[str, Any]:
    """Normalize a returned row into a durable evidence selector."""
    source_table = _infer_source_table(tool_name, key_path, row)
    timestamp_value = _first_value(row, ("timestamp_utc", "timestamp", "time", "ts", "event_timestamp", "first_seen"))
    host = _first_value(row, ("source_host", "host", "hostname", "computer", "sensor", "id_orig_h"))
    username = _first_value(row, ("username", "user", "account", "target_user"))
    artifact_path = _first_value(row, ("artifact_path", "target_path", "file_path", "path", "process_path", "download_path"))
    selector = {
        "case_id": int(case_id),
        "source_table": source_table,
        "source_file": _truncate(_first_value(row, ("source_file", "file", "filename")), 1024),
        "artifact_type": _truncate(_first_value(row, ("artifact_type", "_artifact_type", "type", "log_type")), 120),
        "timestamp_utc": str(timestamp_value) if timestamp_value not in (None, "") else None,
        "event_id": _truncate(_first_value(row, ("event_id", "eventid")), 80),
        "record_id": _truncate(_first_value(row, ("record_id", "event_record_id", "record_number")), 120),
        "source_host": _truncate(host, 255),
        "username": _truncate(username, 255),
        "ioc_value": _truncate(_first_value(row, ("ioc_value", "value", "indicator")), MAX_FIELD_CHARS),
        "artifact_path": _truncate(artifact_path, MAX_FIELD_CHARS),
        "row_uuid": _truncate(_first_value(row, ("row_uuid", "uuid", "event_uuid")), 120),
        "source_id": _truncate(_first_value(row, ("source_id", "id", "uid")), 255),
    }
    selector["selector_hash"] = hash_selector(selector)
    return selector


def hash_selector(selector: Dict[str, Any]) -> str:
    """Hash normalized selector fields, excluding any existing hash."""
    normalized = {
        key: selector.get(key)
        for key in sorted(selector.keys())
        if key != "selector_hash" and selector.get(key) not in ("", [], {})
    }
    return _stable_hash(normalized)


def _iter_candidate_rows(payload: Any, key_path: str = "") -> Iterable[Tuple[str, Dict[str, Any]]]:
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                yield key_path, item
        return
    if not isinstance(payload, dict):
        return
    for key, value in payload.items():
        next_path = f"{key_path}.{key}" if key_path else key
        if key in EVIDENCE_LIST_KEYS and isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    yield next_path, item
            continue
        if isinstance(value, dict):
            yield from _iter_candidate_rows(value, next_path)


def _row_has_evidence_shape(row: Dict[str, Any]) -> bool:
    fields = {
        "timestamp", "timestamp_utc", "event_id", "source_host", "host",
        "username", "user", "artifact_type", "_artifact_type", "source_file",
        "target_path", "file_path", "path", "process_name", "command_line",
        "ioc_value", "value", "rule", "rule_title", "summary",
    }
    return any(row.get(field) not in (None, "", []) for field in fields)


def extract_evidence_refs(
    *,
    case_id: int,
    tool_name: str,
    result_payload: Dict[str, Any],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Extract normalized evidence selectors without raising on partial failures."""
    refs: List[Dict[str, Any]] = []
    warnings: List[str] = []
    seen = set()
    for key_path, row in _iter_candidate_rows(result_payload):
        if not _row_has_evidence_shape(row):
            continue
        try:
            selector = normalize_evidence_selector(
                case_id=case_id,
                row=row,
                tool_name=tool_name,
                key_path=key_path,
            )
            selector_hash = selector["selector_hash"]
            if selector_hash in seen:
                continue
            seen.add(selector_hash)
            refs.append({
                "selector": selector,
                "row": _json_safe(row),
                "key_path": key_path,
            })
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"{key_path or 'row'}: {exc}")
    return refs, warnings


def _result_count(payload: Dict[str, Any], evidence_refs: List[Dict[str, Any]]) -> int:
    for key in ("event_count", "result_count", "total_matches", "count", "download_count", "process_count"):
        value = payload.get(key)
        if isinstance(value, int) and value >= 0:
            return value
    return len(evidence_refs)


def _summarize_result(payload: Dict[str, Any], result_count: int) -> str:
    if payload.get("error"):
        return _truncate(payload.get("error"), MAX_SUMMARY_CHARS) or ""
    summary_parts = [f"result_count={result_count}"]
    for key in ("query_filters", "search", "artifact_types", "artifact_filter", "group_by"):
        if key in payload:
            summary_parts.append(f"{key}={json.dumps(_json_safe(payload.get(key)), sort_keys=True)[:300]}")
    for key in ("summary", "result_summary", "message"):
        if payload.get(key):
            summary_parts.append(str(payload.get(key))[:500])
            break
    return _truncate("; ".join(summary_parts), MAX_SUMMARY_CHARS) or ""


def fingerprint_result(
    *,
    tool_name: str,
    tool_params: Dict[str, Any],
    result_summary: str,
    evidence_refs: List[Dict[str, Any]],
) -> str:
    """Create an order-stable result fingerprint."""
    selector_hashes = sorted(
        ref.get("selector", {}).get("selector_hash", "")
        for ref in evidence_refs
        if ref.get("selector", {}).get("selector_hash")
    )
    stable_payload = {
        "tool_name": tool_name,
        "tool_params": _json_safe(tool_params or {}),
        "result_summary": result_summary or "",
        "selector_hashes": selector_hashes,
    }
    return _stable_hash(stable_payload)


def _store_evidence_refs(step: HuntStep, refs: List[Dict[str, Any]]) -> None:
    for ref in refs:
        selector = ref.get("selector") or {}
        row = ref.get("row") if isinstance(ref.get("row"), dict) else {}
        evidence = HuntEvidenceRef(
            hunt_step_id=step.id,
            case_id=step.hunt_run.case_id,
            source_type=_truncate(ref.get("key_path"), 80),
            source_table=_truncate(selector.get("source_table"), 80),
            source_id=_truncate(selector.get("source_id"), 255),
            source_file=_truncate(selector.get("source_file"), 1024),
            artifact_type=_truncate(selector.get("artifact_type"), 120),
            timestamp=_parse_timestamp(selector.get("timestamp_utc")),
            host=_truncate(selector.get("source_host"), 255),
            username=_truncate(selector.get("username"), 255),
            artifact_path=_truncate(selector.get("artifact_path"), MAX_FIELD_CHARS),
            event_id=_truncate(selector.get("event_id"), 80),
            record_id=_truncate(selector.get("record_id"), 120),
            ioc_value=_truncate(selector.get("ioc_value"), MAX_FIELD_CHARS),
            row_uuid=_truncate(selector.get("row_uuid"), 120),
            summary=_truncate(_first_value(row, ("summary", "rule", "rule_title", "command_line", "process_name")), MAX_FIELD_CHARS),
            provenance=_truncate(row.get("emitted_provenance") or row.get("provenance"), 80),
            selector_json=_json_safe(selector),
            selector_hash=selector.get("selector_hash") or hash_selector(selector),
        )
        db.session.add(evidence)


def complete_step(
    step_or_id: HuntStep | int,
    *,
    result_payload: Optional[Dict[str, Any]] = None,
    coverage_status: Optional[str] = None,
    coverage_detail: Optional[Dict[str, Any]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Optional[HuntStep]:
    """Complete a step; partial evidence extraction never fails the step."""
    step = _get_step(step_or_id)
    if step is None:
        return None
    payload = result_payload if isinstance(result_payload, dict) else {"result": result_payload}
    extraction_warnings: List[str] = []
    evidence_refs: List[Dict[str, Any]] = []
    try:
        evidence_refs, extraction_warnings = extract_evidence_refs(
            case_id=step.hunt_run.case_id,
            tool_name=step.tool_name,
            result_payload=payload,
        )
    except Exception as exc:  # noqa: BLE001
        extraction_warnings.append(f"evidence extraction failed: {exc}")
        evidence_refs = []

    result_count = _result_count(payload, evidence_refs)
    result_summary = _summarize_result(payload, result_count)
    normalized_coverage = normalize_coverage_status(coverage_status or payload.get("coverage_status"))
    if extraction_warnings and normalized_coverage == HuntCoverageStatus.COMPLETE:
        normalized_coverage = HuntCoverageStatus.PARTIAL

    step.status = HuntStepStatus.COMPLETED
    step.completed_at = _utcnow()
    step.result_count = result_count
    step.result_summary = result_summary
    step.coverage_status = normalized_coverage
    step.coverage_detail_json = _json_safe(coverage_detail or payload.get("coverage_detail") or {})
    step.result_fingerprint = fingerprint_result(
        tool_name=step.tool_name,
        tool_params=step.tool_parameters_json or {},
        result_summary=result_summary,
        evidence_refs=evidence_refs,
    )
    step_metadata = dict(metadata or {})
    if extraction_warnings:
        step_metadata["extraction_warnings"] = extraction_warnings
    step.metadata_json = _json_safe(step_metadata)
    _store_evidence_refs(step, evidence_refs)
    step.hunt_run.updated_at = _utcnow()
    db.session.commit()
    return step


def fail_step(
    step_or_id: HuntStep | int,
    *,
    error_message: str,
    result_payload: Optional[Dict[str, Any]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Optional[HuntStep]:
    """Mark a traced step as failed."""
    step = _get_step(step_or_id)
    if step is None:
        return None
    payload = result_payload if isinstance(result_payload, dict) else {}
    step.status = HuntStepStatus.FAILED
    step.completed_at = _utcnow()
    step.error_message = str(error_message or "tool execution failed")
    step.result_count = 0
    step.result_summary = _truncate(payload.get("error") or error_message, MAX_SUMMARY_CHARS)
    step.coverage_status = HuntCoverageStatus.UNKNOWN
    step.metadata_json = _json_safe(metadata or {})
    step.result_fingerprint = fingerprint_result(
        tool_name=step.tool_name,
        tool_params=step.tool_parameters_json or {},
        result_summary=step.result_summary or "",
        evidence_refs=[],
    )
    step.hunt_run.updated_at = _utcnow()
    db.session.commit()
    return step


def skip_step(
    step_or_id: HuntStep | int,
    *,
    reason: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> Optional[HuntStep]:
    """Mark a traced step as skipped without executing the tool."""
    step = _get_step(step_or_id)
    if step is None:
        return None
    step.status = HuntStepStatus.SKIPPED
    step.completed_at = _utcnow()
    step.error_message = str(reason or "tool skipped")
    step.result_count = 0
    step.result_summary = _truncate(reason, MAX_SUMMARY_CHARS)
    step.coverage_status = HuntCoverageStatus.NOT_AVAILABLE
    step.metadata_json = _json_safe(metadata or {})
    step.result_fingerprint = fingerprint_result(
        tool_name=step.tool_name,
        tool_params=step.tool_parameters_json or {},
        result_summary=step.result_summary or "",
        evidence_refs=[],
    )
    step.hunt_run.updated_at = _utcnow()
    db.session.commit()
    return step


def get_hunt_run_ledger(hunt_run_id: int) -> Optional[Dict[str, Any]]:
    run = HuntRun.query.get(int(hunt_run_id))
    return run.to_dict(include_children=True) if run else None
