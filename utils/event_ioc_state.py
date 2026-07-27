"""Single-table ClickHouse storage for mutable IOC event-tag state."""

from __future__ import annotations

from typing import Any, Dict, Optional
from uuid import uuid4

from utils.clickhouse import (
    clickhouse_string_literal,
    get_client,
    run_events_update,
)
from utils.evidence_audit import EVIDENCE_TAGGED, EVIDENCE_UNTAGGED, EvidenceChange

IOC_CASE_STATE_TABLE = "event_ioc_case_state"
IOC_STATE_TABLE = "event_ioc_state"


def _count_matching(client, where_sql: str) -> int:
    """Count rows a mutation is about to touch, for the audit record."""
    try:
        result = client.query(f"SELECT count() FROM events WHERE {where_sql}")
        return int(result.result_rows[0][0]) if result.result_rows else 0
    except Exception:
        return 0


def ensure_event_ioc_state_tables(client=None) -> None:
    """Compatibility no-op now that IOC state lives on `events`."""
    return None


def _normalized_username(value: Any) -> str:
    return str(value or "").strip() or "system"


def start_ioc_refresh(case_id: int, *, updated_by: str, client=None, remote_ip: str = None,
                      operation_id: str = None) -> str:
    client = client or get_client()
    ensure_event_ioc_state_tables(client)

    cleared = _count_matching(client, f"case_id = {int(case_id)} AND length(ioc_types) > 0")
    run_events_update(
        "ioc_types = []",
        f"case_id = {int(case_id)} AND length(ioc_types) > 0",
        client=client,
        audit=EvidenceChange(
            case_id=case_id,
            field_name="ioc_types",
            action=EVIDENCE_UNTAGGED,
            old_value="(existing IOC tags)",
            new_value=[],
            affected_count=cleared,
            username=_normalized_username(updated_by),
            remote_ip=remote_ip,
            operation_id=operation_id,
            details={"reason": "IOC rescan started; prior tags cleared before re-tagging"},
        ),
    )
    return str(uuid4())


def insert_ioc_scan_matches(
    case_id: int,
    scan_version: str,
    ioc_type: str,
    *,
    where_clause: str,
    parameters: Optional[Dict[str, Any]] = None,
    updated_by: str,
    client=None,
    remote_ip: str = None,
    operation_id: str = None,
    ioc_value: str = None,
) -> int:
    client = client or get_client()
    ensure_event_ioc_state_tables(client)

    params = dict(parameters or {})
    params.setdefault("case_id", int(case_id))
    params["scan_version"] = str(scan_version)
    params["ioc_type"] = str(ioc_type)
    params["updated_by"] = _normalized_username(updated_by)

    count_query = f"SELECT count() FROM events WHERE {where_clause}"
    count_result = client.query(count_query, parameters=params)
    match_count = count_result.result_rows[0][0] if count_result.result_rows else 0
    if match_count <= 0:
        return 0

    resolved_where = where_clause.replace("{case_id:UInt32}", str(int(case_id)))
    run_events_update(
        f"ioc_types = arrayDistinct(arrayConcat(ioc_types, [{clickhouse_string_literal(params['ioc_type'])}]))",
        resolved_where,
        client=client,
        audit=EvidenceChange(
            case_id=case_id,
            field_name="ioc_types",
            action=EVIDENCE_TAGGED,
            old_value="(tag absent)",
            new_value=params["ioc_type"],
            affected_count=int(match_count),
            entity_name=ioc_value,
            username=params["updated_by"],
            remote_ip=remote_ip,
            operation_id=operation_id,
            details={
                "scan_version": params["scan_version"],
                "ioc_type": params["ioc_type"],
                "ioc_value": ioc_value,
            },
        ),
    )
    return int(match_count)


def build_ioc_projection(alias: str = "events", case_id_filter_sql: Optional[str] = None) -> Dict[str, str]:
    ioc_types_sql = f"{alias}.ioc_types"
    return {
        "selector_sql": f"{alias}.selector_key",
        "join_sql": "",
        "overlay_enabled_sql": "true",
        "has_overlay_match_sql": f"length({ioc_types_sql}) > 0",
        "ioc_types_sql": ioc_types_sql,
        "has_ioc_sql": f"length({ioc_types_sql}) > 0",
    }


def build_effective_has_ioc_clause(alias: str = "events", *, case_id_sql: Optional[str] = None) -> str:
    raw_has_ioc_sql = f"length({alias}.ioc_types) > 0" if alias else "length(ioc_types) > 0"
    return raw_has_ioc_sql


__all__ = [
    "build_effective_has_ioc_clause",
    "build_ioc_projection",
    "ensure_event_ioc_state_tables",
    "insert_ioc_scan_matches",
    "start_ioc_refresh",
]
