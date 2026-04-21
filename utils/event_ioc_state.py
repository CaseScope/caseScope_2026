"""ClickHouse overlay storage for mutable IOC event-tag state."""

from __future__ import annotations

from typing import Any, Dict, Optional
from uuid import uuid4

from utils.clickhouse import get_client
from utils.event_selector import build_event_selector_sql

IOC_CASE_STATE_TABLE = "event_ioc_case_state"
IOC_STATE_TABLE = "event_ioc_state"


def ensure_event_ioc_state_tables(client=None) -> None:
    client = client or get_client()
    if not hasattr(client, "command"):
        return
    client.command(
        f"""
        CREATE TABLE IF NOT EXISTS {IOC_CASE_STATE_TABLE} (
            case_id UInt32,
            scan_version String,
            updated_by String,
            updated_at DateTime64(3) DEFAULT now64(3)
        )
        ENGINE = ReplacingMergeTree(updated_at)
        ORDER BY case_id
        """
    )
    client.command(
        f"""
        CREATE TABLE IF NOT EXISTS {IOC_STATE_TABLE} (
            case_id UInt32,
            scan_version String,
            selector_key String,
            ioc_types Array(String),
            updated_by String,
            updated_at DateTime64(3) DEFAULT now64(3)
        )
        ENGINE = MergeTree
        ORDER BY (case_id, scan_version, selector_key, updated_at)
        """
    )


def _normalized_username(value: Any) -> str:
    return str(value or "").strip() or "system"


def start_ioc_refresh(case_id: int, *, updated_by: str, client=None) -> str:
    client = client or get_client()
    ensure_event_ioc_state_tables(client)
    scan_version = str(uuid4())
    client.insert(
        IOC_CASE_STATE_TABLE,
        [(int(case_id), scan_version, _normalized_username(updated_by))],
        column_names=["case_id", "scan_version", "updated_by"],
    )
    return scan_version


def insert_ioc_scan_matches(
    case_id: int,
    scan_version: str,
    ioc_type: str,
    *,
    where_clause: str,
    parameters: Optional[Dict[str, Any]] = None,
    updated_by: str,
    client=None,
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

    selector_sql = build_event_selector_sql(alias="")
    insert_query = f"""
        INSERT INTO {IOC_STATE_TABLE}
        SELECT
            {{case_id:UInt32}} AS case_id,
            {{scan_version:String}} AS scan_version,
            {selector_sql} AS selector_key,
            [{{ioc_type:String}}] AS ioc_types,
            {{updated_by:String}} AS updated_by,
            now64(3) AS updated_at
        FROM events
        WHERE {where_clause}
    """
    client.command(insert_query, parameters=params)
    return int(match_count)


def build_ioc_projection(alias: str = "events") -> Dict[str, str]:
    selector_sql = build_event_selector_sql(alias)
    case_state_alias = "ioc_case_state"
    state_alias = "ioc_state"
    join_sql = f"""
        LEFT JOIN (
            SELECT
                case_id,
                argMax(scan_version, updated_at) AS scan_version
            FROM {IOC_CASE_STATE_TABLE}
            GROUP BY case_id
        ) AS {case_state_alias}
        ON {case_state_alias}.case_id = {alias}.case_id
        LEFT JOIN (
            SELECT
                state.case_id,
                state.scan_version,
                state.selector_key,
                arrayDistinct(arrayFlatten(groupArray(state.ioc_types))) AS ioc_types
            FROM {IOC_STATE_TABLE} AS state
            GROUP BY state.case_id, state.scan_version, state.selector_key
        ) AS {state_alias}
        ON {state_alias}.case_id = {alias}.case_id
        AND {state_alias}.scan_version = {case_state_alias}.scan_version
        AND {state_alias}.selector_key = {selector_sql}
    """.strip()
    overlay_enabled_sql = f"notEmpty({case_state_alias}.scan_version)"
    has_overlay_match_sql = f"notEmpty({state_alias}.selector_key)"
    ioc_types_sql = (
        f"if({overlay_enabled_sql}, "
        f"if({has_overlay_match_sql}, {state_alias}.ioc_types, []), "
        f"{alias}.ioc_types)"
    )
    return {
        "selector_sql": selector_sql,
        "join_sql": join_sql,
        "overlay_enabled_sql": overlay_enabled_sql,
        "has_overlay_match_sql": has_overlay_match_sql,
        "ioc_types_sql": ioc_types_sql,
        "has_ioc_sql": f"length({ioc_types_sql}) > 0",
    }


def build_effective_has_ioc_clause(alias: str = "events", *, case_id_sql: Optional[str] = None) -> str:
    case_id_expr = case_id_sql or f"{alias}.case_id"
    selector_sql = build_event_selector_sql(alias)
    overlay_enabled_sql = (
        f"{case_id_expr} IN (SELECT DISTINCT case_id FROM {IOC_CASE_STATE_TABLE})"
    )
    latest_scan_sql = (
        f"SELECT argMax(scan_version, updated_at) "
        f"FROM {IOC_CASE_STATE_TABLE} "
        f"WHERE case_id = {case_id_expr}"
    )
    overlay_match_sql = f"""
        {selector_sql} IN (
            SELECT selector_key
            FROM {IOC_STATE_TABLE}
            WHERE case_id = {case_id_expr}
              AND scan_version = ({latest_scan_sql})
            GROUP BY selector_key
        )
    """.strip()
    raw_has_ioc_sql = f"length({alias}.ioc_types) > 0" if alias else "length(ioc_types) > 0"
    return (
        f"if({overlay_enabled_sql}, "
        f"({overlay_match_sql}), "
        f"({raw_has_ioc_sql}))"
    )


__all__ = [
    "build_effective_has_ioc_clause",
    "build_ioc_projection",
    "ensure_event_ioc_state_tables",
    "insert_ioc_scan_matches",
    "start_ioc_refresh",
]
