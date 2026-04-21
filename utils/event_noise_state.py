"""ClickHouse overlay storage for mutable noise event state."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional
from uuid import uuid4

from utils.clickhouse import get_client
from utils.event_selector import build_event_selector_key, build_event_selector_sql

NOISE_CASE_STATE_TABLE = "event_noise_case_state"
NOISE_SCAN_STATE_TABLE = "event_noise_state"
NOISE_MANUAL_STATE_TABLE = "event_noise_manual_state"
LEGACY_NOT_NOISE_SQL = "(noise_matched = false OR noise_matched IS NULL)"


def ensure_event_noise_state_tables(client=None) -> None:
    client = client or get_client()
    if not hasattr(client, "command"):
        return
    client.command(
        f"""
        CREATE TABLE IF NOT EXISTS {NOISE_CASE_STATE_TABLE} (
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
        CREATE TABLE IF NOT EXISTS {NOISE_SCAN_STATE_TABLE} (
            case_id UInt32,
            scan_version String,
            selector_key String,
            noise_rules Array(String),
            updated_by String,
            updated_at DateTime64(3) DEFAULT now64(3)
        )
        ENGINE = MergeTree
        ORDER BY (case_id, scan_version, selector_key, updated_at)
        """
    )
    client.command(
        f"""
        CREATE TABLE IF NOT EXISTS {NOISE_MANUAL_STATE_TABLE} (
            case_id UInt32,
            selector_key String,
            noise_matched Bool,
            noise_rules Array(String),
            updated_by String,
            updated_at DateTime64(3) DEFAULT now64(3)
        )
        ENGINE = ReplacingMergeTree(updated_at)
        ORDER BY (case_id, selector_key)
        """
    )


def _normalized_username(value: Any) -> str:
    return str(value or "").strip() or "system"


def start_noise_scan(case_id: int, *, updated_by: str, client=None) -> str:
    client = client or get_client()
    ensure_event_noise_state_tables(client)
    scan_version = str(uuid4())
    updated_at = datetime.now(timezone.utc)
    client.insert(
        NOISE_CASE_STATE_TABLE,
        [(int(case_id), scan_version, _normalized_username(updated_by), updated_at)],
        column_names=["case_id", "scan_version", "updated_by", "updated_at"],
    )
    return scan_version


def ensure_noise_overlay_case(case_id: int, *, updated_by: str, client=None) -> str:
    client = client or get_client()
    ensure_event_noise_state_tables(client)
    query = (
        f"SELECT argMax(scan_version, updated_at) "
        f"FROM {NOISE_CASE_STATE_TABLE} "
        "WHERE case_id = {case_id:UInt32}"
    )
    result = client.query(query, parameters={"case_id": int(case_id)})
    current = result.result_rows[0][0] if result.result_rows else None
    if current:
        return str(current)
    return start_noise_scan(case_id, updated_by=updated_by, client=client)


def insert_noise_scan_matches(
    case_id: int,
    scan_version: str,
    rule_name: str,
    *,
    where_clause: str,
    parameters: Optional[Dict[str, Any]] = None,
    updated_by: str,
    client=None,
) -> int:
    client = client or get_client()
    ensure_event_noise_state_tables(client)

    params = dict(parameters or {})
    params.setdefault("case_id", int(case_id))
    params["scan_version"] = str(scan_version)
    params["rule_name"] = str(rule_name)
    params["updated_by"] = _normalized_username(updated_by)

    count_query = f"SELECT count() FROM events WHERE {where_clause}"
    count_result = client.query(count_query, parameters=params)
    match_count = count_result.result_rows[0][0] if count_result.result_rows else 0
    if match_count <= 0:
        return 0

    selector_sql = build_event_selector_sql(alias="")
    insert_query = f"""
        INSERT INTO {NOISE_SCAN_STATE_TABLE}
        SELECT
            {{case_id:UInt32}} AS case_id,
            {{scan_version:String}} AS scan_version,
            {selector_sql} AS selector_key,
            [{{rule_name:String}}] AS noise_rules,
            {{updated_by:String}} AS updated_by,
            now64(3) AS updated_at
        FROM events
        WHERE {where_clause}
    """
    client.command(insert_query, parameters=params)
    return int(match_count)


def upsert_manual_noise_state_rows(
    case_id: int,
    updates: Iterable[Dict[str, Any]],
    *,
    updated_by: str,
    client=None,
) -> int:
    client = client or get_client()
    ensure_event_noise_state_tables(client)

    prepared_rows = []
    updated_at = datetime.now(timezone.utc)
    for update in updates or []:
        selector_key = str(update.get("selector_key") or "").strip()
        if not selector_key:
            continue
        prepared_rows.append(
            (
                int(case_id),
                selector_key,
                bool(update.get("noise_matched")),
                [str(rule).strip() for rule in (update.get("noise_rules") or []) if str(rule).strip()],
                _normalized_username(updated_by),
                updated_at,
            )
        )

    if not prepared_rows:
        return 0

    client.insert(
        NOISE_MANUAL_STATE_TABLE,
        prepared_rows,
        column_names=[
            "case_id",
            "selector_key",
            "noise_matched",
            "noise_rules",
            "updated_by",
            "updated_at",
        ],
    )
    return len(prepared_rows)


def build_noise_projection(alias: str = "events") -> Dict[str, str]:
    selector_sql = build_event_selector_sql(alias)
    case_state_alias = "noise_case_state"
    scan_alias = "noise_scan_state"
    manual_alias = "noise_manual_state"
    join_sql = f"""
        LEFT JOIN (
            SELECT
                case_id,
                argMax(scan_version, updated_at) AS scan_version
            FROM {NOISE_CASE_STATE_TABLE}
            GROUP BY case_id
        ) AS {case_state_alias}
        ON {case_state_alias}.case_id = {alias}.case_id
        LEFT JOIN (
            SELECT
                state.case_id,
                state.scan_version,
                state.selector_key,
                arrayDistinct(arrayFlatten(groupArray(state.noise_rules))) AS noise_rules
            FROM {NOISE_SCAN_STATE_TABLE} AS state
            GROUP BY state.case_id, state.scan_version, state.selector_key
        ) AS {scan_alias}
        ON {scan_alias}.case_id = {alias}.case_id
        AND {scan_alias}.scan_version = {case_state_alias}.scan_version
        AND {scan_alias}.selector_key = {selector_sql}
        LEFT JOIN (
            SELECT
                case_id,
                selector_key,
                argMax(noise_matched, updated_at) AS noise_matched,
                argMax(noise_rules, updated_at) AS noise_rules
            FROM {NOISE_MANUAL_STATE_TABLE}
            GROUP BY case_id, selector_key
        ) AS {manual_alias}
        ON {manual_alias}.case_id = {alias}.case_id
        AND {manual_alias}.selector_key = {selector_sql}
    """.strip()
    overlay_enabled_sql = f"notEmpty({case_state_alias}.scan_version)"
    scan_match_sql = f"notEmpty({scan_alias}.selector_key)"
    manual_match_sql = f"notEmpty({manual_alias}.selector_key)"
    noise_matched_sql = (
        f"if({overlay_enabled_sql}, "
        f"if({manual_match_sql}, {manual_alias}.noise_matched, {scan_match_sql}), "
        f"{alias}.noise_matched)"
    )
    noise_rules_sql = (
        f"if({overlay_enabled_sql}, "
        f"if({manual_match_sql}, {manual_alias}.noise_rules, "
        f"if({scan_match_sql}, {scan_alias}.noise_rules, [])), "
        f"{alias}.noise_rules)"
    )
    return {
        "selector_sql": selector_sql,
        "join_sql": join_sql,
        "overlay_enabled_sql": overlay_enabled_sql,
        "scan_match_sql": scan_match_sql,
        "manual_match_sql": manual_match_sql,
        "matched_sql": noise_matched_sql,
        "rules_sql": noise_rules_sql,
    }


def build_effective_noise_condition(alias: str = "events", *, case_id_sql: Optional[str] = None) -> str:
    case_id_expr = case_id_sql or f"{alias}.case_id"
    selector_sql = build_event_selector_sql(alias)
    overlay_enabled_sql = (
        f"{case_id_expr} IN (SELECT DISTINCT case_id FROM {NOISE_CASE_STATE_TABLE})"
    )
    latest_scan_sql = (
        f"SELECT argMax(scan_version, updated_at) "
        f"FROM {NOISE_CASE_STATE_TABLE} "
        f"WHERE case_id = {case_id_expr}"
    )
    manual_true_sql = f"""
        {selector_sql} IN (
            SELECT selector_key
            FROM (
                SELECT
                    case_id,
                    selector_key,
                    argMax(noise_matched, updated_at) AS noise_matched
                FROM {NOISE_MANUAL_STATE_TABLE}
                GROUP BY case_id, selector_key
            )
            WHERE case_id = {case_id_expr}
              AND noise_matched = true
        )
    """.strip()
    scan_true_sql = f"""
        {selector_sql} IN (
            SELECT selector_key
            FROM {NOISE_SCAN_STATE_TABLE}
            WHERE case_id = {case_id_expr}
              AND scan_version = ({latest_scan_sql})
            GROUP BY selector_key
        )
    """.strip()
    raw_noise_sql = f"{alias}.noise_matched = true" if alias else "noise_matched = true"
    return (
        f"if({overlay_enabled_sql}, "
        f"(({manual_true_sql}) OR ({scan_true_sql})), "
        f"({raw_noise_sql}))"
    )


def build_effective_not_noise_clause(alias: str = "events", *, case_id_sql: Optional[str] = None) -> str:
    return f"NOT ({build_effective_noise_condition(alias, case_id_sql=case_id_sql)})"


def replace_legacy_noise_filter(query: str, *, alias: str = "events", case_id_sql: Optional[str] = None) -> str:
    effective = build_effective_not_noise_clause(alias, case_id_sql=case_id_sql)
    normalized_variants = (
        LEGACY_NOT_NOISE_SQL,
        " (noise_matched = false OR noise_matched IS NULL) ",
        "AND (noise_matched = false OR noise_matched IS NULL)",
        "AND (noise_matched = false OR noise_matched IS NULL) ",
        "AND (noise_matched = false OR noise_matched IS NULL)\n",
    )
    updated = query
    for variant in normalized_variants:
        updated = updated.replace(variant, variant.replace(LEGACY_NOT_NOISE_SQL, effective))
    return updated


def count_effective_noise_events(case_id: int, client=None) -> int:
    client = client or get_client()
    ensure_event_noise_state_tables(client)
    where_clause = build_effective_noise_condition(alias="events", case_id_sql="{case_id:UInt32}")
    result = client.query(
        f"SELECT count() FROM events WHERE case_id = {{case_id:UInt32}} AND ({where_clause})",
        parameters={"case_id": int(case_id)},
    )
    return result.result_rows[0][0] if result.result_rows else 0


__all__ = [
    "LEGACY_NOT_NOISE_SQL",
    "build_effective_noise_condition",
    "build_effective_not_noise_clause",
    "build_event_selector_key",
    "build_noise_projection",
    "count_effective_noise_events",
    "ensure_event_noise_state_tables",
    "ensure_noise_overlay_case",
    "insert_noise_scan_matches",
    "replace_legacy_noise_filter",
    "start_noise_scan",
    "upsert_manual_noise_state_rows",
]
