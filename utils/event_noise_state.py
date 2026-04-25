"""Single-table ClickHouse storage for mutable noise event state."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional
from uuid import uuid4

from utils.clickhouse import (
    clickhouse_bool_literal,
    clickhouse_string_array_literal,
    clickhouse_string_literal,
    get_client,
    run_events_update,
)
from utils.event_selector import build_event_selector_key

NOISE_CASE_STATE_TABLE = "event_noise_case_state"
NOISE_SCAN_STATE_TABLE = "event_noise_state"
NOISE_MANUAL_STATE_TABLE = "event_noise_manual_state"
LEGACY_NOT_NOISE_SQL = "(noise_matched = false OR noise_matched IS NULL)"


def ensure_event_noise_state_tables(client=None) -> None:
    """Compatibility no-op now that noise state lives on `events`."""
    return None


def _normalized_username(value: Any) -> str:
    return str(value or "").strip() or "system"


def _normalize_artifact_type(value: Any) -> Optional[str]:
    artifact_type = str(value or "").strip()
    if not artifact_type or artifact_type == "-":
        return None
    return artifact_type


def start_noise_scan(case_id: int, *, updated_by: str, client=None) -> str:
    client = client or get_client()
    ensure_event_noise_state_tables(client)
    # Reset scan-derived noise rows while preserving manual noise tags, which are
    # represented as noise_matched=true with an empty noise_rules array.
    run_events_update(
        "noise_matched = false, noise_rules = []",
        f"case_id = {int(case_id)} AND length(noise_rules) > 0",
        client=client,
    )
    return str(uuid4())


def ensure_noise_overlay_case(case_id: int, *, updated_by: str, client=None) -> str:
    return str(uuid4())


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

    resolved_where = where_clause.replace("{case_id:UInt32}", str(int(case_id)))
    run_events_update(
        f"noise_matched = true, noise_rules = arrayDistinct(arrayConcat(noise_rules, {clickhouse_string_array_literal([params['rule_name']])}))",
        resolved_where,
        client=client,
    )
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
    for update in updates or []:
        selector_key = str(update.get("selector_key") or "").strip()
        if not selector_key:
            continue
        prepared_rows.append(
            (
                int(case_id),
                selector_key,
                _normalize_artifact_type(update.get("artifact_type")),
                bool(update.get("noise_matched")),
                [str(rule).strip() for rule in (update.get("noise_rules") or []) if str(rule).strip()],
                _normalized_username(updated_by),
            )
        )

    if not prepared_rows:
        return 0

    grouped_updates: Dict[tuple, List[str]] = {}
    for _, selector_key, artifact_type, noise_matched, noise_rules, _updated_by in prepared_rows:
        grouped_updates.setdefault((artifact_type, bool(noise_matched), tuple(noise_rules)), []).append(selector_key)

    for (artifact_type, noise_matched, noise_rules), selector_keys in grouped_updates.items():
        assignments_sql = ", ".join(
            [
                f"noise_matched = {clickhouse_bool_literal(noise_matched)}",
                f"noise_rules = {clickhouse_string_array_literal(list(noise_rules))}",
            ]
        )
        artifact_filter_sql = (
            f"AND artifact_type = {clickhouse_string_literal(artifact_type)} "
            if artifact_type
            else ""
        )
        where_sql = (
            f"case_id = {int(case_id)} "
            f"{artifact_filter_sql}"
            f"AND has({clickhouse_string_array_literal(selector_keys)}, selector_key)"
        )
        run_events_update(assignments_sql, where_sql, client=client, wait=False)
    return len(prepared_rows)


def build_noise_projection(alias: str = "events", case_id_filter_sql: Optional[str] = None) -> Dict[str, str]:
    noise_matched_sql = f"{alias}.noise_matched"
    noise_rules_sql = f"{alias}.noise_rules"
    return {
        "selector_sql": f"{alias}.selector_key",
        "join_sql": "",
        "overlay_enabled_sql": "true",
        "scan_match_sql": "false",
        "manual_match_sql": "false",
        "matched_sql": noise_matched_sql,
        "rules_sql": noise_rules_sql,
    }


def build_effective_noise_condition(alias: str = "events", *, case_id_sql: Optional[str] = None) -> str:
    raw_noise_sql = f"{alias}.noise_matched = true" if alias else "noise_matched = true"
    return raw_noise_sql


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
    result = client.query(
        "SELECT count() FROM events WHERE case_id = {case_id:UInt32} AND noise_matched = true",
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
