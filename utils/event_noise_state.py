"""Single-table ClickHouse storage for mutable noise event state."""

from __future__ import annotations

import logging
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
from utils.evidence_audit import (
    EVIDENCE_TAGGED,
    EVIDENCE_UNTAGGED,
    EventChange,
    EvidenceChange,
    new_operation_id,
    record_event_changes,
)

logger = logging.getLogger(__name__)

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


def _count_matching(client, where_sql: str) -> int:
    """Count rows a mutation is about to touch, for the audit record."""
    try:
        result = client.query(f"SELECT count() FROM events WHERE {where_sql}")
        return int(result.result_rows[0][0]) if result.result_rows else 0
    except Exception:
        return 0


def _fetch_prior_noise_state(client, case_id: int, selector_keys: List[str]) -> Dict[str, Dict[str, Any]]:
    """Read current noise state for named events, for audit before/after."""
    if not selector_keys:
        return {}
    try:
        result = client.query(
            f"""
            SELECT selector_key, noise_matched, noise_rules, source_file
              FROM events
             WHERE case_id = {int(case_id)}
               AND has({clickhouse_string_array_literal(selector_keys)}, selector_key)
            """
        )
        return {
            row[0]: {
                "noise_matched": bool(row[1]),
                "noise_rules": list(row[2] or []),
                "source_file": row[3] or "",
            }
            for row in result.result_rows
        }
    except Exception:
        logger.debug("Could not read prior noise state for audit", exc_info=True)
        return {}


def start_noise_scan(case_id: int, *, updated_by: str, client=None, remote_ip: str = None,
                     operation_id: str = None) -> str:
    client = client or get_client()
    ensure_event_noise_state_tables(client)
    # Reset scan-derived noise rows while preserving manual noise tags, which are
    # represented as noise_matched=true with an empty noise_rules array.
    where_sql = f"case_id = {int(case_id)} AND length(noise_rules) > 0"
    run_events_update(
        "noise_matched = false, noise_rules = []",
        where_sql,
        client=client,
        audit=EvidenceChange(
            case_id=case_id,
            field_name="noise_rules",
            action=EVIDENCE_UNTAGGED,
            old_value="(existing rule-derived noise flags)",
            new_value=[],
            affected_count=_count_matching(client, where_sql),
            username=_normalized_username(updated_by),
            remote_ip=remote_ip,
            operation_id=operation_id,
            details={"reason": "Noise rescan started; rule-derived flags cleared, manual tags preserved"},
        ),
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
    remote_ip: str = None,
    operation_id: str = None,
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
        audit=EvidenceChange(
            case_id=case_id,
            field_name="noise_rules",
            action=EVIDENCE_TAGGED,
            old_value="(rule not applied)",
            new_value=params["rule_name"],
            affected_count=int(match_count),
            entity_name=params["rule_name"],
            username=params["updated_by"],
            remote_ip=remote_ip,
            operation_id=operation_id,
            details={"scan_version": params["scan_version"], "rule_name": params["rule_name"]},
        ),
    )
    return int(match_count)


def upsert_manual_noise_state_rows(
    case_id: int,
    updates: Iterable[Dict[str, Any]],
    *,
    updated_by: str,
    client=None,
    remote_ip: str = None,
    operation_id: str = None,
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

    operation_id = operation_id or new_operation_id()
    actor = _normalized_username(updated_by)

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

        prior = _fetch_prior_noise_state(client, case_id, selector_keys)
        run_events_update(assignments_sql, where_sql, client=client, wait=False)

        new_state = {"noise_matched": bool(noise_matched), "noise_rules": list(noise_rules)}
        record_event_changes(
            EvidenceChange(
                case_id=case_id,
                field_name="noise_matched",
                action=(
                    EVIDENCE_TAGGED
                    if noise_matched
                    else EVIDENCE_UNTAGGED
                ),
                new_value=new_state,
                predicate=where_sql,
                affected_count=len(selector_keys),
                username=actor,
                remote_ip=remote_ip,
                operation_id=operation_id,
                details={"scope_note": "manual noise tagging"},
            ),
            [
                EventChange(
                    selector_key=selector_key,
                    old_value=prior.get(selector_key, {"noise_matched": False, "noise_rules": []}),
                    new_value=new_state,
                    source_file=prior.get(selector_key, {}).get("source_file"),
                    artifact_type=artifact_type,
                )
                for selector_key in selector_keys
            ],
        )
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
