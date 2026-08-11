"""Single-table ClickHouse storage for mutable analyst event state."""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Optional

from utils.clickhouse import (
    clickhouse_bool_literal,
    clickhouse_nullable_string_literal,
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

ANALYST_STATE_TABLE = "event_analyst_state"


def normalize_analyst_tags(tags: Iterable[Any]) -> List[str]:
    return [str(tag).strip() for tag in (tags or []) if str(tag).strip()]


def _normalize_artifact_type(value: Any) -> Optional[str]:
    artifact_type = str(value or "").strip()
    if not artifact_type or artifact_type == "-":
        return None
    return artifact_type


def ensure_event_analyst_state_table(client=None) -> None:
    """Compatibility no-op now that analyst state lives on `events`."""
    return None


def _count_matching(client, where_sql: str) -> int:
    """Count rows a mutation is about to touch."""
    try:
        result = client.query(f"SELECT count() FROM events WHERE {where_sql}")
        return int(result.result_rows[0][0]) if result.result_rows else 0
    except Exception:
        logger.debug("Could not count analyst state mutation matches", exc_info=True)
        return 0


def build_analyst_projection(
    alias: str = "events",
    state_alias: str = "analyst_state",
    case_id_filter_sql: Optional[str] = None,
) -> Dict[str, str]:
    tagged_sql = f"{alias}.analyst_tagged"
    tags_sql = f"{alias}.analyst_tags"
    notes_sql = f"{alias}.analyst_notes"
    return {
        "selector_sql": f"{alias}.selector_key",
        "join_sql": "",
        "has_overlay_sql": "false",
        "tagged_sql": tagged_sql,
        "tags_sql": tags_sql,
        "notes_sql": notes_sql,
    }


def _fetch_prior_analyst_state(client, case_id: int, selector_keys: List[str]) -> Dict[str, Dict[str, Any]]:
    """Read the current analyst state for named events, for audit before/after.

    The key set is bounded by what the analyst selected, so this stays cheap.
    """
    if not selector_keys:
        return {}
    try:
        result = client.query(
            f"""
            SELECT selector_key, analyst_tagged, analyst_tags, analyst_notes, source_file
              FROM events
             WHERE case_id = {int(case_id)}
               AND has({clickhouse_string_array_literal(selector_keys)}, selector_key)
            """
        )
        return {
            row[0]: {
                "analyst_tagged": bool(row[1]),
                "analyst_tags": list(row[2] or []),
                "analyst_notes": row[3] or "",
                "source_file": row[4] or "",
            }
            for row in result.result_rows
        }
    except Exception:
        logger.debug("Could not read prior analyst state for audit", exc_info=True)
        return {}


def upsert_event_analyst_state_rows(
    case_id: int,
    updates: Iterable[Dict[str, Any]],
    *,
    updated_by: str,
    client=None,
    remote_ip: str = None,
    operation_id: str = None,
) -> int:
    client = client or get_client()
    ensure_event_analyst_state_table(client)

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
                bool(update.get("analyst_tagged")),
                normalize_analyst_tags(update.get("analyst_tags", [])),
                str(update.get("analyst_notes")).strip() if update.get("analyst_notes") else None,
                str(updated_by or "").strip() or "system",
            )
        )

    if not prepared_rows:
        return 0

    grouped_updates: Dict[tuple, List[str]] = {}
    for _, selector_key, artifact_type, analyst_tagged, analyst_tags, analyst_notes, _updated_by in prepared_rows:
        grouped_updates.setdefault(
            (
                artifact_type,
                bool(analyst_tagged),
                tuple(analyst_tags),
                analyst_notes,
            ),
            [],
        ).append(selector_key)

    operation_id = operation_id or new_operation_id()
    actor = str(updated_by or "").strip() or "system"
    matched_total = 0

    for (artifact_type, analyst_tagged, analyst_tags, analyst_notes), selector_keys in grouped_updates.items():
        assignments_sql = ", ".join(
            [
                f"analyst_tagged = {clickhouse_bool_literal(analyst_tagged)}",
                f"analyst_tags = {clickhouse_string_array_literal(list(analyst_tags))}",
                f"analyst_notes = {clickhouse_nullable_string_literal(analyst_notes)}",
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
        matched_count = _count_matching(client, where_sql)
        if matched_count <= 0:
            logger.warning(
                "Analyst tag update matched no events for case %s and %s selector(s)",
                case_id,
                len(selector_keys),
            )
            continue
        matched_total += matched_count

        # Captured before the mutation so the audit row can state what the
        # event looked like beforehand.
        prior = _fetch_prior_analyst_state(client, case_id, selector_keys)
        matched_selector_keys = [key for key in selector_keys if key in prior] or selector_keys

        run_events_update(assignments_sql, where_sql, client=client)

        new_state = {
            "analyst_tagged": bool(analyst_tagged),
            "analyst_tags": list(analyst_tags),
            "analyst_notes": analyst_notes or "",
        }
        record_event_changes(
            EvidenceChange(
                case_id=case_id,
                field_name="analyst_tags",
                action=(
                    EVIDENCE_TAGGED
                    if analyst_tagged
                    else EVIDENCE_UNTAGGED
                ),
                new_value=new_state,
                predicate=where_sql,
                affected_count=matched_count,
                username=actor,
                remote_ip=remote_ip,
                operation_id=operation_id,
                details={"artifact_type": artifact_type} if artifact_type else {},
            ),
            [
                EventChange(
                    selector_key=selector_key,
                    old_value=prior.get(selector_key, {"analyst_tagged": False, "analyst_tags": [], "analyst_notes": ""}),
                    new_value=new_state,
                    source_file=prior.get(selector_key, {}).get("source_file"),
                    artifact_type=artifact_type,
                )
                for selector_key in matched_selector_keys
            ],
        )

    return matched_total


__all__ = [
    "build_analyst_projection",
    "build_event_selector_key",
    "ensure_event_analyst_state_table",
    "normalize_analyst_tags",
    "upsert_event_analyst_state_rows",
]
