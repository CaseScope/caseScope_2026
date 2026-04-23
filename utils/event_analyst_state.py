"""Single-table ClickHouse storage for mutable analyst event state."""

from __future__ import annotations

from datetime import datetime, timezone
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

ANALYST_STATE_TABLE = "event_analyst_state"


def normalize_analyst_tags(tags: Iterable[Any]) -> List[str]:
    return [str(tag).strip() for tag in (tags or []) if str(tag).strip()]


def ensure_event_analyst_state_table(client=None) -> None:
    """Compatibility no-op now that analyst state lives on `events`."""
    return None


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


def upsert_event_analyst_state_rows(
    case_id: int,
    updates: Iterable[Dict[str, Any]],
    *,
    updated_by: str,
    client=None,
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
                bool(update.get("analyst_tagged")),
                normalize_analyst_tags(update.get("analyst_tags", [])),
                str(update.get("analyst_notes")).strip() if update.get("analyst_notes") else None,
                str(updated_by or "").strip() or "system",
            )
        )

    if not prepared_rows:
        return 0

    grouped_updates: Dict[tuple, List[str]] = {}
    for _, selector_key, analyst_tagged, analyst_tags, analyst_notes, _updated_by in prepared_rows:
        grouped_updates.setdefault(
            (
                bool(analyst_tagged),
                tuple(analyst_tags),
                analyst_notes,
            ),
            [],
        ).append(selector_key)

    for (analyst_tagged, analyst_tags, analyst_notes), selector_keys in grouped_updates.items():
        assignments_sql = ", ".join(
            [
                f"analyst_tagged = {clickhouse_bool_literal(analyst_tagged)}",
                f"analyst_tags = {clickhouse_string_array_literal(list(analyst_tags))}",
                f"analyst_notes = {clickhouse_nullable_string_literal(analyst_notes)}",
            ]
        )
        where_sql = (
            f"case_id = {int(case_id)} "
            f"AND has({clickhouse_string_array_literal(selector_keys)}, selector_key)"
        )
        run_events_update(assignments_sql, where_sql, client=client)

    return len(prepared_rows)
