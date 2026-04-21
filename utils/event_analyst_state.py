"""ClickHouse-side overlay storage for mutable analyst event state."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List

from utils.clickhouse import get_client

ANALYST_STATE_TABLE = "event_analyst_state"


def normalize_analyst_tags(tags: Iterable[Any]) -> List[str]:
    return [str(tag).strip() for tag in (tags or []) if str(tag).strip()]


def build_event_selector_key(
    *,
    event_id: Any = "",
    record_id: Any = "",
    source_file: Any = "",
    source_host: Any = "",
    timestamp: Any = "",
    artifact_type: Any = "",
) -> str:
    """Build the canonical selector used by the analyst-state overlay table."""
    event_id_value = str(event_id or "").strip()
    if event_id_value and event_id_value != "-":
        return f"event_id:{event_id_value}"

    try:
        record_id_value = int(record_id)
    except (TypeError, ValueError):
        record_id_value = 0

    source_file_value = str(source_file or "").strip()
    source_host_value = str(source_host or "").strip()
    if record_id_value > 0 and source_file_value and source_host_value and source_host_value != "-":
        return f"record:{record_id_value}|file:{source_file_value}|host:{source_host_value}"

    timestamp_value = str(timestamp or "").strip()
    if timestamp_value:
        artifact_value = str(artifact_type or "").strip()
        host_value = "" if source_host_value == "-" else source_host_value
        return f"ts:{timestamp_value}|host:{host_value}|artifact:{artifact_value}"

    raise ValueError("No unique identifier available")


def build_event_selector_sql(alias: str = "events") -> str:
    """Return the ClickHouse SQL expression that matches `build_event_selector_key()`."""
    def col(name: str) -> str:
        return f"{alias}.{name}" if alias else name

    return f"""
        multiIf(
            {col('event_id')} IS NOT NULL AND {col('event_id')} != '',
            concat('event_id:', {col('event_id')}),
            {col('record_id')} > 0
                AND {col('source_file')} IS NOT NULL AND {col('source_file')} != ''
                AND {col('source_host')} IS NOT NULL AND {col('source_host')} != '',
            concat(
                'record:', toString({col('record_id')}),
                '|file:', {col('source_file')},
                '|host:', {col('source_host')}
            ),
            concat(
                'ts:', formatDateTime(COALESCE({col('timestamp_utc')}, {col('timestamp')}), '%Y-%m-%d %H:%M:%S'),
                '|host:', ifNull({col('source_host')}, ''),
                '|artifact:', ifNull({col('artifact_type')}, '')
            )
        )
    """.strip()


def ensure_event_analyst_state_table(client=None) -> None:
    client = client or get_client()
    client.command(
        f"""
        CREATE TABLE IF NOT EXISTS {ANALYST_STATE_TABLE} (
            case_id UInt32,
            selector_key String,
            analyst_tagged Bool,
            analyst_tags Array(String),
            analyst_notes Nullable(String),
            updated_by String,
            updated_at DateTime64(3) DEFAULT now64(3)
        )
        ENGINE = ReplacingMergeTree(updated_at)
        ORDER BY (case_id, selector_key)
        """
    )


def build_analyst_projection(alias: str = "events", state_alias: str = "analyst_state") -> Dict[str, str]:
    selector_sql = build_event_selector_sql(alias)
    join_sql = f"""
        LEFT JOIN (
            SELECT
                case_id,
                selector_key,
                argMax(analyst_tagged, updated_at) AS analyst_tagged,
                argMax(analyst_tags, updated_at) AS analyst_tags,
                argMax(analyst_notes, updated_at) AS analyst_notes
            FROM {ANALYST_STATE_TABLE}
            GROUP BY case_id, selector_key
        ) AS {state_alias}
        ON {state_alias}.case_id = {alias}.case_id
        AND {state_alias}.selector_key = {selector_sql}
    """.strip()
    has_overlay_sql = f"notEmpty({state_alias}.selector_key)"
    tagged_sql = f"if({has_overlay_sql}, {state_alias}.analyst_tagged, {alias}.analyst_tagged)"
    tags_sql = f"if({has_overlay_sql}, {state_alias}.analyst_tags, {alias}.analyst_tags)"
    notes_sql = f"if({has_overlay_sql}, {state_alias}.analyst_notes, {alias}.analyst_notes)"
    return {
        "selector_sql": selector_sql,
        "join_sql": join_sql,
        "has_overlay_sql": has_overlay_sql,
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
    updated_at = datetime.now(timezone.utc)
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
                updated_at,
            )
        )

    if not prepared_rows:
        return 0

    client.insert(
        ANALYST_STATE_TABLE,
        prepared_rows,
        column_names=[
            "case_id",
            "selector_key",
            "analyst_tagged",
            "analyst_tags",
            "analyst_notes",
            "updated_by",
            "updated_at",
        ],
    )
    return len(prepared_rows)
