"""Helpers for stable event selector keys across overlay tables."""

from __future__ import annotations

from typing import Any


def build_event_selector_key(
    *,
    event_id: Any = "",
    record_id: Any = "",
    source_file: Any = "",
    source_host: Any = "",
    timestamp: Any = "",
    artifact_type: Any = "",
) -> str:
    """Build the canonical selector used by ClickHouse overlay tables."""
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
    """Return the ClickHouse SQL expression matching `build_event_selector_key()`."""

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
