"""Helpers for stable event selector keys across overlay tables."""

from __future__ import annotations

from enum import Enum
from typing import Any


def _normalized_host(value: Any) -> str:
    normalized = str(value or "").strip()
    return "" if normalized == "-" else normalized


def _normalized_component(value: Any) -> str:
    normalized = str(value or "").strip()
    return "" if normalized == "-" else normalized


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
    try:
        record_id_value = int(record_id)
    except (TypeError, ValueError):
        record_id_value = 0

    source_file_value = _normalized_component(source_file)
    source_host_value = _normalized_host(source_host)
    if record_id_value > 0 and source_file_value and source_host_value:
        return f"record:{record_id_value}|file:{source_file_value}|host:{source_host_value}"

    timestamp_value = str(timestamp or "").strip()
    if timestamp_value:
        artifact_value = _normalized_component(artifact_type)
        event_id_value = _normalized_component(event_id)
        return (
            f"ts:{timestamp_value}|host:{source_host_value}|artifact:{artifact_value}"
            f"|event:{event_id_value}|file:{source_file_value}"
        )

    event_id_value = _normalized_component(event_id)
    if event_id_value:
        return f"event_id:{event_id_value}"

    raise ValueError("No unique identifier available")


class SelectorKeySource(str, Enum):
    EVENTS_TABLE = "events_table"
    RAW_EXPRESSION = "raw_expression"


def _raw_selector_expression(alias: str = "events") -> str:
    """Return the canonical ClickHouse expression matching `build_event_selector_key()`."""

    def col(name: str) -> str:
        return f"{alias}.{name}" if alias else name

    return f"""
        multiIf(
            {col('record_id')} > 0
                AND {col('source_file')} IS NOT NULL AND {col('source_file')} != ''
                AND {col('source_file')} != '-'
                AND {col('source_host')} IS NOT NULL AND {col('source_host')} != ''
                AND {col('source_host')} != '-',
            concat(
                'record:', toString({col('record_id')}),
                '|file:', {col('source_file')},
                '|host:', {col('source_host')}
            ),
            COALESCE({col('timestamp_utc')}, {col('timestamp')}) IS NOT NULL,
            concat(
                'ts:', formatDateTime(COALESCE({col('timestamp_utc')}, {col('timestamp')}), '%Y-%m-%d %H:%i:%S'),
                '|host:', if(ifNull({col('source_host')}, '') = '-', '', ifNull({col('source_host')}, '')),
                '|artifact:', if(ifNull({col('artifact_type')}, '') = '-', '', ifNull({col('artifact_type')}, '')),
                '|event:', if(ifNull({col('event_id')}, '') = '-', '', ifNull({col('event_id')}, '')),
                '|file:', if(ifNull({col('source_file')}, '') = '-', '', ifNull({col('source_file')}, ''))
            ),
            {col('event_id')} IS NOT NULL AND {col('event_id')} != ''
                AND {col('event_id')} != '-',
            concat('event_id:', {col('event_id')}),
            ''
        )
    """.strip()


def build_event_selector_sql(
    alias: str = "events",
    *,
    source: SelectorKeySource = SelectorKeySource.EVENTS_TABLE,
) -> str:
    """Return the canonical selector SQL for the current storage model."""
    if source == SelectorKeySource.RAW_EXPRESSION:
        return _raw_selector_expression(alias)
    return f"{alias}.selector_key" if alias else "selector_key"


__all__ = [
    "SelectorKeySource",
    "_raw_selector_expression",
    "build_event_selector_key",
    "build_event_selector_sql",
]
