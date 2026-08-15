"""Structured Phase 0A ingestion measurement helpers.

The helpers in this module are intentionally observational: they only emit
sanitized timing/counter logs and do not affect ingest control flow.
"""
from __future__ import annotations

import logging
import os
import time
from contextlib import contextmanager
from typing import Any, Dict, Iterator, Optional

logger = logging.getLogger("casescope.database_flow.ingest")

_SENSITIVE_KEYS = {
    "file_path",
    "source_path",
    "raw_json",
    "extra_fields",
    "search_blob",
    "command_line",
    "payload",
}


def diagnostic_counts_enabled() -> bool:
    """Return True when optional Phase 0A diagnostic counts are enabled."""
    return os.environ.get("DATABASE_FLOW_DIAGNOSTIC_COUNTS", "").lower() in {"1", "true", "yes", "on"}


def monotonic_ms() -> float:
    """Return the current monotonic clock in milliseconds."""
    return time.perf_counter() * 1000.0


def _sanitize_value(value: Any) -> Any:
    if isinstance(value, float):
        return round(value, 3)
    if isinstance(value, (str, int, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return sanitize_fields(value)
    if isinstance(value, (list, tuple)):
        return [_sanitize_value(item) for item in value[:20]]
    return str(value)


def sanitize_fields(fields: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Drop sensitive evidence-bearing fields and normalize log values."""
    sanitized: Dict[str, Any] = {}
    for key, value in (fields or {}).items():
        if key in _SENSITIVE_KEYS:
            continue
        sanitized[key] = _sanitize_value(value)
    return sanitized


def emit_metric(stage: str, **fields: Any) -> None:
    """Emit one structured metric log event."""
    payload = {"stage": stage, **sanitize_fields(fields)}
    logger.info("database_flow_phase0a_metric %s", payload)


@contextmanager
def timed_stage(stage: str, **fields: Any) -> Iterator[Dict[str, Any]]:
    """Time a stage and emit a structured metric when it exits."""
    started = monotonic_ms()
    counters: Dict[str, Any] = {}
    success = False
    try:
        yield counters
        success = True
    finally:
        emit_metric(
            stage,
            duration_ms=monotonic_ms() - started,
            success=success,
            **fields,
            **counters,
        )


def estimate_rows_bytes(rows: Any) -> int:
    """Best-effort inserted byte estimate without inspecting raw evidence values."""
    try:
        total = 0
        for row in rows or []:
            if isinstance(row, (list, tuple)):
                for value in row:
                    if isinstance(value, str):
                        total += len(value.encode("utf-8", errors="ignore"))
                    elif value is not None:
                        total += 8
            elif row is not None:
                total += 8
        return total
    except Exception:
        return 0
