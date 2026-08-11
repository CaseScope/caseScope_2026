#!/usr/bin/env python3
"""Migration: add and backfill Evidence Identity v2 for ClickHouse events."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import re
import sys
import time
from typing import Any, Dict, Iterable, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from migrations.add_events_table import (  # noqa: E402
    EVENTS_COLUMN_DEFINITIONS,
    assert_events_buffer_is_buffer_engine,
    fence_events_buffer_ingestion,
    get_events_buffer_state,
    recreate_events_buffer,
)
from parsers.base import ParsedEvent  # noqa: E402
from utils.clickhouse import (  # noqa: E402
    destructive_event_rewrite_guard,
    get_migration_client,
    migration_client_effective_settings,
    migration_source_query_settings,
)
from utils.evidence_identity import (  # noqa: E402
    EVIDENCE_IDENTITY_VERSION,
    EVIDENCE_RECORD_KEY_PREFIX,
    EvidenceIdentityQuality,
    build_identity_from_clickhouse_row,
)


IDENTITY_COLUMNS = (
    "evidence_record_key",
    "evidence_identity_version",
    "evidence_identity_quality",
)
IDENTITY_INDEX_NAME = "idx_evidence_record_key"
IDENTITY_INDEX_EXPRESSION = "evidence_record_key TYPE bloom_filter(0.01) GRANULARITY 4"
IDENTITY_INDEX_DEFINITION = f"{IDENTITY_INDEX_NAME} {IDENTITY_INDEX_EXPRESSION}"
SHADOW_TABLE = "events_evidence_identity_backfill"
OLD_TABLE = "events_evidence_identity_previous"
LEGACY_V1_PREFIX = "erk:v1:"
VALID_V2_KEY_PATTERN = rf"^{re.escape(EVIDENCE_RECORD_KEY_PREFIX)}[0-9a-f]{{64}}$"
VALID_QUALITY_VALUES = tuple(quality.value for quality in EvidenceIdentityQuality)
DEFAULT_PROGRESS_INTERVAL_ROWS = int(
    os.environ.get("EVIDENCE_IDENTITY_PROGRESS_INTERVAL_ROWS", 1_000_000)
)
DEFAULT_INSERT_BATCH_SIZE = int(os.environ.get("EVIDENCE_IDENTITY_INSERT_BATCH_SIZE", 1000))
DEFAULT_SOURCE_WINDOW_SECONDS = max(
    int(os.environ.get("EVIDENCE_IDENTITY_SOURCE_WINDOW_SECONDS", 900)),
    1,
)
DEFAULT_COPY_WORKERS = max(int(os.environ.get("EVIDENCE_IDENTITY_COPY_WORKERS", 1)), 1)


def _existing_columns(client, table_name: str) -> set:
    result = client.query(
        """
        SELECT name
        FROM system.columns
        WHERE database = currentDatabase()
          AND table = {table_name:String}
        """,
        parameters={"table_name": table_name},
    )
    return {row[0] for row in result.result_rows}


def _table_exists(client, table_name: str) -> bool:
    result = client.query(
        """
        SELECT count()
        FROM system.tables
        WHERE database = currentDatabase()
          AND table = {table_name:String}
        """,
        parameters={"table_name": table_name},
    )
    return bool(result.result_rows and result.result_rows[0][0])


def _table_engine(client, table_name: str) -> str:
    result = client.query(
        """
        SELECT engine
        FROM system.tables
        WHERE database = currentDatabase()
          AND table = {table_name:String}
        """,
        parameters={"table_name": table_name},
    )
    return str(result.result_rows[0][0]) if result.result_rows else ""


def _table_columns(client, table_name: str) -> List[Dict[str, str]]:
    result = client.query(
        """
        SELECT name, default_kind
        FROM system.columns
        WHERE database = currentDatabase()
          AND table = {table_name:String}
        ORDER BY position
        """,
        parameters={"table_name": table_name},
    )
    return [
        {"name": str(row[0]), "default_kind": str(row[1] or "")}
        for row in result.result_rows
    ]


def _insertable_columns(client, table_name: str = "events") -> List[str]:
    return [
        column["name"]
        for column in _table_columns(client, table_name)
        if column["default_kind"].upper() not in {"MATERIALIZED", "ALIAS"}
    ]


def _required_identity_columns_present(client, table_name: str = "events") -> bool:
    existing = _existing_columns(client, table_name)
    return all(column in existing for column in IDENTITY_COLUMNS)


def verify_identity_columns(client, table_name: str = "events") -> None:
    existing = _existing_columns(client, table_name)
    missing = [column for column in IDENTITY_COLUMNS if column not in existing]
    if missing:
        raise RuntimeError(
            f"{table_name} identity schema verification failed; missing columns: {missing}"
        )


def add_identity_columns(client) -> None:
    existing = _existing_columns(client, "events")
    if not existing:
        raise RuntimeError("events table does not exist or has no columns; cannot prepare identity schema")
    for column_name in IDENTITY_COLUMNS:
        if column_name in existing:
            continue
        definition = EVENTS_COLUMN_DEFINITIONS[column_name]
        client.command(
            f"ALTER TABLE events ADD COLUMN IF NOT EXISTS {column_name} {definition}"
        )
        existing = _existing_columns(client, "events")
        if column_name not in existing:
            raise RuntimeError(
                f"events identity schema verification failed; {column_name} absent after ADD COLUMN"
            )
        print(f"- Verified {column_name} on events")
    verify_identity_columns(client)


def ensure_identity_index(client, *, materialize: bool = False) -> bool:
    verify_identity_columns(client)
    result = client.query(
        """
        SELECT name
        FROM system.data_skipping_indices
        WHERE database = currentDatabase()
          AND table = 'events'
          AND name = {index_name:String}
        """,
        parameters={"index_name": IDENTITY_INDEX_NAME},
    )
    if result.result_rows:
        _verify_identity_index(client)
        return False
    client.command(_add_identity_index_sql())
    _verify_identity_index(client)
    print("- Verified idx_evidence_record_key on events")
    if materialize:
        client.command(f"ALTER TABLE events MATERIALIZE INDEX {IDENTITY_INDEX_NAME}")
        print("- Materialized idx_evidence_record_key on events")
    return True


def _add_identity_index_sql() -> str:
    return f"ALTER TABLE events ADD INDEX IF NOT EXISTS {IDENTITY_INDEX_DEFINITION}"


def _verify_identity_index(client) -> None:
    if not _has_identity_index(client):
        raise RuntimeError(f"{IDENTITY_INDEX_NAME} verification failed after ADD INDEX")


def ensure_events_buffer_schema(client) -> None:
    if not _table_exists(client, "events"):
        return
    if not _table_exists(client, "events_buffer"):
        _recreate_and_verify_events_buffer(client)
        return

    assert_events_buffer_is_buffer_engine(client)
    events_columns = set(_insertable_columns(client, "events"))
    buffer_columns = set(_insertable_columns(client, "events_buffer"))
    if events_columns == buffer_columns:
        _verify_events_buffer_matches_events(client)
        return

    fence_events_buffer_ingestion(client, context="events_buffer schema recreation")
    _verify_table_absent(client, "events_buffer")
    _recreate_and_verify_events_buffer(client)
    print("- Verified events_buffer schema matches events")


def _verify_table_absent(client, table_name: str) -> None:
    if _table_exists(client, table_name):
        raise RuntimeError(f"{table_name} should be absent but still exists")


def _verify_table_exists_with_engine(client, table_name: str, expected_engine: Optional[str] = None) -> None:
    if not _table_exists(client, table_name):
        raise RuntimeError(f"{table_name} should exist but is absent")
    engine = _table_engine(client, table_name)
    if expected_engine and engine.lower() != expected_engine.lower():
        raise RuntimeError(
            f"{table_name} engine verification failed; expected {expected_engine}, found {engine or 'unknown'}"
        )


def _verify_events_buffer_matches_events(client) -> None:
    _verify_table_exists_with_engine(client, "events_buffer", "Buffer")
    events_columns = set(_insertable_columns(client, "events"))
    buffer_columns = set(_insertable_columns(client, "events_buffer"))
    if events_columns != buffer_columns:
        raise RuntimeError("events_buffer schema verification failed; insertable columns differ from events")


def _recreate_and_verify_events_buffer(client) -> None:
    recreate_events_buffer(client)
    _verify_events_buffer_matches_events(client)
    print("- Verified events_buffer table")


def _verify_events_buffer_safe_for_rewrite(client) -> None:
    if not _table_exists(client, "events_buffer"):
        return
    assert_events_buffer_is_buffer_engine(client)


def _row_to_mapping(columns: List[str], row: Iterable[Any]) -> Dict[str, Any]:
    return dict(zip(columns, row))


def _count_events(client, *, table_name: str = "events", case_id: Optional[int] = None) -> int:
    where = ""
    parameters: Dict[str, Any] = {}
    if case_id is not None:
        where = " WHERE case_id = {case_id:UInt32}"
        parameters["case_id"] = int(case_id)
    result = client.query(f"SELECT count() FROM {table_name}{where}", parameters=parameters)
    return int(result.result_rows[0][0]) if result.result_rows else 0


def _count_empty_identity(client, *, table_name: str = "events", case_id: Optional[int] = None) -> int:
    where = "WHERE evidence_record_key = ''"
    parameters: Dict[str, Any] = {}
    if case_id is not None:
        where += " AND case_id = {case_id:UInt32}"
        parameters["case_id"] = int(case_id)
    result = client.query(f"SELECT count() FROM {table_name} {where}", parameters=parameters)
    return int(result.result_rows[0][0]) if result.result_rows else 0


def _count_identity_prefix(
    client,
    prefix: str,
    *,
    table_name: str = "events",
    case_id: Optional[int] = None,
) -> int:
    where = "WHERE startsWith(evidence_record_key, {prefix:String})"
    parameters: Dict[str, Any] = {"prefix": prefix}
    if case_id is not None:
        where += " AND case_id = {case_id:UInt32}"
        parameters["case_id"] = int(case_id)
    result = client.query(f"SELECT count() FROM {table_name} {where}", parameters=parameters)
    return int(result.result_rows[0][0]) if result.result_rows else 0


def _count_valid_v2_identity(
    client,
    *,
    table_name: str = "events",
    case_id: Optional[int] = None,
) -> int:
    where = "WHERE match(evidence_record_key, {v2_pattern:String})"
    parameters: Dict[str, Any] = {"v2_pattern": VALID_V2_KEY_PATTERN}
    if case_id is not None:
        where += " AND case_id = {case_id:UInt32}"
        parameters["case_id"] = int(case_id)
    result = client.query(f"SELECT count() FROM {table_name} {where}", parameters=parameters)
    return int(result.result_rows[0][0]) if result.result_rows else 0


def _count_unknown_identity(
    client,
    *,
    table_name: str = "events",
    case_id: Optional[int] = None,
) -> int:
    where = (
        "WHERE evidence_record_key != '' "
        "AND NOT startsWith(evidence_record_key, {v1_prefix:String}) "
        "AND NOT match(evidence_record_key, {v2_pattern:String})"
    )
    parameters: Dict[str, Any] = {
        "v1_prefix": LEGACY_V1_PREFIX,
        "v2_pattern": VALID_V2_KEY_PATTERN,
    }
    if case_id is not None:
        where += " AND case_id = {case_id:UInt32}"
        parameters["case_id"] = int(case_id)
    result = client.query(f"SELECT count() FROM {table_name} {where}", parameters=parameters)
    return int(result.result_rows[0][0]) if result.result_rows else 0


def _count_invalid_identity_metadata(
    client,
    *,
    table_name: str = "events",
    case_id: Optional[int] = None,
    identity_schema: Optional[Dict[str, Any]] = None,
) -> Optional[int]:
    identity_schema = identity_schema or _identity_schema_state(client)
    required = {"evidence_record_key", "evidence_identity_version", "evidence_identity_quality"}
    if not required.issubset(identity_schema["events_columns"]):
        return None
    quality_sql = ", ".join(f"'{value}'" for value in VALID_QUALITY_VALUES)
    where = (
        "WHERE match(evidence_record_key, {v2_pattern:String}) "
        "AND (evidence_identity_version != {version:String} "
        f"OR evidence_identity_quality NOT IN ({quality_sql}))"
    )
    parameters: Dict[str, Any] = {
        "v2_pattern": VALID_V2_KEY_PATTERN,
        "version": EVIDENCE_IDENTITY_VERSION,
    }
    if case_id is not None:
        where += " AND case_id = {case_id:UInt32}"
        parameters["case_id"] = int(case_id)
    result = client.query(f"SELECT count() FROM {table_name} {where}", parameters=parameters)
    return int(result.result_rows[0][0]) if result.result_rows else 0


def _distinct_case_ids(client) -> List[int]:
    result = client.query("SELECT DISTINCT case_id FROM events ORDER BY case_id")
    return [int(row[0]) for row in result.result_rows]


def _case_source_windows(client, case_id: int, *, window_seconds: int) -> List[tuple]:
    result = client.query(
        f"""
        SELECT
            toUnixTimestamp(toStartOfInterval(timestamp_utc, INTERVAL {int(window_seconds)} SECOND)) * 1000
                AS bucket_start_ms
        FROM events
        WHERE case_id = {{case_id:UInt32}}
        GROUP BY bucket_start_ms
        ORDER BY bucket_start_ms
        """,
        parameters={"case_id": int(case_id)},
    )
    return [
        (
            int(row[0]),
            int(row[0]) + int(window_seconds) * 1000,
        )
        for row in result.result_rows
    ]


def _count_case_partitions(client) -> Optional[int]:
    try:
        return len(_distinct_case_ids(client))
    except Exception:
        return None


def _has_identity_index(client) -> bool:
    result = client.query(
        """
        SELECT count()
        FROM system.data_skipping_indices
        WHERE database = currentDatabase()
          AND table = 'events'
          AND name = {index_name:String}
        """,
        parameters={"index_name": IDENTITY_INDEX_NAME},
    )
    return bool(result.result_rows and result.result_rows[0][0])


def _table_bytes(client, table_name: str) -> Optional[int]:
    try:
        result = client.query(
            """
            SELECT total_bytes
            FROM system.tables
            WHERE database = currentDatabase()
              AND table = {table_name:String}
            """,
            parameters={"table_name": table_name},
        )
    except Exception:
        return None
    try:
        value = result.result_rows[0][0]
    except (AttributeError, IndexError, TypeError):
        return None
    return int(value) if value is not None else None


def _identity_schema_state(client, table_name: str = "events") -> Dict[str, Any]:
    events_columns = _existing_columns(client, table_name)
    missing_columns = [column for column in IDENTITY_COLUMNS if column not in events_columns]
    return {
        "installed": not missing_columns,
        "missing_columns": missing_columns,
        "events_columns": events_columns,
    }


def _identity_version_counts(
    client,
    *,
    table_name: str = "events",
    case_id: Optional[int] = None,
    identity_schema: Optional[Dict[str, Any]] = None,
) -> Dict[str, Optional[int]]:
    identity_schema = identity_schema or _identity_schema_state(client, table_name=table_name)
    if "evidence_record_key" not in identity_schema["events_columns"]:
        return {
            "empty": None,
            "v1": None,
            "v2": None,
            "unknown": None,
            "metadata_invalid": None,
        }
    return {
        "empty": _count_empty_identity(client, table_name=table_name, case_id=case_id),
        "v1": _count_identity_prefix(client, LEGACY_V1_PREFIX, table_name=table_name, case_id=case_id),
        "v2": _count_valid_v2_identity(client, table_name=table_name, case_id=case_id),
        "unknown": _count_unknown_identity(client, table_name=table_name, case_id=case_id),
        "metadata_invalid": _count_invalid_identity_metadata(
            client,
            table_name=table_name,
            case_id=case_id,
            identity_schema=identity_schema,
        ),
    }


def _format_count(value: Optional[int]) -> str:
    return str(value) if value is not None else "unavailable"


def _format_bool(value: bool) -> str:
    return "true" if value else "false"


def _rewrite_required(
    counts: Dict[str, Optional[int]],
    *,
    scoped_rows: int,
    recompute_existing: bool,
) -> bool:
    if any(counts.get(name) is None for name in ("empty", "v1", "unknown", "metadata_invalid")):
        return scoped_rows > 0
    if recompute_existing:
        return scoped_rows > 0
    return (
        counts["empty"] > 0
        or counts["v1"] > 0
        or counts["unknown"] > 0
        or counts["metadata_invalid"] > 0
    )


def _print_preflight(
    client,
    *,
    case_id: Optional[int],
    recompute_existing: bool,
    total_rows: int,
    scoped_rows: int,
    counts: Dict[str, Optional[int]],
    identity_schema: Optional[Dict[str, Any]] = None,
) -> bool:
    identity_schema = identity_schema or _identity_schema_state(client)
    buffer_state = get_events_buffer_state(client)
    previous_exists = _table_exists(client, OLD_TABLE)
    shadow_exists = _table_exists(client, SHADOW_TABLE)
    events_bytes = _table_bytes(client, "events")
    rewrite_needed = _rewrite_required(
        counts,
        scoped_rows=scoped_rows,
        recompute_existing=recompute_existing,
    )

    print("- Evidence Identity migration preflight:")
    print(f"  total events rows: {total_rows}")
    print(f"  target case: {int(case_id) if case_id is not None else 'all cases'}")
    if case_id is not None:
        print(f"  scoped rows: {scoped_rows}")
        print("  rewrite scope: whole events table copy; identity mutation limited to target case")
    print(f"  Evidence Identity schema installed: {_format_bool(identity_schema['installed'])}")
    print(
        "  missing identity columns: "
        f"{', '.join(identity_schema['missing_columns']) if identity_schema['missing_columns'] else 'none'}"
    )
    print(f"  empty evidence keys: {_format_count(counts['empty'])}")
    print(f"  erk:v1 keys: {_format_count(counts['v1'])}")
    print(f"  erk:v2 keys: {_format_count(counts['v2'])}")
    print(f"  other/unknown evidence keys: {_format_count(counts['unknown'])}")
    print(f"  invalid v2 metadata rows: {_format_count(counts['metadata_invalid'])}")
    print(f"  evidence index present: {_format_bool(_has_identity_index(client))}")
    print(
        "  events_buffer: "
        f"exists={buffer_state['exists']} engine={buffer_state['engine'] or 'n/a'} "
        f"pending_rows={buffer_state['pending_rows']}"
    )
    print(f"  previous rollback table present: {_format_bool(previous_exists)}")
    print(f"  stale shadow table present: {_format_bool(shadow_exists)}")
    print(f"  recompute existing requested: {_format_bool(bool(recompute_existing))}")
    print(f"  rewrite necessary: {_format_bool(rewrite_needed)}")
    print(
        "  events table disk bytes: "
        f"{events_bytes if events_bytes is not None else 'unavailable'}"
    )
    if previous_exists and rewrite_needed:
        print("  rollback policy: existing previous table blocks a new rewrite by default")
    return rewrite_needed


def _print_dry_run_plan(
    client,
    *,
    case_id: Optional[int],
    recompute_existing: bool,
    batch_size: int,
    source_window_seconds: int,
    copy_workers: int,
    total_rows: int,
    scoped_rows: int,
    counts: Dict[str, Optional[int]],
    identity_schema: Optional[Dict[str, Any]] = None,
) -> bool:
    identity_schema = identity_schema or _identity_schema_state(client)
    schema_change_required = not identity_schema["installed"]
    index_required = "evidence_record_key" not in identity_schema["events_columns"] or not _has_identity_index(client)
    buffer_state = get_events_buffer_state(client)
    previous_exists = _table_exists(client, OLD_TABLE)
    shadow_exists = _table_exists(client, SHADOW_TABLE)
    case_partition_count = _count_case_partitions(client)
    migration_settings = migration_client_effective_settings()
    rewrite_needed = _rewrite_required(
        counts,
        scoped_rows=scoped_rows,
        recompute_existing=recompute_existing,
    )

    _print_preflight(
        client,
        case_id=case_id,
        recompute_existing=recompute_existing,
        total_rows=total_rows,
        scoped_rows=scoped_rows,
        counts=counts,
        identity_schema=identity_schema,
    )
    print("- Dry-run plan:")
    print(f"  schema change required: {_format_bool(schema_change_required)}")
    print(f"  evidence index required: {_format_bool(index_required)}")
    print(f"  buffer fencing required: {_format_bool(rewrite_needed and buffer_state['exists'])}")
    print(f"  stale shadow disposal required: {_format_bool(rewrite_needed and shadow_exists)}")
    print(f"  identity rewrite required: {_format_bool(rewrite_needed)}")
    print(f"  v1 keys to upgrade: {_format_count(counts['v1'])}")
    print(f"  empty keys to generate: {_format_count(counts['empty'])}")
    print(f"  unknown/malformed keys to repair: {_format_count(counts['unknown'])}")
    print(f"  v2 metadata rows to repair: {_format_count(counts['metadata_invalid'])}")
    print(f"  full table copy required: {_format_bool(rewrite_needed)}")
    print(f"  previous rollback table: {'present' if previous_exists else 'none'}")
    print(
        "  case partitions: "
        f"{case_partition_count if case_partition_count is not None else 'unavailable'}"
    )
    print(f"  migration max_threads: {migration_settings['max_threads']}")
    print(f"  migration max_block_size: {migration_settings['max_block_size']}")
    print(f"  migration max_execution_time: {migration_settings['max_execution_time']}")
    print(f"  migration max_memory_usage: {migration_settings['max_memory_usage'] or 'configured default'}")
    print(f"  migration send_receive_timeout: {migration_settings['send_receive_timeout']}")
    print(f"  Python insert batch size: {int(batch_size)}")
    print(f"  source window seconds: {int(source_window_seconds)}")
    print(f"  copy workers: {int(copy_workers)}")
    print(f"  full v2 recompute requested: {_format_bool(bool(recompute_existing))}")
    print("- Dry run only; no ClickHouse DDL or data writes were executed")
    return rewrite_needed


def _should_recompute_identity(
    row_map: Dict[str, Any],
    *,
    case_id: Optional[int],
    recompute_existing: bool,
) -> bool:
    if case_id is not None and int(row_map.get("case_id") or 0) != int(case_id):
        return False
    key = str(row_map.get("evidence_record_key") or "").strip()
    if not key:
        return True
    if key.startswith(LEGACY_V1_PREFIX):
        return True
    if not _is_valid_v2_evidence_key(key):
        return True
    return bool(recompute_existing)


def _is_valid_v2_evidence_key(value: Any) -> bool:
    return bool(re.fullmatch(VALID_V2_KEY_PATTERN, str(value or "").strip()))


def _has_invalid_identity_metadata(row_map: Dict[str, Any]) -> bool:
    key = str(row_map.get("evidence_record_key") or "").strip()
    if not _is_valid_v2_evidence_key(key):
        return False
    version = str(row_map.get("evidence_identity_version") or "").strip()
    quality = str(row_map.get("evidence_identity_quality") or "").strip()
    return version != EVIDENCE_IDENTITY_VERSION or quality not in VALID_QUALITY_VALUES


def _assert_rewrite_lease_active(rewrite_lease: Any) -> None:
    assert_active = rewrite_lease.get("assert_active") if isinstance(rewrite_lease, dict) else None
    if callable(assert_active):
        assert_active()


def _is_insert_transport_timeout(exc: Exception) -> bool:
    message = repr(exc)
    timeout_markers = (
        "TimeoutError",
        "timed out",
        "ProtocolError",
        "Connection aborted",
    )
    return any(marker in message for marker in timeout_markers)


def _insert_shadow_batch(client, rows: List[tuple], columns: List[str]) -> None:
    try:
        client.insert(SHADOW_TABLE, rows, column_names=columns)
    except Exception as exc:
        if len(rows) <= 1 or not _is_insert_transport_timeout(exc):
            raise
        midpoint = max(len(rows) // 2, 1)
        print(
            "- Shadow insert batch hit a transport timeout; "
            f"retrying as {midpoint:,} and {len(rows) - midpoint:,} row chunks"
        )
        _insert_shadow_batch(client, rows[:midpoint], columns)
        _insert_shadow_batch(client, rows[midpoint:], columns)


def _source_window_query(columns_sql: str) -> str:
    return (
        f"SELECT {columns_sql} FROM events "
        "WHERE case_id = {case_id:UInt32} "
        "AND timestamp_utc >= fromUnixTimestamp64Milli({window_start_ms:Int64}) "
        "AND timestamp_utc < fromUnixTimestamp64Milli({window_end_ms:Int64})"
    )


def _copy_source_window_to_shadow(
    client,
    *,
    columns: List[str],
    batch_size: int,
    current_case_id: int,
    window_start_ms: int,
    window_end_ms: int,
    target_case_id: Optional[int],
    recompute_existing: bool,
) -> Dict[str, int]:
    identity_indexes = {name: columns.index(name) for name in IDENTITY_COLUMNS}
    rows_buffer = []
    rewritten = 0
    copied = 0
    columns_sql = ", ".join(columns)
    with client.query_rows_stream(
        _source_window_query(columns_sql),
        parameters={
            "case_id": int(current_case_id),
            "window_start_ms": int(window_start_ms),
            "window_end_ms": int(window_end_ms),
        },
        settings=migration_source_query_settings(),
    ) as stream:
        for raw_row in stream:
            row = list(raw_row)
            row_map = _row_to_mapping(columns, row)
            if _should_recompute_identity(
                row_map,
                case_id=target_case_id,
                recompute_existing=recompute_existing,
            ):
                identity = build_identity_from_clickhouse_row(row_map)
                row[identity_indexes["evidence_record_key"]] = identity.evidence_record_key
                row[identity_indexes["evidence_identity_version"]] = identity.evidence_identity_version
                row[identity_indexes["evidence_identity_quality"]] = identity.evidence_identity_quality
                rewritten += 1
            elif (
                (target_case_id is None or int(row_map.get("case_id") or 0) == int(target_case_id))
                and _has_invalid_identity_metadata(row_map)
            ):
                identity = build_identity_from_clickhouse_row(row_map)
                row[identity_indexes["evidence_identity_version"]] = identity.evidence_identity_version
                row[identity_indexes["evidence_identity_quality"]] = identity.evidence_identity_quality
                rewritten += 1
            rows_buffer.append(tuple(row))
            copied += 1
            if len(rows_buffer) >= batch_size:
                _insert_shadow_batch(client, rows_buffer, columns)
                rows_buffer = []
    if rows_buffer:
        _insert_shadow_batch(client, rows_buffer, columns)
    return {
        "case_id": int(current_case_id),
        "window_start_ms": int(window_start_ms),
        "copied": copied,
        "rewritten": rewritten,
    }


def _copy_source_window_to_shadow_with_fresh_client(**kwargs) -> Dict[str, int]:
    client = get_migration_client()
    return _copy_source_window_to_shadow(client, **kwargs)


def _rewrite_rows_to_shadow(
    client,
    *,
    columns: List[str],
    batch_size: int,
    case_id: Optional[int],
    recompute_existing: bool,
    progress_interval: int = DEFAULT_PROGRESS_INTERVAL_ROWS,
    source_window_seconds: int = DEFAULT_SOURCE_WINDOW_SECONDS,
    copy_workers: int = DEFAULT_COPY_WORKERS,
    rewrite_lease: Any = None,
) -> int:
    copy_workers = max(int(copy_workers), 1)
    copied = 0
    rewritten = 0
    case_ids = _distinct_case_ids(client)
    total_rows = _count_events(client)
    started_at = time.monotonic()
    next_progress = max(int(progress_interval), 1)
    case_totals: Dict[int, int] = {}
    window_tasks = []
    print(
        f"- Starting bounded case streams for {len(case_ids)} case partitions "
        f"with {copy_workers} copy worker(s)"
    )
    for current_case_id in case_ids:
        source_windows = _case_source_windows(
            client,
            int(current_case_id),
            window_seconds=int(source_window_seconds),
        )
        case_totals[int(current_case_id)] = 0
        print(
            f"- case_id={current_case_id}: streaming {len(source_windows):,} "
            f"{int(source_window_seconds)}s source windows"
        )
        for window_start_ms, window_end_ms in source_windows:
            window_tasks.append(
                {
                    "columns": columns,
                    "batch_size": int(batch_size),
                    "current_case_id": int(current_case_id),
                    "window_start_ms": int(window_start_ms),
                    "window_end_ms": int(window_end_ms),
                    "target_case_id": case_id,
                    "recompute_existing": bool(recompute_existing),
                }
            )

    def apply_result(result: Dict[str, int]) -> None:
        nonlocal copied, rewritten, next_progress
        current_case_id = int(result["case_id"])
        copied += int(result["copied"])
        rewritten += int(result["rewritten"])
        case_totals[current_case_id] = case_totals.get(current_case_id, 0) + int(result["copied"])
        if copied >= next_progress:
            _assert_rewrite_lease_active(rewrite_lease)
            elapsed = max(time.monotonic() - started_at, 0.001)
            percent = (copied / total_rows * 100) if total_rows else 100.0
            print(
                f"- total={copied:,}/{total_rows:,} ({percent:.2f}%); "
                f"identities={rewritten:,}; elapsed={elapsed:.0f}s"
            )
            next_progress += max(int(progress_interval), 1)

    if copy_workers == 1:
        for task in window_tasks:
            _assert_rewrite_lease_active(rewrite_lease)
            apply_result(_copy_source_window_to_shadow(client, **task))
    else:
        with ThreadPoolExecutor(max_workers=copy_workers) as executor:
            task_iter = iter(window_tasks)
            futures = set()
            max_in_flight = max(copy_workers * 2, copy_workers)

            def submit_available() -> None:
                while len(futures) < max_in_flight:
                    try:
                        task = next(task_iter)
                    except StopIteration:
                        return
                    futures.add(
                        executor.submit(_copy_source_window_to_shadow_with_fresh_client, **task)
                    )

            submit_available()
            try:
                while futures:
                    for future in as_completed(futures):
                        futures.remove(future)
                        _assert_rewrite_lease_active(rewrite_lease)
                        apply_result(future.result())
                        submit_available()
                        break
            except Exception:
                for future in futures:
                    future.cancel()
                raise

    for current_case_id in case_ids:
        print(f"- Finished case_id={current_case_id}: {case_totals.get(int(current_case_id), 0):,} rows copied")
    print(f"- Finished shadow copy: {copied} rows copied; {rewritten} identities generated")
    return rewritten


def _prepare_shadow_table(client) -> None:
    if _table_exists(client, SHADOW_TABLE):
        client.command(f"DROP TABLE IF EXISTS {SHADOW_TABLE}")
        _verify_table_absent(client, SHADOW_TABLE)
        print(f"- Verified interrupted shadow table {SHADOW_TABLE} was discarded")
    client.command(f"CREATE TABLE {SHADOW_TABLE} AS events")
    _verify_table_exists_with_engine(client, SHADOW_TABLE)
    events_columns = _insertable_columns(client, "events")
    shadow_columns = _insertable_columns(client, SHADOW_TABLE)
    if events_columns != shadow_columns:
        raise RuntimeError(f"{SHADOW_TABLE} schema verification failed; columns differ from events")
    print(f"- Verified fresh shadow table {SHADOW_TABLE}")


def _swap_shadow_table(client) -> None:
    if _table_exists(client, OLD_TABLE):
        raise RuntimeError(
            f"{OLD_TABLE} already exists; validate/remove/archive it before swapping a new events table"
        )
    client.command(f"RENAME TABLE events TO {OLD_TABLE}, {SHADOW_TABLE} TO events")
    _verify_table_exists_with_engine(client, "events")
    _verify_table_exists_with_engine(client, OLD_TABLE)
    _verify_table_absent(client, SHADOW_TABLE)
    print(f"- Verified {SHADOW_TABLE} swap into events")


def _print_failure_recovery_state(client, *, reason: str, swap_completed: bool = False) -> None:
    print(f"- Evidence Identity migration aborted: {reason}")
    print(f"- Authoritative events table swapped: {_format_bool(bool(swap_completed))}")
    print("- Recovery state:")
    for table_name in ("events", "events_buffer", SHADOW_TABLE, OLD_TABLE):
        try:
            exists = _table_exists(client, table_name)
            engine = _table_engine(client, table_name) if exists else "n/a"
            rows = _count_events(client, table_name=table_name) if exists else "n/a"
        except Exception as exc:
            exists = f"unknown ({exc})"
            engine = "unknown"
            rows = "unknown"
        print(f"  {table_name}: exists={exists} engine={engine} rows={rows}")
    if swap_completed:
        print(
            "- Next operator action: keep event-producing services stopped and validate "
            "post-swap state before recreating or using events_buffer."
        )
    else:
        print(
            "- Next operator action: keep event-producing services stopped. Interrupted "
            "shadow may be discarded on the next migration run. Recreate events_buffer "
            "only after confirming a successful migration or intentionally aborting recovery."
        )


def _validate_final_identity_state(
    client,
    *,
    expected_rows: int,
    case_id: Optional[int],
    table_name: str = "events",
) -> Dict[str, Optional[int]]:
    identity_schema = _identity_schema_state(client, table_name=table_name)
    verify_identity_columns(client, table_name=table_name)
    counts = _identity_version_counts(
        client,
        table_name=table_name,
        case_id=case_id,
        identity_schema=identity_schema,
    )
    failures = []
    if counts["empty"] != 0:
        failures.append(f"empty={_format_count(counts['empty'])}")
    if counts["v1"] != 0:
        failures.append(f"v1={_format_count(counts['v1'])}")
    if counts["unknown"] != 0:
        failures.append(f"unknown={_format_count(counts['unknown'])}")
    if counts["metadata_invalid"] != 0:
        failures.append(f"metadata_invalid={_format_count(counts['metadata_invalid'])}")
    if counts["v2"] != int(expected_rows):
        failures.append(f"v2={_format_count(counts['v2'])} expected={int(expected_rows)}")
    if failures:
        raise RuntimeError(
            f"Final Evidence Identity validation failed on {table_name}: "
            + ", ".join(failures)
        )
    print(
        f"- Final validation complete on {table_name}: "
        f"empty=0 v1=0 unknown=0 metadata_invalid=0 v2={int(expected_rows)}"
    )
    return counts


def backfill_identity_columns(
    client,
    *,
    batch_size: int = DEFAULT_INSERT_BATCH_SIZE,
    source_window_seconds: int = DEFAULT_SOURCE_WINDOW_SECONDS,
    copy_workers: int = DEFAULT_COPY_WORKERS,
    case_id: Optional[int] = None,
    dry_run: bool = False,
    recompute_existing: bool = False,
    replace_previous: bool = False,
    materialize_index: bool = False,
) -> int:
    if dry_run:
        total_rows = _count_events(client)
        scoped_rows = _count_events(client, case_id=case_id)
        identity_schema = _identity_schema_state(client)
        counts = _identity_version_counts(client, case_id=case_id, identity_schema=identity_schema)
        _print_dry_run_plan(
            client,
            case_id=case_id,
            recompute_existing=recompute_existing,
            batch_size=batch_size,
            source_window_seconds=source_window_seconds,
            copy_workers=copy_workers,
            total_rows=total_rows,
            scoped_rows=scoped_rows,
            counts=counts,
            identity_schema=identity_schema,
        )
        return 0

    with destructive_event_rewrite_guard(
        "evidence_identity_v2_shadow_backfill",
        case_id=case_id,
        require_lock=True,
    ) as rewrite_lease:
        total_rows = _count_events(client)
        scoped_rows = _count_events(client, case_id=case_id)
        identity_schema = _identity_schema_state(client)
        counts = _identity_version_counts(client, case_id=case_id, identity_schema=identity_schema)
        rewrite_needed = _print_preflight(
            client,
            case_id=case_id,
            recompute_existing=recompute_existing,
            total_rows=total_rows,
            scoped_rows=scoped_rows,
            counts=counts,
            identity_schema=identity_schema,
        )
        _verify_events_buffer_safe_for_rewrite(client)
        if not rewrite_needed:
            add_identity_columns(client)
            ensure_identity_index(client, materialize=materialize_index)
            ensure_events_buffer_schema(client)
            _validate_final_identity_state(
                client,
                expected_rows=scoped_rows if case_id is not None else total_rows,
                case_id=case_id,
            )
            print("- No Evidence Identity migration work required")
            return 0
        if _table_exists(client, OLD_TABLE):
            if not replace_previous:
                raise RuntimeError(
                    f"{OLD_TABLE} already exists. Validate/remove/archive it before "
                    "running another full rewrite, or rerun with --replace-previous "
                    "after confirming the rollback copy is no longer needed."
                )
            client.command(f"DROP TABLE IF EXISTS {OLD_TABLE}")
            _verify_table_absent(client, OLD_TABLE)
            print(f"- Verified previous rollback table {OLD_TABLE} was replaced by explicit request")

        add_identity_columns(client)
        ensure_identity_index(client, materialize=materialize_index)
        identity_schema = _identity_schema_state(client)
        counts = _identity_version_counts(client, case_id=case_id, identity_schema=identity_schema)
        rewrite_needed = _rewrite_required(
            counts,
            scoped_rows=scoped_rows,
            recompute_existing=recompute_existing,
        )
        if not rewrite_needed:
            ensure_events_buffer_schema(client)
            _validate_final_identity_state(
                client,
                expected_rows=scoped_rows if case_id is not None else total_rows,
                case_id=case_id,
            )
            print("- No Evidence Identity migration work required after schema convergence")
            return 0

        columns = _insertable_columns(client, "events")
        missing_insert_columns = [column for column in ParsedEvent.clickhouse_columns() if column not in columns]
        if missing_insert_columns:
            raise RuntimeError(f"events table is missing parser insert columns: {missing_insert_columns}")

        swap_completed = False
        try:
            _assert_rewrite_lease_active(rewrite_lease)
            if _table_exists(client, "events_buffer"):
                fence_events_buffer_ingestion(client, context="evidence identity snapshot")
            else:
                print("- events_buffer already absent; ingestion remains fenced")
            _verify_table_absent(client, "events_buffer")
            source_count_before_copy = _count_events(client)
            print(f"- Authoritative events source count after Buffer fence: {source_count_before_copy}")

            _prepare_shadow_table(client)
            rewritten = _rewrite_rows_to_shadow(
                client,
                columns=columns,
                batch_size=int(batch_size),
                source_window_seconds=int(source_window_seconds),
                copy_workers=int(copy_workers),
                case_id=case_id,
                recompute_existing=bool(recompute_existing),
                rewrite_lease=rewrite_lease,
            )

            shadow_rows = _count_events(client, table_name=SHADOW_TABLE)
            if shadow_rows != source_count_before_copy:
                raise RuntimeError(
                    "Shadow row count mismatch: "
                    f"events_before_copy={source_count_before_copy}, "
                    f"{SHADOW_TABLE}={shadow_rows}"
                )
            _validate_final_identity_state(
                client,
                table_name=SHADOW_TABLE,
                expected_rows=scoped_rows if case_id is not None else source_count_before_copy,
                case_id=case_id,
            )
            current_original_source_count = _count_events(client)
            if current_original_source_count != source_count_before_copy:
                raise RuntimeError(
                    "Source events row count changed during shadow rewrite: "
                    f"before_copy={source_count_before_copy}, "
                    f"before_swap={current_original_source_count}"
                )

            _assert_rewrite_lease_active(rewrite_lease)
            _swap_shadow_table(client)
            swap_completed = True
            ensure_identity_index(client, materialize=materialize_index)
            _recreate_and_verify_events_buffer(client)
            _validate_final_identity_state(
                client,
                expected_rows=scoped_rows if case_id is not None else source_count_before_copy,
                case_id=case_id,
            )
        except Exception as exc:
            _print_failure_recovery_state(client, reason=str(exc), swap_completed=swap_completed)
            raise
        if not swap_completed:
            raise RuntimeError("Evidence Identity migration ended before swap completed")
        return rewritten


def print_status(client, *, case_id: Optional[int] = None) -> None:
    print(f"- events table present: {_format_bool(_table_exists(client, 'events'))}")
    print(f"- events rows: {_count_events(client)}")
    if case_id is not None:
        print(f"- events rows for case {int(case_id)}: {_count_events(client, case_id=case_id)}")
    identity_schema = _identity_schema_state(client)
    counts = _identity_version_counts(client, case_id=case_id, identity_schema=identity_schema)
    print(f"- Evidence Identity schema installed: {_format_bool(identity_schema['installed'])}")
    print(
        "- missing identity columns: "
        f"{', '.join(identity_schema['missing_columns']) if identity_schema['missing_columns'] else 'none'}"
    )
    print(f"- empty evidence_record_key rows: {_format_count(counts['empty'])}")
    print(f"- erk:v1 evidence_record_key rows: {_format_count(counts['v1'])}")
    print(f"- erk:v2 evidence_record_key rows: {_format_count(counts['v2'])}")
    print(f"- other/unknown evidence_record_key rows: {_format_count(counts['unknown'])}")
    print(f"- invalid v2 identity metadata rows: {_format_count(counts['metadata_invalid'])}")
    print(f"- shadow table present: {_format_bool(_table_exists(client, SHADOW_TABLE))}")
    print(f"- previous table present: {_format_bool(_table_exists(client, OLD_TABLE))}")
    print(f"- {IDENTITY_INDEX_NAME} present: {_format_bool(_has_identity_index(client))}")
    buffer_state = get_events_buffer_state(client)
    print(
        "- events_buffer state: "
        f"exists={buffer_state['exists']} engine={buffer_state['engine'] or 'n/a'} "
        f"pending_rows={buffer_state['pending_rows']}"
    )


def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Add and backfill Evidence Identity v2")
    parser.add_argument("--dry-run", action="store_true", help="show counts without rewriting events")
    parser.add_argument("--status", action="store_true", help="show migration/backfill status only")
    parser.add_argument(
        "--case-id",
        type=int,
        default=None,
        help="limit identity mutation scope to one case; the current migration still copies the full events table",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_INSERT_BATCH_SIZE,
        help="rows per shadow-table insert batch",
    )
    parser.add_argument(
        "--source-window-seconds",
        type=int,
        default=DEFAULT_SOURCE_WINDOW_SECONDS,
        help="seconds per case-scoped source stream window",
    )
    parser.add_argument(
        "--copy-workers",
        type=int,
        default=DEFAULT_COPY_WORKERS,
        help="parallel source-window copy workers; one coordinator still owns swap and validation",
    )
    parser.add_argument(
        "--recompute-existing",
        action="store_true",
        help="recompute existing evidence identities in scope and write v2 keys",
    )
    parser.add_argument(
        "--replace-previous",
        action="store_true",
        help="deliberately drop events_evidence_identity_previous before a new full rewrite",
    )
    parser.add_argument(
        "--materialize-index",
        action="store_true",
        help="materialize the evidence_record_key skipping index immediately after adding it",
    )
    return parser.parse_args(argv)


def migrate(argv: Optional[List[str]] = None) -> None:
    print("=" * 60)
    print("Evidence Identity v2 Migration")
    print("=" * 60)
    args = _parse_args(argv)
    client = get_migration_client()
    if args.status:
        print_status(client, case_id=args.case_id)
        return
    if args.dry_run:
        backfill_identity_columns(
            client,
            batch_size=args.batch_size,
            source_window_seconds=args.source_window_seconds,
            copy_workers=args.copy_workers,
            case_id=args.case_id,
            dry_run=True,
            recompute_existing=args.recompute_existing,
            replace_previous=args.replace_previous,
            materialize_index=args.materialize_index,
        )
        print("Dry run complete")
        return
    total = backfill_identity_columns(
        client,
        batch_size=args.batch_size,
        source_window_seconds=args.source_window_seconds,
        copy_workers=args.copy_workers,
        case_id=args.case_id,
        dry_run=args.dry_run,
        recompute_existing=args.recompute_existing,
        replace_previous=args.replace_previous,
        materialize_index=args.materialize_index,
    )
    if args.dry_run:
        print("Dry run complete")
    else:
        print(f"Backfill complete: {total} event identities generated")


if __name__ == "__main__":
    migrate()
