#!/usr/bin/env python3
"""Migration: add and backfill Evidence Identity v2 for ClickHouse events."""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any, Dict, Iterable, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from migrations.add_events_table import (  # noqa: E402
    EVENTS_COLUMN_DEFINITIONS,
    fence_events_buffer_ingestion,
    get_events_buffer_state,
    recreate_events_buffer,
)
from parsers.base import ParsedEvent  # noqa: E402
from utils.clickhouse import destructive_event_rewrite_guard, get_fresh_client  # noqa: E402
from utils.evidence_identity import (  # noqa: E402
    EVIDENCE_RECORD_KEY_PREFIX,
    build_identity_from_clickhouse_row,
)


IDENTITY_COLUMNS = (
    "evidence_record_key",
    "evidence_identity_version",
    "evidence_identity_quality",
)
IDENTITY_INDEX_NAME = "idx_evidence_record_key"
IDENTITY_INDEX_DEFINITION = (
    "INDEX idx_evidence_record_key evidence_record_key TYPE bloom_filter(0.01) GRANULARITY 4"
)
SHADOW_TABLE = "events_evidence_identity_backfill"
OLD_TABLE = "events_evidence_identity_previous"
LEGACY_V1_PREFIX = "erk:v1:"


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


def add_identity_columns(client) -> None:
    existing = _existing_columns(client, "events")
    if existing:
        for column_name in IDENTITY_COLUMNS:
            if column_name in existing:
                continue
            definition = EVENTS_COLUMN_DEFINITIONS[column_name]
            client.command(
                f"ALTER TABLE events ADD COLUMN IF NOT EXISTS {column_name} {definition}"
            )
            print(f"- Added {column_name} to events")
    ensure_events_buffer_schema(client)


def ensure_identity_index(client, *, materialize: bool = False) -> bool:
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
        return False
    client.command(f"ALTER TABLE events ADD INDEX IF NOT EXISTS {IDENTITY_INDEX_DEFINITION}")
    print("- Added idx_evidence_record_key to events")
    if materialize:
        client.command(f"ALTER TABLE events MATERIALIZE INDEX {IDENTITY_INDEX_NAME}")
        print("- Materialized idx_evidence_record_key on events")
    return True


def ensure_events_buffer_schema(client) -> None:
    if not _table_exists(client, "events"):
        return
    if not _table_exists(client, "events_buffer"):
        recreate_events_buffer(client)
        return

    events_columns = set(_insertable_columns(client, "events"))
    buffer_columns = set(_insertable_columns(client, "events_buffer"))
    if events_columns == buffer_columns:
        return

    if _table_engine(client, "events_buffer").lower() == "buffer":
        fence_events_buffer_ingestion(client, context="events_buffer schema recreation")
        recreate_events_buffer(client)
        print("- Recreated events_buffer to match events schema")
        return

    for column_name in sorted(events_columns - buffer_columns):
        definition = EVENTS_COLUMN_DEFINITIONS.get(column_name)
        if definition:
            client.command(
                f"ALTER TABLE events_buffer ADD COLUMN IF NOT EXISTS {column_name} {definition}"
            )
            print(f"- Added {column_name} to events_buffer")


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


def _count_unknown_identity(
    client,
    *,
    table_name: str = "events",
    case_id: Optional[int] = None,
) -> int:
    where = (
        "WHERE evidence_record_key != '' "
        "AND NOT startsWith(evidence_record_key, {v1_prefix:String}) "
        "AND NOT startsWith(evidence_record_key, {v2_prefix:String})"
    )
    parameters: Dict[str, Any] = {
        "v1_prefix": LEGACY_V1_PREFIX,
        "v2_prefix": EVIDENCE_RECORD_KEY_PREFIX,
    }
    if case_id is not None:
        where += " AND case_id = {case_id:UInt32}"
        parameters["case_id"] = int(case_id)
    result = client.query(f"SELECT count() FROM {table_name} {where}", parameters=parameters)
    return int(result.result_rows[0][0]) if result.result_rows else 0


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


def _identity_version_counts(client, *, case_id: Optional[int] = None) -> Dict[str, int]:
    return {
        "empty": _count_empty_identity(client, case_id=case_id),
        "v1": _count_identity_prefix(client, LEGACY_V1_PREFIX, case_id=case_id),
        "v2": _count_identity_prefix(client, EVIDENCE_RECORD_KEY_PREFIX, case_id=case_id),
        "unknown": _count_unknown_identity(client, case_id=case_id),
    }


def _rewrite_required(counts: Dict[str, int], *, scoped_rows: int, recompute_existing: bool) -> bool:
    if recompute_existing:
        return scoped_rows > 0
    return counts["empty"] > 0 or counts["v1"] > 0


def _print_preflight(
    client,
    *,
    case_id: Optional[int],
    recompute_existing: bool,
    total_rows: int,
    scoped_rows: int,
    counts: Dict[str, int],
) -> bool:
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
    print(f"  empty evidence keys: {counts['empty']}")
    print(f"  erk:v1 keys: {counts['v1']}")
    print(f"  erk:v2 keys: {counts['v2']}")
    print(f"  other/unknown evidence keys: {counts['unknown']}")
    print(f"  evidence index present: {_has_identity_index(client)}")
    print(
        "  events_buffer: "
        f"exists={buffer_state['exists']} engine={buffer_state['engine'] or 'n/a'} "
        f"pending_rows={buffer_state['pending_rows']}"
    )
    print(f"  previous rollback table present: {previous_exists}")
    print(f"  stale shadow table present: {shadow_exists}")
    print(f"  recompute existing requested: {bool(recompute_existing)}")
    print(f"  rewrite necessary: {rewrite_needed}")
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
    total_rows: int,
    scoped_rows: int,
    counts: Dict[str, int],
) -> bool:
    events_columns = _existing_columns(client, "events")
    schema_change_required = any(column not in events_columns for column in IDENTITY_COLUMNS)
    index_required = not _has_identity_index(client)
    buffer_state = get_events_buffer_state(client)
    previous_exists = _table_exists(client, OLD_TABLE)
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
    )
    print("- Dry-run plan:")
    print(f"  schema change required: {schema_change_required}")
    print(f"  evidence index required: {index_required}")
    print(f"  buffer fencing required: {rewrite_needed and buffer_state['exists']}")
    print(f"  identity rewrite required: {rewrite_needed}")
    print(f"  v1 keys to upgrade: {counts['v1']}")
    print(f"  empty keys to generate: {counts['empty']}")
    print(f"  full table copy required: {rewrite_needed}")
    print(f"  previous rollback table: {'present' if previous_exists else 'none'}")
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
    if not str(row_map.get("evidence_record_key") or "").strip():
        return True
    if str(row_map.get("evidence_record_key") or "").startswith(LEGACY_V1_PREFIX):
        return True
    return bool(recompute_existing)


def _rewrite_rows_to_shadow(
    client,
    *,
    columns: List[str],
    batch_size: int,
    case_id: Optional[int],
    recompute_existing: bool,
) -> int:
    identity_indexes = {name: columns.index(name) for name in IDENTITY_COLUMNS}
    rows_buffer = []
    rewritten = 0
    copied = 0
    columns_sql = ", ".join(columns)
    query = f"SELECT {columns_sql} FROM events ORDER BY case_id, timestamp_utc, artifact_type"
    with client.query_rows_stream(query) as stream:
        for raw_row in stream:
            row = list(raw_row)
            row_map = _row_to_mapping(columns, row)
            if _should_recompute_identity(
                row_map,
                case_id=case_id,
                recompute_existing=recompute_existing,
            ):
                identity = build_identity_from_clickhouse_row(row_map)
                row[identity_indexes["evidence_record_key"]] = identity.evidence_record_key
                row[identity_indexes["evidence_identity_version"]] = identity.evidence_identity_version
                row[identity_indexes["evidence_identity_quality"]] = identity.evidence_identity_quality
                rewritten += 1
            rows_buffer.append(tuple(row))
            copied += 1
            if len(rows_buffer) >= batch_size:
                client.insert(SHADOW_TABLE, rows_buffer, column_names=columns)
                rows_buffer = []
                print(f"- Copied {copied} rows to {SHADOW_TABLE}; generated {rewritten} identities")
        if rows_buffer:
            client.insert(SHADOW_TABLE, rows_buffer, column_names=columns)
    print(f"- Finished shadow copy: {copied} rows copied; {rewritten} identities generated")
    return rewritten


def _prepare_shadow_table(client) -> None:
    if _table_exists(client, SHADOW_TABLE):
        client.command(f"DROP TABLE {SHADOW_TABLE}")
        print(f"- Dropped interrupted shadow table {SHADOW_TABLE}")
    client.command(f"CREATE TABLE {SHADOW_TABLE} AS events")
    print(f"- Created shadow table {SHADOW_TABLE}")


def _swap_shadow_table(client) -> None:
    if _table_exists(client, OLD_TABLE):
        raise RuntimeError(
            f"{OLD_TABLE} already exists; validate/remove/archive it before swapping a new events table"
        )
    client.command(f"RENAME TABLE events TO {OLD_TABLE}, {SHADOW_TABLE} TO events")
    recreate_events_buffer(client)
    print(f"- Swapped {SHADOW_TABLE} into events and recreated events_buffer")


def _print_failure_recovery_state(client, *, reason: str) -> None:
    print(f"- Evidence Identity migration aborted: {reason}")
    print("- Recovery state:")
    for table_name in ("events", "events_buffer", SHADOW_TABLE, OLD_TABLE):
        try:
            exists = _table_exists(client, table_name)
            engine = _table_engine(client, table_name) if exists else "n/a"
        except Exception as exc:
            exists = f"unknown ({exc})"
            engine = "unknown"
        print(f"  {table_name}: exists={exists} engine={engine}")
    print(
        "- Next operator action: keep event-producing services stopped, validate "
        "the table state above, then rerun the migration or recreate events_buffer "
        "only after confirming events is the intended active table."
    )


def backfill_identity_columns(
    client,
    *,
    batch_size: int = 10000,
    case_id: Optional[int] = None,
    dry_run: bool = False,
    recompute_existing: bool = False,
    replace_previous: bool = False,
) -> int:
    if dry_run:
        total_rows = _count_events(client)
        scoped_rows = _count_events(client, case_id=case_id)
        counts = _identity_version_counts(client, case_id=case_id)
        _print_dry_run_plan(
            client,
            case_id=case_id,
            recompute_existing=recompute_existing,
            total_rows=total_rows,
            scoped_rows=scoped_rows,
            counts=counts,
        )
        return 0

    columns = _insertable_columns(client, "events")
    missing_insert_columns = [column for column in ParsedEvent.clickhouse_columns() if column not in columns]
    if missing_insert_columns:
        raise RuntimeError(f"events table is missing parser insert columns: {missing_insert_columns}")

    with destructive_event_rewrite_guard(
        "evidence_identity_v2_shadow_backfill",
        case_id=case_id,
    ):
        total_rows = _count_events(client)
        scoped_rows = _count_events(client, case_id=case_id)
        counts = _identity_version_counts(client, case_id=case_id)
        rewrite_needed = _print_preflight(
            client,
            case_id=case_id,
            recompute_existing=recompute_existing,
            total_rows=total_rows,
            scoped_rows=scoped_rows,
            counts=counts,
        )
        if not rewrite_needed:
            print("- No Evidence Identity migration work required")
            return 0
        if _table_exists(client, OLD_TABLE):
            if not replace_previous:
                raise RuntimeError(
                    f"{OLD_TABLE} already exists. Validate/remove/archive it before "
                    "running another full rewrite, or rerun with --replace-previous "
                    "after confirming the rollback copy is no longer needed."
                )
            client.command(f"DROP TABLE {OLD_TABLE}")
            print(f"- Dropped previous rollback table {OLD_TABLE} by explicit request")

        try:
            fence_events_buffer_ingestion(client, context="evidence identity snapshot")
            source_count_before_copy = _count_events(client)
            print(f"- Authoritative events source count after Buffer fence: {source_count_before_copy}")

            _prepare_shadow_table(client)
            rewritten = _rewrite_rows_to_shadow(
                client,
                columns=columns,
                batch_size=int(batch_size),
                case_id=case_id,
                recompute_existing=bool(recompute_existing),
            )

            shadow_rows = _count_events(client, table_name=SHADOW_TABLE)
            current_original_source_count = _count_events(client)
            if shadow_rows != source_count_before_copy:
                client.command(f"DROP TABLE IF EXISTS {SHADOW_TABLE}")
                raise RuntimeError(
                    "Shadow row count mismatch: "
                    f"events_before_copy={source_count_before_copy}, "
                    f"{SHADOW_TABLE}={shadow_rows}"
                )
            if current_original_source_count != source_count_before_copy:
                client.command(f"DROP TABLE IF EXISTS {SHADOW_TABLE}")
                raise RuntimeError(
                    "Source events row count changed during shadow rewrite: "
                    f"before_copy={source_count_before_copy}, "
                    f"before_swap={current_original_source_count}"
                )

            _swap_shadow_table(client)
        except Exception as exc:
            _print_failure_recovery_state(client, reason=str(exc))
            raise
        ensure_identity_index(client, materialize=True)
        remaining_empty = _count_empty_identity(client, case_id=case_id)
        print(f"- Validation complete: {remaining_empty} empty identity keys remain in scope")
        return rewritten


def print_status(client, *, case_id: Optional[int] = None) -> None:
    print(f"- events rows: {_count_events(client)}")
    if case_id is not None:
        print(f"- events rows for case {int(case_id)}: {_count_events(client, case_id=case_id)}")
    counts = _identity_version_counts(client, case_id=case_id)
    print(f"- empty evidence_record_key rows: {counts['empty']}")
    print(f"- erk:v1 evidence_record_key rows: {counts['v1']}")
    print(f"- erk:v2 evidence_record_key rows: {counts['v2']}")
    print(f"- other/unknown evidence_record_key rows: {counts['unknown']}")
    print(f"- shadow table present: {_table_exists(client, SHADOW_TABLE)}")
    print(f"- previous table present: {_table_exists(client, OLD_TABLE)}")
    print(f"- {IDENTITY_INDEX_NAME} present: {_has_identity_index(client)}")
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
    parser.add_argument("--batch-size", type=int, default=10000, help="rows per shadow-table insert batch")
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
    client = get_fresh_client()
    if args.status:
        print_status(client, case_id=args.case_id)
        return
    if args.dry_run:
        backfill_identity_columns(
            client,
            batch_size=args.batch_size,
            case_id=args.case_id,
            dry_run=True,
            recompute_existing=args.recompute_existing,
            replace_previous=args.replace_previous,
        )
        print("Dry run complete")
        return
    add_identity_columns(client)
    ensure_identity_index(client, materialize=args.materialize_index)
    total = backfill_identity_columns(
        client,
        batch_size=args.batch_size,
        case_id=args.case_id,
        dry_run=args.dry_run,
        recompute_existing=args.recompute_existing,
        replace_previous=args.replace_previous,
    )
    if args.dry_run:
        print("Dry run complete")
    else:
        print(f"Backfill complete: {total} event identities generated")


if __name__ == "__main__":
    migrate()
