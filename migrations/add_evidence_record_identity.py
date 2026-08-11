#!/usr/bin/env python3
"""Migration: add and backfill Evidence Identity v1 for ClickHouse events."""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any, Dict, Iterable, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from migrations.add_events_table import EVENTS_BUFFER_SCHEMA, EVENTS_COLUMN_DEFINITIONS  # noqa: E402
from parsers.base import ParsedEvent  # noqa: E402
from utils.clickhouse import destructive_event_rewrite_guard, get_fresh_client  # noqa: E402
from utils.evidence_identity import build_identity_from_clickhouse_row  # noqa: E402


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
        client.command(EVENTS_BUFFER_SCHEMA)
        print("- Created events_buffer table")
        return

    events_columns = set(_insertable_columns(client, "events"))
    buffer_columns = set(_insertable_columns(client, "events_buffer"))
    if events_columns == buffer_columns:
        return

    if _table_engine(client, "events_buffer").lower() == "buffer":
        client.command("DROP TABLE IF EXISTS events_buffer")
        client.command(EVENTS_BUFFER_SCHEMA)
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


def _should_recompute_identity(
    row_map: Dict[str, Any],
    *,
    case_id: Optional[int],
    recompute_existing: bool,
) -> bool:
    if not str(row_map.get("evidence_record_key") or "").strip():
        return True
    if not recompute_existing:
        return False
    return case_id is None or int(row_map.get("case_id") or 0) == int(case_id)


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
        client.command(f"DROP TABLE {OLD_TABLE}")
    client.command("DROP TABLE IF EXISTS events_buffer")
    client.command(f"RENAME TABLE events TO {OLD_TABLE}, {SHADOW_TABLE} TO events")
    client.command(EVENTS_BUFFER_SCHEMA)
    print(f"- Swapped {SHADOW_TABLE} into events and recreated events_buffer")


def backfill_identity_columns(
    client,
    *,
    batch_size: int = 10000,
    case_id: Optional[int] = None,
    dry_run: bool = False,
    recompute_existing: bool = False,
) -> int:
    total_rows = _count_events(client)
    scoped_rows = _count_events(client, case_id=case_id)
    empty_rows = _count_empty_identity(client, case_id=case_id)
    print(
        f"- events rows: {total_rows}; scoped rows: {scoped_rows}; "
        f"empty identity rows in scope: {empty_rows}"
    )
    if dry_run:
        print("- Dry run only; no ClickHouse tables were rewritten")
        return 0

    columns = _insertable_columns(client, "events")
    missing_insert_columns = [column for column in ParsedEvent.clickhouse_columns() if column not in columns]
    if missing_insert_columns:
        raise RuntimeError(f"events table is missing parser insert columns: {missing_insert_columns}")

    with destructive_event_rewrite_guard(
        "evidence_identity_v1_shadow_backfill",
        case_id=case_id,
    ):
        _prepare_shadow_table(client)
        rewritten = _rewrite_rows_to_shadow(
            client,
            columns=columns,
            batch_size=int(batch_size),
            case_id=case_id,
            recompute_existing=bool(recompute_existing),
        )

        shadow_rows = _count_events(client, table_name=SHADOW_TABLE)
        if shadow_rows != total_rows:
            client.command(f"DROP TABLE IF EXISTS {SHADOW_TABLE}")
            raise RuntimeError(
                f"Shadow row count mismatch: events={total_rows}, {SHADOW_TABLE}={shadow_rows}"
            )

        _swap_shadow_table(client)
        ensure_identity_index(client, materialize=True)
        remaining_empty = _count_empty_identity(client, case_id=case_id)
        print(f"- Validation complete: {remaining_empty} empty identity keys remain in scope")
        return rewritten


def print_status(client, *, case_id: Optional[int] = None) -> None:
    print(f"- events rows: {_count_events(client)}")
    if case_id is not None:
        print(f"- events rows for case {int(case_id)}: {_count_events(client, case_id=case_id)}")
    print(f"- empty evidence_record_key rows: {_count_empty_identity(client, case_id=case_id)}")
    print(f"- shadow table present: {_table_exists(client, SHADOW_TABLE)}")
    print(f"- previous table present: {_table_exists(client, OLD_TABLE)}")
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
    has_index = bool(result.result_rows and result.result_rows[0][0])
    print(f"- {IDENTITY_INDEX_NAME} present: {has_index}")


def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Add and backfill Evidence Identity v1")
    parser.add_argument("--dry-run", action="store_true", help="show counts without rewriting events")
    parser.add_argument("--status", action="store_true", help="show migration/backfill status only")
    parser.add_argument("--case-id", type=int, default=None, help="limit identity generation scope to one case")
    parser.add_argument("--batch-size", type=int, default=10000, help="rows per shadow-table insert batch")
    parser.add_argument(
        "--recompute-existing",
        action="store_true",
        help="recompute existing evidence identities in scope, useful for repairing 4.12.5 identities",
    )
    parser.add_argument(
        "--materialize-index",
        action="store_true",
        help="materialize the evidence_record_key skipping index immediately after adding it",
    )
    return parser.parse_args(argv)


def migrate(argv: Optional[List[str]] = None) -> None:
    print("=" * 60)
    print("Evidence Identity v1 Migration")
    print("=" * 60)
    args = _parse_args(argv)
    client = get_fresh_client()
    if args.status:
        print_status(client, case_id=args.case_id)
        return
    add_identity_columns(client)
    ensure_identity_index(client, materialize=args.materialize_index)
    total = backfill_identity_columns(
        client,
        batch_size=args.batch_size,
        case_id=args.case_id,
        dry_run=args.dry_run,
        recompute_existing=args.recompute_existing,
    )
    if args.dry_run:
        print("Dry run complete")
    else:
        print(f"Backfill complete: {total} event identities generated")


if __name__ == "__main__":
    migrate()
