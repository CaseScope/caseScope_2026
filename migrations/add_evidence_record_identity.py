#!/usr/bin/env python3
"""Migration: add and backfill Evidence Identity v1 for ClickHouse events."""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, Iterable

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from migrations.add_events_table import EVENTS_COLUMN_DEFINITIONS  # noqa: E402
from parsers.base import ParsedEvent  # noqa: E402
from utils.clickhouse import clickhouse_string_literal, get_fresh_client  # noqa: E402
from utils.evidence_identity import build_identity_from_clickhouse_row  # noqa: E402


BACKFILL_COLUMNS = [
    column
    for column in ParsedEvent.clickhouse_columns()
    if column not in {"evidence_record_key", "evidence_identity_version", "evidence_identity_quality"}
]
BACKFILL_SELECT_COLUMNS = [*BACKFILL_COLUMNS, "selector_key"]
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


def add_identity_columns(client) -> None:
    for table_name in ("events", "events_buffer"):
        existing = _existing_columns(client, table_name)
        if not existing:
            continue
        for column_name in (
            "evidence_record_key",
            "evidence_identity_version",
            "evidence_identity_quality",
        ):
            if column_name in existing:
                continue
            definition = EVENTS_COLUMN_DEFINITIONS[column_name]
            client.command(
                f"ALTER TABLE {table_name} ADD COLUMN IF NOT EXISTS {column_name} {definition}"
            )
            print(f"- Added {column_name} to {table_name}")


def _row_to_mapping(row: Iterable[Any]) -> Dict[str, Any]:
    return dict(zip(BACKFILL_SELECT_COLUMNS, row))


def _row_scope_predicate(row: Dict[str, Any]) -> str:
    """Build a conservative predicate for idempotent legacy row updates."""

    predicates = [
        f"case_id = {int(row.get('case_id') or 0)}",
        "evidence_record_key = ''",
    ]
    for column_name in ("selector_key", "source_file", "source_path", "source_host", "raw_json"):
        predicates.append(
            f"{column_name} = {clickhouse_string_literal(row.get(column_name) or '')}"
        )
    return " AND ".join(predicates)


def backfill_identity_columns(client, *, batch_size: int = 1000) -> int:
    total = 0
    columns_sql = ", ".join(BACKFILL_SELECT_COLUMNS)
    while True:
        result = client.query(
            f"""
            SELECT {columns_sql}
            FROM events
            WHERE evidence_record_key = ''
            LIMIT {{batch_size:UInt32}}
            """,
            parameters={"batch_size": int(batch_size)},
        )
        rows = list(result.result_rows or [])
        if not rows:
            break

        for raw_row in rows:
            row = _row_to_mapping(raw_row)
            identity = build_identity_from_clickhouse_row(row)
            assignments = ", ".join(
                [
                    f"evidence_record_key = {clickhouse_string_literal(identity.evidence_record_key)}",
                    f"evidence_identity_version = {clickhouse_string_literal(identity.evidence_identity_version)}",
                    f"evidence_identity_quality = {clickhouse_string_literal(identity.evidence_identity_quality)}",
                ]
            )
            client.command(
                f"ALTER TABLE events UPDATE {assignments} WHERE {_row_scope_predicate(row)}"
                " SETTINGS mutations_sync = 1"
            )
            total += 1

        print(f"- Backfilled {total} event identity row scopes")

    return total


def migrate() -> None:
    print("=" * 60)
    print("Evidence Identity v1 Migration")
    print("=" * 60)
    client = get_fresh_client()
    add_identity_columns(client)
    total = backfill_identity_columns(client)
    print(f"Backfill complete: {total} row scopes updated")


if __name__ == "__main__":
    migrate()
