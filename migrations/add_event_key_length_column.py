#!/usr/bin/env python3
"""Migration: add typed Windows logon KeyLength to ClickHouse events."""

from __future__ import annotations

import os
import sys
from typing import Any, Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.clickhouse import get_migration_client  # noqa: E402


EVENTS_TABLE = "events"
KEY_LENGTH_COLUMN = "key_length"
KEY_LENGTH_DEFINITION = "Nullable(UInt16)"


def _column_exists(client: Any, table_name: str, column_name: str) -> bool:
    result = client.query(
        """
        SELECT count()
        FROM system.columns
        WHERE database = currentDatabase()
          AND table = {table_name:String}
          AND name = {column_name:String}
        """,
        parameters={"table_name": table_name, "column_name": column_name},
    )
    return bool(result.result_rows and result.result_rows[0][0])


def add_key_length_column(client: Any = None) -> Dict[str, Any]:
    """Add key_length without backfilling or rewriting historical rows."""
    client = client or get_migration_client()
    before_exists = _column_exists(client, EVENTS_TABLE, KEY_LENGTH_COLUMN)
    sql = (
        f"ALTER TABLE {EVENTS_TABLE} "
        f"ADD COLUMN IF NOT EXISTS {KEY_LENGTH_COLUMN} {KEY_LENGTH_DEFINITION} "
        "AFTER logon_process"
    )
    client.command(sql)
    after_exists = _column_exists(client, EVENTS_TABLE, KEY_LENGTH_COLUMN)
    return {
        "success": after_exists,
        "changed": not before_exists and after_exists,
        "table": EVENTS_TABLE,
        "column": KEY_LENGTH_COLUMN,
        "definition": KEY_LENGTH_DEFINITION,
        "sql": sql,
        "backfill_performed": False,
    }


def main() -> None:
    result = add_key_length_column()
    print(result)


if __name__ == "__main__":
    main()
