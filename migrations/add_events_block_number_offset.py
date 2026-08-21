#!/usr/bin/env python3
"""Enable MergeTree block-number/offset columns for later lightweight UPDATE.

The locked Phase 2 Gate B requirement is:

    enable_block_number_column = 1
    enable_block_offset_column = 1

Fresh CREATE TABLE events (see EVENTS_SCHEMA) already sets both. This migration
is the upgrade path for existing tables via:

    ALTER TABLE events MODIFY SETTING
        enable_block_number_column = 1,
        enable_block_offset_column = 1

Measured on ClickHouse 26.7: this ALTER is metadata, keeps existing parts, and
makes virtual ``_block_number`` / ``_block_offset`` readable on already-inserted
rows without rewriting forensic columns.

This migration:

- is idempotent
- does not run SQL UPDATE / ALTER UPDATE
- does not change product callers
- is NOT invoked from application startup
- refuses the production ``casescope`` database unless ``--apply-production``
"""
from __future__ import annotations

import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


PRODUCTION_DATABASE_NAMES = frozenset({"casescope"})
BLOCK_NUMBER_SETTING = "enable_block_number_column"
BLOCK_OFFSET_SETTING = "enable_block_offset_column"
MODIFY_SETTING_SQL = (
    "ALTER TABLE events MODIFY SETTING "
    f"{BLOCK_NUMBER_SETTING} = 1, {BLOCK_OFFSET_SETTING} = 1"
)


def _current_database_name(client):
    result = client.query("SELECT currentDatabase()")
    if result.result_rows:
        return str(result.result_rows[0][0])
    return os.environ.get("CLICKHOUSE_DATABASE") or "casescope"


def _table_exists(client, table_name="events"):
    result = client.query(
        """
        SELECT count()
        FROM system.tables
        WHERE database = currentDatabase()
          AND name = {table_name:String}
        """,
        parameters={"table_name": table_name},
    )
    return bool(result.result_rows and result.result_rows[0][0])


def _engine_full(client, table_name="events"):
    result = client.query(
        """
        SELECT engine_full
        FROM system.tables
        WHERE database = currentDatabase()
          AND name = {table_name:String}
        """,
        parameters={"table_name": table_name},
    )
    if not result.result_rows:
        return ""
    return str(result.result_rows[0][0] or "")


def _setting_enabled(engine_full, name):
    match = re.search(rf"\b{re.escape(name)}\s*=\s*(\d+)", str(engine_full or ""))
    if not match:
        return False
    return match.group(1) == "1"


def events_has_block_columns_enabled(engine_full):
    return _setting_enabled(engine_full, BLOCK_NUMBER_SETTING) and _setting_enabled(
        engine_full, BLOCK_OFFSET_SETTING
    )


def add_events_block_number_offset(
    client,
    *,
    allow_production=False,
    table_name="events",
):
    """Idempotently enable block number/offset persistence on events."""
    database = _current_database_name(client)
    if database in PRODUCTION_DATABASE_NAMES and not allow_production:
        raise RuntimeError(
            f"Refusing to alter production database {database!r} without allow_production=True"
        )

    sql = (
        f"ALTER TABLE {table_name} MODIFY SETTING "
        f"{BLOCK_NUMBER_SETTING} = 1, {BLOCK_OFFSET_SETTING} = 1"
    )
    result = {
        "database": database,
        "table": table_name,
        "exists": False,
        "changed": False,
        "already_applied": False,
        "sql": None,
        "engine_full_before": "",
        "engine_full_after": "",
        "block_columns_enabled": False,
    }
    if not _table_exists(client, table_name):
        return result

    result["exists"] = True
    engine_before = _engine_full(client, table_name)
    result["engine_full_before"] = engine_before
    needed = not events_has_block_columns_enabled(engine_before)
    if needed:
        client.command(sql)
        result["changed"] = True
        result["sql"] = sql
    else:
        result["already_applied"] = True

    engine_after = _engine_full(client, table_name)
    result["engine_full_after"] = engine_after
    result["block_columns_enabled"] = events_has_block_columns_enabled(engine_after)
    if not result["block_columns_enabled"]:
        raise RuntimeError(
            f"{table_name} still missing {BLOCK_NUMBER_SETTING}=1 and "
            f"{BLOCK_OFFSET_SETTING}=1 after migration"
        )
    return result


def migrate(client=None, *, allow_production=False):
    if client is None:
        from utils.clickhouse import get_fresh_client

        client = get_fresh_client()
    return add_events_block_number_offset(client, allow_production=allow_production)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply-production",
        action="store_true",
        help="Allow ALTER SETTING against the production ClickHouse database named casescope.",
    )
    args = parser.parse_args(argv)
    result = migrate(allow_production=args.apply_production)
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
