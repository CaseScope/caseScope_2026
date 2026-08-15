#!/usr/bin/env python3
"""Reset CaseScope forced-wide MergeTree part settings on `events`.

Phase 1.3 removes the historical `min_bytes_for_wide_part = 0` /
`min_rows_for_wide_part = 0` override so ClickHouse 26.7.3.19 can use its
server defaults (currently 10485760 bytes and 0 rows). Existing Wide parts
are left in place; this does not OPTIMIZE production.

This migration is idempotent. It is NOT invoked from application startup.
Do not run it against the production `casescope` database without
`--apply-production`.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


PRODUCTION_DATABASE_NAMES = frozenset({"casescope"})
FORCED_WIDE_SETTINGS = ("min_bytes_for_wide_part", "min_rows_for_wide_part")
RESET_SETTING_SQL = (
    "ALTER TABLE events RESET SETTING min_bytes_for_wide_part, min_rows_for_wide_part"
)


def _current_database_name(client):
    result = client.query("SELECT currentDatabase()")
    if result.result_rows:
        return str(result.result_rows[0][0])
    return os.environ.get("CLICKHOUSE_DATABASE") or "casescope"


def _table_exists(client, table_name):
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


def events_has_forced_wide_settings(engine_full):
    # min_rows_for_wide_part default is already 0; the CaseScope override that
    # forces Wide is min_bytes_for_wide_part = 0.
    return "min_bytes_for_wide_part = 0" in str(engine_full or "")


def reset_events_forced_wide_part_settings(client, *, allow_production=False):
    """Idempotently RESET forced-wide overrides on the current `events` table."""
    database = _current_database_name(client)
    if database in PRODUCTION_DATABASE_NAMES and not allow_production:
        raise RuntimeError(
            f"Refusing to alter production database {database!r} without allow_production=True"
        )
    if not _table_exists(client, "events"):
        return {
            "database": database,
            "table": "events",
            "exists": False,
            "changed": False,
            "engine_full_before": "",
            "engine_full_after": "",
            "sql": None,
        }

    engine_before = _engine_full(client)
    needed = events_has_forced_wide_settings(engine_before)
    if needed:
        client.command(RESET_SETTING_SQL)
    engine_after = _engine_full(client)
    return {
        "database": database,
        "table": "events",
        "exists": True,
        "changed": needed,
        "engine_full_before": engine_before,
        "engine_full_after": engine_after,
        "sql": RESET_SETTING_SQL if needed else None,
        "forced_wide_remaining": events_has_forced_wide_settings(engine_after),
    }


def migrate(client=None, *, allow_production=False):
    if client is None:
        from utils.clickhouse import get_fresh_client

        client = get_fresh_client()
    return reset_events_forced_wide_part_settings(
        client,
        allow_production=allow_production,
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply-production",
        action="store_true",
        help="Allow running against the production ClickHouse database named casescope.",
    )
    args = parser.parse_args(argv)
    result = migrate(allow_production=args.apply_production)
    print(result)
    if result.get("forced_wide_remaining"):
        raise SystemExit("Forced-wide settings remain after RESET SETTING")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
