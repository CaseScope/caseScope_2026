#!/usr/bin/env python3
"""Migration: add inactive Phase 1B protocol columns to ClickHouse events."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.clickhouse import get_fresh_client


PHASE1B_EVENT_PROTOCOL_COLUMNS = {
    "source_ref_type": "Nullable(String) DEFAULT NULL",
    "source_ref_id": "Nullable(String) DEFAULT NULL",
    "source_generation": "Nullable(UInt32) DEFAULT NULL",
    "ingest_batch_id": "Nullable(String) DEFAULT NULL",
    "ingest_row_ordinal": "Nullable(UInt32) DEFAULT NULL",
    "ingest_row_hash": "Nullable(String) DEFAULT NULL",
    "ingest_attempt_id": "Nullable(UUID) DEFAULT NULL",
}


def protocol_column_ddl(table_name="events"):
    return [
        f"ALTER TABLE {table_name} ADD COLUMN IF NOT EXISTS {column_name} {definition}"
        for column_name, definition in PHASE1B_EVENT_PROTOCOL_COLUMNS.items()
    ]


def migrate_clickhouse(client=None):
    """Add nullable/default protocol columns without touching historical rows."""
    client = client or get_fresh_client()
    for statement in protocol_column_ddl("events"):
        client.command(statement)
        print(f"- Applied: {statement}")
    return True


def migrate():
    print("=" * 50)
    print("Phase 1B Tranche A Event Protocol Column Migration")
    print("=" * 50)
    migrate_clickhouse()
    print("\n" + "=" * 50)
    print("Migration complete!")
    print("=" * 50)
    return True


if __name__ == "__main__":
    migrate()
