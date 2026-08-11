#!/usr/bin/env python3
"""
Migration: Add ClickHouse Events Tables

Creates the ClickHouse tables required by artifact ingestion.

Run with: python migrations/add_events_table.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parsers.base import ParsedEvent
from utils.clickhouse import get_fresh_client


SELECTOR_KEY_EXPRESSION = """
multiIf(
    ifNull(record_id, 0) > 0
        AND source_file != ''
        AND source_file != '-'
        AND source_host != ''
        AND source_host != '-',
    concat(
        'record:', toString(record_id),
        '|file:', source_file,
        '|host:', source_host
    ),
    concat(
        'ts:', formatDateTime(timestamp_utc, '%Y-%m-%d %H:%i:%S'),
        '|host:', if(source_host = '-', '', source_host),
        '|artifact:', if(artifact_type = '-', '', artifact_type),
        '|event:', if(event_id = '-', '', event_id),
        '|file:', if(source_file = '-', '', source_file)
    )
)
""".strip()


EVENTS_COLUMN_DEFINITIONS = {
    "case_id": "UInt32",
    "artifact_type": "LowCardinality(String)",
    "timestamp": "DateTime64(3)",
    "timestamp_utc": "DateTime64(3)",
    "timestamp_source_tz": "LowCardinality(String) DEFAULT 'UTC'",
    "source_file": "String DEFAULT ''",
    "source_path": "String DEFAULT ''",
    "source_host": "LowCardinality(String) DEFAULT ''",
    "case_file_id": "Nullable(UInt32)",
    "event_id": "String DEFAULT ''",
    "channel": "LowCardinality(String) DEFAULT ''",
    "provider": "String DEFAULT ''",
    "record_id": "Nullable(UInt64)",
    "level": "LowCardinality(String) DEFAULT ''",
    "username": "String DEFAULT ''",
    "domain": "String DEFAULT ''",
    "sid": "String DEFAULT ''",
    "logon_type": "Nullable(UInt16)",
    "logon_id": "String DEFAULT ''",
    "remote_host": "String DEFAULT ''",
    "workstation_name": "String DEFAULT ''",
    "auth_package": "LowCardinality(String) DEFAULT ''",
    "logon_process": "String DEFAULT ''",
    "elevated_token": "LowCardinality(String) DEFAULT ''",
    "process_name": "String DEFAULT ''",
    "process_path": "String DEFAULT ''",
    "process_id": "Nullable(UInt64)",
    "parent_process": "String DEFAULT ''",
    "parent_pid": "Nullable(UInt64)",
    "command_line": "String DEFAULT ''",
    "thread_id": "Nullable(UInt64)",
    "executable_info": "String DEFAULT ''",
    "payload_data1": "String DEFAULT ''",
    "payload_data2": "String DEFAULT ''",
    "payload_data3": "String DEFAULT ''",
    "payload_data4": "String DEFAULT ''",
    "payload_data5": "String DEFAULT ''",
    "payload_data6": "String DEFAULT ''",
    "target_path": "String DEFAULT ''",
    "file_hash_md5": "String DEFAULT ''",
    "file_hash_sha1": "String DEFAULT ''",
    "file_hash_sha256": "String DEFAULT ''",
    "file_size": "Nullable(UInt64)",
    "src_ip": "Nullable(IPv4)",
    "dst_ip": "Nullable(IPv4)",
    "src_port": "Nullable(UInt16)",
    "dst_port": "Nullable(UInt16)",
    "reg_key": "String DEFAULT ''",
    "reg_value": "String DEFAULT ''",
    "reg_data": "String DEFAULT ''",
    "rule_title": "String DEFAULT ''",
    "rule_level": "LowCardinality(String) DEFAULT ''",
    "rule_file": "String DEFAULT ''",
    "mitre_tactics": "Array(String) DEFAULT []",
    "mitre_tags": "Array(String) DEFAULT []",
    "raw_json": "String DEFAULT '{}' CODEC(ZSTD(3))",
    "search_blob": "String DEFAULT '' CODEC(ZSTD(1))",
    "extra_fields": "String DEFAULT '{}' CODEC(ZSTD(3))",
    "parser_version": "LowCardinality(String) DEFAULT ''",
    "evidence_record_key": "String DEFAULT ''",
    "evidence_identity_version": "LowCardinality(String) DEFAULT ''",
    "evidence_identity_quality": "LowCardinality(String) DEFAULT ''",
    "indexed_at": "DateTime64(3) DEFAULT now64(3)",
    "selector_key": f"String MATERIALIZED {SELECTOR_KEY_EXPRESSION}",
    "analyst_tagged": "Bool DEFAULT false",
    "analyst_tags": "Array(String) DEFAULT []",
    "analyst_notes": "Nullable(String) DEFAULT NULL",
    "noise_matched": "Bool DEFAULT false",
    "noise_rules": "Array(String) DEFAULT []",
    "ioc_types": "Array(String) DEFAULT []",
    "mitre_attack_ids": "Array(String) DEFAULT []",
    "mitre_attack_tactics": "Array(String) DEFAULT []",
    "mitre_attack_sources": "Array(String) DEFAULT []",
    "mitre_mapping_max_confidence": "UInt8 DEFAULT 0",
}

EVENTS_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS events (
    {",\n    ".join(f"{name} {definition}" for name, definition in EVENTS_COLUMN_DEFINITIONS.items())},

    INDEX idx_search_ngram search_blob TYPE ngrambf_v1(3, 512, 2, 0) GRANULARITY 4,
    INDEX idx_search_token search_blob TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4,
    INDEX idx_event_id event_id TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_selector_key selector_key TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_evidence_record_key evidence_record_key TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY case_id
ORDER BY (case_id, timestamp_utc, artifact_type, source_host, source_file, event_id)
SETTINGS
    index_granularity = 8192,
    min_bytes_for_wide_part = 0,
    min_rows_for_wide_part = 0;
"""

EVENTS_BUFFER_SCHEMA = """
CREATE TABLE IF NOT EXISTS events_buffer AS events
ENGINE = Buffer(
    casescope,
    events,
    16,
    10, 100,
    10000, 100000,
    10000000, 100000000
);
"""


def _assert_insert_columns_are_defined():
    missing = [
        column
        for column in ParsedEvent.clickhouse_columns()
        if column not in EVENTS_COLUMN_DEFINITIONS
    ]
    if missing:
        raise RuntimeError(f"Events schema is missing parser insert columns: {missing}")


def _existing_columns(client, table_name):
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


def _table_engine(client, table_name):
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


def _count_table_rows(client, table_name):
    result = client.query(f"SELECT count() FROM {table_name}")
    return int(result.result_rows[0][0]) if result.result_rows else 0


def _buffer_pending_rows(client):
    """Best-effort count of rows still resident in the Buffer table.

    ClickHouse Buffer SELECT reads the destination table plus in-memory buffer
    rows, so the excess over the durable events count is the pending buffer
    population. This is only used after ingestion has been stopped by the
    operator/runbook.
    """

    if not _table_exists(client, "events_buffer"):
        return 0
    if _table_engine(client, "events_buffer").lower() != "buffer":
        return 0
    events_rows = _count_table_rows(client, "events")
    buffer_visible_rows = _count_table_rows(client, "events_buffer")
    return max(int(buffer_visible_rows) - int(events_rows), 0)


def get_events_buffer_state(client):
    exists = _table_exists(client, "events_buffer")
    engine = _table_engine(client, "events_buffer") if exists else ""
    pending_rows = _buffer_pending_rows(client) if exists and engine.lower() == "buffer" else 0
    return {
        "exists": exists,
        "engine": engine,
        "pending_rows": pending_rows,
    }


def safely_drain_events_buffer(client, *, context="events migration"):
    """Flush and verify the Buffer table before DDL that could discard rows.

    ClickHouse documents OPTIMIZE for Buffer-engine tables as an immediate
    flush, and DROP/DETACH as flushing buffered rows to the destination table.
    The explicit OPTIMIZE keeps pending-row diagnostics visible before fencing.
    """

    if not _table_exists(client, "events_buffer"):
        return {"exists": False, "engine": "", "pending_before": 0, "pending_after": 0}

    engine = _table_engine(client, "events_buffer")
    if engine.lower() != "buffer":
        return {"exists": True, "engine": engine, "pending_before": 0, "pending_after": 0}

    pending_before = _buffer_pending_rows(client)
    print(f"- events_buffer pending rows before {context}: {pending_before}")
    client.command("OPTIMIZE TABLE events_buffer")
    pending_after = _buffer_pending_rows(client)
    print(f"- events_buffer pending rows after drain: {pending_after}")
    if pending_after != 0:
        raise RuntimeError(
            "events_buffer still has pending rows after OPTIMIZE; "
            "stop event-producing services and retry before rewriting events"
        )
    return {
        "exists": True,
        "engine": engine,
        "pending_before": pending_before,
        "pending_after": pending_after,
    }


def fence_events_buffer_ingestion(client, *, context="events migration"):
    """Drain and remove the Buffer ingestion table so late writers fail closed."""

    state = safely_drain_events_buffer(client, context=context)
    if not _table_exists(client, "events_buffer"):
        print("- events_buffer ingestion target is absent")
        return {**state, "fenced": True}
    if _table_engine(client, "events_buffer").lower() == "buffer":
        client.command("DROP TABLE IF EXISTS events_buffer")
        print("- Dropped events_buffer to fence event ingestion")
    else:
        client.command("DROP TABLE IF EXISTS events_buffer")
        print("- Dropped non-Buffer events_buffer replacement to fence event ingestion")
    if _table_exists(client, "events_buffer"):
        raise RuntimeError("events_buffer still exists after fence; aborting migration")
    return {**state, "fenced": True}


def recreate_events_buffer(client):
    client.command(EVENTS_BUFFER_SCHEMA)
    print("- Created or verified events_buffer table")


def _insertable_columns(client, table_name):
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
        row[0]
        for row in result.result_rows
        if str(row[1] or "").upper() not in {"MATERIALIZED", "ALIAS"}
    ]


def _add_missing_columns(client, table_name):
    existing = _existing_columns(client, table_name)
    if not existing:
        return

    for column_name, definition in EVENTS_COLUMN_DEFINITIONS.items():
        if column_name in existing:
            continue
        client.command(
            f"ALTER TABLE {table_name} ADD COLUMN IF NOT EXISTS {column_name} {definition}"
        )
        print(f"- Added {column_name} to {table_name}")


def _ensure_evidence_record_key_index(client):
    result = client.query(
        """
        SELECT name
        FROM system.data_skipping_indices
        WHERE database = currentDatabase()
          AND table = 'events'
          AND name = 'idx_evidence_record_key'
        """
    )
    if result.result_rows:
        return
    client.command(
        "ALTER TABLE events ADD INDEX IF NOT EXISTS "
        "idx_evidence_record_key evidence_record_key TYPE bloom_filter(0.01) GRANULARITY 4"
    )
    print("- Added idx_evidence_record_key to events")


def _ensure_events_buffer_schema(client):
    if not _table_exists(client, "events_buffer"):
        recreate_events_buffer(client)
        return

    events_columns = set(_insertable_columns(client, "events"))
    buffer_columns = set(_insertable_columns(client, "events_buffer"))
    if events_columns == buffer_columns:
        print("- Created or verified events_buffer table")
        return

    if _table_engine(client, "events_buffer").lower() == "buffer":
        fence_events_buffer_ingestion(client, context="events_buffer schema recreation")
        recreate_events_buffer(client)
        print("- Recreated events_buffer table to match events schema")
        return

    _add_missing_columns(client, "events_buffer")


def migrate_clickhouse():
    """Create or update the ClickHouse event tables."""
    _assert_insert_columns_are_defined()

    print("Creating ClickHouse events tables...")
    client = get_fresh_client()

    client.command(EVENTS_SCHEMA)
    print("- Created or verified events table")

    _add_missing_columns(client, "events")
    _ensure_evidence_record_key_index(client)

    _ensure_events_buffer_schema(client)

    result = client.query("DESCRIBE events")
    print(f"- Verified events table has {len(result.result_rows)} columns")


def migrate():
    """Run the migration."""
    print("=" * 50)
    print("Events Table Migration")
    print("=" * 50)
    migrate_clickhouse()
    print("\n" + "=" * 50)
    print("Migration complete!")
    print("=" * 50)


if __name__ == "__main__":
    migrate()
