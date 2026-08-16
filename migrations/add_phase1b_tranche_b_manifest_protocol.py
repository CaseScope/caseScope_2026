#!/usr/bin/env python3
"""Migration: add Phase 1B Tranche B manifest protocol constraints/projections."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db
from sqlalchemy import text
from utils.clickhouse import get_fresh_client


POSTGRES_INDEX_DDL = [
    """
    CREATE UNIQUE INDEX IF NOT EXISTS uq_evidence_source_generation_open_building
    ON evidence_source_generations (case_id, source_ref_type, source_ref_id)
    WHERE visibility_state IN ('BUILDING_INITIAL', 'BUILDING_REPLACEMENT')
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS uq_evidence_source_generation_active
    ON evidence_source_generations (case_id, source_ref_type, source_ref_id)
    WHERE visibility_state = 'ACTIVE'
    """,
]


VISIBLE_EVIDENCE_GENERATIONS_SCHEMA = """
CREATE TABLE IF NOT EXISTS visible_evidence_generations (
    case_id UInt32,
    source_ref_type String,
    source_ref_id String,
    source_generation UInt32,
    visibility_state LowCardinality(String),
    state_version UInt64,
    publishable UInt8,
    updated_at DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(state_version)
ORDER BY (case_id, source_ref_type, source_ref_id, source_generation)
SETTINGS index_granularity = 8192
"""


DURABLE_INGEST_BATCHES_SCHEMA = """
CREATE TABLE IF NOT EXISTS durable_ingest_batches (
    ingest_batch_id String,
    case_id UInt32,
    source_ref_type String,
    source_ref_id String,
    source_generation UInt32,
    batch_ordinal UInt32,
    expected_row_count UInt64,
    batch_content_hash String,
    state LowCardinality(String),
    state_version UInt64,
    durable_at Nullable(DateTime64(3)),
    updated_at DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(state_version)
ORDER BY ingest_batch_id
SETTINGS index_granularity = 8192
"""


def clickhouse_control_table_ddl():
    return [VISIBLE_EVIDENCE_GENERATIONS_SCHEMA, DURABLE_INGEST_BATCHES_SCHEMA]


def migrate_postgres():
    app = create_app()
    with app.app_context():
        for ddl in POSTGRES_INDEX_DDL:
            db.session.execute(text(ddl))
        db.session.commit()
        print("- Added or verified Phase 1B generation partial unique indexes")
    return True


def migrate_clickhouse(client=None):
    client = client or get_fresh_client()
    for ddl in clickhouse_control_table_ddl():
        client.command(ddl)
    print("- Added or verified Phase 1B ClickHouse control tables")
    return True


def migrate():
    print("=" * 50)
    print("Phase 1B Tranche B Manifest Protocol Migration")
    print("=" * 50)
    migrate_postgres()
    migrate_clickhouse()
    print("\n" + "=" * 50)
    print("Migration complete!")
    print("=" * 50)
    return True


if __name__ == "__main__":
    migrate()
