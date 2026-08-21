#!/usr/bin/env python3
"""Migration: add Phase 1B Tranche D2 stale STAGED batch reconciliation fields."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db
from models.database_flow import IngestBatchReconciliationAudit
from sqlalchemy import text


POSTGRES_D2_DDL = [
    "ALTER TABLE ingest_attempts ADD COLUMN IF NOT EXISTS heartbeat_at TIMESTAMP",
    "ALTER TABLE ingest_attempts ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMP",
    "ALTER TABLE ingest_attempts ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP NOT NULL DEFAULT now()",
    "ALTER TABLE ingest_batches ADD COLUMN IF NOT EXISTS reconcile_owner VARCHAR(64)",
    "ALTER TABLE ingest_batches ADD COLUMN IF NOT EXISTS reconcile_lease_expires_at TIMESTAMP",
    "ALTER TABLE ingest_batches ADD COLUMN IF NOT EXISTS reconcile_attempt_count INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE ingest_batches ADD COLUMN IF NOT EXISTS last_reconcile_at TIMESTAMP",
    "ALTER TABLE ingest_batches ADD COLUMN IF NOT EXISTS last_reconcile_outcome VARCHAR(80)",
    "ALTER TABLE ingest_batches ADD COLUMN IF NOT EXISTS last_reconcile_error TEXT",
    "ALTER TABLE ingest_batches ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP NOT NULL DEFAULT now()",
    """
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conname = 'ck_ingest_batch_reconcile_attempt_count_nonnegative'
        ) THEN
            ALTER TABLE ingest_batches
            ADD CONSTRAINT ck_ingest_batch_reconcile_attempt_count_nonnegative
            CHECK (reconcile_attempt_count >= 0);
        END IF;
    END $$;
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_ingest_attempt_lease_expires
    ON ingest_attempts (lease_expires_at)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_ingest_batch_staged_updated
    ON ingest_batches (state, updated_at, id)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_ingest_batch_reconcile_claim
    ON ingest_batches (state, reconcile_lease_expires_at, id)
    """,
]


def migrate_postgres():
    app = create_app()
    with app.app_context():
        for ddl in POSTGRES_D2_DDL:
            db.session.execute(text(ddl))
        db.session.commit()
        IngestBatchReconciliationAudit.__table__.create(db.engine, checkfirst=True)
        print("- Added or verified Phase 1B D2 stale STAGED reconciliation fields")
    return True


def migrate():
    print("=" * 50)
    print("Phase 1B Tranche D2 Staged Batch Reconciler Migration")
    print("=" * 50)
    migrate_postgres()
    print("\n" + "=" * 50)
    print("Migration complete!")
    print("=" * 50)
    return True


if __name__ == "__main__":
    migrate()
