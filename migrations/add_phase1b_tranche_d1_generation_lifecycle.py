#!/usr/bin/env python3
"""Migration: add Phase 1B Tranche D1 generation lifecycle authority fields."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db
from models.database_flow import EvidenceGenerationAudit
from sqlalchemy import text


POSTGRES_D1_DDL = [
    "ALTER TABLE evidence_source_generations ADD COLUMN IF NOT EXISTS final_batch_ordinal INTEGER",
    "ALTER TABLE evidence_source_generations ADD COLUMN IF NOT EXISTS activated_at TIMESTAMP",
    "ALTER TABLE evidence_source_generations ADD COLUMN IF NOT EXISTS superseded_at TIMESTAMP",
    "ALTER TABLE evidence_source_generations ADD COLUMN IF NOT EXISTS superseded_by_generation INTEGER",
    """
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conname = 'ck_evidence_source_generation_final_batch_ordinal_nonnegative'
        ) THEN
            ALTER TABLE evidence_source_generations
            ADD CONSTRAINT ck_evidence_source_generation_final_batch_ordinal_nonnegative
            CHECK (final_batch_ordinal IS NULL OR final_batch_ordinal >= 0);
        END IF;
    END $$;
    """,
]


def migrate_postgres():
    app = create_app()
    with app.app_context():
        for ddl in POSTGRES_D1_DDL:
            db.session.execute(text(ddl))
        db.session.commit()
        EvidenceGenerationAudit.__table__.create(db.engine, checkfirst=True)
        print("- Added or verified Phase 1B D1 lifecycle fields and audit table")
    return True


def migrate():
    print("=" * 50)
    print("Phase 1B Tranche D1 Generation Lifecycle Migration")
    print("=" * 50)
    migrate_postgres()
    print("\n" + "=" * 50)
    print("Migration complete!")
    print("=" * 50)
    return True


if __name__ == "__main__":
    migrate()
