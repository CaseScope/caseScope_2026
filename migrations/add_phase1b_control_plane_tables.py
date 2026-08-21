#!/usr/bin/env python3
"""Migration: add inactive Phase 1B Tranche A PostgreSQL control-plane tables."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db
from models.database_flow import (
    CaseCapabilitySourceState,
    EvidenceGenerationAudit,
    EvidenceSourceGeneration,
    IngestAttempt,
    IngestBatch,
    IngestBatchReconciliationAudit,
)


def migrate():
    """Create PostgreSQL control-plane tables without activating ingest behavior."""
    app = create_app()
    with app.app_context():
        tables = [
            EvidenceSourceGeneration.__table__,
            EvidenceGenerationAudit.__table__,
            IngestAttempt.__table__,
            IngestBatch.__table__,
            IngestBatchReconciliationAudit.__table__,
            CaseCapabilitySourceState.__table__,
        ]
        created = []
        skipped = []
        with db.engine.connect() as connection:
            for table in tables:
                if not db.engine.dialect.has_table(connection, table.name):
                    table.create(db.engine)
                    created.append(table.name)
                    print(f"Created table: {table.name}")
                else:
                    skipped.append(table.name)
                    print(f"Table already exists: {table.name}")

        print(f"Migration complete: {len(created)} created, {len(skipped)} skipped")
        return True


if __name__ == "__main__":
    migrate()
