#!/usr/bin/env python3
"""Migration: add Phase 0B investigative graph tables."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db
from models.graph import (
    GraphEntity,
    GraphEntityObservation,
    GraphRelationship,
    GraphRelationshipEvidence,
)


def migrate():
    """Create PostgreSQL tables for the evidence-backed investigative graph."""
    app = create_app()
    with app.app_context():
        tables = [
            GraphEntity.__table__,
            GraphEntityObservation.__table__,
            GraphRelationship.__table__,
            GraphRelationshipEvidence.__table__,
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


if __name__ == '__main__':
    migrate()
