#!/usr/bin/env python3
"""Migration: add Phase 0D Investigation Threads and Saved Graph Views tables."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db
from models.graph_saved_view import GraphSavedView
from models.investigation_thread import (
    InvestigationThread,
    InvestigationThreadEntity,
    InvestigationThreadEvidence,
    InvestigationThreadFinding,
    InvestigationThreadIOC,
    InvestigationThreadNote,
    InvestigationThreadRelationship,
)
from sqlalchemy import inspect, text


def _table_names(connection):
    return set(db.engine.dialect.get_table_names(connection))


def migrate():
    """Create PostgreSQL tables for Investigation Threads and Saved Graph Views."""
    app = create_app()
    with app.app_context():
        # graph_saved_views first — investigation_threads may FK to it.
        tables = [
            GraphSavedView.__table__,
            InvestigationThread.__table__,
            InvestigationThreadEntity.__table__,
            InvestigationThreadRelationship.__table__,
            InvestigationThreadEvidence.__table__,
            InvestigationThreadIOC.__table__,
            InvestigationThreadFinding.__table__,
            InvestigationThreadNote.__table__,
        ]
        created = []
        skipped = []
        with db.engine.connect() as connection:
            existing = _table_names(connection)
            for table in tables:
                if table.name not in existing:
                    table.create(db.engine)
                    created.append(table.name)
                    print(f"Created table: {table.name}")
                    existing.add(table.name)
                else:
                    skipped.append(table.name)
                    print(f"Table already exists: {table.name}")

        # Ensure SET NULL behavior for current_saved_view_id on existing installs.
        inspector = inspect(db.engine)
        if "investigation_threads" in inspector.get_table_names():
            fks = inspector.get_foreign_keys("investigation_threads")
            has_saved_view_fk = any(
                fk.get("referred_table") == "graph_saved_views"
                and "current_saved_view_id" in (fk.get("constrained_columns") or [])
                for fk in fks
            )
            if not has_saved_view_fk:
                db.session.execute(text("""
                    ALTER TABLE investigation_threads
                    ADD CONSTRAINT fk_investigation_threads_current_saved_view
                    FOREIGN KEY (current_saved_view_id)
                    REFERENCES graph_saved_views(id)
                    ON DELETE SET NULL
                """))
                db.session.commit()
                print("Added current_saved_view_id FK with ON DELETE SET NULL")

        print(f"Migration complete: {len(created)} created, {len(skipped)} skipped")
        return True


if __name__ == "__main__":
    migrate()
