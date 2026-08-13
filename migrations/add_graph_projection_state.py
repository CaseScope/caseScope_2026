#!/usr/bin/env python3
"""Migration: add durable graph projection state."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db
from models.graph import GraphProjectionState
from sqlalchemy import inspect, text


WINDOW_STATE_COLUMNS = {
    'current_window_start_utc': "ALTER TABLE graph_projection_state ADD COLUMN IF NOT EXISTS current_window_start_utc TIMESTAMP",
    'current_window_end_utc': "ALTER TABLE graph_projection_state ADD COLUMN IF NOT EXISTS current_window_end_utc TIMESTAMP",
    'last_completed_window_end_utc': "ALTER TABLE graph_projection_state ADD COLUMN IF NOT EXISTS last_completed_window_end_utc TIMESTAMP",
    'windows_completed': "ALTER TABLE graph_projection_state ADD COLUMN IF NOT EXISTS windows_completed BIGINT NOT NULL DEFAULT 0",
}


def migrate():
    """Create the per-case graph projection state table."""
    app = create_app()
    with app.app_context():
        with db.engine.connect() as connection:
            if not db.engine.dialect.has_table(connection, GraphProjectionState.__tablename__):
                GraphProjectionState.__table__.create(db.engine)
                print(f"Created table: {GraphProjectionState.__tablename__}")
            else:
                print(f"Table already exists: {GraphProjectionState.__tablename__}")
        inspector = inspect(db.engine)
        if GraphProjectionState.__tablename__ in inspector.get_table_names():
            existing = {column['name'] for column in inspector.get_columns(GraphProjectionState.__tablename__)}
            changed = []
            for name, ddl in WINDOW_STATE_COLUMNS.items():
                if name not in existing:
                    db.session.execute(text(ddl))
                    changed.append(name)
            if changed:
                db.session.commit()
                print("Added graph projection window state columns: " + ", ".join(changed))
            else:
                print("Graph projection window state columns already exist")
        return True


if __name__ == '__main__':
    migrate()
