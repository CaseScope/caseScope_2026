#!/usr/bin/env python3
"""Migration: add durable graph projection state."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db
from models.graph import GraphProjectionState


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
        return True


if __name__ == '__main__':
    migrate()
