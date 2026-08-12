#!/usr/bin/env python3
"""Migration: add immutable Investigation Thread report snapshots."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db
from models.investigation_thread import InvestigationThreadReportSnapshot


def migrate():
    """Create PostgreSQL table for Phase 0F immutable Thread report snapshots."""
    app = create_app()
    with app.app_context():
        with db.engine.connect() as connection:
            existing = set(db.engine.dialect.get_table_names(connection))
        if InvestigationThreadReportSnapshot.__tablename__ not in existing:
            InvestigationThreadReportSnapshot.__table__.create(db.engine)
            print(f"Created table: {InvestigationThreadReportSnapshot.__tablename__}")
        else:
            print(f"Table already exists: {InvestigationThreadReportSnapshot.__tablename__}")
    return True


if __name__ == "__main__":
    migrate()
