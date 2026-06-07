#!/usr/bin/env python3
"""Database migration to add analyst case work time tracking tables."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db


def run_migration():
    """Create case work session and activity tables."""
    app = create_app()

    with app.app_context():
        from sqlalchemy import inspect

        inspector = inspect(db.engine)
        existing_tables = set(inspector.get_table_names())
        required = {"case_work_sessions", "case_work_activities"}

        if required.issubset(existing_tables):
            print("Case work tables already exist - skipping creation")
            return True

        print("Creating case work tables...")
        from models.case_work import CaseWorkActivity, CaseWorkSession  # noqa: F401

        db.create_all()
        print("Case work tables created successfully!")
        return True


if __name__ == "__main__":
    print("=" * 60)
    print("Case Work Tables Migration")
    print("=" * 60)
    print()

    try:
        run_migration()
        sys.exit(0)
    except Exception as exc:
        print(f"Migration failed: {exc}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
