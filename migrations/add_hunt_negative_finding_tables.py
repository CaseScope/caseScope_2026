#!/usr/bin/env python3
"""Database migration to add checklist-backed hunt negative finding tables."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db


def run_migration():
    """Create hunt checklist and negative finding tables."""
    app = create_app()

    with app.app_context():
        from sqlalchemy import inspect

        inspector = inspect(db.engine)
        existing_tables = set(inspector.get_table_names())
        required = {
            "hunt_checklist_definitions",
            "hunt_checklist_runs",
            "hunt_checklist_checks",
            "hunt_negative_findings",
        }

        if required.issubset(existing_tables):
            print("Hunt negative finding tables already exist - skipping creation")
            return True

        print("Creating hunt negative finding tables...")
        from models.hunt import (  # noqa: F401
            HuntChecklistCheck,
            HuntChecklistDefinition,
            HuntChecklistRun,
            HuntNegativeFinding,
        )

        db.create_all()
        print("Hunt negative finding tables created successfully!")
        return True


if __name__ == "__main__":
    print("=" * 60)
    print("Hunt Negative Finding Tables Migration")
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
