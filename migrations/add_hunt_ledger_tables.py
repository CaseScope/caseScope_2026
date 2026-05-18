#!/usr/bin/env python3
"""Database migration to add hunt ledger trace tables."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db


def run_migration():
    """Create hunt_runs, hunt_hypotheses, hunt_steps, and hunt_evidence_refs."""
    app = create_app()

    with app.app_context():
        from sqlalchemy import inspect

        inspector = inspect(db.engine)
        existing_tables = set(inspector.get_table_names())
        required = {
            "hunt_runs",
            "hunt_hypotheses",
            "hunt_steps",
            "hunt_evidence_refs",
        }

        if required.issubset(existing_tables):
            print("Hunt ledger tables already exist - skipping creation")
            return True

        print("Creating hunt ledger tables...")
        from models.hunt import HuntRun, HuntHypothesis, HuntStep, HuntEvidenceRef  # noqa: F401

        db.create_all()
        print("Hunt ledger tables created successfully!")
        return True


if __name__ == "__main__":
    print("=" * 60)
    print("Hunt Ledger Tables Migration")
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
