#!/usr/bin/env python3
"""Seed versioned hunt checklist definitions for Phase 3 negative findings."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app


def run_migration():
    """Seed built-in hunt checklist definitions."""
    app = create_app()

    with app.app_context():
        from utils.hunt_checklist_templates import seed_hunt_checklist_definitions

        result = seed_hunt_checklist_definitions()
        print(
            "Hunt checklist definitions seeded: "
            f"created={result['created']} updated={result['updated']} skipped={result['skipped']}"
        )
        return True


if __name__ == "__main__":
    print("=" * 60)
    print("Hunt Checklist Definitions Seed Migration")
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
