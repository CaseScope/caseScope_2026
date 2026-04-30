#!/usr/bin/env python3
"""Database migration to add the AI audit log table.

The v1 record hash includes exactly: hash_version, timestamp, case_uuid,
function, provider_type, model, user_id, status, response_complete,
prompt_hash, response_hash, and previous_record_hash.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db


def run_migration():
    """Create the tamper-evident AI audit table and indexes."""
    app = create_app()

    with app.app_context():
        from sqlalchemy import inspect

        inspector = inspect(db.engine)
        existing_tables = set(inspector.get_table_names())

        if "ai_audit_log" in existing_tables:
            print("Table 'ai_audit_log' already exists - skipping creation")
            return True

        print("Creating AI audit log table...")

        from models.ai_audit_log import AIAuditLog  # noqa: F401

        db.create_all()
        print("AI audit log table created successfully!")
        return True


if __name__ == "__main__":
    print("=" * 60)
    print("AI Audit Log Table Migration")
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
