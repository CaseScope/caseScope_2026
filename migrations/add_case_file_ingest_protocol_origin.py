#!/usr/bin/env python3
"""Migration: add CaseFile manifest adoption marker for Phase 1B C1."""
import os
import sys

from sqlalchemy import text

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db


ADD_COLUMN_SQL = """
ALTER TABLE case_files
ADD COLUMN IF NOT EXISTS ingest_protocol_origin VARCHAR(32)
NOT NULL DEFAULT 'legacy_or_unknown'
"""

SET_FUTURE_DEFAULT_SQL = """
ALTER TABLE case_files
ALTER COLUMN ingest_protocol_origin SET DEFAULT 'not_started'
"""

CHECK_CONSTRAINT_SQL = """
ALTER TABLE case_files
ADD CONSTRAINT ck_case_file_ingest_protocol_origin
CHECK (ingest_protocol_origin IN ('not_started', 'legacy_or_unknown', 'manifest_initial'))
"""


def migrate():
    app = create_app()
    with app.app_context():
        with db.engine.begin() as connection:
            connection.execute(text(ADD_COLUMN_SQL))
            connection.execute(text(SET_FUTURE_DEFAULT_SQL))
            existing = connection.execute(text("""
                SELECT 1
                FROM pg_constraint
                WHERE conname = 'ck_case_file_ingest_protocol_origin'
            """)).scalar()
            if not existing:
                connection.execute(text(CHECK_CONSTRAINT_SQL))
        print("- Added CaseFile ingest_protocol_origin marker")
        return True


if __name__ == "__main__":
    migrate()
