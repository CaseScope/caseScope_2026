#!/usr/bin/env python3
"""Add lifecycle fields to case_analysis_runs.

Adds:
- last_progress_at
- partial_results_available
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db


def _column_exists(table_name: str, column_name: str) -> bool:
    sql = """
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = :table_name
          AND column_name = :column_name
    """
    return bool(db.session.execute(
        db.text(sql),
        {'table_name': table_name, 'column_name': column_name}
    ).fetchone())


def _index_exists(index_name: str) -> bool:
    sql = "SELECT 1 FROM pg_indexes WHERE indexname = :index_name"
    return bool(db.session.execute(
        db.text(sql),
        {'index_name': index_name}
    ).fetchone())


def run_migration():
    app = create_app()

    with app.app_context():
        table_name = 'case_analysis_runs'

        columns_to_add = [
            ('last_progress_at', 'TIMESTAMP'),
            ('partial_results_available', 'BOOLEAN NOT NULL DEFAULT FALSE'),
        ]

        for column_name, column_type in columns_to_add:
            try:
                if _column_exists(table_name, column_name):
                    print(f"  [SKIP] Column {table_name}.{column_name} already exists")
                    continue

                sql = f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"
                db.session.execute(db.text(sql))
                db.session.commit()
                print(f"  [OK] Added column {table_name}.{column_name}")
            except Exception as exc:
                db.session.rollback()
                print(f"  [ERROR] Failed to add column {column_name}: {exc}")

        try:
            backfill_sql = f"""
                UPDATE {table_name}
                SET last_progress_at = COALESCE(last_progress_at, completed_at, started_at)
                WHERE last_progress_at IS NULL
            """
            db.session.execute(db.text(backfill_sql))
            db.session.commit()
            print(f"  [OK] Backfilled {table_name}.last_progress_at")
        except Exception as exc:
            db.session.rollback()
            print(f"  [ERROR] Failed to backfill last_progress_at: {exc}")

        index_name = 'ix_case_analysis_runs_last_progress_at'
        try:
            if _index_exists(index_name):
                print(f"  [SKIP] Index {index_name} already exists")
            else:
                db.session.execute(db.text(
                    f"CREATE INDEX {index_name} ON {table_name} (last_progress_at)"
                ))
                db.session.commit()
                print(f"  [OK] Created index {index_name}")
        except Exception as exc:
            db.session.rollback()
            print(f"  [ERROR] Failed to create index {index_name}: {exc}")

        print("\nCase analysis lifecycle migration complete.")
        return True


if __name__ == '__main__':
    try:
        run_migration()
        sys.exit(0)
    except Exception as exc:
        print(f"Migration failed: {exc}")
        raise
