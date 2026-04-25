#!/usr/bin/env python3
"""Add durable IOC AI enhancement run tracking."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db


def _table_exists(table_name: str) -> bool:
    sql = """
        SELECT 1
        FROM information_schema.tables
        WHERE table_name = :table_name
    """
    return bool(db.session.execute(db.text(sql), {"table_name": table_name}).fetchone())


def _index_exists(index_name: str) -> bool:
    sql = "SELECT 1 FROM pg_indexes WHERE indexname = :index_name"
    return bool(db.session.execute(db.text(sql), {"index_name": index_name}).fetchone())


def _create_index(index_name: str, table_name: str, columns: str) -> None:
    if _index_exists(index_name):
        print(f"  [SKIP] Index {index_name} already exists")
        return
    db.session.execute(db.text(f"CREATE INDEX {index_name} ON {table_name} ({columns})"))
    db.session.commit()
    print(f"  [OK] Created index {index_name}")


def run_migration():
    app = create_app()

    with app.app_context():
        table_name = "case_ioc_enhancement_runs"
        if _table_exists(table_name):
            print(f"  [SKIP] Table {table_name} already exists")
        else:
            db.session.execute(db.text("""
                CREATE TABLE case_ioc_enhancement_runs (
                    id SERIAL PRIMARY KEY,
                    run_uuid VARCHAR(36) NOT NULL UNIQUE,
                    case_id INTEGER NOT NULL REFERENCES cases(id),
                    report_index INTEGER NOT NULL DEFAULT 0,
                    status VARCHAR(20) NOT NULL DEFAULT 'pending',
                    progress_percent INTEGER NOT NULL DEFAULT 0,
                    current_phase VARCHAR(255),
                    celery_task_id VARCHAR(100),
                    model VARCHAR(255),
                    error_message TEXT,
                    staged_candidates JSON NOT NULL DEFAULT '[]'::json,
                    summary JSON,
                    requested_by VARCHAR(80),
                    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    started_at TIMESTAMP,
                    completed_at TIMESTAMP,
                    last_progress_at TIMESTAMP
                )
            """))
            db.session.commit()
            print(f"  [OK] Created table {table_name}")

        indexes = [
            ("ix_case_ioc_enhancement_runs_run_uuid", table_name, "run_uuid"),
            ("ix_case_ioc_enhancement_runs_case_id", table_name, "case_id"),
            ("ix_case_ioc_enhancement_runs_status", table_name, "status"),
            ("ix_case_ioc_enhancement_runs_celery_task_id", table_name, "celery_task_id"),
            ("ix_case_ioc_enhancement_runs_last_progress_at", table_name, "last_progress_at"),
        ]
        for index_name, target_table, columns in indexes:
            try:
                _create_index(index_name, target_table, columns)
            except Exception as exc:
                db.session.rollback()
                print(f"  [ERROR] Failed to create index {index_name}: {exc}")

        print("\nIOC enhancement run migration complete.")
        return True


if __name__ == "__main__":
    try:
        run_migration()
        sys.exit(0)
    except Exception as exc:
        print(f"Migration failed: {exc}")
        raise
