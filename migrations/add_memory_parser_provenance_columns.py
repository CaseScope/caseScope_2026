#!/usr/bin/env python3
"""Add persisted parser provenance columns to memory artifact tables."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db


MEMORY_TABLES = (
    'memory_processes',
    'memory_network',
    'memory_services',
    'memory_malfind',
    'memory_modules',
    'memory_credentials',
    'memory_sids',
    'memory_info',
)


def _column_exists(table_name: str, column_name: str) -> bool:
    sql = """
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = :table_name
          AND column_name = :column_name
    """
    return bool(
        db.session.execute(
            db.text(sql),
            {'table_name': table_name, 'column_name': column_name},
        ).fetchone()
    )


def run_migration() -> bool:
    app = create_app()

    with app.app_context():
        for table_name in MEMORY_TABLES:
            try:
                if _column_exists(table_name, 'parser_provenance'):
                    print(f"  [SKIP] Column {table_name}.parser_provenance already exists")
                    continue

                db.session.execute(
                    db.text(
                        f"ALTER TABLE {table_name} "
                        "ADD COLUMN parser_provenance JSONB"
                    )
                )
                db.session.commit()
                print(f"  [OK] Added column {table_name}.parser_provenance")
            except Exception as exc:
                db.session.rollback()
                print(f"  [ERROR] Failed to add {table_name}.parser_provenance: {exc}")

        print("\nMemory parser provenance migration complete.")
        return True


if __name__ == '__main__':
    try:
        run_migration()
        sys.exit(0)
    except Exception as exc:
        print(f"Migration failed: {exc}")
        raise
