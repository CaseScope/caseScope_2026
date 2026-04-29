#!/usr/bin/env python3
"""Add structured IOC source metadata contribution history."""

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
    return bool(
        db.session.execute(
            db.text(sql),
            {"table_name": table_name, "column_name": column_name},
        ).fetchone()
    )


def run_migration() -> bool:
    app = create_app()

    with app.app_context():
        table_name = "iocs"
        column_name = "source_metadata"
        try:
            if _column_exists(table_name, column_name):
                print(f"  [SKIP] Column {table_name}.{column_name} already exists")
            else:
                db.session.execute(
                    db.text(
                        f"ALTER TABLE {table_name} "
                        f"ADD COLUMN {column_name} JSON NOT NULL DEFAULT '[]'::json"
                    )
                )
                db.session.commit()
                print(f"  [OK] Added column {table_name}.{column_name}")

            db.session.execute(
                db.text(
                    f"UPDATE {table_name} "
                    f"SET {column_name} = '[]'::json "
                    f"WHERE {column_name} IS NULL"
                )
            )
            db.session.commit()
            print(f"  [OK] Backfilled {table_name}.{column_name}")
        except Exception as exc:
            db.session.rollback()
            print(f"  [ERROR] Failed to add {table_name}.{column_name}: {exc}")
            raise

        print("\nIOC source metadata migration complete.")
        return True


if __name__ == "__main__":
    try:
        run_migration()
        sys.exit(0)
    except Exception as exc:
        print(f"Migration failed: {exc}")
        raise
