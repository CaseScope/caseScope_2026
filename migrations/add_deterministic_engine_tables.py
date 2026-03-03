#!/usr/bin/env python3
"""Database migration for Deterministic Evidence Engine

Adds to ai_analysis_results:
- deterministic_score (Float, indexed)
- ai_adjustment (Float)
- coverage_quality (Float, indexed)
- evidence_package (JSON)

Creates new table:
- analyst_verdicts (for delta validation pipeline)

Author: CaseScope
Date: March 2026
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db


def run_migration():
    """Add deterministic engine columns and analyst_verdicts table"""
    app = create_app()

    with app.app_context():
        # --- Add columns to ai_analysis_results ---
        columns_to_add = [
            ("deterministic_score", "FLOAT"),
            ("ai_adjustment", "FLOAT"),
            ("coverage_quality", "FLOAT"),
            ("evidence_package", "JSON"),
        ]

        for col_name, col_type in columns_to_add:
            try:
                check_sql = """
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'ai_analysis_results'
                    AND column_name = :col
                """
                exists = db.session.execute(
                    db.text(check_sql), {'col': col_name}
                ).fetchone()

                if exists:
                    print(f"  [SKIP] Column ai_analysis_results.{col_name} already exists")
                    continue

                alter_sql = f"ALTER TABLE ai_analysis_results ADD COLUMN {col_name} {col_type}"
                db.session.execute(db.text(alter_sql))
                db.session.commit()
                print(f"  [OK] Added column ai_analysis_results.{col_name} ({col_type})")
            except Exception as e:
                print(f"  [ERROR] Failed to add column {col_name}: {e}")
                db.session.rollback()

        # --- Add indexes on new columns ---
        indexes_to_create = [
            ("ix_ai_analysis_det_score", "ai_analysis_results", "deterministic_score"),
            ("ix_ai_analysis_cov_quality", "ai_analysis_results", "coverage_quality"),
        ]

        for idx_name, table_name, columns in indexes_to_create:
            try:
                check_sql = "SELECT 1 FROM pg_indexes WHERE indexname = :idx"
                exists = db.session.execute(
                    db.text(check_sql), {'idx': idx_name}
                ).fetchone()

                if exists:
                    print(f"  [SKIP] Index {idx_name} already exists")
                    continue

                create_sql = f"CREATE INDEX {idx_name} ON {table_name} ({columns})"
                db.session.execute(db.text(create_sql))
                db.session.commit()
                print(f"  [OK] Created index {idx_name} on {table_name}({columns})")
            except Exception as e:
                print(f"  [ERROR] Failed to create index {idx_name}: {e}")
                db.session.rollback()

        # --- Create analyst_verdicts table ---
        try:
            table_check = """
                SELECT 1 FROM information_schema.tables
                WHERE table_name = 'analyst_verdicts'
            """
            exists = db.session.execute(db.text(table_check)).fetchone()

            if exists:
                print("  [SKIP] Table analyst_verdicts already exists")
            else:
                create_sql = """
                    CREATE TABLE analyst_verdicts (
                        id SERIAL PRIMARY KEY,
                        analysis_result_id INTEGER NOT NULL
                            REFERENCES ai_analysis_results(id),
                        verdict VARCHAR(20) NOT NULL,
                        analyst_id INTEGER NOT NULL REFERENCES users(id),
                        notes TEXT,
                        created_at TIMESTAMP DEFAULT NOW()
                    )
                """
                db.session.execute(db.text(create_sql))

                db.session.execute(db.text(
                    "CREATE INDEX ix_analyst_verdicts_result "
                    "ON analyst_verdicts (analysis_result_id)"
                ))
                db.session.execute(db.text(
                    "CREATE INDEX ix_analyst_verdicts_verdict "
                    "ON analyst_verdicts (verdict)"
                ))
                db.session.commit()
                print("  [OK] Created table analyst_verdicts with indexes")
        except Exception as e:
            print(f"  [ERROR] Failed to create analyst_verdicts table: {e}")
            db.session.rollback()

        print("\nDeterministic engine migration complete.")
        return True


if __name__ == '__main__':
    print("=" * 60)
    print("Deterministic Evidence Engine Migration")
    print("=" * 60)
    print()

    try:
        run_migration()
        sys.exit(0)
    except Exception as e:
        print(f"Migration failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
