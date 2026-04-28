#!/usr/bin/env python3
"""Database migration to add Cloud AI privacy alias tables."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db


def run_migration():
    """Create privacy alias vault tables and supporting indexes."""
    app = create_app()

    with app.app_context():
        from sqlalchemy import inspect

        inspector = inspect(db.engine)
        existing_tables = set(inspector.get_table_names())

        if {'privacy_aliases', 'privacy_alias_counters'}.issubset(existing_tables):
            print("Tables 'privacy_aliases' and 'privacy_alias_counters' already exist - skipping creation")
            return True

        print("Creating Cloud AI privacy alias tables...")

        from models.privacy_alias import PrivacyAlias, PrivacyAliasCounter  # noqa: F401

        db.create_all()

        indexes = [
            (
                'idx_privacy_alias_case_type_alias',
                'privacy_aliases',
                'case_id, entity_type, alias_value',
            ),
            (
                'idx_privacy_alias_case_source',
                'privacy_aliases',
                'case_id, source',
            ),
            (
                'idx_privacy_alias_case_last_seen',
                'privacy_aliases',
                'case_id, last_seen_at DESC',
            ),
            (
                'idx_privacy_alias_counter_case_type',
                'privacy_alias_counters',
                'case_id, entity_type',
            ),
        ]

        for index_name, table_name, columns in indexes:
            try:
                db.session.execute(
                    db.text(
                        f'CREATE INDEX IF NOT EXISTS {index_name} ON {table_name} ({columns})'
                    )
                )
                print(f'  Created index: {index_name}')
            except Exception as exc:
                print(f'  Warning creating index {index_name}: {exc}')

        db.session.commit()
        print("Cloud AI privacy alias tables created successfully!")
        return True


if __name__ == '__main__':
    print('=' * 60)
    print('Cloud AI Privacy Alias Tables Migration')
    print('=' * 60)
    print()

    try:
        run_migration()
        sys.exit(0)
    except Exception as exc:
        print(f'Migration failed: {exc}')
        import traceback

        traceback.print_exc()
        sys.exit(1)
