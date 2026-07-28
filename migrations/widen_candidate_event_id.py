#!/usr/bin/env python3
"""Migration: widen candidate_event_sets.event_id from 20 to 255 characters.

The column was declared as a Windows Event ID, which fits in a handful of
characters, but the pipeline stages events from every source. Non-Windows
sources identify an event by something much longer: EDR telemetry uses a UUID of
36 characters, and NTFS change journal records run to 131. Across the indexed
corpus 16.2 million events in 18 of the 19 cases carry an identifier that does
not fit.

The effect was that pattern analysis aborted with StringDataRightTruncation as
soon as a matched pattern included one of those events, and because the failure
happened mid-flush it poisoned the session for everything after it, so the whole
run failed rather than that one pattern.

Usage:
    python migrations/widen_candidate_event_id.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db

TABLE = 'candidate_event_sets'
COLUMN = 'event_id'
TARGET_LENGTH = 255


def run_migration():
    app = create_app()

    with app.app_context():
        from sqlalchemy import inspect, text

        inspector = inspect(db.engine)

        if TABLE not in inspector.get_table_names():
            print(f'{TABLE} does not exist; nothing to do.')
            return

        column = next(
            (c for c in inspector.get_columns(TABLE) if c['name'] == COLUMN), None
        )
        if column is None:
            print(f'{TABLE}.{COLUMN} does not exist; nothing to do.')
            return

        current_length = getattr(column['type'], 'length', None)
        print(f'{TABLE}.{COLUMN} is currently VARCHAR({current_length})')

        if current_length is not None and current_length >= TARGET_LENGTH:
            print('Already wide enough; nothing to do.')
            return

        print(f'Widening to VARCHAR({TARGET_LENGTH})...')
        db.session.execute(
            text(f'ALTER TABLE {TABLE} ALTER COLUMN {COLUMN} TYPE VARCHAR({TARGET_LENGTH})')
        )
        db.session.commit()

        inspector = inspect(db.engine)
        column = next(c for c in inspector.get_columns(TABLE) if c['name'] == COLUMN)
        print(f'Done. {TABLE}.{COLUMN} is now VARCHAR({getattr(column["type"], "length", None)})')


if __name__ == '__main__':
    run_migration()
