#!/usr/bin/env python3
"""Database migration to store chat transcripts as jsonb.

The transcript column was `json`, which has no concatenation operator, so a
turn could only be saved by rewriting the whole transcript. Converting to
`jsonb` lets a turn append just its new messages.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db


def run_migration():
    """Convert chat_conversation_sessions.messages from json to jsonb."""
    app = create_app()

    with app.app_context():
        from sqlalchemy import inspect

        inspector = inspect(db.engine)
        if 'chat_conversation_sessions' not in inspector.get_table_names():
            print("Table 'chat_conversation_sessions' does not exist - nothing to convert")
            return True

        column_type = None
        for column in inspector.get_columns('chat_conversation_sessions'):
            if column['name'] == 'messages':
                column_type = str(column['type']).lower()
                break

        if column_type is None:
            print("Column 'messages' does not exist - nothing to convert")
            return True

        if 'jsonb' in column_type:
            print("Column 'messages' is already jsonb - skipping conversion")
            return True

        print(f"Converting 'messages' from {column_type} to jsonb...")
        db.session.execute(
            db.text(
                "ALTER TABLE chat_conversation_sessions "
                "ALTER COLUMN messages TYPE jsonb USING messages::text::jsonb"
            )
        )
        db.session.commit()
        print("Column 'messages' converted to jsonb successfully!")
        return True


if __name__ == '__main__':
    print("=" * 60)
    print("Chat Transcript jsonb Migration")
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
