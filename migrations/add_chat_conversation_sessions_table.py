#!/usr/bin/env python3
"""Database migration to add server-side chat conversation sessions.

Creates the `chat_conversation_sessions` table used to keep the backend
authoritative for per-user, per-case DFIR chat history.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db


def run_migration():
    """Create the chat_conversation_sessions table and indexes."""
    app = create_app()

    with app.app_context():
        from sqlalchemy import inspect

        inspector = inspect(db.engine)
        existing_tables = inspector.get_table_names()

        if 'chat_conversation_sessions' in existing_tables:
            print("Table 'chat_conversation_sessions' already exists - skipping creation")
            return True

        print("Creating 'chat_conversation_sessions' table...")

        from models.rag import ChatConversationSession  # noqa: F401

        db.create_all()

        indexes = [
            (
                "idx_chat_conversation_case_user",
                "chat_conversation_sessions",
                "case_id, user_id",
            ),
            (
                "idx_chat_conversation_last_activity",
                "chat_conversation_sessions",
                "last_activity_at DESC",
            ),
        ]

        for index_name, table_name, columns in indexes:
            try:
                db.session.execute(
                    db.text(
                        f"CREATE INDEX IF NOT EXISTS {index_name} ON {table_name} ({columns})"
                    )
                )
                print(f"  Created index: {index_name}")
            except Exception as exc:
                print(f"  Warning creating index {index_name}: {exc}")

        db.session.commit()
        print("Table 'chat_conversation_sessions' created successfully!")
        return True


if __name__ == '__main__':
    print("=" * 60)
    print("Chat Conversation Sessions Table Migration")
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
