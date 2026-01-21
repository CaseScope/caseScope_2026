#!/usr/bin/env python3
"""Database migration to add Ask AI History table

Creates the ask_ai_history table for server-side storage of 
Ask AI conversations, enabling cross-device persistence.

Author: CaseScope
Date: January 2026
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db


def run_migration():
    """Create the ask_ai_history table"""
    app = create_app()
    
    with app.app_context():
        # Check if table already exists
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        existing_tables = inspector.get_table_names()
        
        if 'ask_ai_history' in existing_tables:
            print("Table 'ask_ai_history' already exists - skipping creation")
            return True
        
        print("Creating 'ask_ai_history' table...")
        
        # Import model to register with SQLAlchemy
        from models.rag import AskAIHistory
        
        # Create the table
        db.create_all()
        
        # Add indexes
        indexes = [
            ("idx_ask_ai_history_case_user", "ask_ai_history", "case_id, user_id"),
            ("idx_ask_ai_history_created_at", "ask_ai_history", "created_at DESC"),
        ]
        
        for index_name, table_name, columns in indexes:
            try:
                db.session.execute(db.text(f"CREATE INDEX IF NOT EXISTS {index_name} ON {table_name} ({columns})"))
                print(f"  Created index: {index_name}")
            except Exception as e:
                print(f"  Warning creating index {index_name}: {e}")
        
        db.session.commit()
        print("Table 'ask_ai_history' created successfully!")
        
        return True


if __name__ == '__main__':
    print("=" * 60)
    print("Ask AI History Table Migration")
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
