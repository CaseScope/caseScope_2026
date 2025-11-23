"""
Database Migration: Add case_lock table (v1.25.0)
Creates table for tracking which user is actively working on each case
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import app, db
from sqlalchemy import text

def run_migration():
    """Add case_lock table"""
    with app.app_context():
        try:
            # Check if table already exists
            result = db.session.execute(text("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_name = 'case_lock'
                );
            """))
            table_exists = result.scalar()
            
            if table_exists:
                print("✅ case_lock table already exists, skipping migration")
                return
            
            # Create case_lock table
            print("Creating case_lock table...")
            db.session.execute(text("""
                CREATE TABLE case_lock (
                    id SERIAL PRIMARY KEY,
                    case_id INTEGER NOT NULL UNIQUE REFERENCES "case"(id) ON DELETE CASCADE,
                    user_id INTEGER NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
                    locked_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT (NOW() AT TIME ZONE 'UTC'),
                    last_activity TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT (NOW() AT TIME ZONE 'UTC'),
                    session_id VARCHAR(255) NOT NULL
                );
            """))
            
            # Create indexes
            print("Creating indexes...")
            db.session.execute(text("""
                CREATE INDEX ix_case_lock_case_id ON case_lock (case_id);
            """))
            db.session.execute(text("""
                CREATE INDEX ix_case_lock_user_id ON case_lock (user_id);
            """))
            db.session.execute(text("""
                CREATE INDEX ix_case_lock_last_activity ON case_lock (last_activity);
            """))
            
            db.session.commit()
            print("✅ Migration complete: case_lock table created")
            print("   - Table: case_lock")
            print("   - Indexes: case_id, user_id, last_activity")
            print("   - Unique constraint: case_id (one lock per case)")
            print("   - Foreign keys: case_id, user_id (CASCADE DELETE)")
            
        except Exception as e:
            db.session.rollback()
            print(f"❌ Migration failed: {e}")
            raise

if __name__ == '__main__':
    print("="*80)
    print("DATABASE MIGRATION: Add case_lock table (v1.25.0)")
    print("="*80)
    run_migration()

