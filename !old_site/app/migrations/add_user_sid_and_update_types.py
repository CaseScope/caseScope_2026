"""
Database Migration: Add user_sid field and update user_type values for Known Users
Version: 1.21.0
Date: November 22, 2025

CHANGES:
1. Add user_sid column (VARCHAR(255), nullable, indexed)
   - Stores Windows Security Identifier (SID)
   - Example: S-1-5-21-3623811015-3361044348-30300820-1013
   - Used for precise user tracking across domain/local contexts

2. Update user_type enum values:
   - OLD: 'domain', 'local', '-' (dash for unknown)
   - NEW: 'domain', 'local', 'unknown', 'invalid'
   - Migrate existing '-' → 'unknown'
   - 'invalid' type for users that should not exist (e.g., disabled accounts that show activity)

PURPOSE:
- Integration with IOC system (v1.21.0)
- Better forensic tracking with SID support
- Clearer user classification (unknown vs invalid)
- Prepare for automatic IOC ↔ Known User synchronization

USAGE:
    /opt/casescope/venv/bin/python app/migrations/add_user_sid_and_update_types.py
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import db, app
from sqlalchemy import text

def migrate():
    """Apply migration"""
    print("=" * 80)
    print("MIGRATION: Add user_sid field and update user_type values")
    print("=" * 80)
    
    with app.app_context():
        try:
            # Step 1: Add user_sid column
            print("\n[1/3] Adding user_sid column...")
            db.session.execute(text("""
                ALTER TABLE known_user 
                ADD COLUMN IF NOT EXISTS user_sid VARCHAR(255);
            """))
            db.session.commit()
            print("✅ user_sid column added")
            
            # Step 2: Add index on user_sid
            print("\n[2/3] Adding index on user_sid...")
            db.session.execute(text("""
                CREATE INDEX IF NOT EXISTS ix_known_user_user_sid 
                ON known_user(user_sid);
            """))
            db.session.commit()
            print("✅ Index created on user_sid")
            
            # Step 3: Update user_type values (dash → unknown)
            print("\n[3/3] Migrating user_type values ('-' → 'unknown')...")
            result = db.session.execute(text("""
                UPDATE known_user 
                SET user_type = 'unknown' 
                WHERE user_type = '-';
            """))
            db.session.commit()
            rows_updated = result.rowcount
            print(f"✅ Updated {rows_updated} rows: '-' → 'unknown'")
            
            # Verify migration
            print("\n" + "=" * 80)
            print("VERIFICATION")
            print("=" * 80)
            
            # Check column exists
            result = db.session.execute(text("""
                SELECT column_name, data_type, is_nullable
                FROM information_schema.columns
                WHERE table_name = 'known_user' AND column_name = 'user_sid';
            """))
            col_info = result.fetchone()
            if col_info:
                print(f"✅ user_sid column: {col_info[1]} (nullable: {col_info[2]})")
            else:
                print("❌ user_sid column NOT FOUND")
                return False
            
            # Check index exists
            result = db.session.execute(text("""
                SELECT indexname 
                FROM pg_indexes 
                WHERE tablename = 'known_user' AND indexname = 'ix_known_user_user_sid';
            """))
            idx_info = result.fetchone()
            if idx_info:
                print(f"✅ Index exists: {idx_info[0]}")
            else:
                print("⚠️  Index not found (may not be critical)")
            
            # Check user_type distribution
            result = db.session.execute(text("""
                SELECT user_type, COUNT(*) as count
                FROM known_user
                GROUP BY user_type
                ORDER BY count DESC;
            """))
            print("\n📊 user_type distribution:")
            for row in result:
                print(f"   - {row[0]}: {row[1]} users")
            
            # Check for remaining dashes (should be 0)
            result = db.session.execute(text("""
                SELECT COUNT(*) FROM known_user WHERE user_type = '-';
            """))
            dash_count = result.scalar()
            if dash_count > 0:
                print(f"\n⚠️  WARNING: {dash_count} users still have '-' as user_type")
            else:
                print("\n✅ No users with '-' user_type (migration complete)")
            
            print("\n" + "=" * 80)
            print("✅ MIGRATION SUCCESSFUL")
            print("=" * 80)
            return True
            
        except Exception as e:
            print(f"\n❌ MIGRATION FAILED: {e}")
            db.session.rollback()
            return False

if __name__ == '__main__':
    success = migrate()
    sys.exit(0 if success else 1)
