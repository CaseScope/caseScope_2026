"""
Database Migration: Remove incorrect global unique constraint on known_user.username
v1.20.1 - Fix to ensure Known Users are properly case-specific

PROBLEM:
- Two unique constraints existed on known_user table:
  1. ix_known_user_username (GLOBAL - username unique across ALL cases) ❌
  2. uq_known_user_case_username (CASE-SPECIFIC - username unique per case) ✅
- The global constraint prevented same username in different cases
- This contradicted the design intent: Known Users should be case-specific
- User encountered error: "duplicate key value violates unique constraint ix_known_user_username"
  when trying to add "Guest" to their case, but "Guest" already existed in case 9

SOLUTION:
- Dropped the incorrect global unique constraint: ix_known_user_username
- Kept the correct case-specific constraint: uq_known_user_case_username
- Now users can have same username across different cases (as intended)

Run with:
    cd /opt/casescope/app
    source /opt/casescope/venv/bin/activate
    sudo -u casescope python3 migrations/remove_global_username_constraint.py
"""

import sys
sys.path.insert(0, '/opt/casescope/app')

from main import app, db

def migrate():
    """Remove global unique constraint on username, keep case-specific constraint"""
    with app.app_context():
        try:
            from sqlalchemy import text
            
            # Check if the incorrect global index exists
            result = db.session.execute(text("""
                SELECT indexname 
                FROM pg_indexes 
                WHERE tablename = 'known_user' 
                AND indexname = 'ix_known_user_username'
            """))
            
            if result.fetchone():
                print("❌ Found incorrect global unique constraint: ix_known_user_username")
                print("📝 Dropping global unique constraint...")
                
                db.session.execute(text("DROP INDEX IF EXISTS ix_known_user_username"))
                db.session.commit()
                
                print("✅ Removed global unique constraint")
            else:
                print("✅ Global unique constraint already removed")
            
            # Verify correct constraint exists
            result = db.session.execute(text("""
                SELECT conname 
                FROM pg_constraint 
                WHERE conname = 'uq_known_user_case_username'
            """))
            
            if result.fetchone():
                print("✅ Correct case-specific constraint exists: uq_known_user_case_username")
            else:
                print("⚠️  WARNING: Case-specific constraint missing!")
                return False
            
            print("\n📊 Current constraints on known_user:")
            result = db.session.execute(text("""
                SELECT indexname, indexdef 
                FROM pg_indexes 
                WHERE tablename = 'known_user'
                ORDER BY indexname
            """))
            for row in result:
                print(f"   - {row[0]}")
            
            return True
            
        except Exception as e:
            print(f"❌ Migration failed: {e}")
            db.session.rollback()
            return False

if __name__ == '__main__':
    print("=" * 70)
    print("Remove Global Username Constraint Migration - v1.20.1")
    print("=" * 70)
    
    success = migrate()
    
    if success:
        print("\n✅ Migration completed successfully!")
        print("   Known Users are now properly case-specific.")
    else:
        print("\n❌ Migration failed. Please check the error above.")
        sys.exit(1)

