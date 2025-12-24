"""
Database Migration: Add 'active' field to known_user table
v1.20.0 - Track whether known users are currently active in the environment

Run with:
    cd /opt/casescope/app
    source /opt/casescope/venv/bin/activate
    sudo -u casescope python3 migrations/add_active_field_to_known_user.py
"""

import sys
sys.path.insert(0, '/opt/casescope/app')

from main import app, db

def migrate():
    """Add active field to known_user table"""
    with app.app_context():
        try:
            # Check if column already exists
            from sqlalchemy import inspect, text
            inspector = inspect(db.engine)
            columns = [col['name'] for col in inspector.get_columns('known_user')]
            
            if 'active' in columns:
                print("✅ Column 'active' already exists in known_user table")
                return True
            
            print("📝 Adding 'active' column to known_user table...")
            
            # Add column with default value TRUE (existing users assumed active)
            db.session.execute(text(
                "ALTER TABLE known_user ADD COLUMN active BOOLEAN NOT NULL DEFAULT TRUE"
            ))
            db.session.commit()
            
            print("✅ Migration completed successfully")
            print(f"   - Added 'active' column (BOOLEAN, default=TRUE)")
            
            # Show stats
            from models import KnownUser
            total_users = KnownUser.query.count()
            print(f"   - {total_users} existing users now marked as active")
            
            return True
            
        except Exception as e:
            print(f"❌ Migration failed: {e}")
            db.session.rollback()
            return False

if __name__ == '__main__':
    print("=" * 60)
    print("Known User 'active' Field Migration - v1.20.0")
    print("=" * 60)
    
    success = migrate()
    
    if success:
        print("\n✅ Migration completed successfully!")
    else:
        print("\n❌ Migration failed. Please check the error above.")
        sys.exit(1)

