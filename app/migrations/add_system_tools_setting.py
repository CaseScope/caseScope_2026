"""
Migration: Add SystemToolsSetting table for known-good exclusions

Created: 2025-11-29
Version: 1.38.0

This migration creates the system_tools_setting table which stores:
- RMM tool exclusions (LabTech, Datto, Kaseya, etc.)
- Remote connectivity tool exclusions with known-good session IDs
- Known-good IP addresses and CIDR ranges

Usage:
    cd /opt/casescope/app
    sudo -u casescope ../venv/bin/python3 migrations/add_system_tools_setting.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import app, db
from sqlalchemy import text


def run_migration():
    """Create the system_tools_setting table"""
    
    with app.app_context():
        # Check if table already exists
        result = db.session.execute(text("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_name = 'system_tools_setting'
            );
        """))
        exists = result.scalar()
        
        if exists:
            print("✓ Table 'system_tools_setting' already exists. Skipping creation.")
            return True
        
        print("Creating 'system_tools_setting' table...")
        
        # Create the table
        db.session.execute(text("""
            CREATE TABLE system_tools_setting (
                id SERIAL PRIMARY KEY,
                setting_type VARCHAR(50) NOT NULL,
                tool_name VARCHAR(100),
                executable_pattern VARCHAR(500),
                known_good_ids TEXT,
                ip_or_cidr VARCHAR(50),
                description VARCHAR(500),
                created_by INTEGER REFERENCES "user"(id),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE
            );
        """))
        
        # Create indexes
        db.session.execute(text("""
            CREATE INDEX idx_system_tools_setting_type ON system_tools_setting(setting_type);
        """))
        db.session.execute(text("""
            CREATE INDEX idx_system_tools_setting_active ON system_tools_setting(is_active);
        """))
        
        db.session.commit()
        print("✓ Table 'system_tools_setting' created successfully!")
        print("✓ Indexes created on setting_type and is_active columns.")
        
        return True


if __name__ == '__main__':
    try:
        success = run_migration()
        if success:
            print("\n✅ Migration completed successfully!")
            sys.exit(0)
        else:
            print("\n❌ Migration failed!")
            sys.exit(1)
    except Exception as e:
        print(f"\n❌ Migration error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

