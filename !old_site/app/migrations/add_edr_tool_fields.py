#!/usr/bin/env python3
"""
Migration: Add EDR tool fields to system_tools_setting table
Version: 1.40.0
Date: 2025-11-29

Adds fields for EDR/Security tools that need context-aware exclusion:
- exclude_routine: Whether to exclude routine health checks
- keep_responses: Whether to keep isolation/response actions  
- routine_commands: JSON list of routine commands to exclude
- response_patterns: JSON list of response patterns to keep
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import app, db
from sqlalchemy import text


def run_migration():
    """Add EDR tool fields to system_tools_setting table."""
    
    with app.app_context():
        conn = db.engine.connect()
        
        # Check if columns already exist
        result = conn.execute(text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'system_tools_setting' 
            AND column_name = 'exclude_routine'
        """))
        
        if result.fetchone():
            print("Migration already applied - EDR fields exist")
            conn.close()
            return True
        
        print("Adding EDR tool fields to system_tools_setting table...")
        
        try:
            # Add exclude_routine column
            conn.execute(text("""
                ALTER TABLE system_tools_setting 
                ADD COLUMN exclude_routine BOOLEAN DEFAULT TRUE
            """))
            print("  - Added exclude_routine column")
            
            # Add keep_responses column
            conn.execute(text("""
                ALTER TABLE system_tools_setting 
                ADD COLUMN keep_responses BOOLEAN DEFAULT TRUE
            """))
            print("  - Added keep_responses column")
            
            # Add routine_commands column
            conn.execute(text("""
                ALTER TABLE system_tools_setting 
                ADD COLUMN routine_commands TEXT
            """))
            print("  - Added routine_commands column")
            
            # Add response_patterns column
            conn.execute(text("""
                ALTER TABLE system_tools_setting 
                ADD COLUMN response_patterns TEXT
            """))
            print("  - Added response_patterns column")
            
            conn.commit()
            print("Migration completed successfully!")
            
        except Exception as e:
            print(f"Migration failed: {e}")
            conn.rollback()
            conn.close()
            return False
        
        conn.close()
        return True


if __name__ == '__main__':
    success = run_migration()
    sys.exit(0 if success else 1)

