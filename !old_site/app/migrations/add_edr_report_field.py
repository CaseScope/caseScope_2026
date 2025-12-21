#!/usr/bin/env python3
"""
Migration: Add edr_report field to Case table
Version: 1.37.0
Date: 2025-11-29

This migration adds the edr_report field to store EDR/MDR reports
from vendors like Huntress, Blackpoint, CrowdStrike, etc.
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from sqlalchemy import text


def run_migration(db_session):
    """Add edr_report column to case table."""
    
    print("=" * 60)
    print("Migration: Add edr_report field to Case table")
    print("=" * 60)
    
    try:
        # Check if column already exists
        result = db_session.execute(text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'case' AND column_name = 'edr_report'
        """))
        
        if result.fetchone():
            print("✓ Column 'edr_report' already exists in 'case' table")
            return True
        
        # Add the column
        print("Adding 'edr_report' column to 'case' table...")
        db_session.execute(text("""
            ALTER TABLE "case" 
            ADD COLUMN edr_report TEXT
        """))
        
        db_session.commit()
        print("✓ Successfully added 'edr_report' column")
        
        return True
        
    except Exception as e:
        print(f"✗ Migration failed: {e}")
        db_session.rollback()
        return False


if __name__ == '__main__':
    from app.models import db
    from flask import Flask
    
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
        'DATABASE_URL', 
        'postgresql://casescope:casescope@localhost/casescope'
    )
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    db.init_app(app)
    
    with app.app_context():
        success = run_migration(db.session)
        sys.exit(0 if success else 1)

