#!/usr/bin/env python3
"""Migration: Create case_reports table for tracking generated reports

This migration creates the case_reports table if it doesn't exist.
SQLAlchemy's create_all() should handle this automatically, but this
script can be run manually if needed.

Usage:
    python migrations/add_case_reports_table.py
"""
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db
from models.case_report import CaseReport


def run_migration():
    """Create case_reports table if it doesn't exist"""
    app = create_app()
    
    with app.app_context():
        from sqlalchemy import inspect
        
        inspector = inspect(db.engine)
        
        if 'case_reports' not in inspector.get_table_names():
            print("Creating case_reports table...")
            
            # Create the table
            CaseReport.__table__.create(db.engine)
            
            print("Successfully created case_reports table")
            
        else:
            print("case_reports table already exists")
            
            # Check if all columns exist
            columns = [c['name'] for c in inspector.get_columns('case_reports')]
            model_columns = [c.name for c in CaseReport.__table__.columns]
            
            missing = set(model_columns) - set(columns)
            if missing:
                print(f"Warning: Missing columns in existing table: {missing}")
                print("You may need to manually add these columns or drop/recreate the table")
            else:
                print("All expected columns present")


if __name__ == '__main__':
    run_migration()
