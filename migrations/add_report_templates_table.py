#!/usr/bin/env python3
"""Migration: Create report_templates table for report template metadata

This migration creates the report_templates table if it doesn't exist.
SQLAlchemy's create_all() should handle this automatically, but this
script can be run manually if needed.

Usage:
    python migrations/add_report_templates_table.py
"""
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db
from models.report_template import ReportTemplate

def run_migration():
    """Create report_templates table if it doesn't exist"""
    app = create_app()
    
    with app.app_context():
        from sqlalchemy import inspect
        
        inspector = inspect(db.engine)
        
        if 'report_templates' not in inspector.get_table_names():
            print("Creating report_templates table...")
            
            # Create the table
            ReportTemplate.__table__.create(db.engine)
            
            print("Successfully created report_templates table")
            
            # Create the templates folder if it doesn't exist
            template_folder = ReportTemplate.get_template_folder()
            if not os.path.exists(template_folder):
                os.makedirs(template_folder, exist_ok=True)
                print(f"Created templates folder: {template_folder}")
            
            # Initial scan for any existing templates
            result = ReportTemplate.scan_templates(updated_by='system')
            print(f"Initial scan: {result['added']} templates found")
            
        else:
            print("report_templates table already exists")
            
            # Check if all columns exist
            columns = [c['name'] for c in inspector.get_columns('report_templates')]
            model_columns = [c.name for c in ReportTemplate.__table__.columns]
            
            missing = set(model_columns) - set(columns)
            if missing:
                print(f"Warning: Missing columns in existing table: {missing}")
                print("You may need to manually add these columns or drop/recreate the table")
            else:
                print("All expected columns present")


if __name__ == '__main__':
    run_migration()
