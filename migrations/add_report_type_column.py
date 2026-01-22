#!/usr/bin/env python3
"""Migration: Add report_type column to report_templates table

Adds a report_type column to categorize templates by their report type:
- dfir: Full DFIR report with exec summary, timeline, IOCs
- timeline: Detailed timeline report with event grouping
- detailed_iocs: IOC-focused report with enrichment data

Usage:
    python migrations/add_report_type_column.py
"""
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db
from models.report_template import ReportTemplate, ReportType


def run_migration():
    """Add report_type column to report_templates table"""
    app = create_app()
    
    with app.app_context():
        from sqlalchemy import inspect, text
        
        inspector = inspect(db.engine)
        
        # Check if table exists
        if 'report_templates' not in inspector.get_table_names():
            print("report_templates table does not exist. Creating...")
            ReportTemplate.__table__.create(db.engine)
            print("Table created.")
            return
        
        # Check if column already exists
        columns = [c['name'] for c in inspector.get_columns('report_templates')]
        
        if 'report_type' in columns:
            print("report_type column already exists")
        else:
            print("Adding report_type column...")
            
            # Add the column with default value
            db.session.execute(text(
                "ALTER TABLE report_templates ADD COLUMN report_type VARCHAR(50) DEFAULT 'dfir'"
            ))
            db.session.commit()
            print("Column added successfully")
        
        # Update existing templates based on filename patterns
        print("\nUpdating existing templates with detected report types...")
        templates = ReportTemplate.query.all()
        updated = 0
        
        for template in templates:
            # Only update if not already set or is the default 'dfir'
            detected_type = ReportTemplate._detect_report_type_from_filename(template.filename)
            
            if template.report_type != detected_type:
                old_type = template.report_type
                template.report_type = detected_type
                print(f"  {template.filename}: {old_type} -> {detected_type}")
                updated += 1
        
        if updated > 0:
            db.session.commit()
            print(f"\nUpdated {updated} template(s)")
        else:
            print("No updates needed")
        
        # Show final state
        print("\nCurrent templates:")
        for t in ReportTemplate.query.all():
            label = ReportType.labels().get(t.report_type, t.report_type)
            print(f"  {t.id}: {t.filename} -> {t.display_name} [{label}]")


if __name__ == '__main__':
    run_migration()
