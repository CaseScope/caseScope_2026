#!/usr/bin/env python3
"""Migration: Add remediation documentation fields to cases table

Adds fields for documenting incident response actions:
- containment_actions
- eradication_actions
- recovery_actions
- lessons_learned

Usage:
    python migrations/add_remediation_fields.py
"""
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db

def run_migration():
    """Add remediation fields to cases table"""
    app = create_app()
    
    with app.app_context():
        from sqlalchemy import inspect, text
        
        inspector = inspect(db.engine)
        
        if 'cases' not in inspector.get_table_names():
            print("Cases table does not exist")
            return
        
        columns = [c['name'] for c in inspector.get_columns('cases')]
        
        fields_to_add = [
            ('containment_actions', 'TEXT'),
            ('eradication_actions', 'TEXT'),
            ('recovery_actions', 'TEXT'),
            ('lessons_learned', 'TEXT')
        ]
        
        for field_name, field_type in fields_to_add:
            if field_name not in columns:
                print(f"Adding {field_name} column...")
                db.session.execute(text(f"""
                    ALTER TABLE cases ADD COLUMN {field_name} {field_type}
                """))
                db.session.commit()
                print(f"Successfully added {field_name}")
            else:
                print(f"Column {field_name} already exists")
        
        print("Migration complete")


if __name__ == '__main__':
    run_migration()
