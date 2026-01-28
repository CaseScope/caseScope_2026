#!/usr/bin/env python3
"""Migration: Add attack_description field to cases table

Adds field for documenting attack narrative:
- attack_description: Analyst narrative explaining what occurred

Usage:
    python migrations/add_attack_description.py
"""
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db

def run_migration():
    """Add attack_description field to cases table"""
    app = create_app()
    
    with app.app_context():
        from sqlalchemy import inspect, text
        
        inspector = inspect(db.engine)
        
        if 'cases' not in inspector.get_table_names():
            print("Cases table does not exist")
            return
        
        columns = [c['name'] for c in inspector.get_columns('cases')]
        
        if 'attack_description' not in columns:
            print("Adding attack_description column...")
            db.session.execute(text("""
                ALTER TABLE cases ADD COLUMN attack_description TEXT
            """))
            db.session.commit()
            print("Successfully added attack_description")
        else:
            print("Column attack_description already exists")
        
        print("Migration complete")


if __name__ == '__main__':
    run_migration()
