#!/usr/bin/env python3
"""Migration: Add hidden column to known_systems, known_users, and iocs tables

This migration adds the 'hidden' boolean column to support excluding items from reports.

Usage:
    python migrations/add_hidden_columns.py
"""
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db

def run_migration():
    """Add hidden column to tables if not present"""
    app = create_app()
    
    with app.app_context():
        from sqlalchemy import inspect, text
        
        inspector = inspect(db.engine)
        
        tables_to_update = [
            ('known_systems', 'hidden'),
            ('known_users', 'hidden'),
            ('iocs', 'hidden')
        ]
        
        for table_name, column_name in tables_to_update:
            if table_name not in inspector.get_table_names():
                print(f"Table {table_name} does not exist, skipping")
                continue
            
            columns = [c['name'] for c in inspector.get_columns(table_name)]
            
            if column_name not in columns:
                print(f"Adding {column_name} column to {table_name}...")
                
                # Add the column with default value
                db.session.execute(text(f"""
                    ALTER TABLE {table_name} 
                    ADD COLUMN {column_name} BOOLEAN NOT NULL DEFAULT FALSE
                """))
                db.session.commit()
                
                print(f"Successfully added {column_name} to {table_name}")
            else:
                print(f"Column {column_name} already exists in {table_name}")
        
        print("Migration complete")


if __name__ == '__main__':
    run_migration()
