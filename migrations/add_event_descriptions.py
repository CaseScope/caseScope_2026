"""
Database Migration: Add EventDescription table

Run this script to add the event_description table to the database
"""

import sys
import os

# Add the app directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from main import app, db
from models import EventDescription

def run_migration():
    """Create the event_description table"""
    with app.app_context():
        print("Creating event_description table...")
        db.create_all()
        print("✓ Migration complete!")
        
        # Verify table was created
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        
        if 'event_description' in tables:
            print("✓ event_description table verified")
        else:
            print("✗ Warning: event_description table not found")
        
        print("\nYou can now:")
        print("1. Navigate to Settings → EVTX Descriptions")
        print("2. Click 'Update Descriptions' to scrape event data")

if __name__ == '__main__':
    run_migration()

