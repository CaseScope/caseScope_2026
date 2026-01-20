#!/usr/bin/env python3
"""Migration: Create pcap_files table for PCAP file tracking

This migration creates the pcap_files table if it doesn't exist.
SQLAlchemy's create_all() should handle this automatically, but this
script can be run manually if needed.

Usage:
    python migrations/add_pcap_files_table.py
"""
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db
from models.pcap_file import PcapFile

def run_migration():
    """Create pcap_files table if it doesn't exist"""
    app = create_app()
    
    with app.app_context():
        from sqlalchemy import inspect
        
        inspector = inspect(db.engine)
        
        if 'pcap_files' not in inspector.get_table_names():
            print("Creating pcap_files table...")
            
            # Create the table
            PcapFile.__table__.create(db.engine)
            
            print("Successfully created pcap_files table")
        else:
            print("pcap_files table already exists")
            
            # Check if all columns exist
            columns = [c['name'] for c in inspector.get_columns('pcap_files')]
            model_columns = [c.name for c in PcapFile.__table__.columns]
            
            missing = set(model_columns) - set(columns)
            if missing:
                print(f"Warning: Missing columns in existing table: {missing}")
                print("You may need to manually add these columns or drop/recreate the table")
            else:
                print("All expected columns present")


if __name__ == '__main__':
    run_migration()
