#!/usr/bin/env python3
"""
Migration: Add Archive Jobs Table

Creates the archive_jobs table for tracking case archive/restore operations.

Run with: python migrations/add_archive_jobs_table.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db
from models.archive_job import ArchiveJob


def migrate():
    """Create archive_jobs table"""
    app = create_app()
    
    with app.app_context():
        table = ArchiveJob.__table__
        
        if not db.engine.dialect.has_table(db.engine.connect(), table.name):
            table.create(db.engine)
            print(f"✓ Created table: {table.name}")
            print("\nMigration complete: 1 table created")
        else:
            print(f"○ Table already exists: {table.name}")
            print("\nMigration complete: 0 tables created (already exists)")
        
        return True


if __name__ == '__main__':
    migrate()
