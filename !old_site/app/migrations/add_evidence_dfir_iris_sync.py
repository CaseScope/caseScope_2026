#!/usr/bin/env python3
"""
Database Migration: Add DFIR-IRIS sync fields to evidence_file table
Run with: /opt/casescope/venv/bin/python app/migrations/add_evidence_dfir_iris_sync.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import db
from main import app
from sqlalchemy import text

def migrate():
    """Add DFIR-IRIS sync fields to evidence_file table"""
    print("=" * 80)
    print("DATABASE MIGRATION: Add DFIR-IRIS Sync Fields to evidence_file")
    print("=" * 80)
    print()
    
    with app.app_context():
        # Check if columns already exist
        result = db.session.execute(text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_schema = 'public' 
            AND table_name = 'evidence_file'
            AND column_name IN ('dfir_iris_synced', 'dfir_iris_file_id', 'dfir_iris_sync_date');
        """))
        existing_columns = [row.column_name for row in result]
        
        if 'dfir_iris_synced' in existing_columns:
            print("✅ DFIR-IRIS sync columns already exist")
            print()
            return
        
        print("Adding DFIR-IRIS sync columns to evidence_file table...")
        print()
        
        # Add the DFIR-IRIS sync columns
        db.session.execute(text("""
            ALTER TABLE evidence_file 
            ADD COLUMN IF NOT EXISTS dfir_iris_synced BOOLEAN DEFAULT FALSE,
            ADD COLUMN IF NOT EXISTS dfir_iris_file_id VARCHAR(100),
            ADD COLUMN IF NOT EXISTS dfir_iris_sync_date TIMESTAMP;
        """))
        
        # Commit changes
        db.session.commit()
        
        print("✅ DFIR-IRIS sync columns added successfully")
        print()
        
        # Verify columns were added
        result = db.session.execute(text("""
            SELECT column_name, data_type, is_nullable, column_default
            FROM information_schema.columns 
            WHERE table_name = 'evidence_file'
            AND column_name IN ('dfir_iris_synced', 'dfir_iris_file_id', 'dfir_iris_sync_date')
            ORDER BY ordinal_position;
        """))
        
        print("New Columns:")
        print("-" * 80)
        for row in result:
            default_val = row.column_default or 'NULL'
            print(f"  {row.column_name:25} {row.data_type:20} {row.is_nullable:5} {default_val}")
        print()
        
        print("=" * 80)
        print("MIGRATION COMPLETE")
        print("=" * 80)


if __name__ == '__main__':
    migrate()

