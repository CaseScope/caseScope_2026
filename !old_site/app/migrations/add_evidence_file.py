#!/usr/bin/env python3
"""
Database Migration: Add evidence_file table for archival storage
Run with: python migrations/add_evidence_file.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import db
from main import app
from sqlalchemy import text

def migrate():
    """Add evidence_file table"""
    print("=" * 80)
    print("DATABASE MIGRATION: Add evidence_file Table")
    print("=" * 80)
    print()
    
    with app.app_context():
        # Check if table already exists
        result = db.session.execute(text("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = 'evidence_file'
            );
        """))
        table_exists = result.scalar()
        
        if table_exists:
            print("✅ evidence_file table already exists")
            print()
            return
        
        print("Creating evidence_file table...")
        print()
        
        # Create the evidence_file table
        db.session.execute(text("""
            CREATE TABLE evidence_file (
                id SERIAL PRIMARY KEY,
                case_id INTEGER NOT NULL REFERENCES "case"(id) ON DELETE CASCADE,
                filename VARCHAR(500) NOT NULL,
                original_filename VARCHAR(500) NOT NULL,
                file_path VARCHAR(1000) NOT NULL,
                file_size BIGINT DEFAULT 0,
                size_mb INTEGER DEFAULT 0,
                file_hash VARCHAR(64),
                file_type VARCHAR(50),
                mime_type VARCHAR(100),
                description TEXT,
                upload_source VARCHAR(20) DEFAULT 'http',
                uploaded_by INTEGER REFERENCES "user"(id) ON DELETE SET NULL,
                uploaded_at TIMESTAMP DEFAULT NOW()
            );
        """))
        
        # Create indices
        print("Creating indices...")
        db.session.execute(text("""
            CREATE INDEX idx_evidence_file_case_id ON evidence_file(case_id);
            CREATE INDEX idx_evidence_file_hash ON evidence_file(file_hash);
        """))
        
        # Commit changes
        db.session.commit()
        
        print("✅ evidence_file table created successfully")
        print("✅ Indices created successfully")
        print()
        
        # Verify table structure
        result = db.session.execute(text("""
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_name = 'evidence_file'
            ORDER BY ordinal_position;
        """))
        
        print("Table Structure:")
        print("-" * 80)
        for row in result:
            print(f"  {row.column_name:25} {row.data_type}")
        print()
        
        print("=" * 80)
        print("MIGRATION COMPLETE")
        print("=" * 80)


if __name__ == '__main__':
    migrate()

