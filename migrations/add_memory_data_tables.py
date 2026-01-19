#!/usr/bin/env python3
"""
Migration: Add Memory Forensics Data Tables

Creates tables for storing parsed Volatility 3 output:
- memory_processes: Process listings
- memory_network: Network connections  
- memory_services: Windows services
- memory_malfind: Suspicious memory regions
- memory_modules: Loaded DLLs
- memory_credentials: Extracted credentials
- memory_sids: Process SIDs
- memory_info: System information

Run with: python migrations/add_memory_data_tables.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models.database import db
from models.memory_data import (
    MemoryProcess, MemoryNetwork, MemoryService, MemoryMalfind,
    MemoryModule, MemoryCredential, MemorySID, MemoryInfo
)


def migrate():
    """Create memory data tables"""
    app = create_app()
    
    with app.app_context():
        # Create all new tables
        tables = [
            MemoryProcess.__table__,
            MemoryNetwork.__table__,
            MemoryService.__table__,
            MemoryMalfind.__table__,
            MemoryModule.__table__,
            MemoryCredential.__table__,
            MemorySID.__table__,
            MemoryInfo.__table__,
        ]
        
        created = []
        skipped = []
        
        for table in tables:
            if not db.engine.dialect.has_table(db.engine.connect(), table.name):
                table.create(db.engine)
                created.append(table.name)
                print(f"✓ Created table: {table.name}")
            else:
                skipped.append(table.name)
                print(f"○ Table already exists: {table.name}")
        
        print(f"\nMigration complete: {len(created)} created, {len(skipped)} skipped")
        return True


if __name__ == '__main__':
    migrate()
