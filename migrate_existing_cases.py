#!/usr/bin/env python3
"""
Migration Script: Mark existing extracted files as standalone
Converts pre-ZIP-architecture cases to new structure
"""

import sys
import os

# Add app directory to path
sys.path.insert(0, '/opt/casescope/app')

from models import CaseFile
from main import db, app

def migrate_case_files():
    """Mark all existing files as standalone (not virtual, not in container)"""
    
    with app.app_context():
        # Get all existing case files that don't have the new flags set
        files = CaseFile.query.filter(
            CaseFile.is_container == False,
            CaseFile.is_virtual == False,
            CaseFile.parent_file_id == None
        ).all()
        
        print(f"Found {len(files)} files to migrate")
        
        migrated = 0
        for file in files:
            # Set target_index based on file type
            if file.file_type == 'evtx':
                file.target_index = f"case_{file.case_id}"
            elif file.file_type in ['ndjson', 'json', 'jsonl']:
                file.target_index = f"case_{file.case_id}"
            elif file.file_type == 'zip':
                # Existing ZIPs become containers
                file.is_container = True
                file.target_index = None  # Containers don't have a target
            else:
                file.target_index = f"case_{file.case_id}"
            
            # These are standalone files (already in storage)
            # is_container = False (not a ZIP)
            # is_virtual = False (physically in storage)
            # parent_file_id = None (no parent container)
            
            migrated += 1
            
            if migrated % 50 == 0:
                print(f"Migrated {migrated} files...")
                db.session.commit()
        
        db.session.commit()
        print(f"\n✅ Migration complete! {migrated} files marked as standalone")
        print(f"   All files are now compatible with ZIP-centric architecture")

if __name__ == '__main__':
    print("=" * 60)
    print("CaseScope Migration: Existing Files → Standalone")
    print("=" * 60)
    print()
    
    migrate_case_files()
    
    print()
    print("Migration successful! System ready for new ZIP-centric uploads.")

