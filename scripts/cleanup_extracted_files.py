#!/usr/bin/env python3
"""
Cleanup Script: Hide Files Extracted from ZIPs
===============================================
Fixes Issue #3: ZIP filename appearing multiple times

This script identifies files that were extracted from ZIPs and marks them as hidden
so they don't appear in the main file list.

Criteria for identifying extracted files:
1. original_filename ends with .zip
2. filename does NOT end with .zip
3. is_virtual = False (not from old ZIP-centric system)
4. is_container = False (not a ZIP container itself)

These files should be hidden from the main view.
"""

import sys
import os

# Add app directory to path
app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if app_dir not in sys.path:
    sys.path.insert(0, app_dir)

from app.main import app, db
from app.models import CaseFile

def cleanup_extracted_files():
    """Mark files extracted from ZIPs as hidden"""
    
    with app.app_context():
        # Find files where:
        # - original_filename is a ZIP
        # - filename is NOT a ZIP
        # - is_virtual = False
        # - is_container = False
        # - not already hidden
        
        extracted_files = CaseFile.query.filter(
            CaseFile.original_filename.like('%.zip'),
            ~CaseFile.filename.like('%.zip'),
            CaseFile.is_virtual == False,
            CaseFile.is_container == False,
            CaseFile.is_hidden == False
        ).all()
        
        print(f"Found {len(extracted_files)} files extracted from ZIPs")
        
        if extracted_files:
            print("\nSample files to be hidden:")
            for file in extracted_files[:10]:
                print(f"  - {file.filename} (from {file.original_filename})")
            
            if len(extracted_files) > 10:
                print(f"  ... and {len(extracted_files) - 10} more")
            
            # Ask for confirmation
            response = input(f"\nMark these {len(extracted_files)} files as hidden? (yes/no): ")
            
            if response.lower() in ['yes', 'y']:
                for file in extracted_files:
                    file.is_hidden = True
                
                db.session.commit()
                print(f"\n✓ Marked {len(extracted_files)} files as hidden")
                print("These files will no longer appear in the main file list.")
            else:
                print("\nOperation cancelled")
        else:
            print("No files need to be hidden")

if __name__ == '__main__':
    cleanup_extracted_files()

