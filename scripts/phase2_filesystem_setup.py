#!/usr/bin/env python3
"""
PHASE 2: File System Setup
Creates upload folder structure to be used during case creation
"""

import os
import sys

def create_base_directories():
    """Create base upload directories if they don't exist"""
    print("=" * 60)
    print("PHASE 2: FILE SYSTEM SETUP")
    print("=" * 60)
    print()
    
    base_dirs = [
        '/opt/casescope/uploads',
        '/opt/casescope/uploads/web',
        '/opt/casescope/uploads/sftp',
        '/opt/casescope/staging',
        '/opt/casescope/case_files'  # Storage folder
    ]
    
    print("[1/1] Creating base directory structure...")
    for directory in base_dirs:
        try:
            os.makedirs(directory, mode=0o770, exist_ok=True)
            print(f"  ✓ Created/verified: {directory}")
        except Exception as e:
            print(f"  ! Error creating {directory}: {e}")
            return False
    
    print()
    print("=" * 60)
    print("PHASE 2 COMPLETE: Base directories created")
    print("=" * 60)
    print()
    print("Note: Case-specific folders will be created when cases are created")
    print("  - /opt/casescope/uploads/web/<case_id>/")
    print("  - /opt/casescope/uploads/sftp/<case_id>/")
    print("  - /opt/casescope/staging/<case_id>/ (created when processing starts)")
    print("  - /opt/casescope/case_files/<case_id>/ (created when processing starts)")
    print()
    return True

if __name__ == '__main__':
    success = create_base_directories()
    sys.exit(0 if success else 1)

