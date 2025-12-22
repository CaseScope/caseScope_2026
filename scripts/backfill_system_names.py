#!/usr/bin/env python3
"""
Backfill script to extract system names from existing EVTX files
Run this to update files that are missing source_system data
"""

import os
import sys

# Add app directory to path
sys.path.insert(0, '/opt/casescope/app')

from main import app, db
from models import CaseFile
from parsers.evtx_parser import parse_evtx_file

def backfill_system_names(case_id):
    """Extract system names from files that don't have them"""
    
    with app.app_context():
        # Find files with no system name
        files_no_system = CaseFile.query.filter_by(
            case_id=case_id,
            source_system=None
        ).all()
        
        print(f"\n🔍 Found {len(files_no_system)} files missing system names\n")
        
        updated = 0
        no_events = 0
        no_name_found = 0
        
        for file_record in files_no_system:
            if not os.path.exists(file_record.file_path):
                print(f"❌ File not found: {file_record.filename}")
                continue
            
            # Skip files with 0 events - they're empty
            if file_record.event_count == 0:
                no_events += 1
                continue
            
            print(f"📄 {file_record.filename} ({file_record.event_count:,} events)")
            
            # Try to extract system name
            source_system = None
            
            try:
                # Read first few events to find computer name
                event_count = 0
                for event in parse_evtx_file(file_record.file_path):
                    # Try multiple field names
                    source_system = (
                        event.get('computer') or 
                        event.get('Computer') or 
                        event.get('computer_name')
                    )
                    
                    if source_system:
                        break
                    
                    event_count += 1
                    if event_count > 20:  # Check first 20 events
                        break
            
            except Exception as e:
                print(f"  ⚠️  Error parsing: {e}")
                continue
            
            # Fallback: try filename - look for pattern COMPUTERNAME_*
            if not source_system:
                parts = file_record.filename.split('_')
                # Look for segments that could be computer names
                for i, part in enumerate(parts):
                    # Skip date patterns and known prefixes
                    if part.startswith('2025') or part.startswith('MF-') or part.startswith('Microsoft'):
                        continue
                    # Look for reasonable computer name (3-15 chars, alphanumeric with dashes/dots)
                    if 3 <= len(part) <= 15 and any(c.isalpha() for c in part):
                        # Check if it looks like a hostname
                        if not part.lower().endswith(('.evtx', '.log', '.json')):
                            source_system = part
                            print(f"  📝 Extracted from filename: {source_system}")
                            break
            
            # Update database
            if source_system:
                file_record.source_system = source_system
                db.session.commit()
                print(f"  ✅ Updated: {source_system}")
                updated += 1
            else:
                print(f"  ⚠️  No system name found")
                no_name_found += 1
        
        print(f"\n" + "="*50)
        print(f"✅ Updated: {updated} files")
        print(f"⏭️  Skipped (0 events): {no_events} files")  
        print(f"⚠️  No name found: {no_name_found} files")
        print(f"📊 Total processed: {len(files_no_system)} files")
        print("="*50 + "\n")

if __name__ == '__main__':
    case_id = int(sys.argv[1]) if len(sys.argv) > 1 else 2
    print(f"🚀 Backfilling system names for case {case_id}...")
    backfill_system_names(case_id)

