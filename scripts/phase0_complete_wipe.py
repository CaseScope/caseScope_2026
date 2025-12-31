#!/usr/bin/env python3
"""
PHASE 0: Complete Data Wipe for File Upload Redesign
Deletes ALL cases, OpenSearch indices, and files to start fresh.
"""

import os
import sys
import shutil
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from main import app, db
from models import Case, CaseFile, ActiveTask
from opensearch_indexer import OpenSearchIndexer
from audit_logger import log_action

def wipe_database():
    """Delete all cases and related records from database"""
    print("=" * 60)
    print("PHASE 0: COMPLETE DATA WIPE")
    print("=" * 60)
    print()
    
    with app.app_context():
        print("[1/8] Counting existing data...")
        case_count = Case.query.count()
        file_count = CaseFile.query.count()
        task_count = ActiveTask.query.count()
        
        print(f"  - Cases: {case_count}")
        print(f"  - Files: {file_count}")
        print(f"  - Active Tasks: {task_count}")
        print()
        
        if case_count == 0 and file_count == 0:
            print("  ✓ Database already clean (no cases or files)")
        else:
            print("[2/8] Deleting all case files from database...")
            # Get case IDs for OpenSearch cleanup
            case_ids = [case.id for case in Case.query.all()]
            
            # Delete all case files first (to avoid foreign key constraint)
            CaseFile.query.delete()
            db.session.commit()
            print(f"  ✓ Deleted {file_count} case files")
            
            print("[3/8] Deleting all cases from database...")
            Case.query.delete()
            db.session.commit()
            print(f"  ✓ Deleted {case_count} cases")
            
            print("[3/8] Clearing active_tasks table...")
            ActiveTask.query.delete()
            db.session.commit()
            print(f"  ✓ Deleted {task_count} active tasks")
            
            return case_ids
        
        return []

def wipe_opensearch_indices(case_ids):
    """Delete all OpenSearch indices for cases"""
    if not case_ids:
        print("\n[4/8] Checking for OpenSearch indices...")
        # Still check for orphaned indices
        indexer = OpenSearchIndexer()
        try:
            indices = indexer.client.cat.indices(format='json')
            case_indices = [idx['index'] for idx in indices if idx['index'].startswith('case_')]
            if case_indices:
                print(f"  ! Found {len(case_indices)} orphaned indices")
                case_ids = list(set([int(idx.split('_')[1].split('_')[0]) for idx in case_indices if '_' in idx and idx.split('_')[1].split('_')[0].isdigit()]))
            else:
                print("  ✓ No OpenSearch indices found")
                return
        except Exception as e:
            print(f"  ✓ No OpenSearch indices found (error: {e})")
            return
    
    print(f"\n[4/8] Deleting OpenSearch indices for {len(case_ids)} cases...")
    indexer = OpenSearchIndexer()
    deleted_count = 0
    
    for case_id in case_ids:
        # Delete main index and all specialized indices
        index_patterns = [
            f'case_{case_id}',
            f'case_{case_id}_browser',
            f'case_{case_id}_execution',
            f'case_{case_id}_network',
            f'case_{case_id}_devices'
        ]
        
        for index_name in index_patterns:
            try:
                if indexer.client.indices.exists(index=index_name):
                    indexer.client.indices.delete(index=index_name)
                    deleted_count += 1
                    print(f"  ✓ Deleted index: {index_name}")
            except Exception as e:
                print(f"  ! Error deleting {index_name}: {e}")
    
    print(f"  ✓ Deleted {deleted_count} OpenSearch indices")

def wipe_filesystem():
    """Delete all case files from filesystem"""
    print("\n[5/8] Deleting files from /opt/casescope/case_files/*...")
    case_files_dir = '/opt/casescope/case_files'
    if os.path.exists(case_files_dir):
        deleted_count = 0
        for item in os.listdir(case_files_dir):
            item_path = os.path.join(case_files_dir, item)
            try:
                if os.path.isdir(item_path):
                    shutil.rmtree(item_path)
                else:
                    os.remove(item_path)
                deleted_count += 1
            except Exception as e:
                print(f"  ! Error deleting {item}: {e}")
        print(f"  ✓ Deleted {deleted_count} items from case_files/")
    else:
        print(f"  ✓ Directory does not exist (will be created in Phase 2)")
    
    print("\n[6/8] Deleting files from /opt/casescope/uploads/web/*...")
    web_uploads_dir = '/opt/casescope/uploads/web'
    if os.path.exists(web_uploads_dir):
        deleted_count = 0
        for item in os.listdir(web_uploads_dir):
            item_path = os.path.join(web_uploads_dir, item)
            try:
                if os.path.isdir(item_path):
                    shutil.rmtree(item_path)
                else:
                    os.remove(item_path)
                deleted_count += 1
            except Exception as e:
                print(f"  ! Error deleting {item}: {e}")
        print(f"  ✓ Deleted {deleted_count} items from uploads/web/")
    else:
        print(f"  ✓ Directory does not exist (will create in Phase 2)")
    
    print("\n[7/8] Deleting files from /opt/casescope/uploads/sftp/*...")
    sftp_uploads_dir = '/opt/casescope/uploads/sftp'
    if os.path.exists(sftp_uploads_dir):
        deleted_count = 0
        for item in os.listdir(sftp_uploads_dir):
            item_path = os.path.join(sftp_uploads_dir, item)
            try:
                if os.path.isdir(item_path):
                    shutil.rmtree(item_path)
                else:
                    os.remove(item_path)
                deleted_count += 1
            except Exception as e:
                print(f"  ! Error deleting {item}: {e}")
        print(f"  ✓ Deleted {deleted_count} items from uploads/sftp/")
    else:
        print(f"  ✓ Directory does not exist (will create in Phase 2)")
    
    print("\n[8/8] Deleting files from /opt/casescope/staging/*...")
    staging_dir = '/opt/casescope/staging'
    if os.path.exists(staging_dir):
        deleted_count = 0
        for item in os.listdir(staging_dir):
            item_path = os.path.join(staging_dir, item)
            try:
                if os.path.isdir(item_path):
                    shutil.rmtree(item_path)
                else:
                    os.remove(item_path)
                deleted_count += 1
            except Exception as e:
                print(f"  ! Error deleting {item}: {e}")
        print(f"  ✓ Deleted {deleted_count} items from staging/")
    else:
        print(f"  ✓ Directory does not exist (will create in Phase 2)")

def log_wipe():
    """Log the complete wipe to audit trail"""
    with app.app_context():
        try:
            log_action(
                action='system_wipe_phase0',
                resource_type='system',
                details={
                    'reason': 'File upload redesign - NEW_FILE_UPLOAD.ND implementation',
                    'phase': 'PHASE 0',
                    'timestamp': datetime.utcnow().isoformat(),
                    'wiped': ['database_cases', 'opensearch_indices', 'case_files', 'uploads', 'staging']
                },
                status='success'
            )
            print("\n✓ Logged complete wipe to audit trail")
        except Exception as e:
            print(f"\n! Warning: Could not log to audit trail: {e}")

if __name__ == '__main__':
    print("\n" + "!" * 60)
    print("WARNING: This will DELETE ALL case data permanently!")
    print("!" * 60)
    print()
    
    response = input("Type 'DELETE EVERYTHING' to confirm: ")
    if response != 'DELETE EVERYTHING':
        print("\n✗ Aborted. No changes made.")
        sys.exit(1)
    
    print("\n✓ Confirmed. Beginning complete wipe...\n")
    
    # Execute wipe in order
    case_ids = wipe_database()
    wipe_opensearch_indices(case_ids)
    wipe_filesystem()
    log_wipe()
    
    print("\n" + "=" * 60)
    print("PHASE 0 COMPLETE: All data wiped successfully")
    print("=" * 60)
    print("\nReady for Phase 1: Database Migrations")
    print()

