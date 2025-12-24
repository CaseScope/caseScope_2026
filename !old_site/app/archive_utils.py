#!/usr/bin/env python3
"""
Archive Utilities - Case File Archiving and Restoration
Version: 1.18.0
Purpose: Archive case files to cold storage while retaining indexed data
"""

import os
import zipfile
import shutil
import logging
from datetime import datetime
from typing import Dict, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


def get_archive_root_path() -> Optional[str]:
    """
    Get configured archive root path from settings
    
    Returns:
        Archive root path or None if not configured
    """
    try:
        from main import db
        from models import SystemSettings
        
        setting = db.session.query(SystemSettings).filter_by(
            setting_key='archive_root_path'
        ).first()
        
        path = setting.setting_value if setting else None
        
        # Return None if empty string
        return path if path and path.strip() else None
        
    except Exception as e:
        logger.error(f"[ARCHIVE] Error getting archive path: {e}")
        return None


def validate_archive_path(path: str) -> Dict:
    """
    Validate archive path is usable
    
    Checks:
    - Path exists
    - Path is absolute
    - Path is writable
    - Path owned by casescope:casescope
    - Sufficient disk space (>100GB recommended)
    
    Args:
        path: Archive root path to validate
        
    Returns:
        {
            'valid': bool,
            'message': str,
            'space_gb': float,
            'owner': str
        }
    """
    try:
        # Check if path exists
        if not os.path.exists(path):
            return {
                'valid': False,
                'message': f'Path does not exist: {path}',
                'space_gb': 0,
                'owner': 'unknown'
            }
        
        # Check if absolute
        if not os.path.isabs(path):
            return {
                'valid': False,
                'message': f'Path must be absolute (e.g., /archive not {path})',
                'space_gb': 0,
                'owner': 'unknown'
            }
        
        # Check if writable
        if not os.access(path, os.W_OK):
            return {
                'valid': False,
                'message': f'Path is not writable. Run: sudo chown casescope:casescope {path}',
                'space_gb': 0,
                'owner': 'unknown'
            }
        
        # Get disk space
        stat = os.statvfs(path)
        free_bytes = stat.f_bavail * stat.f_frsize
        free_gb = free_bytes / (1024**3)
        
        # Get owner
        import pwd, grp
        stat_info = os.stat(path)
        owner_uid = stat_info.st_uid
        owner_gid = stat_info.st_gid
        owner_name = pwd.getpwuid(owner_uid).pw_name
        group_name = grp.getgrgid(owner_gid).gr_name
        owner = f'{owner_name}:{group_name}'
        
        # Check space
        if free_gb < 100:
            return {
                'valid': False,
                'message': f'Insufficient space: {free_gb:.1f}GB free (recommend 100GB+)',
                'space_gb': free_gb,
                'owner': owner
            }
        
        # All checks passed
        return {
            'valid': True,
            'message': f'Archive path valid: {free_gb:.1f}GB free, owner {owner}',
            'space_gb': free_gb,
            'owner': owner
        }
        
    except Exception as e:
        logger.error(f"[ARCHIVE] Error validating path {path}: {e}")
        return {
            'valid': False,
            'message': f'Validation error: {str(e)}',
            'space_gb': 0,
            'owner': 'unknown'
        }


def get_case_files_path(case_id: int) -> str:
    """
    Get the path to case files directory
    
    Args:
        case_id: Case ID
        
    Returns:
        Full path to case files (e.g., /opt/casescope/uploads/123/)
    """
    return f'/opt/casescope/uploads/{case_id}'


def get_case_file_size(case_id: int) -> Dict:
    """
    Calculate total size of case files
    
    Args:
        case_id: Case ID
        
    Returns:
        {
            'size_bytes': int,
            'size_mb': float,
            'size_gb': float,
            'file_count': int,
            'size_display': str  # Human-readable (e.g., "5.2 GB")
        }
    """
    try:
        case_path = get_case_files_path(case_id)
        
        if not os.path.exists(case_path):
            return {
                'size_bytes': 0,
                'size_mb': 0,
                'size_gb': 0,
                'file_count': 0,
                'size_display': '0 B'
            }
        
        total_size = 0
        file_count = 0
        
        for dirpath, dirnames, filenames in os.walk(case_path):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                if os.path.exists(filepath):
                    total_size += os.path.getsize(filepath)
                    file_count += 1
        
        size_mb = total_size / (1024**2)
        size_gb = total_size / (1024**3)
        
        # Human-readable display
        if size_gb >= 1:
            size_display = f'{size_gb:.1f} GB'
        elif size_mb >= 1:
            size_display = f'{size_mb:.1f} MB'
        else:
            size_display = f'{total_size:,} B'
        
        return {
            'size_bytes': total_size,
            'size_mb': size_mb,
            'size_gb': size_gb,
            'file_count': file_count,
            'size_display': size_display
        }
        
    except Exception as e:
        logger.error(f"[ARCHIVE] Error calculating case {case_id} size: {e}")
        return {
            'size_bytes': 0,
            'size_mb': 0,
            'size_gb': 0,
            'file_count': 0,
            'size_display': 'Unknown'
        }


def get_archive_directory(case_id: int, case_name: str) -> str:
    """
    Get archive directory path for a case
    
    Format: {archive_root}/{YYYY-MM-DD} - {case_name}_case{id}/
    Example: /archive/2025-11-20 - SERVU_case123/
    
    Args:
        case_id: Case ID
        case_name: Case name
        
    Returns:
        Full path to archive directory
    """
    archive_root = get_archive_root_path()
    if not archive_root:
        raise ValueError('Archive root path not configured in System Settings')
    
    # Sanitize case name for filesystem
    safe_name = "".join(c for c in case_name if c.isalnum() or c in (' ', '-', '_')).strip()
    safe_name = safe_name[:100]  # Limit length
    
    # Create directory name
    date_str = datetime.now().strftime('%Y-%m-%d')
    dir_name = f'{date_str} - {safe_name}_case{case_id}'
    
    return os.path.join(archive_root, dir_name)


def archive_case(db, case_id: int, current_user_id: int) -> Dict:
    """
    Archive a case by creating ZIP of files and removing originals
    
    Process:
    1. Validate archive path is configured
    2. Get all case files from database
    3. Create archive directory
    4. Create ZIP of /opt/casescope/uploads/{case_id}/
    5. Verify ZIP integrity (test extract)
    6. Record archive path in database
    7. Delete original files (keep directory structure)
    8. Update case status to 'Archived'
    9. Audit log
    
    Args:
        db: Database session
        case_id: Case ID to archive
        current_user_id: User performing archive
        
    Returns:
        {
            'status': 'success' | 'error',
            'message': str,
            'archive_path': str,
            'size_mb': float,
            'file_count': int
        }
    """
    from models import Case
    from audit_logger import log_action
    
    logger.info("="*80)
    logger.info(f"[ARCHIVE] Starting archive process for case {case_id}")
    logger.info("="*80)
    
    try:
        # Step 1: Get case
        case = db.session.get(Case, case_id)
        if not case:
            return {
                'status': 'error',
                'message': f'Case {case_id} not found',
                'archive_path': '',
                'size_mb': 0,
                'file_count': 0
            }
        
        logger.info(f"[ARCHIVE] Case: {case.name} (ID: {case.id})")
        
        # Step 2: Validate archive path
        archive_root = get_archive_root_path()
        if not archive_root:
            return {
                'status': 'error',
                'message': 'Archive root path not configured in System Settings',
                'archive_path': '',
                'size_mb': 0,
                'file_count': 0
            }
        
        validation = validate_archive_path(archive_root)
        if not validation['valid']:
            return {
                'status': 'error',
                'message': validation['message'],
                'archive_path': '',
                'size_mb': 0,
                'file_count': 0
            }
        
        logger.info(f"[ARCHIVE] Archive root validated: {archive_root}")
        
        # Step 3: Check if already archived
        if case.status == 'Archived':
            return {
                'status': 'error',
                'message': 'Case is already archived',
                'archive_path': case.archive_path or '',
                'size_mb': 0,
                'file_count': 0
            }
        
        # Step 4: Get case files size
        size_info = get_case_file_size(case_id)
        logger.info(f"[ARCHIVE] Case size: {size_info['size_display']} ({size_info['file_count']} files)")
        
        if size_info['file_count'] == 0:
            return {
                'status': 'error',
                'message': 'No files to archive (case has 0 files)',
                'archive_path': '',
                'size_mb': 0,
                'file_count': 0
            }
        
        # Step 5: Create archive directory
        archive_dir = get_archive_directory(case_id, case.name)
        os.makedirs(archive_dir, exist_ok=True)
        
        # Set ownership to casescope:casescope
        shutil.chown(archive_dir, user='casescope', group='casescope')
        
        logger.info(f"[ARCHIVE] Archive directory created: {archive_dir}")
        
        # Step 6: Create ZIP file
        zip_path = os.path.join(archive_dir, 'archive.zip')
        case_files_path = get_case_files_path(case_id)
        
        logger.info(f"[ARCHIVE] Creating ZIP: {zip_path}")
        logger.info(f"[ARCHIVE] Source: {case_files_path}")
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(case_files_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    # Store relative path to preserve directory structure
                    arcname = os.path.relpath(file_path, case_files_path)
                    zipf.write(file_path, arcname)
                    logger.debug(f"[ARCHIVE]   Added: {arcname}")
        
        # Set ownership to casescope:casescope
        shutil.chown(zip_path, user='casescope', group='casescope')
        
        zip_size_mb = os.path.getsize(zip_path) / (1024**2)
        logger.info(f"[ARCHIVE] ZIP created: {zip_size_mb:.1f} MB")
        
        # Step 7: Verify ZIP integrity
        logger.info(f"[ARCHIVE] Verifying ZIP integrity...")
        try:
            with zipfile.ZipFile(zip_path, 'r') as zipf:
                # Test ZIP can be read
                zip_file_list = zipf.namelist()
                if len(zip_file_list) != size_info['file_count']:
                    raise ValueError(f"File count mismatch: ZIP has {len(zip_file_list)} files, expected {size_info['file_count']}")
                
                # Test ZIP integrity
                bad_file = zipf.testzip()
                if bad_file:
                    raise ValueError(f"ZIP integrity check failed: {bad_file}")
            
            logger.info(f"[ARCHIVE] ✅ ZIP integrity verified ({len(zip_file_list)} files)")
            
        except Exception as e:
            logger.error(f"[ARCHIVE] ❌ ZIP verification failed: {e}")
            # Delete bad ZIP
            if os.path.exists(zip_path):
                os.remove(zip_path)
            return {
                'status': 'error',
                'message': f'ZIP verification failed: {str(e)}',
                'archive_path': '',
                'size_mb': 0,
                'file_count': 0
            }
        
        # Step 8: Delete original files (keep directory structure)
        logger.info(f"[ARCHIVE] Removing original files from: {case_files_path}")
        
        files_deleted = 0
        for root, dirs, files in os.walk(case_files_path):
            for file in files:
                file_path = os.path.join(root, file)
                os.remove(file_path)
                files_deleted += 1
                logger.debug(f"[ARCHIVE]   Deleted: {file_path}")
        
        logger.info(f"[ARCHIVE] ✅ Deleted {files_deleted} original files (directory structure preserved)")
        
        # Step 9: Update database
        case.status = 'Archived'
        case.archive_path = zip_path
        case.archived_at = datetime.utcnow()
        case.archived_by = current_user_id
        db.session.commit()
        
        logger.info(f"[ARCHIVE] ✅ Database updated")
        
        # Step 10: Audit log
        log_action(
            'case_archive_completed',
            resource_type='case',
            resource_id=case_id,
            resource_name=case.name,
            details={
                'archive_path': zip_path,
                'size_mb': round(zip_size_mb, 2),
                'file_count': size_info['file_count'],
                'original_size_mb': round(size_info['size_mb'], 2)
            }
        )
        
        logger.info("="*80)
        logger.info(f"[ARCHIVE] ✅ Archive complete!")
        logger.info(f"[ARCHIVE] Path: {zip_path}")
        logger.info(f"[ARCHIVE] Size: {zip_size_mb:.1f} MB")
        logger.info(f"[ARCHIVE] Files: {size_info['file_count']}")
        logger.info("="*80)
        
        return {
            'status': 'success',
            'message': f'Case archived successfully: {size_info["file_count"]} files ({size_info["size_display"]})',
            'archive_path': zip_path,
            'size_mb': zip_size_mb,
            'file_count': size_info['file_count']
        }
        
    except Exception as e:
        logger.error(f"[ARCHIVE] ❌ Archive failed: {e}", exc_info=True)
        
        # Audit log failure
        try:
            from audit_logger import log_action
            log_action(
                'case_archive_failed',
                resource_type='case',
                resource_id=case_id,
                details={'error': str(e)}
            )
        except:
            pass
        
        return {
            'status': 'error',
            'message': f'Archive failed: {str(e)}',
            'archive_path': '',
            'size_mb': 0,
            'file_count': 0
        }


def restore_case(db, case_id: int, current_user_id: int, new_status: str = 'In Progress') -> Dict:
    """
    Restore an archived case by extracting ZIP back to original location
    
    Process:
    1. Validate case is archived
    2. Validate archive ZIP exists
    3. Extract ZIP to /opt/casescope/uploads/{case_id}/
    4. Verify all files restored (compare counts)
    5. Set ownership to casescope:casescope
    6. Update case status (user's choice)
    7. Update restored_at timestamp
    8. Delete archive ZIP
    9. Audit log
    
    Args:
        db: Database session
        case_id: Case ID to restore
        current_user_id: User performing restore
        new_status: New case status after restore (default: 'In Progress')
        
    Returns:
        {
            'status': 'success' | 'error',
            'message': str,
            'files_restored': int
        }
    """
    from models import Case
    from audit_logger import log_action
    
    logger.info("="*80)
    logger.info(f"[RESTORE] Starting restore process for case {case_id}")
    logger.info("="*80)
    
    try:
        # Step 1: Get case
        case = db.session.get(Case, case_id)
        if not case:
            return {
                'status': 'error',
                'message': f'Case {case_id} not found',
                'files_restored': 0
            }
        
        logger.info(f"[RESTORE] Case: {case.name} (ID: {case.id})")
        
        # Step 2: Check if archived
        if case.status != 'Archived':
            return {
                'status': 'error',
                'message': 'Case is not archived',
                'files_restored': 0
            }
        
        # Step 3: Check archive path
        if not case.archive_path or not os.path.exists(case.archive_path):
            return {
                'status': 'error',
                'message': f'Archive file not found: {case.archive_path}',
                'files_restored': 0
            }
        
        zip_path = case.archive_path
        logger.info(f"[RESTORE] Archive: {zip_path}")
        
        # Step 4: Get file count from ZIP
        with zipfile.ZipFile(zip_path, 'r') as zipf:
            expected_files = len(zipf.namelist())
        
        logger.info(f"[RESTORE] Expected files: {expected_files}")
        
        # Step 5: Extract ZIP
        case_files_path = get_case_files_path(case_id)
        logger.info(f"[RESTORE] Extracting to: {case_files_path}")
        
        # Ensure directory exists
        os.makedirs(case_files_path, exist_ok=True)
        
        with zipfile.ZipFile(zip_path, 'r') as zipf:
            zipf.extractall(case_files_path)
        
        logger.info(f"[RESTORE] ✅ Files extracted")
        
        # Step 6: Set ownership to casescope:casescope
        logger.info(f"[RESTORE] Setting ownership to casescope:casescope...")
        
        for root, dirs, files in os.walk(case_files_path):
            # Set directory ownership
            shutil.chown(root, user='casescope', group='casescope')
            
            # Set file ownership
            for file in files:
                file_path = os.path.join(root, file)
                shutil.chown(file_path, user='casescope', group='casescope')
        
        logger.info(f"[RESTORE] ✅ Ownership set")
        
        # Step 7: Verify file count
        restored_count = 0
        for root, dirs, files in os.walk(case_files_path):
            restored_count += len(files)
        
        if restored_count != expected_files:
            logger.warning(f"[RESTORE] ⚠️  File count mismatch: restored {restored_count}, expected {expected_files}")
        else:
            logger.info(f"[RESTORE] ✅ File count verified: {restored_count} files")
        
        # Step 8: Update database
        case.status = new_status
        case.restored_at = datetime.utcnow()
        # Keep archive_path and archived_at for audit trail
        db.session.commit()
        
        logger.info(f"[RESTORE] ✅ Database updated (status: {new_status})")
        
        # Step 9: Delete archive ZIP
        try:
            archive_dir = os.path.dirname(zip_path)
            shutil.rmtree(archive_dir)
            logger.info(f"[RESTORE] ✅ Archive deleted: {archive_dir}")
        except Exception as e:
            logger.warning(f"[RESTORE] ⚠️  Could not delete archive: {e}")
        
        # Step 10: Audit log
        log_action(
            'case_restore_completed',
            resource_type='case',
            resource_id=case_id,
            resource_name=case.name,
            details={
                'files_restored': restored_count,
                'new_status': new_status,
                'archive_path': zip_path
            }
        )
        
        logger.info("="*80)
        logger.info(f"[RESTORE] ✅ Restore complete!")
        logger.info(f"[RESTORE] Files: {restored_count}")
        logger.info(f"[RESTORE] Status: {new_status}")
        logger.info("="*80)
        
        return {
            'status': 'success',
            'message': f'Case restored successfully: {restored_count} files',
            'files_restored': restored_count
        }
        
    except Exception as e:
        logger.error(f"[RESTORE] ❌ Restore failed: {e}", exc_info=True)
        
        # Audit log failure
        try:
            from audit_logger import log_action
            log_action(
                'case_restore_failed',
                resource_type='case',
                resource_id=case_id,
                details={'error': str(e)}
            )
        except:
            pass
        
        return {
            'status': 'error',
            'message': f'Restore failed: {str(e)}',
            'files_restored': 0
        }


def is_case_archived(case) -> bool:
    """
    Check if case is archived
    
    Args:
        case: Case model instance
        
    Returns:
        True if case status is 'Archived'
    """
    return case.status == 'Archived'


def require_unarchived_case(case) -> tuple:
    """
    Helper to block operations on archived cases
    
    Usage:
        archived, error_response = require_unarchived_case(case)
        if archived:
            return error_response
    
    Args:
        case: Case model instance
        
    Returns:
        (is_archived: bool, error_response: tuple or None)
    """
    from flask import jsonify
    
    if is_case_archived(case):
        return True, (jsonify({
            'success': False,
            'error': 'Cannot perform this operation on an archived case. Please restore the case first.'
        }), 403)
    
    return False, None

