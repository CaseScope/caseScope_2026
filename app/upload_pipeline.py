#!/usr/bin/env python3
"""
UNIFIED UPLOAD PIPELINE (v9.6.0)

Single staging area for ALL uploads (HTTP + Bulk)
Clean, linear workflow with proper duplicate detection
"""

import os
import sys
import shutil
import zipfile
import json
import hashlib
import subprocess
import tempfile
import logging
from typing import List, Dict, Tuple, Optional
from datetime import datetime

# Initialize module logger (works from Flask or Celery)
logger = logging.getLogger(__name__)


def init_logger(flask_logger):
    """
    Initialize logger from Flask app (optional)
    Module has its own logger but can use Flask's if provided
    """
    global logger
    logger = flask_logger


# ============================================================================
# STAGING AREA MANAGEMENT
# ============================================================================

def get_staging_path(case_id: int) -> str:
    """Get staging directory for a case"""
    return f"/opt/casescope/staging/{case_id}"


def get_final_upload_path(case_id: int) -> str:
    """Get final upload directory for a case"""
    return f"/opt/casescope/uploads/{case_id}"


def ensure_staging_exists(case_id: int) -> str:
    """Create staging directory if it doesn't exist"""
    staging_dir = get_staging_path(case_id)
    os.makedirs(staging_dir, exist_ok=True)
    return staging_dir


def clear_staging(case_id: int):
    """Clear all files from staging directory"""
    staging_dir = get_staging_path(case_id)
    if os.path.exists(staging_dir):
        shutil.rmtree(staging_dir)
        os.makedirs(staging_dir, exist_ok=True)
    logger.info(f"[STAGING] Cleared: {staging_dir}")


# ============================================================================
# STEP 1: STAGE FILES (HTTP or Bulk)
# ============================================================================

def stage_http_upload(case_id: int, uploaded_file, filename: str) -> Dict:
    """
    Stage a file from HTTP upload
    
    Args:
        case_id: Case ID
        uploaded_file: Flask file object
        filename: Original filename
    
    Returns:
        dict: {'success': bool, 'file_path': str, 'message': str}
    """
    staging_dir = ensure_staging_exists(case_id)
    dest_path = os.path.join(staging_dir, filename)
    
    try:
        uploaded_file.save(dest_path)
        file_size = os.path.getsize(dest_path)
        logger.info(f"[STAGE] HTTP upload: {filename} ({file_size:,} bytes)")
        
        return {
            'success': True,
            'file_path': dest_path,
            'file_size': file_size,
            'message': f'Staged: {filename}'
        }
    except Exception as e:
        logger.error(f"[STAGE] Failed to stage {filename}: {e}")
        return {
            'success': False,
            'file_path': None,
            'file_size': 0,
            'message': f'Error: {str(e)}'
        }


def stage_bulk_upload(case_id: int, source_folder: str, cleanup_after: bool = True) -> Dict:
    """
    Stage files from bulk upload folder (e.g. /opt/casescope/local_uploads)
    Only stages supported file types
    
    Args:
        case_id: Case ID
        source_folder: Path to bulk upload folder
        cleanup_after: If True, delete original files after successful copy (default: True)
    
    Returns:
        dict: {'status': str, 'files_staged': int, 'message': str}
    """
    staging_dir = ensure_staging_exists(case_id)
    
    if not os.path.exists(source_folder):
        return {
            'status': 'error',
            'files_staged': 0,
            'message': f'Source folder not found: {source_folder}'
        }
    
    # Supported extensions (from bulk_import.py)
    ALLOWED_EXTENSIONS = {'.evtx', '.ndjson', '.json', '.csv', '.log', '.zip'}  # All formats accepted for upload (v1.14.0: Added .log for IIS)
    
    files_staged = 0
    staged_files = []  # Track successfully staged files for cleanup
    
    for filename in os.listdir(source_folder):
        source_path = os.path.join(source_folder, filename)
        
        if not os.path.isfile(source_path):
            continue
        
        # Check if file extension is supported
        ext = os.path.splitext(filename)[1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            logger.debug(f"[STAGE] Skipping unsupported file: {filename}")
            continue
        
        dest_path = os.path.join(staging_dir, filename)
        
        try:
            shutil.copy2(source_path, dest_path)
            files_staged += 1
            staged_files.append(source_path)
            logger.info(f"[STAGE] Bulk upload: {filename}")
        except Exception as e:
            logger.error(f"[STAGE] Failed to stage {filename}: {e}")
            continue
    
    # Cleanup: Delete originals after successful staging
    if cleanup_after and files_staged > 0:
        for source_path in staged_files:
            try:
                os.remove(source_path)
                logger.info(f"[CLEANUP] Removed: {os.path.basename(source_path)}")
            except Exception as e:
                logger.warning(f"[CLEANUP] Failed to remove {source_path}: {e}")
    
    return {
        'status': 'success',
        'files_staged': files_staged,
        'message': f'Staged {files_staged} files from bulk upload' + (' (originals cleaned up)' if cleanup_after else '')
    }


# ============================================================================
# STEP 2: EXTRACT ZIP FILES
# ============================================================================

def is_temp_file(filename: str) -> bool:
    """
    Detect Windows temporary files created during extraction.
    
    Patterns:
    - Files ending with _$[A-Z0-9]+.ext (e.g., TASERVER3_$17WWJ3J.evtx)
    - Files starting with ~$ (e.g., ~$document.evtx)
    - Files with .tmp extension
    
    Args:
        filename: File name to check
        
    Returns:
        bool: True if file appears to be a temporary file
    """
    import re
    
    # Pattern: *_$[A-Z0-9]+.ext (Windows temp files during extraction)
    # Example: TASERVER3_$17WWJ3J.evtx, FILE_$ABC123.evtx
    temp_pattern = r'_\$[A-Z0-9]+\.[a-z]+$'
    
    # Pattern: ~$filename (Windows temp files)
    tilde_pattern = r'^~\$'
    
    # Check patterns
    if re.search(temp_pattern, filename, re.IGNORECASE):
        return True
    
    if re.search(tilde_pattern, filename):
        return True
    
    # Check .tmp extension
    if filename.lower().endswith('.tmp'):
        return True
    
    return False


def is_iis_log(zip_file: zipfile.ZipFile, file_info: zipfile.ZipInfo) -> bool:
    """
    Detect if a .log file inside a ZIP is an IIS W3C Extended Log Format file.
    
    Args:
        zip_file: ZipFile object
        file_info: ZipInfo object for the .log file
        
    Returns:
        bool: True if IIS log, False otherwise
    """
    try:
        # Read first 1024 bytes from the file in the ZIP
        with zip_file.open(file_info) as f:
            header = f.read(1024).decode('utf-8', errors='ignore')
        
        # Check for IIS W3C Extended Log Format signatures
        if ('Microsoft Internet Information Services' in header or 
            ('#Fields:' in header and ('cs-method' in header or 'cs-uri-stem' in header or 's-ip' in header))):
            return True
        
        return False
    except Exception as e:
        logger.warning(f"[ZIP] Could not peek at .log file {file_info.filename}: {e}")
        return False


def extract_single_zip(zip_path: str, target_dir: str, prefix: str = "") -> Dict:
    """
    Extract a single ZIP file recursively (handles nested ZIPs)
    
    Args:
        zip_path: Path to ZIP file
        target_dir: Directory to extract to
        prefix: Filename prefix (e.g., "ParentZIP_")
    
    Returns:
        dict: {
            'files_extracted': int,
            'nested_zips_found': int,
            'temp_files_skipped': int,
            'non_iis_logs_skipped': int,  # v1.14.0: .log files that are NOT IIS logs
            'expected_files': int,  # Expected EVTX/NDJSON/IIS files (excluding temp files)
            'validation_passed': bool,  # True if extracted == expected
            'validation_details': str  # Human-readable validation message
        }
    """
    stats = {
        'files_extracted': 0,
        'nested_zips_found': 0,
        'temp_files_skipped': 0,
        'non_iis_logs_skipped': 0,  # v1.14.0: Track non-IIS .log files skipped
        'expected_files': 0,
        'validation_passed': True,
        'validation_details': ''
    }
    zip_name = os.path.splitext(os.path.basename(zip_path))[0]
    current_prefix = f"{prefix}{zip_name}_" if prefix else f"{zip_name}_"
    
    temp_extract_dir = os.path.join(target_dir, f"_temp_{zip_name}")
    os.makedirs(temp_extract_dir, exist_ok=True)
    
    try:
        # STEP 1: Count expected files BEFORE extraction (for validation)
        expected_evtx = 0
        expected_ndjson = 0
        expected_iis = 0
        expected_temp = 0
        expected_non_iis_logs = 0
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            for zip_info in zip_ref.infolist():
                # Skip directories
                if zip_info.is_dir():
                    continue
                
                filename = os.path.basename(zip_info.filename)
                file_lower = filename.lower()
                
                # Count expected files by type
                if file_lower.endswith('.zip'):
                    # Nested ZIPs handled separately
                    continue
                elif file_lower.endswith('.evtx'):
                    if is_temp_file(filename):
                        expected_temp += 1
                    else:
                        expected_evtx += 1
                elif file_lower.endswith('.ndjson'):
                    if is_temp_file(filename):
                        expected_temp += 1
                    else:
                        expected_ndjson += 1
                elif file_lower.endswith('.log'):
                    # v1.14.0: Smart extraction - only IIS logs
                    if is_iis_log(zip_ref, zip_info):
                        expected_iis += 1
                    else:
                        expected_non_iis_logs += 1
        
        stats['expected_files'] = expected_evtx + expected_ndjson + expected_iis
        expected_total = stats['expected_files']
        
        log_msg = f"[EXTRACT] {zip_name}: Expected {expected_evtx} EVTX + {expected_ndjson} NDJSON"
        if expected_iis > 0:
            log_msg += f" + {expected_iis} IIS"
        log_msg += f" = {expected_total} files"
        if expected_temp > 0:
            log_msg += f" ({expected_temp} temp files will be skipped)"
        if expected_non_iis_logs > 0:
            log_msg += f" ({expected_non_iis_logs} non-IIS .log files will be skipped)"
        logger.info(log_msg)
        
        # STEP 2: Extract and process
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(temp_extract_dir)
        
        # Process extracted contents
        for root, dirs, files in os.walk(temp_extract_dir):
            for file in files:
                file_path = os.path.join(root, file)
                file_lower = file.lower()
                
                if file_lower.endswith('.zip'):
                    # Found nested ZIP
                    stats['nested_zips_found'] += 1
                    logger.info(f"[EXTRACT]   Nested ZIP: {file}")
                    nested_stats = extract_single_zip(file_path, target_dir, current_prefix)
                    stats['files_extracted'] += nested_stats['files_extracted']
                    stats['nested_zips_found'] += nested_stats['nested_zips_found']
                    stats['temp_files_skipped'] += nested_stats.get('temp_files_skipped', 0)
                    stats['non_iis_logs_skipped'] += nested_stats.get('non_iis_logs_skipped', 0)
                    # Aggregate expected files from nested ZIPs
                    stats['expected_files'] += nested_stats.get('expected_files', 0)
                    # If nested ZIP validation failed, mark parent as failed
                    if not nested_stats.get('validation_passed', True):
                        stats['validation_passed'] = False
                    os.remove(file_path)
                    
                elif file_lower.endswith(('.evtx', '.ndjson')):
                    # Skip Windows temporary files created during extraction
                    if is_temp_file(file):
                        logger.warning(f"[EXTRACT]   Skipping temp file: {file}")
                        os.remove(file_path)  # Delete temp file
                        stats['temp_files_skipped'] += 1
                        continue
                    
                    # Move to target with prefix
                    # NOTE: Only EVTX, NDJSON, and IIS logs are extracted from ZIPs
                    # JSON and CSV inside ZIPs are ignored
                    prefixed_name = f"{current_prefix}{file}"
                    target_path = os.path.join(target_dir, prefixed_name)
                    shutil.move(file_path, target_path)
                    stats['files_extracted'] += 1
                    logger.info(f"[EXTRACT]   → {prefixed_name}")
                
                elif file_lower.endswith('.log'):
                    # v1.14.0: Smart extraction - only extract IIS logs
                    # Check if this is an IIS log
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            header = f.read(1024)
                        
                        is_iis_file = ('Microsoft Internet Information Services' in header or 
                                      ('#Fields:' in header and ('cs-method' in header or 'cs-uri-stem' in header or 's-ip' in header)))
                        
                        if is_iis_file:
                            # This is an IIS log - extract it
                            prefixed_name = f"{current_prefix}{file}"
                            target_path = os.path.join(target_dir, prefixed_name)
                            shutil.move(file_path, target_path)
                            stats['files_extracted'] += 1
                            logger.info(f"[EXTRACT]   → {prefixed_name} (IIS log)")
                        else:
                            # Not an IIS log - skip it
                            logger.info(f"[EXTRACT]   Skipping non-IIS .log file: {file}")
                            os.remove(file_path)
                            stats['non_iis_logs_skipped'] += 1
                    except Exception as e:
                        logger.warning(f"[EXTRACT]   Could not check .log file {file}: {e}, skipping")
                        os.remove(file_path)
                        stats['non_iis_logs_skipped'] += 1
        
        # STEP 3: Validate extraction results
        extracted_count = stats['files_extracted']
        temp_skipped = stats.get('temp_files_skipped', 0)
        
        if extracted_count == expected_total:
            stats['validation_passed'] = True
            stats['validation_details'] = f"✓ Validation PASSED: Extracted {extracted_count} files (expected {expected_total})"
            logger.info(f"[EXTRACT] ✓ {zip_name}: Validation PASSED - {extracted_count}/{expected_total} files extracted")
        else:
            stats['validation_passed'] = False
            missing = expected_total - extracted_count
            stats['validation_details'] = f"⚠ Validation WARNING: Extracted {extracted_count} files, expected {expected_total} (missing {missing})"
            logger.warning(f"[EXTRACT] ⚠ {zip_name}: Validation WARNING - Extracted {extracted_count}/{expected_total} files (missing {missing})")
        
        if temp_skipped > 0:
            stats['validation_details'] += f", {temp_skipped} temp files skipped"
        
        # Cleanup temp directory
        shutil.rmtree(temp_extract_dir, ignore_errors=True)
        
    except Exception as e:
        logger.error(f"[EXTRACT] Error extracting {os.path.basename(zip_path)}: {e}")
        stats['validation_passed'] = False
        stats['validation_details'] = f"✗ Validation FAILED: Extraction error - {str(e)}"
        shutil.rmtree(temp_extract_dir, ignore_errors=True)
    
    return stats


def extract_zips_in_staging(case_id: int) -> Dict:
    """
    Extract all ZIP files in staging (recursive, handles nested ZIPs)
    
    Returns:
        dict: {
            'status': str,
            'total_extracted': int (alias for files_extracted),
            'zips_processed': int,
            'files_extracted': int,
            'nested_zips_found': int,
            'zips_deleted': int
        }
    """
    staging_dir = get_staging_path(case_id)
    stats = {
        'status': 'success',
        'zips_processed': 0,
        'files_extracted': 0,
        'nested_zips_found': 0,
        'temp_files_skipped': 0,
        'zips_deleted': 0,
        'validation_passed': True,
        'validation_warnings': []
    }
    
    logger.info("="*80)
    logger.info("[EXTRACT] Starting recursive ZIP extraction")
    logger.info("="*80)
    
    # Find all top-level ZIP files
    zip_files = [f for f in os.listdir(staging_dir) 
                 if f.lower().endswith('.zip') and not f.startswith('_temp_')]
    
    if not zip_files:
        logger.info("[EXTRACT] No ZIP files found")
        return stats
    
    logger.info(f"[EXTRACT] Found {len(zip_files)} ZIP file(s)")
    
    for zip_filename in zip_files:
        zip_path = os.path.join(staging_dir, zip_filename)
        
        try:
            logger.info(f"[EXTRACT] Processing: {zip_filename}")
            extract_stats = extract_single_zip(zip_path, staging_dir)
            
            stats['files_extracted'] += extract_stats['files_extracted']
            stats['nested_zips_found'] += extract_stats['nested_zips_found']
            stats['temp_files_skipped'] += extract_stats.get('temp_files_skipped', 0)
            
            # Track validation results
            if not extract_stats.get('validation_passed', True):
                stats['validation_passed'] = False
                validation_msg = extract_stats.get('validation_details', 'Validation failed')
                stats['validation_warnings'].append(f"{zip_filename}: {validation_msg}")
            
            # Delete original ZIP
            os.remove(zip_path)
            stats['zips_deleted'] += 1
            stats['zips_processed'] += 1
            
            temp_skipped = extract_stats.get('temp_files_skipped', 0)
            validation_status = "✓" if extract_stats.get('validation_passed', True) else "⚠"
            logger.info(f"[EXTRACT] {validation_status} {zip_filename}: {extract_stats['files_extracted']} files, "
                       f"{extract_stats['nested_zips_found']} nested ZIPs"
                       + (f", {temp_skipped} temp files skipped" if temp_skipped > 0 else "")
                       + (f" - {extract_stats.get('validation_details', '')}" if not extract_stats.get('validation_passed', True) else ""))
            
        except Exception as e:
            logger.error(f"[EXTRACT] Failed to process {zip_filename}: {e}")
            continue
    
    logger.info("="*80)
    logger.info(f"[EXTRACT] Complete: {stats['zips_processed']} ZIPs, "
                f"{stats['files_extracted']} files, {stats['nested_zips_found']} nested ZIPs"
                + (f", {stats['temp_files_skipped']} temp files skipped" if stats['temp_files_skipped'] > 0 else ""))
    
    # Log validation summary
    if not stats['validation_passed']:
        logger.warning(f"[EXTRACT] ⚠ VALIDATION WARNINGS:")
        for warning in stats['validation_warnings']:
            logger.warning(f"[EXTRACT]   - {warning}")
    else:
        logger.info(f"[EXTRACT] ✓ All ZIPs validated successfully")
    
    logger.info("="*80)
    
    # Add alias for backward compatibility
    stats['total_extracted'] = stats['files_extracted']
    
    return stats


# ============================================================================
# STEP 3: BUILD FILE QUEUE (Deduplicate + Hash)
# ============================================================================

def hash_file_fast(file_path: str) -> str:
    """Fast SHA256 hash using chunked reading"""
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()


def build_file_queue(db, CaseFile, SkippedFile, case_id: int) -> Dict:
    """
    Build queue of files to process, checking for duplicates
    
    Process:
    1. Scan all files in staging
    2. For each file: hash + check if (hash + filename) exists in DB
    3. If duplicate (exists in CaseFile or SkippedFile): 
       - Just delete file and skip (DON'T add to SkippedFile again)
       - Already processed or already skipped, no need to log again
    4. If new: create DB record, add to queue
    
    Returns:
        dict: {
            'status': str,
            'files_found': int,
            'files_queued': int,
            'duplicates_skipped': int,
            'zero_bytes_skipped': int,
            'queue': [(file_id, filename, file_path), ...]
        }
    """
    staging_dir = get_staging_path(case_id)
    final_dir = get_final_upload_path(case_id)
    os.makedirs(final_dir, exist_ok=True)
    
    stats = {
        'status': 'success',
        'files_found': 0,
        'files_queued': 0,
        'duplicates_skipped': 0,
        'zero_bytes_skipped': 0,
        'temp_files_skipped': 0,
        'queue': []
    }
    
    logger.info("="*80)
    logger.info("[QUEUE] Building file queue with duplicate detection")
    logger.info("="*80)
    
    # Get all files in staging
    all_files = [f for f in os.listdir(staging_dir) 
                 if os.path.isfile(os.path.join(staging_dir, f))]
    
    stats['files_found'] = len(all_files)
    logger.info(f"[QUEUE] Found {len(all_files)} file(s) in staging")
    
    for filename in all_files:
        staging_path = os.path.join(staging_dir, filename)
        file_size = os.path.getsize(staging_path)
        
        # Skip Windows temporary files (safety net - should be caught during extraction)
        if is_temp_file(filename):
            logger.warning(f"[QUEUE] Skipping temp file: {filename}")
            os.remove(staging_path)
            stats['temp_files_skipped'] += 1
            continue
        
        # Skip zero-byte files
        if file_size == 0:
            logger.warning(f"[QUEUE] Skipping zero-byte file: {filename}")
            os.remove(staging_path)
            stats['zero_bytes_skipped'] += 1
            continue
        
        # Hash file
        file_hash = hash_file_fast(staging_path)
        
        # Check if (hash + filename) exists in CaseFile
        existing_case_file = db.session.query(CaseFile).filter_by(
            case_id=case_id,
            original_filename=filename,
            file_hash=file_hash
        ).first()
        
        if existing_case_file:
            # Already processed or in queue - just delete and skip
            logger.info(f"[QUEUE] Duplicate skipped: {filename} (already in CaseFile, file_id {existing_case_file.id})")
            os.remove(staging_path)
            stats['duplicates_skipped'] += 1
            continue
        
        # Check if (hash + filename) exists in SkippedFile
        existing_skipped = db.session.query(SkippedFile).filter_by(
            case_id=case_id,
            filename=filename,
            file_hash=file_hash
        ).first()
        
        if existing_skipped:
            # Already skipped before - just delete and skip
            logger.info(f"[QUEUE] Duplicate skipped: {filename} (already in SkippedFile, reason: {existing_skipped.skip_reason})")
            os.remove(staging_path)
            stats['duplicates_skipped'] += 1
            continue
        
        # NEW FILE - Move to final upload directory
        final_path = os.path.join(final_dir, filename)
        shutil.move(staging_path, final_path)
        
        # Create CaseFile record (status: Queued)
        case_file = CaseFile(
            case_id=case_id,
            filename=filename,
            original_filename=filename,
            file_path=final_path,
            file_size=file_size,
            file_hash=file_hash,
            mime_type='application/octet-stream',
            uploaded_by=1,  # Will be overridden by caller
            indexing_status='Queued',
            upload_type='staging',
            is_indexed=False
        )
        db.session.add(case_file)
        db.session.flush()  # Get ID without committing
        
        stats['queue'].append((case_file.id, filename, final_path))
        stats['files_queued'] += 1
        logger.info(f"[QUEUE] Queued: {filename} (file_id={case_file.id})")
    
    # Commit all DB changes
    db.session.commit()
    
    logger.info("="*80)
    logger.info(f"[QUEUE] Complete:")
    logger.info(f"  Files found: {stats['files_found']}")
    logger.info(f"  Files queued: {stats['files_queued']}")
    logger.info(f"  Duplicates skipped: {stats['duplicates_skipped']}")
    logger.info(f"  Zero-byte skipped: {stats['zero_bytes_skipped']}")
    if stats['temp_files_skipped'] > 0:
        logger.info(f"  Temp files skipped: {stats['temp_files_skipped']}")
    logger.info("="*80)
    
    return stats


# ============================================================================
# STEP 4: FILTER ZERO-EVENT FILES
# ============================================================================

def filter_zero_event_files(db, CaseFile, SkippedFile, queue: List[Tuple], case_id: int) -> Dict:
    """
    Convert EVTX to JSON, get event counts, handle 0-event files
    
    For 0-event files:
    1. Create CaseFile record (for audit trail)
    2. Mark as hidden in UI
    3. Archive EVTX to /opt/casescope/archive/{case_id}/
    4. Add to SkippedFile table
    5. Remove from processing queue
    
    Args:
        queue: List of (file_id, filename, file_path) tuples
        case_id: Case ID for archive folder
    
    Returns:
        dict: {
            'processed': int,
            'zero_events': int,
            'valid_files': int,
            'filtered_queue': [(file_id, filename, file_path, event_count), ...]
        }
    """
    stats = {
        'processed': 0,
        'zero_events': 0,
        'valid_files': 0,
        'filtered_queue': []
    }
    
    # Create archive directory
    archive_dir = f"/opt/casescope/archive/{case_id}"
    os.makedirs(archive_dir, exist_ok=True)
    
    logger.info("="*80)
    logger.info("[FILTER] Checking for zero-event files")
    logger.info("="*80)
    
    for file_id, filename, file_path in queue:
        stats['processed'] += 1
        
        # Only check EVTX files
        if not filename.lower().endswith('.evtx'):
            # NDJSON/JSON files: assume valid, will get counted during indexing
            stats['filtered_queue'].append((file_id, filename, file_path, None))
            stats['valid_files'] += 1
            continue
        
        try:
            # Run evtx_dump to get event count
            cmd = ['/opt/casescope/bin/evtx_dump', '-t', '1', '--no-confirm-overwrite', file_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode != 0:
                logger.warning(f"[FILTER] evtx_dump failed for {filename}, assuming valid")
                stats['filtered_queue'].append((file_id, filename, file_path, None))
                stats['valid_files'] += 1
                continue
            
            # Count events from output
            event_count = result.stdout.count('Event') if result.stdout else 0
            
            if event_count == 0:
                logger.warning(f"[FILTER] Zero events: {filename}")
                
                # Get CaseFile record
                case_file = db.session.get(CaseFile, file_id)
                if case_file:
                    # Update CaseFile: keep record for audit, but mark as hidden
                    case_file.event_count = 0
                    case_file.is_indexed = True
                    case_file.is_hidden = True  # Hidden from UI
                    case_file.file_state = 'Hidden'
                    
                    # Set file_type based on extension if not already set
                    if not case_file.file_type or case_file.file_type == 'UNKNOWN':
                        filename_lower = filename.lower()
                        if filename_lower.endswith('.evtx'):
                            case_file.file_type = 'EVTX'
                        elif filename_lower.endswith('.ndjson'):
                            case_file.file_type = 'NDJSON'
                        elif filename_lower.endswith('.json'):
                            case_file.file_type = 'JSON'
                        elif filename_lower.endswith('.csv'):
                            case_file.file_type = 'CSV'
                        else:
                            case_file.file_type = 'UNKNOWN'
                        logger.info(f"[FILTER]   Set file_type to: {case_file.file_type}")
                    
                    # Archive the EVTX file (for audit purposes)
                    archive_path = os.path.join(archive_dir, filename)
                    shutil.move(file_path, archive_path)
                    case_file.file_path = archive_path  # Update path to archive location
                    logger.info(f"[FILTER]   Archived to: {archive_path}")
                    
                    # Add to SkippedFile (for reporting)
                    skipped = SkippedFile(
                        case_id=case_id,
                        filename=filename,
                        file_size=case_file.file_size,
                        file_hash=case_file.file_hash,
                        skip_reason='zero_events',
                        skip_details='EVTX file has 0 events (archived for audit)',
                        upload_type='staging'
                    )
                    db.session.add(skipped)
                
                stats['zero_events'] += 1
                # DO NOT add to filtered_queue - file won't be processed
            else:
                # Valid file with events - add to queue for processing
                stats['filtered_queue'].append((file_id, filename, file_path, event_count))
                stats['valid_files'] += 1
                logger.info(f"[FILTER] Valid: {filename} ({event_count} events)")
        
        except Exception as e:
            logger.error(f"[FILTER] Error processing {filename}: {e}")
            # Assume valid on error - better to process than skip
            stats['filtered_queue'].append((file_id, filename, file_path, None))
            stats['valid_files'] += 1
    
    db.session.commit()
    
    logger.info("="*80)
    logger.info(f"[FILTER] Complete:")
    logger.info(f"  Files processed: {stats['processed']}")
    logger.info(f"  Zero-event files: {stats['zero_events']} (archived)")
    logger.info(f"  Valid files: {stats['valid_files']}")
    logger.info("="*80)
    
    return stats


# ============================================================================
# MAIN PIPELINE ORCHESTRATION
# ============================================================================

def process_upload_pipeline(db, CaseFile, SkippedFile, case_id: int, 
                           upload_source: str, celery_app=None) -> Dict:
    """
    Main pipeline orchestrator
    
    Args:
        db: Database session
        CaseFile: CaseFile model
        SkippedFile: SkippedFile model
        case_id: Case ID
        upload_source: 'http' or 'bulk' or 'staging' (if files already in staging)
        celery_app: Celery app for task queuing
    
    Returns:
        dict: Complete pipeline statistics
    """
    pipeline_stats = {
        'stage': 'starting',
        'files_found': 0,
        'files_queued': 0,
        'duplicates_skipped': 0,
        'zero_bytes_skipped': 0,
        'zero_events_skipped': 0,
        'files_ready': 0,
        'zips_extracted': 0
    }
    
    try:
        # STEP 2: Extract ZIPs
        extract_stats = extract_zips_in_staging(case_id)
        pipeline_stats['stage'] = 'extracted'
        pipeline_stats['zips_extracted'] = extract_stats['files_extracted']
        
        # STEP 3: Build queue (deduplicate)
        queue_stats = build_file_queue(db, CaseFile, SkippedFile, case_id)
        pipeline_stats['stage'] = 'queued'
        pipeline_stats['files_found'] = queue_stats['files_found']
        pipeline_stats['files_queued'] = queue_stats['files_queued']
        pipeline_stats['duplicates_skipped'] = queue_stats['duplicates_skipped']
        pipeline_stats['zero_bytes_skipped'] = queue_stats['zero_bytes_skipped']
        pipeline_stats['temp_files_skipped'] = extract_stats.get('temp_files_skipped', 0) + queue_stats.get('temp_files_skipped', 0)
        
        # STEP 4: Filter zero-event files
        filter_stats = filter_zero_event_files(db, CaseFile, SkippedFile, queue_stats['queue'], case_id)
        pipeline_stats['stage'] = 'filtered'
        pipeline_stats['zero_events_skipped'] = filter_stats['zero_events']
        pipeline_stats['files_ready'] = filter_stats['valid_files']
        
        # STEP 5: Queue files for processing
        if celery_app and filter_stats['filtered_queue']:
            for file_id, filename, file_path, event_count in filter_stats['filtered_queue']:
                celery_app.send_task('tasks.process_file', args=[file_id, 'full'])
                logger.info(f"[PIPELINE] Queued for processing: {filename} (file_id={file_id})")
        
        pipeline_stats['stage'] = 'complete'
        pipeline_stats['success'] = True
        
    except Exception as e:
        logger.error(f"[PIPELINE] Error: {e}")
        import traceback
        traceback.print_exc()
        pipeline_stats['stage'] = 'error'
        pipeline_stats['success'] = False
        pipeline_stats['error'] = str(e)
    
    return pipeline_stats

