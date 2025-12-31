"""
File Ingestion System - NEW_FILE_UPLOAD.ND Implementation
Handles complete file upload and processing pipeline
"""

import os
import re
import hashlib
import zipfile
import shutil
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Tuple, Optional

# Will be imported within functions to avoid circular imports
# from main import db
# from models import Case, CaseFile, IngestionProgress
# from audit_logger import log_action


def sanitize_folder_name(filename: str) -> str:
    """
    Sanitize ZIP filename for use as subfolder name
    
    Rules (NEW_FILE_UPLOAD.ND #9):
    - Remove/replace: < > : " / \ | ? * newlines tabs
    - Replace spaces with underscores
    - Keep dashes and periods
    - No max length limit
    - Example: "Security Logs.zip" → "Security_Logs.zip/"
    
    Args:
        filename: Original filename with extension
    
    Returns:
        Sanitized folder name
    """
    # Replace invalid characters
    invalid_chars = r'[<>:"/\\|?*\n\t]'
    sanitized = re.sub(invalid_chars, '_', filename)
    
    # Replace spaces with underscores
    sanitized = sanitized.replace(' ', '_')
    
    # Remove any double underscores
    while '__' in sanitized:
        sanitized = sanitized.replace('__', '_')
    
    return sanitized


def calculate_sha256(file_path: str) -> str:
    """
    Calculate SHA256 hash of a file
    
    Args:
        file_path: Path to file
    
    Returns:
        SHA256 hash as hex string
    """
    sha256_hash = hashlib.sha256()
    
    with open(file_path, 'rb') as f:
        # Read in chunks for memory efficiency
        for chunk in iter(lambda: f.read(8192), b''):
            sha256_hash.update(chunk)
    
    return sha256_hash.hexdigest()


def check_duplicate_file(case_id: int, file_hash: str) -> Optional[Dict]:
    """
    Check if file with same hash already exists in storage for this case
    
    Args:
        case_id: Case ID
        file_hash: SHA256 hash
    
    Returns:
        Dict with duplicate info if found, None if no duplicate
        {
            'exists': bool,
            'file_id': int,
            'file_path': str,
            'file_exists_on_disk': bool,
            'verified_hash': str (if re-verified)
        }
    """
    from main import db
    from models import CaseFile
    
    # Query database for existing file with same hash
    existing = CaseFile.query.filter_by(
        case_id=case_id,
        file_hash=file_hash
    ).first()
    
    if not existing:
        return None
    
    # Verify file still exists in storage
    file_exists = os.path.exists(existing.file_path) if existing.file_path else False
    
    result = {
        'exists': True,
        'file_id': existing.id,
        'file_path': existing.file_path,
        'file_exists_on_disk': file_exists,
        'original_filename': existing.original_filename
    }
    
    # If file exists on disk, re-verify hash
    if file_exists:
        try:
            verified_hash = calculate_sha256(existing.file_path)
            result['verified_hash'] = verified_hash
            result['hash_matches'] = (verified_hash == file_hash)
        except Exception as e:
            result['verification_error'] = str(e)
    
    return result


def extract_zip_to_staging(zip_path: str, staging_folder: str, case_id: int) -> Dict:
    """
    Extract ZIP file to staging with sanitized subfolder naming
    
    Args:
        zip_path: Path to ZIP file
        staging_folder: Staging directory for this case
        case_id: Case ID for logging
    
    Returns:
        Dict with extraction results:
        {
            'success': bool,
            'extracted_folder': str,
            'files_extracted': int,
            'nested_zips': List[str],
            'errors': List[Dict]
        }
    """
    from audit_logger import log_action
    
    # Get ZIP filename and create sanitized subfolder name
    zip_filename = os.path.basename(zip_path)
    subfolder_name = sanitize_folder_name(zip_filename)
    extraction_path = os.path.join(staging_folder, subfolder_name)
    
    # Create extraction directory
    os.makedirs(extraction_path, mode=0o770, exist_ok=True)
    
    errors = []
    nested_zips = []
    files_extracted = 0
    
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            # Get file list
            file_list = zip_ref.namelist()
            
            # Extract all files
            for file_info in zip_ref.infolist():
                try:
                    zip_ref.extract(file_info, extraction_path)
                    files_extracted += 1
                    
                    # Check if this is a nested ZIP (treat as regular file, no recursive extraction)
                    extracted_path = os.path.join(extraction_path, file_info.filename)
                    if file_info.filename.lower().endswith('.zip') and os.path.isfile(extracted_path):
                        nested_zips.append(file_info.filename)
                    
                except Exception as e:
                    errors.append({
                        'file': file_info.filename,
                        'error': str(e)
                    })
        
        # Log successful extraction
        log_action(
            action='zip_extracted',
            resource_type='file',
            details={
                'case_id': case_id,
                'zip_file': zip_filename,
                'extracted_to': extraction_path,
                'files_extracted': files_extracted,
                'nested_zips_count': len(nested_zips),
                'errors_count': len(errors)
            },
            status='success' if len(errors) == 0 else 'partial'
        )
        
        return {
            'success': len(errors) == 0,
            'extracted_folder': extraction_path,
            'files_extracted': files_extracted,
            'nested_zips': nested_zips,
            'errors': errors
        }
        
    except Exception as e:
        log_action(
            action='zip_extraction_failed',
            resource_type='file',
            details={
                'case_id': case_id,
                'zip_file': zip_filename,
                'error': str(e)
            },
            status='failed'
        )
        
        return {
            'success': False,
            'error': str(e),
            'files_extracted': 0,
            'errors': [{'file': zip_filename, 'error': str(e)}]
        }


def get_parser_type_from_file(filename: str, file_content_sample: bytes = None) -> str:
    """
    Determine parser type from filename and optionally file content
    
    Args:
        filename: File name with extension
        file_content_sample: Optional first few bytes for content detection
    
    Returns:
        Parser type string (evtx, edr, firewall, iis, sysmon, json, xml, csv, etc.)
    """
    filename_lower = filename.lower()
    
    # Extension-based detection
    if filename_lower.endswith('.evtx'):
        return 'evtx'
    elif filename_lower.endswith(('.ndjson', '.jsonl')):
        return 'edr'  # NDJSON typically EDR logs
    elif filename_lower.endswith('.json'):
        return 'json'
    elif filename_lower.endswith('.xml'):
        return 'xml'
    elif filename_lower.endswith('.csv'):
        # Could be firewall or generic CSV
        return 'firewall'  # Default for CSV, can be refined with content inspection
    elif filename_lower.endswith('.log'):
        # Could be IIS or other text log
        if 'iis' in filename_lower or 'w3svc' in filename_lower:
            return 'iis'
        return 'log'
    elif filename_lower.endswith('.pf'):
        return 'prefetch'
    elif filename_lower.endswith('.dat'):
        if 'srudb' in filename_lower:
            return 'srum'
        elif 'webcache' in filename_lower:
            return 'webcache'
        return 'dat'
    elif filename_lower.endswith(('.db', '.sqlite', '.sqlite3')):
        if 'history' in filename_lower:
            return 'browser_history'
        return 'sqlite'
    
    # Sysmon detection (usually in evtx but could be ndjson)
    if 'sysmon' in filename_lower:
        return 'sysmon'
    
    # Default fallback
    return 'unknown'


def determine_file_status(parsed: bool, event_count: int, has_errors: bool) -> str:
    """
    Determine file status based on processing results
    
    Status definitions (NEW_FILE_UPLOAD.ND):
    - New: File before ANY index processing is done
    - ParseFail: Unable to parse and index file
    - ZeroEvents: File parsed but contains no events  
    - Error: Some other error happened with file
    - Partial: Not all events indexed successfully
    - Indexed: All events indexed successfully
    
    Args:
        parsed: Whether file was successfully parsed
        event_count: Number of events found
        has_errors: Whether there were partial errors
    
    Returns:
        Status string
    """
    if not parsed:
        return 'ParseFail'
    
    if event_count == 0:
        return 'ZeroEvents'
    
    if has_errors:
        return 'Partial'
    
    return 'Indexed'


def move_file_to_storage(source_path: str, case_id: int, original_filename: str, 
                         preserve_structure: bool = True) -> Tuple[bool, str, Optional[str]]:
    """
    Move file from staging to storage with validation
    
    All-or-nothing operation per file (NEW_FILE_UPLOAD.ND #11, #12)
    
    Args:
        source_path: Source file path in staging
        case_id: Case ID
        original_filename: Original filename
        preserve_structure: Whether to preserve subfolder structure
    
    Returns:
        Tuple of (success: bool, storage_path: str, error: Optional[str])
    """
    from audit_logger import log_action
    
    try:
        # Determine storage path
        storage_base = f'/opt/casescope/case_files/{case_id}'
        os.makedirs(storage_base, mode=0o770, exist_ok=True)
        
        if preserve_structure:
            # Preserve subfolder structure from staging
            # Extract relative path from staging
            staging_base = f'/opt/casescope/staging/{case_id}'
            if source_path.startswith(staging_base):
                rel_path = os.path.relpath(source_path, staging_base)
                storage_path = os.path.join(storage_base, rel_path)
            else:
                storage_path = os.path.join(storage_base, os.path.basename(source_path))
        else:
            storage_path = os.path.join(storage_base, original_filename)
        
        # Create parent directory if needed
        os.makedirs(os.path.dirname(storage_path), mode=0o770, exist_ok=True)
        
        # Calculate original hash
        original_hash = calculate_sha256(source_path)
        
        # Move file
        shutil.move(source_path, storage_path)
        
        # Post-move validation: Re-check SHA256
        verified_hash = calculate_sha256(storage_path)
        
        if original_hash != verified_hash:
            # Hash mismatch - this needs user decision (CONTINUE or ABORT)
            # For now, log it but keep the file
            log_action(
                action='file_move_hash_mismatch',
                resource_type='file',
                details={
                    'case_id': case_id,
                    'file': original_filename,
                    'original_hash': original_hash,
                    'verified_hash': verified_hash,
                    'storage_path': storage_path,
                    'action_taken': 'kept_file_logged_discrepancy'
                },
                status='warning'
            )
            # Note: In full implementation, this would trigger user prompt
            # For now, we continue and log the discrepancy
        
        return (True, storage_path, None)
        
    except Exception as e:
        error_msg = str(e)
        log_action(
            action='file_move_failed',
            resource_type='file',
            details={
                'case_id': case_id,
                'file': original_filename,
                'source_path': source_path,
                'error': error_msg
            },
            status='failed'
        )
        return (False, None, error_msg)


def cleanup_staging(case_id: int):
    """
    Clean up staging folder after successful ingestion
    
    Args:
        case_id: Case ID
    """
    from audit_logger import log_action
    
    staging_dir = f'/opt/casescope/staging/{case_id}'
    
    if os.path.exists(staging_dir):
        try:
            # Count files before deletion
            file_count = sum(1 for _ in Path(staging_dir).rglob('*') if _.is_file())
            
            shutil.rmtree(staging_dir)
            
            log_action(
                action='staging_cleanup',
                resource_type='case',
                details={
                    'case_id': case_id,
                    'files_deleted': file_count
                },
                status='success'
            )
            
        except Exception as e:
            log_action(
                action='staging_cleanup_failed',
                resource_type='case',
                details={
                    'case_id': case_id,
                    'error': str(e)
                },
                status='failed'
            )


def cleanup_uploads(case_id: int, upload_type: str = 'web'):
    """
    Clean up upload folder after successful staging
    
    Args:
        case_id: Case ID
        upload_type: 'web' or 'sftp'
    """
    from audit_logger import log_action
    
    upload_dir = f'/opt/casescope/uploads/{upload_type}/{case_id}'
    
    if os.path.exists(upload_dir):
        try:
            # Count files before deletion
            file_count = sum(1 for _ in Path(upload_dir).rglob('*') if _.is_file())
            
            # Delete all files but keep the folder
            for item in os.listdir(upload_dir):
                item_path = os.path.join(upload_dir, item)
                if os.path.isfile(item_path):
                    os.remove(item_path)
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path)
            
            log_action(
                action='upload_cleanup',
                resource_type='case',
                details={
                    'case_id': case_id,
                    'upload_type': upload_type,
                    'files_deleted': file_count
                },
                status='success'
            )
            
        except Exception as e:
            log_action(
                action='upload_cleanup_failed',
                resource_type='case',
                details={
                    'case_id': case_id,
                    'upload_type': upload_type,
                    'error': str(e)
                },
                status='failed'
            )


def scan_upload_folder(case_id: int, upload_type: str = 'web') -> List[Dict]:
    """
    Scan upload folder for files to process
    
    Args:
        case_id: Case ID
        upload_type: 'web' or 'sftp'
    
    Returns:
        List of file info dicts:
        [
            {
                'path': str,
                'filename': str,
                'size': int,
                'is_zip': bool
            }
        ]
    """
    upload_dir = f'/opt/casescope/uploads/{upload_type}/{case_id}'
    
    if not os.path.exists(upload_dir):
        return []
    
    files = []
    for item in os.listdir(upload_dir):
        item_path = os.path.join(upload_dir, item)
        if os.path.isfile(item_path):
            files.append({
                'path': item_path,
                'filename': item,
                'size': os.path.getsize(item_path),
                'is_zip': item.lower().endswith('.zip')
            })
    
    return files


def stage_file(file_path: str, case_id: int, is_zip: bool = False) -> Dict:
    """
    Stage a file for processing - either move to staging or extract ZIP
    
    Args:
        file_path: Source file path in uploads
        case_id: Case ID
        is_zip: Whether file is a ZIP archive
    
    Returns:
        Dict with staging results:
        {
            'success': bool,
            'staged_files': List[str],  # Paths to staged files
            'is_zip': bool,
            'extraction_folder': str (if ZIP),
            'error': str (if failed)
        }
    """
    from audit_logger import log_action
    
    staging_base = f'/opt/casescope/staging/{case_id}'
    os.makedirs(staging_base, mode=0o770, exist_ok=True)
    
    filename = os.path.basename(file_path)
    
    if is_zip:
        # Extract ZIP to subfolder
        result = extract_zip_to_staging(file_path, staging_base, case_id)
        
        if result['success']:
            # Get list of extracted files
            extraction_folder = result['extracted_folder']
            staged_files = []
            
            for root, dirs, files in os.walk(extraction_folder):
                for file in files:
                    full_path = os.path.join(root, file)
                    staged_files.append(full_path)
            
            return {
                'success': True,
                'staged_files': staged_files,
                'is_zip': True,
                'extraction_folder': extraction_folder,
                'nested_zips': result.get('nested_zips', []),
                'files_extracted': len(staged_files)
            }
        else:
            return {
                'success': False,
                'error': result.get('error', 'Unknown extraction error'),
                'is_zip': True
            }
    
    else:
        # Regular file - just move to staging
        try:
            dest_path = os.path.join(staging_base, filename)
            shutil.move(file_path, dest_path)
            
            log_action(
                action='file_staged',
                resource_type='file',
                details={
                    'case_id': case_id,
                    'filename': filename,
                    'staged_path': dest_path
                },
                status='success'
            )
            
            return {
                'success': True,
                'staged_files': [dest_path],
                'is_zip': False
            }
            
        except Exception as e:
            log_action(
                action='file_staging_failed',
                resource_type='file',
                details={
                    'case_id': case_id,
                    'filename': filename,
                    'error': str(e)
                },
                status='failed'
            )
            
            return {
                'success': False,
                'error': str(e),
                'is_zip': False
            }


def create_file_record(case_id: int, file_path: str, original_filename: str, 
                       file_hash: str, uploaded_by: int, parser_type: str = None) -> int:
    """
    Create database record for a file
    
    Args:
        case_id: Case ID
        file_path: Path to file in storage
        original_filename: Original filename
        file_hash: SHA256 hash
        uploaded_by: User ID who uploaded
        parser_type: Parser type (auto-determined if None)
    
    Returns:
        File ID of created record
    """
    from main import db
    from models import CaseFile
    
    # Auto-determine parser type if not provided
    if not parser_type:
        parser_type = get_parser_type_from_file(original_filename)
    
    # Get file info
    file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
    file_type = os.path.splitext(original_filename)[1].lstrip('.')
    
    # Create record
    case_file = CaseFile(
        case_id=case_id,
        filename=os.path.basename(file_path),
        original_filename=original_filename,
        file_type=file_type,
        file_size=file_size,
        file_path=file_path,
        file_hash=file_hash,
        parser_type=parser_type,
        status='New',  # NEW status per NEW_FILE_UPLOAD.ND
        uploaded_by=uploaded_by,
        uploaded_at=datetime.utcnow()
    )
    
    db.session.add(case_file)
    db.session.flush()
    
    return case_file.id


def get_or_create_ingestion_progress(case_id: int, user_id: int) -> int:
    """
    Get existing ingestion progress or create new one
    
    Args:
        case_id: Case ID
        user_id: User ID starting ingestion
    
    Returns:
        IngestionProgress ID
    """
    from main import db
    from models import IngestionProgress
    
    # Check for existing in-progress ingestion
    existing = IngestionProgress.query.filter_by(
        case_id=case_id,
        status='in_progress'
    ).first()
    
    if existing:
        return existing.id
    
    # Create new progress record
    progress = IngestionProgress(
        case_id=case_id,
        started_by=user_id,
        started_at=datetime.utcnow(),
        status='pending',
        can_resume=True
    )
    
    db.session.add(progress)
    db.session.flush()
    
    return progress.id


def update_ingestion_progress(progress_id: int, **kwargs):
    """
    Update ingestion progress record
    
    Args:
        progress_id: IngestionProgress ID
        **kwargs: Fields to update (status, current_step, processed_files, etc.)
    """
    from main import db
    from models import IngestionProgress
    
    progress = IngestionProgress.query.get(progress_id)
    if not progress:
        return
    
    for key, value in kwargs.items():
        if hasattr(progress, key):
            setattr(progress, key, value)
    
    db.session.commit()

