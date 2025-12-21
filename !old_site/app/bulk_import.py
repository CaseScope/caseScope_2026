"""
Bulk Import Module
Handles local directory file imports for batch processing

Reuses existing upload pipeline functions for consistency
"""

import os
import shutil
from typing import List, Dict, Tuple
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

BULK_IMPORT_DIR = '/opt/casescope/bulk_import'
ALLOWED_EXTENSIONS = {'.evtx', '.ndjson', '.json', '.csv', '.log', '.zip'}  # All formats accepted for upload (v1.14.0: Added .log for IIS)


def scan_bulk_import_directory() -> Dict[str, List[str]]:
    """
    Scan bulk import directory for supported files
    
    Returns:
        Dict with file counts and paths by type
    """
    if not os.path.exists(BULK_IMPORT_DIR):
        return {'error': 'Bulk import directory not found', 'files': []}
    
    files_by_type = {
        'evtx': [],
        'json': [],
        'ndjson': [],
        'csv': [],
        'iis': [],  # v1.14.0: IIS log files
        'zip': [],
        'other': []
    }
    
    try:
        for item in os.listdir(BULK_IMPORT_DIR):
            filepath = os.path.join(BULK_IMPORT_DIR, item)
            
            # Skip directories
            if os.path.isdir(filepath):
                continue
            
            # Check extension
            ext = Path(item).suffix.lower()
            
            if ext in ALLOWED_EXTENSIONS:
                # Categorize by type
                if ext == '.evtx':
                    files_by_type['evtx'].append(filepath)
                elif ext == '.csv':
                    files_by_type['csv'].append(filepath)
                elif ext in ['.jsonl', '.ndjson']:
                    files_by_type['ndjson'].append(filepath)
                elif ext == '.json':
                    files_by_type['json'].append(filepath)
                elif ext == '.log':
                    # v1.14.0: IIS logs detected by .log extension
                    files_by_type['iis'].append(filepath)
                elif ext == '.zip':
                    files_by_type['zip'].append(filepath)
            else:
                files_by_type['other'].append(filepath)
        
        # Calculate totals
        total_supported = sum(len(files_by_type[k]) for k in ['evtx', 'json', 'ndjson', 'csv', 'iis', 'zip'])
        
        return {
            'total_supported': total_supported,
            'total_other': len(files_by_type['other']),
            'files_by_type': files_by_type,
            'directory': BULK_IMPORT_DIR
        }
    
    except Exception as e:
        logger.error(f"Error scanning bulk import directory: {e}")
        return {'error': str(e), 'files': []}


def move_file_to_staging(source_path: str, staging_dir: str, case_id: int) -> Tuple[bool, str, str]:
    """
    Move file from bulk import directory to staging
    Reuses staging directory structure from upload_pipeline
    
    Args:
        source_path: Full path to source file
        staging_dir: Base staging directory
        case_id: Case ID for organization
        
    Returns:
        Tuple of (success, destination_path, error_message)
    """
    try:
        filename = os.path.basename(source_path)
        dest_path = os.path.join(staging_dir, filename)
        
        # Move file (faster than copy+delete)
        shutil.move(source_path, dest_path)
        
        logger.info(f"[BULK IMPORT] Moved {filename} to staging")
        return True, dest_path, None
    
    except Exception as e:
        error_msg = f"Failed to move {os.path.basename(source_path)}: {str(e)}"
        logger.error(f"[BULK IMPORT] {error_msg}")
        return False, None, error_msg


def cleanup_processed_files(staging_dir: str):
    """
    Clean up staging directory after processing
    Reusable cleanup function
    
    Args:
        staging_dir: Directory to clean
    """
    try:
        if os.path.exists(staging_dir):
            shutil.rmtree(staging_dir)
            logger.info(f"[BULK IMPORT] Cleaned up staging directory: {staging_dir}")
    except Exception as e:
        logger.error(f"[BULK IMPORT] Failed to clean staging: {e}")


def get_bulk_import_stats() -> Dict[str, int]:
    """
    Get statistics about bulk import directory
    
    Returns:
        Dict with file counts
    """
    scan_result = scan_bulk_import_directory()
    
    if 'error' in scan_result:
        return {
            'total_files': 0,
            'supported_files': 0,
            'unsupported_files': 0,
            'error': scan_result['error']
        }
    
    return {
        'total_files': scan_result['total_supported'] + scan_result['total_other'],
        'supported_files': scan_result['total_supported'],
        'unsupported_files': scan_result['total_other'],
        'evtx_count': len(scan_result['files_by_type']['evtx']),
        'json_count': len(scan_result['files_by_type']['json']),
        'ndjson_count': len(scan_result['files_by_type']['ndjson']),
        'csv_count': len(scan_result['files_by_type']['csv']),
        'iis_count': len(scan_result['files_by_type'].get('iis', [])),  # v1.14.0: IIS log count
        'zip_count': len(scan_result['files_by_type']['zip']),
        'directory': scan_result['directory']
    }

