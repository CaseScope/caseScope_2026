"""
Archive Detection and Hostname Extraction Utilities
====================================================
Detects archive type and extracts hostnames from various sources
"""

import os
import re
import zipfile
import logging
from typing import Optional, Dict, List, Tuple

logger = logging.getLogger(__name__)


def extract_hostname_from_filename(filename: str) -> Optional[str]:
    """
    Extract hostname from filename
    
    Args:
        filename: File or archive name
    
    Returns:
        Hostname or None
    
    Examples:
        ATN62319.zip -> ATN62319
        WORKSTATION-01.zip -> WORKSTATION-01
        forensic_collection.zip -> forensic_collection
    """
    # Remove extension
    name = os.path.splitext(filename)[0]
    
    # Remove common suffixes
    name = re.sub(r'[-_](collection|forensic|data|export|archive)$', '', name, flags=re.IGNORECASE)
    
    # Remove dates (YYYYMMDD, YYYY-MM-DD)
    name = re.sub(r'[-_]\d{4}[-_]?\d{2}[-_]?\d{2}$', '', name)
    
    # Clean up
    name = name.strip('_- ')
    
    return name if name and len(name) > 2 else None


def detect_archive_type(zip_path: str) -> Dict[str, any]:
    """
    Detect archive type by inspecting contents
    
    Args:
        zip_path: Path to ZIP file
    
    Returns:
        dict with 'type', 'confidence', 'hostnames', 'structure'
    """
    result = {
        'type': 'unknown',
        'confidence': 'low',
        'hostnames': [],
        'structure': 'unknown',
        'has_evtx': False,
        'has_mft': False,
        'file_count': 0,
        'sample_paths': []
    }
    
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            file_list = zf.namelist()
            result['file_count'] = len(file_list)
            result['sample_paths'] = file_list[:20]  # First 20 for inspection
            
            # Pattern 1: CyLR/KAPE Single-Host Collection
            # Structure: C/Windows/System32/winevt/Logs/*.evtx
            evtx_files = [f for f in file_list if f.endswith('.evtx')]
            mft_files = [f for f in file_list if '$MFT' in f]
            
            result['has_evtx'] = len(evtx_files) > 0
            result['has_mft'] = len(mft_files) > 0
            
            # Check for CyLR structure (C/, D/, etc. at root)
            root_dirs = set()
            for path in file_list:
                if '/' in path:
                    root_dirs.add(path.split('/')[0])
            
            is_cylr_structure = any(d in ['C', 'D', 'E', 'F'] for d in root_dirs)
            
            if is_cylr_structure and result['has_evtx']:
                result['type'] = 'single_host'
                result['confidence'] = 'high'
                result['structure'] = 'cylr'
                logger.info(f"Detected CyLR archive with {len(evtx_files)} EVTX files")
                return result
            
            # Pattern 2: Multi-host with hostname directories
            # Structure: HOSTNAME1/..., HOSTNAME2/...
            potential_hostnames = []
            for path in file_list[:100]:  # Sample first 100
                if '/' in path:
                    first_dir = path.split('/')[0]
                    # Skip known non-hostname directories
                    if first_dir not in ['C', 'D', 'E', 'F', 'Users', 'Windows', 'Program Files']:
                        # Check if it looks like a hostname
                        if re.match(r'^[A-Za-z0-9][A-Za-z0-9\-_.]+$', first_dir):
                            potential_hostnames.append(first_dir)
            
            unique_hostnames = list(set(potential_hostnames))
            if len(unique_hostnames) > 1:
                result['type'] = 'multi_host'
                result['confidence'] = 'high'
                result['hostnames'] = unique_hostnames[:20]  # Limit to 20
                result['structure'] = 'hostname_dirs'
                logger.info(f"Detected multi-host archive with {len(unique_hostnames)} hostnames")
                return result
            
            # Pattern 3: NDJSON/JSON bulk export (likely EDR)
            json_files = [f for f in file_list if f.endswith(('.json', '.ndjson', '.jsonl'))]
            if len(json_files) > 0 and len(json_files) == len(file_list):
                result['type'] = 'multi_host'
                result['confidence'] = 'medium'
                result['structure'] = 'ndjson_export'
                logger.info(f"Detected NDJSON export with {len(json_files)} files")
                return result
            
            # Pattern 4: CSV/Log files
            csv_files = [f for f in file_list if f.endswith(('.csv', '.log', '.txt'))]
            if len(csv_files) > len(file_list) * 0.8:  # 80% are logs/csv
                result['type'] = 'multi_host'
                result['confidence'] = 'medium'
                result['structure'] = 'log_export'
                logger.info(f"Detected log export with {len(csv_files)} log files")
                return result
            
            # Default: Unknown with artifacts
            if result['has_evtx'] or result['has_mft']:
                result['type'] = 'single_host'
                result['confidence'] = 'medium'
                result['structure'] = 'custom'
            
    except zipfile.BadZipFile:
        logger.error(f"Bad ZIP file: {zip_path}")
        result['confidence'] = 'none'
    except Exception as e:
        logger.error(f"Error detecting archive type: {e}")
        result['confidence'] = 'none'
    
    return result


def suggest_hostname_source(archive_info: Dict, filename: str) -> Tuple[str, str, str]:
    """
    Suggest initial hostname and source method
    
    Args:
        archive_info: Result from detect_archive_type()
        filename: Original filename
    
    Returns:
        (suggested_hostname, source_method, confidence)
    """
    if archive_info['type'] == 'single_host':
        # For single-host, use filename as initial guess
        hostname = extract_hostname_from_filename(filename)
        if hostname:
            return hostname, 'filename', 'pending'  # Will be refined during processing
        else:
            return 'Unknown', 'none', 'low'
    
    elif archive_info['type'] == 'multi_host':
        # For multi-host, don't assign a single hostname
        return None, 'per_file', 'high'
    
    else:
        # Unknown type
        hostname = extract_hostname_from_filename(filename)
        return hostname or 'Unknown', 'filename', 'low'


def extract_username_from_path(file_path: str) -> Optional[str]:
    """
    Extract username from Windows file path
    
    Args:
        file_path: File path (e.g., C/Users/username/...)
    
    Returns:
        Username or None
    
    Examples:
        C/Users/tab/AppData/... -> tab
        C/Users/Administrator/Desktop/... -> Administrator
    """
    # Pattern: C/Users/<username>/
    match = re.search(r'[/\\]Users[/\\]([^/\\]+)[/\\]', file_path, re.IGNORECASE)
    if match:
        username = match.group(1)
        # Filter out system accounts
        if username.lower() not in ['public', 'default', 'all users', 'defaultuser0']:
            return username
    
    return None


def is_generic_filename(filename: str) -> bool:
    """
    Check if filename is too generic to be a useful hostname
    
    Args:
        filename: Filename to check
    
    Returns:
        True if generic, False if specific
    """
    generic_names = [
        'data', 'forensic', 'collection', 'export', 'archive', 
        'logs', 'backup', 'evidence', 'case', 'investigation',
        'artifacts', 'files', 'documents', 'output', 'results',
        'untitled', 'new', 'temp', 'test'
    ]
    
    name_lower = filename.lower()
    return any(generic in name_lower for generic in generic_names)


def validate_hostname(hostname: str) -> Tuple[bool, str]:
    """
    Validate if string looks like a valid hostname
    
    Args:
        hostname: Hostname to validate
    
    Returns:
        (is_valid, reason)
    """
    if not hostname or len(hostname) == 0:
        return False, "Empty hostname"
    
    if len(hostname) > 255:
        return False, "Hostname too long (max 255 characters)"
    
    if len(hostname) < 2:
        return False, "Hostname too short (min 2 characters)"
    
    # Check for valid characters
    if not re.match(r'^[A-Za-z0-9][A-Za-z0-9\-_.]*[A-Za-z0-9]$', hostname):
        return False, "Invalid characters in hostname"
    
    # Check if it's a generic name
    if is_generic_filename(hostname):
        return True, "Generic but acceptable"
    
    return True, "Valid"

