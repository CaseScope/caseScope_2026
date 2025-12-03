"""
caseScope v9.5.0 - Modular File Processing Functions

This module contains the 4 core processing functions that operate on individual files:
1. duplicate_check() - Check if file already exists (hash + filename)
2. index_file() - Convert EVTX→JSON, count events, index to OpenSearch
3. chainsaw_file() - Run SIGMA rules and flag violations
4. hunt_iocs() - Search for IOCs and flag matches

Each function is standalone and can be called individually or as part of a pipeline.

Architecture:
- Worker Stack (normal upload): duplicate_check → index_file → chainsaw_file → hunt_iocs
- Single File Reindex: Clear all → index_file → chainsaw_file → hunt_iocs
- Single File Rechainsaw: Clear SIGMA → chainsaw_file
- Single File Rehunt: Clear IOC → hunt_iocs
- Bulk Operations: Clear all (bulk) → run function on each file
"""

import os
import json
import subprocess
import tempfile
import hashlib
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


# ============================================================================
# AUTO-HIDE KNOWN GOOD EVENTS (v1.45.0: Uses events_known_good module)
# ============================================================================

def apply_auto_hide(event: dict, exclusions: dict = None) -> dict:
    """
    Check if event should be auto-hidden based on exclusion rules.
    
    Called during indexing (initial, reindex, bulk) to automatically hide
    known-good events (RMM tools, EDR health checks, etc.)
    
    v1.46.0: Sets event_status='noise' in OpenSearch if matches exclusions.
    Database EventStatus records are created after bulk indexing completes
    by querying OpenSearch for all noise events and syncing to database.
    
    Args:
        event: Event dictionary (must have search_blob already populated)
        exclusions: Pre-loaded exclusions dict (optional, will load if None)
    
    Returns:
        Event with event_status='noise' if it matches exclusions, 
        or 'new' if no status is set (default for non-noise events)
    """
    # Initialize event_status to 'new' if not already set
    # This ensures all events have an explicit status in OpenSearch
    if 'event_status' not in event:
        event['event_status'] = 'new'
    
    # Skip if no search_blob (can't check patterns)
    search_blob = event.get('search_blob', '')
    if not search_blob:
        return event
    
    # Load exclusions if not provided (cached for performance)
    if exclusions is None:
        try:
            from events_known_good import get_cached_exclusions
            exclusions = get_cached_exclusions()
        except Exception as e:
            logger.debug(f"[AUTO_HIDE] Could not load exclusions: {e}")
            return event
    
    # Skip if no exclusions configured
    if not any([
        exclusions.get('rmm_executables'),
        exclusions.get('remote_tools'),
        exclusions.get('edr_tools'),
        exclusions.get('known_good_ips')
    ]):
        return event
    
    # Check if event should be marked as known-good noise using the centralized module
    try:
        from events_known_good import is_known_good_event
        if is_known_good_event(event, search_blob, exclusions):
            # Mark in OpenSearch document for immediate filtering
            event['event_status'] = 'noise'
            event['status_reason'] = 'auto_known_good'
    except Exception as e:
        logger.debug(f"[AUTO_HIDE] Error checking event: {e}")
    
    return event


# ============================================================================
# AUTO-HIDE NOISE EVENTS (v1.46.0: Uses events_known_noise module)
# ============================================================================

def apply_auto_hide_noise(event: dict) -> dict:
    """
    Check if event should be auto-hidden as noise.
    
    Called during indexing AFTER apply_auto_hide() to automatically hide
    noise events (system processes, monitoring commands, firewall logs).
    
    v1.46.0: Uses events_known_noise module for consistent detection logic
    across indexing and the Hide Noise button. Sets event_status='noise' in
    OpenSearch, then database EventStatus records are synced after bulk 
    indexing completes.
    
    Args:
        event: Event dictionary (must have search_blob already populated)
    
    Returns:
        Event with event_status='noise' if it matches noise patterns,
        or unchanged if already has a status or doesn't match patterns
    """
    # Skip if already marked as noise (don't overwrite known-good reason)
    if event.get('event_status') == 'noise':
        return event
    
    # Check if event is noise using the centralized module
    try:
        from events_known_noise import is_noise_event, is_firewall_noise
        
        # Check for noise process/command
        if is_noise_event(event):
            event['event_status'] = 'noise'
            event['status_reason'] = 'noise_auto_index'
            return event
        
        # Check for firewall noise
        if is_firewall_noise(event):
            event['event_status'] = 'noise'
            event['status_reason'] = 'firewall_noise_auto_index'
            return event
            
    except Exception as e:
        logger.debug(f"[AUTO_HIDE_NOISE] Error checking event: {e}")
    
    return event


# ============================================================================
# IIS LOG PARSING (v1.14.0: IIS W3C Extended Log Format support)
# ============================================================================

def extract_computer_name_iis(filename: str, first_event: dict = None) -> str:
    """
    Extract computer name from IIS log filename or server IP.
    
    Priority:
    1. Filename prefix (e.g., WEB-SERVER-01_u_ex250112.log -> WEB-SERVER-01)
    2. Server IP from first event (s-ip field)
    3. Default: 'IIS-Server'
    
    Args:
        filename: Original IIS log filename
        first_event: First parsed event (for s-ip fallback)
        
    Returns:
        Computer name string (sanitized for use in document IDs)
    """
    computer_name = None
    
    # Try filename prefix
    if '_' in filename:
        prefix = filename.split('_')[0]
        # Validate it's not just "u", "ex", or IIS service name
        if prefix not in ['u', 'ex', 'ncsa', 'W3SVC1', 'W3SVC2', 'W3SVC3', 'W3SVC4', 'W3SVC5']:
            computer_name = prefix
    
    # Try server IP from first event
    if not computer_name and first_event and 's-ip' in first_event:
        computer_name = f"IIS-{first_event['s-ip']}"
    
    # Fallback
    if not computer_name:
        computer_name = 'IIS-Server'
    
    # v1.14.0 FIX: Sanitize for URL safety and document IDs
    # Remove/replace characters that break URL encoding or OpenSearch _id
    computer_name = computer_name.replace('%', '_').replace('/', '_').replace('\\', '_')
    
    return computer_name


def parse_iis_log(file_path, opensearch_key, file_id, filename):
    """
    Parse IIS W3C Extended Log Format.
    
    Example IIS log structure:
        #Software: Microsoft Internet Information Services 10.0
        #Version: 1.0
        #Date: 2025-01-12 00:00:00
        #Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken
        2025-01-12 14:23:45 192.168.1.100 GET /api/users id=123 443 - 203.0.113.45 Mozilla/5.0... https://example.com/ 200 0 0 125
    
    Args:
        file_path: Path to .log file
        opensearch_key: Unique key for this file's events
        file_id: CaseFile ID for tracking
        filename: Original filename
        
    Returns:
        List of event dictionaries ready for OpenSearch indexing
    """
    logger.info(f"[PARSE IIS] Parsing IIS log: {filename}")
    
    events = []
    field_names = []
    computer_name = None
    row_num = 0
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                
                # Skip empty lines
                if not line:
                    continue
                
                # Parse #Fields: header to get column names
                if line.startswith('#Fields:'):
                    field_names = line[8:].strip().split()
                    logger.info(f"[PARSE IIS] Found {len(field_names)} fields: {field_names}")
                    continue
                
                # Skip other comment lines
                if line.startswith('#'):
                    continue
                
                # Parse data rows
                if not field_names:
                    logger.warning(f"[PARSE IIS] No #Fields: header found, skipping line {line_num}")
                    continue
                
                # Split by whitespace, respecting that some fields might be "-" (empty)
                values = line.split()
                
                # Handle case where values don't match field count (malformed line)
                if len(values) != len(field_names):
                    logger.warning(f"[PARSE IIS] Line {line_num}: Expected {len(field_names)} fields, got {len(values)}, skipping")
                    continue
                
                row_num += 1
                
                # Build event dictionary
                event = {}
                # v1.18.0: List of numeric fields that should be converted to integers for proper range queries
                numeric_fields = {'time-taken', 'sc-status', 'sc-substatus', 'sc-win32-status', 's-port', 'cs-bytes', 'sc-bytes'}
                
                for field_name, value in zip(field_names, values):
                    # Convert "-" to empty string (IIS convention for empty fields)
                    if value == '-':
                        event[field_name] = ''
                    # Convert numeric fields to integers for proper comparison
                    elif field_name in numeric_fields:
                        try:
                            event[field_name] = int(value)
                        except (ValueError, TypeError):
                            # Keep as string if conversion fails
                            event[field_name] = value
                    else:
                        event[field_name] = value
                
                # Extract timestamp from date + time fields
                date_str = event.get('date', '')
                time_str = event.get('time', '')
                
                if date_str and time_str:
                    # Combine into ISO 8601 format: "2025-01-12T14:23:45.000Z"
                    timestamp_str = f"{date_str}T{time_str}.000Z"
                else:
                    # Fallback to current time if parsing fails
                    timestamp_str = datetime.utcnow().isoformat() + 'Z'
                    logger.warning(f"[PARSE IIS] Row {row_num}: Missing date/time, using fallback timestamp")
                
                # Extract computer name from first event
                if row_num == 1:
                    computer_name = extract_computer_name_iis(filename, event)
                    logger.info(f"[PARSE IIS] Computer name: {computer_name}")
                
                # Build OpenSearch-compatible event structure
                # CRITICAL: Add System.TimeCreated.SystemTime for date range queries
                event['System'] = {
                    'TimeCreated': {
                        'SystemTime': timestamp_str
                    },
                    'Computer': computer_name
                }
                
                # Add normalized fields for search/dedup (v1.14.0 FIX)
                event['normalized_timestamp'] = timestamp_str
                event['normalized_computer'] = computer_name
                event['normalized_event_id'] = 'IIS'  # IIS logs don't have traditional event IDs
                
                # Add metadata for filtering and tracking
                event['opensearch_key'] = opensearch_key
                event['source_file'] = filename
                event['source_file_type'] = 'IIS'
                event['file_id'] = file_id
                event['row_number'] = row_num
                
                # Initialize IOC/SIGMA flags
                event['has_ioc'] = False
                event['has_sigma'] = False
                
                events.append(event)
        
        logger.info(f"[PARSE IIS] Parsed {len(events)} events from {filename}")
        return events
        
    except Exception as e:
        logger.error(f"[PARSE IIS] Error parsing IIS log {filename}: {e}")
        return []


# ============================================================================
# EVENT NORMALIZATION (v1.13.4: Fix mapping conflicts)
# ============================================================================

def normalize_event_structure(event):
    """
    Normalize event structure to prevent OpenSearch mapping conflicts.
    
    Problem 1 (v1.13.4): EVTX files can have different representations of the same field:
    - File A: {"EventID": 4624}                       ← simple value
    - File B: {"EventID": {"#text": 4624, "#attributes": {...}}}  ← XML object
    
    Problem 2 (v1.13.5): EventData fields have inconsistent data types:
    - Event A: {"Data": 123}                          ← numeric
    - Event B: {"Data": "300 Eastern Standard Time"}  ← string
    
    Problem 3 (v1.13.8): UserData fields have same issue as EventData:
    - Event A: {"UserData": {"Parameter0": 123}}      ← numeric
    - Event B: {"UserData": {"Parameter0": "servicing"}}  ← string
    
    All cause mapping conflicts in consolidated indices (v1.13.1: 1 index per case).
    First file sets mapping, subsequent files with different types fail.
    
    Solution: 
    1. Flatten XML structures (extract #text if present)
    2. Convert ALL EventData AND UserData values to strings for consistent mapping
    3. Flatten nested objects/lists to JSON strings
    4. **v1.19.2**: Extract forensic fields BEFORE stringifying EventData/UserData
    
    Args:
        event: Event dictionary from EVTX/JSON parsing
        
    Returns:
        Normalized event dictionary with XML structures flattened and consistent types
    """
    if not isinstance(event, dict):
        return event
    
    normalized = {}
    
    # v1.19.2: Extract forensic fields BEFORE stringifying EventData/UserData
    # This allows key forensic fields to be searchable as top-level fields
    event_id = None
    event_data_raw = None
    user_data_raw = None
    
    # First pass: extract event_id and raw data for forensic extraction
    if 'Event' in event and isinstance(event['Event'], dict):
        event_obj = event['Event']
        if 'System' in event_obj and isinstance(event_obj['System'], dict):
            system_obj = event_obj['System']
            if 'EventID' in system_obj:
                event_id_val = system_obj['EventID']
                if isinstance(event_id_val, dict) and '#text' in event_id_val:
                    event_id = event_id_val['#text']
                else:
                    event_id = event_id_val
        if 'EventData' in event_obj:
            event_data_raw = event_obj['EventData']
        if 'UserData' in event_obj:
            user_data_raw = event_obj['UserData']
    
    # Extract forensic fields if we have EventData or UserData
    forensic_fields = {}
    if event_id and (event_data_raw or user_data_raw):
        forensic_fields = extract_forensic_fields(event_data_raw, user_data_raw, event_id)
    
    # Second pass: normalize structure
    for key, value in event.items():
        if isinstance(value, dict):
            # Check for XML structure: {"#text": value, "#attributes": {...}}
            if '#text' in value:
                # Extract the actual value from #text
                normalized[key] = value['#text']
            elif key in ['EventData', 'UserData']:
                # v1.13.9 FINAL FIX: Convert ENTIRE UserData/EventData to JSON string
                # OpenSearch can map UserData as TEXT or OBJECT depending on first file indexed
                # Converting to string ensures consistency and prevents mapping conflicts
                import json
                
                # Convert the entire UserData/EventData block to a JSON string
                # This prevents mapping conflicts and preserves searchability
                normalized[key] = json.dumps(value, sort_keys=True)
            else:
                # Recursively normalize nested dicts (not EventData/UserData)
                normalized[key] = normalize_event_structure(value)
        elif isinstance(value, list):
            # Recursively normalize list items
            normalized[key] = [normalize_event_structure(item) for item in value]
        else:
            # Keep simple values as-is (except in EventData/UserData, handled above)
            normalized[key] = value
    
    # v1.19.2: Add extracted forensic fields as top-level fields
    # These are searchable/filterable and can be used as IOCs
    if forensic_fields:
        normalized.update(forensic_fields)
    
    return normalized


# ============================================================================
# FORENSIC FIELD EXTRACTION (v1.19.2)
# ============================================================================

def extract_forensic_fields(event_data, user_data, event_id):
    """
    Extract ALL fields from EventData/UserData for top-level indexing.
    
    Problem: EventData is stored as JSON string to avoid mapping conflicts (v1.13.9).
    Solution: Extract ALL fields BEFORE stringification for searchability.
    
    Philosophy: Extract everything, let analysts search/filter what matters.
    - Works for ANY application (Windows, Sysmon, Tableau, custom apps)
    - Future-proof (no need to maintain field lists)
    - Still keeps JSON blob for full-text search (backward compatible)
    
    Benefits:
    - Direct search/filter by ANY field
    - Add any field as IOC easily
    - Display any field as column
    - Works with custom/unknown event types
    
    Args:
        event_data: EventData dict (before JSON stringification)
        user_data: UserData dict (before JSON stringification)
        event_id: Windows Event ID (string or int)
        
    Returns:
        dict: ALL extracted fields with 'forensic_' prefix
    """
    extracted = {}
    
    # Parse EventData if it's already a JSON string (shouldn't happen in normal flow)
    if isinstance(event_data, str):
        try:
            import json
            event_data = json.loads(event_data)
        except:
            event_data = {}
    
    # Parse UserData if it's already a JSON string
    if isinstance(user_data, str):
        try:
            import json
            user_data = json.loads(user_data)
        except:
            user_data = {}
    
    # Ensure event_data and user_data are dicts
    if not isinstance(event_data, dict):
        event_data = {}
    if not isinstance(user_data, dict):
        user_data = {}
    
    # ========================================================================
    # EXTRACT ALL EVENTDATA FIELDS (v1.19.2 - Universal Extraction)
    # ========================================================================
    
    def extract_all_fields(data_dict, prefix='forensic_'):
        """
        Recursively extract all fields from a dictionary.
        Handles nested dicts, lists, and converts all values to strings.
        """
        fields = {}
        
        for key, value in data_dict.items():
            # Skip internal XML attributes
            if key.startswith('#') or key.startswith('@'):
                continue
            
            # Create field name with prefix
            field_name = f'{prefix}{key}'
            
            # Handle different value types
            if value is None or value == '' or value == '-':
                # Skip empty/null/placeholder values
                continue
            elif isinstance(value, dict):
                # For nested dicts, check if it's an EventXML structure
                if 'EventXML' in str(key) or '#text' in value:
                    # Extract #text if present (XML structure)
                    if '#text' in value:
                        fields[field_name] = str(value['#text'])
                    # Also recurse into the dict
                    nested_fields = extract_all_fields(value, prefix=f'{prefix}{key}_')
                    fields.update(nested_fields)
                else:
                    # Regular nested dict - recurse with dot notation
                    nested_fields = extract_all_fields(value, prefix=f'{prefix}{key}_')
                    fields.update(nested_fields)
            elif isinstance(value, list):
                # For lists, extract each item with index
                for idx, item in enumerate(value):
                    if isinstance(item, dict):
                        nested_fields = extract_all_fields(item, prefix=f'{prefix}{key}_{idx}_')
                        fields.update(nested_fields)
                    elif item and item != '-':
                        fields[f'{prefix}{key}_{idx}'] = str(item)
            else:
                # Simple value (string, int, float, bool) - convert to string
                str_value = str(value)
                # Skip common placeholder values
                if str_value not in ['', '-', '0.0.0.0', '::', '0x0']:
                    fields[field_name] = str_value
        
        return fields
    
    # Extract all EventData fields
    if event_data:
        extracted.update(extract_all_fields(event_data, prefix='forensic_'))
    
    # Extract all UserData fields
    if user_data:
        extracted.update(extract_all_fields(user_data, prefix='forensic_UserData_'))
    
    return extracted


# ============================================================================
# FUNCTION 1: DUPLICATE CHECK
# ============================================================================

def duplicate_check(db, CaseFile, SkippedFile, case_id: int, filename: str, 
                   file_path: str, upload_type: str = 'http', exclude_file_id: int = None) -> dict:
    """
    Check if file already exists in case (hash + filename match).
    
    Logic:
    - If hash + filename match → Skip (duplicate)
    - If hash matches but filename different → Proceed (different source system)
    - If hash doesn't match → Proceed (new file)
    - If file has 0 events → Log and skip
    
    Args:
        db: SQLAlchemy database session
        CaseFile: CaseFile model class
        SkippedFile: SkippedFile model class
        case_id: Case ID
        filename: Original filename (e.g., "DESKTOP-123_Security.evtx")
        file_path: Full path to file on disk
        upload_type: 'http' or 'local'
    
    Returns:
        dict: {
            'status': 'skip' | 'proceed',
            'reason': str (if skip),
            'file_hash': str,
            'file_size': int
        }
    """
    logger.info("="*80)
    logger.info("[DUPLICATE CHECK] Starting duplicate check")
    logger.info(f"[DUPLICATE CHECK] Case: {case_id}, File: {filename}")
    logger.info("="*80)
    
    # Calculate file hash and size
    file_size = os.path.getsize(file_path)
    
    # Check for 0-byte files
    if file_size == 0:
        logger.warning(f"[DUPLICATE CHECK] File is 0 bytes, skipping: {filename}")
        
        # Log to skipped_file table
        skipped = SkippedFile(
            case_id=case_id,
            filename=filename,
            file_size=0,
            file_hash=None,
            skip_reason='zero_bytes',
            skip_details='File is 0 bytes (corrupt or empty)',
            upload_type=upload_type
        )
        db.session.add(skipped)
        db.session.commit()
        
        return {
            'status': 'skip',
            'reason': 'zero_bytes',
            'file_hash': None,
            'file_size': 0
        }
    
    # Calculate SHA256 hash
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256_hash.update(chunk)
    file_hash = sha256_hash.hexdigest()
    
    logger.info(f"[DUPLICATE CHECK] File hash: {file_hash[:16]}...")
    logger.info(f"[DUPLICATE CHECK] File size: {file_size:,} bytes")
    
    # Check for existing file with same hash + filename
    query = db.session.query(CaseFile).filter_by(
        case_id=case_id,
        original_filename=filename,
        file_hash=file_hash,
        is_deleted=False
    )
    
    # v9.5.4: Exclude the current file being processed (don't match against self!)
    if exclude_file_id:
        query = query.filter(CaseFile.id != exclude_file_id)
    
    existing = query.first()
    
    if existing:
        logger.warning(f"[DUPLICATE CHECK] Duplicate found: hash + filename match (file_id={existing.id})")
        
        # Log to skipped_file table
        skipped = SkippedFile(
            case_id=case_id,
            filename=filename,
            file_size=file_size,
            file_hash=file_hash,
            skip_reason='duplicate_hash',
            skip_details=f'Duplicate of file_id {existing.id}',
            upload_type=upload_type
        )
        db.session.add(skipped)
        db.session.commit()
        
        return {
            'status': 'skip',
            'reason': 'duplicate_hash',
            'file_hash': file_hash,
            'file_size': file_size
        }
    
    logger.info("[DUPLICATE CHECK] ✓ No duplicate found, proceeding")
    return {
        'status': 'proceed',
        'reason': None,
        'file_hash': file_hash,
        'file_size': file_size
    }


# ============================================================================
# FUNCTION 2: INDEX FILE
# ============================================================================

def index_file(db, opensearch_client, CaseFile, Case, case_id: int, filename: str,
              file_path: str, file_hash: str, file_size: int, uploader_id: int,
              upload_type: str = 'http', file_id: int = None, celery_task=None, 
              use_event_descriptions: bool = True, force_reindex: bool = False) -> dict:
    """
    Convert EVTX→JSON, count events, index to OpenSearch, update/create DB record.
    
    Process:
    1. Run evtx_dump to convert EVTX to JSONL (or use existing NDJSON)
    2. Count actual events from JSONL
    3. Index events to OpenSearch (bulk operation)
    4. Update existing CaseFile record OR create new one if file_id not provided
    5. Update Case aggregates (total_files, total_events)
    
    Args:
        db: SQLAlchemy database session
        opensearch_client: OpenSearch client instance
        CaseFile: CaseFile model class
        Case: Case model class
        case_id: Case ID
        filename: Original filename
        file_path: Full path to file on disk
        file_hash: SHA256 hash
        file_size: File size in bytes
        uploader_id: User ID of uploader
        upload_type: 'http' or 'local'
        celery_task: Celery task instance for progress updates (optional)
    
    Returns:
        dict: {
            'status': 'success' | 'error',
            'message': str,
            'file_id': int,
            'event_count': int,
            'index_name': str
        }
    """
    from utils import make_index_name
    from tasks import commit_with_retry
    
    # Check if event deduplication is enabled
    from event_deduplication import should_deduplicate_events, generate_event_document_id
    deduplicate_enabled = should_deduplicate_events(case_id)
    if deduplicate_enabled:
        logger.info("[INDEX FILE] Event deduplication ENABLED - using deterministic document IDs")
    else:
        logger.info("[INDEX FILE] Event deduplication DISABLED - using auto-generated document IDs")
    
    logger.info("="*80)
    logger.info("[INDEX FILE] Starting file indexing")
    logger.info(f"[INDEX FILE] File: {filename}")
    logger.info("="*80)
    
    # Determine file type
    filename_lower = filename.lower()
    is_evtx = filename_lower.endswith('.evtx')
    is_json = filename_lower.endswith(('.json', '.ndjson', '.jsonl'))
    is_csv = filename_lower.endswith('.csv')
    is_iis = False
    
    # Detect file type
    if filename_lower.endswith('.evtx'):
        file_type = 'EVTX'
    elif filename_lower.endswith('.ndjson'):
        file_type = 'NDJSON'
    elif filename_lower.endswith('.json'):
        file_type = 'JSON'
    elif filename_lower.endswith('.jsonl'):
        file_type = 'NDJSON'
    elif filename_lower.endswith('.csv'):
        file_type = 'CSV'
    elif filename_lower.endswith('.log'):
        # Peek at first 1024 bytes to detect IIS logs
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                header = f.read(1024)
            
            # Check for IIS W3C Extended Log Format signatures
            if ('Microsoft Internet Information Services' in header or 
                ('#Fields:' in header and ('cs-method' in header or 'cs-uri-stem' in header or 's-ip' in header))):
                file_type = 'IIS'
                is_iis = True
                logger.info(f"[INDEX FILE] Detected IIS W3C Extended Log Format")
            else:
                file_type = 'LOG'  # Generic log file (not supported)
        except Exception as e:
            logger.warning(f"[INDEX FILE] Could not peek at .log file: {e}")
            file_type = 'UNKNOWN'
    else:
        file_type = 'UNKNOWN'
    
    if not (is_evtx or is_json or is_csv or is_iis):
        logger.error(f"[INDEX FILE] Unsupported file type: {filename}")
        return {
            'status': 'error',
            'message': f'Unsupported file type: {filename}',
            'file_id': None,
            'event_count': 0,
            'index_name': None
        }
    
    # Calculate size in MB (rounded)
    size_mb = round(file_size / (1024 * 1024))
    
    # Generate index name and opensearch_key
    index_name = make_index_name(case_id, filename)
    # Strip all extensions for opensearch_key
    clean_name = filename.replace('.evtx', '').replace('.ndjson', '').replace('.jsonl', '').replace('.json', '').replace('.csv', '').replace('.log', '')
    opensearch_key = f"case{case_id}_{clean_name}"
    
    logger.info(f"[INDEX FILE] File type: {file_type}")
    logger.info(f"[INDEX FILE] Size: {size_mb} MB ({file_size:,} bytes)")
    logger.info(f"[INDEX FILE] Target index: {index_name}")
    logger.info(f"[INDEX FILE] OpenSearch key: {opensearch_key}")
    
    # Use existing CaseFile record or create new one
    if file_id:
        logger.info(f"[INDEX FILE] Using existing CaseFile record: file_id={file_id}")
        case_file = db.session.get(CaseFile, file_id)
        if not case_file:
            logger.error(f"[INDEX FILE] CaseFile {file_id} not found!")
            return {
                'status': 'error',
                'message': f'CaseFile {file_id} not found',
                'file_id': None,
                'event_count': 0,
                'index_name': None
            }
        
        # CRITICAL: Prevent duplicate indexing (unless force_reindex=True for intentional re-index)
        if case_file.is_indexed and not force_reindex:
            logger.info(f"[INDEX FILE] File {file_id} already indexed (is_indexed=True), skipping to prevent duplicate indexing")
            logger.info(f"[INDEX FILE] Use force_reindex=True or operation='reindex' to intentionally re-index")
            return {
                'status': 'success',
                'message': 'File already indexed (skipped to prevent duplicate)',
                'file_id': file_id,
                'event_count': case_file.event_count,
                'index_name': make_index_name(case_id, filename)
            }
        
        # Update existing record
        case_file.file_size = file_size
        case_file.size_mb = size_mb
        case_file.file_hash = file_hash
        case_file.file_type = file_type
        case_file.indexing_status = 'Indexing'
        case_file.is_indexed = False  # Will be set to True after successful indexing
        case_file.opensearch_key = opensearch_key
        if force_reindex:
            logger.info(f"[INDEX FILE] Force re-index enabled, re-indexing file {file_id}")
        logger.info(f"[INDEX FILE] Updated existing CaseFile record: file_id={file_id}")
    else:
        # Create new CaseFile record (status: Indexing)
        case_file = CaseFile(
            case_id=case_id,
            original_filename=filename,
            filename=os.path.basename(file_path),
            file_path=file_path,
            file_size=file_size,
            size_mb=size_mb,
            file_hash=file_hash,
            file_type=file_type,
            uploaded_by=uploader_id,
            indexing_status='Indexing',
            is_indexed=False,
            upload_type=upload_type,
            opensearch_key=opensearch_key
        )
        db.session.add(case_file)
        file_id = case_file.id
        logger.info(f"[INDEX FILE] Created new CaseFile record: file_id={file_id}")
    
    commit_with_retry(db.session, logger_instance=logger)
    
    try:
        # STEP 1: Convert EVTX to JSONL (if needed) or prepare CSV
        if is_evtx:
            logger.info("[INDEX FILE] Converting EVTX to JSONL...")
            json_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.jsonl')
            json_path = json_file.name
            json_file.close()
            
            # Run evtx_dump
            cmd = ['/opt/casescope/bin/evtx_dump', '-o', 'jsonl', file_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode != 0:
                error_msg = f'evtx_dump failed: {result.stderr[:100]}'
                logger.error(f"[INDEX FILE] {error_msg}")
                case_file.indexing_status = 'Failed'
                case_file.error_message = f'EVTX parsing failed. {result.stderr[:400]}'
                commit_with_retry(db.session, logger_instance=logger)
                return {
                    'status': 'error',
                    'message': error_msg,
                    'file_id': file_id,
                    'event_count': 0,
                    'index_name': index_name
                }
            
            # Write JSONL to file
            with open(json_path, 'w') as f:
                f.write(result.stdout)
            
            logger.info(f"[INDEX FILE] ✓ EVTX converted to JSONL: {json_path}")
        elif is_csv:
            # CSV files will be processed directly (no conversion needed)
            json_path = None
            logger.info(f"[INDEX FILE] CSV file detected, will process directly")
        elif is_iis:
            # IIS logs will be processed directly (no conversion needed)
            json_path = None
            logger.info(f"[INDEX FILE] IIS log detected, will process directly")
        else:
            # Use existing JSON/NDJSON/JSONL file
            json_path = file_path
            logger.info(f"[INDEX FILE] Using existing JSON file: {json_path}")
        
        # STEP 2: Count events and index to OpenSearch
        logger.info("[INDEX FILE] Indexing events to OpenSearch...")
        
        # Create index with proper settings if it doesn't exist
        try:
            if not opensearch_client.indices.exists(index=index_name):
                opensearch_client.indices.create(
                    index=index_name,
                    body={
                        "settings": {
                            "index": {
                                "max_result_window": 100000,  # Allow deep pagination
                                "mapping.total_fields.limit": 50000,  # v1.27.15: Increased from 10K to 50K for large forensic datasets
                                "mapping.nested_fields.limit": 500     # v1.27.15: Increased from 100 to 500 for complex event structures
                            }
                        },
                        "mappings": {
                            "properties": {
                                # v1.18.1 FIX: Explicit mappings for IIS numeric fields
                                # Problem: Dynamic mapping treats these as text → breaks range queries
                                # Solution: Define as long (integer) BEFORE first document indexed
                                "time-taken": {"type": "long"},       # Response time in milliseconds
                                "sc-status": {"type": "long"},        # HTTP status code (200, 404, 500)
                                "sc-substatus": {"type": "long"},     # HTTP substatus code
                                "sc-win32-status": {"type": "long"},  # Windows error code
                                "s-port": {"type": "long"},           # Server port number
                                "cs-bytes": {"type": "long"},         # Client-to-server bytes
                                "sc-bytes": {"type": "long"}          # Server-to-client bytes
                            }
                        }
                    },
                    ignore=[400]  # CRITICAL FIX (v1.13.9): Ignore "already exists" errors from race conditions
                )
                logger.info(f"[INDEX FILE] Created index {index_name} with max_result_window=100000, field_limit=10000")
            else:
                logger.debug(f"[INDEX FILE] Index {index_name} already exists")
        except Exception as e:
            error_str = str(e)
            
            # v1.13.9: Check if this is a race condition (index created by another worker)
            if 'resource_already_exists_exception' in error_str:
                logger.warning(f"[INDEX FILE] Index creation race condition - another worker created {index_name}, continuing...")
                # Don't fail - the index exists, so we can proceed to indexing
            elif 'maximum shards open' in error_str or 'max_shards_per_node' in error_str:
                # Shard limit error - fail the file
                logger.critical(f"[INDEX FILE] ⚠️  OPENSEARCH SHARD LIMIT REACHED - Cannot create more indices")
                case_file.indexing_status = 'Failed: Shard Limit'
                case_file.error_message = 'OpenSearch shard limit reached. Please consolidate indices or increase cluster.max_shards_per_node setting.'
                commit_with_retry(db.session, logger_instance=logger)
                return {
                    'status': 'error',
                    'message': f'Index creation failed: {e}',
                    'file_id': file_id,
                    'event_count': 0,
                    'index_name': None
                }
            else:
                # Generic index creation failure - fail the file
                logger.error(f"[INDEX FILE] Failed to create index {index_name}: {e}")
                case_file.indexing_status = f'Failed: {str(e)[:100]}'
                case_file.error_message = str(e)[:500] if hasattr(case_file, 'error_message') else None
                commit_with_retry(db.session, logger_instance=logger)
                return {
                    'status': 'error',
                    'message': f'Index creation failed: {e}',
                    'file_id': file_id,
                    'event_count': 0,
                    'index_name': None
                }
        
        from opensearchpy.helpers import bulk as opensearch_bulk
        
        event_count = 0  # Events parsed from file
        indexed_count = 0  # Events successfully indexed to OpenSearch
        auto_hidden_count = 0  # Events auto-hidden during indexing (v1.43.17)
        bulk_data = []
        
        # v1.45.0: Pre-load exclusions for auto-hide using events_known_good module
        try:
            from events_known_good import get_cached_exclusions, has_exclusions_configured
            auto_hide_exclusions = get_cached_exclusions() if has_exclusions_configured() else None
            if auto_hide_exclusions:
                logger.info("[INDEX FILE] Auto-hide enabled: will hide known-good events during indexing")
        except Exception as e:
            auto_hide_exclusions = None
            logger.debug(f"[INDEX FILE] Auto-hide not available: {e}")
        
        # Process CSV files
        if is_csv:
            logger.info("[INDEX FILE] Processing CSV file...")
            import csv
            
            with open(file_path, 'r', encoding='utf-8-sig') as csvfile:  # utf-8-sig handles BOM
                # Detect delimiter and read CSV
                try:
                    sample = csvfile.read(8192)
                    csvfile.seek(0)
                    sniffer = csv.Sniffer()
                    dialect = sniffer.sniff(sample)
                    reader = csv.DictReader(csvfile, dialect=dialect)
                except:
                    # Fallback to standard comma delimiter
                    csvfile.seek(0)
                    reader = csv.DictReader(csvfile)
                
                row_num = 0
                for row in reader:
                    row_num += 1
                    
                    if not row or not any(row.values()):
                        continue
                    
                    # Convert CSV row to event dictionary
                    event = dict(row)
                    
                    # CRITICAL: Rename CSV fields that conflict with EVTX object structures (v1.13.8)
                    # EVTX uses 'Event' as an object: {System: {...}, EventData: {...}}
                    # CSV files (SonicWall, firewalls, etc.) use 'Event' as a string field
                    # This causes mapping conflicts in consolidated indices (1 index per case)
                    field_renames = {
                        'Event': 'CSV_Event',  # SonicWall: "Geo IP Responder Blocked"
                        'System': 'CSV_System', # Potential conflict with EVTX System object
                        'EventData': 'CSV_EventData'  # Potential conflict with EVTX EventData object
                    }
                    
                    for old_name, new_name in field_renames.items():
                        if old_name in event:
                            event[new_name] = event.pop(old_name)
                    
                    # Add metadata
                    event['opensearch_key'] = opensearch_key
                    event['source_file_type'] = 'CSV'
                    event['row_number'] = row_num
                    
                    # CRITICAL: Normalize event structure to prevent mapping conflicts (v1.13.4)
                    event = normalize_event_structure(event)
                    
                    # CRITICAL: Add source_file and file_id for filtering (1 index per case)
                    event['source_file'] = filename
                    event['file_id'] = file_id
                    
                    # Normalize event fields for consistent search
                    from event_normalization import normalize_event
                    event = normalize_event(event)
                    
                    # v1.43.17: Auto-hide known good events during indexing
                    event = apply_auto_hide(event, auto_hide_exclusions)
                    
                    # v1.46.0: Auto-hide noise events during indexing (after known-good)
                    event = apply_auto_hide_noise(event)
                    
                    # Add deterministic document ID for deduplication if enabled
                    bulk_doc = {
                        '_index': index_name,
                        '_source': event
                    }
                    if deduplicate_enabled:
                        doc_id = generate_event_document_id(case_id, event)
                        bulk_doc['_id'] = doc_id
                    
                    bulk_data.append(bulk_doc)
                    
                    event_count += 1
                    if event.get('is_hidden'):
                        auto_hidden_count += 1
                    
                    # Bulk index every 1000 events
                    if len(bulk_data) >= 1000:
                        try:
                            success, errors = opensearch_bulk(opensearch_client, bulk_data, raise_on_error=False)
                            indexed_count += success
                            if errors:
                                logger.warning(f"[INDEX FILE] {len(errors)} events failed to index in batch")
                                # Log first error for debugging (v1.13.4)
                                if len(errors) > 0:
                                    first_error = errors[0]
                                    if isinstance(first_error, dict):
                                        error_detail = first_error.get('index', {}).get('error', {})
                                        error_type = error_detail.get('type', 'unknown')
                                        error_reason = error_detail.get('reason', 'unknown')
                                        logger.error(f"[INDEX FILE] First bulk error: {error_type} - {error_reason}")
                        except Exception as e:
                            logger.error(f"[INDEX FILE] Bulk index error: {e}")
                        bulk_data = []
                        
                        # Update progress
                        if celery_task:
                            celery_task.update_state(
                                state='PROGRESS',
                                meta={
                                    'current': event_count,
                                    'total': event_count,
                                    'status': f'Indexing {event_count:,} CSV rows'
                                }
                            )
                        
                        logger.info(f"[INDEX FILE] Progress: {event_count:,} CSV rows indexed")
            
            logger.info(f"[INDEX FILE] ✓ CSV processing complete: {event_count:,} rows ({auto_hidden_count:,} auto-hidden)")
        
        # Process IIS log files
        elif is_iis:
            logger.info("[INDEX FILE] Processing IIS log file...")
            
            # Parse IIS log into events
            parsed_events = parse_iis_log(file_path, opensearch_key, file_id, filename)
            
            if not parsed_events:
                logger.warning(f"[INDEX FILE] No events parsed from IIS log")
            
            # Bulk index IIS events
            for event in parsed_events:
                # Normalize event fields for consistent search
                from event_normalization import normalize_event
                event = normalize_event(event)
                
                # v1.43.17: Auto-hide known good events during indexing
                event = apply_auto_hide(event, auto_hide_exclusions)
                
                # v1.46.0: Auto-hide noise events during indexing (after known-good)
                event = apply_auto_hide_noise(event)
                
                # Add deterministic document ID for deduplication if enabled
                bulk_doc = {
                    '_index': index_name,
                    '_source': event
                }
                if deduplicate_enabled:
                    doc_id = generate_event_document_id(case_id, event)
                    bulk_doc['_id'] = doc_id
                
                bulk_data.append(bulk_doc)
                event_count += 1
                if event.get('is_hidden'):
                    auto_hidden_count += 1
                
                # Bulk index every 1000 events
                if len(bulk_data) >= 1000:
                    try:
                        success, errors = opensearch_bulk(opensearch_client, bulk_data, raise_on_error=False)
                        indexed_count += success
                        if errors:
                            logger.warning(f"[INDEX FILE] {len(errors)} events failed to index in batch")
                            if len(errors) > 0:
                                first_error = errors[0]
                                if isinstance(first_error, dict):
                                    error_detail = first_error.get('index', {}).get('error', {})
                                    error_type = error_detail.get('type', 'unknown')
                                    error_reason = error_detail.get('reason', 'unknown')
                                    logger.error(f"[INDEX FILE] First bulk error: {error_type} - {error_reason}")
                    except Exception as e:
                        logger.error(f"[INDEX FILE] Bulk index error: {e}")
                    bulk_data = []
                    
                    # Update progress
                    if celery_task:
                        celery_task.update_state(
                            state='PROGRESS',
                            meta={
                                'current': event_count,
                                'total': event_count,
                                'status': f'Indexing {event_count:,} IIS log entries'
                            }
                        )
                    
                    logger.info(f"[INDEX FILE] Progress: {event_count:,} IIS log entries indexed")
            
            logger.info(f"[INDEX FILE] ✓ IIS log processing complete: {event_count:,} entries ({auto_hidden_count:,} auto-hidden)")
        
        # Process JSON/NDJSON/EVTX files
        elif json_path:
            with open(json_path, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    if not line.strip():
                        continue
                    
                    try:
                        event = json.loads(line)
                        
                        # Add opensearch_key for linking DB ↔ OpenSearch
                        event['opensearch_key'] = opensearch_key
                        
                        # Add source file type for filtering
                        if is_evtx:
                            event['source_file_type'] = 'EVTX'
                        else:
                            # Detect EDR vs generic JSON
                            is_edr = (
                                ('@timestamp' in event and ('process' in event or 'host' in event or 'agent' in event)) or
                                ('event' in event and isinstance(event.get('event'), dict) and 
                                 ('kind' in event['event'] or 'category' in event['event'])) or
                                'ecs' in event
                            )
                            event['source_file_type'] = 'EDR' if is_edr else 'JSON'
                        
                        # Normalize event fields (timestamp, computer, event_id) for consistent search
                        from event_normalization import normalize_event
                        event = normalize_event(event)
                        
                        # Add event description if available (Phase 3: Integration)
                        if use_event_descriptions:
                            try:
                                event_id = None
                                event_source = 'Security'  # Default
                                
                                # Extract event ID from event structure (handle both System and Event.System)
                                system_data = None
                                if 'System' in event:
                                    system_data = event['System']
                                elif 'Event' in event and isinstance(event['Event'], dict) and 'System' in event['Event']:
                                    system_data = event['Event']['System']
                                
                                if system_data and 'EventID' in system_data:
                                    event_id_data = system_data['EventID']
                                    if isinstance(event_id_data, dict) and '#text' in event_id_data:
                                        event_id = int(event_id_data['#text'])
                                    elif isinstance(event_id_data, int):
                                        event_id = event_id_data
                                    elif isinstance(event_id_data, str):
                                        event_id = int(event_id_data)
                                
                                # Extract channel/source
                                if system_data and 'Channel' in system_data:
                                    event_source = system_data['Channel']
                                
                                # Lookup event description
                                if event_id:
                                    from models import EventDescription
                                    event_desc = db.session.query(EventDescription).filter_by(
                                        event_id=event_id,
                                        event_source=event_source
                                    ).first()
                                    
                                    if event_desc:
                                        event['event_title'] = event_desc.title
                                        event['event_description'] = event_desc.description
                                        event['event_category'] = event_desc.category
                                        logger.debug(f"[INDEX FILE] Added description for Event ID {event_id}: {event_desc.title}")
                            except Exception as e:
                                # Don't fail indexing if description lookup fails
                                logger.warning(f"[INDEX FILE] Could not add event description: {e}")
                        
                        # CRITICAL: Normalize event structure to prevent mapping conflicts (v1.13.4)
                        event = normalize_event_structure(event)
                        
                        # CRITICAL: Add source_file and file_id for filtering (1 index per case)
                        event['source_file'] = filename
                        event['file_id'] = file_id
                        
                        # v1.43.17: Auto-hide known good events during indexing
                        event = apply_auto_hide(event, auto_hide_exclusions)
                        
                        # v1.46.0: Auto-hide noise events during indexing (after known-good)
                        event = apply_auto_hide_noise(event)
                        
                        # Add deterministic document ID for deduplication if enabled
                        bulk_doc = {
                            '_index': index_name,
                            '_source': event
                        }
                        if deduplicate_enabled:
                            doc_id = generate_event_document_id(case_id, event)
                            bulk_doc['_id'] = doc_id
                        
                        bulk_data.append(bulk_doc)
                        
                        event_count += 1
                        if event.get('is_hidden'):
                            auto_hidden_count += 1
                        
                        # Bulk index every 1000 events
                        if len(bulk_data) >= 1000:
                            try:
                                success, errors = opensearch_bulk(opensearch_client, bulk_data, raise_on_error=False)
                                indexed_count += success
                                if errors:
                                    logger.warning(f"[INDEX FILE] {len(errors)} events failed to index in batch")
                                    # Log first error for debugging (v1.13.4)
                                    if len(errors) > 0:
                                        first_error = errors[0]
                                        if isinstance(first_error, dict):
                                            error_detail = first_error.get('index', {}).get('error', {})
                                            error_type = error_detail.get('type', 'unknown')
                                            error_reason = error_detail.get('reason', 'unknown')
                                            logger.error(f"[INDEX FILE] First bulk error: {error_type} - {error_reason}")
                            except Exception as e:
                                logger.error(f"[INDEX FILE] Bulk index error: {e}")
                            bulk_data = []
                            
                            # Update progress
                            if celery_task:
                                celery_task.update_state(
                                    state='PROGRESS',
                                    meta={
                                        'current': event_count,
                                        'total': event_count,  # Unknown total at this point
                                        'status': f'Indexing {event_count:,} events'
                                    }
                                )
                            
                            logger.info(f"[INDEX FILE] Progress: {event_count:,} events indexed")
                    
                    except json.JSONDecodeError as e:
                        logger.warning(f"[INDEX FILE] Skipping invalid JSON line {line_num}: {e}")
                        continue
        
        # Index remaining events
        if bulk_data:
            try:
                success, errors = opensearch_bulk(opensearch_client, bulk_data, raise_on_error=False)
                indexed_count += success
                if errors:
                    logger.warning(f"[INDEX FILE] {len(errors)} events failed to index in final batch")
                    # Log first error for debugging (v1.13.4)
                    if len(errors) > 0:
                        first_error = errors[0]
                        if isinstance(first_error, dict):
                            error_detail = first_error.get('index', {}).get('error', {})
                            error_type = error_detail.get('type', 'unknown')
                            error_reason = error_detail.get('reason', 'unknown')
                            logger.error(f"[INDEX FILE] First bulk error: {error_type} - {error_reason}")
            except Exception as e:
                logger.error(f"[INDEX FILE] Final bulk index error: {e}")
        
        logger.info(f"[INDEX FILE] ✓ Parsed {event_count:,} events, indexed {indexed_count:,} to {index_name} ({auto_hidden_count:,} auto-hidden)")
        
        # STEP 2.5: Sync event statuses to database (v1.46.0)
        # Query OpenSearch for all events marked as 'noise' and create EventStatus records
        # This ensures database counts match OpenSearch filtering
        if indexed_count > 0:
            try:
                logger.info(f"[INDEX FILE] Syncing event statuses to database...")
                noise_query = {
                    "size": 10000,  # Max batch size
                    "_source": False,  # Only need IDs
                    "query": {
                        "bool": {
                            "must": [
                                {"term": {"file_id": file_id}},
                                {"term": {"event_status": "noise"}}
                            ]
                        }
                    }
                }
                
                noise_response = opensearch_client.search(index=index_name, body=noise_query)
                noise_event_ids = [hit['_id'] for hit in noise_response['hits']['hits']]
                
                if noise_event_ids:
                    from event_status import bulk_set_status, STATUS_NOISE
                    bulk_set_status(case_id, noise_event_ids, STATUS_NOISE, user_id=None, 
                                  notes="Auto-set during indexing")
                    logger.info(f"[INDEX FILE] ✓ Synced {len(noise_event_ids):,} noise events to database")
            except Exception as e:
                logger.warning(f"[INDEX FILE] Failed to sync event statuses to database: {e}")
        
        # Verify indexing success
        if indexed_count == 0 and event_count > 0:
            error_msg = f'Parsed {event_count} events but indexed 0. This usually means OpenSearch rejected the bulk indexing request. Check OpenSearch logs for rejection reasons (field limit, mapping conflicts, etc.)'
            logger.error(f"[INDEX FILE] CRITICAL: {error_msg}")
            case_file.indexing_status = 'Failed: 0 events indexed'
            case_file.error_message = error_msg
            case_file.event_count = 0
            commit_with_retry(db.session, logger_instance=logger)
            return {
                'status': 'error',
                'message': f'Indexing failed: 0 of {event_count} events indexed',
                'file_id': file_id,
                'event_count': 0,
                'index_name': index_name
            }
        
        # Use indexed_count (actual) instead of event_count (parsed)
        event_count = indexed_count
        
        # Check for 0 events OR JSON files with 0-1 events (CyLR artifacts)
        should_hide = False
        hide_reason = None
        
        if event_count == 0:
            should_hide = True
            hide_reason = "0 events"
        elif event_count == 1 and file_type == 'JSON' and not is_evtx:
            # JSON files (not EVTX-converted) with 1 event are CyLR artifacts
            should_hide = True
            hide_reason = "CyLR artifact (1 event)"
        
        if should_hide:
            logger.warning(f"[INDEX FILE] File has {hide_reason}, marking as hidden")
            case_file.indexing_status = 'Completed'
            case_file.is_indexed = True
            case_file.event_count = event_count
            case_file.is_hidden = True  # Auto-hide non-event files
            commit_with_retry(db.session, logger_instance=logger)
            
            # Clean up temp JSONL
            if is_evtx and os.path.exists(json_path):
                os.remove(json_path)
            
            return {
                'status': 'success',
                'message': 'File indexed but has 0 events (auto-hidden)',
                'file_id': file_id,
                'event_count': 0,
                'index_name': index_name
            }
        
        # STEP 3: Update CaseFile record
        case_file.event_count = event_count
        case_file.is_indexed = True
        commit_with_retry(db.session, logger_instance=logger)
        
        # STEP 4: Update Case aggregates
        case = db.session.get(Case, case_id)
        if case:
            case.total_files = db.session.query(CaseFile).filter_by(
                case_id=case_id, is_deleted=False
            ).count()
            
            from sqlalchemy import func
            case.total_events = db.session.query(func.sum(CaseFile.event_count)).filter_by(
                case_id=case_id, is_deleted=False
            ).scalar() or 0
            
            commit_with_retry(db.session, logger_instance=logger)
            logger.info(f"[INDEX FILE] ✓ Updated case aggregates: {case.total_files} files, {case.total_events:,} events")
        
        # Clean up temp JSONL
        if is_evtx and os.path.exists(json_path):
            os.remove(json_path)
        
        logger.info("[INDEX FILE] ✓ File indexing completed successfully")
        return {
            'status': 'success',
            'message': 'File indexed successfully',
            'file_id': file_id,
            'event_count': event_count,
            'index_name': index_name
        }
    
    except Exception as e:
        error_msg = str(e)
        logger.error(f"[INDEX FILE] Error: {error_msg}")
        import traceback
        traceback_str = traceback.format_exc()
        logger.error(traceback_str)
        
        case_file.indexing_status = 'Failed'
        case_file.error_message = f'{error_msg[:200]}. Check worker logs for full stack trace.'
        commit_with_retry(db.session, logger_instance=logger)
        
        return {
            'status': 'error',
            'message': error_msg,
            'file_id': file_id,
            'event_count': 0,
            'index_name': index_name
        }


# ============================================================================
# FUNCTION 3: CHAINSAW FILE
# ============================================================================

def chainsaw_file(db, opensearch_client, CaseFile, SigmaRule, SigmaViolation,
                 file_id: int, index_name: str, celery_task=None) -> dict:
    """
    Run SIGMA rules against file events using Chainsaw and flag violations.
    
    v9.5.0: This function wraps the existing process_sigma_rules() implementation
    from tasks.py, which uses Chainsaw CLI for SIGMA processing.
    
    Process:
    1. Check if file is EVTX (skip if not)
    2. Get enabled SIGMA rules
    3. Run Chainsaw CLI against EVTX file
    4. Parse detections and create SigmaViolation records
    5. Update OpenSearch events with has_sigma_violation flag
    6. Update CaseFile.violation_count
    7. Update Case.total_events_with_SIGMA_violations
    
    Args:
        db: SQLAlchemy database session
        opensearch_client: OpenSearch client instance
        CaseFile: CaseFile model class
        SigmaRule: SigmaRule model class
        SigmaViolation: SigmaViolation model class
        file_id: CaseFile ID
        index_name: OpenSearch index name
        celery_task: Celery task instance for progress updates (optional)
    
    Returns:
        dict: {
            'status': 'success' | 'error',
            'message': str,
            'violations': int
        }
    """
    logger.info("="*80)
    logger.info("[CHAINSAW FILE] Starting SIGMA processing")
    logger.info(f"[CHAINSAW FILE] file_id={file_id}, index={index_name}")
    logger.info("="*80)
    
    # Get file record
    case_file = db.session.get(CaseFile, file_id)
    if not case_file:
        logger.error(f"[CHAINSAW FILE] File {file_id} not found")
        return {'status': 'error', 'message': 'File not found', 'violations': 0}
    
    # Only process EVTX files
    if not case_file.original_filename.lower().endswith('.evtx'):
        logger.info("[CHAINSAW FILE] Skipping SIGMA (not an EVTX file)")
        case_file.violation_count = 0
        from tasks import commit_with_retry
        commit_with_retry(db.session, logger_instance=logger)
        return {'status': 'success', 'message': 'Skipped (not EVTX)', 'violations': 0}
    
    # Update status
    case_file.indexing_status = 'SIGMA Testing'
    from tasks import commit_with_retry
    commit_with_retry(db.session, logger_instance=logger)
    
    # Setup paths
    import os
    import subprocess
    import tempfile
    import shutil
    import csv
    from pathlib import Path
    
    # Use existing sigma rules repo
    sigma_dir = Path("/opt/casescope/sigma_rules_repo")
    sigma_rules = sigma_dir / "rules" / "windows"
    
    # lolrmm rules (clone to home dir if not exists)
    home_dir = Path.home()
    lolrmm_dir = home_dir / "lolrmm"
    lolrmm_sigma = lolrmm_dir / "detections" / "sigma"
    
    # Rules cache directory
    cache_dir = Path("/opt/casescope/staging/.rules-merged")
    cache_dir.mkdir(parents=True, exist_ok=True)
    
    mapping_file = "/opt/casescope/chainsaw/mappings/sigma-event-logs-all.yml"
    chainsaw_bin = "/opt/casescope/bin/chainsaw"
    
    # Validate mapping file
    if not os.path.exists(mapping_file):
        logger.error(f"[CHAINSAW FILE] Mapping file not found: {mapping_file}")
        return {'status': 'error', 'message': 'Chainsaw mapping file not found', 'violations': 0}
    
    try:
        # Update SigmaHQ rules (already present at /opt/casescope/sigma_rules_repo)
        logger.info("[CHAINSAW FILE] Using existing SigmaHQ rules...")
        if (sigma_dir / ".git").exists():
            logger.info("[CHAINSAW FILE] Updating SigmaHQ rules...")
            subprocess.run(["/usr/bin/git", "-C", str(sigma_dir), "pull", "--quiet"], 
                         check=False, capture_output=True, timeout=60)
        
        # Clone/update lolrmm rules
        logger.info("[CHAINSAW FILE] Ensuring lolrmm rules are present...")
        if (lolrmm_dir / ".git").exists():
            logger.info("[CHAINSAW FILE] Updating lolrmm rules...")
            subprocess.run(["/usr/bin/git", "-C", str(lolrmm_dir), "pull", "--quiet"],
                         check=False, capture_output=True, timeout=60)
        elif not lolrmm_dir.exists():
            logger.info("[CHAINSAW FILE] Cloning lolrmm rules...")
            subprocess.run(["/usr/bin/git", "clone", "--quiet", "--depth", "1",
                          "https://github.com/magicsword-io/lolrmm.git", str(lolrmm_dir)],
                         check=True, capture_output=True, timeout=300)
        
        # Validate rule directories exist
        if not sigma_rules.exists():
            logger.error(f"[CHAINSAW FILE] SigmaHQ Windows rules not found at: {sigma_rules}")
            return {'status': 'error', 'message': 'SigmaHQ rules not found', 'violations': 0}
        
        # Build merged rules cache (with file-based lock for concurrent workers)
        import fcntl
        lock_file = Path("/tmp/casescope_rules_cache.lock")
        lock_fd = None
        
        try:
            # Check if cache is already ready
            sigma_cache = cache_dir / "sigma"
            cache_ready = (cache_dir.exists() and 
                          sigma_cache.exists() and 
                          any(sigma_cache.rglob('*.yml')))
            
            if not cache_ready:
                # Acquire exclusive lock to build cache
                lock_fd = open(lock_file, 'w')
                fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX)
                
                # Double-check after acquiring lock (another worker may have built it)
                cache_ready = (cache_dir.exists() and 
                              sigma_cache.exists() and 
                              any(sigma_cache.rglob('*.yml')))
                
                if not cache_ready:
                    logger.info("[CHAINSAW FILE] Building merged rules cache...")
                    shutil.rmtree(cache_dir, ignore_errors=True)
                    cache_dir.mkdir(parents=True, exist_ok=True)
                    
                    # Copy SigmaHQ Windows rules
                    shutil.copytree(sigma_rules, sigma_cache)
                    logger.info(f"[CHAINSAW FILE] Copied SigmaHQ Windows rules to cache ({sigma_cache})")
                    
                    # Copy specialized rule sets (DFIR, Emerging Threats, Threat Hunting)
                    additional_rules = [
                        (sigma_dir / "rules-dfir", cache_dir / "dfir"),
                        (sigma_dir / "rules-emerging-threats", cache_dir / "emerging-threats"),
                        (sigma_dir / "rules-threat-hunting", cache_dir / "threat-hunting"),
                    ]
                    
                    for source, dest in additional_rules:
                        if source.exists():
                            try:
                                shutil.copytree(source, dest)
                                rule_count = sum(1 for _ in dest.rglob('*.yml'))
                                logger.info(f"[CHAINSAW FILE] Copied {source.name} ({rule_count} rules) to cache")
                            except Exception as e:
                                logger.warning(f"[CHAINSAW FILE] Could not copy {source.name}: {e}")
                    
                    # Copy lolrmm rules if available
                    if lolrmm_sigma.exists():
                        lolrmm_cache = cache_dir / "lolrmm"
                        shutil.copytree(lolrmm_sigma, lolrmm_cache)
                        logger.info(f"[CHAINSAW FILE] Copied lolrmm rules to cache ({lolrmm_cache})")
                else:
                    logger.info("[CHAINSAW FILE] Rules cache already ready (built by another worker)")
            else:
                logger.info("[CHAINSAW FILE] Using existing rules cache")
        finally:
            # Release lock
            if lock_fd:
                fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)
                lock_fd.close()
        
        # Get the EVTX file path
        evtx_path = case_file.file_path
        if not os.path.exists(evtx_path):
            logger.error(f"[CHAINSAW FILE] EVTX file not found: {evtx_path}")
            return {'status': 'error', 'message': 'EVTX file not found', 'violations': 0}
        
        # Create temp output directory for chainsaw results
        with tempfile.TemporaryDirectory(prefix="chainsaw_") as tmpdir:
            logger.info(f"[CHAINSAW FILE] Running Chainsaw against {case_file.original_filename}...")
            
            # Run chainsaw
            cmd = [
                chainsaw_bin, "hunt",
                "--sigma", str(cache_dir),
                "--mapping", mapping_file,
                "--output", tmpdir,
                "--csv",
                evtx_path
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode != 0:
                logger.warning(f"[CHAINSAW FILE] Chainsaw exit code: {result.returncode}")
                logger.warning(f"[CHAINSAW FILE] stderr: {result.stderr[:500]}")
            
            # Parse CSV output and count violations
            violations_found = []
            csv_files = list(Path(tmpdir).glob("*.csv"))
            
            logger.info(f"[CHAINSAW FILE] Found {len(csv_files)} CSV output file(s)")
            
            # Get SigmaRule model
            from main import SigmaRule
            
            # Cache for rule lookups (rule_title -> rule_id)
            rule_cache = {}
            
            for csv_file in csv_files:
                try:
                    with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                        reader = csv.DictReader(f)
                        for row in reader:
                            # Extract rule name and level
                            # Chainsaw CSV uses 'detections' column for rule names
                            rule_title = (row.get('detections', '').strip() or 
                                        row.get('name', '').strip() or 
                                        row.get('rule', '').strip() or 
                                        row.get('Rule', '').strip() or 
                                        row.get('title', '').strip() or 
                                        row.get('detection', '').strip() or 
                                        row.get('rule_title', '').strip() or 'Unknown')
                            rule_level = row.get('level', row.get('Level', 'medium'))
                            
                            # Get or create SigmaRule
                            if rule_title not in rule_cache:
                                sigma_rule = db.session.query(SigmaRule).filter_by(title=rule_title).first()
                                if not sigma_rule:
                                    # Create new rule entry
                                    sigma_rule = SigmaRule(
                                        title=rule_title,
                                        description=row.get('description', row.get('Description', ''))[:500] or 'Detected by Chainsaw',
                                        rule_yaml='# Auto-generated from Chainsaw detection',
                                        level=rule_level,
                                        tags='[]',
                                        is_enabled=True
                                    )
                                    db.session.add(sigma_rule)
                                    db.session.flush()  # Get the ID
                                rule_cache[rule_title] = sigma_rule.id
                            
                            # Build event data JSON
                            event_data = {
                                'timestamp': row.get('timestamp', row.get('Timestamp', '')),
                                'computer': row.get('computer', row.get('Computer', '')),
                                'description': row.get('description', row.get('Description', ''))
                            }
                            
                            # Create violation record
                            violation_data = {
                                'case_id': case_file.case_id,
                                'file_id': file_id,
                                'rule_id': rule_cache[rule_title],
                                'rule_title': rule_title,  # Store for OpenSearch flagging
                                'event_id': row.get('Event ID', row.get('EventID', row.get('event_id', ''))),
                                'event_data': json.dumps(event_data),  # Store as proper JSON string
                                'matched_fields': '{}',  # Placeholder
                                'severity': rule_level
                            }
                            violations_found.append(violation_data)
                except Exception as e:
                    logger.warning(f"[CHAINSAW FILE] Error parsing CSV {csv_file.name}: {e}")
                    import traceback
                    logger.warning(traceback.format_exc())
            
            # Store violations in database
            violation_count = len(violations_found)
            logger.info(f"[CHAINSAW FILE] Found {violation_count} SIGMA violations")
            
            if violation_count > 0:
                # Delete existing violations for this file
                db.session.query(SigmaViolation).filter_by(file_id=file_id).delete()
                
                # Insert new violations
                for v in violations_found:
                    # Remove rule_title from dict (only for OpenSearch, not DB model)
                    db_data = {k: val for k, val in v.items() if k != 'rule_title'}
                    violation = SigmaViolation(**db_data)
                    db.session.add(violation)
                
                logger.info(f"[CHAINSAW FILE] Stored {violation_count} violations in database")
                
                # Update OpenSearch events with has_sigma flag and rule name
                # Extract unique timestamps and computers to find matching events
                logger.info("[CHAINSAW FILE] Updating OpenSearch events with has_sigma flags...")
                
                # Build map: (timestamp, computer) -> rule_title
                # If multiple rules match same event, concatenate with semicolon
                violation_map = {}
                for v in violations_found:
                    try:
                        event_data = json.loads(v['event_data'])  # Parse JSON string back to dict
                        timestamp = event_data.get('timestamp', '')
                        computer = event_data.get('computer', '')
                        if timestamp and computer:
                            key = (timestamp, computer)
                            rule_title = v.get('rule_title', 'Unknown')
                            if key in violation_map:
                                # Multiple rules for same event - append with separator
                                violation_map[key] += f"; {rule_title}"
                            else:
                                violation_map[key] = rule_title
                    except (json.JSONDecodeError, KeyError) as e:
                        logger.warning(f"[CHAINSAW FILE] Could not parse event_data for flagging: {e}")
                        continue
                
                # Search OpenSearch for these events and update them
                from opensearchpy.helpers import bulk as opensearch_bulk
                batch_size = 100
                total_updated = 0
                
                for identifier_batch in [list(violation_map.keys())[i:i+batch_size] for i in range(0, len(violation_map), batch_size)]:
                    # Build query to find events matching these identifiers
                    should_clauses = []
                    for timestamp, computer in identifier_batch:
                        should_clauses.append({
                            "bool": {
                                "must": [
                                    {"match": {"normalized_timestamp": timestamp}},
                                    {"match": {"normalized_computer": computer}}
                                ]
                            }
                        })
                    
                    search_query = {
                        "query": {
                            "bool": {
                                "should": should_clauses,
                                "minimum_should_match": 1
                            }
                        },
                        "size": 1000,
                        "_source": ["normalized_timestamp", "normalized_computer"]
                    }
                    
                    try:
                        search_results = opensearch_client.search(index=index_name, body=search_query)
                        hits = search_results['hits']['hits']
                        
                        if hits:
                            # Prepare bulk updates with has_sigma flag AND sigma_rule field
                            bulk_updates = []
                            for hit in hits:
                                # Get the rule title for this specific event
                                hit_timestamp = hit['_source'].get('normalized_timestamp', '')
                                hit_computer = hit['_source'].get('normalized_computer', '')
                                rule_title = violation_map.get((hit_timestamp, hit_computer), 'Unknown')
                                
                                bulk_updates.append({
                                    '_op_type': 'update',
                                    '_index': index_name,
                                    '_id': hit['_id'],
                                    'script': {
                                        'source': 'ctx._source.has_sigma = true; ctx._source.sigma_rule = params.rule',
                                        'lang': 'painless',
                                        'params': {
                                            'rule': rule_title
                                        }
                                    }
                                })
                            
                            if bulk_updates:
                                opensearch_bulk(opensearch_client, bulk_updates)
                                total_updated += len(bulk_updates)
                                logger.info(f"[CHAINSAW FILE] Updated {len(bulk_updates)} OpenSearch events with has_sigma flag and rule name")
                    
                    except Exception as e:
                        logger.warning(f"[CHAINSAW FILE] Error updating OpenSearch batch: {e}")
                        continue
                
                logger.info(f"[CHAINSAW FILE] ✓ Updated {total_updated} total OpenSearch events with has_sigma flag")
            
            # Update file violation count
            case_file.violation_count = violation_count
            commit_with_retry(db.session, logger_instance=logger)
            
            # Update case aggregate
            from main import Case
            case = db.session.get(Case, case_file.case_id)
            if case:
                from sqlalchemy import func
                case.total_events_with_SIGMA_violations = db.session.query(
                    func.sum(CaseFile.violation_count)
                ).filter_by(case_id=case.id, is_deleted=False).scalar() or 0
                commit_with_retry(db.session, logger_instance=logger)
            
            logger.info(f"[CHAINSAW FILE] ✓ SIGMA processing complete: {violation_count} violations")
            return {
                'status': 'success',
                'message': f'Found {violation_count} violations',
                'violations': violation_count
            }
    
    except subprocess.TimeoutExpired:
        logger.error("[CHAINSAW FILE] Chainsaw timed out")
        return {'status': 'error', 'message': 'Chainsaw timeout', 'violations': 0}
    except Exception as e:
        logger.error(f"[CHAINSAW FILE] Error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return {'status': 'error', 'message': str(e), 'violations': 0}


# ============================================================================
# FUNCTION 4: HUNT IOCS
# ============================================================================

def hunt_iocs(db, opensearch_client, CaseFile, IOC, IOCMatch, file_id: int,
             index_name: str, celery_task=None) -> dict:
    """
    Search for IOCs in file events (grep-like search) and flag matches.
    
    Process:
    1. Get active IOCs for case
    2. For each IOC, search OpenSearch (simple_query_string, case-insensitive)
    3. Create IOCMatch records
    4. Update OpenSearch events with has_ioc flag
    5. Update CaseFile.ioc_event_count
    6. Update Case.total_events_with_IOCs
    
    Args:
        db: SQLAlchemy database session
        opensearch_client: OpenSearch client instance
        CaseFile: CaseFile model class
        IOC: IOC model class
        IOCMatch: IOCMatch model class
        file_id: CaseFile ID
        index_name: OpenSearch index name (consolidated case index, e.g., "case_9" - v1.13.1)
        celery_task: Celery task instance for progress updates (optional)
    
    Returns:
        dict: {
            'status': 'success' | 'error',
            'message': str,
            'matches': int
        }
    """
    logger.info("="*80)
    logger.info("[HUNT IOCS] Starting IOC hunting (v1.13.1: consolidated indices)")
    logger.info(f"[HUNT IOCS] file_id={file_id}, index={index_name}")
    logger.info(f"[HUNT IOCS] Query filters by file_id within case index")
    logger.info("="*80)
    
    # Get file record
    case_file = db.session.get(CaseFile, file_id)
    if not case_file:
        logger.error(f"[HUNT IOCS] File {file_id} not found")
        return {'status': 'error', 'message': 'File not found', 'matches': 0}
    
    # Update status
    case_file.indexing_status = 'IOC Hunting'
    from tasks import commit_with_retry
    commit_with_retry(db.session, logger_instance=logger)
    
    # v9.5.10: Check if index exists before hunting (0-event files have no index)
    try:
        if not opensearch_client.indices.exists(index=index_name):
            logger.warning(f"[HUNT IOCS] Index {index_name} does not exist (0-event file?), skipping IOC hunt")
            case_file.ioc_event_count = 0
            case_file.indexing_status = 'Completed'
            commit_with_retry(db.session, logger_instance=logger)
            return {'status': 'success', 'message': 'Index does not exist (0-event file)', 'matches': 0}
    except Exception as e:
        logger.error(f"[HUNT IOCS] Error checking index existence: {e}")
        # Continue anyway - might be a transient error
    
    try:
        # Get active IOCs for this case
        iocs = db.session.query(IOC).filter_by(
            case_id=case_file.case_id,
            is_active=True
        ).all()
        
        if not iocs:
            logger.warning("[HUNT IOCS] No active IOCs found")
            case_file.ioc_event_count = 0
            commit_with_retry(db.session, logger_instance=logger)
            return {'status': 'success', 'message': 'No active IOCs', 'matches': 0}
        
        logger.info(f"[HUNT IOCS] Found {len(iocs)} active IOCs to hunt")
        
        total_matches = 0
        
        # =========================================================================
        # v1.43.12: IOC Hunting now uses search_blob field
        # =========================================================================
        # search_blob contains ALL event data (flattened) EXCEPT:
        # - Internal metadata (has_sigma, file_id, etc.)
        # - Static event descriptions (event_description, event_title)
        # 
        # Benefits:
        # - Much faster (1 field vs 8,759+ fields with ["*"])
        # - Excludes noise (event_description won't trigger false IOC matches)
        # - Consistent with main event search function
        # =========================================================================
        
        # Process each IOC
        for idx, ioc in enumerate(iocs, 1):
            logger.info(f"[HUNT IOCS] Processing IOC {idx}/{len(iocs)}: {ioc.ioc_type}={ioc.ioc_value}")
            
            # v1.43.12: All IOC types now search search_blob field only
            # v1.43.14: Fixed tokenization issue for COMMAND IOCs
            # =========================================================================
            # TOKENIZATION FIX (v1.43.14):
            # search_blob analyzer keeps "command.exe" as a single token.
            # Searching for "net" won't find "net.exe", but WILL find ".NET" → "net"
            # This caused 36k false positives for "net" IOC.
            # 
            # Solution: For COMMAND IOCs, search for "{command}.exe"
            # - "net" → search "net.exe" (1,826 matches vs 36k)
            # - "nltest" → search "nltest.exe" (finds actual executions)
            # =========================================================================
            
            # Determine search value based on IOC type
            search_value = ioc.ioc_value
            
            if ioc.ioc_type == 'command':
                # v1.43.14: For COMMAND IOCs, search for the .exe form
                # This prevents "net" matching ".NET" and other partial matches
                if not search_value.lower().endswith('.exe'):
                    search_value = f"{search_value}.exe"
                logger.info(f"[HUNT IOCS] COMMAND IOC: searching for '{search_value}' (added .exe)")
            
            if ioc.ioc_type == 'command_complex':
                # Complex IOC - extract distinctive terms (obfuscated PowerShell, etc.)
                # This avoids "too many nested clauses" errors (maxClauseCount limit)
                import re
                # Extract words that are 5+ characters and look distinctive (mixed case, uncommon)
                words = re.findall(r'\b\w{5,}\b', ioc.ioc_value)
                # Prioritize mixed-case words (likely obfuscated/distinctive)
                distinctive_words = [w for w in words if not w.islower() and not w.isupper()]
                if not distinctive_words:
                    distinctive_words = words[:5]  # Max 5 terms
                
                search_terms = ' AND '.join(distinctive_words[:5])
                
                query = {
                    "query": {
                        "bool": {
                            "must": [
                                {
                                    "query_string": {
                                        "query": search_terms,
                                        "fields": ["search_blob"],
                                        "default_operator": "AND",
                                        "lenient": True
                                    }
                                }
                            ],
                            "filter": [
                                {"term": {"file_id": file_id}}
                            ]
                        }
                    }
                }
                logger.info(f"[HUNT IOCS] Using distinctive terms for command_complex: {search_terms}")
            else:
                # Standard IOC - use simple_query_string on search_blob
                query = {
                    "query": {
                        "bool": {
                            "must": [
                                {
                                    "simple_query_string": {
                                        "query": f'"{search_value}"',  # Quote for phrase matching
                                        "fields": ["search_blob"],
                                        "default_operator": "and"
                                    }
                                }
                            ],
                            "filter": [
                                {"term": {"file_id": file_id}}
                            ]
                        }
                    }
                }
                logger.info(f"[HUNT IOCS] Searching search_blob for: {search_value}")
            
            try:
                # Use scroll API to get ALL results (not limited to 10,000)
                # Initial search with scroll context
                scroll_query = query.copy()
                scroll_query['size'] = 5000  # Batch size per scroll
                
                response = opensearch_client.search(
                    index=index_name, 
                    body=scroll_query,
                    scroll='5m'  # Keep scroll context alive for 5 minutes
                )
                
                scroll_id = response.get('_scroll_id')
                all_hits = response['hits']['hits']
                total_hits = response['hits']['total']['value']
                
                # Continue scrolling if there are more results
                while len(all_hits) < total_hits and scroll_id:
                    response = opensearch_client.scroll(
                        scroll_id=scroll_id,
                        scroll='5m'
                    )
                    scroll_id = response.get('_scroll_id')
                    batch_hits = response['hits']['hits']
                    if not batch_hits:
                        break
                    all_hits.extend(batch_hits)
                
                # Clear scroll context
                if scroll_id:
                    try:
                        opensearch_client.clear_scroll(scroll_id=scroll_id)
                    except:
                        pass
                
                if all_hits:
                    logger.info(f"[HUNT IOCS] Found {len(all_hits)} matches for IOC: {ioc.ioc_value} (total: {total_hits})")
                    
                    # Create IOCMatch records in batches
                    import json
                    batch_size = 1000
                    for i in range(0, len(all_hits), batch_size):
                        batch = all_hits[i:i+batch_size]
                        
                        for hit in batch:
                            event_id = hit['_id']
                            event_source = hit['_source']
                            
                            # Store full event data as JSON
                            event_data_json = json.dumps(event_source)
                            
                            ioc_match = IOCMatch(
                                ioc_id=ioc.id,
                                case_id=case_file.case_id,
                                file_id=file_id,
                                event_id=event_id,
                                index_name=index_name,
                                matched_field=f'auto_detected_{ioc.ioc_type}',
                                event_data=event_data_json
                            )
                            db.session.add(ioc_match)
                            total_matches += 1
                        
                        commit_with_retry(db.session, logger_instance=logger)
                        logger.info(f"[HUNT IOCS] Committed batch {i//batch_size + 1} ({len(batch)} matches)")
                    
                    # Update OpenSearch events with has_ioc flag, increment ioc_count, and store IOC type info
                    from opensearchpy.helpers import bulk as opensearch_bulk
                    for i in range(0, len(all_hits), batch_size):
                        batch = all_hits[i:i+batch_size]
                        bulk_updates = []
                        for hit in batch:
                            # Store IOC type and value for UI display
                            ioc_info = f"{ioc.ioc_type}:{ioc.ioc_value[:50]}"  # Type + truncated value
                            bulk_updates.append({
                                '_op_type': 'update',
                                '_index': index_name,
                                '_id': hit['_id'],
                                'script': {
                                    'source': '''
                                        ctx._source.has_ioc = true; 
                                        if (ctx._source.ioc_count == null) { 
                                            ctx._source.ioc_count = 1 
                                        } else { 
                                            ctx._source.ioc_count += 1 
                                        }
                                        if (ctx._source.ioc_details == null) {
                                            ctx._source.ioc_details = [params.ioc_type];
                                        } else if (!ctx._source.ioc_details.contains(params.ioc_type)) {
                                            ctx._source.ioc_details.add(params.ioc_type);
                                        }
                                        if (ctx._source.matched_iocs == null) {
                                            ctx._source.matched_iocs = [params.ioc_info];
                                        } else if (!ctx._source.matched_iocs.contains(params.ioc_info)) {
                                            ctx._source.matched_iocs.add(params.ioc_info);
                                        }
                                    ''',
                                    'lang': 'painless',
                                    'params': {
                                        'ioc_type': ioc.ioc_type,
                                        'ioc_info': ioc_info
                                    }
                                }
                            })

                        if bulk_updates:
                            try:
                                success_count, errors = opensearch_bulk(opensearch_client, bulk_updates, raise_on_error=False, raise_on_exception=False)
                                if errors:
                                    logger.error(f"[HUNT IOCS] Bulk update had {len(errors)} errors for IOC type: {ioc.ioc_type}")
                                    # Log first error for debugging
                                    if errors:
                                        logger.error(f"[HUNT IOCS] First error: {errors[0]}")
                                else:
                                    logger.info(f"[HUNT IOCS] ✅ Updated OpenSearch batch {i//batch_size + 1} ({success_count} events) with IOC type: {ioc.ioc_type}")
                            except Exception as bulk_err:
                                logger.error(f"[HUNT IOCS] Bulk update exception: {bulk_err}")
            
            except Exception as e:
                logger.error(f"[HUNT IOCS] Error searching for IOC {ioc.ioc_value}: {e}")
                continue
            
            # Update progress
            if celery_task:
                celery_task.update_state(
                    state='PROGRESS',
                    meta={
                        'current': idx,
                        'total': len(iocs),
                        'status': f'IOC {idx}/{len(iocs)}'
                    }
                )
        
        # Update file IOC count
        case_file.ioc_event_count = total_matches
        commit_with_retry(db.session, logger_instance=logger)
        
        # Update case aggregates
        from main import Case
        case = db.session.get(Case, case_file.case_id)
        if case:
            from sqlalchemy import func
            case.total_events_with_IOCs = db.session.query(
                func.sum(CaseFile.ioc_event_count)
            ).filter_by(case_id=case.id, is_deleted=False).scalar() or 0
            commit_with_retry(db.session, logger_instance=logger)
        
        logger.info(f"[HUNT IOCS] ✓ Found {total_matches} IOC matches")
        return {
            'status': 'success',
            'message': f'Found {total_matches} matches',
            'matches': total_matches
        }
    
    except Exception as e:
        logger.error(f"[HUNT IOCS] Error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return {'status': 'error', 'message': str(e), 'matches': 0}

