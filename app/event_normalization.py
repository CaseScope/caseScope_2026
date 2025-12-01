"""
Event Normalization Module
Normalize event fields during ingestion for consistent search/display
"""

from datetime import datetime
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


def normalize_event_timestamp(event: Dict[str, Any]) -> Optional[str]:
    """
    Extract and normalize timestamp from various event structures
    
    Returns ISO 8601 timestamp string or None
    """
    timestamp_value = None
    
    # Priority 1: EVTX structure - System.TimeCreated.#attributes.SystemTime or @attributes.SystemTime
    if 'System' in event:
        time_created = event.get('System', {}).get('TimeCreated', {})
        timestamp_value = time_created.get('#attributes', {}).get('SystemTime') or time_created.get('@attributes', {}).get('SystemTime')
    
    # Priority 2: EVTX->JSON import - Event.System.TimeCreated
    if not timestamp_value and 'Event' in event and isinstance(event.get('Event'), dict):
        time_created = event.get('Event', {}).get('System', {}).get('TimeCreated', {})
        timestamp_value = time_created.get('#attributes', {}).get('SystemTime') or time_created.get('@attributes', {}).get('SystemTime')
    
    # Priority 3: Common timestamp field names (including CSV)
    if not timestamp_value:
        timestamp_fields = [
            '@timestamp', 'timestamp', 'Time', 'time', 'datetime',
            'TimeCreated', 'timeCreated', 'event_time', 'eventtime',
            'created_at', 'createdAt', 'date', 'Date',
            'TIME_CREATED', 'CreatedDate', 'created'
        ]
        
        for field in timestamp_fields:
            if field in event and event[field]:
                timestamp_value = event[field]
                break
    
    # Convert to ISO format
    if timestamp_value:
        try:
            ts_str = str(timestamp_value)
            
            # Already ISO format (with T separator)
            if 'T' in ts_str:
                # Normalize timezone
                ts_str = ts_str.replace('Z', '+00:00')
                dt = datetime.fromisoformat(ts_str)
                return dt.isoformat()
            
            # Date format (YYYY-MM-DD)
            elif '-' in ts_str and len(ts_str) >= 10:
                dt = datetime.fromisoformat(ts_str)
                return dt.isoformat()
            
            # Unix timestamp (seconds)
            elif ts_str.isdigit():
                ts_int = int(ts_str)
                # Check if milliseconds
                if ts_int > 10000000000:
                    ts_int = ts_int / 1000
                dt = datetime.fromtimestamp(ts_int)
                return dt.isoformat()
            
            # CSV/Firewall formats (MM/DD/YYYY HH:MM:SS or similar)
            else:
                # Try common CSV date formats
                date_formats = [
                    '%m/%d/%Y %H:%M:%S',      # SonicWall: 10/15/2025 12:35:21
                    '%m/%d/%Y %H:%M',          # MM/DD/YYYY HH:MM
                    '%d/%m/%Y %H:%M:%S',      # DD/MM/YYYY HH:MM:SS
                    '%Y/%m/%d %H:%M:%S',      # YYYY/MM/DD HH:MM:SS
                    '%m-%d-%Y %H:%M:%S',      # MM-DD-YYYY HH:MM:SS
                    '%Y-%m-%d %H:%M:%S'       # YYYY-MM-DD HH:MM:SS
                ]
                
                for fmt in date_formats:
                    try:
                        dt = datetime.strptime(ts_str, fmt)
                        return dt.isoformat()
                    except:
                        continue
        
        except Exception as e:
            logger.debug(f"[NORMALIZE] Could not parse timestamp '{timestamp_value}': {e}")
    
    return None


def normalize_event_computer(event: Dict[str, Any]) -> Optional[str]:
    """
    Extract computer/hostname from various event structures
    
    Returns computer name string or None
    """
    computer_name = None
    
    # Priority 1: EVTX structure - System.Computer
    if 'System' in event:
        computer_name = event.get('System', {}).get('Computer')
    
    # Priority 2: EVTX->JSON import - Event.System.Computer
    if not computer_name and 'Event' in event and isinstance(event.get('Event'), dict):
        computer_name = event.get('Event', {}).get('System', {}).get('Computer')
    
    # Priority 3: Common computer field names (including CSV/Firewall)
    if not computer_name:
        computer_fields = [
            'computer_name', 'ComputerName', 'computername',
            'hostname', 'Hostname', 'host_name', 'HostName',
            'machine', 'Machine', 'device', 'Device',
            'agent', 'Agent', 'host', 'Host',
            'Dst. Name',  # SonicWall CSV
            'Source Name', 'Destination Name'
        ]
        
        for field in computer_fields:
            value = event.get(field)
            if value:
                # Handle nested dict (e.g., {"host": {"name": "server1"}})
                if isinstance(value, dict):
                    computer_name = value.get('name') or value.get('hostname')
                elif isinstance(value, str):
                    computer_name = value
                
                if computer_name:
                    break
    
    # Fallback for firewall logs: use device type
    if not computer_name and event.get('source_file_type') == 'CSV':
        # Check if this looks like a firewall log
        if any(field in event for field in ['Src. IP', 'Dst. IP', 'Firewall', 'Category', 'Group']):
            computer_name = 'Firewall'
    
    return computer_name if computer_name else None


def normalize_event_id(event: Dict[str, Any]) -> Optional[str]:
    """
    Extract event ID from various event structures
    
    Returns event ID string or None
    """
    event_id = None
    
    # Priority 1: EVTX structure - System.EventID
    if 'System' in event and 'EventID' in event.get('System', {}):
        event_id_raw = event['System']['EventID']
        if isinstance(event_id_raw, dict):
            event_id = str(event_id_raw.get('#text', event_id_raw.get('text', '')))
        else:
            event_id = str(event_id_raw)
    
    # Priority 2: EVTX->JSON import - Event.System.EventID
    if not event_id and 'Event' in event and isinstance(event.get('Event'), dict):
        if 'System' in event['Event'] and 'EventID' in event['Event']['System']:
            event_id_raw = event['Event']['System']['EventID']
            if isinstance(event_id_raw, dict):
                event_id = str(event_id_raw.get('#text', event_id_raw.get('text', '')))
            else:
                event_id = str(event_id_raw)
    
    # Priority 3: Common event ID field names (including CSV)
    if not event_id:
        event_id_fields = [
            'event_id', 'eventid', 'EventID', 'event.id',
            'Event',  # SonicWall CSV (event type like "Port Scan Possible")
            'ID',     # SonicWall CSV (numeric ID)
            'event_type', 'EventType', 'event_name', 'EventName'
        ]
        for field in event_id_fields:
            if field in event and event[field]:
                event_id = str(event[field])
                break
    
    # Fallback for CSV: use 'Event' field if it exists
    if not event_id and event.get('source_file_type') == 'CSV':
        if 'Event' in event and event['Event']:
            event_id = 'CSV'  # Generic CSV identifier
    
    return event_id if event_id else None


def create_search_blob(event: Dict[str, Any]) -> str:
    """
    Create flattened search blob from ALL event data
    
    v1.43.5: Enhanced to extract from ENTIRE event, not just EVTX fields.
    This ensures search_blob works for ALL event types (EVTX, EDR, CSV, JSON, IIS).
    
    Behavior:
    - Recursively extracts ALL text from nested structures (dicts, arrays)
    - Normalizes line breaks (\\r\\n → space)
    - Collapses multiple spaces
    - Excludes internal metadata fields (has_sigma, file_id, etc.)
    - Excludes already-flattened forensic_* fields (avoid duplication)
    
    This solves the IOC matching issue where simple_query_string phrase matching
    fails on multi-line text. The search_blob field contains normalized content
    for reliable phrase matching across ALL event types.
    
    Args:
        event: Original event dictionary
    
    Returns:
        Flattened, normalized text string for searching
    """
    # Fields to EXCLUDE from search_blob (internal/metadata/already-processed)
    EXCLUDE_FIELDS = {
        # Internal metadata
        'has_sigma', 'has_ioc', 'ioc_count', 'ioc_details', 'matched_iocs',
        'is_hidden', 'hidden_by', 'hidden_at',
        'file_id', 'source_file', 'opensearch_key', 'source_file_type',
        'row_number',  # CSV row number
        
        # Already-flattened fields (would duplicate content)
        'search_blob',  # Don't include ourselves
        'normalized_timestamp', 'normalized_computer', 'normalized_event_id',
        
        # Large/noisy fields
        '@timestamp',  # Timestamp string, not useful for text search
    }
    
    # Field prefixes to exclude (forensic_* fields are already extracted)
    EXCLUDE_PREFIXES = ('forensic_',)
    
    def extract_text(obj, key=None, depth=0):
        """Recursively extract text from nested structures"""
        if depth > 15:  # Prevent infinite recursion on deeply nested data
            return ""
        
        # Skip excluded fields
        if key:
            if key in EXCLUDE_FIELDS:
                return ""
            if any(key.startswith(prefix) for prefix in EXCLUDE_PREFIXES):
                return ""
        
        if isinstance(obj, str):
            # Normalize line breaks and extra whitespace
            text = obj.replace('\\r\\n', ' ').replace('\\n', ' ').replace('\\r', ' ')
            text = text.replace('\r\n', ' ').replace('\n', ' ').replace('\r', ' ')
            return text
        elif isinstance(obj, dict):
            # Recursively extract from all dict values
            texts = []
            for k, v in obj.items():
                text = extract_text(v, key=k, depth=depth + 1)
                if text:
                    texts.append(text)
            return ' '.join(texts)
        elif isinstance(obj, list):
            # Extract from all list items
            texts = []
            for item in obj:
                text = extract_text(item, depth=depth + 1)
                if text:
                    texts.append(text)
            return ' '.join(texts)
        elif isinstance(obj, bool):
            return ""  # Skip boolean values (not useful for text search)
        elif obj is not None:
            return str(obj)
        else:
            return ""
    
    # v1.43.5: Extract from ENTIRE event (all fields, all event types)
    search_blob = extract_text(event, depth=0)
    
    # Collapse multiple spaces to single space
    search_blob = ' '.join(search_blob.split())
    
    # Limit size to prevent huge blobs (100KB max)
    if len(search_blob) > 100000:
        search_blob = search_blob[:100000]
    
    return search_blob


def normalize_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Add normalized fields to event for consistent search/display
    
    Adds the following normalized fields:
    - normalized_timestamp: ISO 8601 timestamp
    - normalized_computer: Computer/hostname
    - normalized_event_id: Event ID
    - search_blob: Flattened searchable text (v1.16.24)
    
    Args:
        event: Original event dictionary
    
    Returns:
        Event dictionary with normalized fields added
    """
    # Add normalized timestamp
    normalized_ts = normalize_event_timestamp(event)
    if normalized_ts:
        event['normalized_timestamp'] = normalized_ts
    
    # Add normalized computer name
    normalized_computer = normalize_event_computer(event)
    if normalized_computer:
        event['normalized_computer'] = normalized_computer
    
    # Add normalized event ID
    normalized_id = normalize_event_id(event)
    if normalized_id:
        event['normalized_event_id'] = normalized_id
    
    # Add search blob for improved IOC/search matching (v1.16.24)
    # Flattens nested data and normalizes line breaks
    search_blob = create_search_blob(event)
    if search_blob:
        event['search_blob'] = search_blob
    
    return event

