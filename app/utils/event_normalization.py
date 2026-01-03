"""
Event Normalization Module
Normalize event fields during ingestion for consistent search/display across all file types
Ported from old site to ensure comprehensive field extraction
"""

from datetime import datetime
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


def normalize_event_timestamp(event: Dict[str, Any]) -> Optional[str]:
    """
    Extract and normalize timestamp from various event structures
    
    Handles EVTX, NDJSON, CSV, IIS, and other formats
    
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
    
    # Priority 3: Common timestamp field names (including CSV, NDJSON)
    if not timestamp_value:
        timestamp_fields = [
            '@timestamp', 'timestamp', 'Time', 'time', 'datetime',
            'TimeCreated', 'timeCreated', 'event_time', 'eventtime',
            'created_at', 'createdAt', 'date', 'Date',
            'TIME_CREATED', 'CreatedDate', 'created', 'system_time'
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
    
    Handles EVTX, NDJSON, CSV, IIS, and other formats with comprehensive field checking
    This is the key function that fixes the "Unknown" computer name issue
    
    Returns computer name string or None
    """
    computer_name = None
    
    # Priority 1: EVTX structure - System.Computer
    if 'System' in event:
        computer_name = event.get('System', {}).get('Computer')
    
    # Priority 2: EVTX->JSON import - Event.System.Computer (CRITICAL for ZIP files!)
    if not computer_name and 'Event' in event and isinstance(event.get('Event'), dict):
        computer_name = event.get('Event', {}).get('System', {}).get('Computer')
    
    # Priority 3: Common computer field names (including CSV/Firewall/NDJSON)
    if not computer_name:
        computer_fields = [
            'computer', 'Computer',  # Direct field
            'computer_name', 'ComputerName', 'computername',
            'hostname', 'Hostname', 'host_name', 'HostName',
            'machine', 'Machine', 'device', 'Device',
            'agent', 'Agent', 'host', 'Host',
            'Dst. Name',  # SonicWall CSV - original case
            'dst_name',   # SonicWall CSV - normalized to lowercase
            'src_name',   # SonicWall CSV - normalized source name
            'Source Name', 'Destination Name',  # Firewall logs
            'source_name', 'destination_name',  # Normalized versions
            'normalized_computer'  # Already normalized
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
    
    # Priority 4: NDJSON/EDR - host.hostname or host.name
    if not computer_name and isinstance(event.get('host'), dict):
        computer_name = event.get('host', {}).get('hostname') or event.get('host', {}).get('name')
    
    # Priority 5: Fallback for firewall logs - use device type
    if not computer_name:
        file_type = event.get('file_type', '').lower()
        log_source = event.get('log_source_type', '').lower()
        # Check if this looks like a firewall log (CSV or firewall source type)
        if 'csv' in file_type or 'firewall' in log_source or 'sonicwall' in log_source:
            # Check for firewall-specific fields (normalized lowercase versions)
            if any(field in event for field in ['src_ip', 'dst_ip', 'fw_action', 'category', 'group', 'firewall']):
                computer_name = 'Firewall'
    
    # Priority 6: IIS logs - use server from metadata
    if not computer_name and event.get('file_type') == 'IIS':
        computer_name = event.get('s-ip', 'IIS-Server')
        if computer_name and computer_name != 'IIS-Server':
            computer_name = f'IIS-{computer_name}'
    
    return computer_name if computer_name else None


def normalize_event_id(event: Dict[str, Any]) -> Optional[str]:
    """
    Extract event ID from various event structures
    
    Handles EVTX, NDJSON, CSV, IIS, and other formats
    
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
    
    # Priority 2: EVTX->JSON import - Event.System.EventID (CRITICAL for ZIP files!)
    if not event_id and 'Event' in event and isinstance(event.get('Event'), dict):
        if 'System' in event['Event'] and 'EventID' in event['Event']['System']:
            event_id_raw = event['Event']['System']['EventID']
            if isinstance(event_id_raw, dict):
                event_id = str(event_id_raw.get('#text', event_id_raw.get('text', '')))
            else:
                event_id = str(event_id_raw)
    
    # Priority 3: Common event ID field names (including CSV, NDJSON)
    if not event_id:
        event_id_fields = [
            'event_id', 'eventid', 'EventID', 'event.id',
            'id',     # SonicWall CSV (numeric ID) - normalized to lowercase
            'Event',  # SonicWall CSV (event type) - original case
            'fw_event',  # SonicWall CSV (renamed from 'Event' to avoid conflicts)
            'ID',     # SonicWall CSV (numeric ID) - original case
            'event_type', 'EventType', 'event_name', 'EventName',
            'event.code',  # NDJSON/EDR
            'normalized_event_id'  # Already normalized
        ]
        for field in event_id_fields:
            value = event.get(field)
            if value:
                # Handle nested event.code
                if field == 'event' and isinstance(value, dict):
                    event_id = str(value.get('code', ''))
                else:
                    event_id = str(value)
                if event_id:
                    break
    
    # Priority 4: Fallback for CSV - use 'Event' field if it exists
    if not event_id and event.get('file_type') == 'CSV':
        if 'Event' in event and event['Event']:
            event_id = 'CSV'
    
    return event_id if event_id else None


def normalize_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Add normalized fields to event for consistent search/display
    
    This is the main function called during indexing for ALL file types.
    Ensures computer names and other fields are properly extracted regardless of source format.
    
    Adds the following normalized fields:
    - normalized_timestamp: ISO 8601 timestamp
    - normalized_computer: Computer/hostname (FIXES "Unknown" issue)
    - normalized_event_id: Event ID
    
    Args:
        event: Original event dictionary
    
    Returns:
        Event dictionary with normalized fields added (modifies in-place)
    """
    # Add normalized timestamp
    normalized_ts = normalize_event_timestamp(event)
    if normalized_ts:
        event['normalized_timestamp'] = normalized_ts
    
    # Add normalized computer name (CRITICAL FIX!)
    normalized_computer = normalize_event_computer(event)
    if normalized_computer:
        event['normalized_computer'] = normalized_computer
    else:
        # Log when we can't find a computer name to help debugging
        logger.debug(f"[NORMALIZE] No computer name found in event. Available fields: {list(event.keys())[:20]}")
    
    # Add normalized event ID
    normalized_id = normalize_event_id(event)
    if normalized_id:
        event['normalized_event_id'] = normalized_id
    
    return event

