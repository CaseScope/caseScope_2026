"""
EVTX Event Description Lookup Utility
Maps Windows Event Log IDs + Log Sources to human-readable descriptions
"""

import json
import os
import logging
from typing import Optional, Dict, Tuple

logger = logging.getLogger(__name__)

# Cache for the event database
_event_database = None


def load_event_database() -> Dict:
    """
    Load the EVTX event database from JSON file
    
    Returns:
        Dictionary containing event definitions
    """
    global _event_database
    
    if _event_database is not None:
        return _event_database
    
    try:
        database_path = os.path.join(os.path.dirname(__file__), 'evtx_event_database.json')
        with open(database_path, 'r', encoding='utf-8') as f:
            _event_database = json.load(f)
        logger.info(f"Loaded EVTX event database with {len(_event_database.get('events', {}))} log sources")
        return _event_database
    except Exception as e:
        logger.error(f"Failed to load EVTX event database: {e}")
        return {'events': {}}


def normalize_channel_name(channel: str) -> str:
    """
    Normalize Windows Event Log channel name for lookup
    
    Handles common variations:
    - 'Security' -> 'Security'
    - 'Microsoft-Windows-Sysmon/Operational' -> 'Microsoft-Windows-Sysmon/Operational'
    - 'Microsoft-Windows-Windows Defender/Operational' -> 'Microsoft-Windows-Windows Defender/Operational'
    
    Args:
        channel: The Windows Event Log channel name
    
    Returns:
        Normalized channel name for database lookup
    """
    if not channel:
        return ''
    
    # Remove extra whitespace
    channel = channel.strip()
    
    # Common normalizations
    # Some logs might have variations in naming
    channel_map = {
        'security': 'Security',
        'system': 'System',
        'application': 'Application',
        'windows powershell': 'Windows PowerShell',
        'microsoft-windows-powershell/operational': 'Microsoft-Windows-PowerShell/Operational',
        'microsoft-windows-sysmon/operational': 'Microsoft-Windows-Sysmon/Operational',
        'microsoft-windows-taskscheduler/operational': 'Microsoft-Windows-TaskScheduler/Operational',
        'microsoft-windows-windows defender/operational': 'Microsoft-Windows-Windows Defender/Operational',
        'microsoft-windows-windows firewall with advanced security/firewall': 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall',
        'microsoft-windows-terminalservices-localsessionmanager/operational': 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
        'microsoft-windows-terminalservices-remoteconnectionmanager/operational': 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
        'microsoft-windows-smbserver/security': 'Microsoft-Windows-SMBServer/Security',
        'microsoft-windows-ntlm/operational': 'Microsoft-Windows-NTLM/Operational',
        'microsoft-windows-aad/operational': 'Microsoft-Windows-AAD/Operational',
        'microsoft-windows-application-experience/program-compatibility-assistant': 'Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant',
        'cisco secure client': 'Cisco Secure Client'
    }
    
    # Try exact match first
    lower_channel = channel.lower()
    if lower_channel in channel_map:
        return channel_map[lower_channel]
    
    # Return as-is if no mapping found
    return channel


def get_event_description(event_id: str, channel: str, provider_name: str = None) -> Tuple[Optional[str], Optional[str]]:
    """
    Get human-readable title and description for a Windows Event
    
    Args:
        event_id: The Event ID (e.g., '4624', '1', '17')
        channel: The Windows Event Log channel (e.g., 'Security', 'System')
        provider_name: Optional provider name for additional context
    
    Returns:
        Tuple of (title, description) or (None, None) if not found
    """
    if not event_id:
        return None, None
    
    # Convert event_id to string in case it's an integer
    event_id_str = str(event_id)
    
    # Normalize the channel name
    normalized_channel = normalize_channel_name(channel) if channel else ''
    
    # Load database
    db = load_event_database()
    events = db.get('events', {})
    
    # First try: exact channel match
    if normalized_channel in events:
        channel_events = events[normalized_channel]
        if event_id_str in channel_events:
            event_data = channel_events[event_id_str]
            return event_data.get('title'), event_data.get('description')
    
    # Second try: provider_name match (for channels we might not have normalized)
    if provider_name:
        normalized_provider = normalize_channel_name(provider_name)
        if normalized_provider in events:
            provider_events = events[normalized_provider]
            if event_id_str in provider_events:
                event_data = provider_events[event_id_str]
                return event_data.get('title'), event_data.get('description')
    
    # Not found
    return None, None


def enhance_event_description(
    event_id: str,
    channel: str,
    provider_name: str = None,
    original_description: str = None
) -> str:
    """
    Enhance an event description with database information
    
    If a match is found in the database, returns the enhanced description.
    Otherwise, returns the original description.
    
    Args:
        event_id: The Event ID
        channel: The Windows Event Log channel
        provider_name: Optional provider name
        original_description: The original description to fall back to
    
    Returns:
        Enhanced description string
    """
    title, description = get_event_description(event_id, channel, provider_name)
    
    if title and description:
        # Found in database - return enhanced description
        # Format: "Title - Description"
        return f"{title} - {description}"
    
    # Not found - return original or construct basic description
    if original_description:
        return original_description
    
    # No original description either - construct basic one
    if provider_name:
        return f"{provider_name} - [{channel}]"
    elif channel:
        return f"Event {event_id} - [{channel}]"
    else:
        return f"Event {event_id}"


def get_event_title(event_id: str, channel: str, provider_name: str = None) -> Optional[str]:
    """
    Get just the title for an event (for badges/short display)
    
    Args:
        event_id: The Event ID
        channel: The Windows Event Log channel
        provider_name: Optional provider name
    
    Returns:
        Event title or None if not found
    """
    title, _ = get_event_description(event_id, channel, provider_name)
    return title


def is_event_in_database(event_id: str, channel: str, provider_name: str = None) -> bool:
    """
    Check if an event exists in the database
    
    Args:
        event_id: The Event ID
        channel: The Windows Event Log channel
        provider_name: Optional provider name
    
    Returns:
        True if event is in database, False otherwise
    """
    title, description = get_event_description(event_id, channel, provider_name)
    return title is not None and description is not None


# Preload database on module import for better performance
try:
    load_event_database()
except Exception as e:
    logger.warning(f"Could not preload EVTX event database: {e}")

