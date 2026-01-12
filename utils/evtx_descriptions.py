"""
EVTX Event Description Lookup Utility
Maps Windows Event Log IDs + Log Sources to human-readable descriptions
"""

import logging
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# Cache for database lookups
_description_cache = {}


def normalize_channel_name(channel: str) -> str:
    """
    Normalize Windows Event Log channel name for lookup
    
    Handles common variations:
    - 'Security' -> 'Security'
    - 'Microsoft-Windows-Sysmon/Operational' -> 'Microsoft-Windows-Sysmon/Operational'
    
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
    channel_map = {
        'security': 'Security',
        'system': 'System',
        'application': 'Application',
        'windows powershell': 'Windows PowerShell',
        'microsoft-windows-powershell/operational': 'Microsoft-Windows-PowerShell/Operational',
        'microsoft-windows-sysmon/operational': 'Microsoft-Windows-Sysmon/Operational',
        'microsoft-windows-taskscheduler/operational': 'Microsoft-Windows-TaskScheduler/Operational',
        'microsoft-windows-windows defender/operational': 'Microsoft-Windows-Windows Defender/Operational',
        'microsoft-windows-terminalservices-localsessionmanager/operational': 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
        'microsoft-windows-terminalservices-remoteconnectionmanager/operational': 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
        'microsoft-windows-smbserver/security': 'Microsoft-Windows-SMBServer/Security',
    }
    
    # Try exact match first
    lower_channel = channel.lower()
    if lower_channel in channel_map:
        return channel_map[lower_channel]
    
    # Return as-is if no mapping found
    return channel


def get_event_description(event_id: str, channel: str, provider_name: str = None) -> Tuple[Optional[str], Optional[str]]:
    """
    Get human-readable description for a Windows Event
    
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
    
    # Check cache first
    cache_key = (event_id_str, normalized_channel)
    if cache_key in _description_cache:
        return _description_cache[cache_key]
    
    # Query database
    try:
        from models.event_description import EventDescription
        
        # First try: exact channel match
        event = EventDescription.query.filter_by(
            event_id=event_id_str,
            log_source=normalized_channel
        ).first()
        
        if event:
            result = (event.description.split('.')[0] if '.' in event.description else event.description,
                      event.description)
            _description_cache[cache_key] = result
            return result
        
        # Second try: provider_name match
        if provider_name:
            normalized_provider = normalize_channel_name(provider_name)
            event = EventDescription.query.filter_by(
                event_id=event_id_str,
                log_source=normalized_provider
            ).first()
            
            if event:
                result = (event.description.split('.')[0] if '.' in event.description else event.description,
                          event.description)
                _description_cache[cache_key] = result
                return result
        
    except Exception as e:
        logger.debug(f"Error looking up event description: {e}")
    
    # Not found
    _description_cache[cache_key] = (None, None)
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
        return description
    
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


def clear_cache():
    """Clear the description cache (e.g., after database update)"""
    global _description_cache
    _description_cache = {}
