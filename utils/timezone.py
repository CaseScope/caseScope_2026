"""Timezone utilities for CaseScope

Provides functions for:
- Converting naive datetimes to UTC based on assumed source timezone
- Converting UTC datetimes to display timezone
- DST-aware conversions using zoneinfo (Python 3.9+)
"""
from datetime import datetime, timezone as dt_timezone
from typing import Optional
import logging

logger = logging.getLogger(__name__)

# Use zoneinfo (Python 3.9+) or fall back to pytz
try:
    from zoneinfo import ZoneInfo
    ZONEINFO_AVAILABLE = True
except ImportError:
    try:
        from pytz import timezone as pytz_timezone
        ZONEINFO_AVAILABLE = False
        logger.info("Using pytz for timezone support (zoneinfo not available)")
    except ImportError:
        ZONEINFO_AVAILABLE = None
        logger.warning("Neither zoneinfo nor pytz available - timezone support limited")


def get_tz(tz_name: str):
    """Get a timezone object by IANA name
    
    Args:
        tz_name: IANA timezone identifier (e.g., 'America/New_York', 'UTC')
        
    Returns:
        Timezone object (ZoneInfo or pytz.timezone)
    """
    if ZONEINFO_AVAILABLE is True:
        return ZoneInfo(tz_name)
    elif ZONEINFO_AVAILABLE is False:
        return pytz_timezone(tz_name)
    else:
        # Fallback to UTC only
        if tz_name == 'UTC':
            return dt_timezone.utc
        raise RuntimeError("No timezone library available. Install pytz or upgrade to Python 3.9+")


def to_utc(naive_dt: datetime, source_tz: str) -> datetime:
    """Convert naive datetime (assumed to be in source_tz) to UTC
    
    This function handles DST automatically based on the date.
    
    Args:
        naive_dt: A datetime without timezone info, assumed to be in source_tz
        source_tz: IANA timezone identifier the datetime is assumed to be in
        
    Returns:
        Naive datetime converted to UTC (tzinfo stripped for ClickHouse compatibility)
    """
    if naive_dt is None:
        return None
    
    # If already has tzinfo, convert directly
    if naive_dt.tzinfo is not None:
        utc_dt = naive_dt.astimezone(get_tz('UTC'))
        return utc_dt.replace(tzinfo=None)
    
    # Handle UTC specially (no conversion needed)
    if source_tz == 'UTC':
        return naive_dt
    
    try:
        tz = get_tz(source_tz)
        
        if ZONEINFO_AVAILABLE is True:
            # zoneinfo: use replace to assign timezone, then convert
            local_dt = naive_dt.replace(tzinfo=tz)
            utc_dt = local_dt.astimezone(get_tz('UTC'))
        else:
            # pytz: must use localize() for proper DST handling
            local_dt = tz.localize(naive_dt, is_dst=None)
            utc_dt = local_dt.astimezone(get_tz('UTC'))
        
        # Return naive datetime for ClickHouse compatibility
        return utc_dt.replace(tzinfo=None)
        
    except Exception as e:
        logger.warning(f"Timezone conversion failed for {naive_dt} from {source_tz}: {e}")
        # Return original on error
        return naive_dt


def from_utc(utc_dt: datetime, display_tz: str) -> datetime:
    """Convert UTC datetime to display timezone
    
    This function handles DST automatically based on the date.
    
    Args:
        utc_dt: A datetime in UTC (naive or aware)
        display_tz: IANA timezone identifier to convert to
        
    Returns:
        Aware datetime in the display timezone
    """
    if utc_dt is None:
        return None
    
    try:
        # Make aware as UTC if naive
        if utc_dt.tzinfo is None:
            utc_dt = utc_dt.replace(tzinfo=get_tz('UTC'))
        
        # Convert to display timezone
        display_dt = utc_dt.astimezone(get_tz(display_tz))
        return display_dt
        
    except Exception as e:
        logger.warning(f"Timezone conversion failed for {utc_dt} to {display_tz}: {e}")
        return utc_dt


def format_for_display(utc_dt: datetime, display_tz: str, 
                       fmt: str = '%Y-%m-%d %H:%M:%S') -> str:
    """Format UTC datetime for display in a specific timezone
    
    Args:
        utc_dt: A datetime in UTC
        display_tz: IANA timezone identifier to display in
        fmt: strftime format string
        
    Returns:
        Formatted string in the display timezone
    """
    if utc_dt is None:
        return ''
    
    try:
        local_dt = from_utc(utc_dt, display_tz)
        return local_dt.strftime(fmt)
    except Exception as e:
        logger.warning(f"Format failed for {utc_dt} in {display_tz}: {e}")
        return str(utc_dt)


def parse_time_window(from_str: str, to_str: str, case_tz: str) -> tuple:
    """Parse user-entered time window and convert to UTC for queries
    
    Args:
        from_str: Start datetime string (ISO format or YYYY-MM-DD HH:MM:SS)
        to_str: End datetime string
        case_tz: Case timezone (user enters times in this TZ)
        
    Returns:
        Tuple of (from_utc, to_utc) as naive datetime objects
    """
    formats = [
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%dT%H:%M',
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%d %H:%M',
        '%Y-%m-%d',
    ]
    
    def parse_dt(dt_str: str) -> Optional[datetime]:
        if not dt_str:
            return None
        for fmt in formats:
            try:
                return datetime.strptime(dt_str.strip(), fmt)
            except ValueError:
                continue
        return None
    
    from_dt = parse_dt(from_str)
    to_dt = parse_dt(to_str)
    
    # Convert from case timezone to UTC
    from_utc_dt = to_utc(from_dt, case_tz) if from_dt else None
    to_utc_dt = to_utc(to_dt, case_tz) if to_dt else None
    
    return from_utc_dt, to_utc_dt


def is_valid_timezone(tz_name: str) -> bool:
    """Check if timezone name is valid
    
    Args:
        tz_name: IANA timezone identifier
        
    Returns:
        True if valid
    """
    try:
        get_tz(tz_name)
        return True
    except Exception:
        return False


# Known UTC source artifacts (timestamps are definitively UTC)
UTC_SOURCE_ARTIFACTS = {
    'evtx',           # Windows EVTX (FILETIME is UTC)
    'prefetch',       # Prefetch (FILETIME is UTC)
    'registry',       # Registry (FILETIME is UTC)
    'lnk',            # LNK shortcuts (FILETIME is UTC)
    'jumplist',       # JumpLists (FILETIME is UTC)
    'mft',            # MFT (FILETIME is UTC)
    'srum',           # SRUM (OLE dates as UTC)
    'activities_cache',  # Windows Timeline (FILETIME is UTC)
    'browser_history',   # Browser (WebKit/Mozilla timestamps are UTC)
    'browser_cookies',
    'browser_forms',
    'browser_logins',
    'browser_autofill',
    'browser_download',
    'firefox_session',
    'firefox_addon',
    'firefox_search_engine',
    'firefox_handler',
    'huntress',       # Huntress EDR (ISO8601 UTC)
    'json_log',       # Usually UTC if ISO8601
}

# Ambiguous source artifacts (may be local time, use case TZ)
AMBIGUOUS_SOURCE_ARTIFACTS = {
    'iis',            # IIS logs (usually server local time)
    'firewall',       # Firewall/syslog (varies)
    'sonicwall',      # SonicWall CSV (usually local)
    'csv_log',        # Generic CSV (unknown)
    'scheduled_task', # XML registration date (local)
    'webcache_history',
    'webcache_cache',
    'webcache_cookies',
    'webcache_downloads',
}


def get_source_tz_for_artifact(artifact_type: str, case_tz: str) -> str:
    """Determine source timezone for an artifact type
    
    Args:
        artifact_type: Parser artifact type
        case_tz: Case timezone (used for ambiguous sources)
        
    Returns:
        Timezone identifier to assume for this artifact's timestamps
    """
    if artifact_type in UTC_SOURCE_ARTIFACTS:
        return 'UTC'
    elif artifact_type in AMBIGUOUS_SOURCE_ARTIFACTS:
        return case_tz
    else:
        # Default to UTC for unknown types
        return 'UTC'
