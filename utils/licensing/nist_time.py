"""NIST Time Server Utility

Fetches accurate time from multiple NIST servers to prevent local date manipulation.
Uses multiple servers for redundancy and verification.
"""

import logging
import socket
import struct
from datetime import datetime, timezone
from typing import Optional, Tuple, List
import time

logger = logging.getLogger(__name__)

# NIST NTP servers (US-based for accuracy)
NIST_SERVERS = [
    'time.nist.gov',           # Primary NIST server
    'time-a-g.nist.gov',       # NIST Gaithersburg, MD
    'time-b-g.nist.gov',       # NIST Gaithersburg, MD
    'time-a-wwv.nist.gov',     # NIST Fort Collins, CO
    'time-b-wwv.nist.gov',     # NIST Fort Collins, CO
    'time-a-b.nist.gov',       # NIST Boulder, CO
    'time-b-b.nist.gov',       # NIST Boulder, CO
]

# Alternative NTP servers if NIST unreachable
FALLBACK_SERVERS = [
    'pool.ntp.org',
    '0.pool.ntp.org',
    '1.pool.ntp.org',
]

# NTP epoch starts at 1900-01-01, Unix at 1970-01-01
NTP_EPOCH_OFFSET = 2208988800

# Cache settings
_cached_nist_time: Optional[datetime] = None
_cached_local_offset: Optional[float] = None
_cache_timestamp: Optional[float] = None
CACHE_DURATION_SECONDS = 3600  # Cache for 1 hour

# Tolerance for server agreement (seconds)
SERVER_AGREEMENT_TOLERANCE = 5

# Connection timeout
NTP_TIMEOUT = 3


class NistTimeResult:
    """Result of NIST time query."""
    
    def __init__(self):
        self.success = False
        self.nist_time: Optional[datetime] = None
        self.local_time: Optional[datetime] = None
        self.offset_seconds: float = 0
        self.servers_queried: int = 0
        self.servers_agreed: int = 0
        self.is_local_time_trusted: bool = True
        self.error_message: Optional[str] = None
    
    def to_dict(self):
        return {
            'success': self.success,
            'nist_time': self.nist_time.isoformat() if self.nist_time else None,
            'local_time': self.local_time.isoformat() if self.local_time else None,
            'offset_seconds': self.offset_seconds,
            'servers_queried': self.servers_queried,
            'servers_agreed': self.servers_agreed,
            'is_local_time_trusted': self.is_local_time_trusted,
            'error_message': self.error_message
        }


def _query_ntp_server(server: str) -> Optional[datetime]:
    """
    Query a single NTP server and return the time.
    
    Args:
        server: NTP server hostname
        
    Returns:
        datetime: UTC time from server, or None if failed
    """
    try:
        # Create NTP request packet (mode 3 = client)
        # 48 bytes, first byte: LI=0, VN=3, Mode=3 -> 0x1B
        ntp_packet = b'\x1b' + 47 * b'\0'
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(NTP_TIMEOUT)
        
        try:
            sock.sendto(ntp_packet, (server, 123))
            response, _ = sock.recvfrom(1024)
            
            if len(response) >= 48:
                # Extract transmit timestamp (bytes 40-47)
                # Seconds since 1900-01-01
                seconds = struct.unpack('!I', response[40:44])[0]
                fraction = struct.unpack('!I', response[44:48])[0]
                
                # Convert to Unix timestamp
                unix_timestamp = seconds - NTP_EPOCH_OFFSET + (fraction / (2**32))
                
                return datetime.fromtimestamp(unix_timestamp, tz=timezone.utc)
        finally:
            sock.close()
            
    except socket.timeout:
        logger.debug(f"[NIST] Timeout querying {server}")
    except socket.gaierror:
        logger.debug(f"[NIST] DNS resolution failed for {server}")
    except Exception as e:
        logger.debug(f"[NIST] Error querying {server}: {e}")
    
    return None


def get_nist_time(use_cache: bool = True) -> NistTimeResult:
    """
    Get accurate time from NIST servers.
    
    Queries multiple servers and requires agreement for trust.
    
    Args:
        use_cache: Whether to use cached result if available
        
    Returns:
        NistTimeResult: Time query result
    """
    global _cached_nist_time, _cached_local_offset, _cache_timestamp
    
    result = NistTimeResult()
    result.local_time = datetime.now(timezone.utc)
    
    # Check cache
    if use_cache and _cache_timestamp and _cached_nist_time:
        cache_age = time.time() - _cache_timestamp
        if cache_age < CACHE_DURATION_SECONDS:
            # Adjust cached NIST time by elapsed seconds
            elapsed = cache_age
            result.nist_time = datetime.fromtimestamp(
                _cached_nist_time.timestamp() + elapsed, 
                tz=timezone.utc
            )
            result.success = True
            result.offset_seconds = _cached_local_offset
            result.is_local_time_trusted = abs(_cached_local_offset) < 300  # 5 min tolerance
            result.servers_agreed = 3  # Cached from previous query
            return result
    
    # Query multiple servers
    all_servers = NIST_SERVERS + FALLBACK_SERVERS
    server_times: List[Tuple[str, datetime]] = []
    
    for server in all_servers[:5]:  # Query up to 5 servers
        result.servers_queried += 1
        nist_dt = _query_ntp_server(server)
        
        if nist_dt:
            server_times.append((server, nist_dt))
            logger.debug(f"[NIST] Got time from {server}: {nist_dt.isoformat()}")
            
            # Stop if we have 3 responses
            if len(server_times) >= 3:
                break
    
    if not server_times:
        result.error_message = "Could not reach any NIST time servers"
        result.is_local_time_trusted = True  # Fallback to local
        logger.warning("[NIST] No time servers reachable, using local time")
        return result
    
    # Check agreement between servers
    timestamps = [dt.timestamp() for _, dt in server_times]
    avg_timestamp = sum(timestamps) / len(timestamps)
    
    agreed_count = 0
    for ts in timestamps:
        if abs(ts - avg_timestamp) <= SERVER_AGREEMENT_TOLERANCE:
            agreed_count += 1
    
    result.servers_agreed = agreed_count
    
    if agreed_count < 2:
        result.error_message = "Time servers disagree - possible network issue"
        result.is_local_time_trusted = True  # Fallback to local
        logger.warning("[NIST] Server times disagree, using local time")
        return result
    
    # Use average time from agreeing servers
    result.nist_time = datetime.fromtimestamp(avg_timestamp, tz=timezone.utc)
    result.success = True
    
    # Calculate offset from local time
    result.offset_seconds = result.nist_time.timestamp() - result.local_time.timestamp()
    
    # Local time is trusted if within 5 minutes of NIST
    result.is_local_time_trusted = abs(result.offset_seconds) < 300
    
    if not result.is_local_time_trusted:
        logger.warning(f"[NIST] Local time is off by {result.offset_seconds:.0f} seconds!")
    
    # Cache the result
    _cached_nist_time = result.nist_time
    _cached_local_offset = result.offset_seconds
    _cache_timestamp = time.time()
    
    logger.info(f"[NIST] Time verified from {agreed_count} servers, offset: {result.offset_seconds:.1f}s")
    
    return result


def get_accurate_utc_now() -> datetime:
    """
    Get accurate UTC time, preferring NIST servers.
    
    Falls back to local time if NIST unreachable.
    
    Returns:
        datetime: Accurate UTC datetime
    """
    result = get_nist_time()
    
    if result.success and result.nist_time:
        return result.nist_time
    
    return datetime.now(timezone.utc)


def is_expired(expires_at: datetime) -> Tuple[bool, Optional[int]]:
    """
    Check if a license has expired using NIST time.
    
    Args:
        expires_at: Expiration datetime (should be timezone-aware)
        
    Returns:
        Tuple[bool, int]: (is_expired, days_remaining or None)
    """
    now = get_accurate_utc_now()
    
    # Ensure expires_at is timezone-aware
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    
    delta = expires_at - now
    days_remaining = delta.days
    
    if delta.total_seconds() <= 0:
        return True, None
    
    return False, days_remaining


def is_expiring_soon(expires_at: datetime, threshold_days: int = 30) -> Tuple[bool, Optional[int]]:
    """
    Check if a license is expiring soon using NIST time.
    
    Args:
        expires_at: Expiration datetime
        threshold_days: Days threshold for "expiring soon" warning
        
    Returns:
        Tuple[bool, int]: (is_expiring_soon, days_remaining)
    """
    expired, days_remaining = is_expired(expires_at)
    
    if expired:
        return False, None  # Already expired, not "expiring soon"
    
    if days_remaining is not None and days_remaining <= threshold_days:
        return True, days_remaining
    
    return False, days_remaining


def clear_cache():
    """Clear the NIST time cache."""
    global _cached_nist_time, _cached_local_offset, _cache_timestamp
    _cached_nist_time = None
    _cached_local_offset = None
    _cache_timestamp = None
