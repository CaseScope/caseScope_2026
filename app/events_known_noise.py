"""
Known Noise Events Module
=========================

Identifies and hides events that are known system noise - routine Windows 
operations, monitoring loops, and non-security-relevant activity.

This is DIFFERENT from events_known_good.py:
- known_good: Events from TRUSTED tools (RMM, EDR) - based on System Settings
- known_noise: Events that are routine SYSTEM NOISE - based on hardcoded patterns

Usage:
    from events_known_noise import hide_noise_events
    
    # Hide noise events for a case
    result = hide_noise_events(case_id=25)
    
    # Check if a single event is noise
    from events_known_noise import is_noise_event
    if is_noise_event(event_data):
        # event is system noise

Author: CaseScope
Version: 1.0.0
"""

import logging
import re
from typing import Dict, List, Optional, Any, Set

logger = logging.getLogger(__name__)


# =============================================================================
# NOISE DEFINITIONS
# =============================================================================

# Processes that are always noise (system management, not attack-related)
NOISE_PROCESSES = [
    # Windows system management
    'auditpol.exe',      # Windows audit policy - often run by EDR/RMM
    'gpupdate.exe',      # Group policy update
    'wuauclt.exe',       # Windows Update
    'msiexec.exe',       # Installer
    'dism.exe',          # Deployment Image Service
    'sppsvc.exe',        # Software Protection Platform
    'winmgmt.exe',       # WMI service
    
    # Console/shell infrastructure (never useful alone)
    'conhost.exe',       # Console host - spawned by every cmd.exe
    'find.exe',          # Usually part of "command | find" pipes
    'findstr.exe',       # Same as find.exe
    'sort.exe',          # Pipe utility
    'more.com',          # Pipe utility
    
    # Monitoring/health check processes
    'tasklist.exe',      # Process listing (RMM monitoring loops)
    'quser.exe',         # Session queries (RMM health checks)
    'query.exe',         # Query commands
    
    # Windows runtime/background (system noise)
    'runtimebroker.exe', # Windows Runtime Broker
    'taskhostw.exe',     # Task Host Window
    'backgroundtaskhost.exe',  # Background task host
    'wmiprvse.exe',      # WMI Provider Host (when parent is system)
    
    # Update/maintenance processes
    'huntressupdater.exe',     # Huntress updates
    'microsoftedgeupdate.exe', # Edge updates
    'fulltrustnotifier.exe',   # Adobe notifications
    'filecoauth.exe',          # Office/OneDrive co-auth
    
    # Search indexing
    'searchprotocolhost.exe',  # Windows Search
    'searchfilterhost.exe',    # Windows Search
]

# Usernames that are system noise
# NOTE: Do NOT include '' - empty usernames are handled by is_noise_user() returning True for falsy values
NOISE_USERS = {
    'system', 'network service', 'local service', 'anonymous logon',
    'window manager', 'dwm-1', 'dwm-2', 'dwm-3', 'dwm-4',
    'umfd-0', 'umfd-1', 'umfd-2', 'umfd-3',
    '-', 'n/a', 'font driver host', 'defaultaccount', 
    'guest', 'wdagutilityaccount'
}

# Values that should never be IOCs (system providers, generic terms)
NOISE_IOC_VALUES = {
    # Windows Event Providers
    '.net runtime', 'microsoft-windows-security-auditing',
    'microsoft-windows-powershell', 'microsoft-windows-sysmon',
    'microsoft-windows-taskscheduler', 'microsoft-windows-dns-client',
    'microsoft-windows-kernel-general', 'microsoft-windows-kernel-power',
    'microsoft-windows-winlogon', 'microsoft-windows-user profiles service',
    'microsoft-windows-groupolicy', 'microsoft-windows-windowsupdateclient',
    'microsoft-windows-bits-client', 'microsoft-windows-eventlog',
    'microsoft-windows-wmi', 'service control manager', 'schannel',
    'application error', 'windows error reporting', 'volsnap',
    
    # Generic system terms
    'security', 'system', 'application', 'setup', 'forwarded events',
    'windows powershell', 'powershell', 'microsoft', 'windows',
    
    # Common noise strings
    'n/a', 'na', 'none', 'null', 'unknown', 'undefined', '-', '--', '---',
    'true', 'false', 'yes', 'no', '0', '1',
    
    # Local/loopback
    '127.0.0.1', '::1', 'localhost',
}

# Strings that indicate non-hostname (shouldn't be treated as hostnames)
NOT_HOSTNAMES = {
    # Common words
    'the', 'and', 'from', 'with', 'this', 'that', 'was', 'has', 'been', 'have', 'had',
    'are', 'were', 'will', 'would', 'could', 'should', 'may', 'might', 'must', 'shall',
    'can', 'for', 'but', 'not', 'you', 'all', 'can', 'her', 'his', 'its', 'our', 'out',
    'own', 'she', 'who', 'how', 'now', 'old', 'see', 'way', 'who', 'did', 'get', 'got',
    'him', 'let', 'put', 'say', 'too', 'use', 'via', 'name', 'host', 'user', 'file',
    
    # IT/Security terms that aren't hostnames
    'system', 'server', 'client', 'machine', 'computer', 'endpoint', 'device', 'network',
    'domain', 'local', 'remote', 'internal', 'external', 'unknown', 'none', 'null', 'test',
    'logging', 'security', 'event', 'events', 'alert', 'alerts', 'incident', 'malware',
    'threat', 'attack', 'attacker', 'victim', 'target', 'source', 'destination',
    'process', 'service', 'application', 'software', 'hardware', 'firewall', 'router',
    'gateway', 'proxy', 'dns', 'dhcp', 'vpn', 'rdp', 'ssh', 'http', 'https', 'ftp',
    'admin', 'administrator', 'root', 'guest', 'default', 'public', 'private',
    'enabled', 'disabled', 'active', 'inactive', 'running', 'stopped', 'failed',
    'success', 'error', 'warning', 'info', 'debug', 'critical', 'high', 'medium', 'low',
    'true', 'false', 'yes', 'no', 'on', 'off', 'new', 'old', 'first', 'last',
    'powershell', 'cmd', 'command', 'script', 'executed', 'execution', 'lateral',
    'movement', 'persistence', 'credential', 'access', 'privilege', 'escalation',
    'enumeration', 'discovery', 'exfiltration', 'reconnaissance', 'initial'
}

# Exact command patterns that are monitoring noise
# Only excluded when parent is generic (cmd.exe, svchost.exe, etc.)
NOISE_COMMAND_PATTERNS = [
    # Network monitoring commands (run thousands of times by RMM/EDR)
    'netstat -ano',
    'netstat  -ano',
    'netstat -an',
    'netstat  -an',
    'ipconfig /all',
    'ipconfig  /all',
    
    # System info gathering (monitoring, not attacks)
    'systeminfo',
    'hostname',
    
    # Session/user queries (RMM health checks)
    'quser',
    '"quser"',
    'query user',
    
    # Process listing (RMM monitoring loops)
    'tasklist',
    
    # Pipe output filters
    'find /i',
    'find "',
    'find  /i',
    'find  "',
    
    # Audit policy commands (EDR continuously sets these)
    'auditpol.exe /set',
    'auditpol /set',
    'auditpol.exe  /set',
    
    # Console host (spawned by every cmd.exe)
    'conhost.exe 0xffffffff',
    'conhost.exe  0xffffffff',
    
    # PowerShell monitoring - Defender checks
    'get-mppreference',
    'get-mpthreat',
    'get-mpcomputerstatus',
]

# Generic parents - when command is noise AND parent is generic, it's safe to hide
GENERIC_PARENTS = {
    'cmd.exe', 'svchost.exe', 'services.exe', 'wmiprvse.exe',
    'wmi provider host', 'powershell.exe', 'pwsh.exe'
}

# Firewall/network noise keywords (for filtering discovered IPs)
FIREWALL_NOISE_KEYWORDS = [
    'firewall', 'fw_', 'fw-', 'deny', 'drop', 'block', 'reject',
    'netflow', 'traffic', 'conn_state', 'action:deny', 'action:drop',
]


# =============================================================================
# DETECTION FUNCTIONS
# =============================================================================

def is_noise_process(process_name: str) -> bool:
    """Check if process name is a known noise process."""
    if not process_name:
        return False
    name_lower = process_name.lower().replace('.exe', '')
    return name_lower in [p.lower().replace('.exe', '') for p in NOISE_PROCESSES]


def is_noise_user(username: str) -> bool:
    """Check if username is a known system/noise account."""
    if not username:
        return True  # Empty username = noise
    name_lower = username.lower()
    
    # Direct match
    if name_lower in NOISE_USERS:
        return True
    
    # Machine accounts (end with $)
    if username.endswith('$'):
        return True
    
    # DWM-N, UMFD-N patterns
    if name_lower.startswith('dwm-') or name_lower.startswith('umfd-'):
        return True
    
    return False


def is_noise_hostname(hostname: str) -> bool:
    """Check if hostname is a known noise/invalid hostname."""
    if not hostname:
        return True
    
    hostname_lower = hostname.lower()
    
    # Check blocklist
    if hostname_lower in NOT_HOSTNAMES:
        return True
    
    # Too short
    if len(hostname) < 3:
        return True
    
    return False


def is_noise_ioc_value(value: str) -> bool:
    """Check if IOC value is noise (system providers, generic terms, etc.)."""
    if not value:
        return True
    
    val_lower = value.lower().strip()
    
    # Direct match
    if val_lower in NOISE_IOC_VALUES:
        return True
    
    # Too short (less than 3 chars)
    if len(val_lower) < 3:
        return True
    
    # Starts with microsoft-windows- (provider names)
    if val_lower.startswith('microsoft-windows-'):
        return True
    
    return False


def is_noise_command(command_line: str, parent_name: str = None) -> bool:
    """
    Check if command line is noise.
    
    A command is considered noise if:
    1. It matches a NOISE_COMMAND_PATTERN exactly, AND
    2. The parent process is generic (cmd.exe, svchost.exe, etc.)
    
    If parent is suspicious (e.g., powershell spawning netstat), we KEEP it.
    """
    if not command_line:
        return False
    
    cmd_lower = command_line.lower().strip()
    
    # Check if command matches any noise pattern
    is_noise_pattern = any(pattern in cmd_lower for pattern in NOISE_COMMAND_PATTERNS)
    
    if not is_noise_pattern:
        return False
    
    # If parent is suspicious, keep the command
    if parent_name:
        parent_lower = parent_name.lower()
        # Only hide if parent is generic
        if parent_lower not in GENERIC_PARENTS:
            return False  # Suspicious parent → keep this command
    
    return True


def is_noise_event(event_data: Dict) -> bool:
    """
    Check if an event is known system noise.
    
    Args:
        event_data: The event document (OpenSearch _source or raw dict)
    
    Returns:
        True if event is noise and should be hidden, False otherwise
    
    Detection Logic:
        1. Process name is in NOISE_PROCESSES
        2. Command line matches NOISE_COMMAND_PATTERNS (with generic parent)
        3. Event is only from noise user with no meaningful activity
    """
    proc = event_data.get('process', {})
    
    # Get process details
    proc_name = (proc.get('name') or proc.get('executable') or '').lower()
    if '\\' in proc_name:
        proc_name = proc_name.split('\\')[-1]
    
    command_line = proc.get('command_line', '')
    
    # Get parent info
    parent = proc.get('parent') or {}  # Handle None parent
    parent_name = (parent.get('name') or parent.get('executable') or '').lower()
    if '\\' in parent_name:
        parent_name = parent_name.split('\\')[-1]
    
    # CHECK 1: Noise process
    if proc_name and is_noise_process(proc_name):
        logger.debug(f"[NOISE] Process is noise: {proc_name}")
        return True
    
    # CHECK 2: Noise command pattern with generic parent
    if command_line and is_noise_command(command_line, parent_name):
        logger.debug(f"[NOISE] Command is noise: {command_line[:50]}...")
        return True
    
    return False


def is_firewall_noise(event_data: Dict) -> bool:
    """Check if event is firewall/network noise (DENY/DROP/BLOCK logs)."""
    search_blob = (event_data.get('search_blob') or '').lower()
    
    if any(kw in search_blob for kw in FIREWALL_NOISE_KEYWORDS):
        return True
    
    return False


# =============================================================================
# SLICED PROCESSING (for parallel workers)
# =============================================================================

def process_slice(
    case_id: int,
    slice_id: int,
    max_slices: int,
    opensearch_client
) -> Dict[str, Any]:
    """
    Process a single slice of events for parallel noise hide operation.
    
    Uses OpenSearch's sliced scroll to divide work among multiple workers.
    Each worker processes 1/max_slices of the total events.
    
    Args:
        case_id: The case ID to process
        slice_id: This worker's slice ID (0 to max_slices-1)
        max_slices: Total number of slices (usually 8 for 8 workers)
        opensearch_client: OpenSearch client instance
    
    Returns:
        Dict with scanned, events_to_hide list, and by_category counts
    """
    index_name = f"case_{case_id}"
    events_to_hide = []
    scanned_count = 0
    by_category = {
        'noise_process': 0,
        'noise_command': 0,
        'firewall_noise': 0
    }
    
    scroll_time = '5m'
    batch_size = 1000
    
    # Sliced scroll query - each slice gets 1/N of events
    query = {
        "size": batch_size,
        "slice": {
            "id": slice_id,
            "max": max_slices
        },
        "_source": ["process", "search_blob"],
        "query": {
            "bool": {
                "must_not": [
                    {"term": {"is_hidden": True}}
                ]
            }
        }
    }
    
    try:
        response = opensearch_client.search(
            index=index_name,
            body=query,
            scroll=scroll_time
        )
    except Exception as e:
        logger.error(f"[NOISE] Slice {slice_id}: Search failed - {e}")
        return {'scanned': 0, 'events_to_hide': [], 'by_category': by_category}
    
    scroll_id = response.get('_scroll_id')
    hits = response['hits']['hits']
    
    logger.info(f"[NOISE] Slice {slice_id}/{max_slices}: Starting scan")
    
    # Process all events in this slice
    while hits:
        for hit in hits:
            src = hit.get('_source', {})
            scanned_count += 1
            
            category = None
            
            # Check noise process
            proc = src.get('process', {})
            proc_name = (proc.get('name') or proc.get('executable') or '')
            if proc_name:
                if '\\' in proc_name:
                    proc_name = proc_name.split('\\')[-1]
                if is_noise_process(proc_name):
                    category = 'noise_process'
            
            # Check noise command
            if not category:
                command_line = proc.get('command_line', '')
                parent = proc.get('parent') or {}  # Handle None parent
                parent_name = parent.get('name') or parent.get('executable') or ''
                if parent_name and '\\' in parent_name:
                    parent_name = parent_name.split('\\')[-1]
                
                if command_line and is_noise_command(command_line, parent_name):
                    category = 'noise_command'
            
            # Check firewall noise
            if not category:
                if is_firewall_noise(src):
                    category = 'firewall_noise'
            
            if category:
                events_to_hide.append({
                    '_id': hit['_id'],
                    '_index': hit['_index'],
                    'category': category
                })
                by_category[category] += 1
        
        # Get next batch
        try:
            response = opensearch_client.scroll(scroll_id=scroll_id, scroll=scroll_time)
            scroll_id = response.get('_scroll_id')
            hits = response['hits']['hits']
        except Exception as e:
            logger.error(f"[NOISE] Slice {slice_id}: Scroll failed - {e}")
            break
    
    # Clear scroll
    try:
        if scroll_id:
            opensearch_client.clear_scroll(scroll_id=scroll_id)
    except:
        pass
    
    logger.info(f"[NOISE] Slice {slice_id}/{max_slices}: Scanned {scanned_count:,}, found {len(events_to_hide):,} to hide")
    
    return {
        'scanned': scanned_count,
        'events_to_hide': events_to_hide,
        'by_category': by_category
    }


def bulk_hide_events(
    events_to_hide: List[Dict],
    opensearch_client,
    index_name: str
) -> int:
    """
    Bulk update events to set is_hidden=True.
    
    Args:
        events_to_hide: List of dicts with {_id, _index, category}
        opensearch_client: OpenSearch client instance
        index_name: Index name for refresh
    
    Returns:
        Number of events successfully hidden
    """
    if not events_to_hide:
        return 0
    
    hidden_count = 0
    bulk_batch_size = 500
    
    for i in range(0, len(events_to_hide), bulk_batch_size):
        batch = events_to_hide[i:i + bulk_batch_size]
        
        bulk_body = []
        for evt in batch:
            bulk_body.append({"update": {"_id": evt['_id'], "_index": evt['_index']}})
            bulk_body.append({"doc": {"is_hidden": True, "hidden_reason": f"noise_{evt.get('category', 'general')}"}})
        
        try:
            bulk_result = opensearch_client.bulk(body=bulk_body, refresh=False)
            if not bulk_result.get('errors'):
                hidden_count += len(batch)
            else:
                # Count successful updates
                for item in bulk_result.get('items', []):
                    if item.get('update', {}).get('status') in [200, 201]:
                        hidden_count += 1
        except Exception as e:
            logger.error(f"[NOISE] Bulk hide failed: {e}")
    
    return hidden_count


# =============================================================================
# BULK HIDE OPERATION (legacy single-threaded)
# =============================================================================

def hide_noise_events(
    case_id: int,
    progress_callback: Optional[callable] = None
) -> Dict[str, Any]:
    """
    Find and hide all noise events in a case.
    
    Args:
        case_id: The case ID to process
        progress_callback: Optional callback function(status, processed, total, found)
    
    Returns:
        Dict with:
            - success: bool
            - total_scanned: int
            - total_hidden: int
            - by_category: Dict with counts per noise category
            - errors: list
    """
    from file_processing import get_opensearch_client
    
    result = {
        'success': False,
        'total_scanned': 0,
        'total_hidden': 0,
        'by_category': {
            'noise_process': 0,
            'noise_command': 0,
            'firewall_noise': 0
        },
        'errors': []
    }
    
    logger.info(f"[NOISE] Starting hide operation for case {case_id}")
    
    # Get OpenSearch client
    opensearch_client = get_opensearch_client()
    if not opensearch_client:
        result['errors'].append("OpenSearch not available")
        return result
    
    index_name = f"case_{case_id}"
    
    # Check index exists
    if not opensearch_client.indices.exists(index=index_name):
        result['errors'].append(f"Index {index_name} does not exist")
        return result
    
    # Scroll through all non-hidden events
    scroll_time = '5m'
    batch_size = 1000
    events_to_hide = []
    
    query = {
        "size": batch_size,
        "_source": ["process", "search_blob", "is_hidden"],
        "query": {
            "bool": {
                "must_not": [
                    {"term": {"is_hidden": True}}
                ]
            }
        }
    }
    
    try:
        response = opensearch_client.search(
            index=index_name,
            body=query,
            scroll=scroll_time
        )
    except Exception as e:
        result['errors'].append(f"Search failed: {e}")
        return result
    
    scroll_id = response.get('_scroll_id')
    hits = response['hits']['hits']
    total_to_scan = response['hits']['total']['value']
    processed_count = 0
    
    logger.info(f"[NOISE] Scanning {total_to_scan:,} events in case {case_id}")
    
    # Scan all events
    while hits:
        for hit in hits:
            src = hit.get('_source', {})
            processed_count += 1
            
            category = None
            
            # Check noise process
            proc = src.get('process', {})
            proc_name = (proc.get('name') or proc.get('executable') or '')
            if proc_name:
                if '\\' in proc_name:
                    proc_name = proc_name.split('\\')[-1]
                if is_noise_process(proc_name):
                    category = 'noise_process'
            
            # Check noise command
            if not category:
                command_line = proc.get('command_line', '')
                parent = proc.get('parent') or {}  # Handle None parent
                parent_name = parent.get('name') or parent.get('executable') or ''
                if parent_name and '\\' in parent_name:
                    parent_name = parent_name.split('\\')[-1]
                
                if command_line and is_noise_command(command_line, parent_name):
                    category = 'noise_command'
            
            # Check firewall noise
            if not category:
                if is_firewall_noise(src):
                    category = 'firewall_noise'
            
            if category:
                events_to_hide.append({
                    '_id': hit['_id'],
                    '_index': hit['_index'],
                    'category': category
                })
                result['by_category'][category] += 1
        
        # Progress callback
        if progress_callback:
            progress_callback('scanning', processed_count, total_to_scan, len(events_to_hide))
        
        # Get next batch
        try:
            response = opensearch_client.scroll(scroll_id=scroll_id, scroll=scroll_time)
            scroll_id = response.get('_scroll_id')
            hits = response['hits']['hits']
        except Exception as e:
            result['errors'].append(f"Scroll failed: {e}")
            break
    
    # Clear scroll
    try:
        opensearch_client.clear_scroll(scroll_id=scroll_id)
    except:
        pass
    
    result['total_scanned'] = processed_count
    
    # Bulk update to hide events
    if events_to_hide:
        total_to_hide = len(events_to_hide)
        hidden_count = 0
        bulk_batch_size = 500
        
        logger.info(f"[NOISE] Hiding {total_to_hide:,} noise events")
        
        for i in range(0, total_to_hide, bulk_batch_size):
            batch = events_to_hide[i:i + bulk_batch_size]
            
            if progress_callback:
                progress_callback('hiding', hidden_count, total_to_hide, total_to_hide)
            
            bulk_body = []
            for evt in batch:
                bulk_body.append({"update": {"_id": evt['_id'], "_index": evt['_index']}})
                bulk_body.append({"doc": {"is_hidden": True, "hidden_reason": f"noise_{evt['category']}"}})
            
            try:
                bulk_result = opensearch_client.bulk(body=bulk_body, refresh=False)
                if not bulk_result.get('errors'):
                    hidden_count += len(batch)
                else:
                    for item in bulk_result.get('items', []):
                        if item.get('update', {}).get('status') in [200, 201]:
                            hidden_count += 1
            except Exception as e:
                result['errors'].append(f"Bulk update failed: {e}")
        
        # Final refresh
        try:
            opensearch_client.indices.refresh(index=index_name)
        except:
            pass
        
        result['total_hidden'] = hidden_count
        logger.info(f"[NOISE] Hid {hidden_count:,} events in case {case_id}")
        logger.info(f"[NOISE] Breakdown: {result['by_category']}")
    else:
        logger.info(f"[NOISE] No noise events found in case {case_id}")
    
    result['success'] = True
    return result


# =============================================================================
# STATISTICS
# =============================================================================

def get_noise_estimate(case_id: int) -> Dict[str, int]:
    """
    Estimate how many noise events exist in a case (without hiding them).
    Useful for preview before bulk hide.
    
    Returns dict with counts by category.
    """
    from file_processing import get_opensearch_client
    
    result = {
        'noise_process': 0,
        'noise_command': 0,
        'firewall_noise': 0,
        'total': 0
    }
    
    opensearch_client = get_opensearch_client()
    if not opensearch_client:
        return result
    
    index_name = f"case_{case_id}"
    
    # Query for noise processes
    for proc in NOISE_PROCESSES[:10]:  # Sample top 10
        try:
            count_result = opensearch_client.count(
                index=index_name,
                body={
                    "query": {
                        "bool": {
                            "must": [
                                {"wildcard": {"process.name.keyword": f"*{proc}*"}}
                            ],
                            "must_not": [
                                {"term": {"is_hidden": True}}
                            ]
                        }
                    }
                }
            )
            result['noise_process'] += count_result.get('count', 0)
        except:
            pass
    
    # Query for firewall noise
    try:
        count_result = opensearch_client.count(
            index=index_name,
            body={
                "query": {
                    "bool": {
                        "must": [
                            {"query_string": {"query": "firewall OR deny OR drop OR block", "default_field": "search_blob"}}
                        ],
                        "must_not": [
                            {"term": {"is_hidden": True}}
                        ]
                    }
                }
            }
        )
        result['firewall_noise'] = count_result.get('count', 0)
    except:
        pass
    
    result['total'] = result['noise_process'] + result['noise_command'] + result['firewall_noise']
    return result


# =============================================================================
# VALIDATION HELPERS (for IOC/hostname validation)
# =============================================================================

def is_valid_hostname(hostname: str, ip_set: Set[str] = None) -> bool:
    """Check if a string looks like a valid hostname."""
    if not hostname or len(hostname) < 3:
        return False
    
    if hostname.lower() in NOT_HOSTNAMES:
        return False
    
    # Check if it's an IP
    ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    if ip_set and hostname in ip_set:
        return False
    if re.match(ip_pattern, hostname):
        return False
    
    # Must have at least one letter
    if not re.search(r'[a-zA-Z]', hostname):
        return False
    
    return True


def is_machine_account(username: str) -> bool:
    """Check if username is a machine account (ends with $)."""
    return username.endswith('$') if username else False

