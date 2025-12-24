"""
Noise Filters Module
====================

Centralized noise filtering constants and functions used across triage modules.
This module provides a single source of truth for identifying system noise vs
potentially malicious activity.

Used by:
- events_known_noise.py (hide noise during indexing)
- ai_triage_find_iocs.py (filter noise from IOC discovery)
- ai_triage_tag_iocs.py (filter noise from event tagging)

Maintenance:
- Add new noise patterns here to apply across all modules
- All comparisons are case-insensitive
"""

import re
import ipaddress
import logging
from typing import Set

logger = logging.getLogger(__name__)


# =============================================================================
# NOISE USERS - System accounts that generate noise
# =============================================================================
# NOTE: Do NOT include '' - empty usernames handled by is_noise_user() 
#       returning True for falsy values

NOISE_USERS: Set[str] = {
    # Windows system accounts
    'system', 'network service', 'local service', 'anonymous logon',
    'window manager', 'font driver host', 
    # DWM/UMFD accounts
    'dwm-1', 'dwm-2', 'dwm-3', 'dwm-4',
    'umfd-0', 'umfd-1', 'umfd-2', 'umfd-3',
    # Built-in accounts
    'defaultaccount', 'guest', 'wdagutilityaccount',
    # NT Authority accounts (with domain prefix)
    'nt authority\\system', 'nt authority\\local service', 
    'nt authority\\network service', 'nt authority\\anonymous logon',
    # Placeholder values
    '-', 'n/a',
}


# =============================================================================
# NOISE PROCESSES - Background processes rarely attack-related
# =============================================================================
# Merged from events_known_noise.py and ai_triage_find_iocs.py

NOISE_PROCESSES: Set[str] = {
    # Windows system management
    'auditpol.exe', 'gpupdate.exe', 'wuauclt.exe', 'msiexec.exe',
    'dism.exe', 'sppsvc.exe', 'winmgmt.exe', 'dismhost.exe',
    'trustedinstaller.exe', 'tiworker.exe',
    
    # Console/shell infrastructure
    'conhost.exe', 'find.exe', 'findstr.exe', 'sort.exe', 'more.com',
    
    # Monitoring/health check
    'tasklist.exe', 'quser.exe', 'query.exe',
    
    # Windows runtime/background
    'runtimebroker.exe', 'taskhostw.exe', 'backgroundtaskhost.exe',
    'wmiprvse.exe', 'sihost.exe', 'backgroundtransferhost.exe',
    'applicationframehost.exe', 'apphostregistrationverifier.exe',
    
    # Update/maintenance
    'huntressupdater.exe', 'microsoftedgeupdate.exe', 'googleupdate.exe',
    'fulltrustnotifier.exe', 'filecoauth.exe', 'update.exe', 'updater.exe',
    
    # Search indexing
    'searchprotocolhost.exe', 'searchfilterhost.exe', 'searchindexer.exe',
    
    # Browsers (background noise)
    'chrome.exe', 'msedge.exe', 'firefox.exe', 'brave.exe', 'opera.exe',
    'chromiumhelper', 'chromesetup.exe', 'msedgewebview2.exe', 
    'wcchronenativemessaginghost.exe', 'wcchrome', 'chrmstp.exe',
    'iexplore.exe',
    
    # Adobe - comprehensive list
    'adobearm.exe', 'adobearm_ucb.exe', 'adobecollabsync.exe',
    'acrord32.exe', 'acrobat.exe', 'acrobat_sl.exe',
    'acrocef.exe', 'acregl.exe', 'adobe desktop service.exe',
    'coresync.exe', 'ccxprocess.exe', 'adobeipcbroker.exe',
    'cefsharp.browsersubprocess.exe', 'armsvc.exe', 'acrotray.exe',
    'crlogtransport.exe', 'crwindowsclientservice.exe',
    
    # Microsoft Office
    'officebackgroundtaskhandler.exe', 'officeclicktorun.exe',
    'officec2rclient.exe', 'appvshnotify.exe',
    'outlook.exe', 'excel.exe', 'winword.exe', 'powerpnt.exe',
    
    # Windows misc
    'smartscreen.exe', 'securityhealthservice.exe', 'spoolsv.exe',
    'audiodg.exe', 'wudfhost.exe', 'wlanext.exe', 'ctfmon.exe',
    'ie4uinit.exe', 'splwow64.exe', 'runonce.exe', 'unregmp2.exe',
    'photos.exe', 'actionsserver.exe', 'mobsync.exe', 'prevhost.exe',
    'atbroker.exe', 'opushutil.exe', 'sdiagnhost.exe',
    'cleanmgr.exe', 'devicecensus.exe', 'msfeedssync.exe',
    'video.ui.exe', 'windowspackagemanagerserver.exe',
    
    # Common software
    'dropbox.exe', 'onedrive.exe', 'teams.exe',
    'slack.exe', 'zoom.exe', 'skypeapp.exe', 'spotify.exe',
    
    # AV/Security (routine operations)
    'msmpeng.exe', 'msseces.exe', 'nissrv.exe',
    'sentinelui.exe', 'sentinelagent.exe',
    
    # Backup software
    'veeam.endpoint.tray.exe',
}


# =============================================================================
# NOISE PATH PATTERNS - Paths that are common noise
# =============================================================================

NOISE_PATH_PATTERNS = [
    # Browsers
    'google\\chrome\\application',
    'mozilla firefox',
    'microsoft\\edge\\application',
    'appdata\\local\\google\\chrome',
    'appdata\\local\\microsoft\\edge',
    'edgewebview',
    # Adobe
    'adobe\\',
    'program files\\common files\\adobe',
    'programdata\\adobe',
    # Windows core
    'windows\\system32\\',
    'windows\\syswow64\\',
    'windows\\winsxs\\',
    'windows\\systemapps\\',
    'windows\\explorer.exe',
    'windows\\microsoft.net\\',
    'windows\\immersivecontrolpanel',
    # Windows apps
    'windowsapps\\',
    'lockapp.exe',
    'searchapp.exe',
    'startmenuexperiencehost',
    'shellexperiencehost',
    'textinputhost.exe',
    'systemsettings.exe',
    # Common safe
    'programdata\\microsoft\\windows',
    # OneDrive
    'appdata\\local\\microsoft\\onedrive',
    # Program Files
    'program files\\internet explorer',
    'program files\\microsoft office',
    'program files (x86)\\microsoft office',
]


# =============================================================================
# NOISE COMMAND PATTERNS - Commands that are monitoring noise
# =============================================================================

NOISE_COMMAND_PATTERNS = [
    # Network monitoring (run thousands of times by RMM/EDR)
    'netstat -ano',
    'netstat  -ano',
    'netstat -an',
    'netstat  -an',
    'ipconfig /all',
    'ipconfig  /all',
    
    # System info gathering
    'systeminfo',
    'hostname',
    
    # Session/user queries (RMM health checks)
    'quser',
    '"quser"',
    'query user',
    
    # Process listing
    'tasklist',
    
    # Pipe output filters
    'find /i',
    'find "',
    'find  /i',
    'find  "',
    
    # Audit policy (EDR continuously sets these)
    'auditpol.exe /set',
    'auditpol /set',
    'auditpol.exe  /set',
    
    # Console host
    'conhost.exe 0xffffffff',
    'conhost.exe  0xffffffff',
    
    # PowerShell monitoring - Defender checks
    'get-mppreference',
    'get-mpthreat',
    'get-mpcomputerstatus',
]


# =============================================================================
# NOISE EVENT IDS - Event IDs that are usually noise even with IOC matches
# =============================================================================

NOISE_EVENT_IDS: Set[int] = {
    4689,   # Process termination (just shows process ended)
    7036,   # Service state change
    7040,   # Service start type changed
    7045,   # New service installed (check carefully, but often noise)
}


# =============================================================================
# GENERIC PARENTS - When command is noise AND parent is generic, safe to hide
# =============================================================================

GENERIC_PARENTS: Set[str] = {
    'cmd.exe', 'svchost.exe', 'services.exe', 'wmiprvse.exe',
    'wmi provider host', 'powershell.exe', 'pwsh.exe'
}


# =============================================================================
# NOISE IOC VALUES - Values that should never be IOCs
# =============================================================================

NOISE_IOC_VALUES: Set[str] = {
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


# =============================================================================
# NOT_HOSTNAMES - Strings that shouldn't be treated as hostnames
# =============================================================================

NOT_HOSTNAMES: Set[str] = {
    # Common words
    'the', 'and', 'from', 'with', 'this', 'that', 'was', 'has', 'been', 'have', 'had',
    'are', 'were', 'will', 'would', 'could', 'should', 'may', 'might', 'must', 'shall',
    'can', 'for', 'but', 'not', 'you', 'all', 'can', 'her', 'his', 'its', 'our', 'out',
    'own', 'she', 'who', 'how', 'now', 'old', 'see', 'way', 'who', 'did', 'get', 'got',
    'him', 'let', 'put', 'say', 'too', 'use', 'via', 'name', 'host', 'user', 'file',
    
    # IT/Security terms
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


# =============================================================================
# DETECTION FUNCTIONS
# =============================================================================

def is_noise_user(username: str) -> bool:
    """
    Check if username is a known system/noise account.
    
    Returns True for:
    - Empty/None usernames
    - System accounts (SYSTEM, NETWORK SERVICE, etc.)
    - Machine accounts (ending with $)
    """
    if not username:
        return True  # Empty username = noise
    
    name_lower = username.lower().strip()
    
    # Direct match
    if name_lower in NOISE_USERS:
        return True
    
    # Machine accounts (end with $)
    if name_lower.endswith('$'):
        return True
    
    return False


def is_machine_account(username: str) -> bool:
    """Check if username is a machine account (ends with $)."""
    if not username:
        return False
    return username.strip().endswith('$')


def is_noise_process(proc_name: str) -> bool:
    """
    Check if process name is background noise (case-insensitive).
    """
    if not proc_name:
        return False
    
    proc_lower = proc_name.lower().strip()
    
    # Direct match
    if proc_lower in NOISE_PROCESSES:
        return True
    
    # Also try without .exe
    proc_no_ext = proc_lower.replace('.exe', '')
    if proc_no_ext in {p.lower().replace('.exe', '') for p in NOISE_PROCESSES}:
        return True
    
    return False


def is_noise_path(path: str) -> bool:
    """Check if path matches a known noise pattern."""
    if not path:
        return False
    
    path_lower = path.lower()
    for pattern in NOISE_PATH_PATTERNS:
        if pattern in path_lower:
            return True
    
    return False


def is_noise_command(cmd: str, parent_name: str = None) -> bool:
    """
    Check if command line is noise.
    
    Args:
        cmd: Command line to check
        parent_name: Optional parent process name for context
    """
    if not cmd:
        return False
    
    cmd_lower = cmd.lower().strip()
    
    # Check against noise patterns
    for pattern in NOISE_COMMAND_PATTERNS:
        if pattern in cmd_lower:
            return True
    
    # If parent is provided and is generic, more likely to be noise
    if parent_name:
        parent_lower = parent_name.lower()
        parent_base = parent_lower.split('\\')[-1]
        if parent_base in GENERIC_PARENTS:
            # Additional checks for generic parent
            if any(p in cmd_lower for p in ['conhost.exe 0x', 'svchost.exe -k']):
                return True
    
    return False


def is_noise_hostname(hostname: str) -> bool:
    """Check if hostname is a known non-hostname value."""
    if not hostname:
        return True
    
    hostname_lower = hostname.lower().strip()
    
    # Check against not-hostname list
    if hostname_lower in NOT_HOSTNAMES:
        return True
    
    # Too short to be a hostname
    if len(hostname_lower) < 2:
        return True
    
    # Just numbers
    if hostname_lower.isdigit():
        return True
    
    return False


def is_noise_ioc_value(value: str) -> bool:
    """Check if value is a known noise IOC value."""
    if not value:
        return True
    return value.lower().strip() in NOISE_IOC_VALUES


# =============================================================================
# IP UTILITY FUNCTIONS
# =============================================================================

def is_valid_ip(ip_str: str) -> bool:
    """Check if string is a valid IP address."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def is_private_ip(ip_str: str) -> bool:
    """Check if IP is private/internal (RFC1918, loopback, link-local)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def is_external_ip(ip_str: str) -> bool:
    """Check if IP is external (not private, loopback, link-local, or reserved)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)
    except ValueError:
        return False


def is_ip_in_range(ip_str: str, cidr: str) -> bool:
    """Check if IP is within a CIDR range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        network = ipaddress.ip_network(cidr, strict=False)
        return ip in network
    except ValueError:
        return False

