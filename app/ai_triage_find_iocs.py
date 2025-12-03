"""
AI Triage - Find IOCs Module
============================

Searches events containing existing IOCs and extracts additional potential IOCs
from those events. This is the "snowball" hunting concept - using known IOCs
to discover new related indicators.

Filtering:
- Does NOT search hidden events
- Filters out known systems (unless they are actor_system type)
- Filters out known IPs from systems
- Filters out VPN IP ranges
- Filters out known-good IPs from system settings

Usage:
    from ai_triage_find_iocs import find_potential_iocs
    
    result = find_potential_iocs(case_id)
    # Returns: {'potential_iocs': {...}, 'events_searched': int, 'matches_found': int}
"""

import re
import logging
from typing import Dict, List, Set, Optional, Any
import ipaddress

logger = logging.getLogger(__name__)


# ============================================================================
# NOISE FILTERING (copied from events_known_noise for standalone use)
# ============================================================================

# NOTE: Do NOT include '' - empty usernames are handled by is_noise_user() returning True for falsy values
NOISE_USERS = {
    'system', 'network service', 'local service', 'anonymous logon',
    'window manager', 'dwm-1', 'dwm-2', 'dwm-3', 'dwm-4',
    'umfd-0', 'umfd-1', 'umfd-2', 'umfd-3',
    '-', 'n/a', 'font driver host', 'defaultaccount', 
    'guest', 'wdagutilityaccount', 'nt authority\\system',
    'nt authority\\local service', 'nt authority\\network service'
}

# Processes that generate lots of noise and are rarely attack-related
# NOTE: All comparisons should be case-insensitive!
NOISE_PROCESSES = {
    # Browsers (background noise)
    'chrome.exe', 'msedge.exe', 'firefox.exe', 'brave.exe', 'opera.exe',
    'chromiumhelper', 'chromesetup.exe', 'update.exe', 'updater.exe',
    'msedgewebview2.exe', 'wcchronenativemessaginghost.exe',
    'wcchrome', 'chrmstp.exe',  # Chrome helpers
    # Adobe - comprehensive list
    'adobearm.exe', 'adobearm_ucb.exe', 'adobecollabsync.exe', 
    'acrord32.exe', 'acrobat.exe', 'acrobat_sl.exe',
    'acrocef.exe', 'acregl.exe', 'adobe desktop service.exe', 
    'coresync.exe', 'ccxprocess.exe', 'adobeipcbroker.exe', 
    'cefsharp.browsersubprocess.exe', 'armsvc.exe', 'acrotray.exe', 
    'crlogtransport.exe', 'crwindowsclientservice.exe',
    # Microsoft Office background
    'officebackgroundtaskhandler.exe', 'officeclicktorun.exe',
    'officec2rclient.exe', 'appvshnotify.exe',
    'outlook.exe', 'excel.exe', 'winword.exe', 'powerpnt.exe',
    # Windows background
    'runtimebroker.exe', 'backgroundtaskhost.exe', 'sihost.exe',
    'taskhostw.exe', 'searchprotocolhost.exe', 'searchfilterhost.exe',
    'searchindexer.exe', 'smartscreen.exe', 'securityhealthservice.exe',
    'msiexec.exe', 'trustedinstaller.exe', 'tiworker.exe',
    'spoolsv.exe', 'audiodg.exe', 'wudfhost.exe', 'wlanext.exe',
    'dismhost.exe', 'ie4uinit.exe', 'splwow64.exe', 'runonce.exe',
    'unregmp2.exe', 'backgroundtransferhost.exe', 'ctfmon.exe',
    'applicationframehost.exe', 'apphostregistrationverifier.exe',
    'photos.exe', 'actionsserver.exe', 'mobsync.exe', 'prevhost.exe',
    'atbroker.exe', 'opushutil.exe', 'sdiagnhost.exe',
    'cleanmgr.exe', 'devicecensus.exe', 'msfeedssync.exe',
    'video.ui.exe', 'windowspackagemanagerserver.exe',
    # Common software 
    'googleupdate.exe', 'dropbox.exe', 'onedrive.exe', 'teams.exe',
    'slack.exe', 'zoom.exe', 'skypeapp.exe', 'spotify.exe',
    # AV/Security (routine, not response)
    'msmpeng.exe', 'msseces.exe', 'nissrv.exe',
    'sentinelui.exe', 'sentinelagent.exe',
    # Backup software
    'veeam.endpoint.tray.exe',
    # IE/Edge legacy
    'iexplore.exe',
}

# Paths that are common noise - skip IOCs from these
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
    'windows\\systemapps\\',  # Modern Windows apps
    'windows\\explorer.exe',
    'windows\\microsoft.net\\',  # .NET framework
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
]


def is_noise_process(proc_name: str) -> bool:
    """Check if process name is background noise (case-insensitive)."""
    if not proc_name:
        return False
    proc_lower = proc_name.lower().strip()
    # Direct match
    if proc_lower in NOISE_PROCESSES:
        return True
    # Partial match for common patterns
    noise_prefixes = [
        # Adobe/browsers
        'adobe', 'acro', 'chrome', 'msedge', 'firefox', 'sentinel', 'veeam',
        'edgewebview', 'adnotification',
        # Windows apps
        'gamebar', 'lockapp', 'searchapp', 'searchui',
        'startmenu', 'textinputhost', 'shellexperiencehost',
        'microsoft.msn.', 'onenote', 'sdxhelper', 'musnotify',
        'locationnotification', 'hxtsr', 'clipesu', 'bdeui',
        'compkgsrv', 'credentialui', 'installagent', 'ngentask',
        'securityapp', 'microsoftsecurity', 'mpcmdrun',
        'ielowutil', 'comppkgsrv',
        # Hardware/drivers
        'rtkaud', 'igfx', 'surfacedtx', 'surfaceapp',
        # Windows utilities
        'settingsync', 'spatialaudiolicense', 'spotifymigrator',
        'useroobe', 'phoneexperience', 'yourphone',
        'securityhealth', 'tabtip', 'tstheme', 'fsquirt',
        'servermannager', 'dllhost',
    ]
    for prefix in noise_prefixes:
        if proc_lower.startswith(prefix):
            return True
    # Also match patterns anywhere in name
    noise_contains = ['webview', 'update', 'setup', 'installer', 'ngen']
    for pattern in noise_contains:
        if pattern in proc_lower:
            return True
    return False


def is_noise_path(path: str) -> bool:
    """Check if path is from a noisy location."""
    if not path:
        return False
    path_lower = path.lower()
    return any(noise in path_lower for noise in NOISE_PATH_PATTERNS)


def is_noise_user(username: str) -> bool:
    """Check if username is system noise."""
    if not username:
        return True
    return username.lower().strip() in NOISE_USERS


def is_machine_account(username: str) -> bool:
    """Check if username is a machine account (ends with $)."""
    return username and username.strip().endswith('$')


def is_noise_command(cmd: str) -> bool:
    """Check if command line is from a noisy process."""
    if not cmd:
        return True
    cmd_lower = cmd.lower()
    # Noise patterns in commands
    noise_cmd_patterns = [
        # Adobe
        'adobe\\', 'acrobat\\', 'adnotificationmanager', 'collabsync',
        '/processrequestinusercontext', '/product:', '/lang:',
        # Browsers
        'google\\chrome\\', 'msedge\\', 'edgewebview',
        'microsoft\\edge\\application', 'identityhelper', 'identity_helper',
        # NOTE: ScreenConnect is handled separately with ID checks (not filtered here)
        # OneDrive/Cloud
        'appdata\\local\\microsoft\\onedrive',
        # Installers
        'installer.exe', 'setup.exe', 'desktopappinstaller',
        # Office background noise
        'sdxhelper', 'onenotem.exe', 'onenote.exe',
        'microsoft shared\\office', 'officesvcmgr',
        '/embedding', '/memorywindow',
        # Windows maintenance
        'ngentask', 'ngen.exe', 'ngensvc',
        'musnotifyicon', 'locationnotification',
        'microsoft.msn.', 'clipesuconsumer',
        'bdeui', 'credentialuibroker',
        'immersivecontrolpanel', 'cleanmgr.exe',
        'devicecensus', 'msfeedssync', 'startupscan',
        'pcawalltaper', 'pcasvc.dll',
        # IE legacy
        'ielowutil', 'iexplore.exe',
        # Cisco VPN
        'cisco\\cisco secure client',
        # Windows Store Apps (WindowsApps folder)
        'windowsapps\\microsoft.yourphone',
        'windowsapps\\microsoft.zunevideo',
        'windowsapps\\spotifyab.',
        'phoneexperiencehost', 'yourphone',
        'zunevideo', 'video.ui.exe',
        # Hardware/drivers
        'surfacehub', 'surfacedtx', 'surfaceappdt',
        'rtkaudusevice', 'igfxemn', 'driverstore\\filerepository',
        # System utilities
        'securityhealthsystray', 'settingsynchost',
        'spatialaudiolicense', 'spotifymigrator', 'spotifystartuptask',
        'useroobeboker', 'tabtip.exe', 'tstheme.exe',
        'searchui.exe', 'fsquirt.exe',
        # Windows system maintenance
        'mobsync.exe', 'sdiagnhost.exe', 'prevhost.exe',
        'atbroker.exe', 'opushutil.exe', 'tlsbln.exe',
        'shcreatelocalserverrun', 'shell32.dll,shcreate',
        # Service start/stop for known safe services
        'net.exe stop ltservice', 'net.exe stop ltsvcmon',
        'net.exe start hpaudio', 'net.exe stop hpaudio',
        'net1  stop hpaudio', 'net1  start hpaudio',
        'net1  stop warp', 'net1  start warp',
        # Embedding
        '-embedding',
    ]
    return any(pattern in cmd_lower for pattern in noise_cmd_patterns)


def is_valid_ip(ip_str: str) -> bool:
    """Check if string is a valid IP address."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def is_private_ip(ip_str: str) -> bool:
    """Check if IP is private/internal."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def contains_existing_ioc(value: str, existing_values: set) -> bool:
    """
    Check if a value contains any existing IOC.
    Used for commands/paths where the IOC might be embedded.
    
    e.g., command "C:\\path\\WinSCP.exe /flag" contains IOC "winscp.exe"
    """
    if not value:
        return False
    value_lower = value.lower()
    
    # Direct match
    if value_lower in existing_values:
        return True
    
    # Check if any existing IOC is contained in the value
    for existing in existing_values:
        if existing and len(existing) >= 3:  # Skip very short values
            if existing in value_lower:
                return True
    
    return False


def check_managed_tool(proc_name: str, search_blob: str, managed_tools: list) -> tuple:
    """
    Check if an event is from a managed tool (RMM, EDR, or Remote).
    
    Returns:
        (is_managed_tool, should_skip, tool_name)
        
    Logic:
    - If not a managed tool: (False, False, None)
    - If managed tool with known-good IDs configured:
        - If ID matches: (True, True, name) -> skip event (legitimate)
        - If NO ID matches: (True, False, name) -> KEEP as potential IOC!
    - If managed tool with NO known-good IDs configured:
        - (True, True, name) -> skip event (trusted by pattern alone)
    """
    proc_lower = (proc_name or '').lower()
    
    # Only check process name for managed tools - search_blob can have false positives
    # (e.g., "huntress.io" portal URL in metadata doesn't mean Huntress agent is running)
    if not proc_lower:
        return (False, False, None)
    
    blob_lower = (search_blob or '').lower()
    
    for tool in managed_tools:
        patterns = tool.get('patterns', [])
        
        # Check if the PROCESS NAME matches any pattern for this tool
        # We specifically check proc_name, not search_blob, to avoid false positives
        is_match = False
        for pattern in patterns:
            if pattern and pattern in proc_lower:
                is_match = True
                break
        
        if not is_match:
            continue
            
        # It's a managed tool event
        tool_name = tool.get('name', 'Unknown')
        known_ids = tool.get('known_good_ids', [])
        
        if known_ids:
            # Tool has known-good IDs - check if any match in the full blob
            for known_id in known_ids:
                if known_id and known_id in blob_lower:
                    # Known-good ID found - this is legitimate
                    return (True, True, tool_name)
            
            # No known-good ID found - could be attacker's tool!
            return (True, False, tool_name)
        else:
            # No known-good IDs configured - trust by pattern alone
            return (True, True, tool_name)
    
    return (False, False, None)


def is_ip_in_range(ip_str: str, range_str: str) -> bool:
    """Check if IP is in a CIDR range or single IP."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if '/' in range_str:
            network = ipaddress.ip_network(range_str, strict=False)
            return ip in network
        elif '-' in range_str:
            # Handle IP range like "192.168.1.1-192.168.1.50"
            start, end = range_str.split('-')
            start_ip = ipaddress.ip_address(start.strip())
            end_ip = ipaddress.ip_address(end.strip())
            return start_ip <= ip <= end_ip
        else:
            return ip == ipaddress.ip_address(range_str)
    except (ValueError, TypeError):
        return False


# ============================================================================
# CONTEXT LOADING
# ============================================================================

def get_case_context(case_id: int) -> Dict:
    """
    Load context for the case:
    - Known systems (names and IPs)
    - Actor systems (names and IPs)
    - VPN IP ranges
    - Known-good IPs from system settings
    - Existing IOCs
    """
    from models import System, IOC, SystemToolsSetting
    
    context = {
        'known_systems': set(),      # System names that are NOT actor
        'known_ips': set(),          # IPs from non-actor systems
        'actor_systems': set(),      # Actor system names
        'actor_ips': set(),          # Actor IPs
        'known_good_ips': [],        # From system settings
        'managed_tools': [],         # RMM/EDR/Remote tools with ID checking
        'existing_iocs': {},         # Existing IOCs by type
        'existing_ioc_values': set() # All existing IOC values (for dedup)
    }
    
    try:
        # Get systems
        systems = System.query.filter_by(case_id=case_id, hidden=False).all()
        for sys in systems:
            name = (sys.system_name or '').lower().strip()
            ip = (sys.ip_address or '').strip()
            
            if sys.system_type == 'actor_system':
                if name:
                    context['actor_systems'].add(name)
                if ip and is_valid_ip(ip):
                    context['actor_ips'].add(ip)
            else:
                if name:
                    context['known_systems'].add(name)
                if ip and is_valid_ip(ip):
                    context['known_ips'].add(ip)
        
        # Note: VPN ranges are NOT filtered - they have another purpose (identifying VPN users)
        # We want to discover IOCs even if they're in VPN ranges
        
        # Get known-good IPs from system settings
        settings = SystemToolsSetting.query.filter_by(setting_type='known_good_ip', is_active=True).all()
        for setting in settings:
            if setting.ip_or_cidr:
                context['known_good_ips'].append(setting.ip_or_cidr.strip())
        
        # Get ALL tool patterns (RMM, EDR, Remote) - same logic for all:
        # - If tool has known-good IDs configured: only skip if ID matches
        # - If tool has NO known-good IDs: skip by pattern alone (trusted tool)
        import json as _json
        
        context['managed_tools'] = []  # All RMM/EDR/Remote tools with ID checking
        
        tool_settings = SystemToolsSetting.query.filter(
            SystemToolsSetting.setting_type.in_(['rmm_tool', 'edr_tool', 'remote_tool']),
            SystemToolsSetting.is_active == True
        ).all()
        
        for setting in tool_settings:
            if not setting.executable_pattern:
                continue
                
            # Parse known-good IDs (only remote_tool has this field, but check for all)
            ids = []
            if setting.known_good_ids:
                try:
                    ids = _json.loads(setting.known_good_ids)
                except:
                    pass
            
            # Parse executable patterns
            patterns = []
            for p in setting.executable_pattern.split(','):
                p = p.strip().lower()
                if p:
                    if '*' in p:
                        patterns.append(p.split('*')[0])  # Get prefix before wildcard
                    else:
                        patterns.append(p)
            
            if patterns:
                context['managed_tools'].append({
                    'name': setting.tool_name,
                    'type': setting.setting_type,
                    'patterns': patterns,
                    'known_good_ids': [i.lower().strip() for i in ids if i]
                })
        
        logger.info(f"[FIND_IOC] Loaded {len(context['managed_tools'])} managed tools for filtering")
        
        # Get existing IOCs
        existing_iocs = IOC.query.filter_by(case_id=case_id, is_active=True).all()
        for ioc in existing_iocs:
            ioc_type = ioc.ioc_type
            ioc_value = (ioc.ioc_value or '').strip()
            
            if ioc_type not in context['existing_iocs']:
                context['existing_iocs'][ioc_type] = []
            context['existing_iocs'][ioc_type].append(ioc_value)
            context['existing_ioc_values'].add(ioc_value.lower())
        
        logger.info(f"[FIND_IOC] Case {case_id} context: {len(context['known_systems'])} systems, "
                   f"{len(context['actor_systems'])} actor systems, "
                   f"{len(context['existing_iocs'])} IOC types")
        
    except Exception as e:
        logger.error(f"[FIND_IOC] Failed to load case context: {e}")
    
    return context


# ============================================================================
# IOC SEARCHING
# ============================================================================

def search_events_with_iocs(case_id: int, iocs: Dict[str, List[str]], limit: int = None) -> List[Dict]:
    """
    Search OpenSearch for events containing any of the given IOCs.
    Only searches visible (non-hidden) events.
    
    Uses scroll API to retrieve ALL matching events (no 10K limit).
    If limit is provided, stops after that many events.
    
    Uses search_blob field which contains all event data flattened.
    """
    from main import opensearch_client
    
    client = opensearch_client
    index_name = f"case_{case_id}"
    
    # Build OR query for all IOC values
    should_clauses = []
    all_ioc_values = []
    
    for ioc_type, values in iocs.items():
        for value in values[:50]:  # Limit per type to avoid huge queries
            if value and len(value) >= 3:  # Skip very short values
                all_ioc_values.append(value.lower())
                should_clauses.append({
                    "match_phrase": {
                        "search_blob": value.lower()
                    }
                })
    
    if not should_clauses:
        logger.warning("[FIND_IOC] No valid IOCs to search for")
        return []
    
    # Query: must NOT be hidden, should match at least one IOC
    query = {
        "query": {
            "bool": {
                "must_not": [
                    {"term": {"is_hidden": True}}
                ],
                "should": should_clauses,
                "minimum_should_match": 1
            }
        },
        "_source": ["search_blob", "process", "host", "user", "source", "destination", 
                    "@timestamp", "normalized_event_id", "event", "Event",
                    "forensic_Workstation", "forensic_TargetServerName", "forensic_IpAddress",
                    "winlog"]
    }
    
    try:
        logger.info(f"[FIND_IOC] Searching case_{case_id} for {len(should_clauses)} IOC patterns (using scroll)...")
        
        all_hits = []
        scroll_time = "2m"
        batch_size = 1000
        
        # Initial search with scroll
        response = client.search(
            index=index_name, 
            body=query, 
            scroll=scroll_time,
            size=batch_size
        )
        
        scroll_id = response.get('_scroll_id')
        hits = response.get('hits', {}).get('hits', [])
        all_hits.extend(hits)
        
        # Continue scrolling until no more results or limit reached
        while hits:
            if limit and len(all_hits) >= limit:
                all_hits = all_hits[:limit]
                break
                
            response = client.scroll(scroll_id=scroll_id, scroll=scroll_time)
            scroll_id = response.get('_scroll_id')
            hits = response.get('hits', {}).get('hits', [])
            all_hits.extend(hits)
        
        # Clean up scroll context
        try:
            if scroll_id:
                client.clear_scroll(scroll_id=scroll_id)
        except:
            pass
        
        logger.info(f"[FIND_IOC] Found {len(all_hits)} events matching IOCs")
        return all_hits
        
    except Exception as e:
        logger.error(f"[FIND_IOC] OpenSearch query failed: {e}")
        return []


# ============================================================================
# IOC EXTRACTION FROM EVENTS
# ============================================================================

def extract_iocs_from_events(events: List[Dict], context: Dict) -> Dict[str, Set[str]]:
    """
    Extract potential IOCs from event data.
    Filters based on context (known systems, known IPs, etc.)
    
    Returns dict of IOC types to sets of values.
    """
    potential_iocs = {
        'usernames': set(),
        'hostnames': set(),
        'ips': set(),
        'processes': set(),
        'commands': set(),
        'paths': set(),
    }
    
    known_systems = context['known_systems']
    known_ips = context['known_ips']
    actor_systems = context['actor_systems']
    actor_ips = context['actor_ips']
    known_good_ips = context['known_good_ips']
    existing_values = context['existing_ioc_values']
    managed_tools = context.get('managed_tools', [])  # All RMM/EDR/Remote tools
    
    skipped_noise = 0
    skipped_known_tools = 0
    kept_unknown_tools = 0
    
    for hit in events:
        src = hit.get('_source', {})
        search_blob = (src.get('search_blob', '') or '').lower()
        
        # === SKIP NOISE EVENTS ===
        # Check if this event is from a noisy process - skip entire event
        proc = src.get('process', {}) or {}
        proc_name = ''
        if isinstance(proc, dict):
            proc_name = proc.get('name', '') or proc.get('executable', '') or ''
            if isinstance(proc_name, str):
                # Extract just filename
                if '\\' in proc_name:
                    proc_name = proc_name.split('\\')[-1]
                if '/' in proc_name:
                    proc_name = proc_name.split('/')[-1]
                proc_name_lower = proc_name.lower()
                
                # Check managed tools (RMM, EDR, Remote) with ID verification
                is_managed, should_skip, tool_name = check_managed_tool(proc_name, search_blob, managed_tools)
                if is_managed:
                    if should_skip:
                        # Known-good tool/ID - this is legitimate, skip it
                        skipped_known_tools += 1
                        continue
                    else:
                        # UNKNOWN ID - could be attacker's tool! KEEP IT
                        kept_unknown_tools += 1
                        logger.info(f"[FIND_IOC] Keeping {tool_name} event - no known-good ID match!")
                        # Don't continue - let it be processed as a potential IOC
                
                # Skip entire event if from noise process
                if is_noise_process(proc_name):
                    skipped_noise += 1
                    continue
        
        # Also check search_blob for noise if process name not found
        if not proc_name and search_blob:
            # Check managed tools via search_blob
            is_managed, should_skip, tool_name = check_managed_tool('', search_blob, managed_tools)
            if is_managed:
                if should_skip:
                    skipped_known_tools += 1
                    continue
                else:
                    kept_unknown_tools += 1
                    logger.info(f"[FIND_IOC] Keeping {tool_name} event (via blob) - no known-good ID match!")
            
            # Check for noise patterns in search_blob
            noise_blob_patterns = [
                'chrome.exe', 'msedge.exe', 'firefox.exe',
                'acrobat.exe', 'acrord32.exe', 'acrocef.exe', 'adobearm',
                'spotify.exe', 'zoom.exe', 'teams.exe', 'slack.exe',
                'outlook.exe', 'excel.exe', 'winword.exe',
                'backgroundtransferhost.exe', 'runtimebroker.exe',
            ]
            if any(pattern in search_blob for pattern in noise_blob_patterns):
                skipped_noise += 1
                continue
        
        # === USERNAMES ===
        user_data = src.get('user', {}) or {}
        if isinstance(user_data, dict):
            username = user_data.get('name', '') or ''
        else:
            username = ''
        if username and isinstance(username, str) and not is_noise_user(username) and not is_machine_account(username):
            if username.lower() not in existing_values:
                potential_iocs['usernames'].add(username)
        
        # Check process user
        proc = src.get('process', {}) or {}
        proc_user_field = proc.get('user') or proc.get('user_name') or ''
        # Handle case where user is a dict with nested 'name' field
        if isinstance(proc_user_field, dict):
            proc_user = proc_user_field.get('name', '') or ''
        else:
            proc_user = proc_user_field or ''
        if proc_user and not is_noise_user(proc_user) and not is_machine_account(proc_user):
            if proc_user.lower() not in existing_values:
                potential_iocs['usernames'].add(proc_user)
        
        # === HOSTNAMES ===
        host_data = src.get('host', {}) or {}
        if isinstance(host_data, dict):
            hostname = host_data.get('name', '') or host_data.get('hostname', '') or ''
        else:
            hostname = ''
        if hostname and isinstance(hostname, str):
            hostname_lower = hostname.lower().strip()
            # Skip if it's a known (non-actor) system
            if hostname_lower not in known_systems:
                # Include actor systems as they're interesting
                if hostname_lower not in existing_values:
                    potential_iocs['hostnames'].add(hostname)
        
        # Source/destination hosts
        for field in ['source', 'destination']:
            data = src.get(field, {}) or {}
            host = data.get('hostname') or data.get('host') or ''
            # Handle case where host is a dict
            if isinstance(host, dict):
                host = host.get('name', '') or ''
            if host and isinstance(host, str):
                host_lower = host.lower().strip()
                if host_lower not in known_systems and host_lower not in existing_values:
                    potential_iocs['hostnames'].add(host)
        
        # Windows Security event fields (logon events, etc.)
        # These contain source workstations, target servers, etc.
        
        # Check multiple possible locations for event data
        # CaseScope format: forensic_* fields at top level
        # Also check Event.EventData and winlog.event_data for compatibility
        
        workstation = None
        target_server = None
        logon_ip = None
        
        # Method 1: CaseScope forensic_* fields (top-level)
        workstation = src.get('forensic_Workstation', '') or ''
        target_server = src.get('forensic_TargetServerName', '') or ''
        logon_ip = src.get('forensic_IpAddress', '') or ''
        
        # Method 2: Event.EventData (nested XML structure)
        if not workstation:
            event_obj = src.get('Event', {}) or {}
            if isinstance(event_obj, dict):
                event_data_str = event_obj.get('EventData', '') or ''
                # EventData might be a JSON string or dict
                if isinstance(event_data_str, str) and event_data_str:
                    try:
                        import json
                        event_data_dict = json.loads(event_data_str)
                        workstation = workstation or event_data_dict.get('Workstation', '') or event_data_dict.get('WorkstationName', '')
                        target_server = target_server or event_data_dict.get('TargetServerName', '')
                        logon_ip = logon_ip or event_data_dict.get('IpAddress', '')
                    except:
                        pass
                elif isinstance(event_data_str, dict):
                    workstation = workstation or event_data_str.get('Workstation', '') or event_data_str.get('WorkstationName', '')
                    target_server = target_server or event_data_str.get('TargetServerName', '')
                    logon_ip = logon_ip or event_data_str.get('IpAddress', '')
        
        # Method 3: winlog.event_data (Elastic/Beats format)
        if not workstation:
            winlog = src.get('winlog', {}) or {}
            winlog_event_data = winlog.get('event_data', {}) or {}
            workstation = workstation or winlog_event_data.get('WorkstationName', '') or winlog_event_data.get('Workstation', '')
            target_server = target_server or winlog_event_data.get('TargetServerName', '')
            logon_ip = logon_ip or winlog_event_data.get('IpAddress', '')
        
        # Process workstation
        if workstation and isinstance(workstation, str):
            workstation = workstation.strip()
            # Skip common noise values
            if workstation and workstation not in ['-', '', 'N/A', 'null', 'NULL']:
                ws_lower = workstation.lower()
                if ws_lower not in known_systems and ws_lower not in existing_values:
                    potential_iocs['hostnames'].add(workstation)
        
        # Process target server
        if target_server and isinstance(target_server, str):
            target_server = target_server.strip()
            if target_server and target_server not in ['-', '', 'N/A', 'null', 'NULL', 'localhost']:
                ts_lower = target_server.lower()
                if ts_lower not in known_systems and ts_lower not in existing_values:
                    potential_iocs['hostnames'].add(target_server)
        
        # === IP ADDRESSES ===
        # Collect IPs from various fields
        ips_to_check = []
        
        # Standard source/destination fields
        for field in ['source', 'destination']:
            data = src.get(field, {}) or {}
            ip = data.get('ip') or data.get('address') or ''
            if isinstance(ip, dict):
                ip = ''
            if ip and isinstance(ip, str):
                ips_to_check.append(ip)
        
        # Windows Security event logon IP (from earlier extraction)
        if logon_ip and isinstance(logon_ip, str):
            logon_ip = logon_ip.strip()
            # Skip localhost/noise values
            if logon_ip and logon_ip not in ['-', '', '::1', '127.0.0.1', '0.0.0.0']:
                ips_to_check.append(logon_ip)
        
        # Check each IP
        for ip in ips_to_check:
            if not is_valid_ip(ip):
                continue
            
            # Skip IPv6 link-local and other noise addresses
            try:
                ip_obj = ipaddress.ip_address(ip)
                # Skip link-local (fe80::)
                if ip_obj.is_link_local:
                    continue
                # Skip loopback
                if ip_obj.is_loopback:
                    continue
                # Skip IPv4-mapped IPv6 that are private (::ffff:10.x.x.x, ::ffff:192.168.x.x)
                if hasattr(ip_obj, 'ipv4_mapped') and ip_obj.ipv4_mapped:
                    if ip_obj.ipv4_mapped.is_private:
                        continue
            except:
                pass
            
            # Skip private IPs that are known systems
            if ip in known_ips:
                continue
            # Skip known-good IPs from system settings
            if any(is_ip_in_range(ip, r) for r in known_good_ips):
                continue
            # Skip if already an IOC
            if ip in existing_values:
                continue
            # Include - actor IPs are interesting, public IPs too
            # Note: VPN ranges are NOT filtered - they have another purpose
            potential_iocs['ips'].add(ip)
        
        # === PROCESSES ===
        proc_name = proc.get('name', '') or proc.get('executable', '') or ''
        if proc_name:
            # Extract just filename
            if '\\' in proc_name:
                proc_name = proc_name.split('\\')[-1]
            if '/' in proc_name:
                proc_name = proc_name.split('/')[-1]
            proc_name_lower = proc_name.lower()
            # Skip if it's an existing IOC (exact match on filename)
            if proc_name and proc_name_lower not in existing_values:
                # Skip common Windows processes and noise processes
                common_procs = {'cmd.exe', 'powershell.exe', 'svchost.exe', 'services.exe', 
                               'explorer.exe', 'lsass.exe', 'csrss.exe', 'wininit.exe',
                               'conhost.exe', 'dwm.exe', 'taskhostw.exe'}
                # Check managed tools (with ID verification)
                is_managed, should_skip, _ = check_managed_tool(proc_name, search_blob, managed_tools)
                # Only skip if it's a managed tool AND it has known-good ID (or no IDs configured)
                if proc_name_lower not in common_procs and not is_noise_process(proc_name):
                    if not (is_managed and should_skip):
                        potential_iocs['processes'].add(proc_name)
        
        # === COMMAND LINES ===
        cmd_line = proc.get('command_line', '') or ''
        if cmd_line and len(cmd_line) > 20:  # Only interesting commands
            # Skip if command contains any existing IOC (avoid duplicates)
            if not contains_existing_ioc(cmd_line, existing_values):
                # Check managed tools (with ID verification)
                is_managed_cmd, should_skip_cmd, _ = check_managed_tool('', cmd_line.lower(), managed_tools)
                # Skip noise commands
                if not (is_managed_cmd and should_skip_cmd) and not is_noise_command(cmd_line):
                    # Skip very generic commands
                    if not any(skip in cmd_line.lower() for skip in ['conhost.exe 0x', 'c:\\windows\\system32\\svchost.exe -k']):
                        potential_iocs['commands'].add(cmd_line[:500])  # Truncate
        
        # === PATHS ===
        # Extract paths from command line
        path_pattern = r'[A-Za-z]:\\(?:[^\s\\/:*?"<>|\']+\\)+[^\s\\/:*?"<>|\']*'
        if cmd_line and isinstance(cmd_line, str):
            paths = re.findall(path_pattern, cmd_line)
            for path in paths:
                path = path.rstrip("'\".,;:")
                # Skip if path contains any existing IOC
                if len(path) >= 15 and not contains_existing_ioc(path, existing_values):
                    # Skip Windows system paths and noise paths (Chrome, Adobe, etc.)
                    if not path.lower().startswith('c:\\windows\\system32') and not is_noise_path(path):
                        potential_iocs['paths'].add(path)
    
    # Log summary
    logger.info(f"[FIND_IOC] Skipped {skipped_noise} noise events, {skipped_known_tools} known-good tool events")
    if kept_unknown_tools > 0:
        logger.warning(f"[FIND_IOC] KEPT {kept_unknown_tools} tool events with UNKNOWN IDs (potential attacker tools!)")
    for ioc_type, values in potential_iocs.items():
        if values:
            logger.info(f"[FIND_IOC] Found {len(values)} potential {ioc_type}")
    
    return potential_iocs


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def find_potential_iocs(case_id: int) -> Dict[str, Any]:
    """
    Main entry point for finding potential IOCs from events.
    
    Flow:
    1. Load case context (systems, existing IOCs, etc.)
    2. Search for events containing existing IOCs (excluding hidden)
    3. Extract potential new IOCs from those events
    4. Filter out known systems and IPs
    5. Return results
    
    Returns:
        {
            'success': bool,
            'potential_iocs': {
                'usernames': [...],
                'hostnames': [...],
                'ips': [...],
                'processes': [...],
                'commands': [...],
                'paths': [...]
            },
            'events_searched': int,
            'existing_ioc_count': int,
            'error': str (if failed)
        }
    """
    logger.info(f"[FIND_IOC] Starting IOC discovery for case {case_id}")
    
    try:
        # Load context
        context = get_case_context(case_id)
        
        # Check if we have IOCs to search with
        existing_iocs = context['existing_iocs']
        if not existing_iocs:
            logger.warning(f"[FIND_IOC] No existing IOCs in case {case_id}")
            return {
                'success': False,
                'error': 'No existing IOCs to search with. Add IOCs manually or extract from EDR report first.',
                'potential_iocs': {},
                'events_searched': 0,
                'existing_ioc_count': 0
            }
        
        # Count existing IOCs
        existing_count = sum(len(v) for v in existing_iocs.values())
        logger.info(f"[FIND_IOC] Searching with {existing_count} existing IOCs")
        
        # Search for events
        events = search_events_with_iocs(case_id, existing_iocs)
        
        if not events:
            return {
                'success': True,
                'potential_iocs': {},
                'events_searched': 0,
                'existing_ioc_count': existing_count,
                'message': 'No events found matching existing IOCs'
            }
        
        # Extract potential IOCs
        potential_iocs = extract_iocs_from_events(events, context)
        
        # Convert sets to lists for JSON
        result_iocs = {}
        total_found = 0
        for ioc_type, values in potential_iocs.items():
            if values:
                result_iocs[ioc_type] = sorted(list(values))[:100]  # Limit per type
                total_found += len(values)
        
        logger.info(f"[FIND_IOC] Completed: {total_found} potential IOCs from {len(events)} events")
        
        return {
            'success': True,
            'potential_iocs': result_iocs,
            'events_searched': len(events),
            'existing_ioc_count': existing_count,
            'total_found': total_found
        }
        
    except Exception as e:
        logger.error(f"[FIND_IOC] Failed: {e}", exc_info=True)
        return {
            'success': False,
            'error': str(e),
            'potential_iocs': {},
            'events_searched': 0,
            'existing_ioc_count': 0
        }


def get_ioc_discovery_summary(result: Dict) -> Dict:
    """Generate a summary for UI display."""
    summary = {
        'total_found': 0,
        'by_type': {},
        'events_searched': result.get('events_searched', 0),
        'existing_ioc_count': result.get('existing_ioc_count', 0)
    }
    
    potential = result.get('potential_iocs', {})
    for ioc_type, values in potential.items():
        count = len(values)
        if count > 0:
            summary['by_type'][ioc_type] = count
            summary['total_found'] += count
    
    return summary

