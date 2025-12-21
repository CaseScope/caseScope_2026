"""
Auto-Hide Known Good Events Module (v1.43.17)

Modular functions to check if events should be auto-hidden during indexing.
Used by file_processing.py for: initial index, reindex, bulk reindex, select reindex.

This keeps the auto-hide logic in one place for easy maintenance.
"""

import logging
import ipaddress
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


def load_exclusions_for_auto_hide() -> Dict:
    """
    Load exclusion patterns from SystemToolsSetting.
    Returns dict with: rmm_executables, remote_tools, edr_tools, known_good_ips
    
    Cached for performance during bulk operations.
    """
    import json
    from models import SystemToolsSetting, db
    
    exclusions = {
        'rmm_executables': [],
        'remote_tools': [],
        'edr_tools': [],
        'known_good_ips': []
    }
    
    try:
        settings = SystemToolsSetting.query.filter_by(is_active=True).all()
        
        for s in settings:
            if s.setting_type == 'rmm_tool' and s.executable_pattern:
                patterns = [p.strip().lower() for p in s.executable_pattern.split(',') if p.strip()]
                exclusions['rmm_executables'].extend(patterns)
                
            elif s.setting_type == 'remote_tool':
                ids = json.loads(s.known_good_ids) if s.known_good_ids else []
                exclusions['remote_tools'].append({
                    'name': s.tool_name,
                    'pattern': (s.executable_pattern or '').lower(),
                    'known_good_ids': [i.lower() for i in ids if i]
                })
                
            elif s.setting_type == 'edr_tool':
                routines = json.loads(s.routine_commands) if s.routine_commands else []
                responses = json.loads(s.response_patterns) if s.response_patterns else []
                executables = [p.strip().lower() for p in (s.executable_pattern or '').split(',') if p.strip()]
                exclusions['edr_tools'].append({
                    'name': s.tool_name,
                    'executables': executables,
                    'exclude_routine': s.exclude_routine if s.exclude_routine is not None else True,
                    'keep_responses': s.keep_responses if s.keep_responses is not None else True,
                    'routine_commands': [r.lower() for r in routines if r],
                    'response_patterns': [r.lower() for r in responses if r]
                })
                
            elif s.setting_type == 'known_good_ip' and s.ip_or_cidr:
                exclusions['known_good_ips'].append(s.ip_or_cidr)
                
    except Exception as e:
        logger.warning(f"[AUTO_HIDE] Error loading exclusions: {e}")
    
    return exclusions


def should_auto_hide_event(event_data: Dict, search_blob: str, exclusions: Dict) -> bool:
    """
    Check if an event should be auto-hidden based on exclusion rules.
    
    Args:
        event_data: The event document being indexed
        search_blob: The flattened search_blob string (lowercase)
        exclusions: Pre-loaded exclusions dict from load_exclusions_for_auto_hide()
    
    Returns:
        True if event should be hidden, False otherwise
    
    Logic (v1.43.16 - requires .exe context to avoid URL matches):
    1. RMM: If executable pattern (with .exe) in search_blob → HIDE
    2. Remote: If tool pattern AND session ID both in search_blob → HIDE
    3. EDR: If executable (with .exe) AND routine command in search_blob → HIDE
           (unless response pattern also present → KEEP)
    4. IPs: If source IP matches known-good range → HIDE
    """
    blob = search_blob.lower() if search_blob else ''
    
    # =========================================================================
    # CHECK 1: RMM Tool - Executable pattern in search_blob
    # =========================================================================
    for rmm_pattern in exclusions.get('rmm_executables', []):
        if '*' in rmm_pattern:
            prefix = rmm_pattern.split('*')[0]
            if prefix and f"{prefix}" in blob and '.exe' in blob:
                return True
        else:
            if rmm_pattern in blob:
                return True
    
    # =========================================================================
    # CHECK 2: Remote Tool - Tool pattern AND session ID both in search_blob
    # =========================================================================
    for tool_config in exclusions.get('remote_tools', []):
        pattern = tool_config.get('pattern', '')
        if pattern and pattern in blob:
            for known_id in tool_config.get('known_good_ids', []):
                if known_id and known_id in blob:
                    return True
    
    # =========================================================================
    # CHECK 3: EDR Tool - Context-aware exclusion
    # =========================================================================
    for edr_config in exclusions.get('edr_tools', []):
        edr_executables = edr_config.get('executables', [])
        
        # Check if EDR executable (must have .exe context) is in blob
        edr_in_blob = False
        for exe in edr_executables:
            if '*' in exe:
                prefix = exe.split('*')[0]
                if prefix and f"{prefix}" in blob and '.exe' in blob:
                    edr_in_blob = True
                    break
            else:
                if exe in blob:
                    edr_in_blob = True
                    break
        
        if edr_in_blob:
            # Check for response action - DON'T hide these
            if edr_config.get('keep_responses', True):
                response_patterns = edr_config.get('response_patterns', [])
                if any(pattern in blob for pattern in response_patterns if pattern):
                    continue
            
            # Check for routine command - HIDE
            if edr_config.get('exclude_routine', True):
                routine_commands = edr_config.get('routine_commands', [])
                for routine in routine_commands:
                    if routine and f"{routine}.exe" in blob:
                        return True
    
    # =========================================================================
    # CHECK 4: Source IP is in known-good range
    # =========================================================================
    source_ip = _extract_source_ip(event_data)
    if source_ip:
        for ip_range in exclusions.get('known_good_ips', []):
            try:
                ip_obj = ipaddress.ip_address(source_ip)
                if '/' in ip_range:
                    network = ipaddress.ip_network(ip_range, strict=False)
                    if ip_obj in network:
                        return True
                else:
                    if ip_obj == ipaddress.ip_address(ip_range):
                        return True
            except:
                pass
    
    return False


def _extract_source_ip(event_data: Dict) -> Optional[str]:
    """Extract source IP from event data."""
    proc = event_data.get('process', {})
    
    source_ip = None
    if event_data.get('source', {}).get('ip'):
        source_ip = event_data['source']['ip']
    elif event_data.get('host', {}).get('ip'):
        source_ip = event_data['host']['ip']
    elif proc.get('user_logon', {}).get('ip'):
        source_ip = proc['user_logon']['ip']
    
    if isinstance(source_ip, list):
        source_ip = source_ip[0] if source_ip else None
    
    return source_ip


# Cache for exclusions during bulk operations
_exclusions_cache = None
_exclusions_cache_time = None


def get_cached_exclusions(max_age_seconds: int = 60) -> Dict:
    """
    Get exclusions with caching for bulk operations.
    Cache expires after max_age_seconds.
    """
    import time
    global _exclusions_cache, _exclusions_cache_time
    
    now = time.time()
    
    if _exclusions_cache is None or _exclusions_cache_time is None:
        _exclusions_cache = load_exclusions_for_auto_hide()
        _exclusions_cache_time = now
    elif now - _exclusions_cache_time > max_age_seconds:
        _exclusions_cache = load_exclusions_for_auto_hide()
        _exclusions_cache_time = now
    
    return _exclusions_cache


def clear_exclusions_cache():
    """Clear the exclusions cache (call after settings change)."""
    global _exclusions_cache, _exclusions_cache_time
    _exclusions_cache = None
    _exclusions_cache_time = None


def has_exclusions_configured() -> bool:
    """Check if any exclusions are configured."""
    exclusions = get_cached_exclusions()
    return any([
        exclusions.get('rmm_executables'),
        exclusions.get('remote_tools'),
        exclusions.get('edr_tools'),
        exclusions.get('known_good_ips')
    ])

