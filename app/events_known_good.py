"""
Known Good Events Module
========================

Identifies and hides events that match known-good patterns based on System Settings.

Usage:
    from events_known_good import hide_known_good_events
    
    # Hide known good events for a case
    result = hide_known_good_events(case_id=25)
    
    # Check if a single event is known-good
    from events_known_good import is_known_good_event
    if is_known_good_event(event_data, search_blob):
        # event matches known-good patterns

Author: CaseScope
Version: 1.0.0
"""

import logging
import ipaddress
import json
from typing import Dict, List, Optional, Any, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# CONFIGURATION LOADER
# =============================================================================

def load_exclusions() -> Dict:
    """
    Load exclusion patterns from SystemToolsSetting.
    
    Returns dict with:
        - rmm_executables: List of RMM executable patterns (e.g., "ltsvc.exe", "labtech*.exe")
        - remote_tools: List of dicts with {name, pattern, known_good_ids}
        - edr_tools: List of dicts with {name, executables, routine_commands, response_patterns, ...}
        - known_good_ips: List of IP/CIDR ranges
    """
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
                # RMM tools: comma-separated executable patterns
                patterns = [p.strip().lower() for p in s.executable_pattern.split(',') if p.strip()]
                exclusions['rmm_executables'].extend(patterns)
                
            elif s.setting_type == 'remote_tool':
                # Remote tools: pattern + list of known-good session IDs
                ids = json.loads(s.known_good_ids) if s.known_good_ids else []
                exclusions['remote_tools'].append({
                    'name': s.tool_name,
                    'pattern': (s.executable_pattern or '').lower(),
                    'known_good_ids': [i.lower() for i in ids if i]
                })
                
            elif s.setting_type == 'edr_tool':
                # EDR tools: executables + routine commands + response patterns
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
                # Known-good IPs: single IP or CIDR range
                exclusions['known_good_ips'].append(s.ip_or_cidr)
                
    except Exception as e:
        logger.warning(f"[KNOWN_GOOD] Error loading exclusions: {e}")
    
    return exclusions


# =============================================================================
# EXCLUSION CACHE (for bulk operations)
# =============================================================================

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
        _exclusions_cache = load_exclusions()
        _exclusions_cache_time = now
    elif now - _exclusions_cache_time > max_age_seconds:
        _exclusions_cache = load_exclusions()
        _exclusions_cache_time = now
    
    return _exclusions_cache


def clear_cache():
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


# =============================================================================
# SINGLE EVENT DETECTION
# =============================================================================

def is_known_good_event(event_data: Dict, search_blob: str, exclusions: Optional[Dict] = None) -> bool:
    """
    Check if an event matches known-good patterns.
    
    Args:
        event_data: The event document (OpenSearch _source or raw dict)
        search_blob: The flattened search_blob string
        exclusions: Pre-loaded exclusions (optional, will load if not provided)
    
    Returns:
        True if event is known-good and should be hidden, False otherwise
    
    Detection Logic:
        1. RMM: If executable pattern (with .exe context) in search_blob → KNOWN GOOD
        2. Remote: If tool pattern AND session ID both in search_blob → KNOWN GOOD
        3. EDR: If executable AND routine command in search_blob → KNOWN GOOD
               (unless response pattern also present → NOT KNOWN GOOD, keep it)
        4. IPs: If source IP matches known-good range → KNOWN GOOD
    """
    if exclusions is None:
        exclusions = get_cached_exclusions()
    
    blob = (search_blob or '').lower()
    
    # =========================================================================
    # CHECK 1: RMM Tools
    # =========================================================================
    # Match executable patterns. Wildcards require .exe context to avoid
    # matching URLs (e.g., "huntress" in "huntress.io")
    for rmm_pattern in exclusions.get('rmm_executables', []):
        if '*' in rmm_pattern:
            # Wildcard: "labtech*.exe" → need prefix + .exe in blob
            prefix = rmm_pattern.split('*')[0]
            if prefix and prefix in blob and '.exe' in blob:
                logger.debug(f"[KNOWN_GOOD] RMM match: {rmm_pattern}")
                return True
        else:
            # Exact: "ltsvc.exe" must be in blob
            if rmm_pattern in blob:
                logger.debug(f"[KNOWN_GOOD] RMM match: {rmm_pattern}")
                return True
    
    # =========================================================================
    # CHECK 2: Remote Tools (e.g., TeamViewer, AnyDesk)
    # =========================================================================
    # Must have BOTH the tool pattern AND a known-good session ID
    for tool_config in exclusions.get('remote_tools', []):
        pattern = tool_config.get('pattern', '')
        if pattern and pattern in blob:
            for known_id in tool_config.get('known_good_ids', []):
                if known_id and known_id in blob:
                    logger.debug(f"[KNOWN_GOOD] Remote tool match: {tool_config['name']} + {known_id}")
                    return True
    
    # =========================================================================
    # CHECK 3: EDR Tools (e.g., Huntress, CrowdStrike, SentinelOne)
    # =========================================================================
    # Hide routine health checks, KEEP response/isolation actions
    for edr_config in exclusions.get('edr_tools', []):
        edr_executables = edr_config.get('executables', [])
        
        # Check if EDR executable (with .exe context) is in blob
        edr_in_blob = False
        matched_exe = None
        for exe in edr_executables:
            if '*' in exe:
                prefix = exe.split('*')[0]
                if prefix and prefix in blob and '.exe' in blob:
                    edr_in_blob = True
                    matched_exe = exe
                    break
            else:
                if exe in blob:
                    edr_in_blob = True
                    matched_exe = exe
                    break
        
        if edr_in_blob:
            # Check for response action - DON'T hide these (attacker activity!)
            if edr_config.get('keep_responses', True):
                response_patterns = edr_config.get('response_patterns', [])
                if any(pattern in blob for pattern in response_patterns if pattern):
                    logger.debug(f"[KNOWN_GOOD] EDR response action, keeping: {matched_exe}")
                    continue  # Don't hide, check other rules
            
            # Check for routine command - HIDE
            if edr_config.get('exclude_routine', True):
                routine_commands = edr_config.get('routine_commands', [])
                for routine in routine_commands:
                    # Routine must be present as .exe to avoid partial matches
                    if routine and f"{routine}.exe" in blob:
                        logger.debug(f"[KNOWN_GOOD] EDR routine: {matched_exe} + {routine}.exe")
                        return True
    
    # =========================================================================
    # CHECK 4: Known-Good Source IPs
    # =========================================================================
    source_ip = _extract_source_ip(event_data)
    if source_ip:
        for ip_range in exclusions.get('known_good_ips', []):
            try:
                ip_obj = ipaddress.ip_address(source_ip)
                if '/' in ip_range:
                    network = ipaddress.ip_network(ip_range, strict=False)
                    if ip_obj in network:
                        logger.debug(f"[KNOWN_GOOD] Known-good IP: {source_ip} in {ip_range}")
                        return True
                else:
                    if ip_obj == ipaddress.ip_address(ip_range):
                        logger.debug(f"[KNOWN_GOOD] Known-good IP: {source_ip}")
                        return True
            except ValueError:
                pass  # Invalid IP format
    
    return False


def _extract_source_ip(event_data: Dict) -> Optional[str]:
    """Extract source IP from various event field locations."""
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


# =============================================================================
# BULK HIDE OPERATION
# =============================================================================

def hide_known_good_events(
    case_id: int,
    progress_callback: Optional[callable] = None
) -> Dict[str, Any]:
    """
    Find and hide all known-good events in a case.
    
    Args:
        case_id: The case ID to process
        progress_callback: Optional callback function(status, processed, total, found)
    
    Returns:
        Dict with:
            - success: bool
            - total_scanned: int
            - total_hidden: int
            - errors: list
    """
    from file_processing import get_opensearch_client
    
    result = {
        'success': False,
        'total_scanned': 0,
        'total_hidden': 0,
        'errors': []
    }
    
    # Load exclusions
    exclusions = load_exclusions()
    if not has_exclusions_configured():
        logger.info(f"[KNOWN_GOOD] No exclusions configured, skipping case {case_id}")
        result['success'] = True
        return result
    
    logger.info(f"[KNOWN_GOOD] Starting hide operation for case {case_id}")
    
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
        "_source": ["search_blob", "source", "host", "process", "is_hidden"],
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
    
    logger.info(f"[KNOWN_GOOD] Scanning {total_to_scan:,} events in case {case_id}")
    
    # Scan all events
    while hits:
        for hit in hits:
            src = hit.get('_source', {})
            search_blob = src.get('search_blob', '')
            processed_count += 1
            
            if is_known_good_event(src, search_blob, exclusions):
                events_to_hide.append({
                    '_id': hit['_id'],
                    '_index': hit['_index']
                })
        
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
        
        logger.info(f"[KNOWN_GOOD] Hiding {total_to_hide:,} known-good events")
        
        for i in range(0, total_to_hide, bulk_batch_size):
            batch = events_to_hide[i:i + bulk_batch_size]
            
            if progress_callback:
                progress_callback('hiding', hidden_count, total_to_hide, total_to_hide)
            
            bulk_body = []
            for evt in batch:
                bulk_body.append({"update": {"_id": evt['_id'], "_index": evt['_index']}})
                bulk_body.append({"doc": {"is_hidden": True}})
            
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
                result['errors'].append(f"Bulk update failed: {e}")
        
        # Final refresh
        try:
            opensearch_client.indices.refresh(index=index_name)
        except:
            pass
        
        result['total_hidden'] = hidden_count
        logger.info(f"[KNOWN_GOOD] Hid {hidden_count:,} events in case {case_id}")
    else:
        logger.info(f"[KNOWN_GOOD] No known-good events found in case {case_id}")
    
    result['success'] = True
    return result


# =============================================================================
# UNHIDE OPERATION
# =============================================================================

def unhide_all_events(case_id: int) -> Dict[str, Any]:
    """
    Unhide all hidden events in a case (reset is_hidden to False).
    
    Args:
        case_id: The case ID to process
    
    Returns:
        Dict with success, total_unhidden, errors
    """
    from file_processing import get_opensearch_client
    
    result = {
        'success': False,
        'total_unhidden': 0,
        'errors': []
    }
    
    opensearch_client = get_opensearch_client()
    if not opensearch_client:
        result['errors'].append("OpenSearch not available")
        return result
    
    index_name = f"case_{case_id}"
    
    try:
        # Update by query - set is_hidden=False for all hidden events
        update_result = opensearch_client.update_by_query(
            index=index_name,
            body={
                "script": {
                    "source": "ctx._source.is_hidden = false",
                    "lang": "painless"
                },
                "query": {
                    "term": {"is_hidden": True}
                }
            },
            refresh=True
        )
        
        result['total_unhidden'] = update_result.get('updated', 0)
        result['success'] = True
        logger.info(f"[KNOWN_GOOD] Unhid {result['total_unhidden']:,} events in case {case_id}")
        
    except Exception as e:
        result['errors'].append(f"Unhide failed: {e}")
    
    return result


# =============================================================================
# SINGLE EVENT HIDE/UNHIDE
# =============================================================================

def hide_event(case_id: int, event_id: str) -> bool:
    """Hide a single event by ID."""
    from file_processing import get_opensearch_client
    
    opensearch_client = get_opensearch_client()
    if not opensearch_client:
        return False
    
    try:
        opensearch_client.update(
            index=f"case_{case_id}",
            id=event_id,
            body={"doc": {"is_hidden": True}},
            refresh=True
        )
        return True
    except Exception as e:
        logger.error(f"[KNOWN_GOOD] Failed to hide event {event_id}: {e}")
        return False


def unhide_event(case_id: int, event_id: str) -> bool:
    """Unhide a single event by ID."""
    from file_processing import get_opensearch_client
    
    opensearch_client = get_opensearch_client()
    if not opensearch_client:
        return False
    
    try:
        opensearch_client.update(
            index=f"case_{case_id}",
            id=event_id,
            body={"doc": {"is_hidden": False}},
            refresh=True
        )
        return True
    except Exception as e:
        logger.error(f"[KNOWN_GOOD] Failed to unhide event {event_id}: {e}")
        return False


# =============================================================================
# STATISTICS
# =============================================================================

def get_hidden_count(case_id: int) -> int:
    """Get the count of hidden events in a case."""
    from file_processing import get_opensearch_client
    
    opensearch_client = get_opensearch_client()
    if not opensearch_client:
        return 0
    
    try:
        result = opensearch_client.count(
            index=f"case_{case_id}",
            body={
                "query": {
                    "term": {"is_hidden": True}
                }
            }
        )
        return result.get('count', 0)
    except:
        return 0


def get_visible_count(case_id: int) -> int:
    """Get the count of visible (non-hidden) events in a case."""
    from file_processing import get_opensearch_client
    
    opensearch_client = get_opensearch_client()
    if not opensearch_client:
        return 0
    
    try:
        result = opensearch_client.count(
            index=f"case_{case_id}",
            body={
                "query": {
                    "bool": {
                        "must_not": [
                            {"term": {"is_hidden": True}}
                        ]
                    }
                }
            }
        )
        return result.get('count', 0)
    except:
        return 0

