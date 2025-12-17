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
        'rmm_paths': [],  # List of RMM installation paths
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
                
                # RMM paths: Add installation path if specified
                if s.rmm_path:
                    path = s.rmm_path.strip().lower()
                    if path:
                        exclusions['rmm_paths'].append(path)
                
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

def is_known_good_event(event_data: Dict, search_blob: str, exclusions: Optional[Dict] = None) -> tuple:
    """
    Check if an event matches known-good patterns.
    
    Args:
        event_data: The event document (OpenSearch _source or raw dict)
        search_blob: The flattened search_blob string
        exclusions: Pre-loaded exclusions (optional, will load if not provided)
    
    Returns:
        Tuple of (is_match: bool, category: str, reason: str)
        - is_match: True if event is known-good and should be hidden
        - category: 'RMM', 'EDR', 'REMOTE', 'IP', or None
        - reason: Detailed description (e.g., "ConnectWise Automate (ltsvc.exe)")
    
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
    rmm_patterns = exclusions.get('rmm_executables', [])
    
    # DEBUG: Log first time we see exclusions
    if rmm_patterns and not hasattr(is_known_good_event, '_logged_exclusions'):
        logger.info(f"[KNOWN_GOOD] DEBUG: Loaded {len(rmm_patterns)} RMM patterns: {rmm_patterns[:5]}")
        logger.info(f"[KNOWN_GOOD] DEBUG: Loaded {len(exclusions.get('edr_tools', []))} EDR tools")
        logger.info(f"[KNOWN_GOOD] DEBUG: Loaded {len(exclusions.get('remote_tools', []))} Remote tools")
        is_known_good_event._logged_exclusions = True
    
    # =========================================================================
    # CHECK 1: RMM Tools - EXE or PATH
    # =========================================================================
    # Simple: If ANY RMM pattern is in search_blob → noise
    # This catches:
    #   - LTSVC.exe running
    #   - net.exe stop LTService
    #   - Processes with parent LTSVC.exe
    #   - Any path containing c:\windows\ltsvc
    for rmm_pattern in rmm_patterns:
        # Remove wildcard and .exe for simple matching
        search_term = rmm_pattern.replace('*', '').replace('.exe', '').strip().lower()
        if search_term and len(search_term) >= 3:  # Avoid false positives from short terms
            if search_term in blob:
                tool_name = _get_rmm_tool_name(rmm_pattern, exclusions)
                logger.info(f"[KNOWN_GOOD] RMM match: {rmm_pattern} (search_term: {search_term})")
                return (True, 'RMM', f'{tool_name} ({rmm_pattern})')
    
    # Check configured RMM paths from database
    for rmm_path in exclusions.get('rmm_paths', []):
        if rmm_path and rmm_path.lower().strip() in blob:
            tool_name = _get_rmm_tool_name_by_path(rmm_path, exclusions)
            logger.info(f"[KNOWN_GOOD] RMM PATH match: {rmm_path}")
            return (True, 'RMM', f'{tool_name} (path: {rmm_path})')
    
    # =========================================================================
    # CHECK 2: Remote Tools - EXE + ID
    # =========================================================================
    # Simple: If remote tool pattern AND ID both in search_blob → noise
    for tool_config in exclusions.get('remote_tools', []):
        pattern = tool_config.get('pattern', '').lower().strip()
        if pattern and pattern in blob:
            for known_id in tool_config.get('known_good_ids', []):
                known_id_lower = str(known_id).lower().strip()
                if known_id_lower and known_id_lower in blob:
                    logger.info(f"[KNOWN_GOOD] Remote tool match: {tool_config['name']} + {known_id}")
                    return (True, 'REMOTE', f"{tool_config['name']} ({pattern} + ID)")
    
    # =========================================================================
    # CHECK 3: EDR Tools - EXE + Routine Keyword
    # =========================================================================
    # Simple: If EDR pattern + routine keyword in search_blob → noise
    # UNLESS response pattern also present (keep those!)
    for edr_config in exclusions.get('edr_tools', []):
        edr_executables = edr_config.get('executables', [])
        
        # Check if ANY EDR executable pattern is in blob
        edr_in_blob = False
        matched_exe = None
        for exe in edr_executables:
            search_term = exe.replace('*', '').replace('.exe', '').strip().lower()
            if search_term and len(search_term) >= 3 and search_term in blob:
                    edr_in_blob = True
                    matched_exe = exe
                    break
        
        if edr_in_blob:
            # Check for response action - DON'T mark as noise (attacker activity!)
            if edr_config.get('keep_responses', True):
                response_patterns = edr_config.get('response_patterns', [])
                if any(str(pattern).lower().strip() in blob for pattern in response_patterns if pattern):
                    logger.debug(f"[KNOWN_GOOD] EDR response action, keeping: {matched_exe}")
                    continue  # Don't mark as noise, check other rules
            
            # Check for routine command - MARK AS NOISE
            if edr_config.get('exclude_routine', True):
                routine_commands = edr_config.get('routine_commands', [])
                for routine in routine_commands:
                    routine_lower = str(routine).lower().strip()
                    if routine_lower and routine_lower in blob:
                        logger.info(f"[KNOWN_GOOD] EDR routine match: exe={matched_exe}, keyword={routine}")
                        return (True, 'EDR', f"{edr_config['name']} ({matched_exe} + routine)")
    
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
                        return (True, 'IP', f'Known-good IP ({source_ip})')
                else:
                    if ip_obj == ipaddress.ip_address(ip_range):
                        logger.debug(f"[KNOWN_GOOD] Known-good IP: {source_ip}")
                        return (True, 'IP', f'Known-good IP ({source_ip})')
            except ValueError:
                pass  # Invalid IP format
    
    return (False, None, None)


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


def _get_rmm_tool_name(exe_pattern: str, exclusions: Dict) -> str:
    """Get the tool name for an RMM executable pattern."""
    from models import SystemToolsSetting
    try:
        setting = SystemToolsSetting.query.filter(
            SystemToolsSetting.setting_type == 'rmm_tool',
            SystemToolsSetting.executable_pattern.ilike(f'%{exe_pattern}%')
        ).first()
        return setting.tool_name if setting else 'RMM Tool'
    except:
        return 'RMM Tool'


def _get_rmm_tool_name_by_path(rmm_path: str, exclusions: Dict) -> str:
    """Get the tool name for an RMM path."""
    from models import SystemToolsSetting
    try:
        setting = SystemToolsSetting.query.filter(
            SystemToolsSetting.setting_type == 'rmm_tool',
            SystemToolsSetting.rmm_path.ilike(f'%{rmm_path}%')
        ).first()
        return setting.tool_name if setting else 'RMM Tool'
    except:
        return 'RMM Tool'



# =============================================================================
# SLICED PROCESSING (for parallel workers)
# =============================================================================

def process_slice(
    case_id: int,
    slice_id: int,
    max_slices: int,
    exclusions: Dict,
    opensearch_client,
    celery_task=None,
    total_events_estimate: int = 0
) -> Tuple[int, List[Dict]]:
    """
    Process a single slice of events for parallel hide operation.
    
    Uses OpenSearch's sliced scroll to divide work among multiple workers.
    Each worker processes 1/max_slices of the total events.
    
    Args:
        case_id: The case ID to process
        slice_id: This worker's slice ID (0 to max_slices-1)
        max_slices: Total number of slices (usually 8 for 8 workers)
        exclusions: Pre-loaded exclusions dict from load_exclusions()
        opensearch_client: OpenSearch client instance
        celery_task: Celery task instance for progress reporting (optional)
        total_events_estimate: Estimated total events for this slice (for progress %)
    
    Returns:
        Tuple of (events_scanned, events_to_hide_list)
        events_to_hide_list contains dicts with {_id, _index}
    """
    index_name = f"case_{case_id}"
    events_to_hide = []
    scanned_count = 0
    
    scroll_time = '5m'
    batch_size = 1000
    progress_report_interval = 10000  # Report progress every 10K events
    
    # Sliced scroll query - each slice gets 1/N of events
    # Exclude events that already have status='noise' to avoid re-processing
    # ALSO exclude 'confirmed' - analyst-confirmed events are IMMUTABLE
    # NOTE: 'hunted' is NOT excluded - it's automatic and may be wrong, noise filters can override it
    query = {
        "size": batch_size,
        "slice": {
            "id": slice_id,
            "max": max_slices
        },
        "_source": ["search_blob", "source", "host", "process"],
        "query": {
            "bool": {
                "must_not": [
                    {"term": {"event_status": "noise"}},
                    {"term": {"event_status": "confirmed"}}
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
        logger.error(f"[KNOWN_GOOD] Slice {slice_id}: Search failed - {e}")
        return (0, [])
    
    scroll_id = response.get('_scroll_id')
    hits = response['hits']['hits']
    
    logger.info(f"[KNOWN_GOOD] Slice {slice_id}/{max_slices}: Starting scan")
    
    # Process all events in this slice
    last_progress_report = 0
    while hits:
        for hit in hits:
            src = hit.get('_source', {})
            search_blob = src.get('search_blob', '')
            scanned_count += 1
            
            is_match, category, reason = is_known_good_event(src, search_blob, exclusions)
            if is_match:
                events_to_hide.append({
                    '_id': hit['_id'],
                    '_index': hit['_index'],
                    'noise_type': category,
                    'noise_reason': reason
                })
            
            # Report progress periodically
            if celery_task and scanned_count - last_progress_report >= progress_report_interval:
                celery_task.update_state(
                    state='PROGRESS',
                    meta={
                        'slice_id': slice_id,
                        'current': scanned_count,
                        'total': total_events_estimate if total_events_estimate > 0 else scanned_count,
                        'found': len(events_to_hide)
                    }
                )
                last_progress_report = scanned_count
        
        # Get next batch
        try:
            response = opensearch_client.scroll(scroll_id=scroll_id, scroll=scroll_time)
            scroll_id = response.get('_scroll_id')
            hits = response['hits']['hits']
        except Exception as e:
            logger.error(f"[KNOWN_GOOD] Slice {slice_id}: Scroll failed - {e}")
            break
    
    # Clear scroll
    try:
        if scroll_id:
            opensearch_client.clear_scroll(scroll_id=scroll_id)
    except:
        pass
    
    logger.info(f"[KNOWN_GOOD] Slice {slice_id}/{max_slices}: Scanned {scanned_count:,}, found {len(events_to_hide):,} to hide")
    
    return (scanned_count, events_to_hide)


def bulk_hide_events(
    events_to_hide: List[Dict],
    opensearch_client,
    index_name: str,
    case_id: int = None
) -> int:
    """
    Bulk update event status to 'noise' for known-good events.
    Now includes noise_type and noise_reason fields in OpenSearch.
    
    Args:
        events_to_hide: List of dicts with {_id, _index, noise_type, noise_reason}
        opensearch_client: OpenSearch client instance
        index_name: Index name (used to extract case_id if not provided)
        case_id: Case ID for status updates (optional, extracted from index_name if not provided)
    
    Returns:
        Number of events successfully marked as noise
    """
    if not events_to_hide:
        return 0
    
    # Extract case_id from index_name if not provided
    if case_id is None and index_name and index_name.startswith('case_'):
        try:
            case_id = int(index_name.split('_')[1])
        except (IndexError, ValueError):
            pass
    
    if not case_id:
        logger.error("[KNOWN_GOOD] Cannot set event status without case_id")
        return 0
    
    marked_count = 0
    bulk_batch_size = 500
    
    # Update OpenSearch with noise_type and noise_reason
    for i in range(0, len(events_to_hide), bulk_batch_size):
        batch = events_to_hide[i:i + bulk_batch_size]
        
        # Build bulk update for OpenSearch
        bulk_body = []
        for evt in batch:
            bulk_body.append({"update": {"_id": evt['_id'], "_index": evt['_index']}})
            bulk_body.append({
                "doc": {
                    "event_status": "noise",
                    "noise_type": evt.get('noise_type', 'UNKNOWN'),
                    "noise_reason": evt.get('noise_reason', 'Known-good pattern')
                }
            })
        
        try:
            from main import opensearch_client as os_client
            bulk_result = os_client.bulk(body=bulk_body, refresh=False)
            
            if not bulk_result.get('errors'):
                marked_count += len(batch)
            else:
                # Count successful updates
                for item in bulk_result.get('items', []):
                    if item.get('update', {}).get('status') in [200, 201]:
                        marked_count += 1
        except Exception as e:
            logger.error(f"[KNOWN_GOOD] OpenSearch bulk update failed: {e}")
        
        # Update database EventStatus to 'noise'
        try:
            from event_status import bulk_set_status, STATUS_NOISE
            event_ids = [evt['_id'] for evt in batch]
            notes = f"Auto-marked as known-good: {batch[0].get('noise_type', 'UNKNOWN')}"
            bulk_set_status(case_id, event_ids, STATUS_NOISE, user_id=None, notes=notes)
            logger.info(f"[KNOWN_GOOD] Marked {len(event_ids)} events as noise (batch {i // bulk_batch_size + 1})")
        except Exception as e:
            logger.error(f"[KNOWN_GOOD] Failed to update EventStatus for batch: {e}")
    
    return marked_count


# =============================================================================
# LEGACY FUNCTION - NOT USED (kept for backward compatibility with old tasks.py)
# =============================================================================
# The system now uses process_slice_worker() + bulk_hide_events() via coordinator
# This function is only called from deprecated tasks.py code

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
    from main import opensearch_client
    
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
    
    # opensearch_client is already imported above
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
        "_source": ["search_blob", "source", "host", "process", "event_status"],
        "query": {
            "bool": {
                "must_not": [
                    {"term": {"event_status": "noise"}}
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
            
            is_match, category, reason = is_known_good_event(src, search_blob, exclusions)
            if is_match:
                events_to_hide.append({
                    '_id': hit['_id'],
                    '_index': hit['_index'],
                    'noise_type': category,
                    'noise_reason': reason
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
            
            # Update OpenSearch documents to set event_status='noise'
            bulk_body = []
            for evt in batch:
                bulk_body.append({"update": {"_id": evt['_id'], "_index": evt['_index']}})
                bulk_body.append({"doc": {"event_status": "noise", "status_reason": "auto_known_good"}})
            
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
            
            # Update database EventStatus to 'noise'
            try:
                from event_status import bulk_set_status, STATUS_NOISE
                event_ids = [evt['_id'] for evt in batch]
                bulk_set_status(case_id, event_ids, STATUS_NOISE, user_id=None, notes="Auto-marked as known-good")
            except Exception as e:
                logger.warning(f"[KNOWN_GOOD] Failed to update EventStatus for batch: {e}")

        
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
    Reset all noise events back to 'new' status in a case.
    
    Args:
        case_id: The case ID to process
    
    Returns:
        Dict with success, total_unhidden, errors
    """
    from main import opensearch_client
    
    result = {
        'success': False,
        'total_unhidden': 0,
        'errors': []
    }
    
    opensearch_client = opensearch_client  # Use the imported client
    if not opensearch_client:
        result['errors'].append("OpenSearch not available")
        return result
    
    index_name = f"case_{case_id}"
    
    try:
        # Update by query - set event_status='new' for all noise events
        update_result = opensearch_client.update_by_query(
            index=index_name,
            body={
                "script": {
                    "source": "ctx._source.event_status = 'new'; ctx._source.status_reason = '';",
                    "lang": "painless"
                },
                "query": {
                    "term": {"event_status": "noise"}
                }
            },
            refresh=True
        )
        
        result['total_unhidden'] = update_result.get('updated', 0)
        result['success'] = True
        logger.info(f"[KNOWN_GOOD] Reset {result['total_unhidden']:,} events from noise to new in case {case_id}")
        
        # Update database EventStatus - delete all noise status records for this case
        try:
            from event_status import db, EventStatus
            deleted_count = EventStatus.query.filter_by(case_id=case_id, status='noise').delete()
            db.session.commit()
            logger.info(f"[KNOWN_GOOD] Deleted {deleted_count} noise EventStatus records from database")
        except Exception as e:
            logger.warning(f"[KNOWN_GOOD] Failed to delete EventStatus records: {e}")
        
    except Exception as e:
        result['errors'].append(f"Unhide failed: {e}")

    
    return result


# =============================================================================
# SINGLE EVENT HIDE/UNHIDE
# =============================================================================

def hide_event(case_id: int, event_id: str) -> bool:
    """Mark a single event as noise by ID."""
    from main import opensearch_client
    
    opensearch_client = opensearch_client  # Use the imported client
    if not opensearch_client:
        return False
    
    try:
        # Update OpenSearch document
        opensearch_client.update(
            index=f"case_{case_id}",
            id=event_id,
            body={"doc": {"event_status": "noise", "status_reason": "manual"}},
            refresh=True
        )
        
        # Update database EventStatus
        from event_status import bulk_set_status, STATUS_NOISE
        bulk_set_status(case_id, [event_id], STATUS_NOISE, user_id=None, notes="Manually marked as noise")
        
        return True
    except Exception as e:
        logger.error(f"[KNOWN_GOOD] Failed to mark event {event_id} as noise: {e}")
        return False


def unhide_event(case_id: int, event_id: str) -> bool:
    """Mark a single event as new (remove noise status) by ID."""
    from main import opensearch_client
    
    opensearch_client = opensearch_client  # Use the imported client
    if not opensearch_client:
        return False
    
    try:
        # Update OpenSearch document
        opensearch_client.update(
            index=f"case_{case_id}",
            id=event_id,
            body={"doc": {"event_status": "new", "status_reason": ""}},
            refresh=True
        )
        
        # Update database EventStatus
        from event_status import bulk_set_status, STATUS_NEW
        bulk_set_status(case_id, [event_id], STATUS_NEW, user_id=None, notes="Manually unmarked from noise")
        
        return True
    except Exception as e:
        logger.error(f"[KNOWN_GOOD] Failed to unmark event {event_id}: {e}")
        return False


# =============================================================================
# STATISTICS
# =============================================================================

def get_hidden_count(case_id: int) -> int:
    """Get the count of noise events in a case."""
    from main import opensearch_client
    
    opensearch_client = opensearch_client  # Use the imported client
    if not opensearch_client:
        return 0
    
    try:
        result = opensearch_client.count(
            index=f"case_{case_id}",
            body={
                "query": {
                    "term": {"event_status": "noise"}
                }
            }
        )
        return result.get('count', 0)
    except:
        return 0


def get_visible_count(case_id: int) -> int:
    """Get the count of non-noise events in a case."""
    from main import opensearch_client
    
    opensearch_client = opensearch_client  # Use the imported client
    if not opensearch_client:
        return 0
    
    try:
        result = opensearch_client.count(
            index=f"case_{case_id}",
            body={
                "query": {
                    "bool": {
                        "must_not": [
                            {"term": {"event_status": "noise"}}
                        ]
                    }
                }
            }
        )
        return result.get('count', 0)
    except:
        return 0


# =============================================================================
# CELERY TASKS: Parallel Processing (8 Workers)
# =============================================================================

from celery_app import celery_app


@celery_app.task(bind=True, name='events_known_good.hide_known_good_slice_task')
def hide_known_good_slice_task(self, case_id: int, slice_id: int, max_slices: int) -> Dict[str, Any]:
    """
    Celery worker task: Process 1/N slice of events for parallel hide operation.
    
    This task is one of N parallel workers (typically 8) that each process
    a slice of the total events using OpenSearch sliced scroll.
    
    Args:
        case_id: Case ID to process
        slice_id: This worker's slice ID (0 to max_slices-1)
        max_slices: Total number of slices (usually 8)
        
    Returns:
        dict: {
            'status': 'success'|'error',
            'slice_id': int,
            'scanned': int,
            'found': int,
            'hidden': int,
            'error': str (if error)
        }
    """
    from main import app, opensearch_client
    
    logger.info(f"[KNOWN_GOOD_SLICE] Slice {slice_id}/{max_slices} starting for case {case_id}")
    
    result = {
        'status': 'success',
        'slice_id': slice_id,
        'scanned': 0,
        'found': 0,
        'hidden': 0
    }
    
    with app.app_context():
        try:
            # Load exclusions once per worker
            exclusions = get_cached_exclusions()
            
            if not has_exclusions_configured():
                logger.info(f"[KNOWN_GOOD_SLICE] Slice {slice_id}: No exclusions configured")
                return result
            
            # Skip the count query - it's too slow for large datasets (18M+ events)
            # We'll report progress without knowing total upfront
            total_events_estimate = 0
            
            # Process this slice
            scanned, events_to_hide = process_slice(
                case_id=case_id,
                slice_id=slice_id,
                max_slices=max_slices,
                exclusions=exclusions,
                opensearch_client=opensearch_client,
                celery_task=self,  # Pass Celery task for progress reporting
                total_events_estimate=total_events_estimate
            )
            
            result['scanned'] = scanned
            result['found'] = len(events_to_hide)
            
            # Bulk hide events found in this slice
            if events_to_hide:
                index_name = f"case_{case_id}"
                hidden_count = bulk_hide_events(events_to_hide, opensearch_client, index_name, case_id)
                result['hidden'] = hidden_count
                logger.info(f"[KNOWN_GOOD_SLICE] Slice {slice_id}/{max_slices}: Hidden {hidden_count} events")
            
            logger.info(f"[KNOWN_GOOD_SLICE] Slice {slice_id}/{max_slices} complete: scanned={scanned}, found={len(events_to_hide)}, hidden={result['hidden']}")
            
        except Exception as e:
            logger.error(f"[KNOWN_GOOD_SLICE] Slice {slice_id}/{max_slices} error: {e}", exc_info=True)
            result['status'] = 'error'
            result['error'] = str(e)
    
    return result


@celery_app.task(bind=True, name='events_known_good.hide_known_good_all_task')
def hide_known_good_all_task(self, case_id: int) -> Dict[str, Any]:
    """
    Celery coordinator task: Dispatch parallel workers to hide known-good events.
    
    This task coordinates 8 parallel slice workers and waits for all to complete
    using database polling (not .get() to avoid deadlocks).
    
    Args:
        case_id: Case ID to process
        
    Returns:
        dict: {
            'status': 'success'|'error',
            'total_scanned': int,
            'total_hidden': int,
            'workers_completed': int,
            'workers_failed': int,
            'errors': list
        }
    """
    from main import app, db
    from celery import group
    import time
    
    MAX_SLICES = 8  # Use 8 parallel workers
    
    logger.info(f"[KNOWN_GOOD_COORDINATOR] Starting parallel hide for case {case_id} with {MAX_SLICES} workers")
    
    result = {
        'status': 'success',
        'total_scanned': 0,
        'total_hidden': 0,
        'workers_completed': 0,
        'workers_failed': 0,
        'errors': []
    }
    
    with app.app_context():
        try:
            # Check if exclusions are configured
            if not has_exclusions_configured():
                logger.info(f"[KNOWN_GOOD_COORDINATOR] No exclusions configured for case {case_id}")
                result['success'] = True
                return result
            
            # Dispatch 8 parallel slice tasks
            logger.info(f"[KNOWN_GOOD_COORDINATOR] Dispatching {MAX_SLICES} parallel workers...")
            
            job = group([
                hide_known_good_slice_task.s(case_id, i, MAX_SLICES)
                for i in range(MAX_SLICES)
            ])
            
            group_result = job.apply_async()
            
            # Poll for completion (database polling, not .get())
            logger.info(f"[KNOWN_GOOD_COORDINATOR] Waiting for {MAX_SLICES} workers to complete...")
            
            start_time = time.time()
            timeout = 3600  # 1 hour max
            poll_interval = 2  # Check every 2 seconds
            
            while not group_result.ready():
                elapsed = time.time() - start_time
                if elapsed > timeout:
                    logger.error(f"[KNOWN_GOOD_COORDINATOR] Timeout after {elapsed:.0f}s")
                    result['status'] = 'error'
                    result['errors'].append(f'Timeout after {elapsed:.0f}s')
                    return result
                
                # Collect per-worker progress
                worker_details = []
                total_current = 0
                total_estimate = 0
                
                for idx, async_result in enumerate(group_result.results):
                    if async_result.ready():
                        # Worker complete
                        worker_result = async_result.result
                        if isinstance(worker_result, dict):
                            worker_details.append({
                                'id': idx,
                                'current': worker_result.get('scanned', 0),
                                'total': worker_result.get('scanned', 0),
                                'found': worker_result.get('found', 0),
                                'done': True
                            })
                            total_current += worker_result.get('scanned', 0)
                            total_estimate += worker_result.get('scanned', 0)
                    else:
                        # Worker still running - get progress state
                        try:
                            state = async_result.state
                            info = async_result.info
                            
                            if state == 'PROGRESS' and isinstance(info, dict):
                                current = info.get('current', 0)
                                total = info.get('total', current)
                                found = info.get('found', 0)
                                
                                worker_details.append({
                                    'id': idx,
                                    'current': current,
                                    'total': total,
                                    'found': found,
                                    'done': False
                                })
                                total_current += current
                                total_estimate += total
                            else:
                                # Worker started but no progress yet
                                worker_details.append({
                                    'id': idx,
                                    'current': 0,
                                    'total': 0,
                                    'found': 0,
                                    'done': False
                                })
                        except Exception as e:
                            logger.debug(f"[KNOWN_GOOD_COORDINATOR] Could not get progress for worker {idx}: {e}")
                            worker_details.append({
                                'id': idx,
                                'current': 0,
                                'total': 0,
                                'found': 0,
                                'done': False
                            })
                
                # Count completed workers
                completed = sum(1 for r in group_result.results if r.ready())
                
                # Calculate overall progress
                # Since we don't pre-count events, use worker completion as progress
                overall_progress = int((completed / MAX_SLICES) * 100)
                
                logger.debug(f"[KNOWN_GOOD_COORDINATOR] Progress: {completed}/{MAX_SLICES} workers, {total_current:,} events processed")
                
                # Update progress for frontend with per-worker details
                self.update_state(
                    state='PROGRESS',
                    meta={
                        'status': 'processing',
                        'workers_completed': completed,
                        'workers_total': MAX_SLICES,
                        'total_events_processed': total_current,
                        'overall_progress': overall_progress,
                        'worker_details': worker_details,
                        'message': f'{completed}/{MAX_SLICES} workers completed'
                    }
                )
                
                time.sleep(poll_interval)
            
            # Collect results from all workers
            logger.info(f"[KNOWN_GOOD_COORDINATOR] All workers complete, collecting results...")
            
            # Use allow_join_result() to permit .get() within a Celery task
            from celery.result import allow_join_result
            try:
                with allow_join_result():
                    worker_results = group_result.get(timeout=60, propagate=False)
            except Exception as e:
                logger.error(f"[KNOWN_GOOD_COORDINATOR] Error collecting worker results: {e}")
                result['status'] = 'error'
                result['errors'].append(f"Failed to collect results: {str(e)}")
                return result
            
            # Process collected results
            for worker_data in worker_results:
                if worker_data and isinstance(worker_data, dict) and worker_data.get('status') == 'success':
                    result['workers_completed'] += 1
                    result['total_scanned'] += worker_data.get('scanned', 0)
                    result['total_hidden'] += worker_data.get('hidden', 0)
                else:
                    result['workers_failed'] += 1
                    error_msg = worker_data.get('error', 'Unknown error') if isinstance(worker_data, dict) else str(worker_data)
                    slice_id = worker_data.get('slice_id', '?') if isinstance(worker_data, dict) else '?'
                    result['errors'].append(f"Slice {slice_id}: {error_msg}")
                    logger.error(f"[KNOWN_GOOD_COORDINATOR] Worker failed: {error_msg}")
            
            # Final status
            if result['workers_failed'] > 0:
                result['status'] = 'partial'
            
            logger.info(f"[KNOWN_GOOD_COORDINATOR] Complete: {result['workers_completed']} workers succeeded, {result['workers_failed']} failed")
            logger.info(f"[KNOWN_GOOD_COORDINATOR] Scanned: {result['total_scanned']:,} events, Hidden: {result['total_hidden']:,} events")
            
        except Exception as e:
            logger.error(f"[KNOWN_GOOD_COORDINATOR] Fatal error: {e}", exc_info=True)
            result['status'] = 'error'
            result['errors'].append(str(e))
    
    return result


