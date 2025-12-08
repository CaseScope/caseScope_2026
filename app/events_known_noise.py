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
Version: 1.1.0 - Refactored to use centralized noise_filters.py
"""

import logging
import re
from typing import Dict, List, Optional, Any, Set

# Import from centralized noise filters module
from noise_filters import (
    # Constants
    NOISE_USERS,
    NOISE_PROCESSES,
    NOISE_IOC_VALUES,
    NOT_HOSTNAMES,
    NOISE_COMMAND_PATTERNS,
    GENERIC_PARENTS,
    # Functions
    is_noise_user,
    is_noise_process,
    is_noise_command,
    is_noise_ioc_value,
    is_noise_hostname,
    is_machine_account,
)

logger = logging.getLogger(__name__)


# =============================================================================
# MODULE-SPECIFIC CONSTANTS (not shared with other modules)
# =============================================================================

# Firewall/network noise keywords (specific to this module)
FIREWALL_NOISE_KEYWORDS = [
    'firewall', 'fw_', 'fw-', 'deny', 'drop', 'block', 'reject',
    'netflow', 'traffic', 'conn_state', 'action:deny', 'action:drop',
]


# =============================================================================
# DETECTION FUNCTIONS (using centralized noise_filters)
# =============================================================================

def is_noise_event(event_data: Dict) -> tuple:
    """
    Check if an event is known system noise.
    
    Args:
        event_data: The event document (OpenSearch _source or raw dict)
    
    Returns:
        Tuple of (is_match: bool, category: str, reason: str)
        - is_match: True if event is noise and should be hidden
        - category: 'NOISE_PROCESS', 'NOISE_COMMAND', 'FIREWALL', or None
        - reason: Detailed description
    
    Detection Logic:
        1. Process name is in NOISE_PROCESSES → NOISE_PROCESS
        2. Command line matches NOISE_COMMAND_PATTERNS → NOISE_COMMAND
        3. Firewall drop/deny logs → FIREWALL
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
        return (True, 'NOISE_PROCESS', f'System noise process ({proc_name})')
    
    # CHECK 2: Noise command pattern with generic parent
    if command_line and is_noise_command(command_line, parent_name):
        logger.debug(f"[NOISE] Command is noise: {command_line[:50]}...")
        return (True, 'NOISE_COMMAND', f'System noise command')
    
    # CHECK 3: Firewall noise
    if is_firewall_noise(event_data):
        return (True, 'FIREWALL', 'Firewall drop/deny log')
    
    return (False, None, None)


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
    # Exclude events that already have status='noise' to avoid re-processing
    # ALSO exclude 'confirmed' - analyst-confirmed events are IMMUTABLE
    # NOTE: 'hunted' is NOT excluded - it's automatic and may be wrong, noise filters can override it
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
            
            is_match, category, reason = is_noise_event(src)
            if is_match:
                events_to_hide.append({
                    '_id': hit['_id'],
                    '_index': hit['_index'],
                    'noise_type': category,
                    'noise_reason': reason
                })
                
                # Track category for stats
                if category == 'NOISE_PROCESS':
                    by_category['noise_process'] += 1
                elif category == 'NOISE_COMMAND':
                    by_category['noise_command'] += 1
                elif category == 'FIREWALL':
                    by_category['firewall_noise'] += 1
        
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
    index_name: str,
    case_id: int = None
) -> int:
    """
    Bulk update events to set event_status='noise' in both OpenSearch and database.
    Now includes noise_type and noise_reason fields.
    
    Args:
        events_to_hide: List of dicts with {_id, _index, noise_type, noise_reason}
        opensearch_client: OpenSearch client instance
        index_name: Index name for refresh
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
    
    hidden_count = 0
    bulk_batch_size = 500
    
    for i in range(0, len(events_to_hide), bulk_batch_size):
        batch = events_to_hide[i:i + bulk_batch_size]
        
        # Update OpenSearch with noise_type and noise_reason
        bulk_body = []
        for evt in batch:
            bulk_body.append({"update": {"_id": evt['_id'], "_index": evt['_index']}})
            bulk_body.append({"doc": {
                "event_status": "noise",
                "noise_type": evt.get('noise_type', 'UNKNOWN'),
                "noise_reason": evt.get('noise_reason', 'System noise')
            }})
        
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
        
        # Also update database EventStatus to 'noise'
        if case_id:
            try:
                from event_status import bulk_set_status, STATUS_NOISE
                event_ids = [evt['_id'] for evt in batch]
                notes = f"Auto-hidden as noise: {batch[0].get('noise_type', 'UNKNOWN')}"
                bulk_set_status(case_id, event_ids, STATUS_NOISE, user_id=None, notes=notes)
            except Exception as e:
                logger.warning(f"[NOISE] Failed to update EventStatus for batch: {e}")
    
    return hidden_count


# =============================================================================
# LEGACY FUNCTION - NOT USED (kept for backward compatibility with old tasks.py)
# =============================================================================
# The system now uses process_slice() + bulk_hide_events() via coordinator
# This function is only called from deprecated tasks.py code

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
    from main import opensearch_client
    
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
    opensearch_client = opensearch_client  # Use the imported client
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
        "_source": ["process", "search_blob", "event_status"],
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
    
    logger.info(f"[NOISE] Scanning {total_to_scan:,} events in case {case_id}")
    
    # Scan all events
    while hits:
        for hit in hits:
            src = hit.get('_source', {})
            processed_count += 1
            
            is_match, category, reason = is_noise_event(src)
            if is_match:
                events_to_hide.append({
                    '_id': hit['_id'],
                    '_index': hit['_index'],
                    'noise_type': category,
                    'noise_reason': reason
                })
                
                # Track stats
                if category == 'NOISE_PROCESS':
                    result['by_category']['noise_process'] += 1
                elif category == 'NOISE_COMMAND':
                    result['by_category']['noise_command'] += 1
                elif category == 'FIREWALL':
                    result['by_category']['firewall_noise'] += 1
        
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
            
            # Update OpenSearch event_status field
            bulk_body = []
            for evt in batch:
                bulk_body.append({"update": {"_id": evt['_id'], "_index": evt['_index']}})
                bulk_body.append({"doc": {
                    "event_status": "noise",
                    "status_reason": f"noise_{evt['category']}"
                }})
            
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
            
            # Update database EventStatus to 'noise'
            try:
                from event_status import bulk_set_status, STATUS_NOISE
                event_ids = [evt['_id'] for evt in batch]
                bulk_set_status(case_id, event_ids, STATUS_NOISE, user_id=None, notes="Auto-hidden as noise")
            except Exception as e:
                logger.warning(f"[NOISE] Failed to update EventStatus for batch: {e}")

        
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
    from main import opensearch_client
    
    result = {
        'noise_process': 0,
        'noise_command': 0,
        'firewall_noise': 0,
        'total': 0
    }
    
    opensearch_client = opensearch_client  # Use the imported client
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
                                {"term": {"event_status": "noise"}}
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
                            {"term": {"event_status": "noise"}}
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


# is_machine_account is imported from noise_filters


# =============================================================================
# CELERY TASKS: Parallel Processing (8 Workers)
# =============================================================================

from celery_app import celery_app


@celery_app.task(bind=True, name='events_known_noise.hide_noise_slice_task')
def hide_noise_slice_task(self, case_id: int, slice_id: int, max_slices: int) -> Dict[str, Any]:
    """
    Celery worker task: Process 1/N slice of events for parallel noise hide operation.
    
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
            'by_category': dict,
            'error': str (if error)
        }
    """
    from main import app, opensearch_client
    
    logger.info(f"[NOISE_SLICE] Slice {slice_id}/{max_slices} starting for case {case_id}")
    
    result = {
        'status': 'success',
        'slice_id': slice_id,
        'scanned': 0,
        'found': 0,
        'hidden': 0,
        'by_category': {
            'noise_process': 0,
            'noise_command': 0,
            'firewall_noise': 0
        }
    }
    
    with app.app_context():
        try:
            # Process this slice
            slice_result = process_slice(
                case_id=case_id,
                slice_id=slice_id,
                max_slices=max_slices,
                opensearch_client=opensearch_client
            )
            
            result['scanned'] = slice_result['scanned']
            result['found'] = len(slice_result['events_to_hide'])
            result['by_category'] = slice_result['by_category']
            
            # Bulk hide events found in this slice
            if slice_result['events_to_hide']:
                index_name = f"case_{case_id}"
                hidden_count = bulk_hide_events(
                    slice_result['events_to_hide'],
                    opensearch_client,
                    index_name,
                    case_id
                )
                result['hidden'] = hidden_count
                logger.info(f"[NOISE_SLICE] Slice {slice_id}/{max_slices}: Hidden {hidden_count} events")
            
            logger.info(f"[NOISE_SLICE] Slice {slice_id}/{max_slices} complete: scanned={result['scanned']}, found={result['found']}, hidden={result['hidden']}")
            logger.info(f"[NOISE_SLICE] Slice {slice_id}/{max_slices} breakdown: {result['by_category']}")
            
        except Exception as e:
            logger.error(f"[NOISE_SLICE] Slice {slice_id}/{max_slices} error: {e}", exc_info=True)
            result['status'] = 'error'
            result['error'] = str(e)
    
    return result


@celery_app.task(bind=True, name='events_known_noise.hide_noise_all_task')
def hide_noise_all_task(self, case_id: int) -> Dict[str, Any]:
    """
    Celery coordinator task: Dispatch parallel workers to hide noise events.
    
    This task coordinates 8 parallel slice workers and waits for all to complete
    using database polling (not .get() to avoid deadlocks).
    
    Args:
        case_id: Case ID to process
        
    Returns:
        dict: {
            'status': 'success'|'error',
            'total_scanned': int,
            'total_hidden': int,
            'by_category': dict,
            'workers_completed': int,
            'workers_failed': int,
            'errors': list
        }
    """
    from main import app, db
    from celery import group
    import time
    
    MAX_SLICES = 8  # Use 8 parallel workers
    
    logger.info(f"[NOISE_COORDINATOR] Starting parallel hide for case {case_id} with {MAX_SLICES} workers")
    
    result = {
        'status': 'success',
        'total_scanned': 0,
        'total_hidden': 0,
        'by_category': {
            'noise_process': 0,
            'noise_command': 0,
            'firewall_noise': 0
        },
        'workers_completed': 0,
        'workers_failed': 0,
        'errors': []
    }
    
    with app.app_context():
        try:
            # Dispatch 8 parallel slice tasks
            logger.info(f"[NOISE_COORDINATOR] Dispatching {MAX_SLICES} parallel workers...")
            
            job = group([
                hide_noise_slice_task.s(case_id, i, MAX_SLICES)
                for i in range(MAX_SLICES)
            ])
            
            group_result = job.apply_async()
            
            # Poll for completion (database polling, not .get())
            logger.info(f"[NOISE_COORDINATOR] Waiting for {MAX_SLICES} workers to complete...")
            
            start_time = time.time()
            timeout = 3600  # 1 hour max
            poll_interval = 2  # Check every 2 seconds
            
            while not group_result.ready():
                elapsed = time.time() - start_time
                if elapsed > timeout:
                    logger.error(f"[NOISE_COORDINATOR] Timeout after {elapsed:.0f}s")
                    result['status'] = 'error'
                    result['errors'].append(f'Timeout after {elapsed:.0f}s')
                    return result
                
                # Count completed workers
                completed = sum(1 for r in group_result.results if r.ready())
                logger.debug(f"[NOISE_COORDINATOR] Progress: {completed}/{MAX_SLICES} workers complete")
                
                # Update progress for frontend
                self.update_state(
                    state='PROGRESS',
                    meta={
                        'status': 'processing',
                        'workers_completed': completed,
                        'workers_total': MAX_SLICES,
                        'message': f'{completed}/{MAX_SLICES} workers completed'
                    }
                )
                
                time.sleep(poll_interval)
            
            # Collect results from all workers
            logger.info(f"[NOISE_COORDINATOR] All workers complete, collecting results...")
            
            # Use group_result.get() to collect all results at once (safe for GroupResult)
            try:
                worker_results = group_result.get(timeout=60, propagate=False)
            except Exception as e:
                logger.error(f"[NOISE_COORDINATOR] Error collecting worker results: {e}")
                result['status'] = 'error'
                result['errors'].append(f"Failed to collect results: {str(e)}")
                return result
            
            # Process collected results
            for worker_data in worker_results:
                if worker_data and isinstance(worker_data, dict) and worker_data.get('status') == 'success':
                    result['workers_completed'] += 1
                    result['total_scanned'] += worker_data.get('scanned', 0)
                    result['total_hidden'] += worker_data.get('hidden', 0)
                    
                    # Aggregate category counts
                    for category, count in worker_data.get('by_category', {}).items():
                        result['by_category'][category] += count
                else:
                    result['workers_failed'] += 1
                    error_msg = worker_data.get('error', 'Unknown error') if isinstance(worker_data, dict) else str(worker_data)
                    slice_id = worker_data.get('slice_id', '?') if isinstance(worker_data, dict) else '?'
                    result['errors'].append(f"Slice {slice_id}: {error_msg}")
                    logger.error(f"[NOISE_COORDINATOR] Worker failed: {error_msg}")
            
            # Final status
            if result['workers_failed'] > 0:
                result['status'] = 'partial'
            
            logger.info(f"[NOISE_COORDINATOR] Complete: {result['workers_completed']} workers succeeded, {result['workers_failed']} failed")
            logger.info(f"[NOISE_COORDINATOR] Scanned: {result['total_scanned']:,} events, Hidden: {result['total_hidden']:,} events")
            logger.info(f"[NOISE_COORDINATOR] Breakdown: {result['by_category']}")
            
        except Exception as e:
            logger.error(f"[NOISE_COORDINATOR] Fatal error: {e}", exc_info=True)
            result['status'] = 'error'
            result['errors'].append(str(e))
    
    return result


