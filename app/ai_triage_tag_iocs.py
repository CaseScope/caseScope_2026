"""
AI Triage - Tag IOC Events Module
==================================

Automatically marks events with 'hunted' status when they contain highly suspicious IOCs
or match attack patterns. This module finds events and sets their status for investigation.

High-Confidence Criteria (auto-mark as 'hunted'):
1. Event matches 3+ different IOCs
2. Event matches attack patterns (TIER1, TIER2, TIER3 from events_attack_patterns)
3. Commands (full command lines from EDR/forensics)
4. Actor IPs (external IPs associated with attacker)
5. Actor hostnames (attacker-controlled systems)
6. High threat level IOCs (explicitly marked as high/critical)
7. Malware hashes and names
8. Suspicious processes/filenames

Filtering:
- Excludes events with event_status='noise'
- Excludes events with event_status='confirmed' (analyst-confirmed events are IMMUTABLE)
- Applies noise filtering to avoid false positives
- Checks against known good systems

Usage:
    from ai_triage_tag_iocs import tag_high_confidence_events
    
    result = tag_high_confidence_events(case_id, user_id, time_range='24h')
    # Returns: {'success': bool, 'hunted_count': int, 'events_found': int, ...}
"""

import re
import json
import logging
from typing import Dict, List, Set, Optional, Any, Tuple
from datetime import datetime

# Import from centralized noise filters module
from noise_filters import (
    NOISE_USERS,
    NOISE_EVENT_IDS,
    GENERIC_PARENTS,
    is_external_ip,
)

# Import from attack patterns module
from events_attack_patterns import match_pattern_tier

logger = logging.getLogger(__name__)


# ============================================================================
# HIGH-CONFIDENCE IOC TYPES
# ============================================================================

# These IOC types are highly likely to be attack-related (90%+)
HIGH_CONFIDENCE_IOC_TYPES = {
    'command',           # Full command lines are very specific
    'command_complex',   # Complex/obfuscated commands
    'hash',              # File hashes are definitive
    'malware_name',      # Known malware names
    'url',               # Malicious URLs
    'domain',            # C2 domains
    'ip',                # External IPs (checked separately)
    'filename',          # Executable names (nltest.exe, WinSCP.exe) - always tag
    'tool',              # Known attack tools - always tag
}

# These types are high confidence if threat_level is high/critical
CONDITIONAL_IOC_TYPES = {
    'hostname',          # Hostnames marked as high threat
    'filepath',          # Suspicious paths
    'username',          # Compromised accounts
}

# Threat levels that indicate high confidence
HIGH_THREAT_LEVELS = {'high', 'critical'}


# ============================================================================
# MODULE-SPECIFIC CONSTANTS
# ============================================================================

# Events from these processes are usually noise even if IOC matches
# More specific than GENERIC_PARENTS - includes system processes
NOISE_PARENT_PROCESSES = GENERIC_PARENTS | {
    'taskhost.exe', 'taskhostw.exe', 'runtimebroker.exe',
    'searchindexer.exe', 'searchhost.exe', 'searchprotocolhost.exe',
    'tiworker.exe', 'trustedinstaller.exe', 'msiexec.exe',
    'spoolsv.exe', 'lsass.exe', 'csrss.exe', 'wininit.exe',
    'smss.exe', 'system', 'registry', 'fontdrvhost.exe', 'wmi.exe',
}


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_high_confidence_iocs(case_id: int) -> List[Dict]:
    """
    Get IOCs that are highly likely to be attack-related.
    
    High-confidence criteria:
    - Commands: Always high confidence (specific attack indicators)
    - Hashes/Malware: Always high confidence (definitive)
    - IPs: External (non-private) IPs are high confidence
    - Hostnames/Usernames/Files: Only if threat_level is high/critical
    
    Returns list of IOC dicts with: type, value, threat_level, id
    """
    from models import IOC
    
    high_confidence = []
    
    # Get all active IOCs for the case
    iocs = IOC.query.filter_by(case_id=case_id, is_active=True).all()
    
    for ioc in iocs:
        is_high_confidence = False
        reason = None
        
        # Check if type is always high confidence (except IP which needs special handling)
        if ioc.ioc_type in HIGH_CONFIDENCE_IOC_TYPES:
            if ioc.ioc_type == 'ip':
                # Only include external IPs
                if is_external_ip(ioc.ioc_value):
                    is_high_confidence = True
                    reason = f"External IP (non-private)"
            else:
                is_high_confidence = True
                reason = f"Type '{ioc.ioc_type}' is high-confidence"
        
        # Check if conditional type with high threat level
        elif ioc.ioc_type in CONDITIONAL_IOC_TYPES:
            if ioc.threat_level and ioc.threat_level.lower() in HIGH_THREAT_LEVELS:
                is_high_confidence = True
                reason = f"Type '{ioc.ioc_type}' with threat_level '{ioc.threat_level}'"
        
        if is_high_confidence:
            high_confidence.append({
                'id': ioc.id,
                'type': ioc.ioc_type,
                'value': ioc.ioc_value,
                'threat_level': ioc.threat_level,
                'reason': reason
            })
    
    return high_confidence


def get_actor_systems(case_id: int) -> Tuple[Set[str], Set[str]]:
    """
    Get actor system hostnames and IPs.
    These are systems marked as 'actor_system' type - attacker-controlled.
    
    Returns: (hostnames_set, ips_set)
    """
    from models import System
    
    actor_hostnames = set()
    actor_ips = set()
    
    actor_systems = System.query.filter_by(
        case_id=case_id,
        hidden=False,
        system_type='actor_system'
    ).all()
    
    for system in actor_systems:
        if system.system_name:
            actor_hostnames.add(system.system_name.lower())
        if system.ip_address:
            actor_ips.add(system.ip_address)
    
    return actor_hostnames, actor_ips


def get_known_system_ips(case_id: int) -> Set[str]:
    """
    Get IPs of known legitimate systems (non-actor).
    These should NOT be tagged as suspicious.
    """
    from models import System
    
    known_ips = set()
    
    systems = System.query.filter_by(
        case_id=case_id,
        hidden=False
    ).filter(System.system_type != 'actor_system').all()
    
    for system in systems:
        if system.ip_address:
            known_ips.add(system.ip_address)
    
    return known_ips


def get_time_range_filter(case_id: int, time_range: str) -> Optional[Dict]:
    """
    Get time range filter for OpenSearch query.
    
    Uses the newest event timestamp as the end date, works backwards.
    
    Args:
        case_id: Case ID
        time_range: '24h', '3d', '7d', or 'all'
    
    Returns:
        Dict with 'range' query clause, or None if 'all'
        Also returns {'start_date': str, 'end_date': str} for display
    """
    from main import opensearch_client
    from datetime import datetime, timedelta
    
    if time_range == 'all':
        return None
    
    index_name = f"case_{case_id}"
    
    try:
        # Get the newest event timestamp
        response = opensearch_client.search(
            index=index_name,
            body={
                "size": 1,
                "sort": [{"@timestamp": {"order": "desc"}}],
                "_source": ["@timestamp"]
            }
        )
        
        if not response['hits']['hits']:
            return None
        
        newest_event = response['hits']['hits'][0]['_source']
        end_timestamp = newest_event.get('@timestamp')
        
        if not end_timestamp:
            return None
        
        # Parse end timestamp
        if isinstance(end_timestamp, str):
            end_dt = datetime.fromisoformat(end_timestamp.replace('Z', '+00:00'))
        else:
            end_dt = datetime.utcnow()
        
        # Calculate start timestamp based on time range
        if time_range == '24h':
            start_dt = end_dt - timedelta(hours=24)
        elif time_range == '3d':
            start_dt = end_dt - timedelta(days=3)
        elif time_range == '7d':
            start_dt = end_dt - timedelta(days=7)
        else:
            return None
        
        # Format for OpenSearch
        start_iso = start_dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        end_iso = end_dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        
        logger.info(f"[TAG_IOC] Time range filter: {start_dt.strftime('%Y-%m-%d %H:%M')} to {end_dt.strftime('%Y-%m-%d %H:%M')}")
        
        return {
            'filter': {
                "range": {
                    "@timestamp": {
                        "gte": start_iso,
                        "lte": end_iso
                    }
                }
            },
            'start_date': start_dt.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'end_date': end_dt.strftime('%Y-%m-%d %H:%M:%S UTC')
        }
        
    except Exception as e:
        logger.warning(f"[TAG_IOC] Failed to get time range filter: {e}")
        return None


def is_noise_event(event: Dict) -> bool:
    """
    Check if event is likely noise and should not be tagged.
    
    IMPORTANT: For attack detection, we should NOT filter events just because
    the parent is cmd.exe/powershell.exe - attackers USE these to run commands!
    
    We only filter:
    1. Events with noise event IDs (process termination, service state changes)
    2. Events where ONLY system users are involved AND no interesting process
    
    Missing data (None/empty) is NOT considered noise.
    """
    source = event.get('_source', {})
    
    # Check Event ID - these are truly noise regardless of other factors
    event_id = None
    if 'Event' in source and 'System' in source['Event']:
        event_id = source['Event']['System'].get('EventID')
        if isinstance(event_id, dict):
            event_id = event_id.get('#text')
    if event_id:
        try:
            if int(event_id) in NOISE_EVENT_IDS:
                return True
        except (ValueError, TypeError):
            pass
    
    # NOTE: We deliberately do NOT filter based on parent process!
    # Attackers run commands from cmd.exe and powershell.exe - this is expected.
    # The old code filtered events with parent in NOISE_PARENT_PROCESSES,
    # which incorrectly filtered legitimate attack activity like:
    #   - nltest.exe /dclist (parent: cmd.exe)
    #   - WinSCP.exe (parent: explorer.exe or cmd.exe)
    
    # Only filter if ALL users in the event are system/noise users
    # AND there's no interesting process name
    users_in_event = []
    
    user = source.get('user', {}).get('name')
    if user and isinstance(user, str) and user.strip():
        users_in_event.append(user.lower().strip())
    
    for field in ['forensic_SubjectUserName', 'forensic_TargetUserName']:
        user_val = source.get(field)
        if user_val and isinstance(user_val, str) and user_val.strip():
            users_in_event.append(user_val.lower().strip())
    
    # If we have users, check if ALL of them are noise users
    if users_in_event:
        all_noise_users = all(u in NOISE_USERS for u in users_in_event)
        if all_noise_users:
            # Even with noise users, don't filter if there's an interesting process
            proc = source.get('process', {})
            proc_name = proc.get('name') or proc.get('executable') or ''
            command_line = proc.get('command_line') or ''
            
            # If there's a command line or process name, keep it (IOC matched for a reason)
            if command_line or proc_name:
                return False
            
            # No process info and only noise users - likely noise
            return True
    
    return False


def build_ioc_search_query(iocs: List[Dict], actor_hostnames: Set[str], actor_ips: Set[str], 
                          time_range_filter: Optional[Dict] = None) -> Dict:
    """
    Build OpenSearch query to find events matching high-confidence IOCs.
    Excludes events with event_status='noise' or 'confirmed'.
    
    Args:
        iocs: List of IOC dicts
        actor_hostnames: Set of actor hostnames
        actor_ips: Set of actor IPs
        time_range_filter: Optional time range filter from get_time_range_filter()
    """
    should_clauses = []
    
    # Add IOC value matches
    for ioc in iocs:
        value = ioc['value']
        if not value or len(value) < 3:
            continue
        
        # Use query_string for flexible matching
        should_clauses.append({
            "query_string": {
                "query": f'"{value}"',
                "default_field": "search_blob",
                "default_operator": "AND"
            }
        })
    
    # Add actor hostname matches
    for hostname in actor_hostnames:
        if hostname and len(hostname) >= 3:
            should_clauses.append({
                "query_string": {
                    "query": f'"{hostname}"',
                    "default_field": "search_blob",
                    "default_operator": "AND"
                }
            })
    
    # Add actor IP matches
    for ip in actor_ips:
        if ip:
            should_clauses.append({
                "query_string": {
                    "query": f'"{ip}"',
                    "default_field": "search_blob",
                    "default_operator": "AND"
                }
            })
    
    if not should_clauses:
        return None
    
    # Build query with optional time range filter
    # CRITICAL: Exclude 'noise' and 'confirmed' events
    # - noise: Already processed and marked as noise
    # - confirmed: Analyst-confirmed events are IMMUTABLE
    bool_query = {
        "should": should_clauses,
        "minimum_should_match": 1,
        "must_not": [
            {"term": {"event_status": "noise"}},
            {"term": {"event_status": "confirmed"}}
        ]
    }
    
    # Add time range filter if provided
    if time_range_filter and time_range_filter.get('filter'):
        bool_query["filter"] = time_range_filter['filter']
    
    query = {
        "query": {
            "bool": bool_query
        },
        "size": 10000,  # Max per batch
        "_source": True
    }
    
    return query


def search_events_for_tagging(case_id: int, query: Dict) -> List[Dict]:
    """
    Execute search and return matching events.
    Uses scroll API for large result sets.
    """
    from main import opensearch_client
    
    es = opensearch_client
    index_name = f"case_{case_id}"
    
    # Check if index exists
    if not es.indices.exists(index=index_name):
        logger.warning(f"[TAG_IOC] Index {index_name} does not exist")
        return []
    
    events = []
    
    try:
        # Use scroll API for unlimited results
        response = es.search(
            index=index_name,
            body=query,
            scroll='5m'
        )
        
        scroll_id = response.get('_scroll_id')
        hits = response.get('hits', {}).get('hits', [])
        events.extend(hits)
        
        # Continue scrolling if more results (no limit)
        while hits:
            response = es.scroll(scroll_id=scroll_id, scroll='5m')
            scroll_id = response.get('_scroll_id')
            hits = response.get('hits', {}).get('hits', [])
            events.extend(hits)
            
            # Log progress for large datasets
            if len(events) % 50000 == 0:
                logger.info(f"[TAG_IOC] Scroll progress: {len(events)} events retrieved...")
        
        # Clear scroll
        if scroll_id:
            try:
                es.clear_scroll(scroll_id=scroll_id)
            except:
                pass
        
        logger.info(f"[TAG_IOC] Found {len(events)} events matching high-confidence IOCs")
        return events
        
    except Exception as e:
        logger.error(f"[TAG_IOC] Search failed: {e}")
        return []


def get_existing_tags(case_id: int) -> Set[str]:
    """Get set of already-hunted or confirmed event IDs."""
    from event_status import get_event_ids_by_status, STATUS_HUNTED, STATUS_CONFIRMED
    
    hunted_ids = get_event_ids_by_status(case_id, [STATUS_HUNTED])
    confirmed_ids = get_event_ids_by_status(case_id, [STATUS_CONFIRMED])
    return hunted_ids | confirmed_ids


def get_excluded_events(case_id: int) -> Set[str]:
    """Get set of event IDs with status='noise' (excluded from auto-tagging)."""
    from event_status import get_event_ids_by_status, STATUS_NOISE
    
    return get_event_ids_by_status(case_id, [STATUS_NOISE])


def tag_event(case_id: int, user_id: int, event: Dict, index_name: str, reason: str) -> bool:
    """
    Set event status to 'hunted' (Phase 3 auto-tagging).
    Returns True if status set, False if already hunted/confirmed or error.
    """
    from event_status import set_status, get_status, STATUS_HUNTED, STATUS_CONFIRMED
    
    event_id = event.get('_id')
    
    # Check current status - don't overwrite 'confirmed' status
    current_status = get_status(case_id, event_id)
    if current_status == STATUS_HUNTED:
        return False  # Already hunted
    if current_status == STATUS_CONFIRMED:
        return False  # Don't downgrade from confirmed
    
    # Set status to 'hunted' with reason as notes
    notes = f"[Phase 3 Auto] {reason}"
    if set_status(case_id, event_id, STATUS_HUNTED, user_id, notes):
        return True
    else:
        logger.error(f"[TAG_IOC] Failed to set hunted status for event {event_id}")
        return False


def determine_match_reason(event: Dict, iocs: List[Dict], actor_hostnames: Set[str], actor_ips: Set[str]) -> Optional[Tuple[str, int, Optional[Tuple]]]:
    """
    Determine which IOC(s) matched this event and if it matches attack patterns.
    
    Returns:
        Tuple of (reason_string, ioc_match_count, pattern_match) or None if no match
        pattern_match is (tier, category, pattern) or None
    """
    source = event.get('_source', {})
    search_blob = str(source.get('search_blob', '')).lower()
    
    # Also check command line directly
    cmd_line = ''
    proc = source.get('process', {})
    if proc:
        cmd_line = (proc.get('command_line', '') or '').lower()
    forensic_cmd = (source.get('forensic_CommandLine', '') or '').lower()
    
    combined_text = f"{search_blob} {cmd_line} {forensic_cmd}"
    
    matched_iocs = []
    ioc_count = 0
    
    # Check IOCs
    for ioc in iocs:
        value_lower = ioc['value'].lower()
        if value_lower in combined_text:
            matched_iocs.append(f"{ioc['type']}='{ioc['value'][:50]}'")
            ioc_count += 1
            if len(matched_iocs) >= 5:  # Limit to 5 for display
                break
    
    # Check actor hostnames
    for hostname in actor_hostnames:
        if hostname in combined_text:
            matched_iocs.append(f"Actor hostname: {hostname}")
            ioc_count += 1
            break
    
    # Check actor IPs
    for ip in actor_ips:
        if ip in combined_text:
            matched_iocs.append(f"Actor IP: {ip}")
            ioc_count += 1
            break
    
    # Check attack patterns
    pattern_match = None
    if search_blob:
        pattern_match = match_pattern_tier(search_blob)
    
    # Build reason string
    reasons = []
    if ioc_count >= 3:
        reasons.append(f"{ioc_count} IOCs matched")
    if matched_iocs:
        reasons.append("; ".join(matched_iocs[:3]))  # Show first 3
    if pattern_match:
        tier, category, pattern = pattern_match
        reasons.append(f"Tier{tier}:{category}")
    
    if reasons or ioc_count >= 3 or pattern_match:
        return ("; ".join(reasons), ioc_count, pattern_match)
    
    return None


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def tag_high_confidence_events(case_id: int, user_id: int, time_range: str = '24h') -> Dict[str, Any]:
    """
    Main entry point for marking high-confidence IOC events as 'hunted'.
    
    Criteria for marking as 'hunted':
    1. Event matches 3+ different IOCs
    2. Event matches attack patterns (TIER1, TIER2, or TIER3)
    3. Event matches high-confidence IOC types (commands, hashes, external IPs)
    
    No limit on number of events processed - marks ALL matching events.
    
    Args:
        case_id: Case ID to process
        user_id: User ID for status attribution
        time_range: Time range filter ('24h', '3d', '7d', 'all')
                   Uses newest event timestamp as end date, works backwards
    
    Returns:
        {
            'success': bool,
            'hunted_count': int,
            'events_found': int,
            'already_hunted': int,
            'noise_filtered': int,
            'ioc_count': int,
            'actor_count': int,
            'pattern_matches': int,
            'multi_ioc_matches': int,
            'time_range_used': str,
            'date_range': {'start': str, 'end': str},
            'error': str (if failed)
        }
    """
    from models import db
    
    logger.info(f"[TAG_IOC] Starting high-confidence tagging for case {case_id}, time_range={time_range}")
    
    try:
        # Get high-confidence IOCs
        iocs = get_high_confidence_iocs(case_id)
        logger.info(f"[TAG_IOC] Found {len(iocs)} high-confidence IOCs")
        
        # Get actor systems
        actor_hostnames, actor_ips = get_actor_systems(case_id)
        actor_count = len(actor_hostnames) + len(actor_ips)
        logger.info(f"[TAG_IOC] Found {len(actor_hostnames)} actor hostnames, {len(actor_ips)} actor IPs")
        
        # Check if we have anything to search for
        if not iocs and not actor_hostnames and not actor_ips:
            return {
                'success': False,
                'error': 'No high-confidence IOCs or actor systems found. Add commands, hashes, or mark IOCs as high threat level.',
                'hunted_count': 0,
                'events_found': 0,
                'ioc_count': 0,
                'actor_count': 0
            }
        
        # Get time range filter
        time_range_filter = get_time_range_filter(case_id, time_range)
        date_range = {}
        if time_range_filter:
            date_range = {
                'start': time_range_filter.get('start_date', ''),
                'end': time_range_filter.get('end_date', '')
            }
        
        # Get known system IPs (to avoid false positives)
        known_ips = get_known_system_ips(case_id)
        
        # Build search query with time range filter
        query = build_ioc_search_query(iocs, actor_hostnames, actor_ips, time_range_filter)
        if not query:
            return {
                'success': False,
                'error': 'Could not build search query',
                'hunted_count': 0,
                'events_found': 0,
                'ioc_count': len(iocs),
                'actor_count': actor_count
            }
        
        # Search for matching events
        events = search_events_for_tagging(case_id, query)
        
        if not events:
            return {
                'success': True,
                'message': 'No matching events found',
                'hunted_count': 0,
                'events_found': 0,
                'ioc_count': len(iocs),
                'actor_count': actor_count
            }
        
        # Get already hunted/confirmed events
        existing_tags = get_existing_tags(case_id)
        
        # Get manually excluded events (marked as noise by user)
        excluded_events = get_excluded_events(case_id)
        logger.info(f"[TAG_IOC] {len(excluded_events)} events marked as noise by users")
        
        # Process events
        index_name = f"case_{case_id}"
        hunted_count = 0
        already_hunted = 0
        noise_filtered = 0
        user_excluded = 0
        pattern_matches = 0
        multi_ioc_matches = 0
        
        for event in events:
            event_id = event.get('_id')
            
            # Skip if already hunted/confirmed
            if event_id in existing_tags:
                already_hunted += 1
                continue
            
            # Skip if user manually marked as noise
            if event_id in excluded_events:
                user_excluded += 1
                continue
            
            # Skip noise events
            if is_noise_event(event):
                noise_filtered += 1
                continue
            
            # Determine match reason and criteria
            match_result = determine_match_reason(event, iocs, actor_hostnames, actor_ips)
            if not match_result:
                continue
            
            reason, ioc_count, pattern_match = match_result
            
            # Determine if event should be marked as 'hunted'
            should_mark = False
            
            # Criterion 1: 3+ IOC matches
            if ioc_count >= 3:
                should_mark = True
                multi_ioc_matches += 1
                logger.debug(f"[TAG_IOC] Event {event_id[:8]} matched {ioc_count} IOCs")
            
            # Criterion 2: Attack pattern match
            if pattern_match:
                should_mark = True
                pattern_matches += 1
                tier, category, pattern = pattern_match
                logger.debug(f"[TAG_IOC] Event {event_id[:8]} matched Tier{tier} pattern: {category}")
            
            if not should_mark:
                # Also mark if it matches high-confidence IOC types (commands, hashes, external IPs)
                # But we already got those in the query, so if we're here, mark it
                should_mark = True
            
            # Mark the event as 'hunted'
            if should_mark and tag_event(case_id, user_id, event, index_name, reason):
                hunted_count += 1
                existing_tags.add(event_id)  # Track to avoid duplicates in same run
        
        # Commit all status changes
        db.session.commit()
        
        logger.info(f"[TAG_IOC] Completed: hunted {hunted_count}, already hunted {already_hunted}, "
                   f"noise filtered {noise_filtered}, user excluded {user_excluded}, "
                   f"pattern matches {pattern_matches}, multi-IOC matches {multi_ioc_matches}")
        
        return {
            'success': True,
            'hunted_count': hunted_count,
            'events_found': len(events),
            'already_hunted': already_hunted,
            'noise_filtered': noise_filtered,
            'user_excluded': user_excluded,
            'ioc_count': len(iocs),
            'actor_count': actor_count,
            'pattern_matches': pattern_matches,
            'multi_ioc_matches': multi_ioc_matches,
            'time_range_used': time_range,
            'date_range': date_range
        }
        
    except Exception as e:
        logger.error(f"[TAG_IOC] Failed: {e}", exc_info=True)
        return {
            'success': False,
            'error': str(e),
            'hunted_count': 0,
            'events_found': 0,
            'ioc_count': 0,
            'actor_count': 0
        }


def get_tagging_summary(result: Dict) -> Dict:
    """Generate summary for UI display."""
    return {
        'hunted_count': result.get('hunted_count', 0),
        'events_found': result.get('events_found', 0),
        'already_hunted': result.get('already_hunted', 0),
        'noise_filtered': result.get('noise_filtered', 0),
        'user_excluded': result.get('user_excluded', 0),
        'ioc_count': result.get('ioc_count', 0),
        'actor_count': result.get('actor_count', 0),
        'pattern_matches': result.get('pattern_matches', 0),
        'multi_ioc_matches': result.get('multi_ioc_matches', 0)
    }


def get_exclusion_count(case_id: int) -> int:
    """Get count of excluded events for a case."""
    from models import TagExclusion
    return TagExclusion.query.filter_by(case_id=case_id).count()


def get_exclusions(case_id: int) -> List[Dict]:
    """Get list of excluded events for a case."""
    from models import TagExclusion, User
    
    exclusions = TagExclusion.query.filter_by(case_id=case_id).order_by(TagExclusion.excluded_at.desc()).all()
    
    result = []
    for exc in exclusions:
        user = User.query.get(exc.excluded_by)
        result.append({
            'id': exc.id,
            'event_id': exc.event_id,
            'index_name': exc.index_name,
            'reason': exc.reason,
            'excluded_by': user.username if user else 'Unknown',
            'excluded_at': exc.excluded_at.isoformat() if exc.excluded_at else None
        })
    
    return result


def add_exclusion(case_id: int, event_id: str, index_name: str, user_id: int, reason: str = None) -> bool:
    """Add an event to the exclusion list."""
    from models import TagExclusion, db
    
    # Check if already excluded
    existing = TagExclusion.query.filter_by(
        case_id=case_id,
        event_id=event_id,
        index_name=index_name
    ).first()
    
    if existing:
        return False  # Already excluded
    
    try:
        exclusion = TagExclusion(
            case_id=case_id,
            event_id=event_id,
            index_name=index_name,
            reason=reason,
            excluded_by=user_id
        )
        db.session.add(exclusion)
        db.session.commit()
        return True
    except Exception as e:
        logger.error(f"[TAG_IOC] Failed to add exclusion: {e}")
        db.session.rollback()
        return False


def remove_exclusion(case_id: int, event_id: str, index_name: str) -> bool:
    """Remove an event from the exclusion list."""
    from models import TagExclusion, db
    
    try:
        exclusion = TagExclusion.query.filter_by(
            case_id=case_id,
            event_id=event_id,
            index_name=index_name
        ).first()
        
        if exclusion:
            db.session.delete(exclusion)
            db.session.commit()
            return True
        return False
    except Exception as e:
        logger.error(f"[TAG_IOC] Failed to remove exclusion: {e}")
        db.session.rollback()
        return False

