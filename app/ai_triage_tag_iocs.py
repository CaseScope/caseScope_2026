"""
AI Triage - Tag IOC Events Module
==================================

Automatically tags events that contain highly suspicious IOCs.
This module finds events matching high-confidence indicators and tags them
for timeline analysis.

High-Confidence IOCs (90%+ likely attack-related):
- Commands (full command lines from EDR/forensics)
- Actor IPs (external IPs associated with attacker)
- Actor hostnames (attacker-controlled systems)
- High threat level IOCs (explicitly marked as high/critical)
- Malware hashes and names
- Suspicious processes/filenames

Filtering:
- Excludes hidden events
- Applies noise filtering to avoid false positives
- Checks against known good systems

Usage:
    from ai_triage_tag_iocs import tag_high_confidence_events
    
    result = tag_high_confidence_events(case_id, user_id)
    # Returns: {'success': bool, 'tagged_count': int, 'events_found': int, ...}
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
}

# These types are high confidence if threat_level is high/critical
CONDITIONAL_IOC_TYPES = {
    'hostname',          # Hostnames marked as high threat
    'filename',          # Suspicious executables
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


def is_noise_event(event: Dict) -> bool:
    """
    Check if event is likely noise and should not be tagged.
    
    Only returns True if we have positive evidence of noise.
    Missing data (None/empty) is NOT considered noise.
    """
    source = event.get('_source', {})
    
    # Check Event ID
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
    
    # Check parent process (only if present)
    parent = source.get('process', {}).get('parent', {})
    parent_name = parent.get('name') or parent.get('executable')
    if parent_name:  # Only check if we have a parent process
        parent_base = parent_name.split('\\')[-1].split('/')[-1].lower()
        if parent_base in NOISE_PARENT_PROCESSES:
            return True
    
    # Check user (only if present and not empty)
    # We explicitly check that user is a non-empty string
    user = source.get('user', {}).get('name')
    if user and isinstance(user, str) and user.strip():
        user_lower = user.lower().strip()
        # Skip the empty string check - only check actual noise users
        if user_lower and user_lower in NOISE_USERS and user_lower != '':
            return True
    
    # Also check forensic fields (only if present and not empty)
    for field in ['forensic_SubjectUserName', 'forensic_TargetUserName']:
        user_val = source.get(field)
        if user_val and isinstance(user_val, str) and user_val.strip():
            user_lower = user_val.lower().strip()
            if user_lower and user_lower in NOISE_USERS and user_lower != '':
                return True
    
    return False


def build_ioc_search_query(iocs: List[Dict], actor_hostnames: Set[str], actor_ips: Set[str]) -> Dict:
    """
    Build OpenSearch query to find events matching high-confidence IOCs.
    Excludes hidden events.
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
    
    query = {
        "query": {
            "bool": {
                "should": should_clauses,
                "minimum_should_match": 1,
                "must_not": [
                    {"term": {"is_hidden": True}}
                ]
            }
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
    """Get set of already-tagged event IDs."""
    from models import TimelineTag
    
    tags = TimelineTag.query.filter_by(case_id=case_id).all()
    return {tag.event_id for tag in tags}


def tag_event(case_id: int, user_id: int, event: Dict, index_name: str, reason: str) -> bool:
    """
    Create a timeline tag for an event.
    Returns True if tagged, False if already exists or error.
    """
    from models import TimelineTag, db
    
    event_id = event.get('_id')
    source = event.get('_source', {})
    
    # Check if already tagged
    existing = TimelineTag.query.filter_by(
        case_id=case_id,
        event_id=event_id,
        index_name=index_name
    ).first()
    
    if existing:
        return False
    
    # Create minimal event snapshot
    event_snapshot = {
        'timestamp': source.get('normalized_timestamp') or source.get('@timestamp'),
        'computer': source.get('computer_name') or source.get('normalized_computer'),
        'event_id': source.get('Event', {}).get('System', {}).get('EventID'),
        'source_file': source.get('source_file'),
    }
    
    # Add process info if available
    proc = source.get('process', {})
    if proc:
        event_snapshot['process'] = proc.get('name') or proc.get('executable')
        event_snapshot['command_line'] = proc.get('command_line', '')[:500]
    
    # Add forensic fields
    for field in ['forensic_CommandLine', 'forensic_ProcessName', 'forensic_TargetUserName']:
        if source.get(field):
            event_snapshot[field] = str(source.get(field))[:500]
    
    try:
        tag = TimelineTag(
            case_id=case_id,
            user_id=user_id,
            event_id=event_id,
            index_name=index_name,
            event_data=json.dumps(event_snapshot),
            tag_color='red',  # Red for auto-tagged suspicious
            notes=f"[Auto-tagged] {reason}"
        )
        db.session.add(tag)
        return True
    except Exception as e:
        logger.error(f"[TAG_IOC] Failed to tag event {event_id}: {e}")
        return False


def determine_match_reason(event: Dict, iocs: List[Dict], actor_hostnames: Set[str], actor_ips: Set[str]) -> Optional[str]:
    """
    Determine which IOC(s) matched this event.
    Returns a description string or None if no match found.
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
    
    matched = []
    
    # Check IOCs
    for ioc in iocs:
        value_lower = ioc['value'].lower()
        if value_lower in combined_text:
            matched.append(f"IOC:{ioc['type']}='{ioc['value'][:50]}'")
            if len(matched) >= 3:
                break
    
    # Check actor hostnames
    for hostname in actor_hostnames:
        if hostname in combined_text:
            matched.append(f"Actor hostname: {hostname}")
            break
    
    # Check actor IPs
    for ip in actor_ips:
        if ip in combined_text:
            matched.append(f"Actor IP: {ip}")
            break
    
    if matched:
        return "; ".join(matched[:3])
    
    return None


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def tag_high_confidence_events(case_id: int, user_id: int) -> Dict[str, Any]:
    """
    Main entry point for tagging high-confidence IOC events.
    
    Args:
        case_id: Case ID to process
        user_id: User ID for tag attribution
    
    Returns:
        {
            'success': bool,
            'tagged_count': int,
            'events_found': int,
            'already_tagged': int,
            'noise_filtered': int,
            'ioc_count': int,
            'actor_count': int,
            'error': str (if failed)
        }
    """
    from models import db
    
    logger.info(f"[TAG_IOC] Starting high-confidence tagging for case {case_id}")
    
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
                'tagged_count': 0,
                'events_found': 0,
                'ioc_count': 0,
                'actor_count': 0
            }
        
        # Get known system IPs (to avoid false positives)
        known_ips = get_known_system_ips(case_id)
        
        # Build search query
        query = build_ioc_search_query(iocs, actor_hostnames, actor_ips)
        if not query:
            return {
                'success': False,
                'error': 'Could not build search query',
                'tagged_count': 0,
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
                'tagged_count': 0,
                'events_found': 0,
                'ioc_count': len(iocs),
                'actor_count': actor_count
            }
        
        # Get already tagged events
        existing_tags = get_existing_tags(case_id)
        
        # Process events
        index_name = f"case_{case_id}"
        tagged_count = 0
        already_tagged = 0
        noise_filtered = 0
        
        for event in events:
            event_id = event.get('_id')
            
            # Skip if already tagged
            if event_id in existing_tags:
                already_tagged += 1
                continue
            
            # Skip noise events
            if is_noise_event(event):
                noise_filtered += 1
                continue
            
            # Determine match reason
            reason = determine_match_reason(event, iocs, actor_hostnames, actor_ips)
            if not reason:
                continue
            
            # Tag the event
            if tag_event(case_id, user_id, event, index_name, reason):
                tagged_count += 1
                existing_tags.add(event_id)  # Track to avoid duplicates
        
        # Commit all tags
        db.session.commit()
        
        logger.info(f"[TAG_IOC] Completed: tagged {tagged_count}, already tagged {already_tagged}, noise filtered {noise_filtered}")
        
        return {
            'success': True,
            'tagged_count': tagged_count,
            'events_found': len(events),
            'already_tagged': already_tagged,
            'noise_filtered': noise_filtered,
            'ioc_count': len(iocs),
            'actor_count': actor_count
        }
        
    except Exception as e:
        logger.error(f"[TAG_IOC] Failed: {e}", exc_info=True)
        return {
            'success': False,
            'error': str(e),
            'tagged_count': 0,
            'events_found': 0,
            'ioc_count': 0,
            'actor_count': 0
        }


def get_tagging_summary(result: Dict) -> Dict:
    """Generate summary for UI display."""
    return {
        'tagged_count': result.get('tagged_count', 0),
        'events_found': result.get('events_found', 0),
        'already_tagged': result.get('already_tagged', 0),
        'noise_filtered': result.get('noise_filtered', 0),
        'ioc_count': result.get('ioc_count', 0),
        'actor_count': result.get('actor_count', 0)
    }

