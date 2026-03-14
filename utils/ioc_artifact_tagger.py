"""IOC Artifact Tagger for CaseScope

Searches ClickHouse artifacts for IOC matches and updates artifact counts.

Match Types:
    - token: Uses hasTokenCaseInsensitive() on raw_json for whole-word matching
      Best for hashes, IPs, unique identifiers
    - substring: Uses LIKE for partial matching
      Best for file paths, registry, URLs, command lines
    - regex: Uses match() for pattern matching

Also marks matching events with IOC types for visual highlighting.
Thread-safe Redis client initialization.
"""
import os
import re
import json
import logging
import threading
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any

import redis
from config import Config
from utils.clickhouse import get_fresh_client

logger = logging.getLogger(__name__)

# Redis client for progress tracking with thread-safe initialization
_redis_client = None
_redis_lock = threading.Lock()

def _get_redis() -> redis.Redis:
    """Get Redis client for progress tracking (thread-safe)"""
    global _redis_client
    if _redis_client is None:
        with _redis_lock:
            # Double-check after acquiring lock
            if _redis_client is None:
                _redis_client = redis.Redis(
                    host=Config.REDIS_HOST,
                    port=Config.REDIS_PORT,
                    db=Config.REDIS_DB,
                    decode_responses=True
                )
    return _redis_client


def _update_tag_progress(case_id: int, current: int, total: int, 
                         current_ioc: str = '', matches_so_far: int = 0) -> None:
    """Update tagging progress in Redis"""
    try:
        client = _get_redis()
        key = f"ioc_tag_progress:{case_id}"
        progress = {
            'current': current,
            'total': total,
            'current_ioc': current_ioc[:50] if current_ioc else '',
            'matches': matches_so_far,
            'status': 'processing' if current < total else 'complete'
        }
        client.setex(key, 300, json.dumps(progress))  # 5 min expiry
    except Exception as e:
        logger.debug(f"Failed to update tag progress: {e}")


def get_tag_progress(case_id: int) -> Optional[Dict[str, Any]]:
    """Get current tagging progress from Redis"""
    try:
        client = _get_redis()
        key = f"ioc_tag_progress:{case_id}"
        data = client.get(key)
        if data:
            return json.loads(data)
        return None
    except Exception:
        return None


def clear_tag_progress(case_id: int) -> None:
    """Clear tagging progress from Redis"""
    try:
        client = _get_redis()
        key = f"ioc_tag_progress:{case_id}"
        client.delete(key)
    except Exception:
        pass


# Simplified IOC type names for badges
IOC_TYPE_SHORT_NAMES = {
    'IP Address (IPv4)': 'IP',
    'IP Address (IPv6)': 'IP',
    'Domain': 'Domain',
    'FQDN': 'Domain',
    'Hostname': 'Host',
    'URL': 'URL',
    'MD5 Hash': 'Hash',
    'SHA1 Hash': 'Hash',
    'SHA256 Hash': 'Hash',
    'File Path': 'File',
    'File Name': 'File',
    'Process Name': 'Process',
    'Process Path': 'Process',
    'Command Line': 'Command',
    'Registry Key': 'Registry',
    'Registry Value': 'Registry',
    'Username': 'User',
    'SID': 'User',
    'Email Address': 'Email',
    'Password Hash': 'Credential',
    'SSH Key Fingerprint': 'Credential',
    'API Key': 'Credential',
}


def get_short_ioc_type(ioc_type: str) -> str:
    """Get shortened IOC type name for badges."""
    return IOC_TYPE_SHORT_NAMES.get(ioc_type, ioc_type.split()[0] if ioc_type else 'IOC')


def extract_searchable_terms(value: str, ioc_type: str) -> List[Tuple[str, bool]]:
    """Extract searchable terms from an IOC value.
    
    For file paths, extracts the filename.
    For command lines, extracts executables.
    For other types, returns the value as-is plus any useful substrings.
    
    Returns list of (term, is_filename) tuples for case-insensitive search.
    is_filename=True means the term needs word-boundary matching to avoid
    false positives (e.g., 'd.bat' should not match 'build.bat').
    """
    # List of (term, is_filename) tuples
    terms = []
    value = value.strip()
    
    if not value:
        return terms
    
    # Full value is never a "filename" - it's the complete IOC value
    terms.append((value.lower(), False))
    
    if ioc_type in ('File Path', 'Process Path'):
        # Extract filename from path - this IS a filename, needs boundary matching
        filename = os.path.basename(value.replace('\\', '/'))
        if filename and filename.lower() != value.lower():
            terms.append((filename.lower(), True))  # is_filename=True
        
        # Skip name-without-extension - too prone to false positives
        # e.g., 'log1' from 'log1.log' matches '.LOG1' files
    
    elif ioc_type == 'File Name':
        # The value itself is a filename - needs boundary matching
        # Replace the first entry with is_filename=True
        terms[0] = (value.lower(), True)
    
    elif ioc_type == 'Command Line':
        # Extract executable names from command line - these are filenames
        exe_pattern = r'[\\/]?([a-zA-Z0-9_\-\.]+\.(exe|bat|cmd|ps1|vbs|js|dll|msi))'
        matches = re.findall(exe_pattern, value, re.IGNORECASE)
        for match in matches:
            terms.append((match[0].lower(), True))  # is_filename=True
        
        # First token extraction - if it's a standalone command like "rdpclip"
        first_token = value.split()[0] if value.split() else ''
        if first_token:
            first_token = first_token.strip('"\'')
            first_token_name = os.path.basename(first_token.replace('\\', '/'))
            if first_token_name and not any(first_token_name.lower() == t[0] for t in terms):
                # Short command names need boundary matching
                terms.append((first_token_name.lower(), True))
    
    elif ioc_type == 'Process Name':
        # Process names are filenames - need boundary matching
        terms[0] = (value.lower(), True)
        # Add without .exe extension if present
        if value.lower().endswith('.exe'):
            terms.append((value[:-4].lower(), True))
    
    elif ioc_type in ('Registry Key', 'Registry Value'):
        # For registry, also search for the last component
        parts = value.replace('/', '\\').split('\\')
        if len(parts) > 1 and parts[-1]:
            terms.append((parts[-1].lower(), False))
    
    elif ioc_type in ('Domain', 'FQDN', 'Hostname'):
        # Domain matching - also try just the hostname part
        parts = value.split('.')
        if len(parts) > 1:
            terms.append((parts[0].lower(), False))
    
    elif ioc_type == 'URL':
        # Extract domain/hostname from URL
        domain_match = re.search(r'://([^/]+)', value)
        if domain_match:
            domain = domain_match.group(1)
            domain = domain.split(':')[0]
            terms.append((domain.lower(), False))
    
    # Deduplicate while preserving order
    types_allowing_short = {
        'Username', 'Hostname', 'SID', 'IP Address (IPv4)', 'IP Address (IPv6)',
        'Email Address', 'Password Hash', 'MD5 Hash', 'SHA1 Hash', 'SHA256 Hash',
        'API Key', 'SSH Key Fingerprint'
    }
    min_length = 2 if ioc_type in types_allowing_short else 4
    
    seen = set()
    unique_terms = []
    for term, is_filename in terms:
        if term and term not in seen and len(term) >= min_length:
            seen.add(term)
            unique_terms.append((term, is_filename))
    
    return unique_terms


def _can_use_token_match(value: str) -> bool:
    """Check if a value can be used with ClickHouse hasTokenCaseInsensitive().
    
    ClickHouse token functions treat certain characters as separators.
    If the needle contains separators, it will only match the first token,
    causing false positives (e.g., 'advanced ip' would only match 'advanced').
    """
    if not value:
        return False
    
    # Characters that ClickHouse treats as separators in hasTokenCaseInsensitive
    separator_chars = {'.', ',', ':', ';', ' ', '\t', '\n', '\r', '!', '?', 
                       '@', '#', '$', '%', '^', '&', '*', '(', ')', '[', ']',
                       '{', '}', '<', '>', '/', '\\', '|', '~', '`', '"', "'"}
    
    for char in value:
        if char in separator_chars:
            return False
    return True


def build_token_match_clause(value: str, columns: list = None) -> str:
    """Build hasTokenCaseInsensitive clause for token matching.
    
    Token matching ensures 'ltsvc' matches 'c:\\ltsvc\\' but NOT 'altsvc'.
    Searches both raw_json and search_blob for full event data coverage.
    
    IMPORTANT: If value contains separator characters (spaces, dots, etc.),
    hasTokenCaseInsensitive will only match the first token, causing false
    positives. This function will fall back to substring matching in that case.
    
    Args:
        value: The IOC value to match as a token
        columns: List of columns to search (default: ['raw_json', 'search_blob'])
    
    Returns: SQL clause string
    """
    if columns is None:
        columns = ['raw_json', 'search_blob']
    elif isinstance(columns, str):
        columns = ['raw_json', 'search_blob']
    
    # Safety check: if value contains separators, fall back to substring matching
    # to prevent hasTokenCaseInsensitive from matching only the first token
    if not _can_use_token_match(value):
        logger.warning(f"build_token_match_clause called with value containing separators: '{value}'. Using substring matching instead.")
        return build_substring_match_clause(value, columns)
    
    escaped = value.replace("'", "''")
    clauses = [f"hasTokenCaseInsensitive({col}, '{escaped}')" for col in columns]
    return f"({' OR '.join(clauses)})"


def _build_substring_for_column(value: str, column: str) -> str:
    """Build a single LIKE clause for one column."""
    value_lower = value.lower()
    
    # Check if this looks like a path (contains backslashes or is a registry key)
    if '\\' in value or value_lower.startswith(('hklm', 'hkcu', 'hkey_', 'hku')):
        # Split on backslashes and use wildcards between parts
        # This handles JSON escaping variations (\ vs \\ in stored data)
        parts = value_lower.replace('/', '\\').split('\\')
        parts = [p.strip() for p in parts if p.strip()]
        
        if parts:
            # Escape special LIKE characters in each part
            escaped_parts = []
            for part in parts:
                # Also handle spaces within path parts (command lines with paths)
                if ' ' in part:
                    # Split on spaces and join with wildcards
                    subparts = part.split()
                    subparts = [sp.replace("'", "''").replace('%', '\\%').replace('_', '\\_') 
                                for sp in subparts if sp]
                    escaped_parts.append('%'.join(subparts))
                else:
                    escaped = part.replace("'", "''").replace('%', '\\%').replace('_', '\\_')
                    escaped_parts.append(escaped)
            
            # Join with wildcards
            pattern = '%' + '%'.join(escaped_parts) + '%'
            return f"lower({column}) LIKE '{pattern}'"
    
    # Standard substring match - match the exact phrase including spaces
    # For values with spaces (like "advanced ip"), we match the literal phrase
    # rather than splitting into separate words with wildcards between them
    # (splitting caused false positives where "advanced" and "ip" matched separately)
    escaped = value_lower.replace("'", "''").replace('%', '\\%').replace('_', '\\_')
    return f"lower({column}) LIKE '%{escaped}%'"


def build_substring_match_clause(value: str, columns: list = None) -> str:
    """Build LIKE clause for substring matching across multiple columns.
    
    Substring matching finds any occurrence of the value.
    Searches both raw_json and search_blob for full event data coverage.
    
    For paths (containing backslashes), uses wildcards between path segments
    to handle JSON escaping variations in ClickHouse.
    
    For command lines and complex strings with spaces, uses wildcards between 
    words to handle whitespace variations (single vs double spaces).
    
    Args:
        value: The IOC value to match as substring
        columns: List of columns to search (default: ['raw_json', 'search_blob'])
    
    Returns: SQL clause string
    """
    if columns is None:
        columns = ['raw_json', 'search_blob']
    elif isinstance(columns, str):
        columns = ['raw_json', 'search_blob']
    
    clauses = [_build_substring_for_column(value, col) for col in columns]
    return f"({' OR '.join(clauses)})"


def build_regex_match_clause(value: str, columns: list = None) -> str:
    """Build regex match clause across multiple columns.
    
    Args:
        value: The regex pattern to match
        columns: List of columns to search (default: ['raw_json', 'search_blob'])
    
    Returns: SQL clause string
    """
    if columns is None:
        columns = ['raw_json', 'search_blob']
    elif isinstance(columns, str):
        columns = ['raw_json', 'search_blob']
    
    escaped = value.replace("'", "\\'").replace("\\", "\\\\")
    clauses = [f"match(lower({col}), '{escaped}')" for col in columns]
    return f"({' OR '.join(clauses)})"


def build_ioc_match_clause(ioc_value: str, ioc_type: str, match_type: str, 
                           aliases: List[str] = None) -> str:
    """Build the complete WHERE clause for an IOC based on its match type.
    
    Searches both raw_json and search_blob for comprehensive matching.
    
    Args:
        ioc_value: The IOC value
        ioc_type: The IOC type (e.g., 'File Path', 'MD5 Hash')
        match_type: 'token', 'substring', or 'regex'
        aliases: Optional list of aliases to also match
    
    Returns: SQL WHERE clause (without 'WHERE')
    """
    # Build primary match clause based on match_type
    # All functions now search both raw_json and search_blob by default
    # SAFETY: If match_type is 'token' but value contains separators,
    # fall back to substring matching to prevent false positives
    # (hasTokenCaseInsensitive silently matches only the first token)
    effective_match_type = match_type
    if match_type == 'token' and not _can_use_token_match(ioc_value):
        logger.debug(f"IOC '{ioc_value}' contains separators, falling back to substring matching")
        effective_match_type = 'substring'
    
    if effective_match_type == 'token':
        primary_clause = build_token_match_clause(ioc_value)
    elif effective_match_type == 'regex':
        primary_clause = build_regex_match_clause(ioc_value)
    else:  # substring (default)
        primary_clause = build_substring_match_clause(ioc_value)
    
    # If aliases exist, add alias validation (any alias must also match)
    if aliases and len(aliases) > 0:
        alias_clauses = []
        for alias in aliases:
            if alias:
                # Aliases always use substring matching for flexibility
                alias_clauses.append(build_substring_match_clause(alias))
        
        if alias_clauses:
            alias_clause = ' OR '.join(alias_clauses)
            return f"({primary_clause}) AND ({alias_clause})"
    
    return primary_clause


def build_search_conditions(search_terms: List[Tuple[str, bool]], param_prefix: str = 'term') -> Tuple[str, Dict]:
    """Build SQL WHERE conditions and parameters for search terms.
    
    LEGACY: This function is kept for backward compatibility.
    New code should use build_ioc_match_clause() instead.
    
    Args:
        search_terms: List of (term, is_filename) tuples. Filenames use word-boundary matching.
        param_prefix: Prefix for parameter names
    
    Returns (where_clause, params_dict)
    """
    conditions = []
    params = {}
    
    for i, (term, is_filename) in enumerate(search_terms):
        # Escape special characters for LIKE
        escaped_term = term.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
        
        if is_filename:
            # For filenames, require word boundary (path separator, space, or start)
            # This prevents 'd.bat' from matching 'build.bat'
            param_base = f'{param_prefix}_{i}'
            params[f'{param_base}_bs'] = f'%\\{escaped_term}%'  # backslash prefix
            params[f'{param_base}_fs'] = f'%/{escaped_term}%'   # forward slash prefix
            params[f'{param_base}_sp'] = f'% {escaped_term}%'   # space prefix
            params[f'{param_base}_qt'] = f'%"{escaped_term}%'   # quote prefix
            conditions.append(
                f"(lower(search_blob) LIKE {{{param_base}_bs:String}} "
                f"OR lower(search_blob) LIKE {{{param_base}_fs:String}} "
                f"OR lower(search_blob) LIKE {{{param_base}_sp:String}} "
                f"OR lower(search_blob) LIKE {{{param_base}_qt:String}})"
            )
        else:
            # For full paths, hashes, IPs etc - standard substring match
            param_name = f'{param_prefix}_{i}'
            params[param_name] = f'%{escaped_term}%'
            conditions.append(f"lower(search_blob) LIKE {{{param_name}:String}}")
    
    where_clause = ' OR '.join(conditions) if conditions else '1=0'
    return where_clause, params


def search_artifacts_for_ioc(
    case_id: int,
    ioc_value: str,
    ioc_type: str,
    aliases: List[str] = None,
    match_type: str = None,
    limit: int = 1000
) -> Dict[str, Any]:
    """Search ClickHouse artifacts for an IOC.
    
    Uses raw_json for comprehensive matching with three modes:
        - token: hasTokenCaseInsensitive() for whole-word matching
        - substring: LIKE for partial matching  
        - regex: match() for pattern matching
    
    If aliases are provided, uses two-tier matching:
    1. Find events matching the primary IOC value
    2. Count only events where an alias also matches
    
    Returns:
        {
            'match_count': int,
            'earliest': datetime or None,
            'latest': datetime or None,
            'artifact_types': dict of type -> count,
            'match_type_used': str
        }
    """
    from models.ioc import detect_match_type
    
    client = get_fresh_client()
    
    if not ioc_value:
        return {
            'match_count': 0,
            'earliest': None,
            'latest': None,
            'artifact_types': {},
            'match_type_used': None
        }
    
    # Determine match type - explicit > auto-detected
    effective_match_type = match_type or detect_match_type(ioc_value, ioc_type)
    
    # Build the WHERE clause based on match type
    where_clause = build_ioc_match_clause(ioc_value, ioc_type, effective_match_type, aliases)
    
    # Get aggregate stats
    query = f"""
        SELECT 
            count() as cnt,
            min(timestamp) as earliest,
            max(timestamp) as latest
        FROM events 
        WHERE case_id = {case_id}
          AND ({where_clause})
    """
    
    try:
        result = client.query(query)
        row = result.result_rows[0] if result.result_rows else (0, None, None)
        match_count = row[0]
        earliest = row[1]
        latest = row[2]
    except Exception as e:
        logger.error(f"Error searching for IOC: {e}")
        return {
            'match_count': 0,
            'earliest': None,
            'latest': None,
            'artifact_types': {},
            'match_type_used': effective_match_type
        }
    
    # Get artifact type breakdown if we have matches
    artifact_types = {}
    if match_count > 0:
        type_query = f"""
            SELECT artifact_type, count() as cnt
            FROM events 
            WHERE case_id = {case_id}
              AND ({where_clause})
            GROUP BY artifact_type
            ORDER BY cnt DESC
        """
        
        try:
            type_result = client.query(type_query)
            artifact_types = {row[0]: row[1] for row in type_result.result_rows}
        except Exception as e:
            logger.warning(f"Error getting artifact types: {e}")
    
    return {
        'match_count': match_count,
        'earliest': earliest,
        'latest': latest,
        'artifact_types': artifact_types,
        'match_type_used': effective_match_type
    }


def reset_ioc_types_for_case(case_id: int) -> bool:
    """Reset all ioc_types arrays to empty for a case.
    
    This is called before re-tagging to ensure clean state.
    Uses mutations_sync=1 to wait for completion before returning.
    """
    client = get_fresh_client()
    
    try:
        # Use ALTER TABLE UPDATE for MergeTree with synchronous mutation
        client.command(
            f"ALTER TABLE events UPDATE ioc_types = [] "
            f"WHERE case_id = {case_id} "
            f"SETTINGS mutations_sync = 1"
        )
        logger.info(f"Reset ioc_types for case {case_id}")
        return True
    except Exception as e:
        logger.error(f"Error resetting ioc_types for case {case_id}: {e}")
        return False


def mark_events_with_ioc_type(case_id: int, ioc_value: str, ioc_type: str, 
                              aliases: List[str] = None, match_type: str = None) -> int:
    """Mark matching events with an IOC type.
    
    Adds the IOC type to the ioc_types array for matching events.
    Uses arrayPushBack to append without duplicates.
    
    Uses raw_json with match_type-appropriate matching:
        - token: hasTokenCaseInsensitive() for whole-word matching
        - substring: LIKE for partial matching
        - regex: match() for pattern matching
    
    Returns number of events updated.
    """
    from models.ioc import detect_match_type
    
    client = get_fresh_client()
    
    if not ioc_value:
        return 0
    
    # Get short type name for badge
    short_type = get_short_ioc_type(ioc_type)
    
    # Determine match type - explicit > auto-detected
    effective_match_type = match_type or detect_match_type(ioc_value, ioc_type)
    
    # Build the WHERE clause based on match type
    full_where = build_ioc_match_clause(ioc_value, ioc_type, effective_match_type, aliases)
    
    try:
        # First check how many will be updated
        count_query = f"""
            SELECT count() FROM events 
            WHERE case_id = {case_id}
              AND ({full_where})
              AND NOT has(ioc_types, '{short_type}')
        """
        count_result = client.query(count_query)
        update_count = count_result.result_rows[0][0] if count_result.result_rows else 0
        
        if update_count > 0:
            # Update events to add IOC type (synchronous mutation)
            inline_query = f"""
                ALTER TABLE events UPDATE 
                    ioc_types = arrayPushBack(ioc_types, '{short_type}')
                WHERE case_id = {case_id}
                  AND ({full_where})
                  AND NOT has(ioc_types, '{short_type}')
                SETTINGS mutations_sync = 1
            """
            
            client.command(inline_query)
            logger.debug(f"Marked {update_count} events with IOC type '{short_type}' using {effective_match_type} match")
        
        return update_count
        
    except Exception as e:
        logger.error(f"Error marking events with IOC type: {e}")
        return 0


def get_matching_systems_for_ioc(
    case_id: int,
    ioc_value: str,
    ioc_type: str,
    aliases: List[str] = None,
    match_type: str = None
) -> List[str]:
    """Get list of source_host values that have matches for this IOC.
    
    Used to populate system sightings.
    
    Returns: List of distinct source_host values
    """
    from models.ioc import detect_match_type
    
    client = get_fresh_client()
    
    if not ioc_value:
        return []
    
    # Determine match type
    effective_match_type = match_type or detect_match_type(ioc_value, ioc_type)
    
    # Build the WHERE clause
    where_clause = build_ioc_match_clause(ioc_value, ioc_type, effective_match_type, aliases)
    
    query = f"""
        SELECT DISTINCT source_host
        FROM events 
        WHERE case_id = {case_id}
          AND ({where_clause})
          AND source_host != ''
    """
    
    try:
        result = client.query(query)
        return [row[0] for row in result.result_rows if row[0]]
    except Exception as e:
        logger.error(f"Error getting matching systems for IOC: {e}")
        return []


def tag_all_iocs_globally(case_id: int) -> Dict[str, Any]:
    """Tag all IOCs for this case against the case's artifacts.
    
    Searches case-specific IOCs against the case's artifacts to find matches.
    
    Also marks matching events with IOC types for visual highlighting
    and populates system sightings.
    
    Skips IOCs marked as false positives.
    
    Returns summary of IOC matches, events tagged, and system sightings created.
    """
    from models.ioc import IOC
    from models.known_system import KnownSystem
    from models.database import db
    
    # Get IOCs for THIS case that are active and NOT marked as false positives
    iocs = IOC.query.filter(
        IOC.case_id == case_id,
        IOC.false_positive == False,
        IOC.active == True
    ).all()
    
    total_iocs = len(iocs)
    
    if not iocs:
        clear_tag_progress(case_id)
        return {
            'success': True,
            'total_iocs': 0,
            'iocs_with_matches': 0,
            'total_artifact_matches': 0,
            'events_tagged': 0,
            'system_sightings_created': 0,
            'details': []
        }
    
    results = {
        'success': True,
        'total_iocs': total_iocs,
        'iocs_with_matches': 0,
        'total_artifact_matches': 0,
        'events_tagged': 0,
        'system_sightings_created': 0,
        'details': []
    }
    
    # Initialize progress
    _update_tag_progress(case_id, 0, total_iocs, 'Initializing...', 0)
    
    # Step 1: Reset all ioc_types for this case (clean slate)
    logger.info(f"Resetting ioc_types for case {case_id}")
    reset_ioc_types_for_case(case_id)
    
    # Step 2: Reset per-IOC artifact stats so re-tagging does not leave stale counts.
    for ioc in iocs:
        ioc.artifact_count = 0
        ioc.first_seen_in_artifacts = None
        ioc.last_seen_in_artifacts = None
        ioc.system_sightings.delete(synchronize_session=False)

    # Step 3: Search and mark each IOC
    for idx, ioc in enumerate(iocs):
        # Update progress
        _update_tag_progress(
            case_id, idx, total_iocs, 
            ioc.value, results['total_artifact_matches']
        )
        try:
            # Get effective match type (explicit or auto-detected)
            effective_match_type = ioc.get_effective_match_type()
            
            search_result = search_artifacts_for_ioc(
                case_id=case_id,
                ioc_value=ioc.value,
                ioc_type=ioc.ioc_type,
                aliases=ioc.aliases,
                match_type=effective_match_type
            )
            
            if search_result['match_count'] > 0:
                results['iocs_with_matches'] += 1
                results['total_artifact_matches'] += search_result['match_count']
                
                # Mark matching events with IOC type (with alias validation if available)
                events_marked = mark_events_with_ioc_type(
                    case_id=case_id,
                    ioc_value=ioc.value,
                    ioc_type=ioc.ioc_type,
                    aliases=ioc.aliases,
                    match_type=effective_match_type
                )
                results['events_tagged'] += events_marked
                
                # Get matching systems and create sightings
                matching_hosts = get_matching_systems_for_ioc(
                    case_id=case_id,
                    ioc_value=ioc.value,
                    ioc_type=ioc.ioc_type,
                    aliases=ioc.aliases,
                    match_type=effective_match_type
                )
                
                new_system_sightings = 0
                for hostname in matching_hosts:
                    # Look up KnownSystem by hostname within this case (case-insensitive)
                    system = KnownSystem.query.filter(
                        KnownSystem.case_id == case_id,
                        db.func.lower(KnownSystem.hostname) == hostname.lower()
                    ).first()
                    
                    if system:
                        # Add system sighting (returns True if new sighting created)
                        if ioc.add_system_sighting(system.id, case_id):
                            results['system_sightings_created'] += 1
                            new_system_sightings += 1
                
                # Update artifact stats
                ioc.artifact_count = search_result['match_count']
                
                # Handle datetime comparison - normalize to naive UTC for comparison
                # ClickHouse may return timezone-aware, PostgreSQL stores naive
                earliest = search_result['earliest']
                latest = search_result['latest']
                
                # Strip timezone info if present for comparison
                if earliest and hasattr(earliest, 'tzinfo') and earliest.tzinfo is not None:
                    earliest = earliest.replace(tzinfo=None)
                if latest and hasattr(latest, 'tzinfo') and latest.tzinfo is not None:
                    latest = latest.replace(tzinfo=None)
                
                if earliest:
                    if not ioc.first_seen_in_artifacts or earliest < ioc.first_seen_in_artifacts:
                        ioc.first_seen_in_artifacts = earliest
                if latest:
                    if not ioc.last_seen_in_artifacts or latest > ioc.last_seen_in_artifacts:
                        ioc.last_seen_in_artifacts = latest
                
                results['details'].append({
                    'ioc_id': ioc.id,
                    'ioc_type': ioc.ioc_type,
                    'short_type': get_short_ioc_type(ioc.ioc_type),
                    'value': ioc.value[:50] + ('...' if len(ioc.value) > 50 else ''),
                    'match_count': search_result['match_count'],
                    'artifact_types': search_result['artifact_types'],
                    'events_tagged': events_marked,
                    'system_sightings_created': new_system_sightings
                })
                
        except Exception as e:
            logger.error(f"Error tagging IOC {ioc.id}: {e}")
    
    # Mark progress complete
    _update_tag_progress(case_id, total_iocs, total_iocs, 'Complete', results['total_artifact_matches'])
    
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to commit IOC updates: {e}")
        results['success'] = False
        results['error'] = str(e)
    
    # Clear progress after a short delay (let frontend fetch final state)
    # Progress will auto-expire after 5 minutes anyway
    
    return results
