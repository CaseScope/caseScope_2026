"""IOC Artifact Tagger for CaseScope

Searches ClickHouse artifacts for IOC matches and updates artifact counts.
Handles partial matching (e.g., "winscp.exe" in "c:\\windows\\winscp.exe")
and case-insensitive comparisons.

Also marks matching events with IOC types for visual highlighting.
"""
import os
import re
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any

from utils.clickhouse import get_fresh_client

logger = logging.getLogger(__name__)


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


def build_search_conditions(search_terms: List[Tuple[str, bool]], param_prefix: str = 'term') -> Tuple[str, Dict]:
    """Build SQL WHERE conditions and parameters for search terms.
    
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
    limit: int = 1000
) -> Dict[str, Any]:
    """Search ClickHouse artifacts for an IOC.
    
    Uses case-insensitive partial matching on search_blob.
    
    If aliases are provided, uses two-tier matching:
    1. Find events matching the primary IOC value
    2. Count only events where an alias also matches
    
    Returns:
        {
            'match_count': int,
            'earliest': datetime or None,
            'latest': datetime or None,
            'artifact_types': dict of type -> count,
            'matched_terms': list of which search terms matched
        }
    """
    client = get_fresh_client()
    
    # Get searchable terms from primary value
    search_terms = extract_searchable_terms(ioc_value, ioc_type)
    
    if not search_terms:
        return {
            'match_count': 0,
            'earliest': None,
            'latest': None,
            'artifact_types': {},
            'matched_terms': []
        }
    
    where_clause, params = build_search_conditions(search_terms)
    
    # For certain types, also search dedicated columns for more precise matching
    # Column matches are added as OR conditions (don't require alias validation)
    column_conditions = []
    
    if ioc_type == 'Username':
        # Search username column directly (exact match)
        params['username_val'] = ioc_value.lower()
        column_conditions.append(f"lower(username) = {{username_val:String}}")
        # If we have aliases (which may include SID), search sid column too
        if aliases:
            for i, alias in enumerate(aliases):
                if alias and alias.startswith('S-1-'):  # SID pattern
                    params[f'sid_val_{i}'] = alias
                    column_conditions.append(f"sid = {{sid_val_{i}:String}}")
    elif ioc_type == 'Hostname':
        # Search source_host column directly (exact match)
        params['hostname_val'] = ioc_value.lower()
        column_conditions.append(f"lower(source_host) = {{hostname_val:String}}")
    elif ioc_type == 'SID':
        # Search sid column directly (exact match)
        params['sid_exact'] = ioc_value
        column_conditions.append(f"sid = {{sid_exact:String}}")
    
    # Build the search_blob clause with optional alias validation
    search_blob_clause = where_clause
    if aliases and len(aliases) > 0:
        alias_conditions = []
        for i, alias in enumerate(aliases):
            escaped_alias = alias.lower().replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
            param_name = f'alias_{i}'
            params[param_name] = f'%{escaped_alias}%'
            alias_conditions.append(f"lower(search_blob) LIKE {{{param_name}:String}}")
        
        alias_clause = ' OR '.join(alias_conditions)
        search_blob_clause = f"({where_clause}) AND ({alias_clause})"
    
    # Combine: column matches OR (search_blob matches with alias validation)
    if column_conditions:
        column_clause = ' OR '.join(column_conditions)
        where_clause = f"({column_clause}) OR ({search_blob_clause})"
    else:
        where_clause = search_blob_clause
    
    params['case_id'] = case_id
    
    # Get aggregate stats
    query = f"""
        SELECT 
            count() as cnt,
            min(timestamp) as earliest,
            max(timestamp) as latest
        FROM events 
        WHERE case_id = {{case_id:UInt32}} 
          AND ({where_clause})
    """
    
    try:
        result = client.query(query, parameters=params)
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
            'matched_terms': [term for term, _ in search_terms]
        }
    
    # Get artifact type breakdown if we have matches
    artifact_types = {}
    if match_count > 0:
        type_query = f"""
            SELECT artifact_type, count() as cnt
            FROM events 
            WHERE case_id = {{case_id:UInt32}} 
              AND ({where_clause})
            GROUP BY artifact_type
            ORDER BY cnt DESC
        """
        
        try:
            type_result = client.query(type_query, parameters=params)
            artifact_types = {row[0]: row[1] for row in type_result.result_rows}
        except Exception as e:
            logger.warning(f"Error getting artifact types: {e}")
    
    return {
        'match_count': match_count,
        'earliest': earliest,
        'latest': latest,
        'artifact_types': artifact_types,
        'matched_terms': [term for term, _ in search_terms]
    }


def reset_ioc_types_for_case(case_id: int) -> bool:
    """Reset all ioc_types arrays to empty for a case.
    
    This is called before re-tagging to ensure clean state.
    """
    client = get_fresh_client()
    
    try:
        # Use ALTER TABLE UPDATE for MergeTree
        client.command(
            f"ALTER TABLE events UPDATE ioc_types = [] WHERE case_id = {case_id}"
        )
        logger.info(f"Reset ioc_types for case {case_id}")
        return True
    except Exception as e:
        logger.error(f"Error resetting ioc_types for case {case_id}: {e}")
        return False


def mark_events_with_ioc_type(case_id: int, ioc_value: str, ioc_type: str, aliases: List[str] = None) -> int:
    """Mark matching events with an IOC type.
    
    Adds the IOC type to the ioc_types array for matching events.
    Uses arrayPushBack to append without duplicates.
    
    If aliases are provided, uses two-tier matching:
    1. Find events matching the primary IOC value
    2. Only mark events where an alias also matches (contextual validation)
    
    If no aliases, marks all events matching the primary value.
    
    Returns number of events updated.
    """
    client = get_fresh_client()
    
    search_terms = extract_searchable_terms(ioc_value, ioc_type)
    if not search_terms:
        return 0
    
    # Get short type name for badge
    short_type = get_short_ioc_type(ioc_type)
    
    # Build the primary search conditions
    primary_conditions = []
    for term, is_filename in search_terms:
        escaped_term = term.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_').replace("'", "\\'")
        if is_filename:
            # Word-boundary matching for filenames
            primary_conditions.append(
                f"(lower(search_blob) LIKE '%\\\\{escaped_term}%' "
                f"OR lower(search_blob) LIKE '%/{escaped_term}%' "
                f"OR lower(search_blob) LIKE '% {escaped_term}%' "
                f"OR lower(search_blob) LIKE '%\"{escaped_term}%')"
            )
        else:
            primary_conditions.append(f"lower(search_blob) LIKE '%{escaped_term}%'")
    
    primary_where = ' OR '.join(primary_conditions)
    
    # If aliases exist, add alias validation conditions
    # Events must match BOTH the primary IOC AND at least one alias
    if aliases and len(aliases) > 0:
        alias_conditions = []
        for alias in aliases:
            # Aliases should be matched as substrings
            escaped_alias = alias.lower().replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_').replace("'", "\\'")
            alias_conditions.append(f"lower(search_blob) LIKE '%{escaped_alias}%'")
        
        alias_where = ' OR '.join(alias_conditions)
        full_where = f"({primary_where}) AND ({alias_where})"
    else:
        # No aliases - any match on primary value counts
        full_where = primary_where
    
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
            # Update events to add IOC type
            inline_query = f"""
                ALTER TABLE events UPDATE 
                    ioc_types = arrayPushBack(ioc_types, '{short_type}')
                WHERE case_id = {case_id}
                  AND ({full_where})
                  AND NOT has(ioc_types, '{short_type}')
            """
            
            client.command(inline_query)
            logger.debug(f"Marked {update_count} events with IOC type '{short_type}' (aliases: {len(aliases) if aliases else 0})")
        
        return update_count
        
    except Exception as e:
        logger.error(f"Error marking events with IOC type: {e}")
        return 0


def tag_all_iocs_globally(case_id: int) -> Dict[str, Any]:
    """Tag ALL IOCs in the database against a specific case's artifacts.
    
    This searches every IOC (not just case-linked ones) against
    the case's artifacts to find new matches.
    
    Also marks matching events with IOC types for visual highlighting.
    
    Skips IOCs marked as false positives.
    
    Returns summary of updates and new links created.
    """
    from models.ioc import IOC, IOCCase
    from models.database import db
    
    # Get all IOCs that are NOT marked as false positives
    iocs = IOC.query.filter(IOC.false_positive == False).all()
    
    if not iocs:
        return {
            'success': True,
            'total_iocs': 0,
            'iocs_with_matches': 0,
            'new_links_created': 0,
            'total_artifact_matches': 0,
            'events_tagged': 0,
            'details': []
        }
    
    results = {
        'success': True,
        'total_iocs': len(iocs),
        'iocs_with_matches': 0,
        'new_links_created': 0,
        'total_artifact_matches': 0,
        'events_tagged': 0,
        'details': []
    }
    
    # Step 1: Reset all ioc_types for this case (clean slate)
    logger.info(f"Resetting ioc_types for case {case_id}")
    reset_ioc_types_for_case(case_id)
    
    # Step 2: Search and mark each IOC
    for ioc in iocs:
        try:
            search_result = search_artifacts_for_ioc(
                case_id=case_id,
                ioc_value=ioc.value,
                ioc_type=ioc.ioc_type,
                aliases=ioc.aliases
            )
            
            if search_result['match_count'] > 0:
                results['iocs_with_matches'] += 1
                results['total_artifact_matches'] += search_result['match_count']
                
                # Mark matching events with IOC type (with alias validation if available)
                events_marked = mark_events_with_ioc_type(
                    case_id=case_id,
                    ioc_value=ioc.value,
                    ioc_type=ioc.ioc_type,
                    aliases=ioc.aliases
                )
                results['events_tagged'] += events_marked
                
                # Check if already linked to case
                existing_link = IOCCase.query.filter_by(
                    ioc_id=ioc.id,
                    case_id=case_id
                ).first()
                
                if not existing_link:
                    # Create new link
                    new_link = IOCCase(
                        ioc_id=ioc.id,
                        case_id=case_id
                    )
                    db.session.add(new_link)
                    results['new_links_created'] += 1
                
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
                    'was_linked': existing_link is not None
                })
                
        except Exception as e:
            logger.error(f"Error tagging IOC {ioc.id}: {e}")
    
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to commit IOC updates: {e}")
        results['success'] = False
        results['error'] = str(e)
    
    return results
