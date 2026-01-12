"""IOC Artifact Tagger for CaseScope

Searches ClickHouse artifacts for IOC matches and updates artifact counts.
Handles partial matching (e.g., "winscp.exe" in "c:\\windows\\winscp.exe")
and case-insensitive comparisons.
"""
import os
import re
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any

from utils.clickhouse import get_fresh_client

logger = logging.getLogger(__name__)


def extract_searchable_terms(value: str, ioc_type: str) -> List[str]:
    """Extract searchable terms from an IOC value.
    
    For file paths, extracts the filename.
    For command lines, extracts executables.
    For other types, returns the value as-is plus any useful substrings.
    
    Returns list of terms to search for (case-insensitive).
    """
    terms = []
    value = value.strip()
    
    if not value:
        return terms
    
    # Always add the full value (lowercase for comparison)
    terms.append(value.lower())
    
    if ioc_type in ('File Path', 'Process Path'):
        # Extract filename from path
        # Handle both Windows and Unix paths
        filename = os.path.basename(value.replace('\\', '/'))
        if filename and filename.lower() != value.lower():
            terms.append(filename.lower())
        
        # Also try just the name without extension for common executables
        name_no_ext = os.path.splitext(filename)[0]
        if name_no_ext and len(name_no_ext) > 2:
            # Only add if it's a meaningful name (not just "a" or similar)
            terms.append(name_no_ext.lower())
    
    elif ioc_type == 'File Name':
        # Add name without extension as well
        name_no_ext = os.path.splitext(value)[0]
        if name_no_ext and name_no_ext.lower() != value.lower():
            terms.append(name_no_ext.lower())
    
    elif ioc_type == 'Command Line':
        # Extract executable names from command line
        # Look for .exe, .bat, .cmd, .ps1, etc.
        exe_pattern = r'[\\/]?([a-zA-Z0-9_\-\.]+\.(exe|bat|cmd|ps1|vbs|js|dll|msi))'
        matches = re.findall(exe_pattern, value, re.IGNORECASE)
        for match in matches:
            terms.append(match[0].lower())
        
        # Also try to extract the first token (likely the executable)
        first_token = value.split()[0] if value.split() else ''
        if first_token:
            # Remove quotes
            first_token = first_token.strip('"\'')
            # Get just filename if it's a path
            first_token_name = os.path.basename(first_token.replace('\\', '/'))
            if first_token_name:
                terms.append(first_token_name.lower())
    
    elif ioc_type == 'Process Name':
        # Add without .exe extension if present
        if value.lower().endswith('.exe'):
            terms.append(value[:-4].lower())
    
    elif ioc_type in ('Registry Key', 'Registry Value'):
        # For registry, also search for the last component
        parts = value.replace('/', '\\').split('\\')
        if len(parts) > 1 and parts[-1]:
            terms.append(parts[-1].lower())
    
    elif ioc_type in ('Domain', 'FQDN', 'Hostname'):
        # Domain matching - also try just the hostname part
        parts = value.split('.')
        if len(parts) > 1:
            terms.append(parts[0].lower())  # Just the hostname
    
    elif ioc_type == 'URL':
        # Extract domain/hostname from URL
        domain_match = re.search(r'://([^/]+)', value)
        if domain_match:
            domain = domain_match.group(1)
            # Remove port if present
            domain = domain.split(':')[0]
            terms.append(domain.lower())
    
    # Deduplicate while preserving order
    seen = set()
    unique_terms = []
    for term in terms:
        if term and term not in seen and len(term) >= 2:
            seen.add(term)
            unique_terms.append(term)
    
    return unique_terms


def search_artifacts_for_ioc(
    case_id: int,
    ioc_value: str,
    ioc_type: str,
    limit: int = 1000
) -> Dict[str, Any]:
    """Search ClickHouse artifacts for an IOC.
    
    Uses case-insensitive partial matching on search_blob.
    
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
    
    # Get searchable terms
    search_terms = extract_searchable_terms(ioc_value, ioc_type)
    
    if not search_terms:
        return {
            'match_count': 0,
            'earliest': None,
            'latest': None,
            'artifact_types': {},
            'matched_terms': []
        }
    
    # Build OR query for all terms
    # Using case-insensitive LIKE on search_blob
    conditions = []
    params = {'case_id': case_id}
    
    for i, term in enumerate(search_terms):
        # Escape special characters for LIKE
        escaped_term = term.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
        params[f'term_{i}'] = f'%{escaped_term}%'
        conditions.append(f"lower(search_blob) LIKE {{term_{i}:String}}")
    
    where_clause = ' OR '.join(conditions)
    
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
            'matched_terms': search_terms
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
        'matched_terms': search_terms
    }


def tag_all_iocs_for_case(case_id: int) -> Dict[str, Any]:
    """Tag all IOCs linked to a case by searching artifacts.
    
    Updates artifact_count, first_seen_in_artifacts, last_seen_in_artifacts
    for each IOC based on actual ClickHouse search results.
    
    Returns summary of updates made.
    """
    from models.ioc import IOC, IOCCase
    from models.database import db
    
    # Get all IOCs linked to this case (excluding false positives)
    ioc_links = IOCCase.query.filter_by(case_id=case_id).all()
    ioc_ids = [link.ioc_id for link in ioc_links]
    
    if not ioc_ids:
        return {
            'success': True,
            'total_iocs': 0,
            'iocs_with_matches': 0,
            'total_artifact_matches': 0,
            'details': []
        }
    
    # Filter out false positives
    iocs = IOC.query.filter(
        IOC.id.in_(ioc_ids),
        IOC.false_positive == False
    ).all()
    
    results = {
        'success': True,
        'total_iocs': len(iocs),
        'iocs_with_matches': 0,
        'total_artifact_matches': 0,
        'details': []
    }
    
    for ioc in iocs:
        try:
            search_result = search_artifacts_for_ioc(
                case_id=case_id,
                ioc_value=ioc.value,
                ioc_type=ioc.ioc_type
            )
            
            detail = {
                'ioc_id': ioc.id,
                'ioc_type': ioc.ioc_type,
                'value': ioc.value[:50] + ('...' if len(ioc.value) > 50 else ''),
                'match_count': search_result['match_count'],
                'searched_terms': search_result['matched_terms'],
                'artifact_types': search_result['artifact_types']
            }
            
            if search_result['match_count'] > 0:
                results['iocs_with_matches'] += 1
                results['total_artifact_matches'] += search_result['match_count']
                
                # Update IOC record
                ioc.artifact_count = search_result['match_count']
                
                if search_result['earliest']:
                    ioc.first_seen_in_artifacts = search_result['earliest']
                if search_result['latest']:
                    ioc.last_seen_in_artifacts = search_result['latest']
            else:
                # Reset counts if no matches found
                ioc.artifact_count = 0
            
            results['details'].append(detail)
            
        except Exception as e:
            logger.error(f"Error tagging IOC {ioc.id}: {e}")
            results['details'].append({
                'ioc_id': ioc.id,
                'ioc_type': ioc.ioc_type,
                'value': ioc.value[:50],
                'error': str(e)
            })
    
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to commit IOC updates: {e}")
        results['success'] = False
        results['error'] = str(e)
    
    return results


def tag_all_iocs_globally(case_id: int) -> Dict[str, Any]:
    """Tag ALL IOCs in the database against a specific case's artifacts.
    
    This searches every IOC (not just case-linked ones) against
    the case's artifacts to find new matches.
    
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
            'details': []
        }
    
    results = {
        'success': True,
        'total_iocs': len(iocs),
        'iocs_with_matches': 0,
        'new_links_created': 0,
        'total_artifact_matches': 0,
        'details': []
    }
    
    for ioc in iocs:
        try:
            search_result = search_artifacts_for_ioc(
                case_id=case_id,
                ioc_value=ioc.value,
                ioc_type=ioc.ioc_type
            )
            
            if search_result['match_count'] > 0:
                results['iocs_with_matches'] += 1
                results['total_artifact_matches'] += search_result['match_count']
                
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
                if search_result['earliest']:
                    if not ioc.first_seen_in_artifacts or search_result['earliest'] < ioc.first_seen_in_artifacts:
                        ioc.first_seen_in_artifacts = search_result['earliest']
                if search_result['latest']:
                    if not ioc.last_seen_in_artifacts or search_result['latest'] > ioc.last_seen_in_artifacts:
                        ioc.last_seen_in_artifacts = search_result['latest']
                
                results['details'].append({
                    'ioc_id': ioc.id,
                    'ioc_type': ioc.ioc_type,
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
