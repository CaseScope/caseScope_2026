"""Event Deduplication Utility for CaseScope

Post-ingestion deduplication that removes duplicate events from ClickHouse.
Each artifact type has a unique key definition - events matching on all
unique key fields are considered duplicates.

Deduplication keeps the earliest indexed event (by indexed_at) and deletes others.

Progress tracking integrates with the standard progress system for UI feedback.
"""
import logging
from typing import Dict, Any, List, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ArtifactDeduplicationConfig:
    """Configuration for deduplicating a specific artifact type"""
    artifact_type: str
    unique_fields: List[str]  # Fields that together identify a unique event
    description: str


# Unique key definitions per artifact type
# Events matching ALL unique_fields are considered duplicates
ARTIFACT_DEDUP_CONFIGS = [
    ArtifactDeduplicationConfig(
        artifact_type='evtx',
        unique_fields=['source_host', 'source_file', 'record_id'],
        description='Windows Event Logs (by host + file + record ID)'
    ),
    ArtifactDeduplicationConfig(
        artifact_type='prefetch',
        unique_fields=['source_host', 'source_file', 'timestamp'],
        description='Prefetch files (by host + file + execution time)'
    ),
    ArtifactDeduplicationConfig(
        artifact_type='registry',
        unique_fields=['source_host', 'source_file', 'reg_key', 'reg_value', 'timestamp'],
        description='Registry hives (by host + file + key + value + time)'
    ),
    ArtifactDeduplicationConfig(
        artifact_type='browser',
        unique_fields=['source_host', 'source_file', 'timestamp', 'target_path'],
        description='Browser artifacts (by host + file + time + URL/path)'
    ),
    ArtifactDeduplicationConfig(
        artifact_type='lnk',
        unique_fields=['source_host', 'source_file', 'target_path'],
        description='LNK shortcuts (by host + file + target)'
    ),
    ArtifactDeduplicationConfig(
        artifact_type='jumplist',
        unique_fields=['source_host', 'source_file', 'target_path', 'timestamp'],
        description='Jump Lists (by host + file + target + time)'
    ),
    ArtifactDeduplicationConfig(
        artifact_type='huntress',
        unique_fields=['event_id'],
        description='Huntress EDR (by event UUID)'
    ),
    ArtifactDeduplicationConfig(
        artifact_type='scheduled_task',
        unique_fields=['source_host', 'source_file', 'target_path'],
        description='Scheduled Tasks (by host + file + task path)'
    ),
    ArtifactDeduplicationConfig(
        artifact_type='mft',
        unique_fields=['source_host', 'source_file', 'record_id', 'timestamp'],
        description='MFT records (by host + file + record + time)'
    ),
    ArtifactDeduplicationConfig(
        artifact_type='activities_cache',
        unique_fields=['source_host', 'source_file', 'timestamp', 'target_path'],
        description='Activities Cache (by host + file + time + path)'
    ),
    ArtifactDeduplicationConfig(
        artifact_type='webcache',
        unique_fields=['source_host', 'source_file', 'timestamp', 'target_path'],
        description='WebCache (by host + file + time + URL)'
    ),
    ArtifactDeduplicationConfig(
        artifact_type='srum',
        unique_fields=['source_host', 'source_file', 'timestamp', 'process_name'],
        description='SRUM database (by host + file + time + process)'
    ),
    ArtifactDeduplicationConfig(
        artifact_type='iis',
        unique_fields=['source_host', 'source_file', 'timestamp', 'src_ip', 'target_path'],
        description='IIS logs (by host + file + time + client + URL)'
    ),
    ArtifactDeduplicationConfig(
        artifact_type='firewall',
        unique_fields=['source_host', 'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port'],
        description='Firewall logs (by host + time + connection tuple)'
    ),
    ArtifactDeduplicationConfig(
        artifact_type='json_log',
        unique_fields=['source_file', 'timestamp', 'event_id'],
        description='JSON logs (by file + time + event ID)'
    ),
    ArtifactDeduplicationConfig(
        artifact_type='csv_log',
        unique_fields=['source_file', 'timestamp', 'search_blob'],
        description='CSV logs (by file + time + content hash)'
    ),
    ArtifactDeduplicationConfig(
        artifact_type='firefox_session',
        unique_fields=['source_host', 'source_file', 'timestamp', 'target_path'],
        description='Firefox session data (by host + file + time + URL)'
    ),
    ArtifactDeduplicationConfig(
        artifact_type='sonicwall',
        unique_fields=['source_file', 'timestamp', 'src_ip', 'dst_ip', 'event_id'],
        description='SonicWall logs (by file + time + IPs + event)'
    ),
]


def get_dedup_config(artifact_type: str) -> ArtifactDeduplicationConfig:
    """Get deduplication config for an artifact type"""
    for config in ARTIFACT_DEDUP_CONFIGS:
        if config.artifact_type == artifact_type:
            return config
    return None


def build_non_null_condition(fields: List[str]) -> str:
    """Build SQL condition to exclude events with NULL/empty unique fields.
    
    Events with NULL or empty string values in unique fields cannot be
    reliably deduplicated (NULL = NULL is undefined in SQL), so we
    exclude them from deduplication entirely.
    
    Args:
        fields: List of field names that must be non-null
        
    Returns:
        SQL condition string like "(field1 IS NOT NULL AND field1 != '') AND ..."
    """
    conditions = []
    for field in fields:
        # String fields: check for NULL and empty string
        # Integer fields (like record_id): just check for NULL
        if field in ('record_id', 'file_size'):
            conditions.append(f"{field} IS NOT NULL")
        else:
            conditions.append(f"({field} IS NOT NULL AND {field} != '')")
    return ' AND '.join(conditions)


def count_duplicates_for_artifact(client, case_id: int, config: ArtifactDeduplicationConfig) -> int:
    """Count duplicate events for a specific artifact type.
    
    Only considers events where all unique fields are non-null/non-empty.
    Events with NULL/empty unique fields are excluded from deduplication.
    
    Args:
        client: ClickHouse client
        case_id: Case ID
        config: Deduplication config for this artifact type
        
    Returns:
        Number of duplicate events (total - unique) among eligible events
    """
    unique_fields_sql = ', '.join(config.unique_fields)
    non_null_condition = build_non_null_condition(config.unique_fields)
    
    # Count total eligible events (those with all unique fields populated)
    total_result = client.query(
        f"""SELECT count() FROM events 
            WHERE case_id = {{case_id:UInt32}} 
            AND artifact_type = {{artifact_type:String}}
            AND {non_null_condition}""",
        parameters={'case_id': case_id, 'artifact_type': config.artifact_type}
    )
    total = total_result.result_rows[0][0] if total_result.result_rows else 0
    
    if total == 0:
        return 0
    
    # Count unique combinations among eligible events
    unique_result = client.query(
        f"""SELECT count() FROM (
            SELECT {unique_fields_sql}
            FROM events 
            WHERE case_id = {{case_id:UInt32}} 
            AND artifact_type = {{artifact_type:String}}
            AND {non_null_condition}
            GROUP BY {unique_fields_sql}
        )""",
        parameters={'case_id': case_id, 'artifact_type': config.artifact_type}
    )
    unique = unique_result.result_rows[0][0] if unique_result.result_rows else 0
    
    return total - unique


def deduplicate_artifact_type(client, case_id: int, config: ArtifactDeduplicationConfig) -> Dict[str, Any]:
    """Deduplicate events for a specific artifact type.
    
    Uses a two-step approach:
    1. Find all duplicate groups (combinations appearing more than once)
    2. For each group, keep the earliest indexed_at, delete the rest
    
    Only considers events where all unique fields are non-null/non-empty.
    Events with NULL/empty unique fields are excluded from deduplication
    since NULL comparisons are unreliable.
    
    Args:
        client: ClickHouse client
        case_id: Case ID
        config: Deduplication config
        
    Returns:
        Dict with deduplication results
    """
    unique_fields_sql = ', '.join(config.unique_fields)
    non_null_condition = build_non_null_condition(config.unique_fields)
    
    # First, count duplicates to check if there's work to do
    duplicate_count = count_duplicates_for_artifact(client, case_id, config)
    
    if duplicate_count == 0:
        return {
            'artifact_type': config.artifact_type,
            'duplicates_found': 0,
            'duplicates_deleted': 0,
            'success': True
        }
    
    logger.info(f"Found {duplicate_count} duplicate {config.artifact_type} events for case {case_id}")
    
    try:
        # Build the DELETE query using a safer approach
        # ClickHouse doesn't handle correlated subqueries in DELETE properly
        # So we use a different strategy:
        # 1. Create a subquery that finds all (unique_key, min_indexed_at) pairs
        # 2. Delete events where (unique_key, indexed_at) is NOT IN that set
        #    but the unique_key IS in the set of duplicated keys
        #
        # IMPORTANT: Only consider events with all unique fields populated.
        # Events with NULL/empty unique fields are excluded since NULL = NULL
        # is undefined in SQL and would cause incorrect deduplication.
        
        # Build tuple of unique fields for comparison
        unique_tuple = f"({', '.join(config.unique_fields)})"
        unique_tuple_with_time = f"({', '.join(config.unique_fields)}, indexed_at)"
        
        delete_query = f"""
            ALTER TABLE events DELETE 
            WHERE case_id = {case_id}
              AND artifact_type = '{config.artifact_type}'
              AND {non_null_condition}
              AND {unique_tuple} IN (
                  SELECT {', '.join(config.unique_fields)}
                  FROM events
                  WHERE case_id = {case_id}
                    AND artifact_type = '{config.artifact_type}'
                    AND {non_null_condition}
                  GROUP BY {', '.join(config.unique_fields)}
                  HAVING count() > 1
              )
              AND {unique_tuple_with_time} NOT IN (
                  SELECT {', '.join(config.unique_fields)}, min(indexed_at)
                  FROM events
                  WHERE case_id = {case_id}
                    AND artifact_type = '{config.artifact_type}'
                    AND {non_null_condition}
                  GROUP BY {', '.join(config.unique_fields)}
                  HAVING count() > 1
              )
        """
        
        # Execute deletion
        client.command(delete_query)
        
        logger.info(f"Deleted {duplicate_count} duplicate {config.artifact_type} events for case {case_id}")
        
        return {
            'artifact_type': config.artifact_type,
            'description': config.description,
            'duplicates_found': duplicate_count,
            'duplicates_deleted': duplicate_count,
            'success': True
        }
        
    except Exception as e:
        logger.error(f"Error deduplicating {config.artifact_type} for case {case_id}: {e}")
        return {
            'artifact_type': config.artifact_type,
            'description': config.description,
            'duplicates_found': duplicate_count,
            'duplicates_deleted': 0,
            'success': False,
            'error': str(e)
        }


def deduplicate_case_events(case_id: int, case_uuid: str = None, 
                           track_progress: bool = True) -> Dict[str, Any]:
    """Deduplicate all events for a case across all artifact types.
    
    Runs deduplication for each artifact type that has events.
    Tracks progress via Redis for UI feedback.
    
    Args:
        case_id: PostgreSQL/ClickHouse case ID
        case_uuid: Case UUID (for progress tracking)
        track_progress: Whether to update progress in Redis
        
    Returns:
        Dict with summary of deduplication results
    """
    from utils.clickhouse import get_fresh_client
    
    logger.info(f"Starting event deduplication for case {case_id}")
    
    client = get_fresh_client()
    
    # Get list of artifact types with events in this case
    types_result = client.query(
        """SELECT DISTINCT artifact_type, count() as cnt
           FROM events 
           WHERE case_id = {case_id:UInt32}
           GROUP BY artifact_type
           ORDER BY cnt DESC""",
        parameters={'case_id': case_id}
    )
    
    artifact_types_in_case = {row[0]: row[1] for row in types_result.result_rows}
    
    if not artifact_types_in_case:
        logger.info(f"No events found for case {case_id}, skipping deduplication")
        return {
            'success': True,
            'case_id': case_id,
            'artifact_types_checked': 0,
            'total_duplicates_found': 0,
            'total_duplicates_deleted': 0,
            'details': [],
            'message': 'No events to deduplicate'
        }
    
    # Set progress phase if tracking
    if track_progress and case_uuid:
        from utils.progress import set_phase, increment_phase, set_current_item
        # Count how many artifact types we'll process
        types_to_process = [c for c in ARTIFACT_DEDUP_CONFIGS 
                          if c.artifact_type in artifact_types_in_case]
        set_phase(case_uuid, 'deduplication', total=len(types_to_process))
    
    results = []
    total_found = 0
    total_deleted = 0
    errors = []
    
    # Process each artifact type that has events
    for config in ARTIFACT_DEDUP_CONFIGS:
        if config.artifact_type not in artifact_types_in_case:
            continue
        
        event_count = artifact_types_in_case[config.artifact_type]
        logger.debug(f"Checking {config.artifact_type}: {event_count} events")
        
        # Update progress
        if track_progress and case_uuid:
            set_current_item(case_uuid, f"Deduplicating {config.artifact_type}...")
        
        # Run deduplication
        result = deduplicate_artifact_type(client, case_id, config)
        results.append(result)
        
        total_found += result.get('duplicates_found', 0)
        total_deleted += result.get('duplicates_deleted', 0)
        
        if not result.get('success'):
            errors.append(f"{config.artifact_type}: {result.get('error', 'Unknown error')}")
        
        # Increment progress
        if track_progress and case_uuid:
            increment_phase(case_uuid, 'deduplication')
    
    # Build summary
    summary = {
        'success': len(errors) == 0,
        'case_id': case_id,
        'artifact_types_checked': len(results),
        'total_duplicates_found': total_found,
        'total_duplicates_deleted': total_deleted,
        'details': [r for r in results if r.get('duplicates_found', 0) > 0],  # Only include types with dups
        'errors': errors if errors else None
    }
    
    if total_deleted > 0:
        summary['message'] = f"Removed {total_deleted} duplicate events across {len(summary['details'])} artifact types"
        logger.info(f"Deduplication complete for case {case_id}: {summary['message']}")
    else:
        summary['message'] = 'No duplicates found'
        logger.info(f"Deduplication complete for case {case_id}: no duplicates found")
    
    return summary


def get_duplicate_summary(case_id: int) -> Dict[str, Any]:
    """Get a summary of potential duplicates for a case (without deleting).
    
    Useful for previewing what would be deduplicated.
    
    Args:
        case_id: Case ID
        
    Returns:
        Dict with duplicate counts per artifact type
    """
    from utils.clickhouse import get_fresh_client
    
    client = get_fresh_client()
    
    # Get artifact types with events
    types_result = client.query(
        """SELECT DISTINCT artifact_type FROM events WHERE case_id = {case_id:UInt32}""",
        parameters={'case_id': case_id}
    )
    
    artifact_types = [row[0] for row in types_result.result_rows]
    
    summary = {
        'case_id': case_id,
        'total_duplicates': 0,
        'by_artifact_type': {}
    }
    
    for config in ARTIFACT_DEDUP_CONFIGS:
        if config.artifact_type not in artifact_types:
            continue
        
        dup_count = count_duplicates_for_artifact(client, case_id, config)
        
        if dup_count > 0:
            summary['by_artifact_type'][config.artifact_type] = {
                'duplicate_count': dup_count,
                'description': config.description,
                'unique_fields': config.unique_fields
            }
            summary['total_duplicates'] += dup_count
    
    return summary
