"""
Unified Bulk Operations Module (v1.15.0 - Phase 1 Refactoring)
Handles bulk file operations for both case-specific and global scopes

REFACTORING GOALS:
- Eliminate duplicate code between bulk_operations.py and bulk_operations_global.py
- Single source of truth for all bulk operations
- Scope parameter ('case' or 'global') determines behavior
- All routes use same unified functions
"""

import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


# ============================================================================
# FILE RETRIEVAL (scope-aware)
# ============================================================================

def get_files(db, scope: str = 'case', case_id: Optional[int] = None, 
              file_ids: Optional[List[int]] = None,
              include_deleted: bool = False, 
              include_hidden: bool = False) -> List[Any]:
    """
    Get files based on scope (unified function for case/global)
    
    Args:
        db: Database session
        scope: 'case' (single case) or 'global' (all cases)
        case_id: Required if scope='case'
        file_ids: Optional list of specific file IDs (for selected files)
        include_deleted: Include soft-deleted files
        include_hidden: Include hidden (0-event) files
        
    Returns:
        List of CaseFile objects
    """
    from models import CaseFile
    
    query = db.session.query(CaseFile)
    
    # Apply scope filter
    if scope == 'case':
        if case_id is None:
            raise ValueError("case_id required when scope='case'")
        query = query.filter_by(case_id=case_id)
    elif scope == 'global':
        pass  # No filter - get all cases
    else:
        raise ValueError(f"Invalid scope: {scope}. Must be 'case' or 'global'")
    
    # Apply file_ids filter (for selected files)
    if file_ids:
        query = query.filter(CaseFile.id.in_(file_ids))
    
    # Apply deleted/hidden filters
    if not include_deleted:
        query = query.filter_by(is_deleted=False)
    
    if not include_hidden:
        query = query.filter_by(is_hidden=False)
    
    files = query.all()
    
    scope_desc = f"case {case_id}" if scope == 'case' else "all cases"
    logger.info(f"[BULK OPS] [{scope.upper()}] Retrieved {len(files)} file(s) from {scope_desc}")
    
    return files


# ============================================================================
# OPENSEARCH OPERATIONS (scope-aware)
# ============================================================================

def clear_opensearch_events(opensearch_client, files: List[Any], 
                            scope: str = 'case', case_id: Optional[int] = None) -> int:
    """
    Clear OpenSearch events for files (unified for case/global)
    
    Args:
        opensearch_client: OpenSearch client instance
        files: List of CaseFile objects
        scope: 'case' or 'global'
        case_id: Required if scope='case' (for optimization)
    
    Returns:
        Number of events deleted
    """
    from utils import make_index_name
    
    if scope == 'case' and case_id:
        # Optimized: single case, single index
        index_name = make_index_name(case_id)
        deleted_count = 0
        
        # v1.27.15: Check if we're clearing ALL files in the case
        # If so, DELETE the entire index for a true "fresh start"
        # This ensures: (1) Fresh 50K field limit, (2) No old mappings, (3) No timeout issues
        from main import CaseFile, db
        total_case_files = db.session.query(CaseFile).filter(
            CaseFile.case_id == case_id,
            CaseFile.is_deleted == False,
            CaseFile.is_hidden == False
        ).count()
        
        # v1.27.16: Use len(files) instead of checking opensearch_key
        # because reset_file_metadata() may have already cleared it
        files_to_clear = len(files)
        
        logger.info(f"[BULK OPS] [{scope.upper()}] Threshold check: {files_to_clear}/{total_case_files} files ({(files_to_clear/total_case_files*100):.1f}% >= 95%?)")
        
        # If clearing ALL files (or close to it), delete entire index
        if files_to_clear >= total_case_files * 0.95:  # 95% threshold
            try:
                logger.info(f"[BULK OPS] [{scope.upper()}] Deleting entire index {index_name} (clearing {files_to_clear}/{total_case_files} files)")
                result = opensearch_client.indices.delete(index=index_name, ignore=[404])
                logger.info(f"[BULK OPS] [{scope.upper()}] Deleted index {index_name} - will be recreated with fresh 50K field limit")
                # Return 0 since we don't know exact event count (index deleted)
                return 0
            except Exception as e:
                logger.warning(f"[BULK OPS] [{scope.upper()}] Could not delete index {index_name}: {e}, falling back to per-file deletion")
                # Fall through to per-file deletion if index delete fails
        else:
            logger.info(f"[BULK OPS] [{scope.upper()}] Using per-file deletion (threshold not met)")
        
        # Per-file deletion (for partial reindex of selected files)
        for f in files:
            if f.opensearch_key:
                try:
                    result = opensearch_client.delete_by_query(
                        index=index_name,
                        body={"query": {"term": {"file_id": f.id}}},
                        conflicts='proceed',
                        ignore=[404]
                    )
                    event_count = result.get('deleted', 0) if isinstance(result, dict) else 0
                    logger.debug(f"[BULK OPS] [{scope.upper()}] Deleted {event_count} events for file {f.id}")
                    deleted_count += event_count
                except Exception as e:
                    logger.warning(f"[BULK OPS] [{scope.upper()}] Could not delete events for file {f.id}: {e}")
        
        logger.info(f"[BULK OPS] [{scope.upper()}] Deleted {deleted_count} events from case {case_id}")
        return deleted_count
    
    else:
        # Global or multi-case: group files by case_id
        files_by_case = {}
        for f in files:
            if f.case_id not in files_by_case:
                files_by_case[f.case_id] = []
            files_by_case[f.case_id].append(f)
        
        total_deleted = 0
        
        for cid, case_files in files_by_case.items():
            index_name = make_index_name(cid)
            
            for f in case_files:
                if f.opensearch_key:
                    try:
                        result = opensearch_client.delete_by_query(
                            index=index_name,
                            body={"query": {"term": {"file_id": f.id}}},
                            conflicts='proceed',
                            ignore=[404]
                        )
                        event_count = result.get('deleted', 0) if isinstance(result, dict) else 0
                        total_deleted += event_count
                    except Exception as e:
                        logger.warning(f"[BULK OPS] [{scope.upper()}] Could not delete events for file {f.id}: {e}")
        
        logger.info(f"[BULK OPS] [{scope.upper()}] Deleted {total_deleted} events across {len(files_by_case)} case(s)")
        return total_deleted


def clear_ioc_flags_in_opensearch(opensearch_client, files: List[Any],
                                 scope: str = 'case', case_id: Optional[int] = None) -> int:
    """
    Clear has_ioc flags from OpenSearch events (unified for case/global)
    
    Args:
        opensearch_client: OpenSearch client
        files: List of CaseFile objects
        scope: 'case' or 'global'
        case_id: Required if scope='case'
        
    Returns:
        Number of events updated
    """
    from utils import make_index_name
    
    # Group files by case_id
    files_by_case = {}
    for f in files:
        if f.case_id not in files_by_case:
            files_by_case[f.case_id] = []
        files_by_case[f.case_id].append(f)
    
    total_updated = 0
    
    for cid, case_files in files_by_case.items():
        index_name = make_index_name(cid)
        
        try:
            # Check if index exists
            if not opensearch_client.indices.exists(index=index_name):
                continue
            
            # Build file_id list for this case
            file_ids = [f.id for f in case_files if f.opensearch_key]
            
            if not file_ids:
                continue
            
            # Clear has_ioc flag for all files at once
            update_body = {
                "script": {
                    "source": "ctx._source.remove('has_ioc'); ctx._source.remove('ioc_count')",
                    "lang": "painless"
                },
                "query": {
                    "bool": {
                        "must": [
                            {"terms": {"file_id": file_ids}},
                            {"term": {"has_ioc": True}}
                        ]
                    }
                }
            }
            
            response = opensearch_client.update_by_query(
                index=index_name,
                body=update_body,
                conflicts='proceed'
            )
            
            updated = response.get('updated', 0)
            total_updated += updated
            
            if updated > 0:
                logger.info(f"[BULK OPS] [{scope.upper()}] Cleared has_ioc flags from {updated} events in {index_name}")
        
        except Exception as e:
            logger.warning(f"[BULK OPS] [{scope.upper()}] Could not clear has_ioc flags in {index_name}: {e}")
            continue
    
    logger.info(f"[BULK OPS] [{scope.upper()}] ✓ Cleared has_ioc flags from {total_updated} total events")
    return total_updated


def clear_sigma_flags_in_opensearch(opensearch_client, files: List[Any],
                                   scope: str = 'case', case_id: Optional[int] = None) -> int:
    """
    Clear has_sigma flags and sigma_rule fields from OpenSearch events (unified)
    
    Args:
        opensearch_client: OpenSearch client
        files: List of CaseFile objects
        scope: 'case' or 'global'
        case_id: Required if scope='case'
        
    Returns:
        Number of events updated
    """
    from utils import make_index_name
    
    # Group files by case_id
    files_by_case = {}
    for f in files:
        if f.case_id not in files_by_case:
            files_by_case[f.case_id] = []
        files_by_case[f.case_id].append(f)
    
    total_updated = 0
    
    for cid, case_files in files_by_case.items():
        index_name = make_index_name(cid)
        
        try:
            # Check if index exists
            if not opensearch_client.indices.exists(index=index_name):
                continue
            
            # Clear has_sigma flag and sigma_rule field for all files
            file_ids = [f.id for f in case_files if f.is_indexed and f.opensearch_key]
            
            if not file_ids:
                continue
            
            update_body = {
                "script": {
                    "source": "ctx._source.remove('has_sigma'); ctx._source.remove('sigma_rule')",
                    "lang": "painless"
                },
                "query": {
                    "bool": {
                        "must": [
                            {"terms": {"file_id": file_ids}},
                            {"term": {"has_sigma": True}}
                        ]
                    }
                }
            }
            
            response = opensearch_client.update_by_query(
                index=index_name,
                body=update_body,
                conflicts='proceed'
            )
            
            updated = response.get('updated', 0)
            total_updated += updated
            
            if updated > 0:
                logger.info(f"[BULK OPS] [{scope.upper()}] Cleared has_sigma flags from {updated} events in {index_name}")
        
        except Exception as e:
            logger.warning(f"[BULK OPS] [{scope.upper()}] Could not clear has_sigma flags in {index_name}: {e}")
            continue
    
    logger.info(f"[BULK OPS] [{scope.upper()}] ✓ Cleared has_sigma flags from {total_updated} total events")
    return total_updated


# ============================================================================
# DATABASE OPERATIONS (scope-aware)
# ============================================================================

def clear_event_statuses(db, scope: str = 'case', case_id: Optional[int] = None,
                        file_ids: Optional[List[int]] = None) -> int:
    """
    Clear EventStatus records (unified for case/global/file-specific reindex)
    
    This ensures a TRUE fresh start during reindex - old event statuses
    (noise, hunted, confirmed) are completely wiped before re-processing.
    
    Args:
        db: Database session
        scope: 'case', 'global', or 'file'
        case_id: Required if scope='case' or 'file'
        file_ids: Required if scope='file' (list of file IDs)
    
    Returns:
        Number of EventStatus records deleted
    """
    from models import EventStatus
    from main import opensearch_client
    from utils import make_index_name
    
    if scope == 'file' and file_ids:
        # File-specific: Need to get event IDs from OpenSearch first
        index_name = make_index_name(case_id)
        
        all_event_ids = []
        for file_id in file_ids:
            try:
                # Query OpenSearch for event IDs in this file
                response = opensearch_client.search(
                    index=index_name,
                    body={
                        "query": {"term": {"file_id": file_id}},
                        "_source": False,
                        "size": 10000
                    },
                    scroll='5m',
                    ignore=[404]
                )
                
                scroll_id = response.get('_scroll_id')
                hits = response['hits']['hits']
                
                while hits:
                    all_event_ids.extend([hit['_id'] for hit in hits])
                    
                    response = opensearch_client.scroll(scroll_id=scroll_id, scroll='5m')
                    scroll_id = response.get('_scroll_id')
                    hits = response['hits']['hits']
                
                # Clear scroll
                if scroll_id:
                    opensearch_client.clear_scroll(scroll_id=scroll_id)
                    
            except Exception as e:
                logger.warning(f"[BULK OPS] Could not get event IDs for file {file_id}: {e}")
        
        # Delete EventStatus records for these event IDs
        if all_event_ids:
            deleted = EventStatus.query.filter(
                EventStatus.case_id == case_id,
                EventStatus.event_id.in_(all_event_ids)
            ).delete(synchronize_session=False)
            db.session.commit()
            logger.info(f"[BULK OPS] [FILE] Cleared {deleted} EventStatus records for {len(file_ids)} file(s)")
            return deleted
        return 0
    
    elif scope == 'case':
        # Case-specific: Clear all EventStatus for this case
        deleted = EventStatus.query.filter_by(case_id=case_id).delete()
        db.session.commit()
        logger.info(f"[BULK OPS] [CASE] Cleared {deleted} EventStatus records from case {case_id}")
        return deleted
    
    elif scope == 'global':
        # Global: Clear all EventStatus across all cases
        deleted = EventStatus.query.delete()
        db.session.commit()
        logger.info(f"[BULK OPS] [GLOBAL] Cleared {deleted} EventStatus records from all cases")
        return deleted
    
    else:
        raise ValueError(f"Invalid scope: {scope}")


def clear_sigma_violations(db, scope: str = 'case', case_id: Optional[int] = None,
                          file_ids: Optional[List[int]] = None) -> int:
    """
    Clear SIGMA violations (unified for case/global/file-specific)
    
    Args:
        db: Database session
        scope: 'case' or 'global'
        case_id: Required if scope='case'
        file_ids: Optional list of specific file IDs
        
    Returns:
        Number of violations deleted
    """
    from models import SigmaViolation
    
    query = db.session.query(SigmaViolation)
    
    if scope == 'case' and case_id:
        query = query.filter_by(case_id=case_id)
    elif scope == 'global':
        pass  # No filter
    else:
        raise ValueError(f"Invalid scope: {scope}")
    
    if file_ids:
        query = query.filter(SigmaViolation.file_id.in_(file_ids))
    
    count = query.delete(synchronize_session=False)
    db.session.commit()
    
    scope_desc = f"case {case_id}" if scope == 'case' else "all cases"
    logger.info(f"[BULK OPS] [{scope.upper()}] Cleared {count} SIGMA violations from {scope_desc}")
    
    return count


def clear_ioc_matches(db, scope: str = 'case', case_id: Optional[int] = None,
                     file_ids: Optional[List[int]] = None) -> int:
    """
    Clear IOC matches (unified for case/global/file-specific)
    
    Args:
        db: Database session
        scope: 'case' or 'global'
        case_id: Required if scope='case'
        file_ids: Optional list of specific file IDs
        
    Returns:
        Number of IOC matches deleted
    """
    from models import IOCMatch
    
    query = db.session.query(IOCMatch)
    
    if scope == 'case' and case_id:
        query = query.filter_by(case_id=case_id)
    elif scope == 'global':
        pass  # No filter
    else:
        raise ValueError(f"Invalid scope: {scope}")
    
    if file_ids:
        query = query.filter(IOCMatch.file_id.in_(file_ids))
    
    count = query.delete(synchronize_session=False)
    db.session.commit()
    
    scope_desc = f"case {case_id}" if scope == 'case' else "all cases"
    logger.info(f"[BULK OPS] [{scope.upper()}] Cleared {count} IOC matches from {scope_desc}")
    
    return count


def clear_timeline_tags(db, scope: str = 'case', case_id: Optional[int] = None) -> int:
    """
    Clear timeline tags (unified for case/global)
    Timeline tags reference event_id and index_name which change during reindex
    
    Args:
        db: Database session
        scope: 'case' or 'global'
        case_id: Required if scope='case'
        
    Returns:
        Number of tags deleted
    """
    from models import TimelineTag
    
    query = db.session.query(TimelineTag)
    
    if scope == 'case' and case_id:
        query = query.filter_by(case_id=case_id)
    elif scope == 'global':
        pass  # Clear all tags
    else:
        raise ValueError(f"Invalid scope: {scope}")
    
    count = query.delete()
    db.session.commit()
    
    scope_desc = f"case {case_id}" if scope == 'case' else "all cases"
    logger.info(f"[BULK OPS] [{scope.upper()}] Cleared {count} timeline tag(s) from {scope_desc}")
    
    return count


# ============================================================================
# FILE METADATA OPERATIONS
# ============================================================================

def reset_file_metadata(file_obj: Any, reset_opensearch_key: bool = True):
    """
    Reset file processing metadata (same for case/global)
    
    Args:
        file_obj: CaseFile object
        reset_opensearch_key: Whether to clear opensearch_key (True for reindex, False for rechainsaw/rehunt)
    """
    file_obj.event_count = 0
    file_obj.violation_count = 0
    file_obj.ioc_event_count = 0
    file_obj.is_indexed = False
    # Reset state flags
    file_obj.sigma_hunted = False
    file_obj.ioc_hunted = False
    file_obj.known_good = False
    file_obj.known_noise = False
    file_obj.failed = False
    file_obj.file_state = 'New'
    
    if reset_opensearch_key:
        file_obj.opensearch_key = None
    
    logger.debug(f"[BULK OPS] Reset metadata for file {file_obj.id} (opensearch_key cleared: {reset_opensearch_key})")


def prepare_files_for_reindex(db, files: List[Any], scope: str = 'case') -> int:
    """
    Prepare files for re-indexing (unified for case/global)
    
    Args:
        db: Database session
        files: List of CaseFile objects
        scope: 'case' or 'global' (for logging)
        
    Returns:
        Number of files prepared
    """
    for f in files:
        reset_file_metadata(f, reset_opensearch_key=True)
        f.error_message = None
        f.celery_task_id = None
    
    db.session.commit()
    logger.info(f"[BULK OPS] [{scope.upper()}] Prepared {len(files)} file(s) for re-indexing")
    
    return len(files)


def prepare_files_for_rechainsaw(db, files: List[Any], scope: str = 'case') -> int:
    """
    Prepare files for re-SIGMA (unified for case/global)
    
    Args:
        db: Database session
        files: List of CaseFile objects
        scope: 'case' or 'global' (for logging)
        
    Returns:
        Number of files prepared
    """
    for f in files:
        f.celery_task_id = None
        f.violation_count = 0
        # State will be set by processing_sigma.py
    
    db.session.commit()
    logger.info(f"[BULK OPS] [{scope.upper()}] Prepared {len(files)} file(s) for re-SIGMA")
    
    return len(files)


def prepare_files_for_rehunt(db, files: List[Any], scope: str = 'case') -> int:
    """
    Prepare files for IOC re-hunting (unified for case/global)
    
    Args:
        db: Database session
        files: List of CaseFile objects
        scope: 'case' or 'global' (for logging)
        
    Returns:
        Number of files prepared
    """
    for f in files:
        f.celery_task_id = None
        f.ioc_event_count = 0
        # State will be set by processing_ioc.py
    
    db.session.commit()
    logger.info(f"[BULK OPS] [{scope.upper()}] Prepared {len(files)} file(s) for IOC re-hunting")
    
    return len(files)


def requeue_failed_files(db, scope: str = 'case', case_id: Optional[int] = None) -> int:
    """
    Requeue all failed files (unified for case/global)
    
    Args:
        db: Database session
        scope: 'case' or 'global'
        case_id: Required if scope='case'
        
    Returns:
        Number of files requeued
    """
    from models import CaseFile
    
    # Get failed files (any status not in known good statuses)
    known_statuses = ['Completed', 'Indexing', 'SIGMA Testing', 'IOC Hunting', 'Queued']
    query = db.session.query(CaseFile).filter(
        CaseFile.is_deleted == False,
        CaseFile.is_hidden == False,
        ~CaseFile.indexing_status.in_(known_statuses)
    )
    
    if scope == 'case' and case_id:
        query = query.filter_by(case_id=case_id)
    elif scope == 'global':
        pass  # No filter
    else:
        raise ValueError(f"Invalid scope: {scope}")
    
    failed_files = query.all()
    
    count = 0
    for f in failed_files:
        f.celery_task_id = None
        f.error_message = None
        f.failed = False  # Clear failed flag
        # State will be set by processing modules
        count += 1
    
    db.session.commit()
    
    scope_desc = f"case {case_id}" if scope == 'case' else "all cases"
    logger.info(f"[BULK OPS] [{scope.upper()}] Requeued {count} failed file(s) from {scope_desc}")
    
    return count


# ============================================================================
# TASK QUEUING (unified)
# ============================================================================

def queue_file_processing(process_file_task, files: List[Any], operation: str = 'full', 
                         db_session=None, scope: str = 'case') -> int:
    """
    Queue file processing tasks for multiple files (unified for case/global)
    
    Args:
        process_file_task: Celery task (process_file)
        files: List of CaseFile objects
        operation: Operation type ('full', 'chainsaw_only', 'ioc_only')
        db_session: Optional database session (if None, will not commit)
        scope: 'case' or 'global' (for logging)
        
    Returns:
        Number of tasks queued
    """
    queued_count = 0
    skipped_count = 0
    errors = []
    
    for f in files:
        # CRITICAL: Prevent duplicate queuing for 'full' operation
        if operation == 'full' and f.is_indexed:
            logger.debug(f"[BULK OPS] [{scope.upper()}] Skipping file {f.id} (already indexed)")
            skipped_count += 1
            continue
        
        # CRITICAL: Check for stale task_id before queuing
        if f.celery_task_id:
            from celery.result import AsyncResult
            from celery_app import celery_app
            old_task = AsyncResult(f.celery_task_id, app=celery_app)
            
            if old_task.state in ['PENDING', 'STARTED', 'RETRY']:
                logger.debug(f"[BULK OPS] [{scope.upper()}] Skipping file {f.id} (already queued: {old_task.state})")
                skipped_count += 1
                continue
            else:
                logger.debug(f"[BULK OPS] [{scope.upper()}] File {f.id} has stale task_id, clearing")
                f.celery_task_id = None
        
        try:
            result = process_file_task.delay(f.id, operation=operation)
            f.celery_task_id = result.id
            logger.debug(f"[BULK OPS] [{scope.upper()}] Queued {operation} for file {f.id} (task: {result.id})")
            queued_count += 1
        except Exception as e:
            error_msg = f"Failed to queue file {f.id}: {e}"
            logger.error(f"[BULK OPS] [{scope.upper()}] {error_msg}")
            errors.append(error_msg)
            f.celery_task_id = None
    
    # Commit task_id changes
    if db_session and queued_count > 0:
        try:
            db_session.commit()
            logger.debug(f"[BULK OPS] [{scope.upper()}] Committed {queued_count} task_id assignments")
        except Exception as e:
            logger.error(f"[BULK OPS] [{scope.upper()}] Failed to commit task_ids: {e}")
            db_session.rollback()
    
    if errors:
        logger.warning(f"[BULK OPS] [{scope.upper()}] Queued {queued_count}/{len(files)} files. {len(errors)} errors, {skipped_count} skipped.")
    else:
        if skipped_count > 0:
            logger.info(f"[BULK OPS] [{scope.upper()}] Queued {queued_count} file(s) for {operation}, skipped {skipped_count}")
        else:
            logger.info(f"[BULK OPS] [{scope.upper()}] Queued {queued_count} file(s) for {operation}")
    
    return queued_count


# ============================================================================
# FILE DELETION (unified)
# ============================================================================

def delete_files(db, opensearch_client, files: List[Any], 
                scope: str = 'case', case_id: Optional[int] = None) -> Dict[str, int]:
    """
    Delete files and all associated data (unified for case/global)
    
    Args:
        db: Database session
        opensearch_client: OpenSearch client
        files: List of CaseFile objects
        scope: 'case' or 'global'
        case_id: Optional case_id (for logging)
        
    Returns:
        Dict with deletion counts
    """
    import os
    from utils import make_index_name
    
    stats = {
        'files_deleted': 0,
        'events_deleted': 0,
        'sigma_deleted': 0,
        'ioc_deleted': 0,
        'disk_deleted': 0
    }
    
    # Group files by case for efficient OpenSearch deletion
    files_by_case = {}
    for f in files:
        if f.case_id not in files_by_case:
            files_by_case[f.case_id] = []
        files_by_case[f.case_id].append(f)
    
    # Delete from OpenSearch
    for cid, case_files in files_by_case.items():
        index_name = make_index_name(cid)
        
        for f in case_files:
            if f.opensearch_key:
                try:
                    result = opensearch_client.delete_by_query(
                        index=index_name,
                        body={"query": {"term": {"file_id": f.id}}},
                        conflicts='proceed',
                        ignore=[404]
                    )
                    stats['events_deleted'] += result.get('deleted', 0) if isinstance(result, dict) else 0
                except Exception as e:
                    logger.warning(f"[BULK OPS] [{scope.upper()}] Could not delete OpenSearch events for file {f.id}: {e}")
    
    # Delete SIGMA violations and IOC matches
    from models import SigmaViolation, IOCMatch
    
    file_ids = [f.id for f in files]
    
    stats['sigma_deleted'] = db.session.query(SigmaViolation).filter(
        SigmaViolation.file_id.in_(file_ids)
    ).delete(synchronize_session=False)
    
    stats['ioc_deleted'] = db.session.query(IOCMatch).filter(
        IOCMatch.file_id.in_(file_ids)
    ).delete(synchronize_session=False)
    
    # Delete from filesystem and database
    for f in files:
        # Delete from filesystem
        file_path = f.file_path if hasattr(f, 'file_path') else None
        if file_path and os.path.exists(file_path):
            try:
                os.remove(file_path)
                stats['disk_deleted'] += 1
            except Exception as e:
                logger.warning(f"[BULK OPS] [{scope.upper()}] Could not delete file from disk: {e}")
        
        # Delete from database
        db.session.delete(f)
        stats['files_deleted'] += 1
    
    db.session.commit()
    
    scope_desc = f"case {case_id}" if scope == 'case' and case_id else f"{len(files_by_case)} case(s)"
    logger.info(f"[BULK OPS] [{scope.upper()}] Deleted {stats['files_deleted']} files, "
                f"{stats['events_deleted']} events, {stats['sigma_deleted']} SIGMA, "
                f"{stats['ioc_deleted']} IOC matches from {scope_desc}")
    
    return stats


# ============================================================================
# LEGACY COMPATIBILITY (for single-file operations)
# ============================================================================

def clear_file_sigma_violations(db, file_id: int) -> int:
    """Clear SIGMA violations for a specific file (legacy wrapper)"""
    from models import CaseFile
    case_file = db.session.get(CaseFile, file_id)
    if not case_file:
        logger.warning(f"[BULK OPS] Cannot clear SIGMA violations - file {file_id} not found")
        return 0
    return clear_sigma_violations(db, scope='case', case_id=case_file.case_id, file_ids=[file_id])


def clear_file_ioc_matches(db, file_id: int) -> int:
    """Clear IOC matches for a specific file (legacy wrapper)"""
    from models import CaseFile
    case_file = db.session.get(CaseFile, file_id)
    if not case_file:
        logger.warning(f"[BULK OPS] Cannot clear IOC matches - file {file_id} not found")
        return 0
    return clear_ioc_matches(db, scope='case', case_id=case_file.case_id, file_ids=[file_id])


def clear_file_sigma_flags_in_opensearch(opensearch_client, case_id: int, file_obj) -> int:
    """
    Clear has_sigma flags for a specific file (legacy wrapper)
    
    Args:
        opensearch_client: OpenSearch client
        case_id: Case ID
        file_obj: CaseFile object
        
    Returns:
        Number of events updated
    """
    if not file_obj.is_indexed or not file_obj.opensearch_key:
        return 0
    
    return clear_sigma_flags_in_opensearch(opensearch_client, [file_obj], scope='case', case_id=case_id)


# ============================================================================
# BACKWARD COMPATIBILITY ALIASES (for case-specific operations)
# ============================================================================

def get_case_files(db, case_id: int, include_deleted: bool = False, include_hidden: bool = False) -> List[Any]:
    """Legacy wrapper for get_files with scope='case'"""
    return get_files(db, scope='case', case_id=case_id, 
                    include_deleted=include_deleted, include_hidden=include_hidden)


def clear_case_opensearch_indices(opensearch_client, case_id: int, files: List[Any]) -> int:
    """Legacy wrapper for clear_opensearch_events with scope='case'"""
    return clear_opensearch_events(opensearch_client, files, scope='case', case_id=case_id)


def clear_case_sigma_violations(db, case_id: int) -> int:
    """Legacy wrapper for clear_sigma_violations with scope='case'"""
    return clear_sigma_violations(db, scope='case', case_id=case_id)


def clear_case_ioc_matches(db, case_id: int) -> int:
    """Legacy wrapper for clear_ioc_matches with scope='case'"""
    return clear_ioc_matches(db, scope='case', case_id=case_id)


def clear_case_ioc_flags_in_opensearch(opensearch_client, case_id: int, files: list) -> int:
    """Legacy wrapper for clear_ioc_flags_in_opensearch with scope='case'"""
    return clear_ioc_flags_in_opensearch(opensearch_client, files, scope='case', case_id=case_id)


def clear_case_sigma_flags_in_opensearch(opensearch_client, case_id: int, files: list) -> int:
    """Legacy wrapper for clear_sigma_flags_in_opensearch with scope='case'"""
    return clear_sigma_flags_in_opensearch(opensearch_client, files, scope='case', case_id=case_id)


def clear_case_timeline_tags(db, case_id: int) -> int:
    """Legacy wrapper for clear_timeline_tags with scope='case'"""
    return clear_timeline_tags(db, scope='case', case_id=case_id)


def clear_case_data_for_reindex(db, case_id: int, file_ids: List[int]) -> Dict[str, int]:
    """
    Clear all detection/classification data for reindex.
    
    This ensures files are treated as brand new during reindex:
    - EventStatus records (noise, hunted, confirmed)
    - SigmaViolation records
    - IOCMatch records
    - OpenSearch index (deleted entirely)
    
    Args:
        db: Database session
        case_id: Case ID
        file_ids: List of file IDs to clear (for targeted reindex)
    
    Returns:
        Dict with counts of deleted records
    """
    logger.info(f"[REINDEX] Clearing data for case {case_id}, {len(file_ids)} files")
    
    result = {
        'event_statuses_deleted': 0,
        'sigma_violations_deleted': 0,
        'ioc_matches_deleted': 0,
        'timeline_tags_deleted': 0
    }
    
    # Clear EventStatus records
    result['event_statuses_deleted'] = clear_event_statuses(db, scope='case', case_id=case_id)
    
    # Clear SigmaViolation records
    result['sigma_violations_deleted'] = clear_sigma_violations(db, scope='case', case_id=case_id)
    
    # Clear IOCMatch records
    result['ioc_matches_deleted'] = clear_ioc_matches(db, scope='case', case_id=case_id)
    
    # Clear TimelineTag records
    result['timeline_tags_deleted'] = clear_timeline_tags(db, scope='case', case_id=case_id)
    
    # Reset file metadata (event_count, violation_count, ioc_event_count, indexing_status, etc.)
    from models import CaseFile
    files = CaseFile.query.filter(CaseFile.id.in_(file_ids)).all()
    for f in files:
        reset_file_metadata(f, reset_opensearch_key=True)
    db.session.commit()
    
    logger.info(f"[REINDEX] Cleared {result['event_statuses_deleted']} statuses, "
                f"{result['sigma_violations_deleted']} violations, "
                f"{result['ioc_matches_deleted']} IOC matches, "
                f"{result['timeline_tags_deleted']} timeline tags, "
                f"and reset {len(files)} file metadata records")
    
    return result
