"""
Hidden Files Management Module
Handles viewing and toggling visibility of 0-event files
"""

import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


# ============================================================================
# GLOBAL FUNCTIONS (All Cases)
# ============================================================================

def get_hidden_files_count_global(db_session) -> int:
    """Get count of hidden files across ALL cases"""
    from models import CaseFile
    
    return db_session.query(CaseFile).filter_by(
        is_deleted=False,
        is_hidden=True
    ).count()


def get_hidden_files_global(db_session, page: int = 1, per_page: int = 50, search_term: str = None):
    """Get paginated list of hidden files across ALL cases with optional search"""
    from models import CaseFile, Case
    
    query = db_session.query(CaseFile, Case.name).join(Case).filter(
        CaseFile.is_deleted == False,
        CaseFile.is_hidden == True
    )
    
    # Apply search filter if provided
    if search_term:
        search_pattern = f"%{search_term}%"
        query = query.filter(
            (CaseFile.original_filename.ilike(search_pattern)) |
            (CaseFile.file_hash.ilike(search_pattern)) |
            (Case.name.ilike(search_pattern))
        )
    
    query = query.order_by(CaseFile.uploaded_at.desc())
    
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    return pagination


def get_failed_files_count_global(db_session) -> int:
    """Get count of failed files across ALL cases (not hidden)"""
    from models import CaseFile
    
    known_statuses = ['Completed', 'Indexing', 'SIGMA Testing', 'IOC Hunting', 'Queued']
    return db_session.query(CaseFile).filter(
        CaseFile.is_deleted == False,
        CaseFile.is_hidden == False,
        ~CaseFile.indexing_status.in_(known_statuses)
    ).count()


def get_failed_files_global(db_session, page: int = 1, per_page: int = 50, search_term: str = None):
    """Get paginated list of failed files across ALL cases with optional search"""
    from models import CaseFile, Case
    
    known_statuses = ['Completed', 'Indexing', 'SIGMA Testing', 'IOC Hunting', 'Queued']
    query = db_session.query(CaseFile, Case.name).join(Case).filter(
        CaseFile.is_deleted == False,
        CaseFile.is_hidden == False,
        ~CaseFile.indexing_status.in_(known_statuses)
    )
    
    # Apply search filter if provided
    if search_term:
        search_pattern = f"%{search_term}%"
        query = query.filter(
            (CaseFile.original_filename.ilike(search_pattern)) |
            (CaseFile.file_hash.ilike(search_pattern)) |
            (Case.name.ilike(search_pattern))
        )
    
    query = query.order_by(CaseFile.uploaded_at.desc())
    
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    return pagination


# ============================================================================
# CASE-SPECIFIC FUNCTIONS
# ============================================================================

def get_hidden_files_count(db_session, case_id: int) -> int:
    """Get count of hidden files for a case"""
    from models import CaseFile
    
    return db_session.query(CaseFile).filter_by(
        case_id=case_id,
        is_deleted=False,
        is_hidden=True
    ).count()


def get_hidden_events_count(case_id: int) -> int:
    """
    Get count of hidden EVENTS in OpenSearch for a case (v1.43.17).
    
    This queries OpenSearch for events with is_hidden=true in the case index.
    Used to display hidden events count on the dashboard.
    """
    import logging
    logger = logging.getLogger(__name__)
    
    try:
        from file_processing import get_opensearch_client
        client = get_opensearch_client()
        
        index_name = f"case_{case_id}"
        
        # Check if index exists
        if not client.indices.exists(index=index_name):
            return 0
        
        # Count hidden events
        result = client.count(
            index=index_name,
            body={
                "query": {
                    "term": {"is_hidden": True}
                }
            }
        )
        
        return result.get('count', 0)
        
    except Exception as e:
        logger.warning(f"[HIDDEN_EVENTS] Error getting hidden events count for case {case_id}: {e}")
        return 0


def get_hidden_files(db_session, case_id: int, page: int = 1, per_page: int = 50, search_term: str = None):
    """Get paginated list of hidden files with optional search"""
    from models import CaseFile
    
    query = db_session.query(CaseFile).filter_by(
        case_id=case_id,
        is_deleted=False,
        is_hidden=True
    )
    
    # Apply search filter if provided
    if search_term:
        search_pattern = f"%{search_term}%"
        query = query.filter(
            (CaseFile.original_filename.ilike(search_pattern)) |
            (CaseFile.file_hash.ilike(search_pattern))
        )
    
    query = query.order_by(CaseFile.uploaded_at.desc())
    
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    return pagination


def toggle_file_visibility(db_session, file_id: int, user_id: int) -> Dict:
    """Toggle a file's hidden status"""
    from models import CaseFile
    
    file = db_session.get(CaseFile, file_id)
    
    if not file:
        return {'success': False, 'error': 'File not found'}
    
    file.is_hidden = not file.is_hidden
    action = 'hidden' if file.is_hidden else 'visible'
    
    try:
        db_session.commit()
        logger.info(f"[HIDDEN] User {user_id} set file {file_id} to {action}")
        return {
            'success': True,
            'is_hidden': file.is_hidden,
            'action': action
        }
    except Exception as e:
        db_session.rollback()
        logger.error(f"[HIDDEN] Failed to toggle file {file_id}: {e}")
        return {'success': False, 'error': str(e)}


def bulk_unhide_files(db_session, case_id: int, file_ids: List[int], user_id: int) -> Dict:
    """Unhide multiple files at once"""
    from models import CaseFile
    
    try:
        files = db_session.query(CaseFile).filter(
            CaseFile.id.in_(file_ids),
            CaseFile.case_id == case_id,
            CaseFile.is_deleted == False
        ).all()
        
        count = 0
        for file in files:
            file.is_hidden = False
            count += 1
        
        db_session.commit()
        logger.info(f"[HIDDEN] User {user_id} unhid {count} files in case {case_id}")
        
        return {'success': True, 'count': count}
    except Exception as e:
        db_session.rollback()
        logger.error(f"[HIDDEN] Bulk unhide failed: {e}")
        return {'success': False, 'error': str(e)}


def bulk_delete_hidden_files(db_session, case_id: int, file_ids: List[int], user_id: int) -> Dict:
    """Delete multiple hidden files permanently"""
    import os
    from models import CaseFile, SigmaViolation, IOCMatch
    from main import opensearch_client
    
    try:
        files = db_session.query(CaseFile).filter(
            CaseFile.id.in_(file_ids),
            CaseFile.case_id == case_id,
            CaseFile.is_hidden == True,  # Only delete hidden files
            CaseFile.is_deleted == False
        ).all()
        
        if not files:
            return {'success': False, 'error': 'No hidden files found to delete'}
        
        deleted_count = 0
        errors = []
        os_client = opensearch_client
        
        for file in files:
            try:
                # Delete OpenSearch events for this file (v1.13.1: delete by file_id)
                if file.opensearch_key:
                    try:
                        from utils import make_index_name
                        index_name = make_index_name(file.case_id)
                        
                        # Delete events by file_id (not entire index - it's shared)
                        os_client.delete_by_query(
                            index=index_name,
                            body={"query": {"term": {"file_id": file.id}}},
                            conflicts='proceed',
                            ignore=[404]
                        )
                        logger.info(f"[DELETE HIDDEN] Deleted events for file {file.id} from index {index_name}")
                    except Exception as e:
                        logger.warning(f"[DELETE HIDDEN] Failed to delete events for file {file.id}: {e}")
                
                # Delete SIGMA violations
                db_session.query(SigmaViolation).filter_by(file_id=file.id).delete()
                
                # Delete IOC matches
                db_session.query(IOCMatch).filter_by(file_id=file.id).delete()
                
                # Delete physical file
                if file.file_path and os.path.exists(file.file_path):
                    try:
                        os.remove(file.file_path)
                        logger.info(f"[DELETE HIDDEN] Deleted physical file: {file.file_path}")
                    except Exception as e:
                        logger.warning(f"[DELETE HIDDEN] Failed to delete physical file {file.file_path}: {e}")
                
                # Mark as deleted in database
                file.is_deleted = True
                deleted_count += 1
                
            except Exception as e:
                error_msg = f"Error deleting file {file.id}: {str(e)}"
                logger.error(f"[DELETE HIDDEN] {error_msg}")
                errors.append(error_msg)
        
        db_session.commit()
        logger.info(f"[DELETE HIDDEN] User {user_id} deleted {deleted_count} hidden files in case {case_id}")
        
        return {
            'success': True,
            'count': deleted_count,
            'errors': errors
        }
        
    except Exception as e:
        db_session.rollback()
        logger.error(f"[DELETE HIDDEN] Bulk delete failed: {e}")
        return {'success': False, 'error': str(e)}


def get_failed_files_count(db_session, case_id: int) -> int:
    """Get count of failed files for a case (not hidden)"""
    from models import CaseFile
    
    known_statuses = ['Completed', 'Indexing', 'SIGMA Testing', 'IOC Hunting', 'Queued']
    return db_session.query(CaseFile).filter(
        CaseFile.case_id == case_id,
        CaseFile.is_deleted == False,
        CaseFile.is_hidden == False,
        ~CaseFile.indexing_status.in_(known_statuses)
    ).count()


def get_failed_files(db_session, case_id: int, page: int = 1, per_page: int = 50, search_term: str = None):
    """Get paginated list of failed files with optional search"""
    from models import CaseFile
    
    known_statuses = ['Completed', 'Indexing', 'SIGMA Testing', 'IOC Hunting', 'Queued']
    query = db_session.query(CaseFile).filter(
        CaseFile.case_id == case_id,
        CaseFile.is_deleted == False,
        CaseFile.is_hidden == False,
        ~CaseFile.indexing_status.in_(known_statuses)
    )
    
    # Apply search filter if provided
    if search_term:
        search_pattern = f"%{search_term}%"
        query = query.filter(
            (CaseFile.original_filename.ilike(search_pattern)) |
            (CaseFile.file_hash.ilike(search_pattern))
        )
    
    query = query.order_by(CaseFile.uploaded_at.desc())
    
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    return pagination


def get_file_stats_with_hidden(db_session, case_id: int) -> Dict:
    """Get file statistics including hidden count"""
    from models import CaseFile
    from sqlalchemy import func
    
    # Total files (excluding deleted)
    total_files = db_session.query(CaseFile).filter_by(
        case_id=case_id,
        is_deleted=False
    ).count()
    
    # Hidden files
    hidden_files = db_session.query(CaseFile).filter_by(
        case_id=case_id,
        is_deleted=False,
        is_hidden=True
    ).count()
    
    # Visible files
    visible_files = total_files - hidden_files
    
    # Total space (all files including hidden)
    total_space_bytes = db_session.query(func.sum(CaseFile.file_size)).filter_by(
        case_id=case_id,
        is_deleted=False
    ).scalar() or 0
    
    # Total events (visible files only)
    total_events = db_session.query(func.sum(CaseFile.event_count)).filter_by(
        case_id=case_id,
        is_deleted=False,
        is_hidden=False
    ).scalar() or 0
    
    # SIGMA events (visible files only) - using violation_count (active field)
    sigma_events = db_session.query(func.sum(CaseFile.violation_count)).filter_by(
        case_id=case_id,
        is_deleted=False,
        is_hidden=False
    ).scalar() or 0
    
    # IOC events (visible files only)
    ioc_events = db_session.query(func.sum(CaseFile.ioc_event_count)).filter_by(
        case_id=case_id,
        is_deleted=False,
        is_hidden=False
    ).scalar() or 0
    
    # Hidden events count from OpenSearch (v1.43.17)
    hidden_events = get_hidden_events_count(case_id)
    
    # Processing state counts (visible files only)
    files_indexing = db_session.query(CaseFile).filter_by(
        case_id=case_id,
        is_deleted=False,
        is_hidden=False,
        indexing_status='Indexing'
    ).count()
    
    files_sigma = db_session.query(CaseFile).filter_by(
        case_id=case_id,
        is_deleted=False,
        is_hidden=False,
        indexing_status='SIGMA Testing'
    ).count()
    
    files_ioc_hunting = db_session.query(CaseFile).filter_by(
        case_id=case_id,
        is_deleted=False,
        is_hidden=False,
        indexing_status='IOC Hunting'
    ).count()
    
    files_completed = db_session.query(CaseFile).filter_by(
        case_id=case_id,
        is_deleted=False,
        is_hidden=False,
        indexing_status='Completed'
    ).count()
    
    files_queued = db_session.query(CaseFile).filter_by(
        case_id=case_id,
        is_deleted=False,
        is_hidden=False,
        indexing_status='Queued'
    ).count()
    
    # Failed files (any status that's not a known state)
    known_statuses = ['Completed', 'Indexing', 'SIGMA Testing', 'IOC Hunting', 'Queued']
    files_failed = db_session.query(CaseFile).filter(
        CaseFile.case_id == case_id,
        CaseFile.is_deleted == False,
        CaseFile.is_hidden == False,
        ~CaseFile.indexing_status.in_(known_statuses)
    ).count()
    
    return {
        'total_files': total_files,
        'visible_files': visible_files,
        'hidden_files': hidden_files,
        'total_space_bytes': int(total_space_bytes),
        'total_events': int(total_events),
        'sigma_events': int(sigma_events),
        'ioc_events': int(ioc_events),
        'hidden_events': int(hidden_events),
        'files_completed': files_completed,
        'files_indexing': files_indexing,
        'files_sigma': files_sigma,
        'files_ioc_hunting': files_ioc_hunting,
        'files_queued': files_queued,
        'files_failed': files_failed
    }

