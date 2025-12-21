"""
File Statistics Module

Provides consistent file statistics queries across the application.
Uses new flag-based state tracking instead of fragile status string parsing.

Author: System
Date: 2025-12-18
Version: 2.2.0
"""

import logging
from typing import Dict, List, Optional
from sqlalchemy import func, and_, or_

logger = logging.getLogger(__name__)


def get_file_statistics(db_session, CaseFile, case_id: Optional[int] = None) -> Dict:
    """
    Get comprehensive file statistics for a case or globally.
    
    Args:
        db_session: Database session
        CaseFile: CaseFile model class
        case_id: Optional case ID (if None, returns global stats)
        
    Returns:
        dict: File statistics
    """
    # Base filter (exclude deleted files)
    base_filter = [CaseFile.is_deleted == False]
    
    # Add case filter if specified
    if case_id is not None:
        base_filter.append(CaseFile.case_id == case_id)
    
    # Files with events (not hidden, not deleted)
    files_with_events = db_session.query(func.count(CaseFile.id)).filter(
        and_(
            *base_filter,
            CaseFile.is_hidden == False
        )
    ).scalar() or 0
    
    # Hidden files (0-event or filtered)
    hidden_files = db_session.query(func.count(CaseFile.id)).filter(
        and_(
            *base_filter,
            CaseFile.is_hidden == True
        )
    ).scalar() or 0
    
    # Completed files (using is_completed logic)
    # Note: SQLAlchemy can't use @property, so we replicate logic here
    completed_files = db_session.query(func.count(CaseFile.id)).filter(
        and_(
            *base_filter,
            CaseFile.is_indexed == True,
            CaseFile.ioc_hunted == True,
            CaseFile.known_good == True,
            CaseFile.known_noise == True,
            CaseFile.failed == False,
            CaseFile.is_hidden == False,
            CaseFile.event_count > 0,
            # For EVTX files, also need sigma_hunted
            or_(
                ~CaseFile.original_filename.ilike('%.evtx'),
                CaseFile.sigma_hunted == True
            )
        )
    ).scalar() or 0
    
    # Failed files
    failed_files = db_session.query(func.count(CaseFile.id)).filter(
        and_(
            *base_filter,
            CaseFile.failed == True
        )
    ).scalar() or 0
    
    # Indexed files
    indexed_files = db_session.query(func.count(CaseFile.id)).filter(
        and_(
            *base_filter,
            CaseFile.is_indexed == True
        )
    ).scalar() or 0
    
    # SIGMA checked files
    sigma_checked = db_session.query(func.count(CaseFile.id)).filter(
        and_(
            *base_filter,
            CaseFile.sigma_hunted == True
        )
    ).scalar() or 0
    
    # IOC checked files
    ioc_checked = db_session.query(func.count(CaseFile.id)).filter(
        and_(
            *base_filter,
            CaseFile.ioc_hunted == True
        )
    ).scalar() or 0
    
    # Noise checked files (both known_good and known_noise must be True)
    noise_checked = db_session.query(func.count(CaseFile.id)).filter(
        and_(
            *base_filter,
            CaseFile.known_good == True,
            CaseFile.known_noise == True
        )
    ).scalar() or 0
    
    # Queued files (has celery_task_id)
    # Queued files: Files waiting to be processed OR currently processing
    # v2.2.0: Use file_state ONLY (indexing_status is deprecated, not updated by tasks)
    queued_files = db_session.query(func.count(CaseFile.id)).filter(
        and_(
            *base_filter,
            CaseFile.file_state.in_(['Queued', 'Indexing', 'SIGMA Hunting', 'IOC Hunting', 'Noise Checking'])
        )
    ).scalar() or 0
    
    # New files (not yet indexed)
    new_files = db_session.query(func.count(CaseFile.id)).filter(
        and_(
            *base_filter,
            CaseFile.is_new == True
        )
    ).scalar() or 0
    
    # Total space used (sum of file_size)
    total_space = db_session.query(func.sum(CaseFile.file_size)).filter(
        and_(*base_filter)
    ).scalar() or 0
    
    # Convert to GB
    total_space_gb = round(total_space / (1024**3), 2)
    
    # Total files (including hidden, excluding deleted)
    total_files = files_with_events + hidden_files
    
    return {
        'total_files': total_files,
        'files_with_events': files_with_events,
        'hidden_files': hidden_files,
        'completed_files': completed_files,
        'failed_files': failed_files,
        'indexed_files': indexed_files,
        'sigma_checked': sigma_checked,
        'ioc_checked': ioc_checked,
        'noise_checked': noise_checked,
        'queued_files': queued_files,
        'new_files': new_files,
        'total_space_gb': total_space_gb,
    }


def get_files_by_state(db_session, CaseFile, case_id: Optional[int] = None) -> Dict[str, int]:
    """
    Get count of files in each processing state.
    
    Args:
        db_session: Database session
        CaseFile: CaseFile model class
        case_id: Optional case ID (if None, returns global stats)
        
    Returns:
        dict: State name -> count
    """
    # Base filter
    base_filter = [CaseFile.is_deleted == False]
    if case_id is not None:
        base_filter.append(CaseFile.case_id == case_id)
    
    # Query grouped by state
    results = db_session.query(
        CaseFile.file_state,
        func.count(CaseFile.id)
    ).filter(
        and_(*base_filter)
    ).group_by(CaseFile.file_state).all()
    
    # Convert to dict
    state_counts = {state: count for state, count in results}
    
    return state_counts


def get_failed_files_count(db_session, CaseFile, case_id: Optional[int] = None) -> int:
    """
    Get count of failed files (NEW v2.2.0 - uses failed flag).
    
    Args:
        db_session: Database session
        CaseFile: CaseFile model class
        case_id: Optional case ID
        
    Returns:
        int: Count of failed files
    """
    filters = [
        CaseFile.failed == True,
        CaseFile.is_deleted == False
    ]
    
    if case_id is not None:
        filters.append(CaseFile.case_id == case_id)
    
    return db_session.query(func.count(CaseFile.id)).filter(
        and_(*filters)
    ).scalar() or 0


def get_failed_files_paginated(db_session, CaseFile, Case=None, 
                               case_id: Optional[int] = None,
                               page: int = 1, per_page: int = 50, 
                               search_term: Optional[str] = None):
    """
    Get paginated list of failed files.
    
    Args:
        db_session: Database session
        CaseFile: CaseFile model class
        Case: Optional Case model (for global queries with case names)
        case_id: Optional case ID (if None, returns global results)
        page: Page number (1-indexed)
        per_page: Results per page
        search_term: Optional filename search
        
    Returns:
        Pagination object
    """
    # Base query
    if Case and case_id is None:
        # Global query with case names
        query = db_session.query(CaseFile, Case.name).join(
            Case, CaseFile.case_id == Case.id
        )
    else:
        # Case-specific query
        query = db_session.query(CaseFile)
    
    # Filters
    filters = [
        CaseFile.failed == True,
        CaseFile.is_deleted == False
    ]
    
    if case_id is not None:
        filters.append(CaseFile.case_id == case_id)
    
    if search_term:
        filters.append(CaseFile.original_filename.ilike(f'%{search_term}%'))
    
    query = query.filter(and_(*filters))
    
    # Order by most recent first
    query = query.order_by(CaseFile.uploaded_at.desc())
    
    # Paginate
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    
    return pagination


def get_processing_files(db_session, CaseFile, case_id: Optional[int] = None, 
                        limit: int = 100) -> List:
    """
    Get files currently being processed (have celery_task_id).
    
    Args:
        db_session: Database session
        CaseFile: CaseFile model class
        case_id: Optional case ID
        limit: Max results to return
        
    Returns:
        list: CaseFile instances currently processing
    """
    filters = [
        CaseFile.celery_task_id != None,
        CaseFile.is_deleted == False
    ]
    
    if case_id is not None:
        filters.append(CaseFile.case_id == case_id)
    
    return db_session.query(CaseFile).filter(
        and_(*filters)
    ).order_by(CaseFile.id).limit(limit).all()


def get_files_needing_phase(db_session, CaseFile, phase: str, 
                           case_id: Optional[int] = None) -> List:
    """
    Get files that need a specific processing phase.
    
    Args:
        db_session: Database session
        CaseFile: CaseFile model class
        phase: 'sigma', 'ioc', or 'noise'
        case_id: Optional case ID
        
    Returns:
        list: CaseFile instances needing the phase
    """
    # Base filters (indexed, not hidden, not failed, not deleted)
    filters = [
        CaseFile.is_indexed == True,
        CaseFile.is_hidden == False,
        CaseFile.failed == False,
        CaseFile.is_deleted == False
    ]
    
    if case_id is not None:
        filters.append(CaseFile.case_id == case_id)
    
    # Phase-specific filters
    if phase == 'sigma':
        filters.append(CaseFile.sigma_hunted == False)
        filters.append(CaseFile.original_filename.ilike('%.evtx'))  # EVTX only
    elif phase == 'ioc':
        filters.append(CaseFile.ioc_hunted == False)
    elif phase == 'noise':
        filters.append(
            or_(
                CaseFile.known_good == False,
                CaseFile.known_noise == False
            )
        )
    else:
        logger.error(f"Unknown phase: {phase}")
        return []
    
    return db_session.query(CaseFile).filter(and_(*filters)).all()


def get_incomplete_files(db_session, CaseFile, case_id: Optional[int] = None) -> List:
    """
    Get files that are indexed but not completed.
    
    Useful for finding files stuck in intermediate states.
    
    Args:
        db_session: Database session
        CaseFile: CaseFile model class
        case_id: Optional case ID
        
    Returns:
        list: CaseFile instances that are incomplete
    """
    filters = [
        CaseFile.is_indexed == True,
        CaseFile.failed == False,
        CaseFile.is_hidden == False,
        CaseFile.is_deleted == False,
        CaseFile.event_count > 0,
        # At least one phase incomplete
        or_(
            CaseFile.ioc_hunted == False,
            CaseFile.known_good == False,
            CaseFile.known_noise == False,
            # For EVTX, SIGMA must also be complete
            and_(
                CaseFile.original_filename.ilike('%.evtx'),
                CaseFile.sigma_hunted == False
            )
        )
    ]
    
    if case_id is not None:
        filters.append(CaseFile.case_id == case_id)
    
    return db_session.query(CaseFile).filter(and_(*filters)).all()


def get_statistics_summary(db_session, CaseFile, case_id: Optional[int] = None) -> str:
    """
    Get a human-readable summary of file statistics.
    
    Args:
        db_session: Database session
        CaseFile: CaseFile model class
        case_id: Optional case ID
        
    Returns:
        str: Formatted statistics summary
    """
    stats = get_file_statistics(db_session, CaseFile, case_id)
    
    summary = f"""
File Statistics {'for Case ' + str(case_id) if case_id else '(Global)'}:
{'=' * 60}
Total Files:           {stats['total_files']:,}
Files with Events:     {stats['files_with_events']:,}
Hidden Files:          {stats['hidden_files']:,}
Total Space:           {stats['total_space_gb']} GB

Processing Status:
  Completed:           {stats['completed_files']:,}
  Failed:              {stats['failed_files']:,}
  Queued:              {stats['queued_files']:,}
  New (Not Indexed):   {stats['new_files']:,}

Phase Completion:
  Indexed:             {stats['indexed_files']:,}
  SIGMA Checked:       {stats['sigma_checked']:,}
  IOC Checked:         {stats['ioc_checked']:,}
  Noise Checked:       {stats['noise_checked']:,}
{'=' * 60}
    """.strip()
    
    return summary


# ============================================================================
# INDIVIDUAL HELPER FUNCTIONS (for routes compatibility)
# ============================================================================

def get_completed_files_count(case_id: Optional[int] = None) -> int:
    """Get count of completed files"""
    from main import db, CaseFile
    return get_file_statistics(db.session, CaseFile, case_id)['completed_files']


def get_failed_files_count(case_id: Optional[int] = None) -> int:
    """Get count of failed files"""
    from main import db, CaseFile
    
    base_filter = [CaseFile.is_deleted == False, CaseFile.failed == True]
    if case_id is not None:
        base_filter.append(CaseFile.case_id == case_id)
    
    return db.session.query(func.count(CaseFile.id)).filter(and_(*base_filter)).scalar() or 0


def get_queued_files_count(case_id: Optional[int] = None) -> int:
    """Get count of queued files"""
    from main import db, CaseFile
    return get_file_statistics(db.session, CaseFile, case_id)['queued_files']


def get_indexed_files_count(case_id: Optional[int] = None) -> int:
    """Get count of indexed files"""
    from main import db, CaseFile
    return get_file_statistics(db.session, CaseFile, case_id)['indexed_files']


def get_sigma_checked_files_count(case_id: Optional[int] = None) -> int:
    """Get count of SIGMA-checked files"""
    from main import db, CaseFile
    return get_file_statistics(db.session, CaseFile, case_id)['sigma_checked']


def get_ioc_checked_files_count(case_id: Optional[int] = None) -> int:
    """Get count of IOC-checked files"""
    from main import db, CaseFile
    return get_file_statistics(db.session, CaseFile, case_id)['ioc_checked']


def get_noise_checked_files_count(case_id: Optional[int] = None) -> int:
    """Get count of noise-checked files"""
    from main import db, CaseFile
    return get_file_statistics(db.session, CaseFile, case_id)['noise_checked']


def get_hidden_files_count(case_id: Optional[int] = None) -> int:
    """Get count of hidden files"""
    from main import db, CaseFile
    return get_file_statistics(db.session, CaseFile, case_id)['hidden_files']

