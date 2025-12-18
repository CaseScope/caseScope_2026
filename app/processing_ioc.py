#!/usr/bin/env python3
"""
CaseScope Processing Module: IOC Matching
==========================================

Handles IOC matching per-file. Runs in parallel with 8 workers.

This module is responsible for:
1. Searching indexed events for IOC matches (per file)
2. Creating IOCMatch records in database
3. Flagging events in OpenSearch with has_ioc field

Does NOT handle:
- File indexing (see processing_index.py)
- SIGMA detection (see processing_sigma.py)

Author: CaseScope
Version: 2.0.1 - Per-File IOC Processing with Queue Tracking
"""

import logging
from typing import Dict, Any, Optional
from celery_app import celery_app
from sqlalchemy import func
import file_state_manager as fsm

logger = logging.getLogger(__name__)


# ==============================================================================
# CELERY TASK: Hunt IOCs in Single File
# ==============================================================================

@celery_app.task(bind=True, name='processing_ioc.hunt_iocs_task')
def hunt_iocs_task(self, file_id: int) -> Dict[str, Any]:
    """
    Celery task to hunt IOCs in a single file.
    
    This task:
    1. Gets file from database
    2. Searches file events for IOC matches
    3. Creates IOCMatch records
    4. Flags matching events with has_ioc
    5. Updates file IOC count
    
    Args:
        file_id: CaseFile ID to process
        
    Returns:
        dict: {
            'status': 'success'|'error'|'skipped',
            'message': str,
            'file_id': int,
            'matches': int,
            'error': str (if error)
        }
    """
    from main import app, db
    from models import CaseFile, IOC, IOCMatch
    from main import opensearch_client
    from file_processing import hunt_iocs
    from tasks import commit_with_retry
    from utils import make_index_name
    
    logger.info(f"[IOC_TASK] Starting IOC hunting for file_id={file_id}")
    
    with app.app_context():
        try:
            # Get file
            case_file = db.session.get(CaseFile, file_id)
            if not case_file:
                return {
                    'status': 'error',
                    'message': 'File not found',
                    'file_id': file_id,
                    'matches': 0
                }
            
            # Check if file is indexed
            if not case_file.is_indexed or case_file.event_count == 0:
                logger.warning(f"[IOC_TASK] File {file_id} not indexed or has 0 events, skipping")
                case_file.ioc_event_count = 0
                db.session.commit()
                return {
                    'status': 'skipped',
                    'message': 'File not indexed or 0 events',
                    'file_id': file_id,
                    'matches': 0
                }
            
            # Get index name
            index_name = make_index_name(case_file.case_id)
            
            # Start IOC hunting
            fsm.start_ioc_hunting(case_file)
            db.session.commit()
            
            # Hunt IOCs using existing hunt_iocs function
            hunt_result = hunt_iocs(
                db=db,
                opensearch_client=opensearch_client,
                CaseFile=CaseFile,
                IOC=IOC,
                IOCMatch=IOCMatch,
                file_id=file_id,
                index_name=index_name,
                celery_task=self
            )
            
            if hunt_result['status'] == 'error':
                error_msg = hunt_result.get('message', 'Unknown IOC error')
                fsm.mark_failed(case_file, error_msg[:500])
                db.session.commit()
                return {
                    'status': 'error',
                    'message': error_msg,
                    'file_id': file_id,
                    'matches': 0,
                    'error': error_msg
                }
            
            # Update status to IOC Complete
            matches = hunt_result.get('matches', 0)
            fsm.complete_ioc_hunting(case_file)
            commit_with_retry(db.session, logger_instance=logger)
            
            logger.info(f"[IOC_TASK] ✓ File {file_id} IOC hunting complete: {matches} matches")
            
            return {
                'status': 'success',
                'message': f'Found {matches} matches',
                'file_id': file_id,
                'matches': matches
            }
            
        except Exception as e:
            logger.error(f"[IOC_TASK] Error hunting IOCs for file {file_id}: {e}", exc_info=True)
            try:
                case_file = db.session.get(CaseFile, file_id)
                if case_file:
                    fsm.mark_failed(case_file, f'IOC: {str(e)[:500]}')
                    db.session.commit()
            except:
                pass
            
            return {
                'status': 'error',
                'message': str(e),
                'file_id': file_id,
                'matches': 0,
                'error': str(e)
            }


# ==============================================================================
# PHASE COORDINATOR: Hunt IOCs in All Files
# ==============================================================================

def hunt_iocs_all_files(case_id: int, operation: str = 'ioc', phase_num: int = 1) -> Dict[str, Any]:
    """
    Hunt IOCs in all indexed files for a case using parallel workers.
    
    Args:
        case_id: Case ID to process
        operation: Operation name for progress tracking ('index', 'reindex', 'reioc', etc.)
        phase_num: Phase number for progress tracking (default: 1)
    
    This function:
    1. Gets all indexed files for case
    2. Queues them for parallel IOC hunting (max 8 workers)
    3. Waits for ALL files to complete before returning
    
    Args:
        case_id: Case ID to process
        
    Returns:
        dict: {
            'status': 'success'|'error',
            'total_files': int,
            'processed': int,
            'skipped': int,
            'failed': int,
            'total_matches': int,
            'errors': list
        }
    """
    from main import app, db
    from models import CaseFile, Case
    from celery import group
    from tasks import commit_with_retry
    import time
    
    logger.info(f"[IOC_PHASE] Starting IOC hunting phase for case {case_id}")
    
    with app.app_context():
        # Get all indexed files (v2.2.0: no is_hidden filter - process all)
        files = CaseFile.query.filter_by(
            case_id=case_id,
            is_indexed=True,
            is_deleted=False
        ).filter(
            CaseFile.event_count > 0
        ).all()
        
        if not files:
            logger.info(f"[IOC_PHASE] No files to process for case {case_id}")
            return {
                'status': 'success',
                'total_files': 0,
                'processed': 0,
                'skipped': 0,
                'failed': 0,
                'total_matches': 0,
                'errors': []
            }
        
        total_files = len(files)
        logger.info(f"[IOC_PHASE] Found {total_files} files to hunt IOCs")
        
        # Dispatch tasks individually using .delay() (proven approach from v1.x)
        dispatched_count = 0
        
        for f in files:
            try:
                result = hunt_iocs_task.delay(f.id)
                dispatched_count += 1
                
                # Log progress every 1000 files
                if dispatched_count % 1000 == 0:
                    logger.info(f"[IOC_PHASE] Dispatched {dispatched_count}/{total_files} tasks")
            except Exception as e:
                logger.error(f"[IOC_PHASE] Failed to queue file {f.id}: {e}")
        
        logger.info(f"[IOC_PHASE] All {dispatched_count} tasks dispatched to workers")
        
        # Wait for all tasks to complete by SIMPLE QUEUE CHECK
        logger.info(f"[IOC_PHASE] Waiting for {total_files} IOC hunting tasks to complete...")
        
        start_time = time.time()
        timeout = 7200  # 2 hours max
        last_log_time = 0
        
        while True:
            elapsed = time.time() - start_time
            if elapsed > timeout:
                logger.error(f"[IOC_PHASE] Timeout after {timeout}s")
                # Get partial results from DB
                completed = db.session.query(CaseFile).filter(
                    CaseFile.case_id == case_id,
                    CaseFile.indexing_status.in_(['IOC Complete', 'Completed'])
                ).count()
                failed = db.session.query(CaseFile).filter(
                    CaseFile.case_id == case_id,
                    CaseFile.indexing_status.like('Failed%IOC%')
                ).count()
                total_matches = db.session.query(func.sum(CaseFile.ioc_event_count)).filter(
                    CaseFile.case_id == case_id
                ).scalar() or 0
                return {
                    'status': 'error',
                    'total_files': total_files,
                    'processed': completed,
                    'skipped': 0,
                    'failed': failed,
                    'total_matches': total_matches,
                    'errors': ['IOC phase timeout']
                }
            
            # SIMPLE QUEUE CHECK: Count files still being IOC hunted
            in_progress = db.session.query(CaseFile).filter(
                CaseFile.case_id == case_id,
                CaseFile.celery_task_id.isnot(None)
            ).count()
            
            # Calculate completed for progress bar
            completed_count = total_files - in_progress
            
            # Update progress tracker with counts for progress bar
            from progress_tracker import update_phase
            update_phase(case_id, operation, phase_num, 'IOC Matching', 'running',
                        f'{completed_count}/{total_files} files processed',
                        current=completed_count, total=total_files)
            
            # Log progress every 30 seconds
            if elapsed - last_log_time >= 30:
                logger.info(f"[IOC_PHASE] Progress: {in_progress} files still in queue, {completed_count}/{total_files} done")
                last_log_time = elapsed
            
            # QUEUE CHECK: All done when nothing in queue!
            if in_progress == 0:
                logger.info(f"[IOC_PHASE] Queue empty, all IOC tasks complete")
                break
            
            time.sleep(5)
        
        # Collect results from DATABASE
        processed = db.session.query(CaseFile).filter(
            CaseFile.case_id == case_id,
            CaseFile.indexing_status.in_(['IOC Complete', 'Completed'])
        ).count()
        
        failed = db.session.query(CaseFile).filter(
            CaseFile.case_id == case_id,
            CaseFile.indexing_status.like('Failed%IOC%')
        ).count()
        
        # Get total matches from DB
        total_matches = db.session.query(func.sum(CaseFile.ioc_event_count)).filter(
            CaseFile.case_id == case_id,
            is_deleted=False
        ).scalar() or 0
        
        failed_files = db.session.query(CaseFile).filter(
            CaseFile.case_id == case_id,
            CaseFile.indexing_status.like('Failed%IOC%')
        ).all()
        
        skipped = 0  # Files with 0 events were skipped
        errors = [f.error_message or f.indexing_status for f in failed_files if f.error_message or 'Failed' in f.indexing_status]
        
        # Update case aggregate
        case = db.session.get(Case, case_id)
        if case:
            case.total_events_with_IOCs = total_matches
            commit_with_retry(db.session, logger_instance=logger)
        
        logger.info(f"[IOC_PHASE] ✓ IOC hunting complete: {processed} processed, {total_matches} total matches, {failed} failed")
        
        return {
            'status': 'success',
            'total_files': total_files,
            'processed': processed,
            'skipped': skipped,
            'failed': failed,
            'total_matches': total_matches,
            'errors': errors[:10]
        }


# ==============================================================================
# HELPER: Check if IOC Hunting is Complete
# ==============================================================================

def is_ioc_hunting_complete(case_id: int) -> bool:
    """
    Check if IOC hunting has been run on all files for a case.
    
    Args:
        case_id: Case ID to check
        
    Returns:
        bool: True if all files have been processed, False otherwise
    """
    from main import app, db
    from models import CaseFile
    
    with app.app_context():
        # Check for any indexed files that haven't had IOC hunting run (v2.2.0: use ioc_hunted flag)
        pending_count = CaseFile.query.filter_by(
            case_id=case_id,
            is_indexed=True,
            is_deleted=False,
            ioc_hunted=False  # v2.2.0: explicit flag instead of status string
        ).filter(
            CaseFile.event_count > 0
        ).count()
        
        return pending_count == 0
