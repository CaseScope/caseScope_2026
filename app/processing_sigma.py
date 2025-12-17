#!/usr/bin/env python3
"""
CaseScope Processing Module: SIGMA Detection
=============================================

Handles SIGMA rule detection ONLY. Runs in parallel with 8 workers.

This module is responsible for:
1. Running SIGMA rules against EVTX files using Chainsaw
2. Creating SigmaViolation records in database
3. Flagging events in OpenSearch with has_sigma field

Does NOT handle:
- File indexing (see processing_index.py)
- IOC matching (see processing_ioc.py)

Author: CaseScope
Version: 2.0.0 - Modular Processing System
"""

import logging
from typing import Dict, Any, Optional
from celery_app import celery_app
from sqlalchemy import func

logger = logging.getLogger(__name__)


# ==============================================================================
# CELERY TASK: Run SIGMA Detection on Single File
# ==============================================================================

@celery_app.task(bind=True, name='processing_sigma.sigma_detect_task')
def sigma_detect_task(self, file_id: int) -> Dict[str, Any]:
    """
    Celery task to run SIGMA detection on a single file.
    
    This task:
    1. Checks if file is EVTX (skip others)
    2. Runs Chainsaw with SIGMA rules
    3. Creates SigmaViolation records
    4. Flags matching events in OpenSearch
    
    Args:
        file_id: CaseFile ID to process
        
    Returns:
        dict: {
            'status': 'success'|'error'|'skipped',
            'message': str,
            'file_id': int,
            'violations': int,
            'error': str (if error)
        }
    """
    from main import app, db
    from models import CaseFile, SigmaRule, SigmaViolation
    from main import opensearch_client
    from file_processing import chainsaw_file
    from tasks import commit_with_retry
    from utils import make_index_name
    
    logger.info(f"[SIGMA_TASK] Starting SIGMA detection for file_id={file_id}")
    
    with app.app_context():
        try:
            # Get file
            case_file = db.session.get(CaseFile, file_id)
            if not case_file:
                return {
                    'status': 'error',
                    'message': 'File not found',
                    'file_id': file_id
                }
            
            # Only process EVTX files
            if not case_file.original_filename.lower().endswith('.evtx'):
                logger.info(f"[SIGMA_TASK] Skipping non-EVTX file: {case_file.original_filename}")
                case_file.violation_count = 0
                db.session.commit()
                return {
                    'status': 'skipped',
                    'message': 'Not an EVTX file',
                    'file_id': file_id,
                    'violations': 0
                }
            
            # Check if file is indexed
            if not case_file.is_indexed or case_file.event_count == 0:
                logger.warning(f"[SIGMA_TASK] File {file_id} not indexed or has 0 events, skipping")
                case_file.violation_count = 0
                db.session.commit()
                return {
                    'status': 'skipped',
                    'message': 'File not indexed or 0 events',
                    'file_id': file_id,
                    'violations': 0
                }
            
            # Update status
            case_file.indexing_status = 'SIGMA Testing'
            db.session.commit()
            
            # Get index name
            index_name = make_index_name(case_file.case_id)
            
            # Run SIGMA detection using existing chainsaw_file function
            chainsaw_result = chainsaw_file(
                db=db,
                opensearch_client=opensearch_client,
                CaseFile=CaseFile,
                SigmaRule=SigmaRule,
                SigmaViolation=SigmaViolation,
                file_id=file_id,
                index_name=index_name,
                celery_task=self
            )
            
            if chainsaw_result['status'] == 'error':
                error_msg = chainsaw_result.get('message', 'Unknown SIGMA error')
                case_file.indexing_status = 'Failed (SIGMA)'
                case_file.error_message = error_msg[:500]
                db.session.commit()
                return {
                    'status': 'error',
                    'message': error_msg,
                    'file_id': file_id,
                    'violations': 0,
                    'error': error_msg
                }
            
            # Update status
            violations = chainsaw_result.get('violations', 0)
            case_file.indexing_status = 'SIGMA Complete'
            commit_with_retry(db.session, logger_instance=logger)
            
            logger.info(f"[SIGMA_TASK] ✓ File {file_id} SIGMA complete: {violations} violations")
            
            return {
                'status': 'success',
                'message': f'Found {violations} violations',
                'file_id': file_id,
                'violations': violations
            }
            
        except Exception as e:
            logger.error(f"[SIGMA_TASK] Error processing file {file_id}: {e}", exc_info=True)
            try:
                case_file = db.session.get(CaseFile, file_id)
                if case_file:
                    case_file.indexing_status = f'Failed (SIGMA): {str(e)[:150]}'
                    db.session.commit()
            except:
                pass
            
            return {
                'status': 'error',
                'message': str(e),
                'file_id': file_id,
                'violations': 0,
                'error': str(e)
            }


# ==============================================================================
# PHASE COORDINATOR: Run SIGMA Detection on All EVTX Files
# ==============================================================================

def sigma_detect_all_files(case_id: int, operation: str = 'reindex', phase_num: int = 4) -> Dict[str, Any]:
    """
    Run SIGMA detection on all indexed EVTX files for a case using parallel workers.
    
    This function:
    1. Gets all indexed EVTX files for case
    2. Queues them for parallel SIGMA processing (max 8 workers)
    3. Waits for ALL files to complete before returning
    
    Args:
        case_id: Case ID to process
        operation: Progress tracker operation name (default: 'reindex')
        phase_num: Phase number for progress tracker (default: 4 for reindex)
        
    Returns:
        dict: {
            'status': 'success'|'error',
            'total_files': int,
            'processed': int,
            'skipped': int,
            'failed': int,
            'total_violations': int,
            'errors': list
        }
    """
    from main import app, db
    from models import CaseFile
    from celery import group
    import time
    
    logger.info(f"[SIGMA_PHASE] Starting SIGMA detection phase for case {case_id}")
    
    with app.app_context():
        # Get all indexed EVTX files
        files = CaseFile.query.filter_by(
            case_id=case_id,
            is_indexed=True,
            is_deleted=False,
            is_hidden=False
        ).filter(
            CaseFile.original_filename.ilike('%.evtx')
        ).filter(
            CaseFile.event_count > 0
        ).all()
        
        if not files:
            logger.info(f"[SIGMA_PHASE] No EVTX files to process for case {case_id}")
            return {
                'status': 'success',
                'total_files': 0,
                'processed': 0,
                'skipped': 0,
                'failed': 0,
                'total_violations': 0,
                'errors': []
            }
        
        total_files = len(files)
        logger.info(f"[SIGMA_PHASE] Found {total_files} EVTX files to process")
        
        # Dispatch tasks individually using .delay() (proven approach from v1.x)
        dispatched_count = 0
        
        for f in files:
            try:
                result = sigma_detect_task.delay(f.id)
                dispatched_count += 1
                
                # Log progress every 500 files
                if dispatched_count % 500 == 0:
                    logger.info(f"[SIGMA_PHASE] Dispatched {dispatched_count}/{total_files} tasks")
            except Exception as e:
                logger.error(f"[SIGMA_PHASE] Failed to queue file {f.id}: {e}")
        
        logger.info(f"[SIGMA_PHASE] All {dispatched_count} tasks dispatched to workers")
        
        # Wait for all tasks to complete by SIMPLE QUEUE CHECK
        logger.info(f"[SIGMA_PHASE] Waiting for {total_files} SIGMA tasks to complete...")
        
        start_time = time.time()
        timeout = 7200  # 2 hours max
        last_log_time = 0
        
        while True:
            elapsed = time.time() - start_time
            if elapsed > timeout:
                logger.error(f"[SIGMA_PHASE] Timeout after {timeout}s")
                # Get partial results from DB
                completed = db.session.query(CaseFile).filter(
                    CaseFile.case_id == case_id,
                    CaseFile.original_filename.ilike('%.evtx'),
                    CaseFile.indexing_status == 'SIGMA Complete'
                ).count()
                failed = db.session.query(CaseFile).filter(
                    CaseFile.case_id == case_id,
                    CaseFile.original_filename.ilike('%.evtx'),
                    CaseFile.indexing_status.like('Failed%SIGMA%')
                ).count()
                violations = db.session.query(func.sum(CaseFile.violation_count)).filter(
                    CaseFile.case_id == case_id,
                    CaseFile.original_filename.ilike('%.evtx')
                ).scalar() or 0
                return {
                    'status': 'error',
                    'total_files': total_files,
                    'processed': completed,
                    'skipped': 0,
                    'failed': failed,
                    'total_violations': violations,
                    'errors': ['SIGMA phase timeout']
                }
            
            # QUEUE CHECK: Get actual Celery queue size from Redis
            from celery_app import celery_app
            
            # Get Redis client from Celery backend
            try:
                redis_client = celery_app.broker_connection().channel().client
                
                # Count tasks in the main Celery queue
                queue_size = redis_client.llen('celery')
                
                # Also count active tasks (being processed right now)
                # Active tasks = total_files - (completed in DB) - (in queue)
                completed_in_db = db.session.query(CaseFile).filter(
                    CaseFile.case_id == case_id,
                    CaseFile.original_filename.ilike('%.evtx'),
                    CaseFile.is_deleted == False,
                    CaseFile.indexing_status == 'SIGMA Complete'
                ).count()
                
                # Remaining = in queue + currently processing
                # Currently processing = total - completed - in_queue
                active = total_files - completed_in_db - queue_size
                if active < 0:
                    active = 0
                
                remaining = queue_size + active
                
            except Exception as e:
                logger.warning(f"[SIGMA_PHASE] Could not get queue size from Redis: {e}, falling back to DB status")
                # Fallback: use database statuses
                remaining = db.session.query(CaseFile).filter(
                    CaseFile.case_id == case_id,
                    CaseFile.original_filename.ilike('%.evtx'),
                    CaseFile.is_deleted == False,
                    CaseFile.indexing_status.in_(['Indexed', 'SIGMA Testing'])
                ).count()
            
            # Calculate completed for progress bar
            completed_count = total_files - remaining
            
            # Update progress tracker with counts for progress bar
            from progress_tracker import update_phase
            update_phase(case_id, operation, phase_num, 'SIGMA Detection', 'running',
                        f'{completed_count}/{total_files} files processed',
                        current=completed_count, total=total_files)
            
            # Log progress every 30 seconds
            if elapsed - last_log_time >= 30:
                logger.info(f"[SIGMA_PHASE] Progress: {remaining} files remaining, {completed_count}/{total_files} done")
                last_log_time = elapsed
            
            # QUEUE CHECK: All done when nothing remaining!
            if remaining == 0:
                logger.info(f"[SIGMA_PHASE] Queue empty, all SIGMA tasks complete")
                break
            
            time.sleep(5)
        
        # Collect results from DATABASE
        processed = db.session.query(CaseFile).filter(
            CaseFile.case_id == case_id,
            CaseFile.original_filename.ilike('%.evtx'),
            CaseFile.indexing_status == 'SIGMA Complete'
        ).count()
        
        failed = db.session.query(CaseFile).filter(
            CaseFile.case_id == case_id,
            CaseFile.original_filename.ilike('%.evtx'),
            CaseFile.indexing_status.like('Failed%SIGMA%')
        ).count()
        
        # Get total violations from DB
        total_violations = db.session.query(func.sum(CaseFile.violation_count)).filter(
            CaseFile.case_id == case_id,
            CaseFile.original_filename.ilike('%.evtx')
        ).scalar() or 0
        
        failed_files = db.session.query(CaseFile).filter(
            CaseFile.case_id == case_id,
            CaseFile.original_filename.ilike('%.evtx'),
            CaseFile.indexing_status.like('Failed%SIGMA%')
        ).all()
        
        skipped = 0  # Non-EVTX files weren't queued, so no skipped count
        errors = [f.error_message or f.indexing_status for f in failed_files if f.error_message or 'Failed' in f.indexing_status]
        
        logger.info(f"[SIGMA_PHASE] ✓ SIGMA complete: {processed} processed, {total_violations} violations, {skipped} skipped, {failed} failed")
        
        return {
            'status': 'success',
            'total_files': total_files,
            'processed': processed,
            'skipped': skipped,
            'failed': failed,
            'total_violations': total_violations,
            'errors': errors[:10]
        }


# ==============================================================================
# HELPER: Check if SIGMA Phase is Complete
# ==============================================================================

def is_sigma_complete(case_id: int) -> bool:
    """
    Check if SIGMA detection has been run on all EVTX files for a case.
    
    Args:
        case_id: Case ID to check
        
    Returns:
        bool: True if all EVTX files have been processed, False otherwise
    """
    from main import app, db
    from models import CaseFile
    
    with app.app_context():
        # Check for any indexed EVTX files that haven't had SIGMA run
        pending_count = CaseFile.query.filter_by(
            case_id=case_id,
            is_indexed=True,
            is_deleted=False,
            is_hidden=False
        ).filter(
            CaseFile.original_filename.ilike('%.evtx'),
            CaseFile.event_count > 0,
            CaseFile.indexing_status.notin_(['SIGMA Complete', 'Completed'])
        ).count()
        
        return pending_count == 0

