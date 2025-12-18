#!/usr/bin/env python3
"""
CaseScope Processing Module: Indexing
======================================

Handles file indexing operations ONLY. Runs in parallel with 8 workers.

This module is responsible for:
1. Converting files (EVTX, NDJSON, CSV, IIS) to searchable format
2. Indexing events into OpenSearch
3. Updating database metadata

Does NOT handle:
- SIGMA detection (see processing_sigma.py)
- IOC matching (see processing_ioc.py)

Author: CaseScope
Version: 2.0.0 - Modular Processing System
"""

import logging
import os
from typing import Dict, Any, Optional
from celery_app import celery_app
from app import file_state_manager as fsm

logger = logging.getLogger(__name__)


# ==============================================================================
# CELERY TASK: Index Single File
# ==============================================================================

@celery_app.task(bind=True, name='processing_index.index_file_task')
def index_file_task(self, file_id: int) -> Dict[str, Any]:
    """
    Celery task to index a single file.
    
    This task:
    1. Gets file from database
    2. Converts file to JSON format (if needed)
    3. Indexes events to OpenSearch
    4. Updates database with event counts
    
    Args:
        file_id: CaseFile ID to process
        
    Returns:
        dict: {
            'status': 'success'|'error'|'skipped',
            'message': str,
            'file_id': int,
            'event_count': int,
            'error': str (if error)
        }
    """
    from main import app, db
    from models import CaseFile, Case
    from main import opensearch_client
    from file_processing import index_file
    from tasks import commit_with_retry
    from archive_utils import is_case_archived
    
    logger.info(f"[INDEX_TASK] Starting indexing for file_id={file_id}")
    
    with app.app_context():
        try:
            # Get file with row lock to prevent concurrent processing
            case_file = db.session.query(CaseFile).with_for_update().filter_by(id=file_id).first()
            if not case_file:
                return {
                    'status': 'error',
                    'message': 'File not found',
                    'file_id': file_id
                }
            
            # Get case
            case = db.session.get(Case, case_file.case_id)
            if not case:
                return {
                    'status': 'error',
                    'message': 'Case not found',
                    'file_id': file_id
                }
            
            # Archive guard - cannot index files in archived cases
            if is_case_archived(case):
                logger.warning(f"[INDEX_TASK] Cannot index file {file_id}: Case {case.id} is archived")
                case_file.celery_task_id = None
                db.session.commit()
                return {
                    'status': 'error',
                    'message': 'Cannot index file in archived case',
                    'file_id': file_id
                }
            
            # Check if file is already being processed by another task
            if case_file.celery_task_id and case_file.celery_task_id != self.request.id:
                from celery.result import AsyncResult
                old_task = AsyncResult(case_file.celery_task_id, app=celery_app)
                
                if old_task.state in ['SUCCESS', 'FAILURE', 'REVOKED']:
                    logger.warning(f"[INDEX_TASK] Clearing stale task_id {case_file.celery_task_id}")
                    case_file.celery_task_id = None
                    db.session.commit()
                elif old_task.state in ['PENDING', 'STARTED', 'RETRY']:
                    logger.warning(f"[INDEX_TASK] File {file_id} already being processed")
                    return {
                        'status': 'skipped',
                        'message': f'Already being processed (state: {old_task.state})',
                        'file_id': file_id
                    }
            
            # Check if file already indexed (prevent duplicate processing)
            if case_file.is_indexed:
                logger.info(f"[INDEX_TASK] File {file_id} already indexed, skipping")
                case_file.celery_task_id = None
                db.session.commit()
                return {
                    'status': 'skipped',
                    'message': 'File already indexed',
                    'file_id': file_id,
                    'event_count': case_file.event_count or 0
                }
            
            # Set task ID and start indexing
            case_file.celery_task_id = self.request.id
            fsm.start_indexing(case_file)
            db.session.commit()
            
            # Index the file using existing index_file function
            index_result = index_file(
                db=db,
                opensearch_client=opensearch_client,
                CaseFile=CaseFile,
                Case=Case,
                case_id=case.id,
                filename=case_file.original_filename,
                file_path=case_file.file_path,
                file_hash=case_file.file_hash,
                file_size=case_file.file_size,
                uploader_id=case_file.uploaded_by,
                upload_type=case_file.upload_type,
                file_id=file_id,
                celery_task=self,
                force_reindex=False
            )
            
            if index_result['status'] == 'error':
                error_msg = index_result.get('message', 'Unknown indexing error')
                fsm.mark_failed(case_file, error_msg[:500])
                case_file.celery_task_id = None
                db.session.commit()
                return {
                    'status': 'error',
                    'message': error_msg,
                    'file_id': file_id,
                    'error': error_msg
                }
            
            # Mark as indexed (but not completed - SIGMA and IOC still pending)
            fsm.complete_indexing(case_file)
            case_file.celery_task_id = None
            commit_with_retry(db.session, logger_instance=logger)
            
            logger.info(f"[INDEX_TASK] ✓ File {file_id} indexed successfully: {index_result['event_count']} events")
            
            return {
                'status': 'success',
                'message': f'Indexed {index_result["event_count"]} events',
                'file_id': file_id,
                'event_count': index_result['event_count']
            }
            
        except Exception as e:
            logger.error(f"[INDEX_TASK] Error indexing file {file_id}: {e}", exc_info=True)
            try:
                case_file = db.session.get(CaseFile, file_id)
                if case_file:
                    fsm.mark_failed(case_file, str(e)[:500])
                    case_file.celery_task_id = None
                    db.session.commit()
            except:
                pass
            
            return {
                'status': 'error',
                'message': str(e),
                'file_id': file_id,
                'error': str(e)
            }
        
        finally:
            # Always clear celery_task_id in finally block
            try:
                with app.app_context():
                    case_file = db.session.query(CaseFile).filter_by(id=file_id).first()
                    if case_file and case_file.celery_task_id == self.request.id:
                        case_file.celery_task_id = None
                        db.session.commit()
            except:
                pass


# ==============================================================================
# PHASE COORDINATOR: Index All Files in Queue
# ==============================================================================

def index_all_files_in_queue(case_id: int, operation: str = 'index', phase_num: int = 1) -> Dict[str, Any]:
    """
    Index all queued files for a case using parallel workers.
    
    This function:
    1. Gets all unindexed files for case
    2. Queues them for parallel processing (max 8 workers)
    3. Waits for ALL files to complete before returning
    
    Args:
        case_id: Case ID to process
        operation: Operation name for progress tracking ('index' or 'reindex')
        phase_num: Phase number for progress tracking (default: 1)
        
    Returns:
        dict: {
            'status': 'success'|'error',
            'total_files': int,
            'indexed': int,
            'skipped': int,
            'failed': int,
            'errors': list
        }
    """
    from main import app, db
    from models import CaseFile
    from celery import group
    from celery.result import GroupResult
    import time
    
    logger.info(f"[INDEX_PHASE] Starting indexing phase for case {case_id}")
    
    with app.app_context():
        # Get all unindexed files that are queued
        files = CaseFile.query.filter_by(
            case_id=case_id,
            is_indexed=False,
            is_deleted=False,
            is_hidden=False
        ).filter(
            CaseFile.indexing_status.in_(['Queued', 'Failed'])
        ).all()
        
        if not files:
            logger.info(f"[INDEX_PHASE] No files to index for case {case_id}")
            return {
                'status': 'success',
                'total_files': 0,
                'indexed': 0,
                'skipped': 0,
                'failed': 0,
                'errors': []
            }
        
        total_files = len(files)
        logger.info(f"[INDEX_PHASE] Found {total_files} files to index")
        
        # Dispatch tasks individually using .delay() (proven approach from v1.x)
        # This is more reliable than group() for large batches (11K+ files)
        dispatched_count = 0
        
        for f in files:
            try:
                result = index_file_task.delay(f.id)
                dispatched_count += 1
                
                # Log progress every 1000 files
                if dispatched_count % 1000 == 0:
                    logger.info(f"[INDEX_PHASE] Dispatched {dispatched_count}/{total_files} tasks")
            except Exception as e:
                logger.error(f"[INDEX_PHASE] Failed to queue file {f.id}: {e}")
        
        logger.info(f"[INDEX_PHASE] All {dispatched_count} tasks dispatched to workers")
        
        # Wait for all tasks to complete by SIMPLE QUEUE CHECK
        logger.info(f"[INDEX_PHASE] Waiting for {total_files} indexing tasks to complete...")
        
        # Poll DATABASE for completion (with timeout)
        start_time = time.time()
        timeout = 7200  # 2 hours max
        last_log_time = 0
        
        while True:
            elapsed = time.time() - start_time
            if elapsed > timeout:
                logger.error(f"[INDEX_PHASE] Timeout after {timeout}s")
                # Get partial results from DB
                completed = db.session.query(CaseFile).filter(
                    CaseFile.case_id == case_id,
                    CaseFile.indexing_status.in_(['Indexed', 'Completed'])
                ).count()
                failed = db.session.query(CaseFile).filter(
                    CaseFile.case_id == case_id,
                    CaseFile.indexing_status.like('Failed%')
                ).count()
                return {
                    'status': 'error',
                    'total_files': total_files,
                    'indexed': completed,
                    'skipped': 0,
                    'failed': failed,
                    'errors': ['Indexing phase timeout']
                }
            
            # SIMPLE QUEUE CHECK: Count files that are still queued or indexing
            in_progress = db.session.query(CaseFile).filter(
                CaseFile.case_id == case_id,
                CaseFile.indexing_status.in_(['Queued', 'Indexing'])
            ).count()
            
            # Calculate completed for progress bar
            completed_count = total_files - in_progress
            
            # Update progress tracker with counts for progress bar
            from progress_tracker import update_phase
            update_phase(case_id, operation, phase_num, 'Indexing Files', 'running', 
                        f'{completed_count}/{total_files} files indexed',
                        current=completed_count, total=total_files)
            
            # Log progress every 30 seconds
            if elapsed - last_log_time >= 30:
                logger.info(f"[INDEX_PHASE] Progress: {in_progress} files still in queue, {completed_count}/{total_files} done")
                last_log_time = elapsed
            
            # QUEUE CHECK: All done when nothing in queue!
            if in_progress == 0:
                logger.info(f"[INDEX_PHASE] Queue empty, all files processed")
                break
            
            time.sleep(5)
        
        # Collect results from DATABASE
        indexed = db.session.query(CaseFile).filter(
            CaseFile.case_id == case_id,
            CaseFile.indexing_status.in_(['Indexed', 'Completed'])
        ).count()
        
        failed = db.session.query(CaseFile).filter(
            CaseFile.case_id == case_id,
            CaseFile.indexing_status.like('Failed%')
        ).count()
        
        failed_files = db.session.query(CaseFile).filter(
            CaseFile.case_id == case_id,
            CaseFile.indexing_status.like('Failed%')
        ).all()
        
        skipped = 0  # We don't track skipped in DB status
        errors = [f.error_message or f.indexing_status for f in failed_files if f.error_message or 'Failed' in f.indexing_status]
        
        logger.info(f"[INDEX_PHASE] ✓ Indexing complete: {indexed} indexed, {skipped} skipped, {failed} failed")
        
        return {
            'status': 'success',
            'total_files': total_files,
            'indexed': indexed,
            'skipped': skipped,
            'failed': failed,
            'errors': errors[:10]  # Limit error list
        }


# ==============================================================================
# HELPER: Check if Indexing Phase is Complete
# ==============================================================================

def is_indexing_complete(case_id: int) -> bool:
    """
    Check if all files for a case have been indexed.
    
    Args:
        case_id: Case ID to check
        
    Returns:
        bool: True if all files are indexed, False otherwise
    """
    from main import app, db
    from models import CaseFile
    
    with app.app_context():
        # Check for any unindexed files that aren't hidden/deleted
        unindexed_count = CaseFile.query.filter_by(
            case_id=case_id,
            is_indexed=False,
            is_deleted=False,
            is_hidden=False,
            failed=False
        ).count()
        
        return unindexed_count == 0

