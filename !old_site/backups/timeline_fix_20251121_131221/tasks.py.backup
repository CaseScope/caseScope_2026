#!/usr/bin/env python3
"""
CaseScope 2026 v1.0.0 - Celery Tasks
Minimal task orchestrator - delegates to file_processing.py modular functions
"""

import os
import logging
import shutil
from datetime import datetime

from celery_app import celery_app

logger = logging.getLogger(__name__)


# ============================================================================
# OPENSEARCH SHARD LIMIT PROTECTION
# ============================================================================

def check_opensearch_shard_capacity(opensearch_client, threshold_percent=90):
    """
    Check if OpenSearch cluster has capacity for more shards
    Returns: (has_capacity: bool, current_shards: int, max_shards: int, message: str)
    """
    try:
        # Get cluster stats
        cluster_stats = opensearch_client.cluster.stats()
        current_shards = cluster_stats['indices']['shards']['total']
        
        # Get cluster settings
        cluster_settings = opensearch_client.cluster.get_settings()
        max_shards_setting = cluster_settings.get('persistent', {}).get('cluster', {}).get('max_shards_per_node')
        
        # Default OpenSearch shard limit is 1000 per node, but we set it higher
        # If not explicitly set, assume default * number of nodes
        if not max_shards_setting:
            nodes = cluster_stats['nodes']['count']['total']
            max_shards = 1000 * nodes
        else:
            nodes = cluster_stats['nodes']['count']['total']
            max_shards = int(max_shards_setting) * nodes
        
        # Calculate threshold
        threshold = int(max_shards * (threshold_percent / 100.0))
        has_capacity = current_shards < threshold
        
        message = f"OpenSearch Shards: {current_shards:,}/{max_shards:,} ({(current_shards/max_shards*100):.1f}%)"
        
        if not has_capacity:
            logger.warning(f"[SHARD_LIMIT] {message} - THRESHOLD EXCEEDED ({threshold_percent}%)")
        
        return has_capacity, current_shards, max_shards, message
        
    except Exception as e:
        logger.error(f"[SHARD_LIMIT] Failed to check shard capacity: {e}")
        # On error, assume we have capacity to avoid blocking legitimate operations
        return True, 0, 0, f"Shard check failed: {str(e)}"


# ============================================================================
# DATABASE HELPER
# ============================================================================

def commit_with_retry(session, max_retries=3, logger_instance=None):
    """Commit with retry logic for database locking"""
    import time
    for attempt in range(max_retries):
        try:
            session.commit()
            return True
        except Exception as e:
            if attempt < max_retries - 1:
                if logger_instance:
                    logger_instance.warning(f"DB commit failed (attempt {attempt+1}/{max_retries}), retrying...")
                time.sleep(0.5)
                session.rollback()
            else:
                if logger_instance:
                    logger_instance.error(f"DB commit failed after {max_retries} attempts")
                raise


# ============================================================================
# MAIN WORKER TASK - Orchestrates 4 modular functions
# ============================================================================

@celery_app.task(bind=True, name='tasks.process_file')
def process_file(self, file_id, operation='full'):
    """
    Process a file through the 4-step modular pipeline
    
    Steps:
    1. duplicate_check() - Skip if duplicate
    2. index_file() - EVTX→JSON→OpenSearch
    3. chainsaw_file() - SIGMA detection
    4. hunt_iocs() - IOC hunting
    
    Operations:
    - 'full': All 4 steps
    - 'reindex': Clear + re-index
    - 'chainsaw_only': SIGMA only
    - 'ioc_only': IOC only
    """
    from file_processing import duplicate_check, index_file, chainsaw_file, hunt_iocs
    from main import app, db
    from models import Case, CaseFile, SigmaRule, SigmaViolation, IOC, IOCMatch, SkippedFile
    from main import opensearch_client
    from utils import make_index_name
    
    logger.info(f"[TASK] Processing file_id={file_id}, operation={operation}")
    
    with app.app_context():
        try:
            # Get file record with row-level lock to prevent concurrent processing
            # SELECT FOR UPDATE locks the row until commit, preventing race conditions
            case_file = db.session.query(CaseFile).with_for_update().filter_by(id=file_id).first()
            if not case_file:
                return {'status': 'error', 'message': 'File not found'}
            
            case = db.session.get(Case, case_file.case_id)
            if not case:
                return {'status': 'error', 'message': 'Case not found'}
            
            # Archive guard (v1.18.0): Prevent processing files in archived cases
            # Exception: ioc_only and chainsaw_only operations are allowed (work without source files)
            from archive_utils import is_case_archived
            if operation not in ['ioc_only', 'chainsaw_only'] and is_case_archived(case):
                logger.warning(f"[TASK] Cannot process file {file_id}: Case {case.id} is archived")
                case_file.celery_task_id = None  # Clear task ID
                db.session.commit()
                return {
                    'status': 'error',
                    'message': 'Cannot process file in archived case. Please restore the case first.'
                }
            
            # CRITICAL: Prevent duplicate processing (but allow intentional re-index)
            # Check if file is already being processed by another task
            if case_file.celery_task_id and case_file.celery_task_id != self.request.id:
                # Check if the old task is still active
                from celery.result import AsyncResult
                old_task = AsyncResult(case_file.celery_task_id, app=celery_app)
                
                # If old task is finished (SUCCESS/FAILURE), clear the task_id and continue
                if old_task.state in ['SUCCESS', 'FAILURE', 'REVOKED']:
                    logger.warning(f"[TASK] File {file_id} has stale task_id {case_file.celery_task_id} (state: {old_task.state}), clearing and continuing")
                    case_file.celery_task_id = None
                    db.session.commit()
                # If old task is still pending/running, skip this task
                elif old_task.state in ['PENDING', 'STARTED', 'RETRY']:
                    logger.warning(f"[TASK] File {file_id} already being processed by task {case_file.celery_task_id} (state: {old_task.state}), skipping duplicate")
                    return {'status': 'skipped', 'message': f'File already being processed by another task ({old_task.state})'}
                # Unknown state - clear and continue
                else:
                    logger.warning(f"[TASK] File {file_id} has task_id {case_file.celery_task_id} with unknown state {old_task.state}, clearing and continuing")
                    case_file.celery_task_id = None
                    db.session.commit()
            
            # For 'full' operation: Skip if file is already indexed (prevent duplicate processing)
            # For 'reindex' operation: Allow re-indexing even if already indexed (intentional)
            if operation == 'full' and case_file.is_indexed:
                logger.info(f"[TASK] File {file_id} already indexed (is_indexed=True), skipping 'full' operation to prevent duplicate processing")
                case_file.celery_task_id = None  # Clear task ID since we're skipping
                db.session.commit()
                return {
                    'status': 'skipped',
                    'message': 'File already indexed (use re-index operation to re-process)',
                    'file_id': file_id
                }
            
            case_file.celery_task_id = self.request.id
            db.session.commit()
            
            # CRITICAL: Check OpenSearch shard capacity before processing
            # This prevents the worker from crashing when hitting shard limits
            if operation in ['full', 'reindex']:
                has_capacity, current_shards, max_shards, shard_message = check_opensearch_shard_capacity(
                    opensearch_client, threshold_percent=95
                )
                logger.info(f"[TASK] {shard_message}")
                
                if not has_capacity:
                    error_msg = f"OpenSearch shard limit nearly reached ({current_shards:,}/{max_shards:,}). Please consolidate indices or increase shard limit."
                    logger.error(f"[TASK] {error_msg}")
                    case_file.indexing_status = 'Failed'
                    case_file.error_message = error_msg
                    db.session.commit()
                    return {
                        'status': 'error',
                        'message': error_msg,
                        'file_id': file_id,
                        'event_count': 0,
                        'index_name': None
                    }
            
            index_name = make_index_name(case.id, case_file.original_filename)
            
            # FULL OPERATION
            if operation == 'full':
                # Step 1: Duplicate check
                dup_result = duplicate_check(
                    db=db,
                    CaseFile=CaseFile,
                    SkippedFile=SkippedFile,
                    case_id=case.id,
                    filename=case_file.original_filename,
                    file_path=case_file.file_path,
                    upload_type=case_file.upload_type or 'http',
                    exclude_file_id=file_id
                )
                
                if dup_result['status'] == 'skip':
                    case_file.indexing_status = 'Completed'
                    commit_with_retry(db.session, logger_instance=logger)
                    return {'status': 'success', 'message': 'Skipped (duplicate)'}
                
                # Step 2: Index file
                index_result = index_file(
                    db=db,
                    opensearch_client=opensearch_client,
                    CaseFile=CaseFile,
                    Case=Case,
                    case_id=case.id,
                    filename=case_file.original_filename,
                    file_path=case_file.file_path,
                    file_hash=dup_result['file_hash'],
                    file_size=dup_result['file_size'],
                    uploader_id=case_file.uploaded_by,
                    upload_type=case_file.upload_type,
                    file_id=file_id,  # Use existing CaseFile record
                    celery_task=self
                )
                
                if index_result['status'] == 'error':
                    error_msg = index_result.get('message', 'Unknown indexing error')
                    case_file.indexing_status = 'Failed'
                    case_file.error_message = error_msg[:500]
                    db.session.commit()
                    return index_result
                
                if index_result['event_count'] == 0:
                    # File already marked as hidden and indexed by file_processing.py
                    # No need to modify or commit again
                    return {'status': 'success', 'message': '0 events (hidden)'}
                
                # Step 3: SIGMA Testing (EVTX only)
                if case_file.original_filename.lower().endswith('.evtx'):
                    case_file.indexing_status = 'SIGMA Testing'
                    db.session.commit()
                    
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
                else:
                    logger.info(f"[TASK] Skipping SIGMA (non-EVTX file): {case_file.original_filename}")
                    chainsaw_result = {'status': 'success', 'message': 'Skipped (non-EVTX)', 'violations': 0}
                
                # Step 4: IOC Hunting
                case_file.indexing_status = 'IOC Hunting'
                db.session.commit()
                
                ioc_result = hunt_iocs(
                    db=db,
                    opensearch_client=opensearch_client,
                    CaseFile=CaseFile,
                    IOC=IOC,
                    IOCMatch=IOCMatch,
                    file_id=file_id,
                    index_name=index_name,
                    celery_task=self
                )
                
                # CRITICAL: Validate index exists before marking "Completed"
                # Prevents data corruption if worker crashes during indexing
                if not case_file.is_hidden and case_file.event_count > 0:
                    try:
                        if not opensearch_client.indices.exists(index=index_name):
                            error_msg = f'Index {index_name} does not exist despite file having {case_file.event_count} events. Worker may have crashed during indexing, or index was deleted externally.'
                            logger.error(f"[TASK] ❌ VALIDATION FAILED: {error_msg}")
                            logger.error(f"[TASK] ❌ Setting status to 'Failed' to prevent data corruption")
                            case_file.indexing_status = 'Failed: Index missing after processing'
                            case_file.error_message = error_msg
                            case_file.celery_task_id = None
                            db.session.commit()
                            return {
                                'status': 'error',
                                'message': 'Index validation failed - index does not exist',
                                'file_id': file_id
                            }
                    except Exception as e:
                        logger.error(f"[TASK] ❌ Index validation error: {e}")
                        # Continue anyway - might be OpenSearch connectivity issue
                
                # Mark as completed
                case_file.indexing_status = 'Completed'
                case_file.celery_task_id = None
                commit_with_retry(db.session, logger_instance=logger)
                
                logger.info(f"[TASK] ✓ File {file_id} completed successfully (events={index_result['event_count']}, violations={chainsaw_result.get('violations', 0)}, ioc_matches={ioc_result.get('matches', 0)})")
                
                return {
                    'status': 'success',
                    'message': 'Processing completed',
                    'stats': {
                        'events': index_result['event_count'],
                        'violations': chainsaw_result.get('violations', 0),
                        'ioc_matches': ioc_result.get('matches', 0)
                    }
                }
            
            # REINDEX OPERATION (v1.16.25 FIX - Re-index All Files button)
            elif operation == 'reindex':
                """
                Re-index operation: Forces complete re-processing (no duplicate check)
                Assumes: OpenSearch data cleared, DB metadata reset by caller
                Used by: bulk_reindex, bulk_reindex_selected, reindex_single_file
                """
                logger.info(f"[TASK] REINDEX - forcing complete re-processing of file {file_id}")
                
                # Index file with force_reindex=True (skips is_indexed check in file_processing.py)
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
                    force_reindex=True  # CRITICAL: Force re-indexing
                )
                
                if index_result['status'] == 'error':
                    error_msg = index_result.get('message', 'Unknown indexing error')
                    case_file.indexing_status = 'Failed'
                    case_file.error_message = error_msg[:500]
                    db.session.commit()
                    return index_result
                
                if index_result['event_count'] == 0:
                    return {'status': 'success', 'message': '0 events (hidden)'}
                
                # SIGMA Testing (EVTX only)
                if case_file.original_filename.lower().endswith('.evtx'):
                    case_file.indexing_status = 'SIGMA Testing'
                    db.session.commit()
                    
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
                else:
                    logger.info(f"[TASK] Skipping SIGMA (non-EVTX file): {case_file.original_filename}")
                    chainsaw_result = {'status': 'success', 'message': 'Skipped (non-EVTX)', 'violations': 0}
                
                # IOC Hunting
                case_file.indexing_status = 'IOC Hunting'
                db.session.commit()
                
                ioc_result = hunt_iocs(
                    db=db,
                    opensearch_client=opensearch_client,
                    CaseFile=CaseFile,
                    IOC=IOC,
                    IOCMatch=IOCMatch,
                    file_id=file_id,
                    index_name=index_name,
                    celery_task=self
                )
                
                # Mark completed
                case_file.indexing_status = 'Completed'
                case_file.celery_task_id = None
                commit_with_retry(db.session, logger_instance=logger)
                
                return {
                    'status': 'success',
                    'message': 'Re-indexing completed',
                    'stats': {
                        'events': index_result['event_count'],
                        'violations': chainsaw_result.get('violations', 0),
                        'ioc_matches': ioc_result.get('matches', 0)
                    }
                }
            
            # CHAINSAW ONLY
            elif operation == 'chainsaw_only':
                from models import SigmaViolation
                from bulk_operations import clear_file_sigma_flags_in_opensearch
                
                # Clear database violations
                db.session.query(SigmaViolation).filter_by(file_id=file_id).delete()
                db.session.commit()
                
                # CRITICAL: Clear OpenSearch SIGMA flags BEFORE re-running SIGMA
                # This ensures old has_sigma flags and sigma_rule fields are removed
                flags_cleared = clear_file_sigma_flags_in_opensearch(
                    opensearch_client, 
                    case_file.case_id, 
                    case_file
                )
                logger.info(f"[TASK] Cleared SIGMA flags from {flags_cleared} events in {index_name} before re-running SIGMA")
                
                result = chainsaw_file(
                    db=db,
                    opensearch_client=opensearch_client,
                    CaseFile=CaseFile,
                    SigmaRule=SigmaRule,
                    SigmaViolation=SigmaViolation,
                    file_id=file_id,
                    index_name=index_name,
                    celery_task=self
                )
                
                case_file.indexing_status = 'Completed'
                case_file.celery_task_id = None  # v1.17.2 FIX: Clear task ID on completion
                commit_with_retry(db.session, logger_instance=logger)
                return result
            
            # IOC ONLY
            elif operation == 'ioc_only':
                from models import IOCMatch
                # v1.17.1 FIX: Clear IOC matches ONLY for this file, not entire case
                # BEFORE (WRONG): filter(IOCMatch.index_name == index_name) cleared ALL files in case
                # AFTER (CORRECT): filter_by(file_id=file_id) clears only current file
                db.session.query(IOCMatch).filter_by(file_id=file_id).delete()
                db.session.commit()
                
                result = hunt_iocs(
                    db=db,
                    opensearch_client=opensearch_client,
                    CaseFile=CaseFile,
                    IOC=IOC,
                    IOCMatch=IOCMatch,
                    file_id=file_id,
                    index_name=index_name,
                    celery_task=self
                )
                
                case_file.indexing_status = 'Completed'
                case_file.celery_task_id = None  # v1.17.2 FIX: Clear task ID on completion
                commit_with_retry(db.session, logger_instance=logger)
                return result
            
            else:
                return {'status': 'error', 'message': f'Unknown operation: {operation}'}
        
        except Exception as e:
            logger.error(f"[TASK] ❌ Processing failed for file_id={file_id}: {e}", exc_info=True)
            try:
                case_file = db.session.get(CaseFile, file_id)
                if case_file:
                    error_msg = str(e)[:150]  # Truncate long error messages
                    case_file.indexing_status = f'Failed: {error_msg}'
                    case_file.celery_task_id = None  # Clear task ID so file can be re-queued
                    db.session.commit()
                    logger.error(f"[TASK] ❌ File {file_id} marked as 'Failed' (can be re-queued)")
            except Exception as db_error:
                logger.error(f"[TASK] ❌ Could not update file status: {db_error}")
            return {'status': 'error', 'message': str(e), 'file_id': file_id}
        
        finally:
            # CRITICAL: Always clear celery_task_id, even if worker crashes
            # This prevents files from getting stuck in "processing" state forever
            # If task crashes before reaching the normal cleanup, this ensures the file can be re-queued
            try:
                # Need new app context in case the main one was rolled back
                with app.app_context():
                    case_file = db.session.query(CaseFile).filter_by(id=file_id).first()
                    if case_file and case_file.celery_task_id == self.request.id:
                        case_file.celery_task_id = None
                        db.session.commit()
                        logger.debug(f"[TASK] ✓ Cleanup: Cleared celery_task_id for file {file_id}")
            except Exception as cleanup_error:
                # Log but don't raise - cleanup failure shouldn't fail the task
                logger.warning(f"[TASK] ⚠ Failed to clear celery_task_id in finally block: {cleanup_error}")


# ============================================================================
# BULK OPERATIONS
# ============================================================================

@celery_app.task(bind=True, name='tasks.bulk_reindex')
def bulk_reindex(self, case_id):
    """Re-index all files in a case (clears OpenSearch data and DB metadata first)"""
    from main import app, db, opensearch_client
    from bulk_operations import (
        get_case_files, clear_case_opensearch_indices, 
        clear_case_sigma_violations, clear_case_ioc_matches,
        clear_case_timeline_tags, reset_file_metadata, queue_file_processing
    )
    
    with app.app_context():
        # Get all files for case (exclude deleted and hidden files)
        # Hidden files = 0-event files or CyLR artifacts, no point re-indexing
        files = get_case_files(db, case_id, include_deleted=False, include_hidden=False)
        
        if not files:
            return {'status': 'success', 'message': 'No files to reindex', 'files_queued': 0}
        
        # Clear all OpenSearch indices for this case
        indices_deleted = clear_case_opensearch_indices(opensearch_client, case_id, files)
        
        # Clear all SIGMA violations, IOC matches, and timeline tags for this case
        sigma_deleted = clear_case_sigma_violations(db, case_id)
        ioc_deleted = clear_case_ioc_matches(db, case_id)
        tags_deleted = clear_case_timeline_tags(db, case_id)
        
        # Reset all file metadata (including opensearch_key)
        for f in files:
            reset_file_metadata(f, reset_opensearch_key=True)
        
        commit_with_retry(db.session, logger_instance=logger)
        logger.info(f"[BULK REINDEX] Reset metadata for {len(files)} files")
        
        # Queue for re-indexing (v1.16.25: Use 'reindex' operation to force processing)
        queued = queue_file_processing(process_file, files, operation='reindex', db_session=db.session)
        
        return {
            'status': 'success',
            'files_queued': queued,
            'indices_deleted': indices_deleted,
            'sigma_cleared': sigma_deleted,
            'ioc_cleared': ioc_deleted,
            'timeline_tags_cleared': tags_deleted
        }


@celery_app.task(bind=True, name='tasks.bulk_rechainsaw')
def bulk_rechainsaw(self, case_id):
    """Re-run SIGMA on all files in a case (clears old violations and OpenSearch flags first)"""
    from main import app, db, opensearch_client
    from bulk_operations import (
        get_case_files, clear_case_sigma_violations, clear_case_sigma_flags_in_opensearch, queue_file_processing
    )
    
    with app.app_context():
        # Get indexed files first (needed for clearing OpenSearch flags)
        files = get_case_files(db, case_id, include_deleted=False, include_hidden=False)
        files = [f for f in files if f.is_indexed]
        
        if not files:
            return {'status': 'success', 'message': 'No indexed files to process', 'files_queued': 0}
        
        # Clear all existing SIGMA violations for this case (database)
        sigma_deleted = clear_case_sigma_violations(db, case_id)
        
        # CRITICAL: Clear has_sigma flags and sigma_rule fields from OpenSearch indices
        # This ensures old SIGMA flags don't persist after re-run
        flags_cleared = clear_case_sigma_flags_in_opensearch(opensearch_client, case_id, files)
        
        # Reset violation_count and set status to Queued for all files
        for f in files:
            f.violation_count = 0
            f.indexing_status = 'Queued'
            f.celery_task_id = None
        
        commit_with_retry(db.session, logger_instance=logger)
        logger.info(f"[BULK RECHAINSAW] Reset violation_count and status to 'Queued' for {len(files)} files")
        
        # Queue re-chainsaw tasks
        queued = queue_file_processing(process_file, files, operation='chainsaw_only', db_session=db.session)
        
        return {'status': 'success', 'files_queued': queued, 'violations_cleared': sigma_deleted, 'flags_cleared': flags_cleared}


@celery_app.task(bind=True, name='tasks.bulk_rehunt')
def bulk_rehunt(self, case_id):
    """Re-hunt IOCs on all files in a case (clears old matches first)"""
    from main import app, db, opensearch_client
    from bulk_operations import (
        get_case_files, clear_case_ioc_matches, clear_case_ioc_flags_in_opensearch, queue_file_processing
    )
    
    with app.app_context():
        # IMPORTANT: Clear OpenSearch caches before bulk IOC hunting
        # This prevents circuit breaker errors due to high heap usage
        try:
            logger.info(f"[BULK REHUNT] Clearing OpenSearch caches before IOC hunt...")
            opensearch_client.indices.clear_cache(
                index='*',
                fielddata=True,
                query=True,
                request=True
            )
            logger.info(f"[BULK REHUNT] ✓ OpenSearch caches cleared successfully")
        except Exception as e:
            logger.warning(f"[BULK REHUNT] Failed to clear OpenSearch cache: {e}")
        
        # Get files first (needed for clearing OpenSearch flags)
        files = get_case_files(db, case_id, include_deleted=False, include_hidden=False)
        files = [f for f in files if f.is_indexed]
        
        if not files:
            return {'status': 'success', 'message': 'No indexed files to process', 'files_queued': 0}
        
        # Clear all existing IOC matches for this case (database)
        ioc_deleted = clear_case_ioc_matches(db, case_id)
        
        # CRITICAL: Clear has_ioc flags from OpenSearch indices
        # This ensures old IOC flags don't persist after re-hunt
        flags_cleared = clear_case_ioc_flags_in_opensearch(opensearch_client, case_id, files)
        
        # Reset ioc_event_count and set status to Queued for all files
        for f in files:
            f.ioc_event_count = 0
            f.indexing_status = 'Queued'
            f.celery_task_id = None
        
        commit_with_retry(db.session, logger_instance=logger)
        logger.info(f"[BULK REHUNT] Reset ioc_event_count and status to 'Queued' for {len(files)} files")
        
        # Queue re-hunt tasks
        queued = queue_file_processing(process_file, files, operation='ioc_only', db_session=db.session)
        
        return {'status': 'success', 'files_queued': queued, 'matches_cleared': ioc_deleted, 'flags_cleared': flags_cleared}


@celery_app.task(bind=True, name='tasks.refresh_descriptions_case')
def refresh_descriptions_case(self, case_id):
    """Refresh event descriptions for a specific case (v1.13.7)"""
    from main import app, db, opensearch_client
    from models import EventDescription
    from evtx_enrichment import update_event_descriptions_for_case
    
    with app.app_context():
        logger.info(f"[REFRESH DESCRIPTIONS] Starting for case {case_id}")
        
        result = update_event_descriptions_for_case(
            opensearch_client, db, EventDescription, case_id
        )
        
        if result['status'] == 'success':
            logger.info(f"[REFRESH DESCRIPTIONS] ✓ Case {case_id}: {result['message']}")
        else:
            logger.error(f"[REFRESH DESCRIPTIONS] ✗ Case {case_id}: {result['message']}")
        
        return result


@celery_app.task(bind=True, name='tasks.refresh_descriptions_global')
def refresh_descriptions_global(self):
    """Refresh event descriptions for ALL cases (v1.13.7)"""
    from main import app, db, opensearch_client
    from models import EventDescription, Case
    from evtx_enrichment import update_event_descriptions_global
    
    with app.app_context():
        logger.info(f"[REFRESH DESCRIPTIONS GLOBAL] Starting global refresh")
        
        result = update_event_descriptions_global(
            opensearch_client, db, EventDescription, Case
        )
        
        if result['status'] == 'success':
            logger.info(f"[REFRESH DESCRIPTIONS GLOBAL] ✓ {result['message']}")
        else:
            logger.error(f"[REFRESH DESCRIPTIONS GLOBAL] ✗ {result['message']}")
        
        return result


@celery_app.task(bind=True, name='tasks.single_file_rehunt')
def single_file_rehunt(self, file_id):
    """Re-hunt IOCs on a single file (clears old matches first)"""
    from main import app, db
    from models import CaseFile
    from bulk_operations import clear_file_ioc_matches, queue_file_processing
    
    with app.app_context():
        case_file = db.session.get(CaseFile, file_id)
        if not case_file:
            return {'status': 'error', 'message': 'File not found'}
        
        # Clear existing IOC matches for this file
        ioc_deleted = clear_file_ioc_matches(db, file_id)
        
        # Reset ioc_event_count and set status to Queued
        case_file.ioc_event_count = 0
        case_file.indexing_status = 'Queued'
        case_file.celery_task_id = None
        commit_with_retry(db.session, logger_instance=logger)
        
        # Queue re-hunt task
        queue_file_processing(process_file, [case_file], operation='ioc_only', db_session=db.session)
        
        return {'status': 'success', 'file_id': file_id, 'matches_cleared': ioc_deleted}


# ============================================================================
# BULK IMPORT TASK - Process files from local directory
# ============================================================================

@celery_app.task(bind=True, name='tasks.bulk_import_directory')
def bulk_import_directory(self, case_id):
    """
    Process all files from bulk import directory
    
    Reuses upload_pipeline functions for consistency:
    - Scans /opt/casescope/bulk_import/ directory
    - Stages files (with ZIP extraction)
    - Builds file queue (deduplication)
    - Queues for processing
    
    Args:
        case_id: Target case ID
        
    Returns:
        Dict with processing summary
    """
    from main import app, db
    from models import CaseFile, SkippedFile
    from bulk_import import scan_bulk_import_directory, BULK_IMPORT_DIR
    from upload_pipeline import (
        stage_bulk_upload,
        extract_zips_in_staging,
        build_file_queue,
        filter_zero_event_files,
        ensure_staging_exists,
        clear_staging
    )
    from bulk_operations import queue_file_processing
    
    with app.app_context():
        try:
            logger.info(f"[BULK IMPORT] Starting bulk import for case {case_id}")
            
            # Update task state
            self.update_state(state='PROGRESS', meta={'stage': 'Scanning directory', 'progress': 0})
            
            # Step 1: Scan bulk import directory
            scan_result = scan_bulk_import_directory()
            
            if 'error' in scan_result:
                logger.error(f"[BULK IMPORT] Scan failed: {scan_result['error']}")
                return {'status': 'error', 'message': scan_result['error']}
            
            total_files = scan_result['total_supported']
            
            if total_files == 0:
                logger.info("[BULK IMPORT] No files found in directory")
                # Update state before returning so UI shows message
                self.update_state(state='PROGRESS', meta={
                    'stage': 'No files found',
                    'progress': 100,
                    'message': 'No files found in bulk import directory'
                })
                return {'status': 'success', 'message': 'No files to import', 'files_processed': 0}
            
            logger.info(f"[BULK IMPORT] Found {total_files} files to import")
            
            # Get file list for display
            files_by_type = scan_result.get('files_by_type', {})
            all_files = []
            for file_list in files_by_type.values():
                all_files.extend([os.path.basename(f) for f in file_list])
            
            # Update progress
            self.update_state(state='PROGRESS', meta={
                'stage': 'Staging files',
                'progress': 10,
                'files_found': total_files,
                'current_file': None,
                'files_list': all_files[:50],  # Show first 50 files
                'files_processed': 0,
                'files_total': total_files
            })
            
            # Step 2: Stage files from bulk import directory
            # Ensure staging directory exists
            staging_dir = ensure_staging_exists(case_id)
            files_staged = 0
            staged_file_list = []
            
            # Stage files one by one with progress updates
            for file_type, file_paths in files_by_type.items():
                if file_type == 'other':
                    continue
                for file_path in file_paths:
                    filename = os.path.basename(file_path)
                    try:
                        # Update progress for each file
                        self.update_state(state='PROGRESS', meta={
                            'stage': 'Staging files',
                            'progress': 10 + int((files_staged / total_files) * 20),
                            'files_found': total_files,
                            'current_file': filename,
                            'files_list': all_files[:50],
                            'files_processed': files_staged,
                            'files_total': total_files
                        })
                        
                        dest_path = os.path.join(staging_dir, filename)
                        shutil.copy2(file_path, dest_path)
                        files_staged += 1
                        staged_file_list.append(filename)
                        
                        # Cleanup original
                        try:
                            os.remove(file_path)
                        except:
                            pass
                            
                    except Exception as e:
                        logger.error(f"[BULK IMPORT] Failed to stage {filename}: {e}")
                        continue
            
            stage_result = {
                'status': 'success',
                'files_staged': files_staged,
                'staged_files': staged_file_list
            }
            
            logger.info(f"[BULK IMPORT] Staged {files_staged} files")
            
            # Step 3: Extract ZIPs with progress tracking
            # Find ZIP files first
            zip_files = [f for f in os.listdir(staging_dir) 
                        if f.lower().endswith('.zip') and not f.startswith('_temp_')]
            
            extracted_count = 0
            extracted_files = []
            zips_processed = 0
            
            for zip_idx, zip_filename in enumerate(zip_files):
                # Update progress for each ZIP
                self.update_state(state='PROGRESS', meta={
                    'stage': 'Extracting ZIPs',
                    'progress': 30 + int((zip_idx / len(zip_files)) * 20) if zip_files else 30,
                    'files_staged': files_staged,
                    'current_file': f'Extracting {zip_filename}',
                    'zips_processed': zip_idx,
                    'zips_total': len(zip_files),
                    'files_extracted': extracted_count
                })
                
                zip_path = os.path.join(staging_dir, zip_filename)
                try:
                    from upload_pipeline import extract_single_zip
                    extract_stats = extract_single_zip(zip_path, staging_dir)
                    extracted_count += extract_stats.get('files_extracted', 0)
                    zips_processed += 1
                    
                    # Track extracted files (limited list)
                    if len(extracted_files) < 20:
                        extracted_files.append(f"{zip_filename} → {extract_stats.get('files_extracted', 0)} files")
                    
                    # Delete original ZIP
                    os.remove(zip_path)
                    logger.info(f"[BULK IMPORT] Extracted {zip_filename}: {extract_stats.get('files_extracted', 0)} files")
                except Exception as e:
                    logger.error(f"[BULK IMPORT] Failed to extract {zip_filename}: {e}")
                    continue
            
            extract_result = {
                'status': 'success',
                'total_extracted': extracted_count,
                'zips_processed': zips_processed,
                'extracted_files': extracted_files
            }
            
            logger.info(f"[BULK IMPORT] Extracted {extracted_count} files from {zips_processed} ZIPs")
            
            # Step 4: Build file queue (deduplication, 0-event detection)
            # Get list of files in staging for progress tracking
            staging_files = [f for f in os.listdir(staging_dir) 
                            if os.path.isfile(os.path.join(staging_dir, f))]
            
            self.update_state(state='PROGRESS', meta={
                'stage': 'Building file queue',
                'progress': 50,
                'files_extracted': extracted_count,
                'current_file': f'Processing {len(staging_files)} files',
                'files_in_staging': len(staging_files)
            })
            
            queue_result = build_file_queue(db, CaseFile, SkippedFile, case_id)
            
            if queue_result['status'] != 'success':
                logger.error(f"[BULK IMPORT] Queue build failed: {queue_result.get('message')}")
                clear_staging(case_id)
                return queue_result
            
            # Get filenames from queue for display
            queue_file_names = [item[1] for item in queue_result['queue'][:30]]  # First 30 files
            
            # Update progress
            self.update_state(state='PROGRESS', meta={
                'stage': 'Filtering files',
                'progress': 70,
                'total_in_queue': len(queue_result['queue']),
                'queue_files': queue_file_names,
                'duplicates_skipped': queue_result.get('duplicates_skipped', 0)
            })
            
            # Step 5: Filter zero-event files
            filter_result = filter_zero_event_files(
                db, CaseFile, SkippedFile,
                queue_result['queue'],
                case_id
            )
            
            valid_count = filter_result['valid_files']
            
            # Get valid file names for display
            valid_file_names = [item[1] for item in filter_result['filtered_queue'][:30]]
            
            # Update progress
            self.update_state(state='PROGRESS', meta={
                'stage': 'Queueing for processing',
                'progress': 90,
                'valid_files': valid_count,
                'valid_file_names': valid_file_names,
                'zero_event_files': filter_result.get('zero_events', 0)
            })
            
            # Step 6: Queue valid files for processing
            # Get CaseFile objects for the filtered queue
            if valid_count > 0:
                file_ids = [item[0] for item in filter_result['filtered_queue']]
                case_files = db.session.query(CaseFile).filter(CaseFile.id.in_(file_ids)).all()
                
                # Update progress while queueing
                self.update_state(state='PROGRESS', meta={
                    'stage': 'Queueing for processing',
                    'progress': 95,
                    'valid_files': valid_count,
                    'valid_file_names': valid_file_names,
                    'queued_count': len(case_files)
                })
                
                queue_file_processing(process_file, case_files, operation='full', db_session=db.session)
                logger.info(f"[BULK IMPORT] Queued {len(case_files)} files for processing")
            
            # Clean up staging
            clear_staging(case_id)
            
            # Final summary
            summary = {
                'status': 'success',
                'files_found': total_files,
                'files_staged': files_staged,
                'files_extracted': extracted_count,
                'duplicates_skipped': queue_result.get('duplicates_skipped', 0),
                'zero_event_files': filter_result.get('zero_events', 0),
                'valid_files': valid_count,
                'queued_for_processing': valid_count,
                'files_processed': valid_count  # Add this for UI check
            }
            
            logger.info(f"[BULK IMPORT] Complete: {summary}")
            
            # Don't update state to SUCCESS - let Celery mark it as SUCCESS when we return
            # The frontend will detect SUCCESS state from Celery's result
            return summary
            
        except Exception as e:
            logger.error(f"[BULK IMPORT] Fatal error: {e}", exc_info=True)
            # Update state to show error before returning
            try:
                self.update_state(state='FAILURE', meta={
                    'error': str(e),
                    'stage': 'Error',
                    'progress': 0
                })
            except:
                pass
            # Try to clean up on error
            try:
                clear_staging(case_id)
            except:
                pass
            raise  # Re-raise so Celery marks task as FAILURE


# ============================================================================
# AI REPORT GENERATION
# ============================================================================

@celery_app.task(bind=True, name='tasks.generate_ai_report')
def generate_ai_report(self, report_id):
    """
    Generate AI report for a case using Ollama + Phi-3 14B
    
    Args:
        report_id: ID of the AIReport database record
        
    Returns:
        dict: Status and results
    """
    from main import app, db, opensearch_client
    from models import AIReport, Case, IOC, SystemSettings
    from ai_report import generate_case_report_prompt, generate_report_with_ollama, format_report_title, markdown_to_html
    from datetime import datetime
    import time
    
    logger.info(f"[AI REPORT] Starting generation for report_id={report_id}")
    
    with app.app_context():
        try:
            # Get report record
            report = db.session.get(AIReport, report_id)
            if not report:
                logger.error(f"[AI REPORT] Report {report_id} not found")
                return {'status': 'error', 'message': 'Report not found'}
            
            # Store Celery task ID for cancellation support
            report.celery_task_id = self.request.id
            report.status = 'generating'
            report.current_stage = 'Initializing'
            report.progress_percent = 5
            report.progress_message = 'Initializing AI report generation...'
            db.session.commit()
            logger.info(f"[AI REPORT] Task ID: {self.request.id}")
            
            # Check for cancellation
            report = db.session.get(AIReport, report_id)
            if report.status == 'cancelled':
                logger.info(f"[AI REPORT] Report {report_id} was cancelled before starting")
                # Release AI lock on cancellation
                try:
                    from ai_resource_lock import release_ai_lock
                    release_ai_lock()
                    logger.info(f"[AI REPORT] ✅ AI lock released (cancelled early)")
                except Exception as lock_err:
                    logger.error(f"[AI REPORT] Failed to release lock on cancellation: {lock_err}")
                return {'status': 'cancelled', 'message': 'Report generation was cancelled'}
            
            # Get case data
            case = db.session.get(Case, report.case_id)
            if not case:
                report.status = 'failed'
                report.error_message = 'Case not found'
                db.session.commit()
                # Release AI lock on failure
                try:
                    from ai_resource_lock import release_ai_lock
                    release_ai_lock()
                    logger.info(f"[AI REPORT] ✅ AI lock released (case not found)")
                except Exception as lock_err:
                    logger.error(f"[AI REPORT] Failed to release lock: {lock_err}")
                return {'status': 'error', 'message': 'Case not found'}
            
            logger.info(f"[AI REPORT] Gathering data for case '{case.name}'")
            
            # STAGE 1: Collecting Data
            report.current_stage = 'Collecting Data'
            report.progress_percent = 15
            report.progress_message = f'Collecting IOCs and tagged events for {case.name}...'
            db.session.commit()
            
            # Check for cancellation
            report = db.session.get(AIReport, report_id)
            if report.status == 'cancelled':
                logger.info(f"[AI REPORT] Report {report_id} was cancelled during data collection")
                # Release AI lock on cancellation
                try:
                    from ai_resource_lock import release_ai_lock
                    release_ai_lock()
                    logger.info(f"[AI REPORT] ✅ AI lock released (cancelled during data collection)")
                except Exception as lock_err:
                    logger.error(f"[AI REPORT] Failed to release lock on cancellation: {lock_err}")
                return {'status': 'cancelled', 'message': 'Report generation was cancelled'}
            
            iocs = IOC.query.filter_by(case_id=case.id).all()
            logger.info(f"[AI REPORT] Found {len(iocs)} IOCs")
            
            # Get systems for case (for improved AI context)
            from models import System
            systems = System.query.filter_by(case_id=case.id, hidden=False).all()
            logger.info(f"[AI REPORT] Found {len(systems)} systems")
            
            # Get tagged events from OpenSearch (using TimelineTag table)
            # NO LIMIT - Send ALL tagged events to AI (full context for better accuracy)
            report.progress_percent = 30
            report.progress_message = 'Fetching ALL tagged events from database...'
            db.session.commit()
            
            tagged_events = []
            try:
                # Get tagged event IDs from TimelineTag table (same as search page)
                from models import TimelineTag
                timeline_tags = TimelineTag.query.filter_by(case_id=case.id).order_by(TimelineTag.created_at.asc()).all()
                
                if timeline_tags:
                    logger.info(f"[AI REPORT] Found {len(timeline_tags)} tagged events in database")
                    
                    # CRITICAL: Enforce maximum event limit to prevent OOM crashes
                    MAX_EVENTS_FOR_AI = 50000
                    if len(timeline_tags) > MAX_EVENTS_FOR_AI:
                        logger.error(f"[AI REPORT] ❌ Too many tagged events: {len(timeline_tags):,} (max: {MAX_EVENTS_FOR_AI:,})")
                        report.status = 'failed'
                        report.error_message = (
                            f'Too many tagged events ({len(timeline_tags):,}). '
                            f'Maximum allowed: {MAX_EVENTS_FOR_AI:,}. '
                            f'Please tag only the most important events for AI analysis. '
                            f'Tip: Focus on IOC hits, SIGMA violations, and key security events.'
                        )
                        db.session.commit()
                        
                        # Release AI lock on failure
                        try:
                            from ai_resource_lock import release_ai_lock
                            release_ai_lock()
                            logger.info(f"[AI REPORT] ✅ AI lock released (too many events)")
                        except Exception as lock_err:
                            logger.error(f"[AI REPORT] Failed to release lock: {lock_err}")
                        
                        return {
                            'status': 'error',
                            'message': report.error_message
                        }
                    
                    # Get event_ids for OpenSearch query
                    tagged_event_ids = [tag.event_id for tag in timeline_tags]
                    
                    # Fetch full event data from OpenSearch (no limit - send ALL tagged events to AI)
                    if len(tagged_event_ids) > 0:
                        # v1.13.1: Uses consolidated index (case_{id}, not per-file indices)
                        index_pattern = f"case_{case.id}"
                        
                        search_body = {
                            "query": {
                                "ids": {
                                    "values": tagged_event_ids  # Send ALL tagged events (no truncation)
                                }
                            },
                            "size": len(tagged_event_ids),  # Fetch all tagged events
                            "sort": [{"timestamp": {"order": "asc", "unmapped_type": "date"}}]
                        }
                        
                        results = opensearch_client.search(
                            index=index_pattern,
                            body=search_body,
                            ignore_unavailable=True
                        )
                        
                        if results and 'hits' in results and 'hits' in results['hits']:
                            tagged_events = results['hits']['hits']
                            logger.info(f"[AI REPORT] Retrieved {len(tagged_events)} tagged events from OpenSearch")
                else:
                    logger.info(f"[AI REPORT] No tagged events found for case {case.id}")
                    
            except Exception as e:
                logger.warning(f"[AI REPORT] Error fetching tagged events: {e}")
                # Continue without tagged events
            
            # Check for cancellation before prompt building
            report = db.session.get(AIReport, report_id)
            if report.status == 'cancelled':
                logger.info(f"[AI REPORT] Report {report_id} was cancelled after data collection")
                # Release AI lock on cancellation
                try:
                    from ai_resource_lock import release_ai_lock
                    release_ai_lock()
                    logger.info(f"[AI REPORT] ✅ AI lock released (cancelled after data collection)")
                except Exception as lock_err:
                    logger.error(f"[AI REPORT] Failed to release lock on cancellation: {lock_err}")
                return {'status': 'cancelled', 'message': 'Report generation was cancelled'}
            
            # STAGE 2: Check for existing timeline (v1.16.3)
            from models import CaseTimeline
            existing_timeline = CaseTimeline.query.filter_by(
                case_id=case.id,
                status='completed'
            ).order_by(CaseTimeline.created_at.desc()).first()
            
            if existing_timeline:
                logger.info(f"[AI REPORT] Found existing timeline (v{existing_timeline.version}) for case {case.id}")
            else:
                logger.info(f"[AI REPORT] No existing timeline found for case {case.id}")
            
            # STAGE 3: Analyzing Data
            report.current_stage = 'Analyzing Data'
            report.progress_percent = 40
            if existing_timeline:
                report.progress_message = f'Using existing timeline v{existing_timeline.version} + analyzing {len(iocs)} IOCs...'
            else:
                report.progress_message = f'Analyzing {len(iocs)} IOCs and {len(tagged_events)} tagged events...'
            db.session.commit()
            
            prompt = generate_case_report_prompt(case, iocs, tagged_events, systems, existing_timeline)
            logger.info(f"[AI REPORT] Prompt generated ({len(prompt)} characters) with {len(systems)} systems and timeline={'yes' if existing_timeline else 'no'}")
            
            # Store the prompt for debugging/review
            report.prompt_sent = prompt
            db.session.commit()
            
            # Check for cancellation before AI generation
            report = db.session.get(AIReport, report_id)
            if report.status == 'cancelled':
                logger.info(f"[AI REPORT] Report {report_id} was cancelled before AI generation")
                # Release AI lock on cancellation
                try:
                    from ai_resource_lock import release_ai_lock
                    release_ai_lock()
                    logger.info(f"[AI REPORT] ✅ AI lock released (cancelled before AI generation)")
                except Exception as lock_err:
                    logger.error(f"[AI REPORT] Failed to release lock on cancellation: {lock_err}")
                return {'status': 'cancelled', 'message': 'Report generation was cancelled'}
            
            # STAGE 3: Generating Report with AI
            report.current_stage = 'Generating Report'
            report.progress_percent = 50
            report.progress_message = f'Loading {report.model_name} model and generating report...'
            db.session.commit()
            
            start_time = time.time()
            
            # Get hardware mode from config (default to CPU for safety)
            hardware_mode_config = SystemSettings.query.filter_by(setting_key='ai_hardware_mode').first()
            hardware_mode = hardware_mode_config.setting_value if hardware_mode_config else 'cpu'
            
            # Use the model specified in the report record (from database settings)
            # Pass report object, db session, and hardware mode for optimal performance
            success, result = generate_report_with_ollama(
                prompt, 
                model=report.model_name,
                hardware_mode=hardware_mode,
                report_obj=report,
                db_session=db.session
            )
            generation_time = time.time() - start_time
            
            # Check for cancellation after AI generation
            report = db.session.get(AIReport, report_id)
            if report.status == 'cancelled':
                logger.info(f"[AI REPORT] Report {report_id} was cancelled after AI generation")
                # Release AI lock on cancellation
                try:
                    from ai_resource_lock import release_ai_lock
                    release_ai_lock()
                    logger.info(f"[AI REPORT] ✅ AI lock released (cancelled after AI generation)")
                except Exception as lock_err:
                    logger.error(f"[AI REPORT] Failed to release lock on cancellation: {lock_err}")
                return {'status': 'cancelled', 'message': 'Report generation was cancelled'}
            
            if success:
                # STAGE 4: Finalizing Report
                report.current_stage = 'Finalizing'
                report.progress_percent = 95
                report.progress_message = 'Converting report to HTML format...'
                db.session.commit()
                
                # Convert markdown report to HTML for Word compatibility
                markdown_report = result['report']
                html_report = markdown_to_html(markdown_report, case.name, case.company)
                
                # VALIDATION: Check for hallucinations
                from validation import validate_report
                import json
                
                logger.info(f"[AI REPORT] Validating report for hallucinations...")
                validation_results = validate_report(markdown_report, prompt, case.name)
                
                # Log validation results
                if validation_results['passed']:
                    logger.info(f"[AI REPORT] ✅ Validation PASSED - {len(validation_results['warnings'])} warnings")
                else:
                    logger.warning(f"[AI REPORT] ❌ Validation FAILED - {len(validation_results['errors'])} errors")
                    for error in validation_results['errors']:
                        logger.warning(f"[AI REPORT]   - {error['type']}: {error['message']}")
                
                # Update report with success
                report.status = 'completed'
                report.current_stage = 'Completed'
                report.report_title = format_report_title(case.name)
                report.report_content = html_report  # Store as HTML for Word compatibility
                report.raw_response = markdown_report  # Store raw markdown response for debugging
                report.validation_results = json.dumps(validation_results)  # Store validation results
                report.generation_time_seconds = result['duration_seconds']
                report.completed_at = datetime.utcnow()
                report.model_name = result.get('model', 'phi3:14b')
                report.progress_percent = 100
                report.progress_message = 'Report completed successfully!'
                report.celery_task_id = None  # Clear task ID on completion
                
                # Store performance metrics
                eval_count = result.get('eval_count', 0)
                if eval_count > 0 and result['duration_seconds'] > 0:
                    report.tokens_per_second = eval_count / result['duration_seconds']
                    report.total_tokens = eval_count
                
                db.session.commit()
                
                # CRITICAL: Release AI lock on success
                try:
                    from ai_resource_lock import release_ai_lock
                    release_ai_lock()
                    logger.info(f"[AI REPORT] ✅ AI lock released (success)")
                except Exception as lock_err:
                    logger.error(f"[AI REPORT] Failed to release lock on success: {lock_err}")
                
                logger.info(f"[AI REPORT] Report generated successfully in {generation_time:.1f}s")
                
                return {
                    'status': 'success',
                    'report_id': report_id,
                    'generation_time': generation_time,
                    'tokens_generated': result.get('eval_count', 0)
                }
            else:
                # Update report with failure
                error_msg = result.get('error', 'Unknown error')
                report.status = 'failed'
                report.current_stage = 'Failed'
                report.error_message = error_msg
                report.generation_time_seconds = generation_time
                report.celery_task_id = None  # Clear task ID on failure
                
                db.session.commit()
                
                # CRITICAL: Release AI lock on failure
                try:
                    from ai_resource_lock import release_ai_lock
                    release_ai_lock()
                    logger.info(f"[AI REPORT] ✅ AI lock released (failure)")
                except Exception as lock_err:
                    logger.error(f"[AI REPORT] Failed to release lock on failure: {lock_err}")
                
                logger.error(f"[AI REPORT] Generation failed: {error_msg}")
                
                return {
                    'status': 'error',
                    'report_id': report_id,
                    'message': error_msg
                }
                
        except Exception as e:
            logger.error(f"[AI REPORT] Fatal error: {e}", exc_info=True)
            
            # Try to update report status
            try:
                report = db.session.get(AIReport, report_id)
                if report:
                    report.status = 'failed'
                    report.error_message = str(e)
                    db.session.commit()
            except:
                pass
            
            # CRITICAL: Release AI lock on exception
            try:
                from ai_resource_lock import release_ai_lock
                release_ai_lock()
                logger.info(f"[AI REPORT] ✅ AI lock released (exception)")
            except Exception as lock_err:
                logger.error(f"[AI REPORT] Failed to release lock on exception: {lock_err}")
            
            return {
                'status': 'error',
                'report_id': report_id,
                'message': str(e)
            }


# ============================================================================
# CASE DELETION TASK (ASYNC WITH PROGRESS TRACKING)
# ============================================================================

@celery_app.task(bind=True, name='tasks.delete_case_async')
def delete_case_async(self, case_id):
    """
    Asynchronously delete a case and ALL associated data with progress tracking.
    
    Deletes:
    1. Physical files on disk
    2. OpenSearch indices
    3. Database records: CaseFile, IOC, IOCMatch, System, SigmaViolation, 
       TimelineTag, AIReport (cascade AIReportChat), SkippedFile, SearchHistory, Case
    
    Progress tracking:
    - Updates task metadata with current step, progress %, and counts
    - Frontend polls /case/<id>/delete/status for real-time updates
    """
    from main import app, db, opensearch_client
    from models import (Case, CaseFile, IOC, IOCMatch, System, SigmaViolation, 
                        TimelineTag, AIReport, SkippedFile, SearchHistory)
    from utils import make_index_name
    
    logger.info(f"[DELETE_CASE] Starting async deletion of case {case_id}")
    
    # Helper function to update progress
    def update_progress(step, progress_percent, message, **counts):
        """Update Celery task metadata for frontend polling"""
        self.update_state(
            state='PROGRESS',
            meta={
                'step': step,
                'progress': progress_percent,
                'message': message,
                **counts
            }
        )
        logger.info(f"[DELETE_CASE] [{progress_percent}%] {step}: {message}")
    
    # Use app context for all database operations (same pattern as AI report generation)
    with app.app_context():
        try:
            # Step 1: Get case information
            update_progress('Initializing', 0, 'Looking up case...')
            case = db.session.get(Case, case_id)
            if not case:
                logger.error(f"[DELETE_CASE] Case {case_id} not found")
                return {
                    'status': 'error',
                    'message': 'Case not found'
                }
            
            case_name = case.name
            upload_folder = f"/opt/casescope/uploads/{case_id}"
            staging_folder = f"/opt/casescope/staging/{case_id}"
            
            # Step 2: Count all data for progress tracking
            update_progress('Counting', 5, 'Counting files and data...')
            
            files = db.session.query(CaseFile).filter_by(case_id=case_id).all()
            iocs_count = db.session.query(IOC).filter_by(case_id=case_id).count()
            ioc_matches_count = db.session.query(IOCMatch).filter_by(case_id=case_id).count()
            systems_count = db.session.query(System).filter_by(case_id=case_id).count()
            sigma_count = db.session.query(SigmaViolation).filter_by(case_id=case_id).count()
            timeline_count = db.session.query(TimelineTag).filter_by(case_id=case_id).count()
            aireport_count = db.session.query(AIReport).filter_by(case_id=case_id).count()
            skipped_count = db.session.query(SkippedFile).filter_by(case_id=case_id).count()
            search_count = db.session.query(SearchHistory).filter_by(case_id=case_id).count()
            
            total_files = len(files)
            
            update_progress('Counted', 10, f'Found {total_files} files, {iocs_count} IOCs, {systems_count} systems',
                           files=total_files, iocs=iocs_count, systems=systems_count,
                           sigma=sigma_count, ai_reports=aireport_count)
            
            # Step 3: Delete physical files on disk
            update_progress('Deleting Files', 15, f'Removing physical files...')
            
            # Delete uploads folder
            if os.path.exists(upload_folder):
                try:
                    shutil.rmtree(upload_folder)
                    logger.info(f"[DELETE_CASE] Deleted upload folder: {upload_folder}")
                except Exception as e:
                    logger.warning(f"[DELETE_CASE] Failed to delete upload folder {upload_folder}: {e}")
            
            # Delete staging folder
            if os.path.exists(staging_folder):
                try:
                    shutil.rmtree(staging_folder)
                    logger.info(f"[DELETE_CASE] Deleted staging folder: {staging_folder}")
                except Exception as e:
                    logger.warning(f"[DELETE_CASE] Failed to delete staging folder {staging_folder}: {e}")
            
            # Step 4: Delete OpenSearch indices (20% - 50%) - OPTIMIZED with wildcard pattern
            update_progress('Deleting Indices', 20, f'Deleting OpenSearch indices for case {case_id}...')
            
            # Delete case index (v1.13.1+: 1 index per case, not per file)
            # Old: case_{case_id}_* wildcard (deleted 1000+ indices)
            # New: case_{case_id} single index (delete 1 index)
            index_name = f"case_{case_id}"
            deleted_indices = 0
            
            try:
                # Check if index exists
                if opensearch_client.indices.exists(index=index_name):
                    deleted_indices = 1
                    update_progress('Deleting Indices', 30, f'Deleting index: {index_name}')
                    logger.info(f"[DELETE_CASE] Deleting index: {index_name}")
                    
                    # Delete index
                    opensearch_client.indices.delete(index=index_name)
                    update_progress('Deleting Indices', 50, f'✅ Deleted index {index_name}')
                    logger.info(f"[DELETE_CASE] ✅ Deleted index {index_name}")
                else:
                    update_progress('Deleting Indices', 50, 'No indices to delete')
                    logger.info(f"[DELETE_CASE] No index found for case {case_id}")
                    
            except Exception as e:
                logger.warning(f"[DELETE_CASE] Failed to delete index {index_name}: {e}")
                # v1.13.1: No fallback needed - only 1 index per case now
                # Old code used individual per-file deletion (case_{id}_{filename})
                # New architecture: 1 index per case (already tried above)
                logger.info(f"[DELETE_CASE] Index deletion failed for case {case_id} - index may not exist")
            
            # Step 5: Delete database records (50% - 95%)
            update_progress('Deleting DB: AIReports', 55, f'Deleting {aireport_count} AI reports...')
            db.session.query(AIReport).filter_by(case_id=case_id).delete()
            db.session.commit()
            
            update_progress('Deleting DB: Search History', 60, f'Deleting {search_count} search history entries...')
            db.session.query(SearchHistory).filter_by(case_id=case_id).delete()
            db.session.commit()
            
            update_progress('Deleting DB: Timeline Tags', 65, f'Deleting {timeline_count} timeline tags...')
            db.session.query(TimelineTag).filter_by(case_id=case_id).delete()
            db.session.commit()
            
            update_progress('Deleting DB: IOC Matches', 70, f'Deleting {ioc_matches_count} IOC matches...')
            db.session.query(IOCMatch).filter_by(case_id=case_id).delete()
            db.session.commit()
            
            update_progress('Deleting DB: SIGMA Violations', 75, f'Deleting {sigma_count} SIGMA violations...')
            db.session.query(SigmaViolation).filter_by(case_id=case_id).delete()
            db.session.commit()
            
            update_progress('Deleting DB: IOCs', 80, f'Deleting {iocs_count} IOCs...')
            db.session.query(IOC).filter_by(case_id=case_id).delete()
            db.session.commit()
            
            update_progress('Deleting DB: Systems', 83, f'Deleting {systems_count} systems...')
            db.session.query(System).filter_by(case_id=case_id).delete()
            db.session.commit()
            
            update_progress('Deleting DB: Skipped Files', 86, f'Deleting {skipped_count} skipped files...')
            db.session.query(SkippedFile).filter_by(case_id=case_id).delete()
            db.session.commit()
            
            update_progress('Deleting DB: Files', 90, f'Deleting {total_files} file records...')
            db.session.query(CaseFile).filter_by(case_id=case_id).delete()
            db.session.commit()
            
            # Step 6: Delete the case itself
            update_progress('Deleting Case', 95, f'Removing case "{case_name}"...')
            db.session.delete(case)
            db.session.commit()
            
            # Step 7: Done!
            update_progress('Complete', 100, f'Case "{case_name}" deleted successfully')
            
            # Audit log
            from audit_logger import log_action
            log_action('delete_case', resource_type='case', resource_id=case_id,
                      resource_name=case_name, 
                      details={
                          'files_deleted': total_files,
                          'indices_deleted': deleted_indices,
                          'iocs_deleted': iocs_count,
                          'systems_deleted': systems_count,
                          'sigma_violations_deleted': sigma_count,
                          'ai_reports_deleted': aireport_count
                      })
            
            logger.info(f"[DELETE_CASE] ✅ Case {case_id} '{case_name}' deleted successfully")
            logger.info(f"[DELETE_CASE] Summary: {total_files} files, {deleted_indices} indices, "
                       f"{iocs_count} IOCs, {systems_count} systems, {sigma_count} SIGMA violations")
            
            return {
                'status': 'success',
                'case_id': case_id,
                'case_name': case_name,
                'summary': {
                    'files_deleted': total_files,
                    'indices_deleted': deleted_indices,
                    'iocs_deleted': iocs_count,
                    'systems_deleted': systems_count,
                    'sigma_violations_deleted': sigma_count,
                    'timeline_tags_deleted': timeline_count,
                    'ai_reports_deleted': aireport_count
                }
            }
        
        except Exception as e:
            logger.error(f"[DELETE_CASE] Fatal error deleting case {case_id}: {e}", exc_info=True)
            db.session.rollback()
            
            return {
                'status': 'error',
                'case_id': case_id,
                'message': f'Deletion failed: {str(e)}'
            }


# ============================================================================
# AI MODEL TRAINING
# ============================================================================

@celery_app.task(bind=True, name='tasks.generate_case_timeline')
def generate_case_timeline(self, timeline_id):
    """
    Generate AI timeline for a case using Qwen model
    
    Args:
        timeline_id: ID of the CaseTimeline database record
        
    Returns:
        dict: Status and results
    """
    from main import app, db, opensearch_client
    from models import CaseTimeline, Case, IOC, System, SystemSettings
    from ai_report import generate_timeline_prompt, generate_report_with_ollama
    from datetime import datetime
    import time
    
    logger.info(f"[TIMELINE] Starting generation for timeline_id={timeline_id}")
    
    with app.app_context():
        try:
            # Get timeline record
            timeline = db.session.get(CaseTimeline, timeline_id)
            if not timeline:
                logger.error(f"[TIMELINE] Timeline {timeline_id} not found")
                return {'status': 'error', 'message': 'Timeline not found'}
            
            # Store Celery task ID for cancellation support
            timeline.celery_task_id = self.request.id
            timeline.status = 'generating'
            timeline.progress_percent = 5
            timeline.progress_message = 'Initializing timeline generation...'
            db.session.commit()
            logger.info(f"[TIMELINE] Task ID: {self.request.id}")
            
            # Check for cancellation
            timeline = db.session.get(CaseTimeline, timeline_id)
            if timeline.status == 'cancelled':
                logger.info(f"[TIMELINE] Timeline {timeline_id} was cancelled before starting")
                return {'status': 'cancelled', 'message': 'Timeline generation was cancelled'}
            
            # Get case data
            case = db.session.get(Case, timeline.case_id)
            if not case:
                timeline.status = 'failed'
                timeline.error_message = 'Case not found'
                db.session.commit()
                return {'status': 'error', 'message': 'Case not found'}
            
            logger.info(f"[TIMELINE] Gathering data for case '{case.name}'")
            
            # STAGE 1: Collecting Data
            timeline.progress_percent = 15
            timeline.progress_message = f'Collecting events, IOCs, and systems for {case.name}...'
            db.session.commit()
            
            # Get IOCs
            iocs = IOC.query.filter_by(case_id=case.id, is_active=True).all()
            logger.info(f"[TIMELINE] Found {len(iocs)} active IOCs")
            
            # Get systems
            systems = System.query.filter_by(case_id=case.id, hidden=False).all()
            logger.info(f"[TIMELINE] Found {len(systems)} systems")
            
            # Get sample events from OpenSearch (for timeline context)
            # We'll fetch events sorted by timestamp to establish chronological boundaries
            timeline.progress_percent = 30
            timeline.progress_message = 'Fetching events from OpenSearch...'
            db.session.commit()
            
            events_data = []
            event_count = 0
            try:
                # v1.13.1: Uses consolidated index (case_{id}, not per-file indices)
                index_pattern = f"case_{case.id}"
                
                # Get count first
                count_result = opensearch_client.count(
                    index=index_pattern,
                    body={"query": {"match_all": {}}},
                    ignore_unavailable=True
                )
                event_count = count_result.get('count', 0) if count_result else 0
                logger.info(f"[TIMELINE] Total events in case: {event_count:,}")
                
                if event_count > 0:
                    # Fetch sample events sorted by timestamp
                    # v1.18.3 FIX: Use normalized fields for sorting and querying
                    search_body = {
                        "query": {"match_all": {}},
                        "size": min(300, event_count),  # Cap at 300 events for timeline
                        "sort": [{"normalized_timestamp": {"order": "asc", "unmapped_type": "date"}}],
                        "_source": {
                            "includes": [
                                "Event.System.TimeCreated",
                                "Event.System.Computer",
                                "Event.System.EventID",
                                "Event.EventData",
                                "normalized_timestamp",
                                "normalized_computer",
                                "normalized_event_id",
                                "source_file_type",
                                "has_ioc",
                                "has_sigma",
                                "sigma_rule"
                            ]
                        }
                    }
                    
                    results = opensearch_client.search(
                        index=index_pattern,
                        body=search_body,
                        ignore_unavailable=True
                    )
                    
                    if results and 'hits' in results and 'hits' in results['hits']:
                        events_data = results['hits']['hits']
                        logger.info(f"[TIMELINE] Retrieved {len(events_data)} sample events for timeline")
                        
            except Exception as e:
                logger.warning(f"[TIMELINE] Error fetching events: {e}")
                # Continue without events
            
            # Check for cancellation before prompt building
            timeline = db.session.get(CaseTimeline, timeline_id)
            if timeline.status == 'cancelled':
                logger.info(f"[TIMELINE] Timeline {timeline_id} was cancelled after data collection")
                return {'status': 'cancelled', 'message': 'Timeline generation was cancelled'}
            
            # Store data counts
            timeline.event_count = event_count
            timeline.ioc_count = len(iocs)
            timeline.system_count = len(systems)
            db.session.commit()
            
            # STAGE 2: Building Timeline Prompt
            timeline.progress_percent = 40
            timeline.progress_message = f'Building timeline prompt with {event_count:,} events...'
            db.session.commit()
            
            prompt = generate_timeline_prompt(case, iocs, systems, events_data, event_count)
            logger.info(f"[TIMELINE] Prompt generated ({len(prompt)} characters)")
            
            # Store the prompt for debugging
            timeline.prompt_sent = prompt
            db.session.commit()
            
            # Check for cancellation before AI generation
            timeline = db.session.get(CaseTimeline, timeline_id)
            if timeline.status == 'cancelled':
                logger.info(f"[TIMELINE] Timeline {timeline_id} was cancelled before AI generation")
                return {'status': 'cancelled', 'message': 'Timeline generation was cancelled'}
            
            # STAGE 3: Generating Timeline with AI (Qwen)
            timeline.progress_percent = 50
            timeline.progress_message = f'Loading {timeline.model_name} model and generating timeline...'
            db.session.commit()
            
            start_time = time.time()
            
            # Get hardware mode from config
            hardware_mode_config = SystemSettings.query.filter_by(setting_key='ai_hardware_mode').first()
            hardware_mode = hardware_mode_config.setting_value if hardware_mode_config else 'cpu'
            
            # Generate timeline with Qwen
            success, result = generate_report_with_ollama(
                prompt,
                model=timeline.model_name,
                hardware_mode=hardware_mode,
                report_obj=timeline,  # Pass timeline object for progress updates
                db_session=db.session
            )
            generation_time = time.time() - start_time
            
            # Check for cancellation after AI generation
            timeline = db.session.get(CaseTimeline, timeline_id)
            if timeline.status == 'cancelled':
                logger.info(f"[TIMELINE] Timeline {timeline_id} was cancelled after AI generation")
                return {'status': 'cancelled', 'message': 'Timeline generation was cancelled'}
            
            if success:
                # STAGE 4: Finalizing Timeline
                timeline.progress_percent = 95
                timeline.progress_message = 'Finalizing timeline...'
                db.session.commit()
                
                # Store the timeline content (convert dict to JSON string)
                import json as json_lib
                timeline.timeline_content = result.get('report', '') if isinstance(result, dict) else result
                timeline.raw_response = json_lib.dumps(result) if isinstance(result, dict) else result
                timeline.timeline_json = json_lib.dumps(result) if isinstance(result, dict) else None
                timeline.status = 'completed'
                timeline.generation_time_seconds = generation_time
                timeline.progress_percent = 100
                timeline.progress_message = 'Timeline generation completed!'
                
                # Generate title
                timeline.timeline_title = f"Timeline for {case.name} - {len(iocs)} IOCs, {len(systems)} Systems, {event_count:,} Events"
                
                # Store event/IOC/system counts
                timeline.event_count = event_count
                timeline.ioc_count = len(iocs)
                timeline.system_count = len(systems)
                
                db.session.commit()
                
                logger.info(f"[TIMELINE] Timeline {timeline_id} completed in {generation_time:.1f}s")
                
                return {
                    'status': 'completed',
                    'timeline_id': timeline_id,
                    'generation_time': generation_time,
                    'event_count': event_count,
                    'ioc_count': len(iocs),
                    'system_count': len(systems)
                }
            else:
                # Generation failed
                timeline.status = 'failed'
                timeline.error_message = result  # Error message from Ollama
                timeline.progress_percent = 0
                db.session.commit()
                
                logger.error(f"[TIMELINE] Timeline {timeline_id} failed: {result}")
                
                return {
                    'status': 'failed',
                    'error': result
                }
                
        except Exception as e:
            logger.error(f"[TIMELINE] Error generating timeline: {e}", exc_info=True)
            
            # Update timeline status
            try:
                timeline = db.session.get(CaseTimeline, timeline_id)
                if timeline:
                    timeline.status = 'failed'
                    timeline.error_message = str(e)
                    timeline.progress_percent = 0
                    db.session.commit()
            except:
                pass
            
            return {
                'status': 'failed',
                'error': str(e)
            }


@celery_app.task(bind=True, name='tasks.train_dfir_model_from_opencti')
def train_dfir_model_from_opencti(self, model_name='dfir-qwen:latest', limit=50):
    """
    Train DFIR model using OpenCTI threat intelligence
    
    Args:
        model_name: Name of the model to train (default: 'dfir-qwen:latest')
        limit: Maximum number of reports to fetch from OpenCTI (default: 50)
    Modular design: delegates to ai_training.py and LoRA training scripts
    """
    from main import app
    
    with app.app_context():
        from main import db
        from routes.settings import get_setting
        from ai_training import generate_training_data_from_opencti
        from models import AIModel, AITrainingSession
        from flask_login import current_user
        
        # Create training session record for persistent progress tracking
        session = AITrainingSession(
            task_id=self.request.id,
            model_name=model_name,
            user_id=1,  # Default to admin if not in request context
            status='pending',
            progress=0,
            current_step='Initializing...',
            report_count=limit,
            log=''
        )
        db.session.add(session)
        db.session.commit()
        
        log_buffer = []
        
        def log(message):
            """Log and update both Celery state and database session"""
            timestamp = datetime.now().strftime('%H:%M:%S')
            log_message = f"[{timestamp}] {message}"
            log_buffer.append(log_message)
            logger.info(f"[AI_TRAIN] {message}")
            
            # Update Celery task state
            self.update_state(
                state='PROGRESS',
                meta={'log': '\n'.join(log_buffer), 'progress': len(log_buffer)}
            )
            
            # Update database session for persistence
            try:
                session.log = '\n'.join(log_buffer)
                session.status = 'running'
                session.updated_at = datetime.now()
                
                # Calculate progress based on log content
                progress = 0
                current_step = 'Initializing...'
                
                log_text = '\n'.join(log_buffer)
                if 'Step 1/5' in log_text:
                    progress = 5
                    current_step = 'Step 1/5: Retrieving configuration'
                if 'Step 2/5' in log_text:
                    progress = 20
                    current_step = 'Step 2/5: Generating training data'
                if 'Generated' in log_text and 'training examples' in log_text:
                    progress = 35
                if 'Step 3/5' in log_text:
                    progress = 40
                    current_step = 'Step 3/5: Checking environment'
                if 'Step 4/5' in log_text:
                    progress = 50
                    current_step = 'Step 4/5: Training LoRA adapter (30-60 min)'
                if 'epoch' in log_text.lower() or 'loss' in log_text.lower():
                    progress = min(85, max(progress, 55))
                if 'LoRA training complete' in log_text:
                    progress = 90
                if 'Step 5/5' in log_text:
                    progress = 95
                    current_step = 'Step 5/5: Auto-deploying model'
                if 'Training Complete' in log_text:
                    progress = 100
                    current_step = 'Complete!'
                
                session.progress = progress
                session.current_step = current_step
                db.session.commit()
            except Exception as e:
                logger.warning(f"[AI_TRAIN] Could not update session: {e}")
                db.session.rollback()
        
        try:
            log("=" * 60)
            log("🎓 AI Model Training from OpenCTI")
            log("=" * 60)
            log("")
            
            # Step 1: Get model and OpenCTI credentials
            log("Step 1/5: Retrieving configuration...")
            
            # Get model from database
            model = AIModel.query.filter_by(model_name=model_name).first()
            if not model:
                raise Exception(f"Model '{model_name}' not found in database")
            
            if not model.trainable:
                raise Exception(f"Model '{model_name}' is not trainable")
            
            if not model.base_model:
                raise Exception(f"No base model configured for '{model_name}'")
            
            log(f"✅ Model: {model.display_name}")
            log(f"✅ Base Model: {model.base_model}")
            log("")
            
            opencti_url = get_setting('opencti_url', '')
            opencti_api_key = get_setting('opencti_api_key', '')
            
            if not opencti_url or not opencti_api_key:
                raise Exception("OpenCTI credentials not configured")
            
            log(f"✅ OpenCTI URL: {opencti_url}")
            log("")
            
            # Step 2: Generate training data from OpenCTI
            log("Step 2/5: Generating training data from OpenCTI threat reports...")
            result = generate_training_data_from_opencti(
                opencti_url=opencti_url,
                opencti_api_key=opencti_api_key,
                limit=limit,
                progress_callback=log
            )
            
            if not result['success']:
                raise Exception(result.get('error', 'Training data generation failed'))
            
            training_file = result['file_path']
            example_count = result['example_count']
            
            log("")
            log(f"✅ Generated {example_count} training examples")
            log(f"✅ Saved to: {training_file}")
            log("")
            
            # Step 3: Setup training environment (if needed)
            log("Step 3/5: Checking training environment...")
            
            import subprocess
            venv_path = "/opt/casescope/lora_training/venv"
            
            if not os.path.exists(venv_path):
                log("⚠️  Training environment not set up. Installing dependencies...")
                log("This may take 10-15 minutes...")
                
                setup_script = "/opt/casescope/lora_training/scripts/1_setup_environment.sh"
                result = subprocess.run(
                    ["bash", setup_script],
                    capture_output=True,
                    text=True,
                    cwd="/opt/casescope/lora_training"
                )
                
                if result.returncode != 0:
                    log(f"❌ Setup failed: {result.stderr}")
                    raise Exception(f"Training environment setup failed: {result.stderr}")
                
                log("✅ Training environment installed")
            else:
                log("✅ Training environment already set up")
            
            log("")
            
            # Step 4: Train LoRA model
            log("Step 4/5: Training LoRA adapter...")
            log("This will take 30-60 minutes depending on GPU/CPU...")
            log("")
            
            python_exe = f"{venv_path}/bin/python3"
            train_script = "/opt/casescope/lora_training/scripts/2_train_lora.py"
            
            # Train with optimal settings (max_seq_length=512 to fit in 8GB VRAM)
            output_dir = f"/opt/casescope/lora_training/models/{model_name.replace(':', '-')}-trained"
            train_cmd = [
                python_exe,
                train_script,
                "--base_model", model.base_model,  # Use base_model from database
                "--training_data", training_file,
                "--output_dir", output_dir,
                "--epochs", "3",
                "--batch_size", "1",
                "--lora_rank", "8",
                "--max_seq_length", "512"  # Reduced from 1024 to eliminate CPU offloading
            ]
            
            log(f"Running: {' '.join(train_cmd)}")
            log("")
            
            # Run training (this is the long part)
            process = subprocess.Popen(
                train_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd="/opt/casescope/lora_training"
            )
            
            # Stream training output
            for line in iter(process.stdout.readline, ''):
                if line:
                    log(line.strip())
            
            process.wait()
            
            if process.returncode != 0:
                raise Exception("LoRA training failed")
            
            log("")
            log("✅ LoRA training complete!")
            log("")
            
            # Step 5: Auto-deploy trained model
            log("Step 5/5: Auto-deploying trained model...")
            
            try:
                # Update model in database
                model.trained = True
                model.trained_date = datetime.now()
                model.training_examples = example_count
                model.trained_model_path = output_dir
                db.session.commit()
                
                log("✅ Model database updated:")
                log(f"   - Model: {model.display_name}")
                log(f"   - Marked as trained")
                log(f"   - Training date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                log(f"   - Training examples: {example_count}")
                log(f"   - Model path: {output_dir}")
                log("")
                log("🎉 The system will now use this trained model for AI report generation!")
            except Exception as e:
                log(f"⚠️  Warning: Could not update model database: {e}")
                log("   Model trained successfully but not auto-configured")
                db.session.rollback()
            
            log("")
            
            log("=" * 60)
            log("✅ Training Complete!")
            log("=" * 60)
            log(f"Model: {model.display_name}")
            log(f"Training examples: {example_count}")
            log(f"LoRA adapter: {output_dir}")
            log("")
            log("✅ Model is now marked as TRAINED in the system")
            log("✅ Future AI reports will use the trained version automatically")
            
            # Mark session as completed
            session.status = 'completed'
            session.progress = 100
            session.current_step = 'Complete!'
            session.completed_at = datetime.now()
            db.session.commit()
            
            return {
                'status': 'success',
                'message': 'AI training completed successfully',
                'training_file': training_file,
                'example_count': example_count,
                'model_path': output_dir
            }
            
        except Exception as e:
            error_msg = f"Training failed: {e}"
            log("")
            log(f"❌ {error_msg}")
            logger.error(f"[AI_TRAIN] {error_msg}", exc_info=True)
            
            # Mark session as failed
            try:
                session.status = 'failed'
                session.error_message = str(e)
                session.completed_at = datetime.now()
                db.session.commit()
            except:
                pass
            
            return {
                'status': 'failed',
                'error': str(e)
            }
        
        finally:
            # CRITICAL: Always release AI lock (success, failure, or exception)
            try:
                from ai_resource_lock import release_ai_lock
                release_ai_lock()
                logger.info(f"[AI_TRAIN] ✅ AI lock released (training completed)")
            except Exception as lock_err:
                logger.error(f"[AI_TRAIN] Failed to release lock: {lock_err}")


# ============================================================================
# MAINTENANCE / CLEANUP TASKS
# ============================================================================

@celery_app.task(name='tasks.cleanup_old_search_history')
def cleanup_old_search_history():
    """
    Clean up old search history records to prevent database bloat.
    Keeps recent searches (last 90 days) and all favorited searches.
    
    Run daily via Celery Beat or manual trigger.
    
    Returns:
        dict: Cleanup statistics
    """
    from main import app, db
    from models import SearchHistory
    from datetime import datetime, timedelta
    
    logger.info("[CLEANUP] Starting search history cleanup...")
    
    with app.app_context():
        try:
            # Delete non-favorited searches older than 90 days
            cutoff_date = datetime.utcnow() - timedelta(days=90)
            
            # Count before deletion
            old_searches = db.session.query(SearchHistory).filter(
                SearchHistory.created_at < cutoff_date,
                SearchHistory.is_favorite == False  # Keep favorited searches
            ).count()
            
            if old_searches == 0:
                logger.info("[CLEANUP] No old search history to clean up")
                return {
                    'status': 'success',
                    'deleted': 0,
                    'message': 'No old search history found'
                }
            
            # Delete old searches
            deleted = db.session.query(SearchHistory).filter(
                SearchHistory.created_at < cutoff_date,
                SearchHistory.is_favorite == False
            ).delete()
            
            db.session.commit()
            
            logger.info(f"[CLEANUP] ✅ Deleted {deleted:,} old search history records (older than 90 days)")
            
            # Get current stats
            total_searches = db.session.query(SearchHistory).count()
            favorited_searches = db.session.query(SearchHistory).filter_by(is_favorite=True).count()
            
            logger.info(f"[CLEANUP] Current stats: {total_searches:,} total, {favorited_searches:,} favorited")
            
            return {
                'status': 'success',
                'deleted': deleted,
                'total_remaining': total_searches,
                'favorited_remaining': favorited_searches,
                'message': f'Deleted {deleted:,} old search records'
            }
            
        except Exception as e:
            logger.error(f"[CLEANUP] ❌ Search history cleanup failed: {e}", exc_info=True)
            db.session.rollback()
            return {
                'status': 'error',
                'message': str(e)
            }


@celery_app.task(name='tasks.cleanup_old_audit_logs')
def cleanup_old_audit_logs():
    """
    Clean up old audit log records to prevent database bloat.
    Keeps recent logs (last 365 days) for compliance.
    
    Run weekly via Celery Beat or manual trigger.
    
    Returns:
        dict: Cleanup statistics
    """
    from main import app, db
    from models import AuditLog
    from datetime import datetime, timedelta
    
    logger.info("[CLEANUP] Starting audit log cleanup...")
    
    with app.app_context():
        try:
            # Delete audit logs older than 1 year (365 days)
            cutoff_date = datetime.utcnow() - timedelta(days=365)
            
            # Count before deletion
            old_logs = db.session.query(AuditLog).filter(
                AuditLog.timestamp < cutoff_date
            ).count()
            
            if old_logs == 0:
                logger.info("[CLEANUP] No old audit logs to clean up")
                return {
                    'status': 'success',
                    'deleted': 0,
                    'message': 'No old audit logs found'
                }
            
            # Delete old logs in batches (prevent long-running transaction)
            batch_size = 10000
            total_deleted = 0
            
            while True:
                batch_deleted = db.session.query(AuditLog).filter(
                    AuditLog.timestamp < cutoff_date
                ).limit(batch_size).delete(synchronize_session=False)
                
                if batch_deleted == 0:
                    break
                
                total_deleted += batch_deleted
                db.session.commit()
                logger.info(f"[CLEANUP] Deleted batch: {batch_deleted:,} logs ({total_deleted:,} total)")
            
            logger.info(f"[CLEANUP] ✅ Deleted {total_deleted:,} old audit log records (older than 365 days)")
            
            # Get current stats
            total_logs = db.session.query(AuditLog).count()
            
            logger.info(f"[CLEANUP] Current stats: {total_logs:,} audit logs remaining")
            
            return {
                'status': 'success',
                'deleted': total_deleted,
                'total_remaining': total_logs,
                'message': f'Deleted {total_deleted:,} old audit logs'
            }
            
        except Exception as e:
            logger.error(f"[CLEANUP] ❌ Audit log cleanup failed: {e}", exc_info=True)
            db.session.rollback()
            return {
                'status': 'error',
                'message': str(e)
            }
