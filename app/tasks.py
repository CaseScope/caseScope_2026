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
    3. Database records: CaseFile, IOC, IOCMatch, System, KnownUser, SigmaViolation, 
       TimelineTag, AIReport (cascade AIReportChat), CaseTimeline, EvidenceFile,
       SkippedFile, SearchHistory, CaseLock, Case
    
    Progress tracking:
    - Updates task metadata with current step, progress %, and counts
    - Frontend polls /case/<id>/delete/status for real-time updates
    """
    from main import app, db, opensearch_client
    from models import (Case, CaseFile, IOC, IOCMatch, System, KnownUser, SigmaViolation, 
                        TimelineTag, AIReport, SkippedFile, SearchHistory, CaseLock,
                        CaseTimeline, EvidenceFile)
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
            known_users_count = db.session.query(KnownUser).filter_by(case_id=case_id).count()
            sigma_count = db.session.query(SigmaViolation).filter_by(case_id=case_id).count()
            timeline_tag_count = db.session.query(TimelineTag).filter_by(case_id=case_id).count()
            case_timeline_count = db.session.query(CaseTimeline).filter_by(case_id=case_id).count()
            aireport_count = db.session.query(AIReport).filter_by(case_id=case_id).count()
            evidence_count = db.session.query(EvidenceFile).filter_by(case_id=case_id).count()
            skipped_count = db.session.query(SkippedFile).filter_by(case_id=case_id).count()
            search_count = db.session.query(SearchHistory).filter_by(case_id=case_id).count()
            
            total_files = len(files)
            
            update_progress('Counted', 10, f'Found {total_files} files, {iocs_count} IOCs, {systems_count} systems, {known_users_count} known users',
                           files=total_files, iocs=iocs_count, systems=systems_count, known_users=known_users_count,
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
            
            update_progress('Deleting DB: Timeline Tags', 63, f'Deleting {timeline_tag_count} timeline tags...')
            db.session.query(TimelineTag).filter_by(case_id=case_id).delete()
            db.session.commit()
            
            update_progress('Deleting DB: Case Timelines', 65, f'Deleting {case_timeline_count} case timelines...')
            db.session.query(CaseTimeline).filter_by(case_id=case_id).delete()
            db.session.commit()
            
            update_progress('Deleting DB: Evidence Files', 67, f'Deleting {evidence_count} evidence files...')
            db.session.query(EvidenceFile).filter_by(case_id=case_id).delete()
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
            
            update_progress('Deleting DB: Systems', 82, f'Deleting {systems_count} systems...')
            db.session.query(System).filter_by(case_id=case_id).delete()
            db.session.commit()
            
            update_progress('Deleting DB: Known Users', 84, f'Deleting {known_users_count} known users...')
            db.session.query(KnownUser).filter_by(case_id=case_id).delete()
            db.session.commit()
            
            update_progress('Deleting DB: Skipped Files', 86, f'Deleting {skipped_count} skipped files...')
            db.session.query(SkippedFile).filter_by(case_id=case_id).delete()
            db.session.commit()
            
            update_progress('Deleting DB: Files', 90, f'Deleting {total_files} file records...')
            db.session.query(CaseFile).filter_by(case_id=case_id).delete()
            db.session.commit()
            
            # Step 6: Delete case lock (if any)
            update_progress('Deleting DB: Case Lock', 92, f'Removing case lock...')
            db.session.query(CaseLock).filter_by(case_id=case_id).delete()
            db.session.commit()
            
            # Step 6b: Delete embedding queue items (raw SQL - table may not have ORM model)
            update_progress('Deleting DB: Embedding Queue', 93, f'Removing embedding queue items...')
            try:
                from sqlalchemy import text
                db.session.execute(text("DELETE FROM embedding_queue_item WHERE case_id = :case_id"), {'case_id': case_id})
                db.session.commit()
            except Exception as e:
                logger.warning(f"[DELETE_CASE] Failed to delete embedding_queue_item (table may not exist): {e}")
                db.session.rollback()
            
            # Step 8: Delete the case itself
            update_progress('Deleting Case', 95, f'Removing case "{case_name}"...')
            db.session.delete(case)
            db.session.commit()
            
            # Step 9: Done!
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
                          'known_users_deleted': known_users_count,
                          'sigma_violations_deleted': sigma_count,
                          'ai_reports_deleted': aireport_count
                      })
            
            logger.info(f"[DELETE_CASE] ✅ Case {case_id} '{case_name}' deleted successfully")
            logger.info(f"[DELETE_CASE] Summary: {total_files} files, {deleted_indices} indices, "
                       f"{iocs_count} IOCs, {systems_count} systems, {known_users_count} known users, {sigma_count} SIGMA violations")
            
            return {
                'status': 'success',
                'case_id': case_id,
                'case_name': case_name,
                'summary': {
                    'files_deleted': total_files,
                    'indices_deleted': deleted_indices,
                    'iocs_deleted': iocs_count,
                    'systems_deleted': systems_count,
                    'known_users_deleted': known_users_count,
                    'sigma_violations_deleted': sigma_count,
                    'timeline_tags_deleted': timeline_tag_count,
                    'case_timelines_deleted': case_timeline_count,
                    'evidence_files_deleted': evidence_count,
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
            
            # ========================================================================
            # STAGE 1B: Load TAGGED events (analyst-curated timeline events)
            # ========================================================================
            timeline.progress_percent = 30
            timeline.progress_message = 'Fetching analyst-tagged events...'
            db.session.commit()
            
            from models import TimelineTag
            
            # Query all tagged events for this case
            tagged_events = TimelineTag.query.filter_by(case_id=case.id).order_by(TimelineTag.created_at).all()
            logger.info(f"[TIMELINE] Found {len(tagged_events)} analyst-tagged events")
            
            # Check if any events are tagged
            if not tagged_events:
                logger.error(f"[TIMELINE] No tagged events found for case {case.id}")
                timeline.error_message = ("No events have been tagged for timeline generation. "
                                         "Timeline generation requires analyst-tagged events. "
                                         "Please tag relevant events in the search interface before generating a timeline.")
                timeline.status = 'failed'
                timeline.event_count = 0
                timeline.ioc_count = len(iocs)
                timeline.system_count = len(systems)
                db.session.commit()
                return {'status': 'error', 'message': 'No tagged events found. Please tag events first.'}
            
            # Fetch full event data from OpenSearch for each tagged event
            timeline.progress_percent = 40
            timeline.progress_message = f'Loading full data for {len(tagged_events)} tagged events...'
            db.session.commit()
            
            events_data = []
            event_count = len(tagged_events)  # Use TAGGED count, not total database count
            failed_loads = 0
            loaded_from_cache = 0
            
            try:
                for idx, tag in enumerate(tagged_events):
                    # Update progress every 50 events to avoid excessive DB writes
                    if idx > 0 and idx % 50 == 0:
                        progress = 40 + int((idx / len(tagged_events)) * 30)  # Progress from 40% to 70%
                        timeline.progress_percent = min(progress, 70)
                        timeline.progress_message = f'Loading event {idx}/{len(tagged_events)}...'
                        db.session.commit()
                        
                        # Check for cancellation during event loading
                        timeline = db.session.get(CaseTimeline, timeline_id)
                        if timeline.status == 'cancelled':
                            logger.info(f"[TIMELINE] Timeline {timeline_id} cancelled during event loading")
                            return {'status': 'cancelled', 'message': 'Timeline generation was cancelled'}
                    
                    try:
                        # Try to get full event from OpenSearch first
                        event_doc = opensearch_client.get(
                            index=tag.index_name,
                            id=tag.event_id,
                            ignore=[404]
                        )
                        
                        if event_doc and event_doc.get('found'):
                            # Successfully retrieved from OpenSearch
                            events_data.append(event_doc)
                            logger.debug(f"[TIMELINE] Loaded event {tag.event_id} from OpenSearch")
                        else:
                            # Event not found in OpenSearch, try cached data
                            if tag.event_data:
                                import json as json_lib
                                try:
                                    cached_event = json_lib.loads(tag.event_data)
                                    events_data.append({
                                        '_source': cached_event,
                                        '_id': tag.event_id,
                                        '_index': tag.index_name,
                                        'from_cache': True,
                                        'analyst_notes': tag.notes if tag.notes else None,
                                        'tag_color': tag.tag_color
                                    })
                                    loaded_from_cache += 1
                                    logger.debug(f"[TIMELINE] Using cached data for event {tag.event_id}")
                                except json_lib.JSONDecodeError as je:
                                    logger.warning(f"[TIMELINE] Failed to parse cached data for {tag.event_id}: {je}")
                                    failed_loads += 1
                            else:
                                logger.warning(f"[TIMELINE] Event {tag.event_id} not found and no cached data available")
                                failed_loads += 1
                    
                    except Exception as e:
                        logger.warning(f"[TIMELINE] Error fetching event {tag.event_id}: {e}")
                        # Try cached data as fallback
                        if tag.event_data:
                            try:
                                import json as json_lib
                                cached_event = json_lib.loads(tag.event_data)
                                events_data.append({
                                    '_source': cached_event,
                                    '_id': tag.event_id,
                                    '_index': tag.index_name,
                                    'from_cache': True,
                                    'analyst_notes': tag.notes if tag.notes else None,
                                    'tag_color': tag.tag_color
                                })
                                loaded_from_cache += 1
                                logger.debug(f"[TIMELINE] Used cached data after fetch error for {tag.event_id}")
                            except Exception as cache_err:
                                logger.warning(f"[TIMELINE] Could not use cached data for {tag.event_id}: {cache_err}")
                                failed_loads += 1
                        else:
                            failed_loads += 1
            
                logger.info(f"[TIMELINE] Loaded {len(events_data)}/{len(tagged_events)} events "
                           f"({loaded_from_cache} from cache, {failed_loads} failed)")
                
                # Sort events by timestamp (chronological order)
                events_data.sort(key=lambda x: x.get('_source', {}).get('normalized_timestamp', ''))
            
            except Exception as e:
                logger.error(f"[TIMELINE] Critical error loading tagged events: {e}")
                timeline.error_message = f"Error loading tagged events: {str(e)}"
                timeline.status = 'failed'
                timeline.event_count = 0
                timeline.ioc_count = len(iocs)
                timeline.system_count = len(systems)
                db.session.commit()
                return {'status': 'error', 'message': f'Error loading events: {str(e)}'}
            
            # Verify we got at least some events
            if not events_data:
                logger.error(f"[TIMELINE] No event data could be loaded for any tagged events")
                timeline.error_message = ("Could not load any tagged event data from OpenSearch. "
                                         "Events may have been deleted or indices may be unavailable.")
                timeline.status = 'failed'
                timeline.event_count = 0
                timeline.ioc_count = len(iocs)
                timeline.system_count = len(systems)
                db.session.commit()
                return {'status': 'error', 'message': 'No event data available'}
            
            # Warn if significant number of events failed to load
            if failed_loads > 0:
                logger.warning(f"[TIMELINE] {failed_loads} events failed to load out of {len(tagged_events)} "
                              f"({failed_loads/len(tagged_events)*100:.1f}%)")
            
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


# ============================================================================
# HIDE KNOWN GOOD EVENTS (v1.44.0 - Uses events_known_good module)
# ============================================================================

# =============================================================================
# PARALLEL HIDE KNOWN GOOD - Uses 8 workers with sliced scroll
# =============================================================================

# Number of parallel slices (matches worker concurrency)
HIDE_PARALLEL_SLICES = 8


@celery_app.task(bind=True, name='tasks.hide_known_good_slice')
def hide_known_good_slice_task(self, case_id: int, slice_id: int, max_slices: int, user_id: int):
    """
    Worker task: Process one slice of events for hide known good operation.
    
    Uses OpenSearch sliced scroll to process 1/max_slices of total events.
    This task runs in parallel with other slice tasks.
    
    Args:
        case_id: Case ID to process
        slice_id: This worker's slice (0 to max_slices-1)
        max_slices: Total number of slices
        user_id: User who initiated the operation
    
    Returns:
        Dict with scanned, found, and hidden counts for this slice
    """
    from main import app, opensearch_client
    from datetime import datetime
    from events_known_good import load_exclusions, process_slice
    
    with app.app_context():
        try:
            index_name = f"case_{case_id}"
            
            # Load exclusions
            exclusions = load_exclusions()
            
            logger.info(f"[HIDE KNOWN GOOD] Slice {slice_id}/{max_slices}: Starting for case {case_id}")
            
            # Process this slice
            scanned, events_to_hide = process_slice(
                case_id=case_id,
                slice_id=slice_id,
                max_slices=max_slices,
                exclusions=exclusions,
                opensearch_client=opensearch_client
            )
            
            # Bulk hide the events found in this slice
            hidden_count = 0
            if events_to_hide:
                batch_size = 500
                
                for i in range(0, len(events_to_hide), batch_size):
                    batch = events_to_hide[i:i + batch_size]
                    
                    bulk_body = []
                    for evt in batch:
                        bulk_body.append({"update": {"_index": evt['_index'], "_id": evt['_id']}})
                        bulk_body.append({
                            "script": {
                                "source": "ctx._source.is_hidden = true; ctx._source.hidden_by = params.user_id; ctx._source.hidden_at = params.timestamp; ctx._source.hidden_reason = params.reason",
                                "lang": "painless",
                                "params": {
                                    "user_id": user_id,
                                    "timestamp": datetime.utcnow().isoformat(),
                                    "reason": "known_good_exclusion"
                                }
                            }
                        })
                    
                    try:
                        result = opensearch_client.bulk(body=bulk_body, refresh=False)
                        if not result.get('errors', False):
                            hidden_count += len(batch)
                        else:
                            for item in result.get('items', []):
                                if item.get('update', {}).get('status') in [200, 201]:
                                    hidden_count += 1
                    except Exception as e:
                        logger.error(f"[HIDE KNOWN GOOD] Slice {slice_id}: Bulk error - {e}")
            
            logger.info(f"[HIDE KNOWN GOOD] Slice {slice_id}/{max_slices}: Complete - scanned={scanned:,}, found={len(events_to_hide):,}, hidden={hidden_count:,}")
            
            return {
                'slice_id': slice_id,
                'scanned': scanned,
                'found': len(events_to_hide),
                'hidden': hidden_count
            }
            
        except Exception as e:
            logger.error(f"[HIDE KNOWN GOOD] Slice {slice_id}: Error - {e}")
            import traceback
            traceback.print_exc()
            return {
                'slice_id': slice_id,
                'scanned': 0,
                'found': 0,
                'hidden': 0,
                'error': str(e)
            }


@celery_app.task(bind=True, name='tasks.hide_known_good_events')
def hide_known_good_events_task(self, case_id, user_id):
    """
    Coordinator task: Dispatches 8 parallel slice workers and aggregates results.
    
    v1.45.0: Refactored for parallel processing using sliced scroll.
    Uses all 8 Celery workers to process events ~8x faster.
    
    Args:
        case_id: ID of the case to process
        user_id: ID of the user who initiated the task
    
    Returns:
        Dict with status, hidden count, and processed count
    """
    from main import app, db, opensearch_client
    from models import Case
    from celery import group
    from events_known_good import load_exclusions, has_exclusions_configured
    
    with app.app_context():
        try:
            case = db.session.get(Case, case_id)
            if not case:
                return {'status': 'error', 'message': 'Case not found'}
            
            # Validate exclusions are configured
            exclusions = load_exclusions()
            logger.info(f"[HIDE KNOWN GOOD] Loaded exclusions: RMM={len(exclusions.get('rmm_executables', []))}, "
                       f"Remote={len(exclusions.get('remote_tools', []))}, "
                       f"EDR={len(exclusions.get('edr_tools', []))}, "
                       f"IPs={len(exclusions.get('known_good_ips', []))}")
            
            if not has_exclusions_configured():
                return {'status': 'error', 'message': 'No exclusions defined'}
            
            index_name = f"case_{case_id}"
            
            # Count total non-hidden events
            try:
                count_response = opensearch_client.count(
                    index=index_name,
                    body={
                        "query": {
                            "bool": {
                                "must_not": [{"term": {"is_hidden": True}}]
                            }
                        }
                    }
                )
                total_events = count_response.get('count', 0)
            except Exception as e:
                return {'status': 'error', 'message': f'Failed to count events: {e}'}
            
            if total_events == 0:
                return {'status': 'success', 'hidden': 0, 'processed': 0, 'message': 'No visible events to scan'}
            
            logger.info(f"[HIDE KNOWN GOOD] Case {case_id}: Starting parallel scan of {total_events:,} events using {HIDE_PARALLEL_SLICES} workers")
            
            # Initial progress update
            self.update_state(state='PROGRESS', meta={
                'status': 'dispatching',
                'total': total_events,
                'processed': 0,
                'found': 0,
                'percent': 0,
                'workers': HIDE_PARALLEL_SLICES
            })
            
            # Dispatch parallel slice tasks
            slice_tasks = group([
                hide_known_good_slice_task.s(case_id, i, HIDE_PARALLEL_SLICES, user_id)
                for i in range(HIDE_PARALLEL_SLICES)
            ])
            
            # Execute all slices in parallel and wait for results
            group_result = slice_tasks.apply_async()
            
            # Poll for completion with progress updates
            completed_slices = 0
            total_scanned = 0
            total_found = 0
            total_hidden = 0
            
            import time
            while not group_result.ready():
                # Count completed tasks
                completed = sum(1 for r in group_result.results if r.ready())
                if completed > completed_slices:
                    completed_slices = completed
                    # Estimate progress
                    est_scanned = int((completed_slices / HIDE_PARALLEL_SLICES) * total_events)
                    pct = int((completed_slices / HIDE_PARALLEL_SLICES) * 100)
                    
                    self.update_state(state='PROGRESS', meta={
                        'status': 'scanning',
                        'total': total_events,
                        'processed': est_scanned,
                        'found': total_found,
                        'percent': pct,
                        'workers_complete': f'{completed_slices}/{HIDE_PARALLEL_SLICES}'
                    })
                
                time.sleep(0.5)
            
            # Aggregate results from all slices
            # Use allow_join_result to permit .get() inside task (we're coordinating subtasks)
            from celery.result import allow_join_result
            try:
                with allow_join_result():
                    results = group_result.get(timeout=300)  # 5 min timeout
                
                for r in results:
                    if isinstance(r, dict):
                        total_scanned += r.get('scanned', 0)
                        total_found += r.get('found', 0)
                        total_hidden += r.get('hidden', 0)
                        if r.get('error'):
                            logger.warning(f"[HIDE KNOWN GOOD] Slice {r.get('slice_id')} error: {r.get('error')}")
                            
            except Exception as e:
                logger.error(f"[HIDE KNOWN GOOD] Failed to get slice results: {e}")
                return {'status': 'error', 'message': f'Worker aggregation failed: {e}'}
            
            # Refresh index
            try:
                opensearch_client.indices.refresh(index=index_name)
            except:
                pass
            
            # Final progress
            self.update_state(state='PROGRESS', meta={
                'status': 'complete',
                'total': total_events,
                'processed': total_scanned,
                'found': total_found,
                'hidden': total_hidden,
                'percent': 100
            })
            
            logger.info(f"[HIDE KNOWN GOOD] Case {case_id}: Complete - scanned={total_scanned:,}, found={total_found:,}, hidden={total_hidden:,}")
            logger.info(f"[HIDE KNOWN GOOD] Audit: user_id={user_id}, case_id={case_id}, hidden={total_hidden}, processed={total_scanned}")
            
            return {
                'status': 'success',
                'hidden': total_hidden,
                'found': total_found,
                'processed': total_scanned,
                'message': f'Hidden {total_hidden:,} events using {HIDE_PARALLEL_SLICES} parallel workers'
            }
            
        except Exception as e:
            logger.error(f"[HIDE KNOWN GOOD] Error: {e}", exc_info=True)
            return {'status': 'error', 'message': str(e)}


# ============================================================================
# HIDE NOISE EVENTS (v1.46.0)
# Parallel processing using sliced scroll - similar to hide_known_good
# ============================================================================

NOISE_PARALLEL_SLICES = 8  # Use all 8 workers


@celery_app.task(bind=True, name='tasks.hide_noise_slice')
def hide_noise_slice_task(self, case_id: int, slice_id: int, max_slices: int, user_id: int):
    """
    Worker task: Process one slice of events for hide noise operation.
    
    Uses OpenSearch sliced scroll to process 1/max_slices of total events.
    This task runs in parallel with other slice tasks.
    """
    from main import app, db, opensearch_client
    from events_known_noise import process_slice, bulk_hide_events
    
    with app.app_context():
        try:
            logger.info(f"[HIDE NOISE] Slice {slice_id}/{max_slices}: Starting for case {case_id}")
            
            # Process this slice
            result = process_slice(case_id, slice_id, max_slices, opensearch_client)
            
            scanned = result.get('scanned', 0)
            events_to_hide = result.get('events_to_hide', [])
            by_category = result.get('by_category', {})
            
            # Hide the found events
            hidden_count = 0
            if events_to_hide:
                hidden_count = bulk_hide_events(events_to_hide, opensearch_client, f"case_{case_id}")
            
            logger.info(f"[HIDE NOISE] Slice {slice_id}/{max_slices}: Scanned {scanned:,}, found {len(events_to_hide):,}, hid {hidden_count:,}")
            logger.info(f"[HIDE NOISE] Slice {slice_id} breakdown: {by_category}")
            
            return {
                'slice_id': slice_id,
                'scanned': scanned,
                'found': len(events_to_hide),
                'hidden': hidden_count,
                'by_category': by_category,
                'error': None
            }
            
        except Exception as e:
            logger.error(f"[HIDE NOISE] Slice {slice_id} error: {e}", exc_info=True)
            return {
                'slice_id': slice_id,
                'scanned': 0,
                'found': 0,
                'hidden': 0,
                'by_category': {},
                'error': str(e)
            }


@celery_app.task(bind=True, name='tasks.hide_noise_events')
def hide_noise_events_task(self, case_id, user_id):
    """
    Coordinator task: Dispatches 8 parallel slice workers and aggregates results.
    
    v1.46.0: Parallel processing for noise event hiding.
    Uses all 8 Celery workers to process events ~8x faster.
    
    Args:
        case_id: ID of the case to process
        user_id: ID of the user who initiated the task
    
    Returns:
        Dict with status, hidden count, processed count, and category breakdown
    """
    from main import app, db, opensearch_client
    from models import Case
    from celery import group
    
    with app.app_context():
        try:
            case = db.session.get(Case, case_id)
            if not case:
                return {'status': 'error', 'message': 'Case not found'}
            
            index_name = f"case_{case_id}"
            
            # Count total non-hidden events
            try:
                count_response = opensearch_client.count(
                    index=index_name,
                    body={
                        "query": {
                            "bool": {
                                "must_not": [{"term": {"is_hidden": True}}]
                            }
                        }
                    }
                )
                total_events = count_response.get('count', 0)
            except Exception as e:
                return {'status': 'error', 'message': f'Failed to count events: {e}'}
            
            if total_events == 0:
                return {'status': 'success', 'hidden': 0, 'processed': 0, 'message': 'No visible events to scan'}
            
            logger.info(f"[HIDE NOISE] Case {case_id}: Starting parallel scan of {total_events:,} events using {NOISE_PARALLEL_SLICES} workers")
            
            # Initial progress update
            self.update_state(state='PROGRESS', meta={
                'status': 'dispatching',
                'total': total_events,
                'processed': 0,
                'found': 0,
                'percent': 0,
                'workers': NOISE_PARALLEL_SLICES
            })
            
            # Dispatch parallel slice tasks
            slice_tasks = group([
                hide_noise_slice_task.s(case_id, i, NOISE_PARALLEL_SLICES, user_id)
                for i in range(NOISE_PARALLEL_SLICES)
            ])
            
            # Execute all slices in parallel
            group_result = slice_tasks.apply_async()
            
            # Poll for completion with progress updates
            completed_slices = 0
            total_scanned = 0
            total_found = 0
            total_hidden = 0
            aggregate_categories = {
                'noise_process': 0,
                'noise_command': 0,
                'firewall_noise': 0
            }
            
            import time
            while not group_result.ready():
                # Count completed tasks
                completed = sum(1 for r in group_result.results if r.ready())
                if completed > completed_slices:
                    completed_slices = completed
                    est_scanned = int((completed_slices / NOISE_PARALLEL_SLICES) * total_events)
                    pct = int((completed_slices / NOISE_PARALLEL_SLICES) * 100)
                    
                    self.update_state(state='PROGRESS', meta={
                        'status': 'scanning',
                        'total': total_events,
                        'processed': est_scanned,
                        'found': total_found,
                        'percent': pct,
                        'workers_complete': f'{completed_slices}/{NOISE_PARALLEL_SLICES}'
                    })
                
                time.sleep(0.5)
            
            # Aggregate results from all slices
            from celery.result import allow_join_result
            try:
                with allow_join_result():
                    results = group_result.get(timeout=300)  # 5 min timeout
                
                for r in results:
                    if isinstance(r, dict):
                        total_scanned += r.get('scanned', 0)
                        total_found += r.get('found', 0)
                        total_hidden += r.get('hidden', 0)
                        # Aggregate categories
                        for cat, count in r.get('by_category', {}).items():
                            if cat in aggregate_categories:
                                aggregate_categories[cat] += count
                        if r.get('error'):
                            logger.warning(f"[HIDE NOISE] Slice {r.get('slice_id')} error: {r.get('error')}")
                            
            except Exception as e:
                logger.error(f"[HIDE NOISE] Failed to get slice results: {e}")
                return {'status': 'error', 'message': f'Worker aggregation failed: {e}'}
            
            # Refresh index
            try:
                opensearch_client.indices.refresh(index=index_name)
            except:
                pass
            
            # Final progress
            self.update_state(state='PROGRESS', meta={
                'status': 'complete',
                'total': total_events,
                'processed': total_scanned,
                'found': total_found,
                'hidden': total_hidden,
                'percent': 100,
                'by_category': aggregate_categories
            })
            
            logger.info(f"[HIDE NOISE] Case {case_id}: Complete - scanned={total_scanned:,}, found={total_found:,}, hidden={total_hidden:,}")
            logger.info(f"[HIDE NOISE] Categories: {aggregate_categories}")
            logger.info(f"[HIDE NOISE] Audit: user_id={user_id}, case_id={case_id}, hidden={total_hidden}, processed={total_scanned}")
            
            return {
                'status': 'success',
                'hidden': total_hidden,
                'found': total_found,
                'processed': total_scanned,
                'by_category': aggregate_categories,
                'message': f'Hidden {total_hidden:,} noise events using {NOISE_PARALLEL_SLICES} parallel workers'
            }
            
        except Exception as e:
            logger.error(f"[HIDE NOISE] Error: {e}", exc_info=True)
            return {'status': 'error', 'message': str(e)}


# ============================================================================
# AI TRIAGE SEARCH (v1.39.0)
# Full 9-phase automated attack chain analysis
# ============================================================================

# Timeline-worthy processes for Phase 9 (potential recon/lateral movement)
TIMELINE_PROCESSES = [
    # Recon commands
    'nltest.exe', 'whoami.exe', 'ipconfig.exe', 'ping.exe',
    'net.exe', 'net1.exe', 'netstat.exe', 'systeminfo.exe',
    'nslookup.exe', 'route.exe', 'arp.exe', 'tracert.exe',
    'hostname.exe', 'nbtstat.exe',
    
    # Scripting/execution
    'powershell.exe', 'pwsh.exe', 'cmd.exe',
    'rundll32.exe', 'regsvr32.exe', 'mshta.exe',
    'wscript.exe', 'cscript.exe', 'certutil.exe',
    'bitsadmin.exe', 'msbuild.exe',
    
    # Lateral movement / tools
    'psexec.exe', 'psexec64.exe', 'wmic.exe',
    'schtasks.exe',  # Can be attack or maintenance - context matters
    'sc.exe',        # Service control
    'reg.exe',       # Registry manipulation
    
    # Remote access tools
    'winscp.exe', 'putty.exe', 'plink.exe',
    'advanced_ip_scanner.exe', 'nmap.exe', 'masscan.exe',
    
    # Data access
    'notepad.exe', 'wordpad.exe',
]

# Noise processes to EXCLUDE from timeline (system management, not attack-related)
NOISE_PROCESSES = [
    # Windows system management
    'auditpol.exe',      # Windows audit policy - often run by EDR/RMM
    'gpupdate.exe',      # Group policy update
    'wuauclt.exe',       # Windows Update
    'msiexec.exe',       # Installer
    'dism.exe',          # Deployment Image Service
    'sppsvc.exe',        # Software Protection Platform
    'winmgmt.exe',       # WMI service
    
    # Console/shell infrastructure (never useful alone)
    'conhost.exe',       # Console host - spawned by every cmd.exe
    'find.exe',          # Usually part of "command | find" pipes
    'findstr.exe',       # Same as find.exe
    'sort.exe',          # Pipe utility
    'more.com',          # Pipe utility
    
    # Monitoring/health check processes
    'tasklist.exe',      # Process listing (RMM monitoring loops)
    'quser.exe',         # Session queries (RMM health checks)
    'query.exe',         # Query commands
    
    # Windows runtime/background (system noise)
    'runtimebroker.exe', # Windows Runtime Broker
    'taskhostw.exe',     # Task Host Window
    'backgroundtaskhost.exe',  # Background task host
    'wmiprvse.exe',      # WMI Provider Host (when parent is system)
    
    # Update/maintenance processes
    'huntressupdater.exe',     # Huntress updates
    'microsoftedgeupdate.exe', # Edge updates
    'fulltrustnotifier.exe',   # Adobe notifications
    'filecoauth.exe',          # Office/OneDrive co-auth
    
    # Search indexing
    'searchprotocolhost.exe',  # Windows Search
    'searchfilterhost.exe',    # Windows Search
]

# RMM-related paths to exclude (if command line contains these)
RMM_PATH_PATTERNS = [
    'ltsvc', 'labtech', 'automate',  # ConnectWise Automate/LabTech
    'aem', 'datto',                   # Datto RMM
    'kaseya', 'agentmon',             # Kaseya
    'ninjarmmag',                     # NinjaRMM
    'syncro',                         # Syncro
    'atera',                          # Atera
    'n-central', 'basupsrvc',         # N-able
    'huntress',                       # Huntress EDR
    'screenconnect',                  # ConnectWise ScreenConnect
]

# Noise command patterns - EXACT command lines that are monitoring noise (v1.41.0)
# These are excluded ONLY when parent is empty/generic (cmd.exe, svchost.exe)
# If parent is suspicious (powershell spawning netstat), we KEEP it
NOISE_COMMAND_PATTERNS = [
    # Network monitoring commands (run thousands of times by RMM/EDR)
    'netstat -ano',
    'netstat  -ano',          # With extra space (common in EDR data)
    'netstat -an',
    'netstat  -an',
    'ipconfig /all',
    'ipconfig  /all',
    
    # System info gathering (monitoring, not attacks)
    'systeminfo',
    'hostname',
    
    # Session/user queries (RMM health checks)
    'quser',
    '"quser"',                # Often quoted
    'query user',
    
    # Process listing (RMM monitoring loops)
    'tasklist',
    
    # Pipe output filters (part of monitoring chains like "netstat | find")
    'find /i',                # Case-insensitive find (e.g., find /i "Listening")
    'find "',                 # Port/string checks (e.g., find "41997")
    'find  /i',               # With extra space
    'find  "',                # With extra space
    
    # Audit policy commands (EDR continuously sets these)
    'auditpol.exe /set',
    'auditpol /set',
    'auditpol.exe  /set',
    
    # Console host (spawned by every cmd.exe - never useful for timeline)
    'conhost.exe 0xffffffff',
    'conhost.exe  0xffffffff',
    
    # PowerShell monitoring - Defender checks (Huntress, RMM)
    'get-mppreference',       # Defender preference queries
    'get-mpthreat',           # Defender threat queries
    'get-mpcomputerstatus',   # Defender status checks
    
    # PowerShell monitoring - WMI queries (LabTech, RMM)
    'get-wmiobject -class win32_operatingsystem',
    'get-wmiobject -query',
    'get-wmiobject -namespace root',
    
    # Windows service/system processes (never useful in timeline)
    'runtimebroker.exe -embedding',
    'backgroundtaskhost.exe',
    'taskhostw.exe',
    'wmiprvse.exe -secured',
    'svchost.exe -k',
    'sppsvc.exe',             # Software Protection Platform
    
    # Application update processes
    'huntressupdater.exe',
    'microsoftedgeupdate.exe',
]

# Generic/benign parent processes - commands from these are likely monitoring, not attacks
GENERIC_PARENTS = [
    '',                       # Empty parent (EDR didn't capture it)
    'cmd.exe',                # Generic - could be anything
    'svchost.exe',            # Windows service host
    'services.exe',           # Service control manager
    'wmiprvse.exe',           # WMI provider (often used by monitoring)
    'taskhostw.exe',          # Task scheduler host
]

# Maximum events to tag per unique command per host (frequency-based dedup)
# If netstat -ano runs 1000 times on a host, we only tag MAX_EVENTS_PER_COMMAND
MAX_EVENTS_PER_COMMAND = 3

# MITRE ATT&CK patterns for Phase 8
MITRE_PATTERNS = {
    'T1033': {'name': 'System Owner/User Discovery', 'processes': ['whoami.exe', 'quser.exe'], 'indicators': ['whoami', '/all']},
    'T1482': {'name': 'Domain Trust Discovery', 'processes': ['nltest.exe'], 'indicators': ['domain_trusts', '/all_trusts']},
    'T1018': {'name': 'Remote System Discovery', 'processes': ['nltest.exe', 'ping.exe', 'nslookup.exe'], 'indicators': ['dclist', 'ping', 'net view', 'advanced_ip_scanner']},
    'T1016': {'name': 'System Network Config Discovery', 'processes': ['ipconfig.exe', 'netsh.exe', 'route.exe'], 'indicators': ['ipconfig', 'netsh', 'route']},
    'T1087': {'name': 'Account Discovery', 'indicators': ['AdUsers', 'net user', 'net group', 'AdComp']},
    'T1078': {'name': 'Valid Accounts', 'indicators': ['logon', 'authentication']},
    'T1059.001': {'name': 'PowerShell', 'processes': ['powershell.exe'], 'indicators': ['-enc', '-encodedcommand']},
    'T1218.011': {'name': 'Rundll32', 'processes': ['rundll32.exe'], 'indicators': ['rundll32', '.dll,']},
}


@celery_app.task(bind=True, name='tasks.run_ai_triage_search')
def run_ai_triage_search(self, search_id):
    """
    AI Triage Search V2 - Enhanced Attack Chain Analysis (v1.44.0)
    
    Key improvements:
    - RAG pattern detection (password spray, brute force, lateral movement)
    - Authentication chain detection (NPS → DC → Target)
    - Iterative IOC hunting (loop until no new IOCs)
    - AV/EDR malware log check
    - Improved process tree building (30 min window)
    
    Phases:
    1. Prerequisite & Validation
    2. IOC Extraction (LLM with QWEN)
    3. Static Pattern Pre-Tagging (encoded PS, recon, etc.)
    3.5. RAG Pattern Detection (aggregation-based attack patterns)
    4. Iterative IOC Hunting (loop until exhausted)
    5. AV/EDR Log Check (if malware indicated)
    6. Context Window Analysis (±5 min, includes user-tagged)
    7. Process Tree Building (±30 min, full chain)
    8. MITRE Technique Mapping
    9. Timeline Event Auto-Tagging
    
    Args:
        search_id: AITriageSearch record ID
    
    Returns:
        Dict with status and summary
    """
    from main import app, db, opensearch_client
    from models import AITriageSearch, Case, IOC, System, TimelineTag, SystemToolsSetting
    from routes.triage_report import (
        extract_iocs_with_llm, extract_iocs_with_regex,
        extract_from_search_results, extract_recon_from_results,
        search_ioc, RECON_SEARCH_TERMS,
        NOISE_USERS, NOT_HOSTNAMES, is_machine_account, is_valid_hostname
    )
    # v1.44.0: Import pattern detection for RAG-based attack detection
    from triage_patterns import (
        run_all_pattern_detection, search_av_detections,
        TIER1_PATTERNS, TIER2_PATTERNS, TIER3_PATTERNS
    )
    from datetime import datetime, timedelta
    import json
    import re
    import fnmatch
    import ipaddress
    
    def is_noise_user(username):
        """Check if username is a known system/noise account."""
        if not username:
            return True
        name_lower = username.lower()
        # Check against blocklist (imported from triage_report)
        if name_lower in NOISE_USERS:
            return True
        # Check for machine accounts (ending in $)
        if is_machine_account(username):
            return True
        # Check for DWM-N, UMFD-N patterns (extended check)
        if re.match(r'^(dwm|umfd)-\d+$', name_lower):
            return True
        return False
    
    def is_noise_hostname(hostname):
        """Check if hostname is a known noise/invalid hostname."""
        if not hostname:
            return True
        # Use the imported NOT_HOSTNAMES blocklist
        if hostname.lower() in NOT_HOSTNAMES:
            return True
        # Must have at least one letter
        if not any(c.isalpha() for c in hostname):
            return True
        # Too short
        if len(hostname) < 3:
            return True
        return False
    
    def normalize_hostname(hostname):
        """
        Normalize hostname: strip FQDN to just hostname, uppercase.
        E.g., 'CM-DC01.domain.local' -> 'CM-DC01'
        """
        if not hostname:
            return None
        # Strip FQDN - take only the first part before any dot
        hostname = hostname.split('.')[0].upper()
        return hostname if len(hostname) >= 3 else None
    
    def parse_vpn_ip_ranges(vpn_ranges_str):
        """
        Parse VPN IP ranges string into a list of (start_ip, end_ip) tuples and networks.
        
        Supports:
        - Range format: "192.168.100.1-192.168.100.50"
        - CIDR format: "10.10.0.0/24"
        - Multiple ranges separated by comma or semicolon
        
        Returns: list of ipaddress objects (IPv4Network or tuple of IPv4Address)
        """
        if not vpn_ranges_str:
            return []
        
        vpn_ranges = []
        # Split by comma or semicolon
        for part in re.split(r'[,;]', vpn_ranges_str):
            part = part.strip()
            if not part:
                continue
            
            try:
                if '-' in part and '/' not in part:
                    # Range format: 192.168.100.1-192.168.100.50
                    start_ip, end_ip = part.split('-', 1)
                    vpn_ranges.append((
                        ipaddress.IPv4Address(start_ip.strip()),
                        ipaddress.IPv4Address(end_ip.strip())
                    ))
                elif '/' in part:
                    # CIDR format: 10.10.0.0/24
                    vpn_ranges.append(ipaddress.IPv4Network(part.strip(), strict=False))
                else:
                    # Single IP
                    ip = ipaddress.IPv4Address(part.strip())
                    vpn_ranges.append((ip, ip))
            except (ValueError, ipaddress.AddressValueError) as e:
                logger.warning(f"[AI_TRIAGE] Invalid VPN IP range '{part}': {e}")
                continue
        
        return vpn_ranges
    
    def is_vpn_ip(ip_str, vpn_ranges):
        """
        Check if an IP address is within any of the VPN ranges.
        
        Args:
            ip_str: IP address string to check
            vpn_ranges: List from parse_vpn_ip_ranges()
        
        Returns: True if IP is in a VPN range
        """
        if not ip_str or not vpn_ranges:
            return False
        
        try:
            ip = ipaddress.IPv4Address(ip_str)
            
            for vpn_range in vpn_ranges:
                if isinstance(vpn_range, ipaddress.IPv4Network):
                    # CIDR network
                    if ip in vpn_range:
                        return True
                elif isinstance(vpn_range, tuple):
                    # IP range (start, end)
                    start_ip, end_ip = vpn_range
                    if start_ip <= ip <= end_ip:
                        return True
        except (ValueError, ipaddress.AddressValueError):
            return False
        
        return False
    
    with app.app_context():
        start_time = datetime.utcnow()
        search = db.session.get(AITriageSearch, search_id)
        
        if not search:
            return {'status': 'error', 'message': 'Search record not found'}
        
        case = db.session.get(Case, search.case_id)
        if not case:
            search.status = 'failed'
            search.error_message = 'Case not found'
            db.session.commit()
            return {'status': 'error', 'message': 'Case not found'}
        
        def update_progress(phase: int, phase_name: str, message: str, percent: int = 0):
            """Update search progress in database."""
            search.current_phase = phase
            search.current_phase_name = phase_name
            search.progress_message = message
            search.progress_percent = percent
            db.session.commit()
            
            self.update_state(state='PROGRESS', meta={
                'phase': phase,
                'phase_name': phase_name,
                'message': message,
                'percent': percent
            })
        
        def load_exclusions():
            """Load system tools exclusions from database."""
            exclusions = {
                'rmm_executables': [],
                'remote_tools': [],
                'edr_tools': [],
                'known_good_ips': []
            }
            settings = SystemToolsSetting.query.filter_by(is_active=True).all()
            for s in settings:
                if s.setting_type == 'rmm_tool' and s.executable_pattern:
                    patterns = [p.strip().lower() for p in s.executable_pattern.split(',') if p.strip()]
                    exclusions['rmm_executables'].extend(patterns)
                elif s.setting_type == 'remote_tool':
                    ids = json.loads(s.known_good_ids) if s.known_good_ids else []
                    exclusions['remote_tools'].append({
                        'name': s.tool_name,
                        'pattern': (s.executable_pattern or '').lower(),
                        'known_good_ids': [i.lower() for i in ids]
                    })
                elif s.setting_type == 'edr_tool':
                    # EDR tools have context-aware exclusion
                    routine = json.loads(s.routine_commands) if s.routine_commands else []
                    responses = json.loads(s.response_patterns) if s.response_patterns else []
                    executables = [p.strip().lower() for p in (s.executable_pattern or '').split(',') if p.strip()]
                    exclusions['edr_tools'].append({
                        'name': s.tool_name,
                        'executables': executables,
                        'exclude_routine': s.exclude_routine if s.exclude_routine is not None else True,
                        'keep_responses': s.keep_responses if s.keep_responses is not None else True,
                        'routine_commands': [r.lower() for r in routine],
                        'response_patterns': [r.lower() for r in responses]
                    })
                elif s.setting_type == 'known_good_ip' and s.ip_or_cidr:
                    exclusions['known_good_ips'].append(s.ip_or_cidr)
            return exclusions
        
        def should_exclude_event(event, exclusions):
            """Check if event should be excluded from tagging (known-good).
            
            v1.43.15: SIMPLIFIED - Uses search_blob for all pattern matching.
            Same logic as _should_hide_event_task() for consistency.
            
            Logic:
            1. Already hidden → exclude
            2. Noise processes → exclude
            3. RMM: If executable pattern in search_blob → exclude
            4. Remote: If tool pattern AND session ID both in search_blob → exclude
            5. EDR: If executable in search_blob AND routine command in search_blob → exclude
                   (unless response pattern also present → keep)
            6. IPs: If source IP matches known-good range → exclude
            """
            src = event.get('_source', event)
            
            # Already hidden?
            if src.get('is_hidden'):
                return True
            
            proc = src.get('process', {})
            proc_name = (proc.get('name') or '').lower()
            search_blob = (src.get('search_blob') or '').lower()
            
            # Check 0: Noise processes (system management, not attack-related)
            if proc_name.replace('.exe', '') in [p.replace('.exe', '') for p in NOISE_PROCESSES]:
                return True
            
            # =========================================================================
            # CHECK 1: RMM Tool - Executable pattern in search_blob
            # =========================================================================
            # Only check configured RMM executables (e.g., "ltsvc.exe", "labtech*.exe")
            # NOT broad path patterns (which would match URLs like huntress.io)
            for rmm_pattern in exclusions.get('rmm_executables', []):
                if '*' in rmm_pattern:
                    # Wildcard: "labtech*.exe" → check for "labtech" + ".exe" nearby
                    prefix = rmm_pattern.split('*')[0]
                    if prefix and f"{prefix}" in search_blob and '.exe' in search_blob:
                        return True
                else:
                    # Exact: "ltsvc.exe" must be in blob
                    if rmm_pattern in search_blob:
                        return True
            
            # =========================================================================
            # CHECK 2: Remote Tool - Tool pattern AND session ID both in search_blob
            # =========================================================================
            for tool_config in exclusions.get('remote_tools', []):
                pattern = (tool_config.get('pattern') or '').lower()
                if pattern and pattern in search_blob:
                    for known_id in tool_config.get('known_good_ids', []):
                        if known_id and known_id.lower() in search_blob:
                            return True
            
            # =========================================================================
            # CHECK 3: EDR Tool - Context-aware exclusion
            # =========================================================================
            # Only exclude if EDR EXECUTABLE (with .exe) is in blob AND routine command
            # This prevents matching URLs like huntress.io
            for edr_config in exclusions.get('edr_tools', []):
                edr_executables = edr_config.get('executables', [])
                
                # Check if EDR executable (must have .exe) is in the event
                edr_in_blob = False
                for exe in edr_executables:
                    exe_lower = exe.lower()
                    if '*' in exe_lower:
                        # Wildcard: "blackpoint*.exe" → need prefix + .exe
                        prefix = exe_lower.split('*')[0]
                        if prefix and f"{prefix}" in search_blob and '.exe' in search_blob:
                            edr_in_blob = True
                            break
                    else:
                        # Exact: "snapagent.exe" must be in blob
                        if exe_lower in search_blob:
                            edr_in_blob = True
                            break
                
                if edr_in_blob:
                    # FIRST: Check for response action keywords - DON'T exclude these
                    if edr_config.get('keep_responses', True):
                        response_patterns = edr_config.get('response_patterns', [])
                        if any(pattern.lower() in search_blob for pattern in response_patterns if pattern):
                            continue  # Skip - this is a response action, KEEP IT
                    
                    # SECOND: Check for routine command - exclude
                    if edr_config.get('exclude_routine', True):
                        routine_commands = edr_config.get('routine_commands', [])
                        for routine in routine_commands:
                            if routine:
                                routine_lower = routine.lower()
                                if f"{routine_lower}.exe" in search_blob:
                                    return True
            
            # NOTE: Known-good IP filtering is intentionally NOT done here.
            # v1.44.2: Attacks can come from VPN/internal IPs (stolen creds, lateral movement)
            # Known-good IP filtering only applies to "Hide Known Good Events" task,
            # not to AI Triage hunting.
            
            return False
        
        try:
            search.status = 'running'
            db.session.commit()
            
            report_text = case.edr_report or ''
            
            # =========================================================
            # PHASE 1: IOC EXTRACTION FROM REPORT
            # =========================================================
            update_progress(1, 'IOC Extraction', 'Extracting IOCs from EDR report...', 5)
            
            if report_text:
                iocs = extract_iocs_with_llm(report_text)
                if not any(iocs.get(k) for k in iocs if k != 'malware_indicated'):
                    iocs = extract_iocs_with_regex(report_text)
                search.entry_point = 'full_triage'
            else:
                # No report - use existing IOCs
                existing_iocs = IOC.query.filter_by(case_id=search.case_id, is_active=True).all()
                iocs = {'ips': [], 'hostnames': [], 'usernames': [], 'sids': [], 
                       'paths': [], 'processes': [], 'commands': [], 'tools': [], 
                       'hashes': [], 'malware_indicated': False}
                for ioc in existing_iocs:
                    if ioc.ioc_type == 'ip':
                        iocs['ips'].append(ioc.ioc_value)
                    elif ioc.ioc_type == 'hostname':
                        iocs['hostnames'].append(ioc.ioc_value)
                    elif ioc.ioc_type == 'username':
                        iocs['usernames'].append(ioc.ioc_value)
                    elif ioc.ioc_type in ['filepath', 'filename']:
                        iocs['paths'].append(ioc.ioc_value)
                search.entry_point = 'ioc_hunt'
            
            known_ips = set(iocs.get('ips', []))
            known_hostnames = set(h.upper() for h in iocs.get('hostnames', []))
            known_usernames = set(u.lower() for u in iocs.get('usernames', []))
            malware_indicated = iocs.get('malware_indicated', False)
            
            search.iocs_extracted_count = sum(len(v) for k, v in iocs.items() if isinstance(v, list))
            search.iocs_extracted_json = json.dumps(iocs)
            
            update_progress(1, 'IOC Extraction', 
                f'Extracted {len(known_ips)} IPs, {len(known_hostnames)} hosts, {len(known_usernames)} users', 10)
            
            # =========================================================
            # LOAD EXCLUSIONS EARLY - Before any hunting/analysis
            # =========================================================
            # This ensures we don't use events from known-good systems as anchors
            # e.g., if analyst uses ScreenConnect to run whoami, we don't want that polluting results
            exclusions = load_exclusions()
            exclusion_summary = {
                'rmm_tools': len(exclusions.get('rmm_executables', [])),
                'remote_tools': len(exclusions.get('remote_tools', [])),
                'edr_tools': len(exclusions.get('edr_tools', [])),
            }
            logger.info(f"[AI_TRIAGE] Loaded exclusions: {exclusion_summary['rmm_tools']} RMM patterns, "
                       f"{exclusion_summary['remote_tools']} remote tools, {exclusion_summary['edr_tools']} EDR tools "
                       f"(known-good IPs NOT filtered - attacks can come from VPN/internal)")
            
            # Check event count
            try:
                result = opensearch_client.count(index=f"case_{search.case_id}")
                total_events = result['count']
            except:
                total_events = 0
            
            # =========================================================
            # PHASE 2: IOC CLASSIFICATION
            # =========================================================
            update_progress(2, 'IOC Classification', 'Classifying IOCs as SPECIFIC vs BROAD...', 12)
            
            specific_iocs = {
                'processes': iocs.get('processes', []),
                'paths': iocs.get('paths', []),
                'hashes': iocs.get('hashes', []),
                'commands': iocs.get('commands', []),
                'tools': iocs.get('tools', [])
            }
            
            broad_iocs = {
                'usernames': list(known_usernames),
                'hostnames': list(known_hostnames),
                'ips': list(known_ips),
                'sids': iocs.get('sids', [])
            }
            
            update_progress(2, 'IOC Classification', 
                f'SPECIFIC: {sum(len(v) for v in specific_iocs.values())} items, BROAD: {sum(len(v) for v in broad_iocs.values())} items', 15)
            
            # Initialize discovery sets
            discovered_ips = set()
            discovered_hostnames = set()
            discovered_usernames = set()
            discovered_commands = set()
            discovered_filenames = set()
            discovered_threats = set()
            
            # Track anchor events from various sources
            anchor_events = []
            patterns_detected = []
            
            # =========================================================
            # PHASE 2.5: RAG PATTERN DETECTION (v1.44.0)
            # Fast aggregation-based attack pattern detection
            # =========================================================
            if total_events > 0:
                update_progress(2, 'Pattern Detection', 'Running RAG pattern detection (password spray, lateral movement, auth chains)...', 16)
                
                try:
                    # Get known systems for auth chain detection
                    known_systems_set = set(s.system_name.upper() for s in 
                                           System.query.filter_by(case_id=search.case_id).all())
                    
                    # Run all pattern detection
                    pattern_results = run_all_pattern_detection(
                        opensearch_client, search.case_id, known_systems_set
                    )
                    
                    # Add detected events as anchors
                    for event in pattern_results.get('events_to_tag', []):
                        anchor_events.append({
                            'event_id': event['_id'],
                            'event': event,
                            'source': 'pattern_detection',
                            'timestamp': event['_source'].get('normalized_timestamp'),
                            'hostname': event['_source'].get('normalized_computer')
                        })
                    
                    # Add discovered IOCs
                    for ioc in pattern_results.get('iocs_discovered', []):
                        if ioc['type'] == 'ip':
                            discovered_ips.add(ioc['value'])
                        elif ioc['type'] == 'hostname':
                            discovered_hostnames.add(ioc['value'])
                    
                    patterns_detected = pattern_results.get('patterns_detected', [])
                    
                    logger.info(f"[AI_TRIAGE] Pattern detection: {len(patterns_detected)} patterns, "
                               f"{len(pattern_results.get('events_to_tag', []))} events, "
                               f"{len(pattern_results.get('iocs_discovered', []))} IOCs")
                    
                    update_progress(2, 'Pattern Detection', 
                        f'Detected {len(patterns_detected)} attack patterns: {", ".join(patterns_detected) or "none"}', 18)
                    
                except Exception as e:
                    logger.warning(f"[AI_TRIAGE] Pattern detection failed: {e}")
                    update_progress(2, 'Pattern Detection', f'Pattern detection error: {str(e)[:50]}', 18)
            
            # =========================================================
            # PHASE 3: ITERATIVE IOC HUNTING (v1.44.0 - loop until exhausted)
            # =========================================================
            # v1.44.0: ITERATIVE IOC HUNTING
            # Loop until no new IOCs are discovered
            # =========================================================
            if total_events > 0:
                update_progress(3, 'IOC Hunting', 'Starting iterative IOC hunting...', 20)
                
                # Track all IOCs we've already searched (to avoid re-searching)
                searched_ips = set()
                searched_hostnames = set()
                searched_usernames = set()
                
                # Combine known and discovered for hunting
                iocs_to_hunt_ips = known_ips.copy()
                iocs_to_hunt_hostnames = known_hostnames.copy()
                iocs_to_hunt_usernames = known_usernames.copy()
                
                hunt_pass = 0
                max_passes = 5  # Safety limit
                
                while hunt_pass < max_passes:
                    hunt_pass += 1
                    new_discoveries_this_pass = 0
                    
                    # Hunt IPs not yet searched
                    ips_to_search = iocs_to_hunt_ips - searched_ips
                    for i, ip in enumerate(list(ips_to_search)[:20]):  # Limit per pass
                        searched_ips.add(ip)
                        update_progress(3, 'IOC Hunting', f'Pass {hunt_pass}: IP {ip}', 20 + (hunt_pass * 5))
                        results, total = search_ioc(opensearch_client, search.case_id, ip)
                        if total > 0:
                            ips, hosts, users = extract_from_search_results(results)
                            new_ips = ips - iocs_to_hunt_ips - discovered_ips
                            new_hosts = hosts - iocs_to_hunt_hostnames - discovered_hostnames
                            new_users = {u for u in users if u.lower() not in iocs_to_hunt_usernames and u.lower() not in {d.lower() for d in discovered_usernames}}
                            
                            discovered_ips.update(new_ips)
                            discovered_hostnames.update(new_hosts)
                            discovered_usernames.update(new_users)
                            new_discoveries_this_pass += len(new_ips) + len(new_hosts) + len(new_users)
                            
                            # Add to next hunt set
                            iocs_to_hunt_ips.update(new_ips)
                            iocs_to_hunt_hostnames.update(new_hosts)
                            iocs_to_hunt_usernames.update(new_users)
                            
                            # Collect anchor events from IOC matches
                            for hit in results[:50]:  # Limit anchors per IOC
                                if not should_exclude_event(hit, exclusions):
                                    anchor_events.append({
                                        'event_id': hit['_id'],
                                        'event': hit,
                                        'source': 'ioc_hunt',
                                        'matched_ioc': ip,
                                        'timestamp': hit['_source'].get('normalized_timestamp'),
                                        'hostname': hit['_source'].get('normalized_computer')
                                    })
                    
                    # Hunt hostnames not yet searched
                    hosts_to_search = iocs_to_hunt_hostnames - searched_hostnames
                    for hostname in list(hosts_to_search)[:20]:
                        searched_hostnames.add(hostname)
                        results, total = search_ioc(opensearch_client, search.case_id, hostname)
                        if total > 0:
                            ips, hosts, users = extract_from_search_results(results)
                            new_ips = ips - iocs_to_hunt_ips - discovered_ips
                            new_users = {u for u in users if u.lower() not in iocs_to_hunt_usernames and u.lower() not in {d.lower() for d in discovered_usernames}}
                            
                            discovered_ips.update(new_ips)
                            discovered_usernames.update(new_users)
                            new_discoveries_this_pass += len(new_ips) + len(new_users)
                            
                            iocs_to_hunt_ips.update(new_ips)
                            iocs_to_hunt_usernames.update(new_users)
                    
                    # Hunt usernames not yet searched
                    users_to_search = iocs_to_hunt_usernames - searched_usernames
                    for username in list(users_to_search)[:10]:
                        searched_usernames.add(username)
                        results, total = search_ioc(opensearch_client, search.case_id, username)
                        if total > 0:
                            ips, hosts, users = extract_from_search_results(results)
                            new_ips = ips - iocs_to_hunt_ips - discovered_ips
                            new_hosts = hosts - iocs_to_hunt_hostnames - discovered_hostnames
                            
                            discovered_ips.update(new_ips)
                            discovered_hostnames.update(new_hosts)
                            new_discoveries_this_pass += len(new_ips) + len(new_hosts)
                            
                            iocs_to_hunt_ips.update(new_ips)
                            iocs_to_hunt_hostnames.update(new_hosts)
                    
                    logger.info(f"[AI_TRIAGE] Hunt pass {hunt_pass}: {new_discoveries_this_pass} new discoveries")
                    
                    # Stop if no new discoveries
                    if new_discoveries_this_pass == 0:
                        break
                
                update_progress(3, 'IOC Hunting', 
                    f'{hunt_pass} passes: +{len(discovered_ips)} IPs, +{len(discovered_hostnames)} hosts, +{len(discovered_usernames)} users', 38)
            
            # =========================================================
            # PHASE 3.5: RECON/MALWARE HUNTING
            # =========================================================
            if total_events > 0:
                update_progress(3, 'Recon Hunting', 'Searching for recon commands and malware patterns...', 40)
                
                for i, term in enumerate(RECON_SEARCH_TERMS):
                    update_progress(3, 'Recon Hunting', f'Searching: {term}', 40 + min(i, 8))
                    results, total = search_ioc(opensearch_client, search.case_id, term)
                    if total > 0:
                        commands, executables = extract_recon_from_results(results)
                        discovered_commands.update(commands)
                        discovered_filenames.update(executables)
                        
                        # Add as anchor events
                        for hit in results[:20]:
                            if not should_exclude_event(hit, exclusions):
                                anchor_events.append({
                                    'event_id': hit['_id'],
                                    'event': hit,
                                    'source': 'recon_hunt',
                                    'matched_term': term,
                                    'timestamp': hit['_source'].get('normalized_timestamp'),
                                    'hostname': hit['_source'].get('normalized_computer')
                                })
                
                update_progress(3, 'Recon Hunting', 
                    f'Found {len(discovered_commands)} commands, {len(discovered_filenames)} files', 48)
            
            # =========================================================
            # PHASE 4: AV/EDR MALWARE LOG CHECK (v1.44.2)
            # Always check - AV logs may have detections not in report
            # =========================================================
            if total_events > 0:
                update_progress(4, 'AV Log Check', 'Checking AV/EDR logs for malware detections...', 50)
                
                try:
                    av_events, av_iocs = search_av_detections(opensearch_client, search.case_id)
                    
                    for event in av_events:
                        anchor_events.append({
                            'event_id': event['_id'],
                            'event': event,
                            'source': 'av_detection',
                            'timestamp': event['_source'].get('normalized_timestamp'),
                            'hostname': event['_source'].get('normalized_computer')
                        })
                    
                    for ioc in av_iocs:
                        if ioc['type'] == 'malware':
                            discovered_threats.add(ioc['value'])
                        elif ioc['type'] == 'filepath':
                            discovered_filenames.add(ioc['value'])
                    
                    logger.info(f"[AI_TRIAGE] AV check: {len(av_events)} detections, {len(av_iocs)} IOCs")
                    update_progress(4, 'AV Log Check', f'Found {len(av_events)} malware detections', 52)
                    
                except Exception as e:
                    logger.warning(f"[AI_TRIAGE] AV log check failed: {e}")
                    update_progress(4, 'AV Log Check', 'No AV detections found', 52)
            
            # =========================================================
            # PHASE 5: SPECIFIC IOC SEARCH (v1.44.0 - adds to anchor_events)
            # =========================================================
            update_progress(5, 'Specific IOC Search', 'Searching for specific IOC matches...', 53)
            
            specific_anchor_count = 0
            excluded_anchor_count = 0
            seen_anchor_ids = set(a['event_id'] for a in anchor_events)
            
            for ioc_type, values in specific_iocs.items():
                for value in values:
                    if not value:
                        continue
                    
                    # For paths, extract just the filename for better search results
                    search_value = value
                    if ioc_type == 'paths' and ('\\' in value or '/' in value):
                        filename = value.replace('/', '\\').split('\\')[-1]
                        if filename and len(filename) > 3:
                            search_value = filename
                    
                    try:
                        results, total = search_ioc(opensearch_client, search.case_id, search_value)
                        if total > 0:
                            for hit in results[:50]:  # Limit per IOC
                                event_id = hit['_id']
                                if event_id in seen_anchor_ids:
                                    continue  # Already an anchor
                                    
                                if should_exclude_event(hit, exclusions):
                                    excluded_anchor_count += 1
                                    continue
                                
                                anchor_events.append({
                                    'event_id': event_id,
                                    'event': hit,
                                    'source': 'specific_ioc',
                                    'ioc_type': ioc_type,
                                    'matched_ioc': value,
                                    'timestamp': hit['_source'].get('normalized_timestamp') or hit['_source'].get('@timestamp'),
                                    'hostname': hit['_source'].get('normalized_computer')
                                })
                                seen_anchor_ids.add(event_id)
                                specific_anchor_count += 1
                    except Exception as e:
                        logger.warning(f"[AI_TRIAGE] Error searching {ioc_type}={value}: {e}")
            
            logger.info(f"[AI_TRIAGE] Phase 5: {specific_anchor_count} new anchors, {excluded_anchor_count} excluded")
            update_progress(5, 'Specific IOC Search', f'Found {specific_anchor_count} anchors ({excluded_anchor_count} excluded)', 55)
            
            # =========================================================
            # PHASE 6: BROAD IOC AGGREGATION (discovery only)
            # =========================================================
            update_progress(6, 'BROAD IOC Aggregation', 'Discovering related IOCs via aggregations...', 57)
            
            for ioc_type, values in broad_iocs.items():
                for value in values:
                    if not value:
                        continue
                    try:
                        agg_query = {
                            "size": 0,
                            "query": {"query_string": {"query": f'"{value}"', "default_operator": "AND"}},
                            "aggs": {
                                "hosts": {"terms": {"field": "normalized_computer.keyword", "size": 50}},
                                "users": {"terms": {"field": "process.user.name.keyword", "size": 50}},
                                "ips": {"terms": {"field": "host.ip.keyword", "size": 50}}
                            }
                        }
                        result = opensearch_client.search(index=f"case_{search.case_id}", body=agg_query)
                        
                        for bucket in result.get('aggregations', {}).get('hosts', {}).get('buckets', []):
                            host_val = normalize_hostname(bucket['key'])
                            if host_val and not is_noise_hostname(host_val):
                                discovered_hostnames.add(host_val)
                        for bucket in result.get('aggregations', {}).get('users', {}).get('buckets', []):
                            user_val = bucket['key']
                            if user_val and not is_noise_user(user_val):
                                discovered_usernames.add(user_val)
                        for bucket in result.get('aggregations', {}).get('ips', {}).get('buckets', []):
                            if bucket['key'] and not bucket['key'].startswith('127.'):
                                discovered_ips.add(bucket['key'])
                    except Exception as e:
                        logger.warning(f"[AI_TRIAGE] Aggregation error for {ioc_type}={value}: {e}")
            
            search.iocs_discovered_count = len(discovered_ips) + len(discovered_hostnames) + len(discovered_usernames)
            search.iocs_discovered_json = json.dumps({
                'ips': list(discovered_ips),
                'hostnames': list(discovered_hostnames),
                'usernames': list(discovered_usernames),
                'commands': list(discovered_commands),
                'filenames': list(discovered_filenames),
                'threats': list(discovered_threats)
            })
            
            update_progress(6, 'BROAD IOC Aggregation', 
                f'Discovered {len(discovered_hostnames)} hosts, {len(discovered_usernames)} users, {len(discovered_ips)} IPs', 60)
            
            # =========================================================
            # CREATE IOCs AND SYSTEMS IN DATABASE
            # =========================================================
            update_progress(6, 'Creating IOCs & Systems', 'Adding extracted and discovered IOCs to database...', 61)
            
            iocs_created = 0
            iocs_skipped_known = 0  # v1.43.4: Track skipped known systems/IPs
            systems_created = 0
            
            # Get existing IOCs and Systems to avoid duplicates
            existing_iocs = set(
                (i.ioc_type, i.ioc_value.lower()) 
                for i in IOC.query.filter_by(case_id=search.case_id).all()
            )
            existing_systems = set(
                s.system_name.upper() 
                for s in System.query.filter_by(case_id=search.case_id).all()
            )
            
            # v1.43.4: Build lookup tables for known systems and IPs
            # This enables filtering out known infrastructure from IOCs
            all_systems = System.query.filter_by(case_id=search.case_id).all()
            known_system_types = {}  # hostname.lower() -> system_type
            known_system_ips = set()  # Set of known IP addresses
            for s in all_systems:
                known_system_types[s.system_name.lower()] = s.system_type
                if s.ip_address:
                    known_system_ips.add(s.ip_address)
            
            logger.info(f"[AI_TRIAGE] Loaded {len(known_system_types)} known systems, {len(known_system_ips)} known IPs for filtering")
            
            # =========================================================
            # v1.43.10: IOC Value Normalization
            # =========================================================
            # 1. System utilities: Just filename without extension if in normal path
            # 2. Usernames: Strip domain (DOMAIN\user, user@domain) → just username
            # 3. Deduplication handled by existing_iocs set
            
            KNOWN_SYSTEM_UTILITIES = {
                'cmd', 'powershell', 'pwsh', 'whoami', 'ipconfig', 'net', 'net1',
                'netstat', 'ping', 'nslookup', 'tracert', 'hostname', 'systeminfo',
                'tasklist', 'taskkill', 'schtasks', 'sc', 'reg', 'regedit', 'wmic',
                'mshta', 'rundll32', 'regsvr32', 'cscript', 'wscript', 'certutil',
                'bitsadmin', 'msbuild', 'explorer', 'notepad', 'calc', 'msiexec',
                'nltest', 'dsquery', 'csvde', 'ldifde', 'netsh', 'route', 'arp',
                'nbtstat', 'quser', 'query', 'auditpol', 'gpupdate', 'gpresult',
                'bcdedit', 'diskpart', 'format', 'chkdsk', 'sfc', 'dism',
                'attrib', 'icacls', 'cacls', 'takeown', 'robocopy', 'xcopy',
                'findstr', 'find', 'sort', 'more', 'type', 'copy', 'move', 'del',
                'mkdir', 'rmdir', 'cd', 'dir', 'echo', 'set', 'where', 'tree',
            }
            
            NORMAL_SYSTEM_PATHS = [
                'c:\\windows\\system32\\',
                'c:\\windows\\syswow64\\',
                'c:\\windows\\',
                '%systemroot%\\system32\\',
                '%systemroot%\\syswow64\\',
                '%windir%\\system32\\',
                '%windir%\\syswow64\\',
            ]
            
            def normalize_filename_ioc(value):
                """
                Normalize filename/process IOCs:
                - System utilities from normal paths → just the name without extension
                - Other executables → keep as-is (could be suspicious)
                Returns (normalized_value, ioc_type) where ioc_type may change
                """
                if not value:
                    return None, 'filename'
                
                value_lower = value.lower().strip()
                
                # Extract just the filename from a full path
                if '\\' in value or '/' in value:
                    path_lower = value_lower.replace('/', '\\')
                    
                    # Check if it's from a normal system path
                    is_normal_path = any(path_lower.startswith(p) for p in NORMAL_SYSTEM_PATHS)
                    
                    # Get the filename
                    filename = value.replace('/', '\\').split('\\')[-1]
                    filename_no_ext = filename.rsplit('.', 1)[0].lower()
                    
                    if is_normal_path and filename_no_ext in KNOWN_SYSTEM_UTILITIES:
                        # System utility in normal path → just the command name
                        return filename_no_ext, 'command'
                    else:
                        # Not a normal path or not a known utility → keep full path
                        return value, 'filepath'
                else:
                    # Just a filename (e.g., "whoami.exe")
                    filename_no_ext = value.rsplit('.', 1)[0].lower() if '.' in value else value.lower()
                    
                    if filename_no_ext in KNOWN_SYSTEM_UTILITIES:
                        return filename_no_ext, 'command'
                    else:
                        return value, 'filename'
            
            def normalize_username_ioc(username):
                """
                Normalize username by stripping domain:
                - DOMAIN\\username → username
                - user@domain.com → user
                Returns normalized username or None if invalid
                """
                if not username:
                    return None
                
                username = username.strip()
                
                # Handle DOMAIN\username format
                if '\\' in username:
                    username = username.split('\\')[-1]
                
                # Handle user@domain format
                if '@' in username:
                    username = username.split('@')[0]
                
                # Clean up and validate
                username = username.strip()
                if not username or len(username) < 2:
                    return None
                
                return username
            
            # =========================================================
            # v1.43.9: Context-based IP IOC filtering for discovered IPs
            # =========================================================
            # IPs from EDR report: ALWAYS create IOC (analyst/EDR flagged them)
            # Discovered IPs: Only create IOC if they appear in meaningful events
            #
            # Meaningful events:
            #   - Authentication (4624, 4625, 4776, VPN, RDP)
            #   - Process network connections (process.user_logon.ip)
            #   - SIGMA violations
            #
            # NOT meaningful (noise):
            #   - Firewall DENY/DROP/BLOCK logs (perimeter noise)
            #   - General network traffic
            #   - Proxy logs (web browsing)
            # =========================================================
            
            MEANINGFUL_IP_EVENT_IDS = {
                # Authentication events
                '4624', '4625', '4648', '4768', '4769', '4771', '4776',
                # RDP/Remote
                '4778', '4779', '21', '22', '24', '25',
                # VPN/NPS
                '6272', '6273', '6274', '6275', '6278', '6279',
                # Process creation with network
                '1', '3',  # Sysmon process create, network connect
            }
            
            # Keywords indicating firewall/network noise
            FIREWALL_NOISE_KEYWORDS = [
                'firewall', 'fw_', 'fw-', 'deny', 'drop', 'block', 'reject',
                'netflow', 'traffic', 'conn_state', 'action:deny', 'action:drop',
            ]
            
            def is_ip_in_meaningful_context(ip, case_id):
                """
                Check if an IP appears in meaningful events (auth, process network).
                Returns True if IP should become an IOC.
                
                v1.43.9: Filters firewall/network noise from discovered IPs.
                """
                try:
                    # Search for events containing this IP
                    query = {
                        "query": {
                            "bool": {
                                "must": [
                                    {"query_string": {"query": f'"{ip}"'}}
                                ]
                            }
                        },
                        "size": 50,  # Sample events
                        "_source": ["normalized_event_id", "source_file_type", "search_blob", 
                                   "process.user_logon.ip", "has_sigma", "has_ioc"]
                    }
                    
                    result = opensearch_client.search(index=f"case_{case_id}", body=query)
                    hits = result.get('hits', {}).get('hits', [])
                    
                    if not hits:
                        return False  # IP not found
                    
                    meaningful_count = 0
                    noise_count = 0
                    
                    for hit in hits:
                        src = hit.get('_source', {})
                        event_id = str(src.get('normalized_event_id', ''))
                        source_type = (src.get('source_file_type', '') or '').upper()
                        blob = (src.get('search_blob', '') or '').lower()
                        
                        # Check for SIGMA/IOC hits (always meaningful)
                        if src.get('has_sigma') or src.get('has_ioc'):
                            meaningful_count += 1
                            continue
                        
                        # Check for authentication event IDs
                        if event_id in MEANINGFUL_IP_EVENT_IDS:
                            meaningful_count += 1
                            continue
                        
                        # Check for process.user_logon.ip (someone logged in from this IP)
                        proc = src.get('process', {})
                        if isinstance(proc, dict):
                            logon_ip = proc.get('user_logon', {}).get('ip')
                            if logon_ip == ip:
                                meaningful_count += 1
                                continue
                        
                        # Check for firewall/network noise keywords in blob
                        if any(kw in blob for kw in FIREWALL_NOISE_KEYWORDS):
                            noise_count += 1
                            continue
                        
                        # EDR events are generally meaningful
                        if source_type == 'EDR':
                            meaningful_count += 1
                        else:
                            noise_count += 1
                    
                    # IP is meaningful if majority of events are meaningful
                    # Or if there's at least 1 meaningful event
                    return meaningful_count > 0
                    
                except Exception as e:
                    logger.warning(f"[AI_TRIAGE] Context check failed for IP {ip}: {e}")
                    return True  # Be conservative - create IOC on error
            
            # Track IPs from EDR report (always IOC) vs discovered (need filtering)
            report_ips = set(iocs.get('ips', []))
            noise_ips_filtered = 0
            noise_values_filtered = 0
            
            # =========================================================
            # v1.43.13: Noise IOC value filtering
            # =========================================================
            # These are system/application values that should NEVER be IOCs
            NOISE_IOC_VALUES = {
                # Windows Event Providers (from Event.System.Provider.#attributes.Name)
                '.net runtime', 'microsoft-windows-security-auditing',
                'microsoft-windows-powershell', 'microsoft-windows-sysmon',
                'microsoft-windows-taskscheduler', 'microsoft-windows-dns-client',
                'microsoft-windows-kernel-general', 'microsoft-windows-kernel-power',
                'microsoft-windows-winlogon', 'microsoft-windows-user profiles service',
                'microsoft-windows-groupolicy', 'microsoft-windows-windowsupdateclient',
                'microsoft-windows-bits-client', 'microsoft-windows-eventlog',
                'microsoft-windows-wmi', 'service control manager', 'schannel',
                'application error', 'windows error reporting', 'volsnap',
                
                # Generic system terms
                'security', 'system', 'application', 'setup', 'forwarded events',
                'windows powershell', 'powershell', 'microsoft', 'windows',
                
                # Common noise strings
                'n/a', 'na', 'none', 'null', 'unknown', 'undefined', '-', '--', '---',
                'true', 'false', 'yes', 'no', '0', '1',
                
                # Local/loopback
                'localhost', '127.0.0.1', '::1', '0.0.0.0',
            }
            
            def is_noise_ioc_value(value):
                """Check if IOC value is noise (system providers, generic terms, etc.)"""
                if not value:
                    return True
                val_lower = value.lower().strip()
                # Direct match
                if val_lower in NOISE_IOC_VALUES:
                    return True
                # Too short (less than 3 chars)
                if len(val_lower) < 3:
                    return True
                # Starts with microsoft-windows- (provider names)
                if val_lower.startswith('microsoft-windows-'):
                    return True
                return False
            
            # Helper to add IOC if not exists
            # v1.43.4: Enhanced to skip known systems (non-unknown types) and known IPs
            # v1.43.9: Filter discovered IPs based on event context
            # v1.43.13: Filter noise IOC values
            def add_ioc_if_new(ioc_type, ioc_value, is_active=True, from_report=False):
                nonlocal iocs_created, iocs_skipped_known, noise_ips_filtered, noise_values_filtered
                if not ioc_value or (ioc_type, ioc_value.lower()) in existing_iocs:
                    return
                
                # v1.43.13: Skip noise IOC values (system providers, generic terms)
                if is_noise_ioc_value(ioc_value):
                    logger.debug(f"[AI_TRIAGE] Skipping noise IOC value: {ioc_value}")
                    noise_values_filtered += 1
                    return
                
                # v1.43.4: Skip hostname IOCs for known systems with non-unknown types
                # Systems with type='unknown' still become IOCs (need analyst review)
                if ioc_type == 'hostname':
                    hostname_lower = ioc_value.lower()
                    if hostname_lower in known_system_types:
                        sys_type = known_system_types[hostname_lower]
                        if sys_type != 'unknown':
                            logger.debug(f"[AI_TRIAGE] Skipping known {sys_type} hostname IOC: {ioc_value}")
                            iocs_skipped_known += 1
                            return
                
                # v1.43.4: Skip IP IOCs for known system IPs
                # v1.43.9: Filter discovered IPs (not from report) based on event context
                if ioc_type == 'ip':
                    if ioc_value in known_system_ips:
                        logger.debug(f"[AI_TRIAGE] Skipping known system IP IOC: {ioc_value}")
                        iocs_skipped_known += 1
                        return
                    
                    # v1.43.9: Discovered IPs need context check (firewall noise filter)
                    # IPs from EDR report always become IOCs (analyst/EDR flagged them)
                    if not from_report and ioc_value not in report_ips:
                        if not is_ip_in_meaningful_context(ioc_value, search.case_id):
                            logger.info(f"[AI_TRIAGE] Filtering noise IP (no meaningful context): {ioc_value}")
                            noise_ips_filtered += 1
                            return
                
                try:
                    ioc = IOC(
                        case_id=search.case_id,
                        ioc_type=ioc_type,
                        ioc_value=ioc_value,
                        is_active=is_active,
                        description='Created by AI Triage Search'
                    )
                    db.session.add(ioc)
                    existing_iocs.add((ioc_type, ioc_value.lower()))
                    iocs_created += 1
                except Exception as e:
                    logger.warning(f"[AI_TRIAGE] Failed to create IOC {ioc_type}={ioc_value}: {e}")
            
            # Helper to add System if not exists
            # v1.43.3: New systems from triage are added as 'unknown' type
            # This ensures they still become IOCs until an analyst reviews and categorizes them
            def add_system_if_new(hostname):
                nonlocal systems_created
                if not hostname or hostname.upper() in existing_systems:
                    return
                try:
                    system = System(
                        case_id=search.case_id,
                        system_name=hostname.upper(),  # Field is system_name, not hostname
                        system_type='unknown',  # v1.43.3: Use 'unknown' - analyst must review
                        added_by='AI Triage Search'
                    )
                    db.session.add(system)
                    existing_systems.add(hostname.upper())
                    systems_created += 1
                except Exception as e:
                    logger.warning(f"[AI_TRIAGE] Failed to create System {hostname}: {e}")
            
            # Add extracted IOCs from report
            # v1.43.9: IPs from report use from_report=True (always create IOC)
            for ip in iocs.get('ips', []):
                add_ioc_if_new('ip', ip, from_report=True)
            for hostname in iocs.get('hostnames', []):
                normalized = normalize_hostname(hostname)
                if normalized and not is_noise_hostname(normalized):  # Filter noise hostnames
                    add_ioc_if_new('hostname', normalized)
                    add_system_if_new(normalized)
            for username in iocs.get('usernames', []):
                # v1.43.10: Normalize username (strip domain)
                normalized_user = normalize_username_ioc(username)
                if normalized_user and not is_noise_user(normalized_user):
                    add_ioc_if_new('username', normalized_user)
            for sid in iocs.get('sids', []):
                add_ioc_if_new('user_sid', sid, is_active=False)  # SIDs start inactive
            for path in iocs.get('paths', []):
                # v1.43.10: Normalize filepath (system utils → just command name)
                norm_val, norm_type = normalize_filename_ioc(path)
                if norm_val:
                    add_ioc_if_new(norm_type, norm_val)
            for proc in iocs.get('processes', []):
                # v1.43.10: Normalize process (system utils → just command name)
                norm_val, norm_type = normalize_filename_ioc(proc)
                if norm_val:
                    add_ioc_if_new(norm_type, norm_val)
            for cmd in iocs.get('commands', []):
                # v1.43.10: Normalize command (system utils → just command name)
                norm_val, norm_type = normalize_filename_ioc(cmd)
                if norm_val:
                    add_ioc_if_new(norm_type, norm_val)
            for tool in iocs.get('tools', []):
                add_ioc_if_new('tool', tool)
            for hash_val in iocs.get('hashes', []):
                add_ioc_if_new('hash', hash_val)
            
            # Add discovered IOCs
            # v1.43.9: Discovered IPs filtered by context (firewall noise excluded)
            for ip in discovered_ips:
                add_ioc_if_new('ip', ip, from_report=False)  # Will check context
            for hostname in discovered_hostnames:
                normalized = normalize_hostname(hostname)
                if normalized and not is_noise_hostname(normalized):  # Filter noise hostnames
                    add_ioc_if_new('hostname', normalized)
                    add_system_if_new(normalized)
            for username in discovered_usernames:
                # v1.43.10: Normalize username (strip domain)
                normalized_user = normalize_username_ioc(username)
                if normalized_user and not is_noise_user(normalized_user):
                    add_ioc_if_new('username', normalized_user)
            for cmd in discovered_commands:
                # v1.43.10: Normalize command (system utils → just command name)
                norm_val, norm_type = normalize_filename_ioc(cmd)
                if norm_val:
                    add_ioc_if_new(norm_type, norm_val)
            for filename in discovered_filenames:
                # v1.43.10: Normalize filename (system utils → just command name)
                norm_val, norm_type = normalize_filename_ioc(filename)
                if norm_val:
                    add_ioc_if_new(norm_type, norm_val)
            for threat in discovered_threats:
                add_ioc_if_new('threat', threat)
            
            db.session.commit()
            logger.info(f"[AI_TRIAGE] Created {iocs_created} IOCs, {systems_created} Systems (skipped {iocs_skipped_known} known, {noise_ips_filtered} noise IPs, {noise_values_filtered} noise values)")
            
            # =========================================================
            # PHASE 6: TIME WINDOW ANALYSIS (v1.44.0 - includes user-tagged)
            # ±5 min around anchor events (both triage and user-tagged)
            # =========================================================
            update_progress(6, 'Context Analysis', 'Analyzing time windows around anchor events...', 62)
            
            all_window_events = []
            excluded_early_count = 0
            processed_windows = set()
            
            # v1.44.0: Include user-tagged events as additional anchors
            index_name = f"case_{search.case_id}"
            user_tagged = TimelineTag.query.filter_by(
                case_id=search.case_id, 
                index_name=index_name
            ).all()
            
            for tag in user_tagged:
                try:
                    # Fetch the tagged event to get timestamp/hostname
                    result = opensearch_client.get(index=index_name, id=tag.event_id)
                    if result.get('found'):
                        source = result['_source']
                        anchor_events.append({
                            'event_id': tag.event_id,
                            'event': result,
                            'source': 'user_tagged',
                            'timestamp': source.get('normalized_timestamp') or source.get('@timestamp'),
                            'hostname': source.get('normalized_computer')
                        })
                except:
                    pass  # Event may not exist
            
            logger.info(f"[AI_TRIAGE] Context analysis: {len(anchor_events)} anchors ({len(user_tagged)} user-tagged)")
            
            # Deduplicate anchor events
            seen_anchor_ids = set()
            unique_anchors = []
            for anchor in anchor_events:
                if anchor['event_id'] not in seen_anchor_ids:
                    seen_anchor_ids.add(anchor['event_id'])
                    unique_anchors.append(anchor)
            
            # Limit to most relevant anchors (prioritize by source)
            source_priority = {'user_tagged': 0, 'av_detection': 1, 'pattern_detection': 2, 'recon_hunt': 3, 'ioc_hunt': 4, 'specific_ioc': 5}
            unique_anchors.sort(key=lambda x: source_priority.get(x.get('source', 'other'), 99))
            anchors_to_process = unique_anchors[:50]  # Increased limit
            
            for i, anchor in enumerate(anchors_to_process):
                hostname = anchor.get('hostname')
                timestamp = anchor.get('timestamp')
                
                if not hostname or not timestamp:
                    continue
                
                window_key = f"{hostname}|{timestamp[:16]}"
                if window_key in processed_windows:
                    continue
                processed_windows.add(window_key)
                
                try:
                    # Handle various timestamp formats
                    ts = timestamp
                    if isinstance(ts, str):
                        ts = ts.replace('Z', '+00:00')
                        if '+' not in ts and 'T' in ts:
                            ts = ts + '+00:00'
                        anchor_time = datetime.fromisoformat(ts.replace('+00:00', ''))
                    else:
                        anchor_time = ts
                    
                    start = (anchor_time - timedelta(minutes=5)).isoformat() + "Z"
                    end = (anchor_time + timedelta(minutes=5)).isoformat() + "Z"
                    
                    time_query = {
                        "query": {
                            "bool": {
                                "must": [
                                    {"term": {"normalized_computer.keyword": hostname}},
                                    {"range": {"@timestamp": {"gte": start, "lte": end}}}
                                ],
                                "must_not": [
                                    {"term": {"is_hidden": True}}
                                ]
                            }
                        },
                        "sort": [{"@timestamp": "asc"}],
                        "size": 500
                    }
                    
                    result = opensearch_client.search(index=index_name, body=time_query)
                    for hit in result['hits']['hits']:
                        if should_exclude_event(hit, exclusions):
                            excluded_early_count += 1
                            continue
                        all_window_events.append(hit)
                except Exception as e:
                    logger.warning(f"[AI_TRIAGE] Time window error: {e}")
                
                if i % 5 == 0:  # Update less frequently
                    update_progress(6, 'Context Analysis', 
                        f'Windows: {i+1}/{len(anchors_to_process)}, Events: {len(all_window_events)}', 
                        62 + int((i / max(len(anchors_to_process), 1)) * 10))
            
            search.events_analyzed_count = len(all_window_events)
            logger.info(f"[AI_TRIAGE] Context analysis: {len(all_window_events)} events kept, {excluded_early_count} excluded")
            update_progress(6, 'Context Analysis', f'{len(all_window_events)} events ({excluded_early_count} excluded)', 72)
            
            # =========================================================
            # PHASE 7: PROCESS TREE BUILDING (v1.44.0 - enhanced)
            # Extended parent detection, MITRE pattern matching
            # =========================================================
            update_progress(7, 'Process Trees', 'Building process trees and matching MITRE patterns...', 75)
            
            # v1.44.0: Extended list of suspicious parent processes
            SUSPICIOUS_PARENTS = {
                'cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe',
                'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'msbuild.exe', 'excel.exe',
                'winword.exe', 'outlook.exe', 'powerpnt.exe', 'wmiprvse.exe', 'wmic.exe',
                'explorer.exe', 'svchost.exe',  # When spawning shells
            }
            
            suspicious_parents = {}
            techniques_found = {}
            
            for event in all_window_events:
                src = event.get('_source', {})
                proc = src.get('process', {})
                parent = proc.get('parent', {})
                parent_name = (parent.get('name') or '').lower()
                parent_pid = parent.get('pid')
                proc_name = (proc.get('name') or '').lower()
                hostname = src.get('normalized_computer')
                cmd_line = (proc.get('command_line') or '').lower()
                
                # Build process trees with extended parent list
                if parent_name in SUSPICIOUS_PARENTS and parent_pid and hostname:
                    key = f"{hostname}|{parent_pid}"
                    if key not in suspicious_parents:
                        suspicious_parents[key] = {
                            'parent_name': parent_name,
                            'parent_pid': parent_pid,
                            'hostname': hostname,
                            'children': []
                        }
                    suspicious_parents[key]['children'].append({
                        'name': proc_name,
                        'command_line': proc.get('command_line', ''),
                        'timestamp': src.get('@timestamp'),
                        'pid': proc.get('pid')
                    })
                
                # MITRE pattern matching
                for tech_id, pattern in MITRE_PATTERNS.items():
                    matched = False
                    for proc_pattern in pattern.get('processes', []):
                        if proc_pattern.lower() in proc_name:
                            matched = True
                            break
                    for indicator in pattern.get('indicators', []):
                        if indicator.lower() in cmd_line:
                            matched = True
                            break
                    
                    if matched:
                        if tech_id not in techniques_found:
                            techniques_found[tech_id] = {'name': pattern['name'], 'count': 0, 'events': []}
                        techniques_found[tech_id]['count'] += 1
                        if len(techniques_found[tech_id]['events']) < 5:
                            techniques_found[tech_id]['events'].append(event['_id'])
            
            # v1.44.0: Add detected patterns to techniques
            pattern_to_mitre = {
                'password_spray': 'T1110.003',
                'brute_force': 'T1110.001',
                'lateral_movement': 'T1021',
                'pass_the_hash': 'T1550.002',
                'auth_chain': 'T1078',  # Valid accounts
            }
            for pattern in patterns_detected:
                tech_id = pattern_to_mitre.get(pattern)
                if tech_id and tech_id not in techniques_found:
                    techniques_found[tech_id] = {'name': pattern.replace('_', ' ').title(), 'count': 1, 'events': []}
            
            # Build better process tree structure grouped by parent
            process_tree_data = []
            for key, tree in list(suspicious_parents.items())[:30]:
                # Sort children by timestamp
                children = sorted(tree.get('children', []), key=lambda x: x.get('timestamp', ''))
                
                # Get time range (use different var names to avoid shadowing outer start_time)
                if children:
                    tree_start = children[0].get('timestamp', '')[:19] if children[0].get('timestamp') else ''
                    tree_end = children[-1].get('timestamp', '')[:19] if children[-1].get('timestamp') else ''
                else:
                    tree_start = tree_end = ''
                
                process_tree_data.append({
                    'parent_name': tree.get('parent_name'),
                    'parent_pid': tree.get('parent_pid'),
                    'hostname': tree.get('hostname'),
                    'time_range': f"{tree_start} - {tree_end}" if tree_start else '',
                    'child_count': len(children),
                    'children': [
                        {
                            'timestamp': (c.get('timestamp') or '')[:19],
                            'name': c.get('name'),
                            'command': c.get('command_line', '')[:300]
                        }
                        for c in children[:20]  # Limit children per tree
                    ]
                })
            
            search.process_trees_count = len(suspicious_parents)
            search.techniques_found_count = len(techniques_found)
            search.process_trees_json = json.dumps(process_tree_data)
            search.mitre_techniques_json = json.dumps({k: {'name': v['name'], 'count': v['count']} for k, v in techniques_found.items()})
            
            update_progress(7, 'Process Trees', 
                f'Built {len(suspicious_parents)} trees, found {len(techniques_found)} MITRE techniques', 85)
            
            # =========================================================
            # PHASE 8: TIMELINE EVENT AUTO-TAGGING (v1.44.0)
            # =========================================================
            update_progress(8, 'Timeline Tagging', 'Filtering timeline events...', 87)
            
            # Note: exclusions already loaded after Phase 1
            
            # Filter to timeline-worthy events, excluding known-good
            # v1.41.0: Added frequency-based deduplication - if same command runs 100+ times
            # on a host, only tag MAX_EVENTS_PER_COMMAND instances
            timeline_events = []
            seen_keys = set()           # Exact timestamp+command dedup
            command_frequency = {}       # Track {host|command: count} for frequency dedup
            excluded_count = 0
            frequency_skipped = 0
            process_filter_count = 0    # Debug: track how many filtered by process name
            no_process_count = 0         # Debug: track how many have no process
            
            # v1.44.3: Include anchor events directly - these ARE the interesting events
            # (auth chains, AV detections, IOC matches, pattern matches)
            # Use unique_anchors (already deduped and prioritized by source)
            anchor_event_ids = set()
            for anchor in unique_anchors[:200]:  # Cap at 200 anchors for tagging
                event = anchor.get('event')
                if event and event.get('_id'):
                    event_id = event['_id']
                    if event_id not in anchor_event_ids:
                        anchor_event_ids.add(event_id)
                        # Add anchor events directly (they passed exclusion checks when added)
                        timeline_events.append(event)
                        seen_keys.add(event_id)
            
            logger.info(f"[AI_TRIAGE] Added {len(timeline_events)} anchor events directly to timeline")
            
            # Also check window events for additional timeline-worthy process events
            for event in all_window_events:
                src = event.get('_source', {})
                proc = src.get('process', {})
                proc_name = (proc.get('name') or '').lower()
                
                # v1.44.2: Fixed timeline filtering to allow non-process events
                # Auth events (4624, 4776), AV detections, pattern matches don't have process names
                # Only filter by TIMELINE_PROCESSES if the event HAS a process name
                if proc_name:
                    # This is a process event - check if it's timeline-worthy
                    if not any(p.lower().replace('.exe', '') in proc_name for p in TIMELINE_PROCESSES):
                        process_filter_count += 1
                        continue
                else:
                    no_process_count += 1
                # If no process name, it's likely an auth/AV/pattern event - let it through
                
                # Check exclusions (known-good RMM, remote tools)
                if should_exclude_event(event, exclusions):
                    excluded_count += 1
                    continue
                
                # Deduplicate by event ID (already added anchor events use event ID)
                event_id = event.get('_id', '')
                if event_id in seen_keys:
                    continue
                seen_keys.add(event_id)
                
                # v1.41.0: Frequency-based deduplication
                # Track how many times this command appears on this host
                hostname = src.get('normalized_computer', 'unknown')
                cmd = (proc.get('command_line') or '').lower()
                # Normalize command for frequency tracking (strip args that change)
                cmd_base = cmd.split()[0] if cmd else ''  # Just the executable
                freq_key = f"{hostname}|{cmd_base}"
                
                current_count = command_frequency.get(freq_key, 0)
                if current_count >= MAX_EVENTS_PER_COMMAND:
                    frequency_skipped += 1
                    continue  # Already have enough samples of this command on this host
                
                command_frequency[freq_key] = current_count + 1
                timeline_events.append(event)
            
            timeline_events.sort(key=lambda x: x.get('_source', {}).get('@timestamp', ''))
            logger.info(f"[AI_TRIAGE] Timeline filter debug: {len(all_window_events)} total, {no_process_count} no-process, "
                       f"{process_filter_count} filtered by process name, {excluded_count} excluded, {frequency_skipped} freq-skip")
            logger.info(f"[AI_TRIAGE] Filtered to {len(timeline_events)} timeline events "
                       f"({excluded_count} excluded as known-good, {frequency_skipped} skipped by frequency limit)")
            
            update_progress(8, 'Timeline Tagging', f'Filtered to {len(timeline_events)} timeline events', 90)
            
            # Auto-tag timeline events
            index_name = f"case_{search.case_id}"
            existing_tag_ids = set(
                t.event_id for t in TimelineTag.query.filter_by(
                    case_id=search.case_id, index_name=index_name
                ).all()
            )
            existing_tag_count = len(existing_tag_ids)
            
            tags_added = 0
            already_tagged = 0
            for event in timeline_events:
                event_id = event.get('_id')
                if not event_id:
                    continue
                if event_id in existing_tag_ids:
                    already_tagged += 1
                    continue
                
                src = event.get('_source', {})
                proc = src.get('process', {})
                proc_name = proc.get('name', 'Unknown')
                cmd = (proc.get('command_line') or '')[:100]
                ts = src.get('@timestamp', '')[:19]
                
                notes = f"[AI Triage Timeline Event]\n"
                notes += f"Timestamp: {ts}\n"
                notes += f"Process: {proc_name}\n"
                if cmd:
                    notes += f"Command: {cmd}\n"
                notes += f"\nThis event is part of the reconstructed attack timeline."
                
                try:
                    tag = TimelineTag(
                        case_id=search.case_id,
                        user_id=search.generated_by,
                        event_id=event_id,
                        index_name=index_name,
                        event_data=json.dumps(src),
                        tag_color='purple',
                        notes=notes
                    )
                    db.session.add(tag)
                    existing_tag_ids.add(event_id)
                    tags_added += 1
                except Exception as e:
                    logger.warning(f"[AI_TRIAGE] Failed to tag event {event_id}: {e}")
            
            db.session.commit()
            
            logger.info(f"[AI_TRIAGE] Auto-tagging: {tags_added} new, {already_tagged} already tagged, {existing_tag_count} total existing")
            
            search.timeline_events_count = len(timeline_events)
            # Store total tagged (new + already existed from this run's events)
            search.auto_tagged_count = tags_added + already_tagged
            
            # Build timeline JSON with full process tree info
            timeline_data = []
            for event in timeline_events[:100]:  # Increased limit
                src = event.get('_source', {})
                proc = src.get('process', {})
                parent = proc.get('parent', {})
                grandparent = parent.get('parent', {})  # EDR often includes grandparent
                
                timeline_data.append({
                    'timestamp': src.get('@timestamp'),
                    'hostname': src.get('normalized_computer') or src.get('host', {}).get('hostname'),
                    # Process info
                    'process': proc.get('name'),
                    'process_pid': proc.get('pid'),
                    'process_entity_id': proc.get('entity_id'),
                    'command': (proc.get('command_line') or '')[:500],  # Longer command
                    'user': f"{proc.get('user', {}).get('domain', '')}\\{proc.get('user', {}).get('name', '')}".strip('\\'),
                    # Parent info
                    'parent': parent.get('name'),
                    'parent_pid': parent.get('pid'),
                    'parent_entity_id': parent.get('entity_id'),
                    'parent_command': (parent.get('command_line') or '')[:200],
                    # Grandparent info (if available)
                    'grandparent': grandparent.get('name') if grandparent else None,
                    'grandparent_pid': grandparent.get('pid') if grandparent else None,
                    # Event metadata
                    'event_id': event.get('_id'),
                    'file_type': src.get('file_type'),
                    # Hash if available
                    'hash': proc.get('hash', {}).get('sha256') or proc.get('hash', {}).get('md5')
                })
            search.timeline_json = json.dumps(timeline_data)
            
            update_progress(8, 'Timeline Tagging', f'Tagged {tags_added} events', 95)
            
            # =========================================================
            # PHASE 9: LLM SUMMARY GENERATION (v1.44.0)
            # =========================================================
            attack_narrative = ""
            if tags_added > 0 or len(techniques_found) > 0 or len(patterns_detected) > 0:
                update_progress(9, 'Summary', 'Generating attack narrative...', 96)
                
                try:
                    from models import SystemSettings
                    import requests
                    
                    ollama_host = SystemSettings.query.filter_by(setting_key='ollama_host').first()
                    host = ollama_host.setting_value if ollama_host else 'http://localhost:11434'
                    
                    # Build context for LLM
                    summary_context = f"""
DFIR Investigation Summary:

EXTRACTED IOCs (from EDR report):
- IPs: {list(known_ips)[:10]}
- Hostnames: {list(known_hostnames)[:10]}
- Usernames: {list(known_usernames)[:10]}

DISCOVERED IOCs (from hunting):
- New IPs: {list(discovered_ips)[:10]}
- New Hostnames: {list(discovered_hostnames)[:10]}
- New Usernames: {list(discovered_usernames)[:10]}
- Threats/Malware: {list(discovered_threats)[:5]}

PATTERNS DETECTED: {patterns_detected}

MITRE TECHNIQUES: {list(techniques_found.keys())[:10]}

EVENTS TAGGED: {tags_added}
PROCESS TREES: {len(suspicious_parents)}
HUNT PASSES: {hunt_pass if 'hunt_pass' in dir() else 1}
"""
                    
                    prompt = f"""Based on this DFIR investigation data, write a brief attack narrative (2-3 paragraphs).
Focus on: What happened, when, what systems/users were involved, what techniques were used.
Be factual - only state what the evidence shows.

{summary_context}

Write the attack narrative:"""
                    
                    response = requests.post(
                        f"{host}/api/generate",
                        json={
                            "model": "dfir-qwen:latest",
                            "prompt": prompt,
                            "stream": False,
                            "options": {"temperature": 0.3, "num_predict": 500}
                        },
                        timeout=60
                    )
                    
                    if response.status_code == 200:
                        attack_narrative = response.json().get('response', '').strip()
                        logger.info(f"[AI_TRIAGE] Generated attack narrative ({len(attack_narrative)} chars)")
                    
                except Exception as e:
                    logger.warning(f"[AI_TRIAGE] LLM summary generation failed: {e}")
                    attack_narrative = ""
            
            # =========================================================
            # COMPLETE
            # =========================================================
            search.status = 'completed'
            search.completed_at = datetime.utcnow()
            search.generation_time_seconds = (datetime.utcnow() - start_time).total_seconds()
            
            # Build summary (v1.44.0: includes patterns and narrative)
            search.summary_json = json.dumps({
                'entry_point': search.entry_point,
                'iocs_extracted': search.iocs_extracted_count,
                'iocs_discovered': search.iocs_discovered_count,
                'events_analyzed': search.events_analyzed_count,
                'timeline_events': search.timeline_events_count,
                'auto_tagged': search.auto_tagged_count,
                'techniques_found': search.techniques_found_count,
                'process_trees': search.process_trees_count,
                'generation_time': search.generation_time_seconds,
                'patterns_detected': patterns_detected,
                'hunt_passes': hunt_pass if 'hunt_pass' in dir() else 1,
                'attack_narrative': attack_narrative
            })
            
            db.session.commit()
            
            tag_msg = f'{tags_added} new' if tags_added else f'{already_tagged} already tagged'
            pattern_msg = f", patterns: {', '.join(patterns_detected)}" if patterns_detected else ""
            update_progress(8, 'Complete', 
                f'AI Triage V2 complete! {tag_msg}, {len(techniques_found)} MITRE techniques{pattern_msg}', 100)
            
            logger.info(f"[AI_TRIAGE] Case {search.case_id}: Complete - {tags_added} new tags, "
                       f"{len(techniques_found)} techniques, patterns: {patterns_detected}")
            
            return {
                'status': 'success',
                'search_id': search.id,
                'auto_tagged': tags_added,
                'techniques_found': len(techniques_found),
                'timeline_events': len(timeline_events),
                'patterns_detected': patterns_detected,
                'hunt_passes': hunt_pass if 'hunt_pass' in dir() else 1
            }
            
        except Exception as e:
            logger.error(f"[AI_TRIAGE] Error: {e}", exc_info=True)
            search.status = 'failed'
            search.error_message = str(e)
            db.session.commit()
            return {'status': 'error', 'message': str(e)}
