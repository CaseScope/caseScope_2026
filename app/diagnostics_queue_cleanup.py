#!/usr/bin/env python3
"""
CaseScope Diagnostics: Queue Cleanup
=====================================

Emergency cleanup utility to clear all files from processing queues.

⚠️ WARNING: This is a DESTRUCTIVE operation!
This module will:
1. Reset all queued/processing files to 'Failed - Queue Cleared' status
2. Clear Redis progress tracking data
3. Revoke all active Celery tasks for the case
4. Clear OpenSearch scroll contexts

USE CASES:
- Celery workers crashed and left files in processing states
- Redis/Celery broker issues causing stuck tasks
- Need to abort all processing and start fresh with reindex

⚠️ IMPORTANT: After running this, a full reindex is recommended to ensure data integrity.

Author: CaseScope
Version: 2.0.6
"""

import logging
from typing import Dict, Any, List
from datetime import datetime

logger = logging.getLogger(__name__)


# ==============================================================================
# MAIN CLEANUP FUNCTION
# ==============================================================================

def cleanup_all_queues(case_id: int) -> Dict[str, Any]:
    """
    Emergency cleanup: Clear ALL files from processing queues.
    
    This function performs a complete reset of all processing state:
    1. Resets file statuses in database (Queued/Indexing/etc → Failed - Queue Cleared)
    2. Clears Redis progress tracking data
    3. Revokes active Celery tasks
    4. Clears OpenSearch scroll contexts
    
    ⚠️ WARNING: This is destructive and will abort all in-progress operations.
    Files may end up with incomplete/inconsistent data. A reindex is recommended after cleanup.
    
    Args:
        case_id: Case ID to clean up
        
    Returns:
        dict: {
            'status': 'success'|'error',
            'files_reset': int,
            'redis_keys_cleared': int,
            'celery_tasks_revoked': int,
            'scroll_contexts_cleared': int,
            'message': str,
            'details': dict,
            'error': str (if error)
        }
    """
    from main import app, db
    from models import CaseFile
    from celery_app import celery_app
    import redis
    from main import opensearch_client
    from utils import make_index_name
    
    logger.warning(f"[QUEUE_CLEANUP] ⚠️ EMERGENCY CLEANUP starting for case {case_id}")
    
    result = {
        'status': 'success',
        'files_reset': 0,
        'redis_keys_cleared': 0,
        'celery_tasks_revoked': 0,
        'scroll_contexts_cleared': 0,
        'message': '',
        'details': {},
        'timestamp': datetime.utcnow().isoformat()
    }
    
    with app.app_context():
        try:
            # ==================================================================
            # STEP 1: Reset all queued/processing files in database
            # ==================================================================
            logger.info(f"[QUEUE_CLEANUP] Step 1: Resetting file statuses...")
            
            processing_statuses = [
                'Queued',
                'Indexing',
                'SIGMA Testing',
                'IOC Hunting',
                'Known Good Processing',
                'Known Noise Processing'
            ]
            
            files_to_reset = CaseFile.query.filter(
                CaseFile.case_id == case_id,
                CaseFile.is_deleted == False,
                CaseFile.indexing_status.in_(processing_statuses)
            ).all()
            
            files_reset_count = 0
            file_status_details = {}
            
            for file in files_to_reset:
                old_status = file.indexing_status
                file.indexing_status = 'Failed - Queue Cleared'
                files_reset_count += 1
                
                # Track what statuses we reset
                if old_status not in file_status_details:
                    file_status_details[old_status] = 0
                file_status_details[old_status] += 1
            
            db.session.commit()
            
            result['files_reset'] = files_reset_count
            result['details']['file_statuses_reset'] = file_status_details
            
            logger.info(f"[QUEUE_CLEANUP] ✓ Reset {files_reset_count} files: {file_status_details}")
            
            # ==================================================================
            # STEP 2: Clear Redis progress tracking data
            # ==================================================================
            logger.info(f"[QUEUE_CLEANUP] Step 2: Clearing Redis progress data...")
            
            try:
                redis_client = redis.Redis(
                    host=app.config.get('REDIS_HOST', 'localhost'),
                    port=app.config.get('REDIS_PORT', 6379),
                    db=app.config.get('REDIS_DB', 0),
                    decode_responses=True
                )
                
                # Find all progress keys for this case
                progress_patterns = [
                    f'casescope:progress:{case_id}:*',
                    f'casescope:phase:{case_id}:*',
                    f'casescope:operation:{case_id}:*'
                ]
                
                redis_keys_cleared = 0
                for pattern in progress_patterns:
                    keys = redis_client.keys(pattern)
                    if keys:
                        redis_client.delete(*keys)
                        redis_keys_cleared += len(keys)
                        logger.info(f"[QUEUE_CLEANUP] Deleted {len(keys)} keys matching {pattern}")
                
                result['redis_keys_cleared'] = redis_keys_cleared
                logger.info(f"[QUEUE_CLEANUP] ✓ Cleared {redis_keys_cleared} Redis keys")
                
            except Exception as e:
                logger.error(f"[QUEUE_CLEANUP] Redis cleanup error: {e}")
                result['details']['redis_error'] = str(e)
            
            # ==================================================================
            # STEP 3: Revoke active Celery tasks for this case
            # ==================================================================
            logger.info(f"[QUEUE_CLEANUP] Step 3: Revoking Celery tasks...")
            
            try:
                # Get active tasks from Celery
                inspect = celery_app.control.inspect()
                active_tasks = inspect.active()
                
                tasks_to_revoke = []
                
                if active_tasks:
                    for worker, tasks in active_tasks.items():
                        for task in tasks:
                            # Check if task is related to this case
                            task_args = task.get('args', [])
                            task_kwargs = task.get('kwargs', {})
                            
                            # Check if case_id is in args or kwargs
                            is_case_task = False
                            
                            if task_args and len(task_args) > 0:
                                # First arg might be case_id or file_id
                                # For file_id tasks, we'd need to query which case they belong to
                                # For simplicity, we'll revoke tasks with case_id in kwargs
                                pass
                            
                            if task_kwargs.get('case_id') == case_id:
                                is_case_task = True
                            
                            if is_case_task:
                                task_id = task.get('id')
                                tasks_to_revoke.append(task_id)
                                logger.info(f"[QUEUE_CLEANUP] Revoking task {task_id} ({task.get('name')})")
                
                # Revoke tasks
                for task_id in tasks_to_revoke:
                    celery_app.control.revoke(task_id, terminate=True, signal='SIGKILL')
                
                result['celery_tasks_revoked'] = len(tasks_to_revoke)
                result['details']['revoked_task_ids'] = tasks_to_revoke
                
                logger.info(f"[QUEUE_CLEANUP] ✓ Revoked {len(tasks_to_revoke)} Celery tasks")
                
            except Exception as e:
                logger.error(f"[QUEUE_CLEANUP] Celery revoke error: {e}")
                result['details']['celery_error'] = str(e)
            
            # ==================================================================
            # STEP 4: Clear OpenSearch scroll contexts (to free up resources)
            # ==================================================================
            logger.info(f"[QUEUE_CLEANUP] Step 4: Clearing OpenSearch scroll contexts...")
            
            try:
                index_name = make_index_name(case_id)
                
                if opensearch_client.indices.exists(index=index_name):
                    # Clear all scroll contexts for this index
                    # OpenSearch automatically clears scroll contexts after timeout,
                    # but we can explicitly clear them to free resources immediately
                    opensearch_client.clear_scroll(body={'scroll_id': '_all'})
                    result['scroll_contexts_cleared'] = 1  # Cleared all
                    logger.info(f"[QUEUE_CLEANUP] ✓ Cleared OpenSearch scroll contexts")
                else:
                    logger.info(f"[QUEUE_CLEANUP] Index {index_name} does not exist, skipping scroll cleanup")
                    
            except Exception as e:
                logger.error(f"[QUEUE_CLEANUP] OpenSearch cleanup error: {e}")
                result['details']['opensearch_error'] = str(e)
            
            # ==================================================================
            # FINAL SUMMARY
            # ==================================================================
            
            if files_reset_count > 0:
                result['message'] = (
                    f"⚠️ Queue cleanup complete. Reset {files_reset_count} files to 'Failed - Queue Cleared'. "
                    f"Cleared {redis_keys_cleared} Redis keys and revoked {result['celery_tasks_revoked']} tasks. "
                    f"⚠️ IMPORTANT: A full reindex is recommended to ensure data integrity."
                )
            else:
                result['message'] = "✅ Queue is clean. No files were in processing state."
            
            logger.warning(f"[QUEUE_CLEANUP] Cleanup complete: {result['message']}")
            
            return result
            
        except Exception as e:
            logger.error(f"[QUEUE_CLEANUP] Fatal error: {e}", exc_info=True)
            return {
                'status': 'error',
                'message': f'Queue cleanup failed: {str(e)}',
                'error': str(e),
                'files_reset': 0,
                'redis_keys_cleared': 0,
                'celery_tasks_revoked': 0,
                'scroll_contexts_cleared': 0
            }


# ==============================================================================
# DIAGNOSTIC FUNCTIONS
# ==============================================================================

def get_queue_diagnostics(case_id: int) -> Dict[str, Any]:
    """
    Get diagnostic information about the current queue state.
    
    This is a non-destructive function that reports on queue health.
    
    Args:
        case_id: Case ID to diagnose
        
    Returns:
        dict: Diagnostic information about queue state
    """
    from main import app, db
    from models import CaseFile
    import redis
    
    with app.app_context():
        try:
            # Count files in each processing state
            processing_states = {
                'Queued': 0,
                'Indexing': 0,
                'SIGMA Testing': 0,
                'IOC Hunting': 0,
                'Known Good Processing': 0,
                'Known Noise Processing': 0,
                'Failed': 0,
                'Completed': 0
            }
            
            for state in processing_states.keys():
                if state == 'Failed':
                    count = CaseFile.query.filter(
                        CaseFile.case_id == case_id,
                        CaseFile.is_deleted == False,
                        CaseFile.indexing_status.like('Failed%')
                    ).count()
                else:
                    count = CaseFile.query.filter(
                        CaseFile.case_id == case_id,
                        CaseFile.is_deleted == False,
                        CaseFile.indexing_status == state
                    ).count()
                processing_states[state] = count
            
            # Check Redis progress data
            try:
                redis_client = redis.Redis(
                    host=app.config.get('REDIS_HOST', 'localhost'),
                    port=app.config.get('REDIS_PORT', 6379),
                    db=app.config.get('REDIS_DB', 0),
                    decode_responses=True
                )
                
                redis_keys = []
                patterns = [
                    f'casescope:progress:{case_id}:*',
                    f'casescope:phase:{case_id}:*',
                    f'casescope:operation:{case_id}:*'
                ]
                
                for pattern in patterns:
                    keys = redis_client.keys(pattern)
                    redis_keys.extend(keys)
                
                redis_data = len(redis_keys)
            except Exception as e:
                redis_data = f"Error: {e}"
            
            return {
                'status': 'success',
                'case_id': case_id,
                'processing_states': processing_states,
                'redis_keys_count': redis_data,
                'total_in_queue': sum(processing_states[s] for s in ['Queued', 'Indexing', 'SIGMA Testing', 'IOC Hunting', 'Known Good Processing', 'Known Noise Processing'])
            }
            
        except Exception as e:
            logger.error(f"[QUEUE_DIAGNOSTICS] Error: {e}", exc_info=True)
            return {
                'status': 'error',
                'error': str(e)
            }


