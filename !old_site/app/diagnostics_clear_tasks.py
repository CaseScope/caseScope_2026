#!/usr/bin/env python3
"""
CaseScope Diagnostics Module: Clear Stale Tasks
================================================

This module clears orphaned/stale Celery task metadata from Redis.
This is useful when workers crash or are restarted mid-task, leaving
behind corrupted task state that can cause task dispatch issues.

Author: CaseScope
Version: 2.2.2
"""

import logging
import redis
from typing import Dict, Any

logger = logging.getLogger(__name__)


def clear_stale_tasks() -> Dict[str, Any]:
    """
    Clear all stale Celery task metadata and broker state from Redis.
    
    This function:
    1. Clears all celery-task-meta-* keys (task results)
    2. Clears unacked* keys (unacknowledged tasks)
    3. Clears _kombu* keys (Kombu broker state)
    
    Returns:
        dict: {
            'success': bool,
            'task_metadata_cleared': int,
            'unacked_cleared': int,
            'kombu_cleared': int,
            'total_cleared': int,
            'message': str
        }
    """
    try:
        # Connect to Redis (same config as Celery)
        r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=False)
        
        # Test connection
        r.ping()
        logger.info("[CLEAR_TASKS] Connected to Redis")
        
        # Clear celery-task-meta-* (task metadata/results)
        task_meta_keys = list(r.scan_iter(match='celery-task-meta-*', count=500))
        task_meta_count = 0
        if task_meta_keys:
            # Delete in batches of 100
            for i in range(0, len(task_meta_keys), 100):
                batch = task_meta_keys[i:i+100]
                task_meta_count += r.delete(*batch)
        
        logger.info(f"[CLEAR_TASKS] Cleared {task_meta_count} task metadata entries")
        
        # Clear unacked* (unacknowledged tasks)
        unacked_keys = list(r.scan_iter(match='unacked*', count=100))
        unacked_count = 0
        if unacked_keys:
            unacked_count = r.delete(*unacked_keys)
        
        logger.info(f"[CLEAR_TASKS] Cleared {unacked_count} unacked task entries")
        
        # Clear _kombu* (Kombu broker state)
        kombu_keys = list(r.scan_iter(match='_kombu*', count=100))
        kombu_count = 0
        if kombu_keys:
            kombu_count = r.delete(*kombu_keys)
        
        logger.info(f"[CLEAR_TASKS] Cleared {kombu_count} Kombu state entries")
        
        total = task_meta_count + unacked_count + kombu_count
        
        return {
            'success': True,
            'task_metadata_cleared': task_meta_count,
            'unacked_cleared': unacked_count,
            'kombu_cleared': kombu_count,
            'total_cleared': total,
            'message': f'Successfully cleared {total:,} stale task entries from Redis'
        }
        
    except redis.ConnectionError as e:
        logger.error(f"[CLEAR_TASKS] Redis connection error: {e}")
        return {
            'success': False,
            'error': f'Redis connection error: {e}',
            'message': 'Failed to connect to Redis'
        }
    except Exception as e:
        logger.error(f"[CLEAR_TASKS] Unexpected error: {e}", exc_info=True)
        return {
            'success': False,
            'error': str(e),
            'message': f'Failed to clear stale tasks: {e}'
        }

