"""
Celery Health Check Module
Checks if Celery workers are running and healthy before queuing tasks
"""

import logging
from celery_app import celery_app

logger = logging.getLogger(__name__)


def check_workers_available(min_workers=1):
    """
    Check if Celery workers are available and ready
    
    Args:
        min_workers: Minimum number of workers required
    
    Returns:
        tuple: (is_healthy: bool, worker_count: int, error_message: str)
    """
    try:
        # Get worker stats
        inspect = celery_app.control.inspect()
        
        # Check active workers
        stats = inspect.stats()
        
        if not stats:
            error = "No Celery workers are running"
            logger.warning(f"[CELERY HEALTH] {error}")
            return False, 0, error
        
        worker_count = len(stats)
        
        if worker_count < min_workers:
            error = f"Only {worker_count} worker(s) running (minimum {min_workers} required)"
            logger.warning(f"[CELERY HEALTH] {error}")
            return False, worker_count, error
        
        logger.info(f"[CELERY HEALTH] ✓ {worker_count} worker(s) available")
        return True, worker_count, None
    
    except Exception as e:
        error = f"Could not check worker status: {str(e)}"
        logger.error(f"[CELERY HEALTH] {error}")
        return False, 0, error


def get_worker_stats():
    """
    Get detailed worker statistics
    
    Returns:
        dict: Worker statistics or None if unavailable
    """
    try:
        inspect = celery_app.control.inspect()
        
        return {
            'stats': inspect.stats(),
            'active_queues': inspect.active_queues(),
            'active_tasks': inspect.active(),
            'reserved_tasks': inspect.reserved(),
            'registered_tasks': inspect.registered()
        }
    except Exception as e:
        logger.error(f"[CELERY HEALTH] Could not get worker stats: {e}")
        return None


def get_queue_length():
    """
    Get approximate queue length (reserved + active tasks)
    
    Returns:
        int: Approximate queue length or -1 if unavailable
    """
    try:
        inspect = celery_app.control.inspect()
        
        active = inspect.active() or {}
        reserved = inspect.reserved() or {}
        
        # Count total tasks across all workers
        active_count = sum(len(tasks) for tasks in active.values())
        reserved_count = sum(len(tasks) for tasks in reserved.values())
        
        total = active_count + reserved_count
        
        logger.debug(f"[CELERY HEALTH] Queue length: {total} (active={active_count}, reserved={reserved_count})")
        return total
    
    except Exception as e:
        logger.error(f"[CELERY HEALTH] Could not get queue length: {e}")
        return -1

