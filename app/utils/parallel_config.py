"""
Parallel Processing Configuration Helper
Calculates optimal number of parallel slices for task internal parallelism
"""

import logging

logger = logging.getLogger(__name__)


def get_parallel_slice_count():
    """
    Calculate number of parallel slices for task internal parallelism
    based on system configuration.
    
    Uses CELERY_WORKERS * TASK_PARALLEL_PERCENTAGE to determine how many
    parallel threads/slices each long-running task should use internally.
    
    Returns:
        int: Number of slices to use (respects min/max bounds)
        
    Example:
        CELERY_WORKERS = 12
        TASK_PARALLEL_PERCENTAGE = 50
        Result: 6 slices (50% of 12 workers)
    """
    try:
        from config import (
            CELERY_WORKERS,
            TASK_PARALLEL_PERCENTAGE,
            TASK_PARALLEL_MIN,
            TASK_PARALLEL_MAX
        )
        
        # Calculate based on percentage
        calculated = int(CELERY_WORKERS * (TASK_PARALLEL_PERCENTAGE / 100))
        
        # Apply min/max bounds
        slices = max(TASK_PARALLEL_MIN, min(TASK_PARALLEL_MAX, calculated))
        
        logger.debug(
            f"Parallel slices: {slices} "
            f"(calculated={calculated}, workers={CELERY_WORKERS}, "
            f"percentage={TASK_PARALLEL_PERCENTAGE}%)"
        )
        
        return slices
        
    except Exception as e:
        logger.warning(f"Failed to calculate parallel slices, using default: {e}")
        return 4  # Safe default


def get_parallel_config_info():
    """
    Get parallel processing configuration information for display in UI.
    
    Returns:
        dict: Configuration details
    """
    try:
        from config import (
            CELERY_WORKERS,
            TASK_PARALLEL_PERCENTAGE,
            TASK_PARALLEL_MIN,
            TASK_PARALLEL_MAX
        )
        
        slices = get_parallel_slice_count()
        concurrent_tasks = max(1, CELERY_WORKERS // slices) if slices > 0 else 1
        
        return {
            'celery_workers': CELERY_WORKERS,
            'parallel_percentage': TASK_PARALLEL_PERCENTAGE,
            'parallel_slices': slices,
            'parallel_min': TASK_PARALLEL_MIN,
            'parallel_max': TASK_PARALLEL_MAX,
            'concurrent_tasks_estimate': concurrent_tasks,
            'speedup_estimate': f"~{slices}x"
        }
        
    except Exception as e:
        logger.error(f"Failed to get parallel config info: {e}")
        return {
            'celery_workers': 4,
            'parallel_percentage': 50,
            'parallel_slices': 2,
            'parallel_min': 2,
            'parallel_max': 8,
            'concurrent_tasks_estimate': 2,
            'speedup_estimate': '~2x'
        }

