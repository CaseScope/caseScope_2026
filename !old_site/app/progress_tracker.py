#!/usr/bin/env python3
"""
CaseScope Progress Tracker
===========================

Tracks progress of long-running operations (indexing, reindexing, SIGMA, IOC, etc.)

This module provides Redis-backed progress tracking that works across multiple
Gunicorn workers.

Author: CaseScope
Version: 2.0.1 - Redis-backed for multi-worker support
"""

import logging
import time
import json
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

# Redis connection
try:
    import redis
    redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
except Exception as e:
    logger.error(f"Failed to connect to Redis: {e}")
    redis_client = None


# ==============================================================================
# PROGRESS TRACKING
# ==============================================================================

def _get_redis_key(case_id: int, operation: str) -> str:
    """Generate Redis key for progress data"""
    return f"casescope:progress:{case_id}:{operation}"


def start_progress(case_id: int, operation: str, total_phases: int, description: str = "") -> None:
    """
    Start tracking progress for an operation.
    
    Args:
        case_id: Case ID
        operation: Operation type ('index', 'reindex', 'resigma', 'reioc')
        total_phases: Total number of phases in this operation
        description: Optional description of the operation
    """
    if not redis_client:
        logger.warning("[PROGRESS] Redis not available, progress tracking disabled")
        return
    
    key = _get_redis_key(case_id, operation)
    
    # CRITICAL: Clear any stale progress data from previous runs
    try:
        redis_client.delete(key)
        logger.debug(f"[PROGRESS] Cleared stale progress data: case={case_id}, operation={operation}")
    except Exception as e:
        logger.warning(f"[PROGRESS] Failed to clear stale progress: {e}")
    
    progress_data = {
        'status': 'running',
        'current_phase': 0,
        'total_phases': total_phases,
        'description': description,
        'phases': [],
        'start_time': time.time(),
        'last_update': time.time(),
        'error_message': None
    }
    
    try:
        redis_client.setex(key, 3600, json.dumps(progress_data))  # 1 hour TTL
        logger.info(f"[PROGRESS] Started tracking: case={case_id}, operation={operation}, phases={total_phases}")
    except Exception as e:
        logger.error(f"[PROGRESS] Failed to store progress: {e}")


def update_phase(case_id: int, operation: str, phase_num: int, phase_name: str, 
                 status: str, message: str = "", stats: Optional[Dict] = None,
                 current: Optional[int] = None, total: Optional[int] = None) -> None:
    """
    Update progress for a specific phase.
    
    Args:
        case_id: Case ID
        operation: Operation type
        phase_num: Phase number (1-based)
        phase_name: Name of the phase ('Clearing Metadata', 'Indexing Files', etc.)
        status: Phase status ('running', 'completed', 'failed', 'skipped')
        message: Optional status message
        stats: Optional phase statistics dict
        current: Optional current item count (for progress bar)
        total: Optional total item count (for progress bar)
    """
    if not redis_client:
        return
    
    key = _get_redis_key(case_id, operation)
    
    try:
        # Get existing progress
        data = redis_client.get(key)
        if not data:
            logger.warning(f"[PROGRESS] No progress found for case={case_id}, operation={operation}")
            return
        
        progress = json.loads(data)
        progress['current_phase'] = phase_num
        progress['last_update'] = time.time()
        
        # Find or create phase entry
        phase_entry = None
        for p in progress['phases']:
            if p['phase_num'] == phase_num:
                phase_entry = p
                break
        
        if phase_entry is None:
            phase_entry = {
                'phase_num': phase_num,
                'name': phase_name,
                'status': status,
                'message': message,
                'stats': stats or {},
                'start_time': time.time(),
                'end_time': None,
                'current': current,
                'total': total
            }
            progress['phases'].append(phase_entry)
        else:
            phase_entry['status'] = status
            phase_entry['message'] = message
            if stats:
                phase_entry['stats'].update(stats)
            if current is not None:
                phase_entry['current'] = current
            if total is not None:
                phase_entry['total'] = total
            if status in ['completed', 'failed', 'skipped']:
                phase_entry['end_time'] = time.time()
        
        # Save back to Redis
        redis_client.setex(key, 3600, json.dumps(progress))
        logger.debug(f"[PROGRESS] Updated phase: case={case_id}, operation={operation}, phase={phase_num} ({phase_name}): {status}")
        
    except Exception as e:
        logger.error(f"[PROGRESS] Failed to update phase: {e}")


def complete_progress(case_id: int, operation: str, success: bool = True, error_message: str = None) -> None:
    """
    Mark operation as completed.
    
    Args:
        case_id: Case ID
        operation: Operation type
        success: Whether operation succeeded
        error_message: Optional error message if failed
    """
    if not redis_client:
        return
    
    key = _get_redis_key(case_id, operation)
    
    try:
        data = redis_client.get(key)
        if not data:
            return
        
        progress = json.loads(data)
        progress['status'] = 'completed' if success else 'failed'
        progress['last_update'] = time.time()
        progress['error_message'] = error_message
        
        # Save with shorter TTL (10 minutes after completion)
        redis_client.setex(key, 600, json.dumps(progress))
        logger.info(f"[PROGRESS] Completed: case={case_id}, operation={operation}, success={success}")
        
    except Exception as e:
        logger.error(f"[PROGRESS] Failed to complete progress: {e}")


def clear_progress(case_id: int, operation: str) -> None:
    """
    Explicitly clear progress data for an operation.
    
    Useful for:
    - Clearing stale progress before starting new operation
    - Manual cleanup after operation completes
    - Resetting after errors or cancellations
    
    Args:
        case_id: Case ID
        operation: Operation type
    """
    if not redis_client:
        return
    
    key = _get_redis_key(case_id, operation)
    
    try:
        redis_client.delete(key)
        logger.info(f"[PROGRESS] Cleared progress: case={case_id}, operation={operation}")
    except Exception as e:
        logger.error(f"[PROGRESS] Failed to clear progress: {e}")


def get_progress(case_id: int, operation: str) -> Optional[Dict[str, Any]]:
    """
    Get current progress for an operation.
    
    Args:
        case_id: Case ID
        operation: Operation type
        
    Returns:
        Progress dict or None if not found
    """
    if not redis_client:
        return None
    
    key = _get_redis_key(case_id, operation)
    
    try:
        data = redis_client.get(key)
        if not data:
            return None
        
        progress = json.loads(data)
        progress['elapsed_time'] = time.time() - progress['start_time']
        return progress
        
    except Exception as e:
        logger.error(f"[PROGRESS] Failed to get progress: {e}")
        return None


def clear_progress(case_id: int, operation: str) -> None:
    """
    Clear progress tracking for an operation.
    
    Args:
        case_id: Case ID
        operation: Operation type
    """
    if not redis_client:
        return
    
    key = _get_redis_key(case_id, operation)
    
    try:
        redis_client.delete(key)
        logger.info(f"[PROGRESS] Cleared: case={case_id}, operation={operation}")
    except Exception as e:
        logger.error(f"[PROGRESS] Failed to clear progress: {e}")


def clear_old_progress(max_age_seconds: int = 3600) -> int:
    """
    Clear progress entries older than max_age_seconds.
    
    Args:
        max_age_seconds: Maximum age in seconds (default 1 hour)
        
    Returns:
        Number of entries cleared
    """
    if not redis_client:
        return 0
    
    cleared = 0
    
    try:
        # Find all progress keys
        keys = redis_client.keys("casescope:progress:*")
        current_time = time.time()
        
        for key in keys:
            data = redis_client.get(key)
            if data:
                progress = json.loads(data)
                if current_time - progress['last_update'] > max_age_seconds:
                    redis_client.delete(key)
                    cleared += 1
        
        if cleared > 0:
            logger.info(f"[PROGRESS] Cleared {cleared} old progress entries")
            
    except Exception as e:
        logger.error(f"[PROGRESS] Failed to clear old progress: {e}")
    
    return cleared


# ==============================================================================
# ATOMIC COUNTER FUNCTIONS (v2.2.0)
# ==============================================================================

def _get_counter_key(case_id: int, operation: str, phase_num: int, counter_name: str) -> str:
    """Generate Redis key for atomic counter"""
    return f"casescope:counter:{case_id}:{operation}:phase{phase_num}:{counter_name}"


def init_phase_counters(case_id: int, operation: str, phase_num: int, total: int) -> None:
    """
    Initialize counters for a phase.
    
    Args:
        case_id: Case ID
        operation: Operation type
        phase_num: Phase number
        total: Total items to process
    """
    if not redis_client:
        return
    
    try:
        # Set total counter
        total_key = _get_counter_key(case_id, operation, phase_num, 'total')
        redis_client.setex(total_key, 7200, total)  # 2 hour TTL
        
        # Initialize completed counter to 0
        completed_key = _get_counter_key(case_id, operation, phase_num, 'completed')
        redis_client.setex(completed_key, 7200, 0)
        
        # Initialize failed counter to 0
        failed_key = _get_counter_key(case_id, operation, phase_num, 'failed')
        redis_client.setex(failed_key, 7200, 0)
        
        logger.info(f"[PROGRESS] Initialized counters: case={case_id}, operation={operation}, phase={phase_num}, total={total}")
    except Exception as e:
        logger.error(f"[PROGRESS] Failed to init counters: {e}")


def increment_counter(case_id: int, operation: str, phase_num: int, counter_name: str, amount: int = 1) -> int:
    """
    Atomically increment a phase counter.
    
    Args:
        case_id: Case ID
        operation: Operation type
        phase_num: Phase number
        counter_name: Counter name ('completed', 'failed', 'skipped')
        amount: Amount to increment (default 1)
        
    Returns:
        New counter value after increment
    """
    if not redis_client:
        return 0
    
    try:
        key = _get_counter_key(case_id, operation, phase_num, counter_name)
        new_value = redis_client.incrby(key, amount)
        redis_client.expire(key, 7200)  # Refresh TTL
        return new_value
    except Exception as e:
        logger.error(f"[PROGRESS] Failed to increment counter: {e}")
        return 0


def get_counter(case_id: int, operation: str, phase_num: int, counter_name: str) -> int:
    """
    Get current value of a phase counter.
    
    Args:
        case_id: Case ID
        operation: Operation type
        phase_num: Phase number
        counter_name: Counter name ('total', 'completed', 'failed', 'skipped')
        
    Returns:
        Current counter value
    """
    if not redis_client:
        return 0
    
    try:
        key = _get_counter_key(case_id, operation, phase_num, counter_name)
        value = redis_client.get(key)
        return int(value) if value else 0
    except Exception as e:
        logger.error(f"[PROGRESS] Failed to get counter: {e}")
        return 0


def get_phase_progress(case_id: int, operation: str, phase_num: int) -> Dict[str, int]:
    """
    Get all counters for a phase.
    
    Returns:
        dict: {
            'total': int,
            'completed': int,
            'failed': int,
            'skipped': int
        }
    """
    return {
        'total': get_counter(case_id, operation, phase_num, 'total'),
        'completed': get_counter(case_id, operation, phase_num, 'completed'),
        'failed': get_counter(case_id, operation, phase_num, 'failed'),
        'skipped': get_counter(case_id, operation, phase_num, 'skipped')
    }


def clear_phase_counters(case_id: int, operation: str, phase_num: int) -> None:
    """Clear all counters for a specific phase"""
    if not redis_client:
        return
    
    try:
        pattern = f"casescope:counter:{case_id}:{operation}:phase{phase_num}:*"
        keys = redis_client.keys(pattern)
        if keys:
            redis_client.delete(*keys)
            logger.info(f"[PROGRESS] Cleared {len(keys)} counters for phase {phase_num}")
    except Exception as e:
        logger.error(f"[PROGRESS] Failed to clear counters: {e}")


# ==============================================================================
# HELPER: Format Progress for Display
# ==============================================================================

def format_progress_message(progress: Dict[str, Any]) -> str:
    """
    Format progress data into a human-readable message.
    
    Args:
        progress: Progress dict from get_progress()
        
    Returns:
        Formatted status message
    """
    if not progress:
        return "No progress information available"
    
    status = progress['status']
    current_phase = progress['current_phase']
    total_phases = progress['total_phases']
    
    if status == 'completed':
        elapsed = int(progress['elapsed_time'])
        return f"✅ Completed in {elapsed}s"
    elif status == 'failed':
        return f"❌ Failed: {progress.get('error_message', 'Unknown error')}"
    elif status == 'running':
        return f"⏳ Phase {current_phase}/{total_phases} running..."
    else:
        return f"Status: {status}"

