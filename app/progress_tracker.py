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
                 status: str, message: str = "", stats: Optional[Dict] = None) -> None:
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
                'end_time': None
            }
            progress['phases'].append(phase_entry)
        else:
            phase_entry['status'] = status
            phase_entry['message'] = message
            if stats:
                phase_entry['stats'].update(stats)
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

