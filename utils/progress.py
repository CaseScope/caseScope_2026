"""Progress Tracking Utility for CaseScope

Uses Redis hashes for atomic progress tracking per case.
Tracks file processing and post-processing phases (known systems/users discovery).

All increments use HINCRBY for atomicity - no race conditions.
Thread-safe Redis client initialization.
"""
import logging
import threading
import redis
from typing import Optional, Dict, Any
from config import Config

logger = logging.getLogger(__name__)

# Redis connection with thread-safe initialization
_redis_client = None
_redis_lock = threading.Lock()


def get_redis_client() -> redis.Redis:
    """Get or create Redis client (thread-safe)"""
    global _redis_client
    if _redis_client is None:
        with _redis_lock:
            # Double-check after acquiring lock
            if _redis_client is None:
                _redis_client = redis.Redis(
                    host=Config.REDIS_HOST,
                    port=Config.REDIS_PORT,
                    db=Config.REDIS_DB,
                    decode_responses=True
                )
    return _redis_client


def _get_progress_key(case_uuid: str) -> str:
    """Get Redis key for case progress"""
    return f"processing_progress:{case_uuid}"


def init_progress(case_uuid: str, total_files: int) -> None:
    """Initialize progress tracking for a new batch of files.
    
    Called when files are queued for processing.
    If processing is already in progress, adds to existing total instead of
    resetting (prevents race condition when multiple users upload simultaneously).
    
    Args:
        case_uuid: Case UUID
        total_files: Total number of files in this batch
    """
    try:
        client = get_redis_client()
        key = _get_progress_key(case_uuid)
        
        # Check if already processing - add to existing instead of resetting
        existing_status = client.hget(key, 'status')
        if existing_status == 'processing':
            # Add to existing batch instead of replacing
            new_total = client.hincrby(key, 'files_total', total_files)
            logger.info(f"Added {total_files} files to existing progress for case {case_uuid}, new total: {new_total}")
            return
        
        # Delete existing key first to reset all fields
        client.delete(key)
        
        # Set all fields using hash
        client.hset(key, mapping={
            'phase': 'files',
            'files_total': total_files,
            'files_completed': 0,
            'systems_total': 0,
            'systems_completed': 0,
            'users_total': 0,
            'users_completed': 0,
            'current_item': '',
            'status': 'processing'
        })
        
        # Set 24-hour expiry
        client.expire(key, 86400)
        
        # Clear any existing completion trigger
        trigger_key = f"completion_triggered:{case_uuid}"
        client.delete(trigger_key)
        
        logger.info(f"Initialized progress for case {case_uuid}: {total_files} files")
        
    except Exception as e:
        logger.warning(f"Failed to initialize progress: {e}")


def increment_progress(case_uuid: str) -> Optional[Dict[str, Any]]:
    """Atomically increment completed file count for a case.
    
    Uses HINCRBY for atomic increment - no race conditions.
    
    Args:
        case_uuid: Case UUID
        
    Returns:
        Updated progress dict or None if no progress exists
    """
    try:
        client = get_redis_client()
        key = _get_progress_key(case_uuid)
        
        # Check if key exists
        if not client.exists(key):
            return None
        
        # Atomic increment
        completed = client.hincrby(key, 'files_completed', 1)
        total = int(client.hget(key, 'files_total') or 0)
        
        # Check if files phase complete
        status = 'processing'
        if completed >= total:
            # Set status to complete so completion task can trigger
            client.hset(key, 'status', 'complete')
            status = 'complete'
            logger.info(f"All files complete for case {case_uuid}: {completed}/{total}")
        
        logger.debug(f"Progress for case {case_uuid}: {completed}/{total}")
        
        return {
            'completed': completed,
            'total': total,
            'status': status
        }
        
    except Exception as e:
        logger.warning(f"Failed to increment progress: {e}")
        return None


def get_progress(case_uuid: str) -> Optional[Dict[str, Any]]:
    """Get current progress for a case.
    
    Args:
        case_uuid: Case UUID
        
    Returns:
        Progress dict with all phase data or None if no active progress
    """
    try:
        client = get_redis_client()
        key = _get_progress_key(case_uuid)
        
        data = client.hgetall(key)
        if not data:
            return None
        
        # Convert to proper types
        return {
            'phase': data.get('phase', 'files'),
            'status': data.get('status', 'processing'),
            'current_item': data.get('current_item', ''),
            'files': {
                'total': int(data.get('files_total', 0)),
                'completed': int(data.get('files_completed', 0))
            },
            'systems': {
                'total': int(data.get('systems_total', 0)),
                'completed': int(data.get('systems_completed', 0))
            },
            'users': {
                'total': int(data.get('users_total', 0)),
                'completed': int(data.get('users_completed', 0))
            },
            # Legacy compatibility
            'total': int(data.get('files_total', 0)),
            'completed': int(data.get('files_completed', 0))
        }
        
    except Exception as e:
        logger.warning(f"Failed to get progress: {e}")
        return None


def clear_progress(case_uuid: str) -> None:
    """Clear progress tracking for a case.
    
    Called when progress display should be reset to idle.
    
    Args:
        case_uuid: Case UUID
    """
    try:
        client = get_redis_client()
        key = _get_progress_key(case_uuid)
        client.delete(key)
        logger.debug(f"Cleared progress for case {case_uuid}")
        
    except Exception as e:
        logger.warning(f"Failed to clear progress: {e}")


def add_to_progress(case_uuid: str, additional_files: int) -> Optional[Dict[str, Any]]:
    """Add more files to existing progress (for additional uploads during processing).
    
    Args:
        case_uuid: Case UUID
        additional_files: Number of new files to add
        
    Returns:
        Updated progress dict or None
    """
    try:
        client = get_redis_client()
        key = _get_progress_key(case_uuid)
        
        if not client.exists(key):
            # No existing progress, initialize new
            init_progress(case_uuid, additional_files)
            return get_progress(case_uuid)
        
        # Atomic increment of total
        new_total = client.hincrby(key, 'files_total', additional_files)
        client.hset(key, 'status', 'processing')
        
        logger.info(f"Added {additional_files} files to progress for case {case_uuid}, new total: {new_total}")
        
        return get_progress(case_uuid)
        
    except Exception as e:
        logger.warning(f"Failed to add to progress: {e}")
        return None


def set_phase(case_uuid: str, phase: str, total: int = 0, current_item: str = '') -> None:
    """Set the current processing phase.
    
    Args:
        case_uuid: Case UUID
        phase: Phase name ('files', 'buffer_flush', 'systems', 'users', 'complete')
        total: Total items for this phase (for systems/users phases)
        current_item: Current item being processed (optional)
    """
    try:
        client = get_redis_client()
        key = _get_progress_key(case_uuid)
        
        updates = {
            'phase': phase,
            'current_item': current_item
        }
        
        if phase == 'systems':
            updates['systems_total'] = total
            updates['systems_completed'] = 0
            updates['status'] = 'discovering_systems'
        elif phase == 'users':
            updates['users_total'] = total
            updates['users_completed'] = 0
            updates['status'] = 'discovering_users'
        elif phase == 'buffer_flush':
            updates['status'] = 'flushing_buffer'
        elif phase == 'complete':
            updates['status'] = 'complete'
        
        client.hset(key, mapping=updates)
        logger.debug(f"Set phase for case {case_uuid}: {phase}")
        
    except Exception as e:
        logger.warning(f"Failed to set phase: {e}")


def increment_phase(case_uuid: str, phase: str, current_item: str = '') -> Optional[int]:
    """Atomically increment the counter for the current phase.
    
    Args:
        case_uuid: Case UUID
        phase: Phase name ('systems' or 'users')
        current_item: Current item being processed (optional)
        
    Returns:
        New completed count or None on error
    """
    try:
        client = get_redis_client()
        key = _get_progress_key(case_uuid)
        
        if phase == 'systems':
            completed = client.hincrby(key, 'systems_completed', 1)
        elif phase == 'users':
            completed = client.hincrby(key, 'users_completed', 1)
        else:
            return None
        
        if current_item:
            client.hset(key, 'current_item', current_item)
        
        return completed
        
    except Exception as e:
        logger.warning(f"Failed to increment phase: {e}")
        return None


def set_current_item(case_uuid: str, item: str) -> None:
    """Set the current item being processed (for display).
    
    Args:
        case_uuid: Case UUID
        item: Item name/description
    """
    try:
        client = get_redis_client()
        key = _get_progress_key(case_uuid)
        client.hset(key, 'current_item', item)
    except Exception as e:
        logger.warning(f"Failed to set current item: {e}")


# Legacy compatibility functions

def set_completion_phase(case_uuid: str, phase: str) -> None:
    """Legacy function - maps old phase names to new system.
    
    Args:
        case_uuid: Case UUID
        phase: Old phase name
    """
    phase_mapping = {
        'flushing_buffer': 'buffer_flush',
        'discovering_systems': 'systems',
        'discovering_users': 'users',
        'verifying_staging': 'complete',
        'done': 'complete'
    }
    new_phase = phase_mapping.get(phase, phase)
    set_phase(case_uuid, new_phase)


def mark_completion_triggered(case_uuid: str) -> bool:
    """Atomically mark completion as triggered. Returns True only for first caller.
    
    Uses Redis SETNX to ensure only one worker triggers the completion task,
    even if multiple files complete simultaneously.
    
    Args:
        case_uuid: Case UUID
        
    Returns:
        True if this caller is the first to trigger (should proceed with completion)
        False if completion was already triggered by another worker
    """
    try:
        client = get_redis_client()
        key = f"completion_triggered:{case_uuid}"
        
        # SETNX returns True only if key didn't exist (first caller wins)
        was_first = client.setnx(key, "1")
        if was_first:
            # Set 24h expiry for cleanup
            client.expire(key, 86400)
            logger.info(f"Completion trigger acquired for case {case_uuid}")
        else:
            logger.debug(f"Completion already triggered for case {case_uuid}, skipping")
        
        return was_first
        
    except Exception as e:
        logger.warning(f"Failed to mark completion triggered: {e}")
        return False


def clear_completion_trigger(case_uuid: str) -> None:
    """Clear the completion trigger flag for a case.
    
    Called when starting new processing so completion can trigger again.
    
    Args:
        case_uuid: Case UUID
    """
    try:
        client = get_redis_client()
        key = f"completion_triggered:{case_uuid}"
        client.delete(key)
        logger.debug(f"Cleared completion trigger for case {case_uuid}")
        
    except Exception as e:
        logger.warning(f"Failed to clear completion trigger: {e}")
