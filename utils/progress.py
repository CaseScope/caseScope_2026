"""Progress Tracking Utility for CaseScope

Uses Redis to track file processing progress per case.
Provides persistent progress that survives page navigation.
"""
import json
import logging
import redis
from typing import Optional, Dict, Any
from config import Config

logger = logging.getLogger(__name__)

# Redis connection
_redis_client = None


def get_redis_client() -> redis.Redis:
    """Get or create Redis client"""
    global _redis_client
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
    Resets any existing progress for this case.
    
    Args:
        case_uuid: Case UUID
        total_files: Total number of files in this batch
    """
    try:
        client = get_redis_client()
        key = _get_progress_key(case_uuid)
        
        progress_data = {
            'total': total_files,
            'completed': 0,
            'status': 'processing'
        }
        
        # Set with 24-hour expiry (auto-cleanup for stale progress)
        client.setex(key, 86400, json.dumps(progress_data))
        logger.info(f"Initialized progress for case {case_uuid}: {total_files} files")
        
    except Exception as e:
        logger.warning(f"Failed to initialize progress: {e}")


def increment_progress(case_uuid: str) -> Optional[Dict[str, Any]]:
    """Increment completed count for a case.
    
    Called when a file finishes processing.
    
    Args:
        case_uuid: Case UUID
        
    Returns:
        Updated progress dict or None if no progress exists
    """
    try:
        client = get_redis_client()
        key = _get_progress_key(case_uuid)
        
        data = client.get(key)
        if not data:
            return None
        
        progress = json.loads(data)
        progress['completed'] = progress.get('completed', 0) + 1
        
        # Check if complete
        if progress['completed'] >= progress['total']:
            progress['status'] = 'complete'
        
        # Update with same TTL
        client.setex(key, 86400, json.dumps(progress))
        logger.debug(f"Progress for case {case_uuid}: {progress['completed']}/{progress['total']}")
        
        return progress
        
    except Exception as e:
        logger.warning(f"Failed to increment progress: {e}")
        return None


def get_progress(case_uuid: str) -> Optional[Dict[str, Any]]:
    """Get current progress for a case.
    
    Args:
        case_uuid: Case UUID
        
    Returns:
        Progress dict with {total, completed, status} or None if no active progress
    """
    try:
        client = get_redis_client()
        key = _get_progress_key(case_uuid)
        
        data = client.get(key)
        if not data:
            return None
        
        return json.loads(data)
        
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
        
        data = client.get(key)
        if not data:
            # No existing progress, initialize new
            init_progress(case_uuid, additional_files)
            return get_progress(case_uuid)
        
        progress = json.loads(data)
        progress['total'] = progress.get('total', 0) + additional_files
        progress['status'] = 'processing'
        
        client.setex(key, 86400, json.dumps(progress))
        logger.info(f"Added {additional_files} files to progress for case {case_uuid}")
        
        return progress
        
    except Exception as e:
        logger.warning(f"Failed to add to progress: {e}")
        return None


def set_completion_phase(case_uuid: str, phase: str) -> None:
    """Set the current completion phase for a case.
    
    Called during post-indexing tasks (buffer flush, system/user discovery).
    
    Args:
        case_uuid: Case UUID
        phase: Current phase name ('flushing_buffer', 'discovering_systems', 
               'discovering_users', 'done')
    """
    try:
        client = get_redis_client()
        key = _get_progress_key(case_uuid)
        
        data = client.get(key)
        if data:
            progress = json.loads(data)
        else:
            progress = {'total': 0, 'completed': 0}
        
        progress['status'] = 'completing'
        progress['completion_phase'] = phase
        
        client.setex(key, 86400, json.dumps(progress))
        logger.debug(f"Set completion phase for case {case_uuid}: {phase}")
        
    except Exception as e:
        logger.warning(f"Failed to set completion phase: {e}")
