"""Redis-backed in-flight markers for global (non case-scoped) maintenance tasks.

Used for singleton background jobs like the EVTX description scrape, Hayabusa
rules update, and MITRE ATT&CK update so that:
- page reloads can re-attach to a running task (marker stores the task id)
- duplicate submissions can be rejected while one is in flight
The marker is cleared by the task when it finishes; the TTL only guards
against stale keys after a worker crash.
"""
import json
import logging
import time

from utils.progress import get_redis_client

logger = logging.getLogger(__name__)

DEFAULT_MARKER_TTL_SECONDS = 4 * 60 * 60


def _marker_key(task_name: str) -> str:
    return f'global_task_inflight:{task_name}'


def mark_global_task_inflight(task_name: str, task_id: str = None,
                              ttl_seconds: int = DEFAULT_MARKER_TTL_SECONDS) -> None:
    """Mark a named global task as in flight (optionally recording its task id)."""
    try:
        payload = {'task_id': task_id, 'started_at': time.time()}
        get_redis_client().setex(_marker_key(task_name), ttl_seconds, json.dumps(payload))
    except Exception:
        logger.warning(f"Could not set in-flight marker for {task_name}", exc_info=True)


def clear_global_task_inflight(task_name: str) -> None:
    """Clear the in-flight marker for a named global task."""
    try:
        get_redis_client().delete(_marker_key(task_name))
    except Exception:
        logger.warning(f"Could not clear in-flight marker for {task_name}", exc_info=True)


def get_global_task_inflight(task_name: str) -> dict:
    """Return the in-flight marker payload ({task_id, started_at}) or None."""
    try:
        raw = get_redis_client().get(_marker_key(task_name))
        return json.loads(raw) if raw else None
    except Exception:
        logger.warning(f"Could not read in-flight marker for {task_name}", exc_info=True)
        return None
