"""Per-case lock preventing two analysis runs from starting at once.

Starting a run used to be a check followed by an act: the route queried for a
run in a running state, found none, and dispatched. Two requests arriving
together - a double-clicked button is enough - both saw no running analysis and
both dispatched, and the second run's initialisation deletes the first run's
profiles and peer groups out from under it. The database has no constraint that
would have caught it, because a case is allowed any number of historical runs.

The lock is held for the whole run rather than just the dispatch, so it also
covers the window between the run record being created and the first phase
reporting progress, which is where the race was widest.

Redis holds the lock because the web process and the workers are separate
processes and only Redis is shared by both. It carries an expiry so a worker
killed mid-run cannot lock a case out permanently.
"""

from __future__ import annotations

import logging
from typing import Optional

from utils.async_cancellation import _get_redis_client

logger = logging.getLogger(__name__)

# Long enough to outlast a genuine run on a large case, short enough that a lock
# orphaned by a killed worker clears itself the same day. The run's own stale
# watchdog is what normally releases it.
LOCK_TTL_SECONDS = 24 * 3600


def _lock_key(case_id: int) -> str:
    return f"analysis_start_lock:{case_id}"


def acquire_start_lock(case_id: int, analysis_id: str) -> bool:
    """Claim the right to run analysis on this case.

    Returns False when another run already holds it. Failing open on a Redis
    error is deliberate: losing the ability to start any analysis is worse than
    the race the lock prevents, and the route still performs its own check for a
    run in a running state.
    """
    try:
        acquired = _get_redis_client().set(
            _lock_key(case_id), analysis_id, nx=True, ex=LOCK_TTL_SECONDS
        )
        return bool(acquired)
    except Exception as exc:
        logger.warning(
            "Analysis start lock unavailable for case %s, proceeding: %s", case_id, exc
        )
        return True


def release_start_lock(case_id: int, analysis_id: Optional[str] = None) -> None:
    """Release the lock, but only if this run still owns it.

    The ownership check stops a run that already timed out and had its lock
    expire from releasing the lock of the run that legitimately replaced it.
    """
    try:
        client = _get_redis_client()
        key = _lock_key(case_id)
        if analysis_id is not None:
            holder = client.get(key)
            if holder is not None and holder != analysis_id:
                logger.info(
                    "Not releasing analysis lock for case %s: held by %s, not %s",
                    case_id, holder, analysis_id,
                )
                return
        client.delete(key)
    except Exception as exc:
        logger.warning("Failed to release analysis start lock for case %s: %s", case_id, exc)


def current_lock_holder(case_id: int) -> Optional[str]:
    """The analysis_id currently holding the lock, if any."""
    try:
        return _get_redis_client().get(_lock_key(case_id))
    except Exception as exc:
        logger.warning("Could not read analysis start lock for case %s: %s", case_id, exc)
        return None
