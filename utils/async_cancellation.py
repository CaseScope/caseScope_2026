"""Shared cooperative cancellation tokens for long-running async work."""

import json
import logging
import threading
from datetime import datetime
from typing import Any, Dict, Optional

import redis

from config import Config

logger = logging.getLogger(__name__)

_redis_client = None
_redis_lock = threading.Lock()
_TOKEN_TTL_SECONDS = 24 * 3600


def _get_redis_client():
    global _redis_client
    if _redis_client is None:
        with _redis_lock:
            if _redis_client is None:
                _redis_client = redis.Redis(
                    host=Config.REDIS_HOST,
                    port=Config.REDIS_PORT,
                    db=Config.REDIS_DB,
                    decode_responses=True,
                )
    return _redis_client


def _build_key(scope: str, identifier: Any) -> str:
    return f"async_cancel:{scope}:{identifier}"


def request_cancellation(scope: str, identifier: Any, metadata: Optional[Dict[str, Any]] = None) -> None:
    """Persist a cooperative cancellation token for a long-running async unit."""
    payload = {
        "requested_at": datetime.utcnow().isoformat(),
        "scope": scope,
        "id": str(identifier),
    }
    if metadata:
        payload["metadata"] = metadata
    _get_redis_client().setex(
        _build_key(scope, identifier),
        _TOKEN_TTL_SECONDS,
        json.dumps(payload),
    )


def is_cancellation_requested(scope: str, identifier: Any) -> bool:
    """Return True when a cooperative cancellation token is present."""
    try:
        return bool(_get_redis_client().exists(_build_key(scope, identifier)))
    except Exception as exc:
        logger.warning("Cancellation token lookup failed for %s:%s: %s", scope, identifier, exc)
        return False


def clear_cancellation(scope: str, identifier: Any) -> None:
    """Remove a cancellation token once work has acknowledged it."""
    try:
        _get_redis_client().delete(_build_key(scope, identifier))
    except Exception as exc:
        logger.warning("Cancellation token clear failed for %s:%s: %s", scope, identifier, exc)
