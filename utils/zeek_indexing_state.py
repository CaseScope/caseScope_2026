"""Redis-backed in-flight markers for Zeek log indexing.

Gives the network hunting UI a server-side, cross-user signal that a PCAP's
Zeek logs are being indexed, so page reloads can resume status display and
duplicate index requests can be rejected.
"""
import logging

from utils.progress import get_redis_client

logger = logging.getLogger(__name__)

# Generous upper bound for a single PCAP indexing run; the marker is cleared
# explicitly when the task finishes, the TTL only guards against stale keys
# after a worker crash.
INDEXING_MARKER_TTL_SECONDS = 4 * 60 * 60


def _marker_key(pcap_id: int) -> str:
    return f'zeek_indexing:{pcap_id}'


def mark_indexing_inflight(pcap_id: int) -> None:
    """Mark a PCAP as having an in-flight Zeek indexing task."""
    try:
        get_redis_client().setex(_marker_key(pcap_id), INDEXING_MARKER_TTL_SECONDS, '1')
    except Exception:
        logger.warning(f"Could not set Zeek indexing marker for PCAP {pcap_id}", exc_info=True)


def clear_indexing_inflight(pcap_id: int) -> None:
    """Clear the in-flight Zeek indexing marker for a PCAP."""
    try:
        get_redis_client().delete(_marker_key(pcap_id))
    except Exception:
        logger.warning(f"Could not clear Zeek indexing marker for PCAP {pcap_id}", exc_info=True)


def is_indexing_inflight(pcap_id: int) -> bool:
    """Return True if a Zeek indexing task is currently queued or running."""
    try:
        return bool(get_redis_client().exists(_marker_key(pcap_id)))
    except Exception:
        logger.warning(f"Could not read Zeek indexing marker for PCAP {pcap_id}", exc_info=True)
        return False
