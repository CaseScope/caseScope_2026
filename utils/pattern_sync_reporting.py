"""Shared reporting helpers for AttackPattern sync tasks."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Sequence


def finalize_rag_sync_log(
    sync_log: Any,
    *,
    patterns_added: int = 0,
    patterns_updated: int = 0,
    success: bool = True,
    error_message: str | None = None,
    completed_at: Any = None,
) -> None:
    """Apply a normalized completion state to a RAGSyncLog row."""
    sync_log.patterns_added = patterns_added
    sync_log.patterns_updated = patterns_updated
    sync_log.success = success
    sync_log.completed_at = completed_at or datetime.utcnow()
    if error_message is not None:
        sync_log.error_message = error_message


def build_opencti_sync_response(stats: Dict[str, Any]) -> Dict[str, Any]:
    """Build the normalized response payload for the OpenCTI sync task."""
    return {
        'success': True,
        'synced': stats,
        'message': (
            f"Synced {stats['attack_patterns']} patterns, {stats['indicators']} indicators, "
            f"updated {stats['updated']}, overlays +{stats['overlays_added']}/~{stats['overlays_updated']}"
        ),
    }


def build_mitre_sync_response(stats: Dict[str, Any]) -> Dict[str, Any]:
    """Build the normalized response payload for the MITRE ATT&CK sync task."""
    return {
        'success': True,
        'stats': stats,
        'message': (
            f"Synced {stats['new_patterns']} new patterns, "
            f"updated {stats['updated_patterns']}, {stats['errors']} errors"
        ),
    }


def build_multi_source_sync_response(
    *,
    stats: Dict[str, Any],
    sources: Sequence[str],
    total_patterns: int,
    executable_patterns: int,
) -> Dict[str, Any]:
    """Build the normalized response payload for the multi-source sync task."""
    return {
        'success': True,
        'sources_synced': list(sources),
        'stats': stats,
        'total_patterns': total_patterns,
        'executable_patterns': executable_patterns,
        'message': f"Synced {stats['total_added']} new patterns from {len(list(sources))} sources",
    }
