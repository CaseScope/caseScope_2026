"""Shared reporting helpers for AttackPattern sync tasks."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Sequence


EXTERNAL_SYNC_SOURCE_CONFIGS: Dict[str, Dict[str, Any]] = {
    'hayabusa': {
        'stage': 'hayabusa',
        'progress': 10,
        'status': 'Processing Hayabusa rules...',
        'source_key': 'hayabusa',
        'source_label': 'Hayabusa',
    },
    'sigma_github': {
        'stage': 'sigma_github',
        'progress': 30,
        'status': 'Syncing SigmaHQ rules from GitHub...',
        'source_key': 'sigma_github',
        'source_label': 'SigmaHQ',
    },
    'mdecrevoisier': {
        'stage': 'mdecrevoisier',
        'progress': 50,
        'status': 'Syncing mdecrevoisier rules...',
        'source_key': 'mdecrevoisier',
        'source_label': 'mdecrevoisier',
    },
    'opencti_sigma': {
        'stage': 'opencti_sigma',
        'progress': 70,
        'status': 'Syncing Sigma indicators from OpenCTI...',
        'source_key': 'opencti_sigma',
        'source_label': 'OpenCTI Sigma',
        'error_label': 'OpenCTI',
    },
    'car': {
        'stage': 'car',
        'progress': 85,
        'status': 'Syncing MITRE CAR analytics...',
        'source_key': 'car',
        'source_label': 'MITRE CAR',
    },
    'vectorizing': {
        'stage': 'vectorizing',
        'progress': 95,
        'status': 'Updating vector embeddings...',
        'source_label': 'Vector update',
    },
}

DEFAULT_EXTERNAL_SYNC_SOURCES = [
    'hayabusa',
    'opencti_sigma',
]


def get_external_sync_source_config(source_name: str) -> Dict[str, Any]:
    """Return normalized descriptor metadata for an external sync source."""
    config = EXTERNAL_SYNC_SOURCE_CONFIGS.get(source_name)
    if config is None:
        raise KeyError(f'Unknown external sync source: {source_name}')
    return dict(config)


def begin_external_sync_stage(
    source_name: str,
    *,
    update_state: Any,
) -> Dict[str, Any]:
    """Load source config and publish its normalized progress update."""
    config = get_external_sync_source_config(source_name)
    update_state(
        state='PROGRESS',
        meta=build_sync_progress_meta(
            stage=config['stage'],
            progress=config['progress'],
            status=config['status'],
        ),
    )
    return config


def get_default_external_sync_sources() -> list[str]:
    """Return the default source order for external pattern sync."""
    return list(DEFAULT_EXTERNAL_SYNC_SOURCES)


def initialize_external_sync_stats() -> Dict[str, Any]:
    """Build the default stats shape for external pattern sync."""
    stats: Dict[str, Any] = {
        'total_added': 0,
        'total_updated': 0,
        'errors': [],
    }
    for config in EXTERNAL_SYNC_SOURCE_CONFIGS.values():
        source_key = config.get('source_key')
        if source_key:
            stats[source_key] = 0
    return stats


def apply_external_source_sync_result(
    stats: Dict[str, int],
    *,
    source_key: str,
    created: bool,
    added_key: str = 'total_added',
    updated_key: str = 'total_updated',
) -> None:
    """Accumulate a created-versus-updated result for an external source sync."""
    if created:
        stats[source_key] = int(stats.get(source_key, 0)) + 1
        stats[added_key] = int(stats.get(added_key, 0)) + 1
        return
    stats[updated_key] = int(stats.get(updated_key, 0)) + 1


def build_sync_progress_meta(
    *,
    stage: str,
    progress: int,
    status: str,
) -> Dict[str, Any]:
    """Build a normalized progress payload for sync task state updates."""
    return {
        'stage': stage,
        'progress': progress,
        'status': status,
    }


def build_external_source_summary_message(
    *,
    source_label: str,
    added_count: int,
) -> str:
    """Build a normalized completion summary for an external sync source."""
    return f"[RAG] {source_label}: Added {added_count} patterns"


def log_external_sync_stage_summary(
    sync_config: Dict[str, Any],
    stats: Dict[str, Any],
    *,
    log_info: Any,
) -> None:
    """Emit the normalized added-count summary for a completed sync stage."""
    log_info(
        build_external_source_summary_message(
            source_label=sync_config['source_label'],
            added_count=stats[sync_config['source_key']],
        )
    )


def append_sync_error(
    stats: Dict[str, Any],
    *,
    source_label: str,
    error: Any | None = None,
    message: str | None = None,
    errors_key: str = 'errors',
    limit: int = 100,
) -> None:
    """Append a normalized sync error message onto a stats dict."""
    detail = message if message is not None else str(error or '')
    entry = f"{source_label}: {detail[:limit]}" if detail else source_label
    stats.setdefault(errors_key, []).append(entry)


def append_external_sync_stage_error(
    stats: Dict[str, Any],
    sync_config: Dict[str, Any],
    *,
    error: Any | None = None,
    message: str | None = None,
) -> None:
    """Append a normalized error for a stage using its configured label."""
    append_sync_error(
        stats,
        source_label=sync_config.get('error_label', sync_config['source_label']),
        error=error,
        message=message,
    )


def summarize_sync_errors(
    errors: Sequence[str],
    *,
    max_entries: int = 5,
    separator: str = '; ',
) -> str | None:
    """Summarize sync errors for persistence on the sync log."""
    if not errors:
        return None
    return separator.join(errors[:max_entries])


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
