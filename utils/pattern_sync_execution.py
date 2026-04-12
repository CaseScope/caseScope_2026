"""Execution helpers for external pattern sync tasks."""

from __future__ import annotations

import os
import subprocess
from typing import Any, Callable, Dict, Iterable, Sequence


def ensure_git_checkout(
    repo_dir: str,
    repo_url: str,
    *,
    path_exists: Callable[[str], bool] = os.path.exists,
    run_command: Callable[..., Any] = subprocess.run,
    pull_timeout: int = 120,
    clone_timeout: int = 300,
) -> None:
    """Clone a repository if missing, otherwise fast-forward pull it."""
    if path_exists(repo_dir):
        run_command(
            ['git', '-C', repo_dir, 'pull', '--ff-only'],
            check=True,
            capture_output=True,
            timeout=pull_timeout,
        )
        return

    run_command(
        ['git', 'clone', '--depth', '1', repo_url, repo_dir],
        check=True,
        capture_output=True,
        timeout=clone_timeout,
    )


def sync_patterns_from_directories(
    directory_paths: Sequence[str],
    *,
    source_key: str,
    stats: Dict[str, int],
    convert_directory: Callable[[str], Iterable[Dict[str, Any]]],
    save_pattern: Callable[[Dict[str, Any]], bool],
    apply_sync_result: Callable[..., None],
    path_exists: Callable[[str], bool] = os.path.exists,
) -> None:
    """Convert all existing directories for a source and record sync results."""
    for directory_path in directory_paths:
        if not path_exists(directory_path):
            continue
        patterns = convert_directory(directory_path)
        for pattern in patterns:
            created = save_pattern(pattern)
            apply_sync_result(
                stats,
                source_key=source_key,
                created=created,
            )


def sync_repo_backed_patterns(
    *,
    repo_dir: str,
    repo_url: str,
    directory_paths: Sequence[str],
    source_key: str,
    stats: Dict[str, int],
    convert_directory: Callable[[str], Iterable[Dict[str, Any]]],
    save_pattern: Callable[[Dict[str, Any]], bool],
    apply_sync_result: Callable[..., None],
    checkout_repo: Callable[..., None] = ensure_git_checkout,
    sync_directories: Callable[..., None] = sync_patterns_from_directories,
) -> None:
    """Checkout a repo-backed source and sync patterns from its directories."""
    checkout_repo(repo_dir, repo_url)
    sync_directories(
        directory_paths,
        source_key=source_key,
        stats=stats,
        convert_directory=convert_directory,
        save_pattern=save_pattern,
        apply_sync_result=apply_sync_result,
    )


def sync_opencti_sigma_indicators(
    indicators: Iterable[Dict[str, Any]],
    *,
    source_key: str,
    stats: Dict[str, int],
    convert_indicator: Callable[[Dict[str, Any]], Dict[str, Any] | None],
    save_pattern: Callable[[Dict[str, Any]], bool],
    apply_sync_result: Callable[..., None],
    on_indicator_error: Callable[[Dict[str, Any], Exception], None] | None = None,
) -> None:
    """Convert OpenCTI Sigma indicators, save executable patterns, and record results."""
    for indicator in indicators:
        try:
            pattern = convert_indicator(indicator)
            if not pattern or not pattern.get('required_event_ids'):
                continue
            created = save_pattern(pattern)
            apply_sync_result(
                stats,
                source_key=source_key,
                created=created,
            )
        except Exception as exc:
            if on_indicator_error is not None:
                on_indicator_error(indicator, exc)


def load_opencti_sigma_indicators(
    *,
    feature_activated: bool,
    opencti_enabled: bool,
    rag_sync_enabled: bool,
    get_client: Callable[[], Any],
    indicator_limit: int = 500,
) -> Dict[str, Any]:
    """Resolve whether OpenCTI Sigma sync can run and load indicators when ready."""
    if not (feature_activated and opencti_enabled and rag_sync_enabled):
        return {
            'status': 'disabled',
            'indicators': [],
            'error_message': None,
        }

    client = get_client()
    if not client or getattr(client, 'init_error', None):
        return {
            'status': 'unavailable',
            'indicators': [],
            'error_message': 'Client not available',
        }

    return {
        'status': 'ready',
        'indicators': client.get_sigma_indicators(limit=indicator_limit),
        'error_message': None,
    }
