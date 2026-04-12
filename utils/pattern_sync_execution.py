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
