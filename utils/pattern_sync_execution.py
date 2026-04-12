"""Execution helpers for external pattern sync tasks."""

from __future__ import annotations

import os
import subprocess
from typing import Any, Callable, Dict, Iterable, Sequence

from utils.pattern_sync_reporting import run_external_sync_stage


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


def build_opencti_sigma_sync_pattern(
    indicator: Dict[str, Any],
    *,
    converter: Any,
) -> Dict[str, Any] | None:
    """Convert an OpenCTI Sigma indicator into a persistable pattern payload."""
    pattern = converter.convert_sigma_rule(
        indicator['sigma_rule'],
        source='opencti_sigma',
    )
    if pattern:
        pattern['source_id'] = indicator['opencti_id']
    return pattern


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


def run_opencti_sigma_stage(
    *,
    sync_config: Dict[str, Any],
    stats: Dict[str, Any],
    converter: Any,
    get_client: Callable[[], Any],
    feature_activated: bool,
    opencti_enabled: bool,
    rag_sync_enabled: bool,
    save_pattern: Callable[[Dict[str, Any]], bool],
    apply_sync_result: Callable[..., None],
    on_indicator_error: Callable[[Dict[str, Any], Exception], None] | None = None,
) -> bool:
    """Run the OpenCTI Sigma stage and report whether to emit a summary."""
    opencti_sigma_inputs = load_opencti_sigma_indicators(
        feature_activated=feature_activated,
        opencti_enabled=opencti_enabled,
        rag_sync_enabled=rag_sync_enabled,
        get_client=get_client,
    )
    if opencti_sigma_inputs['status'] == 'ready':
        sync_opencti_sigma_indicators(
            opencti_sigma_inputs['indicators'],
            source_key=sync_config['source_key'],
            stats=stats,
            convert_indicator=lambda indicator: build_opencti_sigma_sync_pattern(
                indicator,
                converter=converter,
            ),
            save_pattern=save_pattern,
            apply_sync_result=apply_sync_result,
            on_indicator_error=on_indicator_error,
        )
        return True
    if opencti_sigma_inputs['status'] == 'unavailable':
        raise RuntimeError(opencti_sigma_inputs['error_message'] or 'Client not available')
    return False


def build_external_sync_source_stage_runners(
    *,
    stats: Dict[str, Any],
    update_state: Any,
    log_info: Any,
    log_error: Any,
    log_debug: Any,
    converter: Any,
    get_opencti_client: Any,
    convert_sigma_directory: Any,
    save_pattern: Callable[[Dict[str, Any]], bool],
    apply_sync_result: Callable[..., None],
    hayabusa_paths: Sequence[str],
    sigma_dir: str,
    mdec_dir: str,
    car_dir: str,
    feature_activated: bool,
    opencti_enabled: bool,
    rag_sync_enabled: bool,
) -> Dict[str, Any]:
    """Build the per-source runner map for external pattern sync."""
    return {
        'hayabusa': lambda: run_external_sync_stage(
            'hayabusa',
            stats=stats,
            update_state=update_state,
            log_info=log_info,
            log_error=lambda exc: log_error(f"[RAG] Hayabusa sync error: {exc}"),
            run_stage=lambda hayabusa_sync: sync_patterns_from_directories(
                hayabusa_paths,
                source_key=hayabusa_sync['source_key'],
                stats=stats,
                convert_directory=lambda path: convert_sigma_directory(path, source='hayabusa'),
                save_pattern=save_pattern,
                apply_sync_result=apply_sync_result,
            ),
        ),
        'sigma_github': lambda: run_external_sync_stage(
            'sigma_github',
            stats=stats,
            update_state=update_state,
            log_info=log_info,
            log_error=lambda exc: log_error(f"[RAG] SigmaHQ sync error: {exc}"),
            timeout_error_type=subprocess.TimeoutExpired,
            timeout_message='Git clone timed out',
            run_stage=lambda sigma_github_sync: sync_repo_backed_patterns(
                repo_dir=sigma_dir,
                repo_url='https://github.com/SigmaHQ/sigma.git',
                directory_paths=[
                    f"{sigma_dir}/rules/windows/builtin/security",
                    f"{sigma_dir}/rules/windows/builtin/system",
                    f"{sigma_dir}/rules/windows/process_creation",
                    f"{sigma_dir}/rules/windows/powershell",
                ],
                source_key=sigma_github_sync['source_key'],
                stats=stats,
                convert_directory=lambda path: convert_sigma_directory(path, source='sigma_github'),
                save_pattern=save_pattern,
                apply_sync_result=apply_sync_result,
            ),
        ),
        'mdecrevoisier': lambda: run_external_sync_stage(
            'mdecrevoisier',
            stats=stats,
            update_state=update_state,
            log_info=log_info,
            log_error=lambda exc: log_error(f"[RAG] mdecrevoisier sync error: {exc}"),
            run_stage=lambda mdecrevoisier_sync: sync_repo_backed_patterns(
                repo_dir=mdec_dir,
                repo_url='https://github.com/mdecrevoisier/SIGMA-detection-rules.git',
                directory_paths=[mdec_dir],
                source_key=mdecrevoisier_sync['source_key'],
                stats=stats,
                convert_directory=lambda path: convert_sigma_directory(path, source='mdecrevoisier'),
                save_pattern=save_pattern,
                apply_sync_result=apply_sync_result,
            ),
        ),
        'opencti_sigma': lambda: run_external_sync_stage(
            'opencti_sigma',
            stats=stats,
            update_state=update_state,
            log_info=log_info,
            log_error=lambda exc: log_error(f"[RAG] OpenCTI Sigma sync error: {exc}"),
            run_stage=lambda opencti_sigma_sync: run_opencti_sigma_stage(
                sync_config=opencti_sigma_sync,
                stats=stats,
                converter=converter,
                get_client=get_opencti_client,
                feature_activated=feature_activated,
                opencti_enabled=opencti_enabled,
                rag_sync_enabled=rag_sync_enabled,
                save_pattern=save_pattern,
                apply_sync_result=apply_sync_result,
                on_indicator_error=lambda _indicator, exc: log_debug(
                    f"[RAG] OpenCTI indicator conversion failed: {exc}"
                ),
            ),
        ),
        'car': lambda: run_external_sync_stage(
            'car',
            stats=stats,
            update_state=update_state,
            log_info=log_info,
            log_error=lambda exc: log_error(f"[RAG] MITRE CAR sync error: {exc}"),
            run_stage=lambda car_sync: sync_repo_backed_patterns(
                repo_dir=car_dir,
                repo_url='https://github.com/mitre-attack/car.git',
                directory_paths=[f"{car_dir}/analytics"],
                source_key=car_sync['source_key'],
                stats=stats,
                convert_directory=lambda path: convert_sigma_directory(path, source='mitre_car'),
                save_pattern=save_pattern,
                apply_sync_result=apply_sync_result,
            ),
        ),
    }
