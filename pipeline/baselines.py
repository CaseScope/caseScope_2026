"""Shared Phase 7 baseline-building stage helpers."""

from __future__ import annotations

import time
from typing import Any, Callable, Dict, Optional

from utils.behavioral_profiler import BehavioralProfiler
from utils.peer_clustering import PeerGroupBuilder


def run_behavioral_profiling(
    case_id: int,
    analysis_id: str,
    progress_callback: Optional[Callable[[str, int, str], None]] = None,
) -> Dict[str, Any]:
    """Run the behavioral profiling stage and normalize its contract."""
    started = time.time()
    profiler = BehavioralProfiler(
        case_id=case_id,
        analysis_id=analysis_id,
        progress_callback=progress_callback,
    )
    result = profiler.profile_all()
    return {
        "users_profiled": result.get("users_profiled", 0),
        "systems_profiled": result.get("systems_profiled", 0),
        "duration_seconds": time.time() - started,
    }


def run_peer_clustering(case_id: int, analysis_id: str) -> Dict[str, Any]:
    """Run peer clustering and normalize its return shape."""
    builder = PeerGroupBuilder(case_id, analysis_id)
    result = builder.build_all_peer_groups()
    normalized = {
        "user_groups": result.get("user_groups", 0),
        "system_groups": result.get("system_groups", 0),
    }
    if "total_groups" in result:
        normalized["total_groups"] = result.get("total_groups", 0)
    return normalized


def run_build_baselines(
    case_id: int,
    analysis_id: str,
    progress_callback: Optional[Callable[[str, int, str], None]] = None,
) -> Dict[str, Any]:
    """Run the full baseline-building stage in dependency order."""
    profiling = run_behavioral_profiling(
        case_id=case_id,
        analysis_id=analysis_id,
        progress_callback=progress_callback,
    )
    clustering = run_peer_clustering(
        case_id=case_id,
        analysis_id=analysis_id,
    )
    combined = dict(profiling)
    combined.update(clustering)
    return combined
