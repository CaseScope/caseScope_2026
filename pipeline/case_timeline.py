"""Shared Phase 7 timeline/storyline stage helpers."""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict

logger = logging.getLogger(__name__)


def run_ioc_timeline(
    *,
    case_id: int,
    analysis_id: str,
    progress_callback: Callable[[str, int, str], None],
) -> Dict[str, Any]:
    """Build the deterministic IOC timeline stage."""
    from utils.ioc_timeline_builder import IOCTimelineBuilder

    def _timeline_progress(phase: str, percent: int, message: str) -> None:
        overall_percent = 78 + int(percent * 0.06)
        progress_callback(phase, overall_percent, message)

    builder = IOCTimelineBuilder(
        case_id=case_id,
        analysis_id=analysis_id,
        progress_callback=_timeline_progress,
    )
    result = builder.build()
    entries_count = len(result.get('entries', []))
    links_count = len(result.get('cross_host_links', []))
    progress_callback(
        'ioc_timeline',
        88,
        f'IOC timeline: {entries_count} entries, {links_count} cross-host links',
    )
    return result


def run_incident_storylines(
    *,
    case_id: int,
    record_phase_outcome: Callable[..., None],
    progress_callback: Callable[[str, int, str], None],
) -> Dict[str, Any]:
    """Build generic download/execution/containment storylines."""
    from utils.incident_storyline_detector import IncidentStorylineDetector

    detector = IncidentStorylineDetector(case_id)
    result = detector.build()
    storylines = result.get('storylines', [])
    record_phase_outcome(
        'incident_storylines',
        True,
        details={
            'storyline_count': len(storylines),
            'download_count': result.get('download_count', 0),
            'containment_count': result.get('containment_count', 0),
        },
        message='Incident storyline correlation complete',
    )
    progress_callback(
        'incident_storylines',
        84,
        f"Correlated {len(storylines)} incident storylines",
    )
    return result
