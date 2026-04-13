"""Shared Phase 7 anomaly-detection stage helpers."""

from __future__ import annotations

from typing import Callable, List, Optional

from utils.stateful_detectors import GapDetectionManager


def run_detect_anomalies(
    case_id: int,
    analysis_id: str,
    progress_callback: Optional[Callable[[str, int, str], None]] = None,
) -> List:
    """Run the shared gap-detection stage."""
    manager = GapDetectionManager(
        case_id=case_id,
        analysis_id=analysis_id,
        progress_callback=progress_callback,
    )
    return manager.run_all_detectors()
