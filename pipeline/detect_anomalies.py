"""Shared Phase 7 anomaly-detection stage helpers."""

from __future__ import annotations

from typing import Callable, List, Optional

from utils.stateful_detectors import GapDetectionError, GapDetectionManager


def run_detect_anomalies(
    case_id: int,
    analysis_id: str,
    progress_callback: Optional[Callable[[str, int, str], None]] = None,
) -> List:
    """Run the shared gap-detection stage.

    Raises `GapDetectionError` if any detector failed. The findings from the
    detectors that did complete are persisted first and attached to the error,
    so a crashed detector is reported as a failure rather than silently
    reducing the finding count - which is how this stage came to return nothing
    on every case without any phase being marked as failed.
    """
    manager = GapDetectionManager(
        case_id=case_id,
        analysis_id=analysis_id,
        progress_callback=progress_callback,
    )
    findings = manager.run_all_detectors()

    if manager.has_failures:
        raise GapDetectionError(
            f"Gap detection incomplete: {manager.failure_summary()} failed",
            findings=findings,
            failed_detectors=list(manager.failed_stages),
        )

    return findings
