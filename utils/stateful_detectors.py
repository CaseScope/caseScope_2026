"""Compatibility entrypoint for stateful detector orchestration.

Phase 4a is moving deterministic behavioral detection away from the
legacy ``gap_detectors`` naming. This module exposes the current manager,
base detector, and pure helper surfaces behind a neutral entrypoint so
callers can migrate incrementally without a package move yet.
"""

from utils.gap_detectors import (
    BaseGapDetector,
    GapDetectionManager,
    build_gap_detection_finding_payload,
    deduplicate_gap_detection_findings,
    get_gap_finding_severity_rank,
)

__all__ = [
    'BaseGapDetector',
    'GapDetectionManager',
    'build_gap_detection_finding_payload',
    'deduplicate_gap_detection_findings',
    'get_gap_finding_severity_rank',
]
