"""Gap Detector Bridge for Deterministic Evidence Engine

Pure-function mapper that converts GapDetectionFinding objects into
CheckResult objects consumable by the evidence engine. Idempotent,
no database reads, no side effects.
"""

from typing import List
from utils.finding_contract import (
    build_gap_finding_check_detail,
    get_gap_finding_result_status,
)
from utils.pattern_check_definitions import (
    CheckResult,
    get_check_bindings_for_gap_finding,
)


def map_gap_finding_to_check_results(finding) -> List[CheckResult]:
    """Convert a GapDetectionFinding into CheckResult objects.

    This is a pure function: given the same finding, it always returns
    the same results. No DB access, no side effects.

    Args:
        finding: A GapDetectionFinding model instance (or any object with
                 finding_type, confidence, evidence, details attributes).

    Returns:
        List of CheckResult objects that the evidence engine can consume.
        Empty list if the finding type has no mapping.
    """
    finding_type = getattr(finding, 'finding_type', '') or ''
    check_bindings = get_check_bindings_for_gap_finding(finding_type)
    if not check_bindings:
        return []

    results = []
    for check_binding in check_bindings:
        check_definition = check_binding['check']
        extractor_name = check_binding['detail_extractor']
        detail = build_gap_finding_check_detail(finding, extractor_name)
        confidence = getattr(finding, 'confidence', 0) or 0
        status = get_gap_finding_result_status(confidence)

        results.append(CheckResult(
            check_id=check_definition.id,
            status=status,
            weight=0,
            contribution=0.0,
            detail=f"From gap detector ({finding_type}): {detail}",
            source='gap_detector',
        ))

    return results
