"""Gap Detector Bridge for Deterministic Evidence Engine

Pure-function mapper that converts GapDetectionFinding objects into
CheckResult objects consumable by the evidence engine. Idempotent,
no database reads, no side effects.
"""

from typing import Callable, Dict, List
from utils.finding_contract import get_gap_finding_result_status
from utils.pattern_check_definitions import (
    CheckResult,
    get_check_bindings_for_gap_finding,
)


_DETAIL_EXTRACTORS: Dict[str, Callable] = {
    'distinct_users': lambda finding: _extract_distinct_users(finding),
    'low_per_account': lambda finding: _extract_low_per_account(finding),
    'failure_count': lambda finding: _extract_failure_count(finding),
    'success_count': lambda finding: _extract_success_count(finding),
}


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
        extractor = _DETAIL_EXTRACTORS[extractor_name]
        detail = extractor(finding)
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
def _extract_distinct_users(finding) -> str:
    evidence = getattr(finding, 'evidence', None) or {}
    details = getattr(finding, 'details', None) or {}
    user_count = (
        evidence.get('unique_users')
        or details.get('unique_users')
        or evidence.get('distinct_usernames')
        or '?'
    )
    return f"{user_count} distinct usernames targeted"


def _extract_low_per_account(finding) -> str:
    evidence = getattr(finding, 'evidence', None) or {}
    details = getattr(finding, 'details', None) or {}
    max_per = (
        evidence.get('max_attempts_per_user')
        or details.get('max_attempts_per_user')
        or '?'
    )
    return f"max {max_per} attempts per account"


def _extract_failure_count(finding) -> str:
    event_count = getattr(finding, 'event_count', None) or 0
    evidence = getattr(finding, 'evidence', None) or {}
    count = evidence.get('total_failures') or event_count
    return f"{count} failed logon attempts"


def _extract_success_count(finding) -> str:
    details = getattr(finding, 'details', None) or {}
    successes = details.get('successes') or 0
    return f"{successes} successful logons after failures"
