"""Gap Detector Bridge for Deterministic Evidence Engine

Pure-function mapper that converts GapDetectionFinding objects into
CheckResult objects consumable by the evidence engine. Idempotent,
no database reads, no side effects.
"""

from typing import List, Optional
from utils.pattern_check_definitions import CheckResult


# Maps gap finding_type to the pattern check IDs they can satisfy
_FINDING_TYPE_TO_CHECK = {
    'PASSWORD_SPRAYING': {
        'pattern_id': 'password_spraying',
        'check_mappings': {
            'spray_distinct_users': lambda f: _extract_distinct_users(f),
            'spray_low_per_account': lambda f: _extract_low_per_account(f),
        },
    },
    'BRUTE_FORCE': {
        'pattern_id': 'brute_force',
        'check_mappings': {
            'brute_high_failures': lambda f: _extract_failure_count(f),
            'brute_bad_password': lambda f: _extract_failure_count(f),
            'brute_mssql_failures': lambda f: _extract_failure_count(f),
            'brute_followed_by_success': lambda f: _extract_success_count(f),
        },
    },
    'DISTRIBUTED_BRUTE_FORCE': {
        'pattern_id': 'brute_force',
        'check_mappings': {
            'brute_high_failures': lambda f: _extract_failure_count(f),
            'brute_bad_password': lambda f: _extract_failure_count(f),
            'brute_mssql_failures': lambda f: _extract_failure_count(f),
        },
    },
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
    mapping = _FINDING_TYPE_TO_CHECK.get(finding_type.upper())
    if not mapping:
        return []

    results = []
    for check_id, extractor in mapping['check_mappings'].items():
        detail = extractor(finding)
        confidence = getattr(finding, 'confidence', 0) or 0

        if confidence >= 60:
            status = 'PASS'
        elif confidence >= 30:
            status = 'INCONCLUSIVE'
        else:
            status = 'FAIL'

        results.append(CheckResult(
            check_id=check_id,
            status=status,
            weight=0,
            contribution=0.0,
            detail=f"From gap detector ({finding_type}): {detail}",
            source='gap_detector',
        ))

    return results


def get_gap_pattern_id(finding) -> Optional[str]:
    """Return the pattern_id a gap finding maps to, or None."""
    finding_type = getattr(finding, 'finding_type', '') or ''
    mapping = _FINDING_TYPE_TO_CHECK.get(finding_type.upper())
    return mapping['pattern_id'] if mapping else None


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
