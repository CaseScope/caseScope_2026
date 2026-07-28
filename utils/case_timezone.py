"""Case timezone resolution shared by analysis stages.

Analysis stages query event data in UTC and convert to the case timezone for
any hour-of-day or calendar-day reasoning, so business-hours and off-hours
judgments match what the analyst sees on the hunting pages.
"""

from __future__ import annotations

import logging

DEFAULT_CASE_TIMEZONE = 'UTC'

logger = logging.getLogger(__name__)


def get_case_timezone(case_id: int) -> str:
    """Return the IANA timezone configured for a case, defaulting to UTC."""
    try:
        from models.case import Case

        case_record = Case.query.filter_by(id=case_id).first()
    except Exception as exc:
        logger.warning(
            "[CaseTimezone] Could not resolve timezone for case %s: %s", case_id, exc
        )
        return DEFAULT_CASE_TIMEZONE

    timezone_name = getattr(case_record, 'timezone', None) if case_record else None
    return timezone_name or DEFAULT_CASE_TIMEZONE
