"""Plausible event-time bounds shared by the analysis stages.

Behavioral baselines are only meaningful over times that could plausibly be
real. The guard used to be one-sided - it excluded the epoch and nothing else -
which let two families of corrupt timestamps into every baseline.

Events dated in the future. Across the indexed corpus 21,775 events carry
timestamps up to the year 2299, including 18,865 kernel boot events dated 2101
on one case, written before the clock synchronised. One profile as a result
claimed a period running from 2010 to 2101.

Events dated before authentication logging plausibly existed. Another 389,480
events fall before the year 2000, and they are not real: 150,203 sit on
1980-01-01 and 87,282 on 1985-10-26, both filesystem epoch defaults, and the
remainder are browser and filesystem artifacts. None of them are Windows event
log records. Left in, they stretch a profile period across decades and spread
activity over thousands of calendar days that never happened.

The upper bound is evaluated by the database rather than baked in, so it cannot
go stale, and it allows a day of slack for clock skew on the collected host.
"""

from __future__ import annotations

# Windows event logging predates this, but no credible authentication record in
# the corpus falls before it, while a third of a million artifact timestamps do.
MIN_VALID_EVENT_TIME = '2000-01-01 00:00:00'

# Tolerance for a collected host whose clock ran ahead of the analyst's.
FUTURE_TOLERANCE_SQL = 'now() + INTERVAL 1 DAY'


def event_time_bounds_sql(column: str = 'timestamp_utc') -> str:
    """SQL predicate restricting `column` to a plausible event time.

    Written as a fragment rather than a parameterised range because the upper
    bound has to be evaluated by the database at query time.
    """
    return (
        f"{column} > toDateTime64({{min_time:String}}, 3) "
        f"AND {column} <= {FUTURE_TOLERANCE_SQL}"
    )


def event_time_parameters() -> dict:
    """Bound parameters required by `event_time_bounds_sql`."""
    return {'min_time': MIN_VALID_EVENT_TIME}
