"""The single place a run's progress and status are written.

Progress used to be written from the orchestrator only. The phases that run as
separate tasks reported into Celery task state instead, which the status endpoint
does not read, so a run showed no movement at all while profiling and correlation
were running - and the `profiling` and `correlating` statuses were never reached,
because the orchestrator only ever saw phases that happen after them.

Two rules make one scale out of several writers:

Progress never decreases. Two phases run concurrently and each reports its own
position; without this the bar jumps backwards whenever the slower one reports.
It also means an out-of-order update from a task that was briefly delayed cannot
undo the progress of one that has moved on.

A phase's percentage comes from its declared span in utils.analysis_phases, so
callers express how far through their own phase they are and cannot overwrite
another phase's range.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from models.behavioral_profiles import AnalysisStatus
from models.database import db
from utils.analysis_phases import PHASE_SPANS, phase_progress, phase_status

logger = logging.getLogger(__name__)

# Once a run reaches one of these it is finished, and a late update from a task
# that has not noticed must not revive it.
_TERMINAL = frozenset(AnalysisStatus.terminal_statuses())

# The phase timestamps to stamp the first time a phase reports.
_PHASE_TIMESTAMP_FIELDS = {
    'profiling': 'profiling_started_at',
    'profile_cluster': 'profiling_started_at',
    'clustering': 'profiling_started_at',
    'hayabusa_correlation': 'correlation_started_at',
    'pattern_analysis': 'ai_analysis_started_at',
}


def record_analysis_progress(run, *, phase: str, percent: Optional[int] = None,
                             fraction: Optional[float] = None,
                             message: str = '', commit: bool = True) -> bool:
    """Advance a run's progress, status and phase timestamps.

    Give either an absolute `percent` or a `fraction` of the way through `phase`.
    Returns False when the update was ignored, which happens for a finished run
    or an update that would move progress backwards.
    """
    if run is None:
        return False

    if run.status in _TERMINAL:
        return False

    if percent is None and fraction is not None:
        percent = phase_progress(phase, fraction)
    elif percent is not None:
        # Clamp into the phase's declared span. Call sites carried hand-written
        # absolute numbers that had drifted out of agreement - gap detection
        # reported 20 in one path and 35 in another, the IOC timeline reported 88
        # which belongs to enrichment, and correlation reported 50 which is in
        # pattern analysis - so a phase could move the bar into a range it does
        # not own. The span is now the authority.
        percent = _clamp_to_span(phase, percent)

    now = datetime.utcnow()
    changed = False

    if percent is not None:
        current = run.progress_percent or 0
        if percent >= current:
            run.progress_percent = min(100, percent)
            changed = True
        else:
            logger.debug(
                "Ignoring out-of-order progress for %s: %s%% behind %s%%",
                getattr(run, 'analysis_id', '?'), percent, current,
            )

    if message:
        run.current_phase = message
        changed = True

    status = phase_status(phase)
    if status and run.status != status and _advances_status(run.status, status):
        run.status = status
        changed = True

    timestamp_field = _PHASE_TIMESTAMP_FIELDS.get(phase)
    if timestamp_field and not getattr(run, timestamp_field, None):
        setattr(run, timestamp_field, now)
        changed = True

    if changed:
        run.last_progress_at = now
        if commit:
            try:
                db.session.commit()
            except Exception as exc:
                logger.warning(
                    "Failed to persist progress for %s: %s",
                    getattr(run, 'analysis_id', '?'), exc,
                )
                db.session.rollback()
                return False

    return changed


# The order a healthy run moves through. Used so a phase reporting late cannot
# drag the status back to an earlier one.
_STATUS_ORDER = (
    AnalysisStatus.PENDING,
    AnalysisStatus.PROFILING,
    AnalysisStatus.CORRELATING,
    AnalysisStatus.ANALYZING,
)


def _clamp_to_span(phase: str, percent: int) -> int:
    """Hold an absolute percentage inside the phase's declared span."""
    span = PHASE_SPANS.get(phase)
    if span is None:
        return percent

    start, end = span
    return max(start, min(end, percent))


def _advances_status(current: Optional[str], proposed: str) -> bool:
    """Whether moving from `current` to `proposed` is forward progress.

    Wave 1 runs profiling and correlation concurrently, so both statuses are
    proposed at once and whichever arrives second must not undo the first.
    """
    if current not in _STATUS_ORDER:
        return False
    return _STATUS_ORDER.index(proposed) > _STATUS_ORDER.index(current)
