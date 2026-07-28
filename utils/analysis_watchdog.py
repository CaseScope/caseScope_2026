"""Sweep for analysis runs that stopped making progress and were never finalized.

Staleness was only evaluated when somebody loaded the analysis page for the case.
A run whose worker died therefore stayed in a running state indefinitely, and
because the start lock is held for the whole run, the case could not be analysed
again until a user happened to visit it - the one place that would have noticed is
also the one place blocked by it.

Sweeping on a schedule also reclaims two things an abandoned run leaves behind:
the start lock, and the candidate events staged for the pattern phase, of which
the database holds 775,968 rows belonging to runs that ended without cleanup.

A run is only abandoned if no Celery task is still working on it. A long phase
that has not reported for a while is refreshed rather than failed, because
finalizing a run whose worker is still writing to it would produce two writers
disagreeing about the outcome.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Dict, List

logger = logging.getLogger(__name__)

# Matches the threshold the analysis routes use.
DEFAULT_STALE_MINUTES = 20


def _active_analysis_ids() -> set:
    """analysis_ids that a Celery worker is currently working on.

    An empty set on failure is deliberately ambiguous, so the caller treats an
    uninspectable Celery as "cannot confirm" and leaves runs alone.
    """
    from tasks.celery_tasks import celery_app

    inspector = celery_app.control.inspect(timeout=2)
    active_ids = set()

    for source in (inspector.active(), inspector.reserved(), inspector.scheduled()):
        for tasks in (source or {}).values():
            for task in tasks or []:
                payload = task.get('request', task)
                for argument in payload.get('args') or []:
                    # The phase tasks take the analysis_id as an argument; the
                    # callback takes it third, after the wave results.
                    if isinstance(argument, str) and len(argument) == 36:
                        active_ids.add(argument)

    return active_ids


def sweep_stale_analysis_runs(stale_after_minutes: int = DEFAULT_STALE_MINUTES) -> Dict[str, object]:
    """Finalize abandoned runs and reclaim what they were holding."""
    from models.behavioral_profiles import AnalysisStatus, CaseAnalysisRun
    from models.database import db
    from utils.analysis_run_lock import release_start_lock

    candidates: List[CaseAnalysisRun] = CaseAnalysisRun.query.filter(
        CaseAnalysisRun.status.in_(AnalysisStatus.running_statuses())
    ).all()

    stale = [run for run in candidates if run.is_stale(stale_after_minutes)]
    if not stale:
        return {'examined': len(candidates), 'stale': 0, 'failed': 0, 'refreshed': 0}

    try:
        active_ids = _active_analysis_ids()
        inspected = True
    except Exception as exc:
        logger.warning('[AnalysisWatchdog] Could not inspect Celery: %s', exc)
        active_ids = set()
        inspected = False

    failed = 0
    refreshed = 0
    reclaimed_rows = 0
    now = datetime.utcnow()

    for run in stale:
        if not inspected:
            # Without a reliable view of the workers, failing a run risks
            # finalizing one that is still being written to.
            continue

        if run.analysis_id in active_ids:
            run.last_progress_at = now
            if not run.current_phase:
                run.current_phase = 'Analysis still running'
            refreshed += 1
            continue

        run.status = AnalysisStatus.FAILED
        run.error_message = (
            f'Automatically marked stale after {stale_after_minutes} minutes without '
            'progress and with no worker still running it.'
        )
        run.current_phase = 'Analysis marked stale'
        run.completed_at = now
        run.last_progress_at = run.last_progress_at or now
        failed += 1

        reclaimed_rows += _discard_staged_candidates(run.analysis_id)
        release_start_lock(run.case_id, run.analysis_id)
        logger.warning(
            '[AnalysisWatchdog] Marked %s for case %s stale', run.analysis_id, run.case_id
        )

    db.session.commit()

    return {
        'examined': len(candidates),
        'stale': len(stale),
        'failed': failed,
        'refreshed': refreshed,
        'staged_events_reclaimed': reclaimed_rows,
    }


def _discard_staged_candidates(analysis_id: str) -> int:
    """Delete candidate events staged by a run that will never finish."""
    from models.database import db
    from models.rag import CandidateEventSet

    try:
        deleted = CandidateEventSet.query.filter_by(analysis_id=analysis_id).delete()
        if deleted:
            logger.info(
                '[AnalysisWatchdog] Discarded %s staged candidate events for %s',
                deleted, analysis_id,
            )
        return deleted or 0
    except Exception as exc:
        logger.warning(
            '[AnalysisWatchdog] Could not discard staged events for %s: %s',
            analysis_id, exc,
        )
        db.session.rollback()
        return 0
