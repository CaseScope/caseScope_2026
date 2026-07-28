"""Find and reclaim analysis data that no run stands behind.

Four defects left data behind, all of them fixed, none of them retroactive:

  * The pattern stage cleaned up its staged candidate events after the loop, so
    any failure in the loop stranded them permanently. 775,968 rows, 476 MB.
  * The attack-chain builder wrote suggested actions itself, bypassing the cap
    the shared stage applies, and nothing cleared a superseded run's outstanding
    suggestions. 215,904 rows, 76 MB.
  * A run that failed left its AI adjudications behind, and 760 of them belong to
    a run record that no longer exists at all.
  * A run that failed partway through profiling left its profiles in place, so a
    case can hold behavioural baselines that no finished analysis produced. Those
    are not deleted - they are the only baselines the case has - but the case is
    reported as wanting a re-analysis.

Reporting and deleting are separate deliberately: this decides what is garbage
from the state of the run that produced it, and a run that is merely slow to
finalize must not have its working data pulled out from under it. Nothing here
runs on a schedule.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from models.database import db

logger = logging.getLogger(__name__)

# A run in one of these has stopped, so nothing will come back for its data.
TERMINAL_STATUSES = ('complete', 'partial', 'failed', 'cancelled')

# Deleting hundreds of thousands of rows in one statement holds locks for as long
# as it takes; the batches keep each transaction short.
DEFAULT_BATCH_SIZE = 10000


def _delete_in_batches(model, criteria, batch_size: int, apply: bool) -> int:
    """Delete rows matching `criteria`, committing as it goes."""
    total = model.query.filter(*criteria).count()
    if not apply or not total:
        return total

    removed = 0
    while True:
        ids = [
            row.id for row in
            model.query.filter(*criteria).with_entities(model.id).limit(batch_size).all()
        ]
        if not ids:
            break
        model.query.filter(model.id.in_(ids)).delete(synchronize_session=False)
        db.session.commit()
        removed += len(ids)
    return removed


def _staged_candidate_events(batch_size: int, apply: bool) -> Dict[str, Any]:
    """Candidate events staged by a run that has since stopped.

    These are working data for one pattern-analysis pass and carry no findings.
    """
    from models.rag import CandidateEventSet
    from models.behavioral_profiles import CaseAnalysisRun

    finished = [
        run.analysis_id for run in
        CaseAnalysisRun.query.filter(
            CaseAnalysisRun.status.in_(TERMINAL_STATUSES)
        ).with_entities(CaseAnalysisRun.analysis_id).all()
    ]

    # A row whose run record is gone is stranded too, and cannot be matched by
    # analysis_id against a list of runs that no longer contains it.
    live = [
        run.analysis_id for run in
        CaseAnalysisRun.query.filter(
            ~CaseAnalysisRun.status.in_(TERMINAL_STATUSES)
        ).with_entities(CaseAnalysisRun.analysis_id).all()
    ]

    criteria = [~CandidateEventSet.analysis_id.in_(live)] if live else []
    count = _delete_in_batches(CandidateEventSet, criteria, batch_size, apply)
    return {
        'rows': count,
        'from_finished_runs': len(finished),
        'protected_runs': len(live),
    }


def _unfinished_run_ids() -> List[str]:
    from models.behavioral_profiles import CaseAnalysisRun

    return [
        run.analysis_id for run in
        CaseAnalysisRun.query.filter(
            CaseAnalysisRun.status.in_(('failed', 'cancelled'))
        ).with_entities(CaseAnalysisRun.analysis_id).all()
    ]


def _current_run_ids() -> List[str]:
    """The newest run of each case, whatever became of it."""
    from models.behavioral_profiles import CaseAnalysisRun
    from sqlalchemy import func

    latest_per_case = db.session.query(
        func.max(CaseAnalysisRun.id).label('id')
    ).group_by(CaseAnalysisRun.case_id).subquery()

    return [
        run.analysis_id for run in
        CaseAnalysisRun.query.filter(
            CaseAnalysisRun.id.in_(db.session.query(latest_per_case.c.id))
        ).with_entities(CaseAnalysisRun.analysis_id).all()
    ]


def _actions_from_failed_runs(batch_size: int, apply: bool) -> Dict[str, Any]:
    """Outstanding suggestions from a run that failed or was cancelled.

    The run never reached a conclusion, so these are not a queue of work but the
    residue of a partial pass. Reported separately from the superseded category
    because a failed run may still be the newest one its case has.
    """
    from models.behavioral_profiles import SuggestedAction

    unfinished = _unfinished_run_ids()
    if not unfinished:
        return {'rows': 0, 'runs': 0}

    criteria = [
        SuggestedAction.status == 'pending',
        SuggestedAction.analysis_id.in_(unfinished),
    ]
    count = _delete_in_batches(SuggestedAction, criteria, batch_size, apply)
    return {'rows': count, 'runs': len(unfinished)}


def _superseded_suggested_actions(batch_size: int, apply: bool) -> Dict[str, Any]:
    """Outstanding suggestions from a run that a later run has replaced.

    Only `pending` rows. Anything accepted, rejected or deferred records what the
    analyst decided and is kept regardless of which run raised it.

    Excludes runs that failed, which the previous category already accounts for -
    the two overlap otherwise, and a report whose categories double-count cannot
    be added up.
    """
    from models.behavioral_profiles import SuggestedAction

    current = _current_run_ids()
    criteria = [SuggestedAction.status == 'pending']
    if current:
        criteria.append(~SuggestedAction.analysis_id.in_(current))

    unfinished = _unfinished_run_ids()
    if unfinished:
        criteria.append(~SuggestedAction.analysis_id.in_(unfinished))

    count = _delete_in_batches(SuggestedAction, criteria, batch_size, apply)
    return {'rows': count, 'current_runs_kept': len(current)}


def _ai_results_without_a_run(batch_size: int, apply: bool) -> Dict[str, Any]:
    """AI adjudications whose run record no longer exists.

    Nothing can present these: every reader reaches them through a run.
    """
    from models.behavioral_profiles import CaseAnalysisRun
    from models.rag import AIAnalysisResult

    known = [
        run.analysis_id for run in
        CaseAnalysisRun.query.with_entities(CaseAnalysisRun.analysis_id).all()
    ]
    criteria = [~AIAnalysisResult.analysis_id.in_(known)] if known else []
    count = _delete_in_batches(AIAnalysisResult, criteria, batch_size, apply)
    return {'rows': count, 'known_runs': len(known)}


# Ordered so that each category excludes the rows an earlier one claims, which is
# what makes the reported totals addable.
CATEGORIES = {
    'staged_candidate_events': _staged_candidate_events,
    'actions_from_failed_runs': _actions_from_failed_runs,
    'superseded_suggested_actions': _superseded_suggested_actions,
    'ai_results_without_a_run': _ai_results_without_a_run,
}


def cases_wanting_reanalysis() -> List[Dict[str, Any]]:
    """Cases whose behavioural baselines no finished run produced.

    Profiles are cleared at the start of every run and rebuilt during profiling,
    so a run that failed after that point leaves the case holding baselines from
    an analysis that never reached a conclusion. The peer groups those baselines
    feed, and every anomaly score derived from them, are only as trustworthy as
    the run that stopped.
    """
    from models.behavioral_profiles import (
        CaseAnalysisRun, PeerGroup, SystemBehaviorProfile, UserBehaviorProfile,
    )

    wanting = []
    case_ids = [
        row.case_id for row in
        db.session.query(CaseAnalysisRun.case_id).distinct().all()
    ]
    for case_id in sorted(case_ids):
        latest = CaseAnalysisRun.query.filter_by(case_id=case_id).order_by(
            CaseAnalysisRun.id.desc()
        ).first()
        if not latest or latest.status not in ('failed', 'cancelled'):
            continue
        wanting.append({
            'case_id': case_id,
            'latest_run': latest.analysis_id,
            'latest_status': latest.status,
            'user_profiles': UserBehaviorProfile.query.filter_by(case_id=case_id).count(),
            'system_profiles': SystemBehaviorProfile.query.filter_by(case_id=case_id).count(),
            'peer_groups': PeerGroup.query.filter_by(case_id=case_id).count(),
        })
    return wanting


def reclaim(
    *,
    categories: Optional[List[str]] = None,
    apply: bool = False,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> Dict[str, Any]:
    """Report, and optionally delete, analysis data no run stands behind.

    `apply` defaults to false so the counts can be read before anything is
    removed.
    """
    selected = categories or list(CATEGORIES)
    unknown = [name for name in selected if name not in CATEGORIES]
    if unknown:
        raise ValueError(f"Unknown categories: {', '.join(sorted(unknown))}")

    results: Dict[str, Any] = {}
    for name in selected:
        try:
            results[name] = CATEGORIES[name](batch_size, apply)
        except Exception as exc:
            db.session.rollback()
            logger.exception('[Reclaim] %s failed', name)
            results[name] = {'rows': 0, 'error': str(exc)}

    return {
        'applied': apply,
        'categories': results,
        'total_rows': sum(entry.get('rows', 0) for entry in results.values()),
        'reanalysis_recommended': cases_wanting_reanalysis(),
    }
