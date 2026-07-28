"""One description of the analysis phases: their progress span and whether they matter.

Progress used to be defined in three places that disagreed. The orchestrator
mapped its own phases onto 0-100, the parallel path mapped its wave onto 0-50 and
then reported the tail on the same scale, and each phase task reported its own
0-100 into Celery task state. A run could therefore report 90 percent, then 5
percent, then 60, and the two phases that run concurrently overwrote each other's
numbers.

Every phase's span is declared here once, phases report progress within their own
span, and the run's percentage never decreases.

The second thing declared here is whether a phase failing means the analysis is
incomplete. Any phase reporting failure used to degrade the whole run to
`partial`, which included the AI checkpoints falling back to their rule-based
path and threat-intel enrichment when the OpenCTI service is unreachable. Those
are properties of what the deployment has available, not faults in the run: a
Mode A deployment does not attempt them at all and completes cleanly, while the
same analysis on a Mode B deployment with the model briefly unreachable was
reported as partial, telling the analyst results were missing when every
deterministic phase had in fact finished.
"""

from __future__ import annotations

from typing import Dict, Optional, Tuple

from models.behavioral_profiles import AnalysisStatus


# Phase name -> (start percent, end percent). Wave 1's two phases share a span
# because they run concurrently; progress is monotonic, so whichever is further
# along sets the number.
PHASE_SPANS: Dict[str, Tuple[int, int]] = {
    'profiling': (0, 25),
    'clustering': (25, 35),
    'profile_cluster': (0, 35),
    'hayabusa_correlation': (0, 35),
    'gap_detection': (35, 50),
    'pattern_analysis': (50, 78),
    'ioc_timeline': (78, 83),
    'incident_storylines': (83, 84),
    'ai_triage': (84, 88),
    'opencti_enrichment': (88, 91),
    'ai_synthesis': (91, 95),
    'suggested_actions': (95, 97),
    'finalizing': (97, 100),
    'complete': (100, 100),
}

# The status the run should carry while a phase is executing. Left unmapped, the
# `profiling` and `correlating` statuses were unreachable: the run went from
# `pending` straight to `analyzing`, because only the orchestrator set the status
# and by the time it ran anything those phases had happened in other tasks.
PHASE_STATUS: Dict[str, str] = {
    'profiling': AnalysisStatus.PROFILING,
    'clustering': AnalysisStatus.PROFILING,
    'profile_cluster': AnalysisStatus.PROFILING,
    'hayabusa_correlation': AnalysisStatus.CORRELATING,
    'gap_detection': AnalysisStatus.ANALYZING,
    'pattern_analysis': AnalysisStatus.ANALYZING,
    'ioc_timeline': AnalysisStatus.ANALYZING,
    'incident_storylines': AnalysisStatus.ANALYZING,
    'ai_triage': AnalysisStatus.ANALYZING,
    'opencti_enrichment': AnalysisStatus.ANALYZING,
    'ai_synthesis': AnalysisStatus.ANALYZING,
    'suggested_actions': AnalysisStatus.ANALYZING,
    'finalizing': AnalysisStatus.ANALYZING,
}

# Capabilities that a deployment may simply not have. Their absence is reported
# so the analyst knows what was skipped, but it does not make the run partial.
OPTIONAL_PHASES = frozenset({
    'ai_triage',
    'ai_synthesis',
    'opencti_enrichment',
})


def phase_progress(phase: str, fraction: float) -> Optional[int]:
    """Absolute run progress for a phase that is `fraction` of the way through.

    Returns None for a phase with no declared span, so an unrecognised name
    cannot silently move the bar.
    """
    span = PHASE_SPANS.get(phase)
    if span is None:
        return None

    start, end = span
    fraction = min(max(fraction, 0.0), 1.0)
    return int(round(start + (end - start) * fraction))


def phase_status(phase: str) -> Optional[str]:
    """The run status that corresponds to a phase being in progress."""
    return PHASE_STATUS.get(phase)


def is_optional(phase: str) -> bool:
    """Whether this phase failing leaves the analysis itself complete."""
    return phase in OPTIONAL_PHASES
