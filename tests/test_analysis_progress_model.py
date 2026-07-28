"""Tests for the single progress and status model.

Progress used to be defined in three disagreeing places. The orchestrator mapped
its phases onto 0-100, the parallel path mapped its wave onto 0-50 and the tail
onto the same scale, and each phase task reported its own 0-100 into Celery task
state, which the status endpoint does not read. The visible effects were a bar
that jumped backwards, a run that appeared frozen for the whole of profiling and
correlation, and two run statuses - `profiling` and `correlating` - that were
never reached, because only the orchestrator set the status and by the time it ran
anything those phases had already happened elsewhere.

The other behaviour pinned here is which failures make a run incomplete. Any
phase reporting failure used to degrade the run to `partial`, including the AI
checkpoints falling back to their rule-based path and enrichment when OpenCTI is
unreachable. A deployment without AI configured completes cleanly, so the same
analysis on a deployment whose model was briefly unreachable must not be
reported as missing results.
"""

import importlib.util
import sys
import types
import unittest
from datetime import datetime
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


class _Status:
    PENDING = 'pending'
    PROFILING = 'profiling'
    CORRELATING = 'correlating'
    ANALYZING = 'analyzing'
    PARTIAL = 'partial'
    COMPLETE = 'complete'
    FAILED = 'failed'
    CANCELLED = 'cancelled'

    @classmethod
    def running_statuses(cls):
        return (cls.PENDING, cls.PROFILING, cls.CORRELATING, cls.ANALYZING)

    @classmethod
    def terminal_statuses(cls):
        return (cls.PARTIAL, cls.COMPLETE, cls.FAILED, cls.CANCELLED)


class _Run:
    """Stand-in for CaseAnalysisRun carrying only the progress fields."""

    def __init__(self, status=_Status.PENDING, progress_percent=0):
        self.analysis_id = 'run-1'
        self.status = status
        self.progress_percent = progress_percent
        self.current_phase = None
        self.last_progress_at = None
        self.profiling_started_at = None
        self.correlation_started_at = None
        self.ai_analysis_started_at = None


def _load(module_name, relative_path):
    package = sys.modules.setdefault('utils', types.ModuleType('utils'))
    package.__path__ = [str(REPO_ROOT / 'utils')]

    stubs = {
        'models.behavioral_profiles': types.SimpleNamespace(AnalysisStatus=_Status),
        'models.database': types.SimpleNamespace(
            db=types.SimpleNamespace(
                session=types.SimpleNamespace(commit=lambda: None, rollback=lambda: None)
            )
        ),
    }
    saved = {name: sys.modules.get(name) for name in stubs}
    sys.modules.update(stubs)
    try:
        spec = importlib.util.spec_from_file_location(
            module_name, REPO_ROOT / relative_path
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        for name, previous in saved.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous


phases = _load('analysis_phases_under_test', 'utils/analysis_phases.py')
sys.modules['utils.analysis_phases'] = phases
progress = _load('analysis_progress_under_test', 'utils/analysis_progress.py')


class PhaseSpanTestCase(unittest.TestCase):
    def test_the_spans_cover_zero_to_one_hundred_without_gaps_or_overlap(self):
        """The tail phases partition the run; wave 1's two phases share a span."""
        sequential = [
            'gap_detection', 'pattern_analysis', 'ioc_timeline', 'incident_storylines',
            'ai_triage', 'opencti_enrichment', 'ai_synthesis', 'suggested_actions',
            'finalizing',
        ]
        boundary = phases.PHASE_SPANS['gap_detection'][0]
        for name in sequential:
            start, end = phases.PHASE_SPANS[name]
            self.assertEqual(
                start, boundary, msg=f'{name} does not start where the previous phase ended'
            )
            self.assertGreater(end, start, msg=f'{name} has an empty span')
            boundary = end

        self.assertEqual(boundary, 100)

    def test_wave_one_phases_share_the_span_before_gap_detection(self):
        """They run concurrently, so neither can own a range of its own."""
        gap_start = phases.PHASE_SPANS['gap_detection'][0]
        for name in ('profile_cluster', 'hayabusa_correlation'):
            start, end = phases.PHASE_SPANS[name]
            self.assertEqual(start, 0)
            self.assertEqual(end, gap_start)

    def test_a_fraction_maps_into_the_phase_span(self):
        start, end = phases.PHASE_SPANS['pattern_analysis']
        self.assertEqual(phases.phase_progress('pattern_analysis', 0.0), start)
        self.assertEqual(phases.phase_progress('pattern_analysis', 1.0), end)
        self.assertEqual(
            phases.phase_progress('pattern_analysis', 0.5), (start + end) // 2
        )

    def test_an_out_of_range_fraction_is_held_inside_the_span(self):
        start, end = phases.PHASE_SPANS['pattern_analysis']
        self.assertEqual(phases.phase_progress('pattern_analysis', -1.0), start)
        self.assertEqual(phases.phase_progress('pattern_analysis', 5.0), end)

    def test_an_unknown_phase_cannot_move_the_bar(self):
        self.assertIsNone(phases.phase_progress('not_a_phase', 0.5))

    def test_every_phase_with_a_span_has_a_status(self):
        for name in phases.PHASE_SPANS:
            if name == 'complete':
                continue
            self.assertIsNotNone(
                phases.phase_status(name), msg=f'{name} would leave the run status stale'
            )


class MonotonicProgressTestCase(unittest.TestCase):
    def test_progress_advances(self):
        run = _Run()
        progress.record_analysis_progress(run, phase='pattern_analysis', percent=60)
        self.assertEqual(run.progress_percent, 60)

    def test_progress_never_goes_backwards(self):
        """Two concurrent phases each report their own position."""
        run = _Run()
        progress.record_analysis_progress(run, phase='gap_detection', percent=45)
        progress.record_analysis_progress(run, phase='profile_cluster', percent=10)

        self.assertEqual(
            run.progress_percent, 45, msg='a late update from a slower phase moved the bar back'
        )

    def test_progress_is_capped_at_one_hundred(self):
        run = _Run()
        progress.record_analysis_progress(run, phase='finalizing', percent=250)
        self.assertEqual(run.progress_percent, 100)

    def test_an_absolute_percent_is_held_inside_its_phase(self):
        """Call sites carried numbers belonging to other phases."""
        run = _Run()
        progress.record_analysis_progress(run, phase='ioc_timeline', percent=88)

        start, end = phases.PHASE_SPANS['ioc_timeline']
        self.assertLessEqual(run.progress_percent, end)
        self.assertGreaterEqual(run.progress_percent, start)

    def test_a_finished_run_is_not_revived(self):
        run = _Run(status=_Status.COMPLETE, progress_percent=100)
        self.assertFalse(
            progress.record_analysis_progress(run, phase='gap_detection', percent=40)
        )
        self.assertEqual(run.status, _Status.COMPLETE)
        self.assertEqual(run.progress_percent, 100)

    def test_a_cancelled_run_is_not_revived(self):
        run = _Run(status=_Status.CANCELLED, progress_percent=30)
        self.assertFalse(
            progress.record_analysis_progress(run, phase='pattern_analysis', percent=60)
        )
        self.assertEqual(run.status, _Status.CANCELLED)


class ReachableStatusTestCase(unittest.TestCase):
    def test_profiling_status_is_reached(self):
        run = _Run()
        progress.record_analysis_progress(run, phase='profile_cluster', fraction=0.1)
        self.assertEqual(run.status, _Status.PROFILING)

    def test_correlating_status_is_reached(self):
        run = _Run(status=_Status.PROFILING)
        progress.record_analysis_progress(run, phase='hayabusa_correlation', fraction=0.1)
        self.assertEqual(run.status, _Status.CORRELATING)

    def test_the_status_does_not_move_backwards(self):
        """Wave 1's phases run at once, so both statuses are proposed together."""
        run = _Run()
        progress.record_analysis_progress(run, phase='hayabusa_correlation', fraction=0.5)
        self.assertEqual(run.status, _Status.CORRELATING)

        progress.record_analysis_progress(run, phase='profile_cluster', fraction=0.9)
        self.assertEqual(
            run.status, _Status.CORRELATING, msg='the status regressed to an earlier phase'
        )

    def test_phase_timestamps_are_stamped_once(self):
        run = _Run()
        progress.record_analysis_progress(run, phase='profiling', fraction=0.1)
        first = run.profiling_started_at
        self.assertIsInstance(first, datetime)

        progress.record_analysis_progress(run, phase='profiling', fraction=0.9)
        self.assertEqual(run.profiling_started_at, first)

    def test_correlation_and_analysis_timestamps_are_stamped(self):
        run = _Run()
        progress.record_analysis_progress(run, phase='hayabusa_correlation', fraction=0.1)
        self.assertIsInstance(run.correlation_started_at, datetime)

        progress.record_analysis_progress(run, phase='pattern_analysis', fraction=0.1)
        self.assertIsInstance(run.ai_analysis_started_at, datetime)


class OptionalPhaseTestCase(unittest.TestCase):
    def test_the_ai_checkpoints_and_enrichment_are_optional(self):
        for name in ('ai_triage', 'ai_synthesis', 'opencti_enrichment'):
            with self.subTest(phase=name):
                self.assertTrue(phases.is_optional(name))

    def test_the_deterministic_phases_are_required(self):
        for name in ('profile_cluster', 'gap_detection', 'hayabusa_correlation',
                     'pattern_analysis', 'ioc_timeline', 'suggested_actions'):
            with self.subTest(phase=name):
                self.assertFalse(
                    phases.is_optional(name),
                    msg=f'{name} failing must mean the analysis is incomplete',
                )


class DegradedReasonsTestCase(unittest.TestCase):
    """Exercised against the real analyzer methods, unbound from any instance."""

    def setUp(self):
        source = (REPO_ROOT / 'utils' / 'case_analyzer.py').read_text()
        self.source = source

    def test_degraded_reasons_skip_optional_phases(self):
        self.assertIn('not is_optional(phase)', self.source)

    def test_optional_failures_are_still_reported(self):
        self.assertIn('_unavailable_capabilities', self.source)

    def test_the_capabilities_reach_the_summary(self):
        finalize = (REPO_ROOT / 'pipeline' / 'case_finalize.py').read_text()
        self.assertIn('unavailable_capabilities', finalize)

    def test_the_status_endpoint_exposes_them(self):
        routes = (REPO_ROOT / 'routes' / 'analysis.py').read_text()
        self.assertIn("response['unavailable_capabilities']", routes)


if __name__ == '__main__':
    unittest.main()
