"""Tests for the stale analysis run watchdog.

Staleness was only evaluated when a user loaded the analysis page for the case, so
a run whose worker died stayed in a running state indefinitely. Because the start
lock is held for the whole run, the case could not be analysed again until somebody
happened to visit it - and the page that would have noticed is the one the lock
blocks.

The care needed here is not to finalize a run that is merely slow. A phase can run
for an hour without reporting, and finalizing it while its worker is still writing
would leave two writers disagreeing about the outcome, so a run is only failed when
Celery confirms nothing is working on it.
"""

import importlib.util
import sys
import types
import unittest
from contextlib import contextmanager
from datetime import datetime, timedelta
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
    def __init__(self, analysis_id, case_id=1, minutes_idle=0,
                 status=_Status.ANALYZING):
        self.analysis_id = analysis_id
        self.case_id = case_id
        self.status = status
        self.current_phase = 'Analyzing'
        self.error_message = None
        self.completed_at = None
        self.last_progress_at = datetime.utcnow() - timedelta(minutes=minutes_idle)
        self._minutes_idle = minutes_idle

    def is_stale(self, stale_after_minutes=20):
        if self.status not in _Status.running_statuses():
            return False
        return self._minutes_idle > stale_after_minutes


class _Query:
    def __init__(self, runs):
        self._runs = runs
        self._deleted = 0

    def filter(self, *_args):
        return self

    def filter_by(self, **_kwargs):
        return self

    def all(self):
        return self._runs

    def delete(self):
        return self._deleted


@contextmanager
def _watchdog(runs, active_ids, inspect_raises=False, staged_rows=0):
    """Load the watchdog with stubbed models, keeping them installed while it runs.

    The watchdog imports its models inside the function, so the stubs have to
    survive the call rather than only the module load.
    """
    package = sys.modules.setdefault('utils', types.ModuleType('utils'))
    package.__path__ = [str(REPO_ROOT / 'utils')]

    released = []

    behavioral = types.ModuleType('models.behavioral_profiles')
    behavioral.AnalysisStatus = _Status
    behavioral.CaseAnalysisRun = types.SimpleNamespace(
        query=_Query(runs), status=types.SimpleNamespace(in_=lambda _values: None)
    )

    database = types.ModuleType('models.database')
    database.db = types.SimpleNamespace(
        session=types.SimpleNamespace(commit=lambda: None, rollback=lambda: None)
    )

    candidate_query = _Query([])
    candidate_query._deleted = staged_rows
    rag = types.ModuleType('models.rag')
    rag.CandidateEventSet = types.SimpleNamespace(query=candidate_query)

    lock = types.ModuleType('utils.analysis_run_lock')
    lock.release_start_lock = lambda case_id, analysis_id=None: released.append(
        (case_id, analysis_id)
    )

    def _inspect():
        if inspect_raises:
            raise RuntimeError('celery unreachable')
        return active_ids

    stubs = {
        'models.behavioral_profiles': behavioral,
        'models.database': database,
        'models.rag': rag,
        'utils.analysis_run_lock': lock,
    }
    saved = {name: sys.modules.get(name) for name in stubs}
    sys.modules.update(stubs)
    try:
        spec = importlib.util.spec_from_file_location(
            'analysis_watchdog_under_test', REPO_ROOT / 'utils' / 'analysis_watchdog.py'
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module._active_analysis_ids = _inspect
        yield module, released
    finally:
        for name, previous in saved.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous


class SweepTestCase(unittest.TestCase):
    def test_a_run_still_progressing_is_left_alone(self):
        run = _Run('a' * 36, minutes_idle=2)
        with _watchdog([run], active_ids=set()) as (watchdog, released):
            result = watchdog.sweep_stale_analysis_runs()

        self.assertEqual(result['stale'], 0)
        self.assertEqual(run.status, _Status.ANALYZING)
        self.assertEqual(released, [])

    def test_an_abandoned_run_is_failed(self):
        run = _Run('a' * 36, minutes_idle=45)
        with _watchdog([run], active_ids=set()) as (watchdog, _released):
            result = watchdog.sweep_stale_analysis_runs()

        self.assertEqual(result['failed'], 1)
        self.assertEqual(run.status, _Status.FAILED)
        self.assertIsNotNone(run.completed_at)

    def test_an_abandoned_run_releases_its_lock(self):
        """Otherwise the case can never be analysed again."""
        run = _Run('a' * 36, case_id=7, minutes_idle=45)
        with _watchdog([run], active_ids=set()) as (watchdog, released):
            watchdog.sweep_stale_analysis_runs()

        self.assertEqual(released, [(7, 'a' * 36)])

    def test_an_abandoned_run_has_its_staged_events_discarded(self):
        run = _Run('a' * 36, minutes_idle=45)
        with _watchdog([run], active_ids=set(), staged_rows=1200) as (watchdog, _released):
            result = watchdog.sweep_stale_analysis_runs()

        self.assertEqual(result['staged_events_reclaimed'], 1200)

    def test_a_slow_but_live_run_is_refreshed_not_failed(self):
        """A phase can run an hour without reporting."""
        run = _Run('a' * 36, minutes_idle=45)
        with _watchdog([run], active_ids={'a' * 36}) as (watchdog, released):
            result = watchdog.sweep_stale_analysis_runs()

        self.assertEqual(result['refreshed'], 1)
        self.assertEqual(result['failed'], 0)
        self.assertEqual(run.status, _Status.ANALYZING)
        self.assertEqual(released, [], msg='a live run must keep its lock')

    def test_nothing_is_failed_when_celery_cannot_be_inspected(self):
        """Without a reliable view of the workers, doing nothing is correct."""
        run = _Run('a' * 36, minutes_idle=45)
        with _watchdog([run], active_ids=set(), inspect_raises=True) as (watchdog, released):
            result = watchdog.sweep_stale_analysis_runs()

        self.assertEqual(result['failed'], 0)
        self.assertEqual(run.status, _Status.ANALYZING)
        self.assertEqual(released, [])

    def test_a_finished_run_is_never_considered(self):
        run = _Run('a' * 36, minutes_idle=999, status=_Status.COMPLETE)
        with _watchdog([run], active_ids=set()) as (watchdog, _released):
            result = watchdog.sweep_stale_analysis_runs()

        self.assertEqual(result['stale'], 0)
        self.assertEqual(run.status, _Status.COMPLETE)


class ScheduleTestCase(unittest.TestCase):
    def test_the_sweep_is_on_the_beat_schedule(self):
        source = (REPO_ROOT / 'tasks' / 'celery_tasks.py').read_text()

        self.assertIn('sweep-stale-analysis-runs', source)
        self.assertIn('tasks.sweep_stale_analysis_runs', source)

    def test_the_task_exists(self):
        source = (REPO_ROOT / 'tasks' / 'rag_tasks.py').read_text()

        self.assertIn("name='tasks.sweep_stale_analysis_runs'", source)


if __name__ == '__main__':
    unittest.main()
