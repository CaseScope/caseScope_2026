"""Contract tests for how the analysis phases are dispatched.

Three defects in the previous orchestration are pinned here.

Gap detection ran alongside profiling. All three gap detectors read the
behavioural profiles and peer groups that profiling writes, and run
initialisation deletes the previous run's profiles before profiling starts, so
the behavioural anomaly detector queried a table that was empty at the moment it
looked. It now runs in the phase after profiling has finished.

The orchestrator blocked waiting for its own children. It held a worker slot in a
polling loop while three child tasks needed slots on the same queue, which
deadlocks whenever concurrency is at or below the number of children.

Cancelling a run restarted it. The polling loop's `except Exception` caught
`AnalysisCancelled` and `SoftTimeLimitExceeded` - both ordinary Exception
subclasses - and responded by running all of phases 1 to 4 again in process. So
pressing cancel began the work afresh, and hitting the soft time limit
guaranteed hitting the hard one.
"""

import ast
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
CASE_ANALYZER = REPO_ROOT / 'utils' / 'case_analyzer.py'
RAG_TASKS = REPO_ROOT / 'tasks' / 'rag_tasks.py'
ROUTES = REPO_ROOT / 'routes' / 'analysis.py'


def _function(source_path: Path, name: str):
    tree = ast.parse(source_path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    raise AssertionError(f'{name} not found in {source_path.name}')


def _handled_exception_names(node) -> set:
    names = set()
    for handler in [n for n in ast.walk(node) if isinstance(n, ast.ExceptHandler)]:
        target = handler.type
        if target is None:
            names.add('bare')
        elif isinstance(target, ast.Name):
            names.add(target.id)
        elif isinstance(target, ast.Tuple):
            names.update(
                element.id for element in target.elts if isinstance(element, ast.Name)
            )
    return names


def _calls_in(node) -> set:
    calls = set()
    for inner in ast.walk(node):
        if not isinstance(inner, ast.Call):
            continue
        func = inner.func
        if isinstance(func, ast.Name):
            calls.add(func.id)
        elif isinstance(func, ast.Attribute):
            calls.add(func.attr)
    return calls


class DispatcherTestCase(unittest.TestCase):
    def setUp(self):
        self.dispatcher = _function(RAG_TASKS, 'run_case_analysis')
        self.source = RAG_TASKS.read_text()

    def test_the_dispatcher_does_not_run_the_analysis_itself(self):
        calls = _calls_in(self.dispatcher)

        self.assertNotIn(
            'run_full_analysis',
            calls,
            msg='the dispatching task must not occupy a worker slot for the whole run',
        )

    def test_the_dispatcher_never_waits_on_its_children(self):
        calls = _calls_in(self.dispatcher)

        for blocking in ('sleep', 'ready', 'join', 'allow_join_result'):
            self.assertNotIn(
                blocking,
                calls,
                msg=(
                    f'{blocking} in the dispatcher reintroduces the deadlock: it holds '
                    'a worker slot while its children queue for one'
                ),
            )

    def test_the_dispatcher_uses_a_chord(self):
        self.assertIn('chord(', self.source)
        self.assertIn('begin_analysis', _calls_in(self.dispatcher))

    def test_the_dispatcher_claims_the_start_lock_before_dispatching(self):
        calls = _calls_in(self.dispatcher)
        self.assertIn('acquire_start_lock', calls)

    def test_a_lost_phase_task_is_finalized(self):
        """A worker killed mid-phase would otherwise leave the run running forever."""
        self.assertIn('on_error(', self.source)
        handler = _function(RAG_TASKS, 'analysis_dispatch_failed')
        self.assertIn('_mark_failed', _calls_in(handler))
        self.assertIn('release_start_lock', _calls_in(handler))


class WaveCompositionTestCase(unittest.TestCase):
    def setUp(self):
        self.source = RAG_TASKS.read_text()
        self.dispatcher = _function(RAG_TASKS, 'run_case_analysis')

    def test_wave_one_is_profiling_and_correlation_only(self):
        dispatched = ast.dump(self.dispatcher)

        self.assertIn('analyze_phase_profile', dispatched)
        self.assertIn('analyze_phase_hayabusa', dispatched)

    def test_gap_detection_is_not_in_wave_one(self):
        """It reads what profiling writes, so it cannot run beside it."""
        self.assertNotIn('analyze_phase_gaps', self.source)

    def test_the_callback_runs_gap_detection_then_the_tail(self):
        resume = _function(CASE_ANALYZER, 'resume_from_baselines')
        body = ast.dump(resume)

        self.assertIn('_absorb_wave_results', body)
        self.assertIn('_run_gap_detection_phase', body)
        self.assertIn('_run_tail_phases', body)

    def test_wave_tasks_stop_early_when_cancellation_was_requested(self):
        for task_name in ('analyze_phase_profile', 'analyze_phase_hayabusa'):
            with self.subTest(task=task_name):
                task = _function(RAG_TASKS, task_name)
                self.assertIn('_wave_cancelled_result', _calls_in(task))


class CancellationPropagationTestCase(unittest.TestCase):
    """Cancellation and the soft time limit must end the run, not restart it."""

    def test_absorbing_results_does_not_re_run_the_phases(self):
        absorb = _function(CASE_ANALYZER, '_absorb_wave_results')
        calls = _calls_in(absorb)

        self.assertNotIn(
            '_run_phases_sequential',
            calls,
            msg=(
                'falling back to a sequential re-run is what turned a cancellation '
                'into a fresh start and a soft time limit into a hard one'
            ),
        )

    def test_absorbing_results_swallows_nothing(self):
        absorb = _function(CASE_ANALYZER, '_absorb_wave_results')

        self.assertEqual(
            _handled_exception_names(absorb),
            set(),
            msg='a generic handler here is how cancellation was turned into a re-run',
        )

    def test_cancellation_is_handled_before_the_generic_handler(self):
        for entry_point in ('run_full_analysis', 'resume_from_baselines'):
            with self.subTest(entry_point=entry_point):
                node = _function(CASE_ANALYZER, entry_point)
                handled = [
                    handler.type.id
                    for handler in [n for n in ast.walk(node) if isinstance(n, ast.ExceptHandler)]
                    if isinstance(handler.type, ast.Name)
                ]

                self.assertIn('AnalysisCancelled', handled)
                self.assertIn('SoftTimeLimitExceeded', handled)
                self.assertLess(
                    handled.index('AnalysisCancelled'),
                    handled.index('Exception'),
                    msg='AnalysisCancelled subclasses Exception, so it must be caught first',
                )
                self.assertLess(
                    handled.index('SoftTimeLimitExceeded'),
                    handled.index('Exception'),
                    msg='SoftTimeLimitExceeded subclasses Exception, so it must be caught first',
                )

    def test_cancellation_re_raises_rather_than_returning(self):
        for entry_point in ('run_full_analysis', 'resume_from_baselines'):
            with self.subTest(entry_point=entry_point):
                node = _function(CASE_ANALYZER, entry_point)
                for handler in [n for n in ast.walk(node) if isinstance(n, ast.ExceptHandler)]:
                    if isinstance(handler.type, ast.Name) and handler.type.id == 'AnalysisCancelled':
                        self.assertTrue(
                            any(isinstance(stmt, ast.Raise) for stmt in handler.body),
                            msg='a cancelled run must not be reported as a success',
                        )

    def test_both_entry_points_clear_the_cancellation_token(self):
        for entry_point in ('run_full_analysis', 'resume_from_baselines'):
            with self.subTest(entry_point=entry_point):
                node = _function(CASE_ANALYZER, entry_point)
                self.assertIn('clear_cancellation', _calls_in(node))


class StartLockTestCase(unittest.TestCase):
    def setUp(self):
        self.source = ROUTES.read_text()

    def test_the_route_reports_a_conflict_when_the_case_is_locked(self):
        start = _function(ROUTES, 'start_analysis')
        self.assertIn('current_lock_holder', _calls_in(start))

    def test_abandoning_a_stale_run_frees_the_case(self):
        stale = _function(ROUTES, '_mark_run_stale')
        self.assertIn('release_start_lock', _calls_in(stale))

    def test_cancelling_revokes_the_queued_tasks(self):
        """The token alone only stops work at a phase boundary."""
        cancel = _function(ROUTES, 'cancel_analysis')
        self.assertIn('_revoke_analysis_tasks', _calls_in(cancel))

        revoke = _function(ROUTES, '_revoke_analysis_tasks')
        self.assertIn('revoke', _calls_in(revoke))

    def test_revocation_does_not_terminate_a_running_task(self):
        """Killing a worker mid-write leaves persisted findings half-committed."""
        revoke = _function(ROUTES, '_revoke_analysis_tasks')
        source = ast.get_source_segment(ROUTES.read_text(), revoke) or ''
        self.assertIn('terminate=False', source)


class LivenessTestCase(unittest.TestCase):
    """The staleness check must recognise every task that carries a run forward."""

    def test_the_callback_task_counts_as_active(self):
        matcher = _function(ROUTES, '_active_task_matches_run')
        source = ast.get_source_segment(ROUTES.read_text(), matcher) or ''

        self.assertIn('tasks.analyze_after_baselines', source)
        self.assertIn('tasks.analyze_phase_profile', source)
        self.assertIn('tasks.analyze_phase_hayabusa', source)

    def test_the_deleted_task_is_no_longer_referenced(self):
        self.assertNotIn('tasks.analyze_phase_gaps', ROUTES.read_text())


if __name__ == '__main__':
    unittest.main()
