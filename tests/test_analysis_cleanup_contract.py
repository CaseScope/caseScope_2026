"""Tests for the dead code, legacy API and unbounded-load cleanup.

The substantive one here is the liveness check: it answered False whenever it
could not reach the workers, so a momentary broker hiccup while an analyst had the
page open was indistinguishable from the work having stopped, and failed a healthy
long-running analysis.
"""

import ast
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
CASE_ANALYZER = REPO_ROOT / 'utils/case_analyzer.py'
ANALYSIS_ROUTES = REPO_ROOT / 'routes/analysis.py'
FORMATTER = REPO_ROOT / 'utils/analysis_results_formatter.py'


def _function(path, name):
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    return None


def _source_of(path, name):
    node = _function(path, name)
    assert node is not None, f'{name} not found in {path.name}'
    return ast.get_source_segment(path.read_text(), node)


class DeadCodeTestCase(unittest.TestCase):
    def test_the_duplicated_action_deduplicator_is_gone(self):
        """It was a copy of the one in `pipeline/case_actions.py`, which is the
        one that runs, so the two could drift apart unnoticed."""
        self.assertIsNone(_function(CASE_ANALYZER, '_deduplicate_actions'))

    def test_the_deduplicator_that_runs_still_exists(self):
        actions = REPO_ROOT / 'pipeline/case_actions.py'
        self.assertIsNotNone(_function(actions, '_deduplicate_actions'))
        self.assertIn('_deduplicate_actions(actions)', actions.read_text())

    def test_the_superseded_timeline_callback_is_gone(self):
        """`pipeline/case_timeline.py` builds its own progress closure."""
        self.assertIsNone(_function(CASE_ANALYZER, '_ioc_timeline_progress_callback'))

    def test_no_call_site_referenced_either_of_them(self):
        source = CASE_ANALYZER.read_text()
        self.assertNotIn('_ioc_timeline_progress_callback', source)
        self.assertNotIn('self._deduplicate_actions', source)


class LivenessTestCase(unittest.TestCase):
    def test_an_uninspectable_celery_is_not_reported_as_idle(self):
        source = _source_of(ANALYSIS_ROUTES, '_analysis_has_active_celery_task')
        # Returns None on failure, which is a third answer distinct from False.
        self.assertIn('return None', source)
        self.assertNotIn('return False\n\n    for tasks', source)

    def test_no_worker_responding_is_also_not_idle(self):
        """`inspect().active()` returns None when no worker answers in time, and
        `or {}` turned that into an empty result - the same shape as a worker that
        answered with nothing running."""
        source = _source_of(ANALYSIS_ROUTES, '_analysis_has_active_celery_task')
        self.assertIn('if active_by_worker is None:', source)
        self.assertNotIn('inspector.active() or {}', source)

    def test_a_run_is_not_failed_when_liveness_is_unknown(self):
        source = _source_of(ANALYSIS_ROUTES, '_mark_stale_if_inactive')
        self.assertIn('if active is None:', source)
        # The unknown branch returns before reaching the code that fails the run.
        unknown = source[source.index('if active is None:'):]
        self.assertIn('return False', unknown[:unknown.index('_mark_run_stale')])

    def test_a_confirmed_idle_run_is_still_failed(self):
        source = _source_of(ANALYSIS_ROUTES, '_mark_stale_if_inactive')
        self.assertIn('_mark_run_stale(run)', source)

    def test_a_confirmed_active_run_still_gets_its_heartbeat_refreshed(self):
        source = _source_of(ANALYSIS_ROUTES, '_mark_stale_if_inactive')
        self.assertIn('_refresh_active_stale_run(run)', source)

    def test_the_scheduled_sweep_makes_the_same_distinction(self):
        watchdog = REPO_ROOT / 'utils/analysis_watchdog.py'
        source = _source_of(watchdog, 'sweep_stale_analysis_runs')
        self.assertIn('inspected = False', source)
        self.assertIn('if not inspected:', source)


class LegacyQueryTestCase(unittest.TestCase):
    def test_the_analysis_surfaces_use_the_current_lookup_api(self):
        """`Query.get()` is legacy in SQLAlchemy 2.0."""
        for path in (ANALYSIS_ROUTES, FORMATTER):
            with self.subTest(path=path.name):
                self.assertNotIn('.query.get(', path.read_text())

    def test_they_use_session_get_instead(self):
        for path in (ANALYSIS_ROUTES, FORMATTER):
            with self.subTest(path=path.name):
                self.assertIn('db.session.get(', path.read_text())


class BoundedLoadTestCase(unittest.TestCase):
    """Every view builds its whole payload in memory, so an unbounded load was
    bounded only by how noisy the case was."""

    def test_the_finding_loads_are_capped(self):
        for name in ('_load_gap_findings', '_load_pattern_results', '_load_suggested_actions'):
            with self.subTest(loader=name):
                source = _source_of(FORMATTER, name)
                self.assertIn('limit(self.MAX_ROWS_LOADED)', source)

    def test_the_cap_is_declared_once(self):
        source = FORMATTER.read_text()
        self.assertIn('MAX_ROWS_LOADED = 500', source)
        # No loader should carry its own hardcoded limit.
        self.assertNotIn('.limit(500)', source)

    def test_the_loads_are_ordered_so_the_cap_keeps_what_matters(self):
        for name, column in (
            ('_load_gap_findings', 'GapDetectionFinding.confidence.desc()'),
            ('_load_pattern_results', 'AIAnalysisResult.final_confidence.desc()'),
            ('_load_suggested_actions', 'SuggestedAction.confidence.desc()'),
        ):
            with self.subTest(loader=name):
                self.assertIn(column, _source_of(FORMATTER, name))

    def test_reported_counts_come_from_the_database_not_the_capped_list(self):
        """Otherwise capping the load silently understates a noisy case."""
        for name in ('_load_gap_findings', '_load_pattern_results', '_load_suggested_actions'):
            with self.subTest(loader=name):
                self.assertIn('query.count()', _source_of(FORMATTER, name))

        summary = _source_of(FORMATTER, 'get_summary')
        self.assertIn("self._counts.get('gap_findings'", summary)
        self.assertIn("self._counts.get('pattern_results'", summary)
        self.assertIn("self._counts.get('pending_actions'", summary)

    def test_the_count_is_recorded_even_when_there_is_no_run(self):
        """A missing count would fall back to the length of an empty list, which
        happens to be right, and would stop being right the moment the fallback
        changed."""
        for name in ('_load_gap_findings', '_load_pattern_results', '_load_suggested_actions'):
            with self.subTest(loader=name):
                source = _source_of(FORMATTER, name)
                self.assertIn('] = 0', source)


if __name__ == '__main__':
    unittest.main()
