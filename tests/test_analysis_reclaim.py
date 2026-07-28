"""Tests for reclaiming analysis data that no run stands behind.

The script decides what is garbage from the state of the run that produced it, so
the cases that matter are the ones where it must decide not to delete: a run still
in progress, the newest run of a case, and anything the analyst has acted on.
"""

import ast
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
RECLAIM = REPO_ROOT / 'utils/analysis_reclaim.py'
SCRIPT = REPO_ROOT / 'scripts/reclaim_analysis_data.py'


def _module():
    return ast.parse(RECLAIM.read_text())


def _function(name):
    for node in _module().body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f'{name} not found')


def _source_of(name):
    return ast.get_source_segment(RECLAIM.read_text(), _function(name))


def _body_of(name):
    """Source of a function with its docstring removed.

    The docstrings here describe which statuses are deliberately kept, so a
    substring check against the whole function matches the prose rather than the
    query it is describing.
    """
    source = RECLAIM.read_text()
    node = _function(name)
    body = node.body[1:] if ast.get_docstring(node) else node.body
    return '\n'.join(ast.get_source_segment(source, stmt) or '' for stmt in body)


class SafetyTestCase(unittest.TestCase):
    def test_nothing_is_deleted_unless_apply_is_passed(self):
        source = _source_of('_delete_in_batches')
        self.assertIn('if not apply', source)
        # The count is returned either way, so a report and a deletion agree on
        # what they are talking about.
        self.assertIn('return total', source)

    def test_the_entry_point_defaults_to_reporting(self):
        reclaim = _function('reclaim')
        defaults = dict(
            zip(
                [arg.arg for arg in reclaim.args.kwonlyargs],
                reclaim.args.kw_defaults,
            )
        )
        self.assertIsInstance(defaults['apply'], ast.Constant)
        self.assertFalse(defaults['apply'].value)

    def test_the_cli_defaults_to_reporting(self):
        source = SCRIPT.read_text()
        self.assertIn("'--apply'", source)
        self.assertIn("action='store_true'", source)
        self.assertNotIn('default=True', source)

    def test_a_run_still_in_progress_keeps_its_staged_events(self):
        """The most dangerous case: a slow run's working data must not be pulled
        out from under it."""
        source = _source_of('_staged_candidate_events')
        self.assertIn('~CandidateEventSet.analysis_id.in_(live)', source)
        self.assertIn('~CaseAnalysisRun.status.in_(TERMINAL_STATUSES)', source)

    def test_deletion_is_batched(self):
        """Deleting 775,968 rows in one statement holds locks for as long as it
        takes."""
        source = _source_of('_delete_in_batches')
        self.assertIn('limit(batch_size)', source)
        self.assertIn('db.session.commit()', source)

    def test_a_failing_category_does_not_abort_the_others(self):
        source = _source_of('reclaim')
        self.assertIn('db.session.rollback()', source)
        self.assertIn("'error': str(exc)", source)


class ScopeTestCase(unittest.TestCase):
    def test_only_outstanding_suggestions_are_removed(self):
        """Accepted, rejected and deferred rows record an analyst's decision."""
        for name in ('_actions_from_failed_runs', '_superseded_suggested_actions'):
            with self.subTest(category=name):
                body = _body_of(name)
                self.assertIn("SuggestedAction.status == 'pending'", body)
                for handled in ('accepted', 'rejected', 'deferred'):
                    self.assertNotIn(handled, body)

    def test_the_newest_run_of_a_case_is_kept(self):
        source = _source_of('_superseded_suggested_actions')
        self.assertIn('~SuggestedAction.analysis_id.in_(current)', source)

    def test_the_two_action_categories_do_not_overlap(self):
        """A failed run can also be a superseded one, and a report whose
        categories double-count cannot be added up."""
        source = _source_of('_superseded_suggested_actions')
        self.assertIn('~SuggestedAction.analysis_id.in_(unfinished)', source)

    def test_only_ai_results_whose_run_is_gone_are_removed(self):
        source = _source_of('_ai_results_without_a_run')
        self.assertIn('~AIAnalysisResult.analysis_id.in_(known)', source)

    def test_profiles_are_never_deleted(self):
        """They are the only behavioural baselines their case has, so a case with
        baselines from a run that stopped is reported, not emptied."""
        source = RECLAIM.read_text()
        for node in ast.walk(_module()):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr == 'delete':
                    segment = ast.get_source_segment(source, node) or ''
                    self.assertNotIn('BehaviorProfile', segment)
                    self.assertNotIn('PeerGroup', segment)

        recommend = _source_of('cases_wanting_reanalysis')
        self.assertNotIn('.delete()', recommend)
        self.assertIn('UserBehaviorProfile.query.filter_by(case_id=case_id).count()', recommend)


class ReportTestCase(unittest.TestCase):
    def test_an_unknown_category_is_rejected_rather_than_ignored(self):
        source = _source_of('reclaim')
        self.assertIn('raise ValueError', source)

    def test_reanalysis_is_recommended_only_for_runs_that_did_not_finish(self):
        source = _source_of('cases_wanting_reanalysis')
        self.assertIn("latest.status not in ('failed', 'cancelled')", source)

    def test_the_categories_the_cli_offers_are_the_ones_that_exist(self):
        script = SCRIPT.read_text()
        self.assertIn('choices=sorted(CATEGORIES)', script)


class NotScheduledTestCase(unittest.TestCase):
    def test_nothing_schedules_this(self):
        """Deleting is a decision for an operator, unlike the stale-run sweep,
        which only reclaims what a dead worker abandoned."""
        beat = (REPO_ROOT / 'tasks/celery_tasks.py').read_text()
        self.assertNotIn('analysis_reclaim', beat)
        self.assertNotIn('reclaim_analysis_data', beat)

        for path in (REPO_ROOT / 'tasks').glob('*.py'):
            with self.subTest(path=path.name):
                self.assertNotIn('analysis_reclaim', path.read_text())


if __name__ == '__main__':
    unittest.main()
