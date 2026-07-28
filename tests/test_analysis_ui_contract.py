"""Contract tests for the analysis page's reachable controls and rendered output.

Three defects motivate these: the cancel endpoint existed but nothing in the UI
called it, the AI triage and synthesis phases stored their output and no template
read it, and the suggested-action queue was the sum of every run ever performed
rather than the current one.
"""

import ast
import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
HUNTING_FUNCTIONS = REPO_ROOT / 'static/templates/case_hunting_functions.html'
ANALYSIS_RESULTS = REPO_ROOT / 'static/templates/case_analysis_results.html'
ANALYSIS_ROUTES = REPO_ROOT / 'routes/analysis.py'
CASE_ANALYZER = REPO_ROOT / 'utils/case_analyzer.py'
RESULTS_FORMATTER = REPO_ROOT / 'utils/analysis_results_formatter.py'
MAIN_CSS = REPO_ROOT / 'static/css/main.css'


class CancelButtonTestCase(unittest.TestCase):
    """The cancel endpoint requests cooperative cancellation and revokes queued
    tasks, and was unreachable: no template referenced it, so a run could only be
    stopped by restarting the workers."""

    def setUp(self):
        self.template = HUNTING_FUNCTIONS.read_text()

    def test_the_cancel_endpoint_is_reachable_from_the_analysis_panel(self):
        self.assertIn('btnCancelBehaviorAnalysis', self.template)
        self.assertIn('/analysis/cancel', self.template)

    def test_the_button_posts_rather_than_gets(self):
        cancel_fn = self.template[self.template.index('function cancelBehaviorAnalysis'):]
        cancel_fn = cancel_fn[:cancel_fn.index('\n}')]
        self.assertIn("method: 'POST'", cancel_fn)

    def test_the_route_it_calls_exists_and_accepts_post(self):
        routes = ANALYSIS_ROUTES.read_text()
        self.assertIn(
            "@analysis_bp.route('/<int:case_id>/analysis/cancel', methods=['POST'])",
            routes,
        )

    def test_the_button_is_hidden_when_no_run_is_active(self):
        # Rendered hidden, revealed on start and while polling reports a running
        # status, hidden again when the run reaches a terminal state.
        self.assertRegex(
            self.template,
            r'id="btnCancelBehaviorAnalysis"[^>]*style="display: none;"',
        )
        reset = self.template[self.template.index('function resetBehaviorButton'):]
        reset = reset[:reset.index('\n}')]
        self.assertIn('setBehaviorCancelVisible(false)', reset)

    def test_the_button_is_shown_while_a_run_is_active(self):
        start = self.template[self.template.index('function startBehaviorPatternCreation'):]
        start = start[:start.index('\nfunction ')]
        self.assertIn('setBehaviorCancelVisible(true)', start)

        poll = self.template[self.template.index('function pollBehaviorProgress'):]
        poll = poll[:poll.index('\nfunction ')]
        self.assertIn('setBehaviorCancelVisible(behaviorAnalysisIsRunning(data.status))', poll)

    def test_running_statuses_are_defined_once(self):
        """The list was repeated at four call sites, so the statuses the chord
        rewrite made reachable had to be added to each of them."""
        literals = re.findall(
            r"\['pending', 'profiling', 'correlating', 'analyzing'\]", self.template
        )
        self.assertEqual(len(literals), 1)
        self.assertIn('BEHAVIOR_RUNNING_STATUSES', self.template)

    def test_the_cancel_button_uses_central_styling(self):
        self.assertRegex(
            self.template,
            r'class="btn btn-danger" id="btnCancelBehaviorAnalysis"',
        )
        self.assertIn('.btn-danger {', MAIN_CSS.read_text())


class NarrativeRenderingTestCase(unittest.TestCase):
    """`ai_triage` and `ai_synthesis` were computed, stored on the run summary,
    passed into this template by the view, and never read by it."""

    def setUp(self):
        self.template = ANALYSIS_RESULTS.read_text()

    def test_the_narrative_is_rendered(self):
        self.assertIn('summary.ai_synthesis', self.template)
        self.assertIn('summary.ai_triage', self.template)

    def test_every_field_the_checkpoints_produce_is_rendered(self):
        # Keys taken from the JSON contract the two checkpoint prompts specify.
        for field in (
            'executive_summary',
            'key_findings',
            'recommended_actions',
            'affected_assets',
            'confidence_assessment',
            'priority_findings',
            'investigation_threads',
            'notable_observations',
            'risk_assessment',
        ):
            with self.subTest(field=field):
                self.assertIn(field, self.template)

    def test_a_run_without_a_narrative_renders_no_empty_panel(self):
        self.assertIn('{% if summary.ai_synthesis or summary.ai_triage %}', self.template)

    def test_a_deterministic_narrative_is_labelled_as_one(self):
        """The checkpoints fall back to a rule-based narrative when the model is
        unreachable, and the plainer wording is otherwise indistinguishable from
        the model having little to say."""
        self.assertIn('analysis-narrative-fallback', self.template)
        self.assertIn("synthesis.get('fallback')", self.template)

    def test_the_view_supplies_what_the_template_reads(self):
        view = (REPO_ROOT / 'routes/main.py').read_text()
        self.assertIn("'ai_triage': analysis.summary.get('ai_triage')", view)
        self.assertIn("'ai_synthesis': analysis.summary.get('ai_synthesis')", view)

    def test_narrative_styling_lives_in_the_central_stylesheet(self):
        css = MAIN_CSS.read_text()
        for cls in (
            '.analysis-narrative-panel',
            '.analysis-narrative-summary',
            '.analysis-narrative-item',
            '.analysis-narrative-section-title',
            '.analysis-narrative-columns',
        ):
            with self.subTest(cls=cls):
                self.assertIn(cls + ' {', css)


class SuggestedActionScopeTestCase(unittest.TestCase):
    """The queue accumulated across runs: nothing cleared prior pending rows, and
    the endpoint filtered by status alone unless a caller passed an analysis_id."""

    def test_prior_pending_actions_are_cleared_when_a_run_starts(self):
        source = CASE_ANALYZER.read_text()
        clear = source[source.index('def _clear_previous_analysis_data'):]
        clear = clear[:clear.index('\n    def ')]
        self.assertIn('SuggestedAction.query.filter_by(', clear)
        self.assertIn("status='pending'", clear)
        self.assertIn('.delete()', clear)

    def test_actions_the_analyst_already_handled_are_kept(self):
        """They record a decision, so a re-run must not erase them."""
        source = CASE_ANALYZER.read_text()
        clear = source[source.index('def _clear_previous_analysis_data'):]
        clear = clear[:clear.index('\n    def ')]
        deletion = clear[clear.index('SuggestedAction.query'):]
        deletion = deletion[:deletion.index('.delete()')]
        self.assertIn("status='pending'", deletion)
        for handled in ('accepted', 'rejected', 'deferred'):
            self.assertNotIn(handled, deletion)

    def test_the_endpoint_scopes_to_the_latest_run_by_default(self):
        source = ANALYSIS_ROUTES.read_text()
        endpoint = source[source.index('def get_suggested_actions'):]
        endpoint = endpoint[:endpoint.index('\n@analysis_bp.route')]
        self.assertIn('CaseAnalysisRun.query.filter_by(case_id=case_id)', endpoint)
        self.assertIn('CaseAnalysisRun.id.desc()', endpoint)

    def test_every_run_can_still_be_requested_explicitly(self):
        source = ANALYSIS_ROUTES.read_text()
        endpoint = source[source.index('def get_suggested_actions'):]
        endpoint = endpoint[:endpoint.index('\n@analysis_bp.route')]
        self.assertIn("analysis_id == 'all'", endpoint)

    def test_the_response_states_which_run_it_scoped_to(self):
        source = ANALYSIS_ROUTES.read_text()
        endpoint = source[source.index('def get_suggested_actions'):]
        endpoint = endpoint[:endpoint.index('\n@analysis_bp.route')]
        self.assertIn("'analysis_id': analysis_id", endpoint)

    def test_the_formatter_returns_only_outstanding_actions(self):
        """Its docstring said pending, and it applied no status filter, so the
        analyst was offered work they had already dealt with."""
        source = RESULTS_FORMATTER.read_text()
        loader = source[source.index('def _load_suggested_actions'):]
        loader = loader[:loader.index('\n    def ')]
        self.assertIn("status='pending'", loader)


class QueueWriterTestCase(unittest.TestCase):
    def test_only_the_capped_stage_persists_suggested_actions(self):
        """Two writers existed; only one applied the cap. Any new writer that
        bypasses `pipeline/case_actions.py` reintroduces the accumulation."""
        writers = []
        for path in REPO_ROOT.glob('**/*.py'):
            if any(part in {'venv', 'tests', 'migrations', '__pycache__'} for part in path.parts):
                continue
            source = path.read_text(errors='ignore')
            if 'SuggestedAction(' not in source:
                continue
            try:
                tree = ast.parse(source)
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == 'SuggestedAction'
                ):
                    writers.append(str(path.relative_to(REPO_ROOT)))
                    break

        self.assertEqual(sorted(set(writers)), ['pipeline/case_actions.py'])


if __name__ == '__main__':
    unittest.main()
