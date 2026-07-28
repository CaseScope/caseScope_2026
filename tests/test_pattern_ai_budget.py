"""Tests for the pattern-analysis AI budget.

Pattern analysis evaluates 48 patterns and, in AI mode, asks the model to
adjudicate every evidence package each one produced. Only a per-request timeout
existed, so the phase's cost was the number of packages multiplied by however
long the model took. On a slow endpoint the phase ran until the worker's own time
limit killed it, and the run was then reported as a timeout rather than as a slow
model.

The budget bounds that without losing findings: the AI is only ever an adjustment
on top of a deterministic score, so a package that cannot be afforded keeps the
verdict a deployment without AI would have given it.
"""

import importlib.util
import sys
import types
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_budget():
    package = sys.modules.setdefault('utils', types.ModuleType('utils'))
    package.__path__ = [str(REPO_ROOT / 'utils')]
    spec = importlib.util.spec_from_file_location(
        'pattern_ai_budget_under_test', REPO_ROOT / 'utils' / 'pattern_ai_budget.py'
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


budget_module = _load_budget()
PatternAIBudget = budget_module.PatternAIBudget


class BudgetAccountingTestCase(unittest.TestCase):
    def test_a_pattern_is_allowed_until_it_spends_its_budget(self):
        budget = PatternAIBudget(seconds_per_pattern=10)

        self.assertTrue(budget.allows('spray'))
        budget.record('spray', 4)
        self.assertTrue(budget.allows('spray'))
        budget.record('spray', 7)
        self.assertFalse(budget.allows('spray'))

    def test_patterns_have_separate_budgets(self):
        budget = PatternAIBudget(seconds_per_pattern=10)
        budget.record('spray', 20)

        self.assertFalse(budget.allows('spray'))
        self.assertTrue(
            budget.allows('brute_force'),
            msg='one slow pattern must not starve the rest',
        )

    def test_a_total_budget_stops_every_pattern(self):
        budget = PatternAIBudget(seconds_per_pattern=10, total_seconds=15)
        budget.record('spray', 9)
        budget.record('brute_force', 9)

        self.assertFalse(budget.allows('psexec'))

    def test_zero_means_unlimited(self):
        """Preserves the previous behaviour for anyone who wants it back."""
        budget = PatternAIBudget(seconds_per_pattern=0)
        budget.record('spray', 10_000)

        self.assertFalse(budget.enabled)
        self.assertTrue(budget.allows('spray'))


class GuardTestCase(unittest.TestCase):
    def test_the_guard_returns_the_result_while_in_budget(self):
        budget = PatternAIBudget(seconds_per_pattern=10)
        result = budget.guard('spray', lambda: {'adjustment': 5})

        self.assertEqual(result, {'adjustment': 5})

    def test_the_guard_returns_none_once_over_budget(self):
        """None leaves the deterministic score standing."""
        budget = PatternAIBudget(seconds_per_pattern=1)
        budget.record('spray', 5)

        called = []
        result = budget.guard('spray', lambda: called.append(True))

        self.assertIsNone(result)
        self.assertEqual(called, [], msg='the model must not be called over budget')

    def test_skipped_adjudications_are_counted(self):
        budget = PatternAIBudget(seconds_per_pattern=1)
        budget.record('spray', 5)
        budget.guard('spray', lambda: None)
        budget.guard('spray', lambda: None)

        self.assertEqual(budget.skipped('spray'), 2)
        self.assertEqual(budget.total_skipped, 2)

    def test_time_is_charged_even_when_the_call_raises(self):
        budget = PatternAIBudget(seconds_per_pattern=10)

        with self.assertRaises(RuntimeError):
            budget.guard('spray', lambda: (_ for _ in ()).throw(RuntimeError('model down')))

        self.assertGreaterEqual(budget.spent('spray'), 0.0)

    def test_the_summary_names_the_patterns_that_ran_out(self):
        budget = PatternAIBudget(seconds_per_pattern=1)
        budget.record('spray', 5)
        budget.guard('spray', lambda: None)

        summary = budget.summary()
        self.assertEqual(summary['ai_adjudications_skipped'], 1)
        self.assertEqual(summary['ai_patterns_over_budget'], ['spray'])


class WiringTestCase(unittest.TestCase):
    """The budget has to actually reach the model call and the phase outcome."""

    def setUp(self):
        self.pipeline = (REPO_ROOT / 'pipeline' / 'pattern_analysis.py').read_text()
        self.analyzer = (REPO_ROOT / 'utils' / 'case_analyzer.py').read_text()

    def test_the_loop_accepts_a_budget(self):
        self.assertIn('ai_budget', self.pipeline)

    def test_the_model_call_goes_through_the_budget(self):
        self.assertIn('ai_budget.guard(', self.pipeline)

    def test_the_analyzer_supplies_one(self):
        self.assertIn('budget_from_config(Config)', self.analyzer)

    def test_the_phase_records_what_the_budget_cost(self):
        self.assertIn('ai_budget.summary()', self.analyzer)

    def test_an_absent_budget_still_calls_the_model(self):
        """Callers that pass no budget keep the unlimited behaviour."""
        self.assertIn('if ai_budget is None:', self.pipeline)


class LoopGuardTestCase(unittest.TestCase):
    """Cancellation and cleanup inside the pattern phase."""

    def setUp(self):
        self.pipeline = (REPO_ROOT / 'pipeline' / 'pattern_analysis.py').read_text()
        self.analyzer = (REPO_ROOT / 'utils' / 'case_analyzer.py').read_text()

    def test_the_loop_checks_for_cancellation_each_pattern(self):
        """It was only checked between phases, and this phase runs 48 patterns."""
        self.assertIn('cancellation_check()', self.pipeline)

    def test_the_analyzer_passes_its_cancellation_check(self):
        self.assertIn('cancellation_check=self._ensure_not_cancelled', self.analyzer)

    def test_staged_events_are_cleaned_up_when_the_loop_raises(self):
        """775,968 rows in the database came from cleanup being skipped."""
        self.assertIn('except BaseException:', self.analyzer)
        self.assertIn('self._cleanup_pattern_extractor(extractor)', self.analyzer)

    def test_cleanup_failure_does_not_mask_the_original_error(self):
        import ast

        tree = ast.parse(self.analyzer)
        cleanup = next(
            node for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == '_cleanup_pattern_extractor'
        )

        handlers = [n for n in ast.walk(cleanup) if isinstance(n, ast.ExceptHandler)]
        self.assertTrue(handlers, msg='cleanup must tolerate its own failure')
        self.assertFalse(
            [n for n in ast.walk(cleanup) if isinstance(n, ast.Raise)],
            msg='raising here would replace the failure that prompted the cleanup',
        )


if __name__ == '__main__':
    unittest.main()
