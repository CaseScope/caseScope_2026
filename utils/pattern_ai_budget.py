"""A time budget for the AI adjudication inside pattern analysis.

Pattern analysis evaluates 48 patterns, and in AI mode each one asks the model to
adjudicate every evidence package it produced. The only limit was a per-request
timeout, so the phase's total cost was the number of packages multiplied by
however long the model took - unbounded in practice, and on a slow or degraded
model endpoint the phase would run until the worker's own time limit killed it
and the run was reported as a timeout rather than as a slow model.

The budget makes the cost bounded without discarding work. Every package is still
scored deterministically; the AI is only ever an adjustment on top of that score.
When a pattern exhausts its budget the remaining packages keep their deterministic
verdict, which is the same outcome a deployment without AI gets, and the pattern
records how many adjudications it skipped so the analyst can see the model was
the constraint.
"""

from __future__ import annotations

import logging
import time
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class PatternAIBudget:
    """Tracks AI time spent per pattern and reports when a pattern is over budget."""

    def __init__(self, seconds_per_pattern: float, total_seconds: Optional[float] = None):
        self.seconds_per_pattern = max(0.0, float(seconds_per_pattern))
        self.total_seconds = float(total_seconds) if total_seconds else None
        self._spent: Dict[str, float] = {}
        self._skipped: Dict[str, int] = {}
        self._total_spent = 0.0

    @property
    def enabled(self) -> bool:
        """A budget of zero means unlimited, matching the previous behaviour."""
        return self.seconds_per_pattern > 0

    def allows(self, pattern_id: str) -> bool:
        """Whether the AI may still be consulted for this pattern."""
        if not self.enabled:
            return True

        if self.total_seconds is not None and self._total_spent >= self.total_seconds:
            return False

        return self._spent.get(pattern_id, 0.0) < self.seconds_per_pattern

    def record(self, pattern_id: str, seconds: float) -> None:
        """Charge elapsed AI time to a pattern."""
        self._spent[pattern_id] = self._spent.get(pattern_id, 0.0) + max(0.0, seconds)
        self._total_spent += max(0.0, seconds)

    def record_skipped(self, pattern_id: str) -> None:
        """Note one package that kept its deterministic verdict."""
        self._skipped[pattern_id] = self._skipped.get(pattern_id, 0) + 1

    def spent(self, pattern_id: str) -> float:
        return self._spent.get(pattern_id, 0.0)

    def skipped(self, pattern_id: str) -> int:
        return self._skipped.get(pattern_id, 0)

    @property
    def total_spent(self) -> float:
        return self._total_spent

    @property
    def total_skipped(self) -> int:
        return sum(self._skipped.values())

    def summary(self) -> Dict[str, object]:
        """What the phase should record about the model's contribution."""
        return {
            'ai_seconds_spent': round(self._total_spent, 1),
            'ai_adjudications_skipped': self.total_skipped,
            'ai_patterns_over_budget': sorted(self._skipped),
        }

    def guard(self, pattern_id: str, call):
        """Run `call` under the budget, returning None when it cannot be afforded.

        Returning None rather than raising lets the caller fall back to the
        deterministic verdict, which is what a deployment without AI would use.
        """
        if not self.allows(pattern_id):
            self.record_skipped(pattern_id)
            logger.info(
                "[PatternAIBudget] %s is over its AI budget (%.1fs); keeping the "
                "deterministic verdict", pattern_id, self.spent(pattern_id),
            )
            return None

        started = time.time()
        try:
            return call()
        finally:
            self.record(pattern_id, time.time() - started)


def budget_from_config(config) -> PatternAIBudget:
    """Build the budget from configuration, treating zero as unlimited."""
    return PatternAIBudget(
        seconds_per_pattern=getattr(config, 'ANALYSIS_AI_PATTERN_BUDGET_SECONDS', 0) or 0,
        total_seconds=getattr(config, 'ANALYSIS_AI_TOTAL_BUDGET_SECONDS', 0) or None,
    )
