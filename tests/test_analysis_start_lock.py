"""Tests for the per-case analysis start lock.

Starting a run was a check followed by an act: the route looked for a run in a
running state, found none, and dispatched. Two requests arriving together - a
double-clicked button is enough - both passed the check, and the second run's
initialisation deletes the first run's profiles and peer groups while the first
run is still using them. Nothing in the schema catches it, because a case is
allowed any number of historical runs.
"""

import importlib.util
import sys
import types
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


class _FakeRedis:
    """Enough of Redis to exercise SET NX EX semantics."""

    def __init__(self):
        self.store = {}
        self.failing = False

    def set(self, key, value, nx=False, ex=None):
        if self.failing:
            raise RuntimeError('redis is down')
        if nx and key in self.store:
            return None
        self.store[key] = value
        return True

    def get(self, key):
        if self.failing:
            raise RuntimeError('redis is down')
        return self.store.get(key)

    def delete(self, key):
        if self.failing:
            raise RuntimeError('redis is down')
        self.store.pop(key, None)


def _load_lock_module(redis_client):
    stub = types.ModuleType('utils.async_cancellation')
    stub._get_redis_client = lambda: redis_client

    package = sys.modules.setdefault('utils', types.ModuleType('utils'))
    package.__path__ = [str(REPO_ROOT / 'utils')]

    previous = sys.modules.get('utils.async_cancellation')
    sys.modules['utils.async_cancellation'] = stub
    try:
        spec = importlib.util.spec_from_file_location(
            'analysis_run_lock_under_test', REPO_ROOT / 'utils' / 'analysis_run_lock.py'
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        if previous is None:
            sys.modules.pop('utils.async_cancellation', None)
        else:
            sys.modules['utils.async_cancellation'] = previous


class StartLockTestCase(unittest.TestCase):
    def setUp(self):
        self.redis = _FakeRedis()
        self.lock = _load_lock_module(self.redis)

    def test_the_first_run_claims_the_case(self):
        self.assertTrue(self.lock.acquire_start_lock(7, 'analysis-a'))

    def test_a_second_run_cannot_claim_the_same_case(self):
        """The race the lock exists to close."""
        self.assertTrue(self.lock.acquire_start_lock(7, 'analysis-a'))
        self.assertFalse(self.lock.acquire_start_lock(7, 'analysis-b'))

    def test_different_cases_do_not_block_each_other(self):
        self.assertTrue(self.lock.acquire_start_lock(7, 'analysis-a'))
        self.assertTrue(self.lock.acquire_start_lock(8, 'analysis-b'))

    def test_releasing_lets_the_next_run_start(self):
        self.lock.acquire_start_lock(7, 'analysis-a')
        self.lock.release_start_lock(7, 'analysis-a')
        self.assertTrue(self.lock.acquire_start_lock(7, 'analysis-b'))

    def test_a_run_cannot_release_a_lock_it_does_not_hold(self):
        """A timed-out run must not free the case from under its replacement."""
        self.lock.acquire_start_lock(7, 'analysis-a')
        self.lock.release_start_lock(7, 'analysis-stale')

        self.assertFalse(
            self.lock.acquire_start_lock(7, 'analysis-b'),
            msg='the lock held by analysis-a was released by an unrelated run',
        )

    def test_the_holder_is_reported_for_the_conflict_message(self):
        self.lock.acquire_start_lock(7, 'analysis-a')
        self.assertEqual(self.lock.current_lock_holder(7), 'analysis-a')

    def test_no_holder_when_the_case_is_free(self):
        self.assertIsNone(self.lock.current_lock_holder(7))

    def test_the_lock_carries_an_expiry(self):
        """A worker killed mid-run must not lock a case out permanently."""
        recorded = {}
        original_set = self.redis.set

        def recording_set(key, value, nx=False, ex=None):
            recorded['ex'] = ex
            return original_set(key, value, nx=nx, ex=ex)

        self.redis.set = recording_set
        self.lock.acquire_start_lock(7, 'analysis-a')

        self.assertEqual(recorded['ex'], self.lock.LOCK_TTL_SECONDS)
        self.assertGreater(recorded['ex'], 0)

    def test_a_redis_outage_does_not_prevent_analysis(self):
        """Losing every run is worse than the race the lock prevents."""
        self.redis.failing = True

        self.assertTrue(
            self.lock.acquire_start_lock(7, 'analysis-a'),
            msg='the lock must fail open so analysis stays possible',
        )

    def test_a_redis_outage_does_not_raise_on_release(self):
        self.lock.acquire_start_lock(7, 'analysis-a')
        self.redis.failing = True
        self.lock.release_start_lock(7, 'analysis-a')  # must not raise

    def test_a_redis_outage_reports_no_holder(self):
        self.redis.failing = True
        self.assertIsNone(self.lock.current_lock_holder(7))


if __name__ == '__main__':
    unittest.main()
