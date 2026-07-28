"""Alias numbers must never be reissued to a value the vault already holds.

`--reset` drops every alias counter for a case but only deletes the aliases it
created itself. Aliases created lazily during AI egress survive holding
ACCOUNT_0001 and HOSTNAME_0001, and the allocator treated a missing counter as
an empty vault and restarted at 1. The unique constraint on
(case_id, alias_value) then aborted the rebuild on its first insert, and because
the reset commits its deletion before rebuilding, the case was left stripped of
the aliases it had.
"""

import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SECRET_KEY", "test-secret")

from utils import privacy_aliases  # noqa: E402


class _FakeCounterQuery:
    """Stands in for PrivacyAliasCounter.query with no counter row present."""

    def __init__(self, existing=None):
        self._existing = existing

    def filter_by(self, **_kwargs):
        return self

    def with_for_update(self):
        return self

    def first(self):
        return self._existing


def _fake_counter_model(existing=None):
    """A stand-in for the counter model.

    The real model's `query` is a Flask-SQLAlchemy descriptor that needs an
    application context, so replace the whole symbol the module looks up.
    """

    class _FakeCounterModel:
        query = _FakeCounterQuery(existing)

        def __init__(self, **kwargs):
            for key, value in kwargs.items():
                setattr(self, key, value)

    return _FakeCounterModel


class _FakeSession:
    def __init__(self):
        self.added = []

    def add(self, obj):
        self.added.append(obj)

    def flush(self):
        pass


class AliasNumberAllocationTestCase(unittest.TestCase):
    def _allocate(self, case_id, entity_type, *, highest, existing_counter=None):
        session = _FakeSession()
        with patch.object(privacy_aliases, 'PrivacyAliasCounter',
                          _fake_counter_model(existing_counter)), \
                patch.object(privacy_aliases.db, 'session', session), \
                patch.object(privacy_aliases, '_highest_alias_number',
                             return_value=highest):
            value = privacy_aliases._next_alias_value(case_id, entity_type)
        return value, session

    def test_a_lost_counter_resumes_above_the_surviving_aliases(self):
        value, _ = self._allocate(4, 'ACCOUNT', highest=74)
        self.assertEqual('ACCOUNT_0075', value)

    def test_the_first_alias_of_a_type_still_starts_at_one(self):
        value, _ = self._allocate(4, 'ACCOUNT', highest=0)
        self.assertEqual('ACCOUNT_0001', value)

    def test_the_reissued_number_is_the_one_that_broke_the_rebuild(self):
        # Case 4 held ACCOUNT_0001 from lazy egress; the old allocator handed
        # ACCOUNT_0001 straight back and violated uq_privacy_alias_case_alias.
        value, _ = self._allocate(4, 'ACCOUNT', highest=1)
        self.assertNotEqual(
            'ACCOUNT_0001', value,
            "the allocator reissued an alias value the case already holds",
        )
        self.assertEqual('ACCOUNT_0002', value)

    def test_a_seeded_counter_is_persisted_so_the_scan_is_not_repeated(self):
        value, session = self._allocate(4, 'HOSTNAME', highest=8989)
        self.assertEqual('HOSTNAME_8990', value)
        self.assertEqual(1, len(session.added))
        # Seeded to 8990 and advanced as that number was issued, so the next
        # allocation continues from 8991 without rescanning the vault.
        self.assertEqual(8991, session.added[0].next_number)

    def test_an_existing_counter_is_trusted_without_rescanning(self):
        class _Counter:
            next_number = 500

        counter = _Counter()
        with patch.object(privacy_aliases, 'PrivacyAliasCounter',
                          _fake_counter_model(counter)), \
                patch.object(privacy_aliases.db, 'session', _FakeSession()), \
                patch.object(privacy_aliases, '_highest_alias_number') as scan:
            value = privacy_aliases._next_alias_value(4, 'ACCOUNT')

        self.assertEqual('ACCOUNT_0500', value)
        self.assertEqual(501, counter.next_number)
        scan.assert_not_called()

    def test_numbers_past_four_digits_keep_ascending(self):
        # A capped vault reaches 50000, where zero padding stops mattering and
        # lexical ordering would put ACCOUNT_10000 below ACCOUNT_9999.
        value, _ = self._allocate(5, 'USERNAME', highest=9999)
        self.assertEqual('USERNAME_10000', value)

    def test_consecutive_allocations_do_not_repeat(self):
        class _Counter:
            next_number = 10

        counter = _Counter()
        issued = []
        with patch.object(privacy_aliases, 'PrivacyAliasCounter',
                          _fake_counter_model(counter)), \
                patch.object(privacy_aliases.db, 'session', _FakeSession()):
            for _ in range(5):
                issued.append(privacy_aliases._next_alias_value(4, 'ACCOUNT'))

        self.assertEqual(len(issued), len(set(issued)))
        self.assertEqual(
            ['ACCOUNT_0010', 'ACCOUNT_0011', 'ACCOUNT_0012',
             'ACCOUNT_0013', 'ACCOUNT_0014'],
            issued,
        )


class HighestAliasNumberQueryTestCase(unittest.TestCase):
    """The resume point must be read from the vault, scoped to case and type."""

    def test_the_lookup_is_scoped_and_reads_the_alias_number(self):
        import inspect

        source = inspect.getsource(privacy_aliases._highest_alias_number)
        self.assertIn('PrivacyAlias.case_id == case_id', source)
        self.assertIn('PrivacyAlias.entity_type == entity_type', source)
        self.assertIn('max', source)

    def test_a_case_with_no_aliases_reports_zero(self):
        class _Scalar:
            def filter(self, *_args):
                return self

            def scalar(self):
                return None

        class _Session:
            def query(self, *_args):
                return _Scalar()

        with patch.object(privacy_aliases.db, 'session', _Session()):
            self.assertEqual(0, privacy_aliases._highest_alias_number(99, 'ACCOUNT'))


if __name__ == "__main__":
    unittest.main()
