"""Contract tests for behavioral profile construction.

These pin the decisions that made profiles unusable for peer comparison:
bucketing hour-of-day off a local-time column, applying the minimum-evidence
threshold to GROUP BY cardinality instead of event volume, and reading a
hostname for role hints before reading the events the host actually emitted.
"""

import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_profiler():
    """Load the profiler with its database and ClickHouse dependencies stubbed."""
    stub_names = (
        'models.database',
        'models.known_user',
        'models.known_system',
        'models.behavioral_profiles',
        'utils.clickhouse',
        'utils.case_timezone',
    )
    previous = {name: sys.modules.get(name) for name in stub_names}

    class _Profile:
        def __init__(self, **kwargs):
            for key, value in kwargs.items():
                setattr(self, key, value)

    sys.modules['models.database'] = types.SimpleNamespace(
        db=types.SimpleNamespace(session=types.SimpleNamespace())
    )
    sys.modules['models.known_user'] = types.SimpleNamespace(KnownUser=object)
    sys.modules['models.known_system'] = types.SimpleNamespace(KnownSystem=object)
    sys.modules['models.behavioral_profiles'] = types.SimpleNamespace(
        UserBehaviorProfile=_Profile,
        SystemBehaviorProfile=_Profile,
        SystemRole=types.SimpleNamespace(
            DOMAIN_CONTROLLER='domain_controller',
            SERVER='server',
            WORKSTATION='workstation',
            UNKNOWN='unknown',
        ),
    )
    sys.modules['utils.clickhouse'] = types.SimpleNamespace(get_fresh_client=lambda: None)
    sys.modules['utils.case_timezone'] = types.SimpleNamespace(
        get_case_timezone=lambda _case_id: 'America/New_York',
        DEFAULT_CASE_TIMEZONE='UTC',
    )

    try:
        spec = importlib.util.spec_from_file_location(
            'behavioral_profiler_under_test',
            REPO_ROOT / 'utils' / 'behavioral_profiler.py',
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules['behavioral_profiler_under_test'] = module
        spec.loader.exec_module(module)
        return module
    finally:
        for name, original in previous.items():
            if original is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = original


profiler_module = _load_profiler()
BehavioralProfiler = profiler_module.BehavioralProfiler
SystemRole = profiler_module.SystemRole


class _RecordingClient:
    """Captures the query and parameters instead of contacting ClickHouse."""

    def __init__(self, rows):
        self.rows = rows
        self.query_text = None
        self.parameters = None

    def query(self, query, parameters=None):
        self.query_text = query
        self.parameters = parameters
        return types.SimpleNamespace(result_rows=self.rows)


def _build_profiler(rows):
    profiler = BehavioralProfiler(case_id=7, analysis_id='analysis-under-test')
    client = _RecordingClient(rows)
    profiler.ch_client = client
    return profiler, client


class ProfilerQueryContractTestCase(unittest.TestCase):
    def test_user_query_buckets_utc_column_in_case_timezone(self):
        profiler, client = _build_profiler(rows=[])
        profiler._calculate_user_profile(1, 'jdoe', 'S-1-5-21-1')

        self.assertIn('timestamp_utc', client.query_text)
        self.assertIn('toTimeZone(timestamp_utc', client.query_text)
        self.assertNotIn('toHour(timestamp)', client.query_text)
        self.assertNotIn('toDate(timestamp)', client.query_text)
        self.assertEqual(client.parameters['tz'], 'America/New_York')

    def test_system_query_buckets_utc_column_in_case_timezone(self):
        profiler, client = _build_profiler(rows=[])
        profiler._calculate_system_profile(1, 'CORP-WS-04')

        self.assertIn('toTimeZone(timestamp_utc', client.query_text)
        self.assertNotIn('toHour(timestamp)', client.query_text)
        self.assertEqual(client.parameters['tz'], 'America/New_York')

    def test_identity_values_are_bound_as_parameters_not_interpolated(self):
        profiler, client = _build_profiler(rows=[])
        hostile_username = "O'Brien\\"
        profiler._calculate_user_profile(1, hostile_username, None)

        self.assertNotIn(hostile_username, client.query_text)
        self.assertIn('{username:String}', client.query_text)
        self.assertEqual(client.parameters['username'], hostile_username)

    def test_epoch_events_are_excluded_from_profiles(self):
        profiler, client = _build_profiler(rows=[])
        profiler._calculate_user_profile(1, 'jdoe', None)

        self.assertIn('timestamp_utc > toDateTime64', client.query_text)


class ProfilerEvidenceThresholdTestCase(unittest.TestCase):
    """The minimum applies to events, not to GROUP BY rows."""

    @staticmethod
    def _user_row(hour, day, date, event_id, count):
        return (hour, day, date, event_id, 'HOST-A', 'HOST-B', 'NTLM', 3, count)

    def test_single_row_carrying_many_events_is_profiled(self):
        rows = [self._user_row(9, 2, '2024-08-16', '4624', 10_000)]
        profiler, _ = _build_profiler(rows)
        profiler.min_events_for_profile = 10

        with patch.object(profiler, '_flush_profile_within_savepoint', side_effect=lambda p, _r: p), \
             patch.object(profiler_module.db.session, 'add', create=True), \
             patch.object(profiler_module, 'UserBehaviorProfile') as profile_cls:
            profile_cls.query = types.SimpleNamespace(
                filter_by=lambda **_kw: types.SimpleNamespace(first=lambda: None)
            )
            profiler_module.db.session.no_autoflush = _NullContext()
            result = profiler._calculate_user_profile(1, 'jdoe', None)

        self.assertIsNotNone(
            result,
            msg='10,000 events collapsed into one grouped row must still profile',
        )

    def test_many_rows_carrying_few_events_is_not_profiled(self):
        rows = [
            self._user_row(hour, 2, '2024-08-16', '4624', 1)
            for hour in range(9)
        ]
        profiler, _ = _build_profiler(rows)
        profiler.min_events_for_profile = 10

        profiler_module.db.session.no_autoflush = _NullContext()
        result = profiler._calculate_user_profile(1, 'jdoe', None)

        self.assertIsNone(
            result,
            msg='9 events spread across 9 grouped rows is below the minimum',
        )


class SystemRoleInferenceTestCase(unittest.TestCase):
    def setUp(self):
        self.profiler, _ = _build_profiler(rows=[])

    def _infer(self, hostname, event_counts=None, unique_users=0):
        return self.profiler._infer_system_role(hostname, {
            'event_counts': event_counts or {},
            'unique_users': unique_users,
            'processes': [],
        })

    def test_directory_replication_outranks_low_user_count(self):
        role = self._infer('QUIET-HOST', event_counts={'4932': 0, '4933': 40}, unique_users=2)
        self.assertEqual(role, SystemRole.DOMAIN_CONTROLLER)

    def test_hostname_token_matches_on_boundary(self):
        self.assertEqual(self._infer('CORP-DC01'), SystemRole.DOMAIN_CONTROLLER)
        self.assertEqual(self._infer('DC1.corp.local'), SystemRole.DOMAIN_CONTROLLER)

    def test_substring_lookalikes_are_not_domain_controllers(self):
        for hostname in ('HELPDESK', 'MDCLIENT', 'ABDCX'):
            self.assertNotEqual(
                self._infer(hostname, unique_users=10),
                SystemRole.DOMAIN_CONTROLLER,
                msg=f'{hostname} must not be read as a domain controller',
            )

    def test_substring_lookalikes_are_not_servers(self):
        self.assertNotEqual(
            self._infer('SNAPPY', unique_users=10),
            SystemRole.SERVER,
            msg='SNAPPY must not be read as an application server',
        )

    def test_server_token_still_matches(self):
        self.assertEqual(self._infer('CORP-SQL02'), SystemRole.SERVER)


class _NullContext:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


if __name__ == '__main__':
    unittest.main()
