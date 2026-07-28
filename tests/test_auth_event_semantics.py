"""Contract tests for authentication event semantics used by the detectors.

Three assumptions in this layer were wrong and each on its own was enough to
stop a detector from ever firing: which events count as authentication, whether
a status-bearing event succeeded, and where the attempt came from. A fourth
defect was organisational - the detectors documented one set of thresholds while
configuration supplied another and always won.
"""

import ast
import importlib.util
import sys
import types
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _load(name, relative_path, stubs=None):
    stubs = stubs or {}
    previous = {key: sys.modules.get(key) for key in stubs}
    sys.modules.update(stubs)
    try:
        spec = importlib.util.spec_from_file_location(name, REPO_ROOT / relative_path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        for key, original in previous.items():
            if original is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = original


auth_events = _load('auth_events_under_test', 'utils/stateful_detectors/auth_events.py')


def _config_env_defaults():
    """Extract the fallback value of every `os.environ.get(NAME, default)` in config.py."""
    tree = ast.parse((REPO_ROOT / 'config.py').read_text())
    defaults = {}

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr == 'get'):
            continue
        if not (isinstance(func.value, ast.Attribute) and func.value.attr == 'environ'):
            continue
        if len(node.args) != 2:
            continue
        name = node.args[0]
        default = node.args[1]
        if isinstance(name, ast.Constant) and isinstance(default, ast.Constant):
            defaults[name.value] = default.value

    return defaults


def _load_detector(module_name, relative_path, class_name):
    """Load a detector module with its heavier dependencies stubbed out."""
    base = types.ModuleType('utils.stateful_detectors')

    class _BaseGapDetector:
        def __init__(self, case_id, analysis_id):
            self.case_id = case_id
            self.analysis_id = analysis_id
            self.ch_client = None

    base.BaseGapDetector = _BaseGapDetector

    sliding_window = _load(
        f'{module_name}_sliding_window', 'utils/stateful_detectors/sliding_window.py'
    )

    stubs = {
        'models.database': types.SimpleNamespace(db=types.SimpleNamespace(session=None)),
        'models.behavioral_profiles': types.SimpleNamespace(
            GapDetectionFinding=object,
            GapFindingType=types.SimpleNamespace(
                PASSWORD_SPRAYING='password_spraying',
                BRUTE_FORCE='brute_force',
                DISTRIBUTED_BRUTE_FORCE='distributed_brute_force',
            ),
            UserBehaviorProfile=object,
        ),
        'models.known_user': types.SimpleNamespace(KnownUser=object),
        'utils.stateful_detectors': base,
        'utils.stateful_detectors.auth_events': auth_events,
        'utils.stateful_detectors.sliding_window': sliding_window,
        # An empty configuration, so THRESHOLD_SPEC defaults are what apply.
        'config': types.SimpleNamespace(Config=type('Config', (), {})),
    }
    module = _load(module_name, relative_path, stubs)
    return getattr(module, class_name)


SprayDetector = _load_detector(
    'spray_under_test', 'utils/stateful_detectors/password_spraying.py',
    'PasswordSprayingDetector',
)
BruteDetector = _load_detector(
    'brute_under_test', 'utils/stateful_detectors/brute_force.py',
    'BruteForceDetector',
)


class ThresholdSingleSourceTestCase(unittest.TestCase):
    """Configuration and the detectors must not document different numbers."""

    def setUp(self):
        self.config_defaults = _config_env_defaults()

    def _assert_spec_matches_config(self, spec):
        for name, (config_attribute, documented_default) in spec.items():
            self.assertIn(
                config_attribute,
                self.config_defaults,
                msg=f'{config_attribute} is read by the detector but absent from config.py',
            )
            self.assertEqual(
                float(self.config_defaults[config_attribute]),
                float(documented_default),
                msg=(
                    f'{config_attribute} defaults to '
                    f'{self.config_defaults[config_attribute]} in config.py but the '
                    f'detector documents {documented_default} for {name}. '
                    'Configuration always wins, so the documented value would be fiction.'
                ),
            )

    def test_spray_thresholds_agree_with_config(self):
        self._assert_spec_matches_config(SprayDetector.THRESHOLD_SPEC)

    def test_brute_thresholds_agree_with_config(self):
        self._assert_spec_matches_config(BruteDetector.THRESHOLD_SPEC)

    def test_brute_force_uses_the_documented_minimums(self):
        self.assertEqual(BruteDetector.THRESHOLD_SPEC['min_attempts'][1], 8)
        self.assertEqual(BruteDetector.THRESHOLD_SPEC['min_failure_rate'][1], 0.90)

    def test_thresholds_resolve_from_config_when_present(self):
        config = types.SimpleNamespace(BRUTE_MIN_ATTEMPTS=42)
        resolved = auth_events.resolve_thresholds(
            config, {'min_attempts': ('BRUTE_MIN_ATTEMPTS', 8)}
        )
        self.assertEqual(resolved['min_attempts'], 42)

    def test_explicit_overrides_win(self):
        resolved = auth_events.resolve_thresholds(
            types.SimpleNamespace(BRUTE_MIN_ATTEMPTS=42),
            {'min_attempts': ('BRUTE_MIN_ATTEMPTS', 8)},
            {'min_attempts': 3},
        )
        self.assertEqual(resolved['min_attempts'], 3)


class EventCoverageTestCase(unittest.TestCase):
    def test_kerberos_and_ntlm_events_are_authentication_events(self):
        for event_id in ('4768', '4771', '4776'):
            self.assertIn(
                event_id,
                auth_events.AUTH_EVENT_IDS,
                msg=f'{event_id} carries authentication failures that were being missed',
            )

    def test_status_bearing_events_are_not_treated_as_always_failure(self):
        """4768 and 4776 report both outcomes; most of them succeeded."""
        for event_id in ('4768', '4771', '4776'):
            self.assertIn(event_id, auth_events.STATUS_BEARING_EVENT_IDS)
            self.assertNotIn(event_id, auth_events.ALWAYS_FAILURE_EVENT_IDS)
            self.assertNotIn(event_id, auth_events.ALWAYS_SUCCESS_EVENT_IDS)

    def test_both_success_status_dialects_are_recognised(self):
        self.assertIn('KDC_ERR_NONE', auth_events.SUCCESS_STATUS_TOKENS)
        self.assertIn('Status OK', auth_events.SUCCESS_STATUS_TOKENS)


class SourceIdentityQueryTestCase(unittest.TestCase):
    def setUp(self):
        self.source_query = auth_events.build_source_slot_query(15)
        self.target_query = auth_events.build_target_slot_query(15)

    def test_source_identity_does_not_use_the_logging_host(self):
        """`source_host` names the machine that wrote the event.

        On a domain controller it is the DC itself, so using it as a fallback
        would report the DC as the origin of every Kerberos spray.
        """
        identity_section = self.source_query.split('AS raw_source_identity')[0]
        self.assertNotIn('source_host', identity_section)

    def test_source_identity_falls_back_beyond_src_ip(self):
        for fragment in ('workstation_name', 'payload_workstation', 'remote_ip', 'remote_name'):
            self.assertIn(fragment, self.source_query)

    def test_ephemeral_ports_are_not_part_of_the_identity(self):
        """4771 records ::ffff:10.0.0.5:57392, a new port per connection."""
        self.assertIn('extract(remote_host', self.source_query)
        self.assertIn('[0-9]{1,3}', self.source_query)

    def test_loopback_is_treated_as_unresolved(self):
        self.assertIn('::1', auth_events.UNRESOLVED_SOURCE_PREFIXES)
        self.assertIn('127.', auth_events.UNRESOLVED_SOURCE_PREFIXES)
        self.assertIn("LIKE '::1%'", self.source_query)

    def test_queries_bind_the_case_id_as_a_parameter(self):
        for query in (self.source_query, self.target_query):
            self.assertIn('{case_id:UInt32}', query)

    def test_epoch_events_are_excluded(self):
        for query in (self.source_query, self.target_query):
            self.assertIn('timestamp_utc > toDateTime64', query)

    def test_slots_are_shorter_than_any_detection_window(self):
        self.assertIn('INTERVAL 15 MINUTE', self.source_query)
        self.assertLess(SprayDetector.SLOT_MINUTES, 60)
        self.assertLess(BruteDetector.SLOT_MINUTES, 60)

    def test_placeholder_and_machine_accounts_are_excluded(self):
        for query in (self.source_query, self.target_query):
            self.assertIn("username NOT LIKE '%$'", query)
            self.assertIn("match(username, '[A-Za-z0-9]')", query)

    def test_attempt_sample_pairs_time_with_peer(self):
        """Two independent aggregates could not be correlated by position."""
        self.assertIn('tuple(timestamp_utc', self.source_query)
        self.assertIn('tuple(timestamp_utc', self.target_query)

    def test_successful_accounts_query_accepts_any_success_event(self):
        query = auth_events.build_successful_accounts_query()
        self.assertIn('is_success', query)
        self.assertIn('{source_identity:String}', query)


if __name__ == '__main__':
    unittest.main()
