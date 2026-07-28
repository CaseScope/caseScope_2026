import importlib.util
import sys
import types
import unittest
from datetime import datetime
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
UTILS_DIR = REPO_ROOT / "utils"


def _load_module(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


utils_pkg = sys.modules.setdefault("utils", types.ModuleType("utils"))
utils_pkg.__path__ = [str(UTILS_DIR)]

models_pkg = sys.modules.setdefault("models", types.ModuleType("models"))
models_pkg.__path__ = [str(REPO_ROOT / "models")]

database_module = types.ModuleType("models.database")
database_module.db = types.SimpleNamespace(
    session=types.SimpleNamespace(add=lambda item: None, commit=lambda: None)
)
sys.modules["models.database"] = database_module

behavioral_profiles_module = types.ModuleType("models.behavioral_profiles")
behavioral_profiles_module.GapDetectionFinding = type("GapDetectionFinding", (), {})
behavioral_profiles_module.GapFindingType = type(
    "GapFindingType",
    (),
    {
        "PASSWORD_SPRAYING": "PASSWORD_SPRAYING",
        "BRUTE_FORCE": "BRUTE_FORCE",
        "DISTRIBUTED_BRUTE_FORCE": "DISTRIBUTED_BRUTE_FORCE",
    },
)
behavioral_profiles_module.UserBehaviorProfile = type("UserBehaviorProfile", (), {})
sys.modules["models.behavioral_profiles"] = behavioral_profiles_module

known_user_module = types.ModuleType("models.known_user")
known_user_module.KnownUser = type(
    "KnownUser",
    (),
    {"query": types.SimpleNamespace(filter_by=lambda **kwargs: types.SimpleNamespace(filter=lambda *a, **k: types.SimpleNamespace(first=lambda: None)))},
)
sys.modules["models.known_user"] = known_user_module

config_module = types.ModuleType("config")
config_module.Config = type("Config", (), {})
sys.modules["config"] = config_module

stateful_detectors = _load_module(
    "utils.stateful_detectors",
    UTILS_DIR / "stateful_detectors" / "__init__.py",
)
password_spraying = _load_module(
    "utils.stateful_detectors.password_spraying",
    UTILS_DIR / "stateful_detectors" / "password_spraying.py",
)
brute_force = _load_module(
    "utils.stateful_detectors.brute_force",
    UTILS_DIR / "stateful_detectors" / "brute_force.py",
)


class _FakeResult:
    def __init__(self, rows):
        self.result_rows = rows


class _RecordingClient:
    """Captures the query and bound parameters, and replays fixed slot rows."""

    def __init__(self, rows):
        self.rows = rows
        self.query_text = None
        self.parameters = None

    def query(self, query, parameters=None):
        self.query_text = query
        self.parameters = parameters
        return _FakeResult(self.rows)


def _source_slot(slot_start, failures, successes, usernames, sample=()):
    """A row in the column order build_source_slot_query selects."""
    return (
        "10.0.0.5",
        slot_start,
        failures,
        successes,
        failures + successes,
        list(usernames),
        slot_start,
        slot_start,
        list(sample),
    )


def _target_slot(slot_start, failures, successes, sources, sample=()):
    """A row in the column order build_target_slot_query selects."""
    return (
        "alice",
        slot_start,
        failures,
        successes,
        failures + successes,
        list(sources),
        slot_start,
        slot_start,
        list(sample),
    )


class StatefulDetectorWindowRegressionTestCase(unittest.TestCase):
    """The detectors slide a window across short slots.

    They used to group straight into detection-sized buckets with
    `toStartOfInterval`, so an attack crossing a bucket boundary was split into
    halves that could each fall under the thresholds.
    """

    def test_password_spray_slides_a_window_across_short_slots(self):
        client = _RecordingClient([
            _source_slot(
                datetime(2026, 4, 20, 10, 45), failures=20, successes=0,
                usernames=[f"user{index}" for index in range(6)],
            ),
            _source_slot(
                datetime(2026, 4, 20, 11, 0), failures=20, successes=0,
                usernames=[f"user{index}" for index in range(6, 12)],
            ),
        ])

        detector = password_spraying.PasswordSprayingDetector(
            case_id=7,
            analysis_id="review11-test",
            thresholds={"time_window_hours": 2, "min_unique_users": 10},
        )
        detector._get_clickhouse_client = lambda: client

        candidates = detector._find_spray_candidates()

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["source_identity"], "10.0.0.5")
        self.assertEqual(
            candidates[0]["unique_users"],
            12,
            msg="accounts targeted either side of the hour must count as one attack",
        )
        self.assertEqual(candidates[0]["failures"], 40)

    def test_spray_slot_query_is_parameterized_on_case_id(self):
        client = _RecordingClient([])
        detector = password_spraying.PasswordSprayingDetector(
            case_id=7, analysis_id="review11-test"
        )
        detector._get_clickhouse_client = lambda: client

        detector._find_spray_candidates()

        self.assertIn("{case_id:UInt32}", client.query_text)
        self.assertEqual(client.parameters["case_id"], 7)
        self.assertIn("INTERVAL 15 MINUTE", client.query_text)

    def test_password_spray_success_accounts_stay_scoped_to_detected_window(self):
        client = _RecordingClient([("alice",), ("bob",)])
        detector = password_spraying.PasswordSprayingDetector(
            case_id=7,
            analysis_id="review11-test",
        )
        detector._get_clickhouse_client = lambda: client

        accounts = detector._get_successful_accounts(
            "10.0.0.5",
            datetime(2026, 4, 20, 10, 1, 0),
            datetime(2026, 4, 20, 10, 50, 0),
        )

        self.assertEqual(accounts, ["alice", "bob"])
        self.assertEqual(client.parameters["window_start"], "2026-04-20 10:01:00")
        self.assertEqual(client.parameters["window_end"], "2026-04-20 10:50:00")
        self.assertEqual(client.parameters["source_identity"], "10.0.0.5")

    def test_brute_force_slides_a_window_across_short_slots(self):
        client = _RecordingClient([
            _target_slot(
                datetime(2026, 4, 20, 11, 45), failures=6, successes=0,
                sources=["10.0.0.5"],
            ),
            _target_slot(
                datetime(2026, 4, 20, 12, 0), failures=6, successes=0,
                sources=["10.0.0.6"],
            ),
        ])

        detector = brute_force.BruteForceDetector(
            case_id=7,
            analysis_id="review11-test",
            thresholds={"time_window_hours": 1, "min_attempts": 8},
        )
        detector._get_clickhouse_client = lambda: client

        candidates = detector._find_brute_candidates()

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["username"], "alice")
        self.assertEqual(
            candidates[0]["failures"],
            12,
            msg="six failures either side of the hour is one attack of twelve",
        )
        self.assertEqual(candidates[0]["source_count"], 2)

    def test_brute_force_ignores_unattributable_sources_in_the_source_count(self):
        client = _RecordingClient([
            _target_slot(
                datetime(2026, 4, 20, 11, 45), failures=12, successes=0,
                sources=["10.0.0.5", "unknown"],
            ),
        ])
        detector = brute_force.BruteForceDetector(
            case_id=7,
            analysis_id="review11-test",
            thresholds={"time_window_hours": 1, "min_attempts": 8},
        )
        detector._get_clickhouse_client = lambda: client

        candidates = detector._find_brute_candidates()

        self.assertEqual(candidates[0]["source_count"], 1)
        self.assertEqual(candidates[0]["source_ips_sampled"], ["10.0.0.5"])

    def test_base_gap_detector_formats_sql_datetimes_without_fractional_seconds(self):
        detector = stateful_detectors.BaseGapDetector(case_id=7, analysis_id="review11-test")

        formatted = detector._format_sql_datetime(datetime(2026, 4, 20, 10, 1, 0, 123456))

        self.assertEqual(formatted, "2026-04-20 10:01:00")


if __name__ == "__main__":
    unittest.main()
