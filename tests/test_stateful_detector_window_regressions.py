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


class StatefulDetectorWindowRegressionTestCase(unittest.TestCase):
    def test_password_spray_candidates_group_by_configured_window(self):
        captured = {}

        class FakeClient:
            @staticmethod
            def query(query):
                captured["query"] = query
                return _FakeResult(
                    [
                        (
                            "10.0.0.5",
                            datetime(2026, 4, 20, 10, 0, 0),
                            12,
                            14,
                            14,
                            0,
                            datetime(2026, 4, 20, 10, 1, 0),
                            datetime(2026, 4, 20, 10, 50, 0),
                            2940,
                            ["alice", "bob"],
                            [
                                datetime(2026, 4, 20, 10, 1, 0),
                                datetime(2026, 4, 20, 10, 50, 0),
                            ],
                        )
                    ]
                )

        detector = password_spraying.PasswordSprayingDetector(
            case_id=7,
            analysis_id="review11-test",
            thresholds={"time_window_hours": 2},
        )
        detector._get_clickhouse_client = lambda: FakeClient()

        candidates = detector._find_spray_candidates()

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["bucket_start"], datetime(2026, 4, 20, 10, 0, 0))
        self.assertEqual(candidates[0]["first_attempt"], datetime(2026, 4, 20, 10, 1, 0))
        self.assertIn(
            "toStartOfInterval(COALESCE(timestamp_utc, timestamp), INTERVAL 2 HOUR) as bucket_start",
            captured["query"],
        )
        self.assertIn("GROUP BY src_ip, bucket_start", captured["query"])
        self.assertIn("groupArray(100)(COALESCE(timestamp_utc, timestamp))", captured["query"])

    def test_password_spray_success_accounts_stay_scoped_to_detected_window(self):
        captured = {}

        class FakeClient:
            @staticmethod
            def query(query):
                captured["query"] = query
                return _FakeResult([("alice",), ("bob",)])

        detector = password_spraying.PasswordSprayingDetector(
            case_id=7,
            analysis_id="review11-test",
        )
        detector._get_clickhouse_client = lambda: FakeClient()

        accounts = detector._get_successful_accounts(
            "10.0.0.5",
            datetime(2026, 4, 20, 10, 1, 0),
            datetime(2026, 4, 20, 10, 50, 0),
        )

        self.assertEqual(accounts, ["alice", "bob"])
        self.assertIn(
            "COALESCE(timestamp_utc, timestamp) BETWEEN toDateTime('2026-04-20 10:01:00') "
            "AND toDateTime('2026-04-20 10:50:00')",
            captured["query"],
        )

    def test_brute_force_candidates_group_by_configured_window(self):
        captured = {}

        class FakeClient:
            @staticmethod
            def query(query):
                captured["query"] = query
                return _FakeResult(
                    [
                        (
                            "alice",
                            datetime(2026, 4, 20, 11, 0, 0),
                            4,
                            10,
                            9,
                            1,
                            datetime(2026, 4, 20, 11, 5, 0),
                            datetime(2026, 4, 20, 11, 25, 0),
                            1200,
                            ["10.0.0.5", "10.0.0.6"],
                            [
                                datetime(2026, 4, 20, 11, 5, 0),
                                datetime(2026, 4, 20, 11, 25, 0),
                            ],
                        )
                    ]
                )

        detector = brute_force.BruteForceDetector(
            case_id=7,
            analysis_id="review11-test",
            thresholds={"time_window_hours": 1},
        )
        detector._get_clickhouse_client = lambda: FakeClient()

        candidates = detector._find_brute_candidates()

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["bucket_start"], datetime(2026, 4, 20, 11, 0, 0))
        self.assertEqual(candidates[0]["failures"], 9)
        self.assertIn(
            "toStartOfInterval(COALESCE(timestamp_utc, timestamp), INTERVAL 1 HOUR) as bucket_start",
            captured["query"],
        )
        self.assertIn("GROUP BY username, bucket_start", captured["query"])
        self.assertIn("groupArray(50)(COALESCE(timestamp_utc, timestamp))", captured["query"])

    def test_base_gap_detector_formats_sql_datetimes_without_fractional_seconds(self):
        detector = stateful_detectors.BaseGapDetector(case_id=7, analysis_id="review11-test")

        formatted = detector._format_sql_datetime(datetime(2026, 4, 20, 10, 1, 0, 123456))

        self.assertEqual(formatted, "2026-04-20 10:01:00")


if __name__ == "__main__":
    unittest.main()
