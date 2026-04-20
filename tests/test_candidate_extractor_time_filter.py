import importlib.util
import sys
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_module(name: str, relative_path: str):
    module_path = REPO_ROOT / relative_path
    spec = importlib.util.spec_from_file_location(name, module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


utils_pkg = sys.modules.setdefault("utils", types.ModuleType("utils"))
utils_pkg.__path__ = [str(REPO_ROOT / "utils")]

clickhouse_stub = types.ModuleType("utils.clickhouse")
clickhouse_stub.get_fresh_client = lambda: None
sys.modules["utils.clickhouse"] = clickhouse_stub
utils_pkg.clickhouse = clickhouse_stub

models_pkg = sys.modules.setdefault("models", types.ModuleType("models"))
database_stub = types.ModuleType("models.database")
database_stub.db = object()
sys.modules["models.database"] = database_stub
models_pkg.database = database_stub

candidate_extractor = _load_module(
    "candidate_extractor_time_filter_module",
    Path("utils") / "candidate_extractor.py",
)


class CandidateExtractorTimeFilterTestCase(unittest.TestCase):
    def setUp(self):
        self.extractor = object.__new__(candidate_extractor.CandidateExtractor)

    def test_build_time_filter_uses_utc_normalized_timestamp_column(self):
        clause = self.extractor._build_time_filter(
            datetime(2026, 4, 20, 10, 0, 0),
            datetime(2026, 4, 20, 11, 30, 0),
        )

        self.assertEqual(
            clause,
            "COALESCE(timestamp_utc, timestamp) >= '2026-04-20 10:00:00' "
            "AND COALESCE(timestamp_utc, timestamp) <= '2026-04-20 11:30:00'",
        )

    def test_build_time_filter_converts_aware_inputs_to_naive_utc(self):
        eastern = timezone(timedelta(hours=-4))

        clause = self.extractor._build_time_filter(
            datetime(2026, 4, 20, 10, 0, 0, tzinfo=eastern),
            datetime(2026, 4, 20, 11, 30, 0, tzinfo=eastern),
        )

        self.assertEqual(
            clause,
            "COALESCE(timestamp_utc, timestamp) >= '2026-04-20 14:00:00' "
            "AND COALESCE(timestamp_utc, timestamp) <= '2026-04-20 15:30:00'",
        )


if __name__ == "__main__":
    unittest.main()
