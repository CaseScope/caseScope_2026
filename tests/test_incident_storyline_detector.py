import importlib.util
import sys
import types
import unittest
from datetime import datetime
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_module(name: str, relative_path: str):
    module_path = REPO_ROOT / relative_path
    spec = importlib.util.spec_from_file_location(name, module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class _QueryResult:
    def __init__(self, rows):
        self.result_rows = rows


class _FakeClickHouseClient:
    def __init__(self):
        self.queries = []
        self.first = datetime(2026, 6, 1, 12, 0, 0)
        self.last = datetime(2026, 6, 1, 12, 10, 0)

    def query(self, sql, parameters=None):
        self.queries.append(sql)
        if 'toStartOfInterval(COALESCE(timestamp_utc, timestamp)' in sql:
            return _QueryResult([(self.first, self.last, 42)])
        if 'SELECT count()' in sql:
            return _QueryResult([(1,)])
        if 'WITH downloads AS' in sql:
            return _QueryResult([(
                'HOST-1',
                'user',
                self.first,
                'C:/Users/user/Downloads/dropper.exe',
                'dropper.exe',
                self.first,
                'dropper.exe',
                'C:/Users/user/Downloads/dropper.exe',
                'dropper.exe',
                '4688',
            )])
        if 'WITH download_hosts AS' in sql:
            return _QueryResult([(
                'HOST-1',
                'user',
                self.first,
                'mde_xdr',
                'Defender',
                '1116',
                'Defender blocked malware',
            )])
        return _QueryResult([])


class IncidentStorylineDetectorTestCase(unittest.TestCase):
    def test_detector_batches_without_source_row_limit(self):
        client = _FakeClickHouseClient()
        fake_utils = types.ModuleType('utils')
        fake_utils.__path__ = []
        fake_clickhouse = types.ModuleType('utils.clickhouse')
        fake_clickhouse.get_fresh_client = lambda: client

        previous_modules = {
            name: sys.modules.get(name)
            for name in ('utils', 'utils.clickhouse')
        }
        sys.modules['utils'] = fake_utils
        sys.modules['utils.clickhouse'] = fake_clickhouse

        try:
            module = _load_module(
                'incident_storyline_detector_under_test',
                'utils/incident_storyline_detector.py',
            )
        finally:
            for name, previous in previous_modules.items():
                if previous is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = previous

        progress = []
        detector = module.IncidentStorylineDetector(
            7,
            target_downloads_per_window=10,
            progress_callback=lambda *_args: progress.append(_args),
        )

        result = detector.build()

        self.assertEqual(result['storyline_count'], 1)
        self.assertEqual(result['download_count'], 1)
        self.assertEqual(result['containment_count'], 1)
        self.assertEqual(result['windows_processed'], 1)
        self.assertTrue(progress)
        self.assertFalse(any('max_source_rows' in query for query in client.queries))


if __name__ == '__main__':
    unittest.main()
