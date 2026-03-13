import os
import sys
import types
import unittest
from unittest.mock import patch

os.environ.setdefault('SECRET_KEY', 'test-secret')

from parsers.registry import BatchProcessor, process_file


class _FakeEvent:
    def __init__(self, payload):
        self.payload = payload

    def to_clickhouse_row(self):
        return self.payload


class _FakeParser:
    def __init__(self):
        self.errors = []
        self.warnings = []

    def can_parse(self, _file_path):
        return True

    def parse(self, _file_path):
        yield _FakeEvent(['row-1'])
        raise RuntimeError('parser exploded')


class _FakeRegistry:
    def detect_type(self, _file_path):
        return 'fake'

    def get_parser(self, **_kwargs):
        return _FakeParser()


class _FakeClient:
    def __init__(self):
        self.inserts = []

    def insert(self, table, batch, column_names=None):
        self.inserts.append((table, list(batch), column_names))


class BatchProcessorSafetyTestCase(unittest.TestCase):
    def test_batch_processor_does_not_flush_on_exception_exit(self):
        client = _FakeClient()
        processor = BatchProcessor(client, batch_size=100)

        with self.assertRaises(RuntimeError):
            with processor as active_processor:
                active_processor.add_event(_FakeEvent(['row-1']))
                raise RuntimeError('boom')

        self.assertEqual(client.inserts, [])

    def test_process_file_cleans_partial_rows_after_parser_failure(self):
        client = _FakeClient()
        clickhouse_module = types.ModuleType('utils.clickhouse')
        delete_calls = []

        def _delete_file_events(case_file_id):
            delete_calls.append(case_file_id)

        clickhouse_module.delete_file_events = _delete_file_events
        utils_package = types.ModuleType('utils')
        utils_package.clickhouse = clickhouse_module

        with patch('parsers.registry._get_registry', return_value=_FakeRegistry()):
            with patch.dict(sys.modules, {'utils': utils_package, 'utils.clickhouse': clickhouse_module}):
                result = process_file(
                    file_path='/tmp/example.evtx',
                    case_id=42,
                    source_host='HOST1',
                    case_file_id=99,
                    clickhouse_client=client,
                    batch_size=1,
                )

        self.assertFalse(result.success)
        self.assertEqual(len(client.inserts), 1)
        self.assertEqual(delete_calls, [99])


if __name__ == '__main__':
    unittest.main()
