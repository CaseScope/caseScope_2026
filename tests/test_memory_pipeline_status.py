import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
from datetime import datetime
from unittest.mock import patch

os.environ.setdefault('SECRET_KEY', 'test-secret')

BASE_DIR = os.path.dirname(os.path.dirname(__file__))


class _FakeSession:
    def __init__(self):
        self.commit_calls = 0
        self.rollback_calls = 0

    def commit(self):
        self.commit_calls += 1

    def rollback(self):
        self.rollback_calls += 1


fake_session = _FakeSession()
fake_db = types.SimpleNamespace(session=fake_session)

models_package = types.ModuleType('models')
sys.modules.setdefault('models', models_package)

database_module = types.ModuleType('models.database')
database_module.db = fake_db
sys.modules['models.database'] = database_module
models_package.database = database_module

memory_data_module = types.ModuleType('models.memory_data')
for class_name in [
    'MemoryProcess', 'MemoryNetwork', 'MemoryService', 'MemoryMalfind',
    'MemoryModule', 'MemoryCredential', 'MemorySID', 'MemoryInfo',
]:
    setattr(memory_data_module, class_name, type(class_name, (), {}))
sys.modules['models.memory_data'] = memory_data_module
models_package.memory_data = memory_data_module

memory_job_module = types.ModuleType('models.memory_job')
memory_job_module.MemoryJob = type('MemoryJob', (), {})
sys.modules['models.memory_job'] = memory_job_module
models_package.memory_job = memory_job_module

artifact_paths_spec = importlib.util.spec_from_file_location(
    'utils.artifact_paths',
    os.path.join(BASE_DIR, 'utils', 'artifact_paths.py'),
)
artifact_paths_module = importlib.util.module_from_spec(artifact_paths_spec)
artifact_paths_spec.loader.exec_module(artifact_paths_module)

utils_package = types.ModuleType('utils')
utils_package.artifact_paths = artifact_paths_module
sys.modules.setdefault('utils', utils_package)
sys.modules['utils.artifact_paths'] = artifact_paths_module

celery_module = types.ModuleType('celery')
celery_module.shared_task = lambda *args, **kwargs: (lambda func: func)
sys.modules.setdefault('celery', celery_module)

redis_module = types.ModuleType('redis')
redis_module.Redis = object
sys.modules.setdefault('redis', redis_module)

memory_parser_spec = importlib.util.spec_from_file_location(
    'memory_parser_under_test',
    os.path.join(BASE_DIR, 'parsers', 'memory_parser.py'),
)
memory_parser = importlib.util.module_from_spec(memory_parser_spec)
memory_parser_spec.loader.exec_module(memory_parser)

memory_tasks_spec = importlib.util.spec_from_file_location(
    'memory_tasks_under_test',
    os.path.join(BASE_DIR, 'tasks', 'memory_tasks.py'),
)
memory_tasks = importlib.util.module_from_spec(memory_tasks_spec)
memory_tasks_spec.loader.exec_module(memory_tasks)


class _FakeQuery:
    def __init__(self, obj):
        self.obj = obj

    def get(self, _job_id):
        return self.obj

    def filter_by(self, **_kwargs):
        return self

    def first(self):
        return self.obj


class MemoryPipelineStatusTestCase(unittest.TestCase):
    def test_extract_timestamp_from_info_supports_variable_value_rows(self):
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as handle:
            json.dump([
                {'Variable': 'Kernel Base', 'Value': '0x1234'},
                {'Variable': 'SystemTime', 'Value': '2026-03-11 13:14:49+00:00'},
            ], handle)
            path = handle.name

        try:
            parsed = memory_tasks.extract_timestamp_from_info(path)
            self.assertEqual(parsed, datetime(2026, 3, 11, 13, 14, 49))
        finally:
            os.remove(path)

    def test_merge_plugin_ingestion_results_tracks_zero_rows_and_unsupported(self):
        completed = [
            {'name': 'windows.netscan', 'row_count': 0},
            {'name': 'windows.psscan', 'row_count': 239},
        ]
        failed = [{'name': 'windows.scheduled_tasks', 'error': 'page fault'}]
        ingest_result = {
            'plugin_statuses': {
                'windows_netscan': {'state': 'completed_zero_rows', 'count': 0},
                'windows_psscan': {
                    'state': 'completed_unsupported',
                    'count': 239,
                    'reason': 'Retained as raw output only',
                },
            }
        }

        merged_completed, merged_failed = memory_tasks.merge_plugin_ingestion_results(
            completed,
            failed,
            ingest_result,
        )

        self.assertEqual(merged_completed[0]['state'], 'completed_zero_rows')
        self.assertEqual(merged_completed[1]['state'], 'completed_unsupported')
        self.assertEqual(merged_completed[1]['reason'], 'Retained as raw output only')
        self.assertEqual(merged_failed[0]['state'], 'failed')

    def test_parse_output_folder_prefers_netscan_and_marks_netstat_unsupported(self):
        parser = memory_parser.MemoryParser(job_id=1, case_id=1, hostname='HOST1')

        def _count_rows(self, filepath):
            return self._count_json_rows(filepath)

        parser.parse_network = types.MethodType(_count_rows, parser)

        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, 'windows_netscan.json'), 'w', encoding='utf-8') as handle:
                json.dump([{'PID': 1, 'LocalAddr': '10.0.0.1'}], handle)
            with open(os.path.join(tmpdir, 'windows_netstat.json'), 'w', encoding='utf-8') as handle:
                json.dump([{'PID': 2, 'LocalAddr': '10.0.0.2'}], handle)
            with open(os.path.join(tmpdir, 'windows_psscan.json'), 'w', encoding='utf-8') as handle:
                json.dump([{'PID': 123, 'ImageFileName': 'hidden.exe'}], handle)

            result = parser.parse_output_folder(tmpdir)

        self.assertTrue(result['success'])
        self.assertEqual(result['plugin_statuses']['windows_netscan']['state'], 'completed_ingested')
        self.assertEqual(result['plugin_statuses']['windows_netstat']['state'], 'completed_unsupported')
        self.assertIn('netscan already produced network results', result['plugin_statuses']['windows_netstat']['reason'])
        self.assertEqual(result['plugin_statuses']['windows_psscan']['state'], 'completed_unsupported')

    def test_parse_output_folder_uses_netstat_when_netscan_is_empty(self):
        parser = memory_parser.MemoryParser(job_id=1, case_id=1, hostname='HOST1')

        def _count_rows(self, filepath):
            return self._count_json_rows(filepath)

        parser.parse_network = types.MethodType(_count_rows, parser)

        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, 'windows_netscan.json'), 'w', encoding='utf-8') as handle:
                json.dump([], handle)
            with open(os.path.join(tmpdir, 'windows_netstat.json'), 'w', encoding='utf-8') as handle:
                json.dump([{'PID': 2, 'LocalAddr': '10.0.0.2'}], handle)

            result = parser.parse_output_folder(tmpdir)

        self.assertTrue(result['success'])
        self.assertEqual(result['plugin_statuses']['windows_netscan']['state'], 'completed_zero_rows')
        self.assertEqual(result['plugin_statuses']['windows_netstat']['state'], 'completed_ingested')

    def test_ingest_memory_job_propagates_system_time_to_job(self):
        fake_job = types.SimpleNamespace(
            id=7,
            case_id=22,
            hostname='HOST1',
            output_folder=None,
            memory_timestamp=None,
        )
        fake_info = types.SimpleNamespace(system_time=datetime(2026, 3, 11, 13, 14, 49))

        memory_job_module.MemoryJob.query = _FakeQuery(fake_job)
        memory_parser.MemoryInfo.query = _FakeQuery(fake_info)

        with tempfile.TemporaryDirectory() as tmpdir:
            os.makedirs(os.path.join(tmpdir, 'vol3_output'), exist_ok=True)
            fake_job.output_folder = tmpdir

            with patch.object(memory_parser, 'clear_job_data', lambda _job_id: None):
                with patch.object(memory_parser, 'update_cross_memory_counts', lambda _case_id: None):
                    with patch.object(
                        memory_parser.MemoryParser,
                        'parse_output_folder',
                        return_value={'success': True, 'plugin_statuses': {}},
                    ):
                        result = memory_parser.ingest_memory_job(7)

        self.assertTrue(result['success'])
        self.assertEqual(fake_job.memory_timestamp, fake_info.system_time)


if __name__ == '__main__':
    unittest.main()
