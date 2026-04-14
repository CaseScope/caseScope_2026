import importlib.util
import unittest
import sys
import types
from unittest.mock import Mock, patch

def _load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _load_modules():
    fake_utils = types.ModuleType('utils')
    fake_utils.__path__ = []
    fake_models = types.ModuleType('models')
    fake_models.__path__ = []

    fake_clickhouse = types.ModuleType('utils.clickhouse')
    fake_clickhouse.get_fresh_client = lambda: None

    fake_timezone = types.ModuleType('utils.timezone')
    fake_timezone.format_for_display = lambda value, _tz: str(value)

    fake_case = types.ModuleType('models.case')
    fake_case.Case = type('Case', (), {'get_by_id': staticmethod(lambda _case_id: None)})

    fake_case_file = types.ModuleType('models.case_file')
    fake_case_file.CaseFile = type('CaseFile', (), {'query': None})

    fake_database = types.ModuleType('models.database')
    fake_database.db = types.SimpleNamespace(
        or_=lambda *args: ('or', args),
        session=types.SimpleNamespace(rollback=lambda: None),
    )

    fake_memory_data = types.ModuleType('models.memory_data')
    for name in ['MemoryCredential', 'MemoryMalfind', 'MemoryModule', 'MemoryNetwork', 'MemoryProcess', 'MemoryService']:
        setattr(fake_memory_data, name, type(name, (), {}))

    fake_memory_job = types.ModuleType('models.memory_job')
    fake_memory_job.MemoryJob = type('MemoryJob', (), {})

    fake_network_log = types.ModuleType('models.network_log')
    fake_network_log.query_logs = lambda **kwargs: {}
    fake_network_log.search_all_logs = lambda **kwargs: {}

    fake_ioc = types.ModuleType('models.ioc')
    fake_ioc.IOC = type('IOC', (), {'query': None})
    fake_ioc.detect_ioc_type_from_value = lambda value: 'IP Address (IPv4)' if value and '.' in value else 'File Name'
    fake_ioc.detect_match_type = lambda _value, _ioc_type: 'token'

    fake_ioc_artifact_tagger = types.ModuleType('utils.ioc_artifact_tagger')
    fake_ioc_artifact_tagger.search_artifacts_for_ioc = lambda **kwargs: {}
    fake_ioc_artifact_tagger.build_ioc_match_clause = lambda value, _ioc_type, _match_type: f"positionCaseInsensitive(search_blob, '{value}') > 0"

    previous_modules = {
        name: sys.modules.get(name)
        for name in [
            'utils',
            'utils.clickhouse',
            'utils.provenance',
            'utils.timezone',
            'utils.forensic_chat_sources',
            'utils.chat_tools',
            'models',
            'models.case',
            'models.case_file',
            'models.database',
            'models.memory_data',
            'models.memory_job',
            'models.network_log',
            'models.ioc',
            'utils.ioc_artifact_tagger',
        ]
    }

    sys.modules['utils'] = fake_utils
    sys.modules['utils.clickhouse'] = fake_clickhouse
    provenance_module = _load_module(
        'utils.provenance',
        '/opt/casescope/utils/provenance.py',
    )
    sys.modules['utils.provenance'] = provenance_module
    sys.modules['utils.timezone'] = fake_timezone
    sys.modules['models'] = fake_models
    sys.modules['models.case'] = fake_case
    sys.modules['models.case_file'] = fake_case_file
    sys.modules['models.database'] = fake_database
    sys.modules['models.memory_data'] = fake_memory_data
    sys.modules['models.memory_job'] = fake_memory_job
    sys.modules['models.network_log'] = fake_network_log
    sys.modules['models.ioc'] = fake_ioc
    sys.modules['utils.ioc_artifact_tagger'] = fake_ioc_artifact_tagger

    try:
        forensic_module = _load_module(
            'utils.forensic_chat_sources',
            '/opt/casescope/utils/forensic_chat_sources.py',
        )
        sys.modules['utils.forensic_chat_sources'] = forensic_module
        chat_module = _load_module(
            'utils.chat_tools',
            '/opt/casescope/utils/chat_tools.py',
        )
        sys.modules['utils.chat_tools'] = chat_module
        return forensic_module, chat_module
    finally:
        for name, previous in previous_modules.items():
            if previous is not None:
                sys.modules[name] = previous
            else:
                sys.modules.pop(name, None)


class _DummyCase:
    timezone = 'UTC'


class _FakeResult:
    def __init__(self, rows):
        self.result_rows = rows


class _ArtifactSearchClient:
    def __init__(self):
        self.calls = []

    def query(self, query, parameters=None):
        self.calls.append((query, parameters))
        if 'SELECT count()' in query:
            return _FakeResult([(3,)])
        if 'GROUP BY artifact_type' in query:
            return _FakeResult([
                ('browser_download', 2),
                ('registry', 1),
            ])
        return _FakeResult([
            ('2026-04-01 10:00:00', 'browser_download', 'HOST-1', 'alice', '1', 'chrome.exe',
             r'C:\Users\alice\Downloads\evil.exe', 'chrome.exe --type=renderer', 'Download detected',
             'History', ['filename'], 'browser_download evil.exe'),
        ])


class _ProcessSearchClient:
    def __init__(self):
        self.calls = []

    def query(self, query, parameters=None):
        self.calls.append((query, parameters or {}))
        return _FakeResult([])


class _BrowserDownloadClient:
    def __init__(self):
        self.calls = []

    def query(self, query, parameters=None):
        self.calls.append((query, parameters or {}))
        return _FakeResult([
            (
                '2026-04-01 10:00:00',
                'HOST-1',
                r'C:\Users\alice\Downloads\evil.exe',
                'alice',
                '{"file_path":"C:\\\\Users\\\\alice\\\\Downloads\\\\evil.exe","url":"https://example.test/evil.exe","filename":"evil.exe"}',
                '{}',
                ['filename'],
                'History',
                None,
            ),
        ])


class _ChatToolClient:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def query(self, query, parameters=None):
        self.calls.append((query, parameters or {}))
        return _FakeResult(self.rows)


class _LookupIOCClient:
    def __init__(self):
        self.calls = []

    def query(self, query, parameters=None):
        self.calls.append((query, parameters or {}))
        if 'GROUP BY source_host' in query:
            return _FakeResult([
                ('ACMAT-DC', 4),
                ('ATN82194', 2),
            ])
        if "event_id = '4624'" in query:
            return _FakeResult([
                ('Support', 'ACMAT-DC', 3, 'WS-44', 'vpn-gw-01', 2, '2026-01-27 11:40:00', '2026-01-27 12:00:00'),
                ('hmckaig', 'ATN82194', 10, 'WS-44', 'vpn-gw-01', 1, '2026-01-27 12:58:00', '2026-01-27 12:58:00'),
            ])
        return _FakeResult([])


class ForensicChatToolTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.forensic_chat_sources, cls.chat_tools = _load_modules()

    def test_tool_registry_includes_new_forensic_tools(self):
        expected_tools = {
            'search_artifacts',
            'get_browser_downloads',
            'get_processes',
            'get_process_tree',
            'search_memory',
            'search_network_logs',
        }

        self.assertTrue(expected_tools.issubset(set(self.chat_tools.TOOL_REGISTRY.keys())))
        defined = {tool['function']['name'] for tool in self.chat_tools.TOOL_DEFINITIONS}
        self.assertTrue(expected_tools.issubset(defined))

    def test_search_artifacts_uses_bound_parameters_and_breakdown(self):
        client = _ArtifactSearchClient()

        with patch.object(self.forensic_chat_sources.Case, 'get_by_id', return_value=_DummyCase()), \
             patch.object(self.forensic_chat_sources, 'get_fresh_client', return_value=client):
            result = self.forensic_chat_sources.search_artifacts(
                9,
                search="evil.exe",
                artifact_type="browser_download,registry",
                host="srv' OR 1=1 --",
                username='alice',
                limit=10,
            )

        self.assertEqual(result['total_matches'], 3)
        self.assertEqual(result['artifact_types']['browser_download'], 2)
        row_query, row_params = client.calls[-1]
        self.assertIn('{search:String}', row_query)
        self.assertIn('{host:String}', row_query)
        self.assertIn('{artifact_types:Array(String)}', row_query)
        self.assertNotIn("srv' OR 1=1 --", row_query)
        self.assertEqual(row_params['host'], "srv' OR 1=1 --")
        self.assertEqual(row_params['artifact_types'], ['browser_download', 'registry'])
        self.assertEqual(result['provenance_summary']['highest_provenance'], 'ELEVATED_RISK')
        self.assertEqual(result['artifacts'][0]['field_provenance']['host'], 'SYSTEM_DERIVED')
        self.assertEqual(result['artifacts'][0]['field_provenance']['summary'], 'ELEVATED_RISK')
        self.assertEqual(result['_provenance']['emitted_provenance'], 'ELEVATED_RISK')

    def test_browser_download_tool_surfaces_ioc_flagged_downloads(self):
        fake_result = {
            'downloads': [{
                'filename': 'evil.exe',
                'file_path': r'C:\Users\alice\Downloads\evil.exe',
                'source_host': 'HOST-1',
                'username': 'alice',
                'source_url': 'https://example.test/evil.exe',
                'ioc_types': ['filename'],
                'has_ioc': True,
            }],
            'total': 1,
            'provenance_summary': {'highest_provenance': 'ELEVATED_RISK'},
            '_provenance': {'emitted_provenance': 'ELEVATED_RISK'},
        }

        with patch.object(self.chat_tools, 'get_browser_download_rows', return_value=fake_result):
            result = self.chat_tools.get_browser_downloads(14, filename='evil.exe')

        self.assertEqual(result['total'], 1)
        self.assertTrue(result['downloads'][0]['has_ioc'])
        self.assertEqual(result['provenance_summary']['highest_provenance'], 'ELEVATED_RISK')
        self.assertEqual(result['_provenance']['emitted_provenance'], 'ELEVATED_RISK')
        self.assertEqual(result['filters']['filename'], 'evil.exe')

    def test_browser_download_rows_emit_provenance_metadata(self):
        client = _BrowserDownloadClient()

        with patch.object(self.forensic_chat_sources.Case, 'get_by_id', return_value=_DummyCase()), \
             patch.object(self.forensic_chat_sources, 'get_fresh_client', return_value=client):
            result = self.forensic_chat_sources.get_browser_download_rows(
                9,
                filename='evil.exe',
                limit=10,
            )

        self.assertEqual(result['total'], 1)
        self.assertEqual(result['provenance_summary']['highest_provenance'], 'ELEVATED_RISK')
        self.assertEqual(result['downloads'][0]['field_provenance']['source_host'], 'SYSTEM_DERIVED')
        self.assertEqual(result['downloads'][0]['field_provenance']['filename'], 'ELEVATED_RISK')
        self.assertEqual(result['_provenance']['emitted_provenance'], 'ELEVATED_RISK')

    def test_network_tool_uses_shared_backend_wrapper(self):
        fake_result = {'success': True, 'logs': [{'log_type': 'http'}], 'total': 1}

        with patch.object(self.chat_tools, 'search_network_logs_for_case', return_value=fake_result) as search_mock:
            result = self.chat_tools.search_network_logs(27, search='evil.exe', log_type='http', limit=12)

        self.assertEqual(result['total'], 1)
        search_mock.assert_called_once_with(
            27,
            search='evil.exe',
            log_type='http',
            pcap_id=None,
            src_ip='',
            dst_ip='',
            limit=12,
        )

    def test_get_processes_accepts_multiple_hostnames(self):
        client = _ProcessSearchClient()
        memory_job_query = Mock()
        memory_job_query.filter_by.return_value = memory_job_query
        memory_job_query.filter.return_value = memory_job_query
        memory_job_query.all.return_value = []

        with patch.object(self.forensic_chat_sources.Case, 'get_by_id', return_value=_DummyCase()), \
             patch.object(self.forensic_chat_sources, 'get_fresh_client', return_value=client), \
             patch.object(self.forensic_chat_sources.MemoryJob, 'query', memory_job_query, create=True):
            result = self.forensic_chat_sources.get_unified_process_list(
                9,
                hostname=['ACMAT-DC', 'ATN82730', 'ATN82194'],
                source='events',
                limit=10,
            )

        self.assertEqual(result['total'], 0)
        query_text, query_params = client.calls[0]
        self.assertIn('{hostnames:Array(String)}', query_text)
        self.assertEqual(query_params['hostnames'], ['ACMAT-DC', 'ATN82730', 'ATN82194'])

    def test_execute_tool_rolls_back_failed_tool_calls(self):
        rollback = Mock()

        with patch.dict(self.chat_tools.TOOL_REGISTRY, {'boom': lambda **_: (_ for _ in ()).throw(RuntimeError('broken'))}, clear=False), \
             patch.object(self.chat_tools.db.session, 'rollback', rollback):
            result = self.chat_tools.execute_tool('boom', 9, {})

        self.assertIn('Tool execution failed', result['error'])
        rollback.assert_called_once()

    def test_query_events_returns_source_side_logon_fields(self):
        client = _ChatToolClient([
            (
                '2026-01-01 00:00:00', '4624', 'host-a', 'alice', 'Security', 'Rule',
                'high', 'cmd.exe', 'cmd /c whoami', '1.2.3.4', '5.6.7.8', 3,
                'vpn-gw-01', 'WS-44', 'NTLM', 'Advapi',
                'IpAddress:1.2.3.4 WorkstationName:WS-44'
            )
        ])

        with patch.object(self.chat_tools, 'get_fresh_client', return_value=client):
            result = self.chat_tools.query_events(case_id=7, event_id='4624')

        self.assertEqual(result['events'][0]['remote_host'], 'vpn-gw-01')
        self.assertEqual(result['events'][0]['workstation_name'], 'WS-44')
        self.assertEqual(result['events'][0]['auth_package'], 'NTLM')
        self.assertEqual(result['events'][0]['logon_process'], 'Advapi')
        self.assertIn('WorkstationName:WS-44', result['events'][0]['summary'])

    def test_count_events_accepts_source_group_aliases(self):
        client = _ChatToolClient([('WS-44', 2)])

        with patch.object(self.chat_tools, 'get_fresh_client', return_value=client):
            result = self.chat_tools.count_events(case_id=7, event_id='4624', group_by='workstation')

        query, _ = client.calls[0]
        self.assertIn('SELECT workstation_name, count() as cnt', query)
        self.assertEqual(result['grouped_by'], 'workstation_name')
        self.assertEqual(result['groups'][0]['value'], 'WS-44')
        self.assertEqual(result['groups'][0]['count'], 2)

    def test_lookup_ioc_returns_source_side_logon_context_for_ip_addresses(self):
        fake_ioc_module = types.ModuleType('models.ioc')
        fake_value_normalized = type('ValueNormalized', (), {
            'ilike': staticmethod(lambda _pattern: ('ilike', _pattern)),
        })

        class _KnownIOCQuery:
            def filter_by(self, **_kwargs):
                return self

            def filter(self, *_args, **_kwargs):
                return self

            def limit(self, _limit):
                return self

            def all(self):
                return []

        fake_ioc_model = type('IOC', (), {
            'query': _KnownIOCQuery(),
            'value_normalized': fake_value_normalized,
        })
        fake_ioc_module.IOC = fake_ioc_model
        fake_ioc_module.detect_ioc_type_from_value = lambda _value: 'IP Address (IPv4)'
        fake_ioc_module.detect_match_type = lambda _value, _ioc_type: 'token'

        fake_ioc_artifact_tagger = types.ModuleType('utils.ioc_artifact_tagger')
        fake_ioc_artifact_tagger.search_artifacts_for_ioc = lambda **_kwargs: {}
        fake_ioc_artifact_tagger.build_ioc_match_clause = (
            lambda value, _ioc_type, _match_type: f"positionCaseInsensitive(search_blob, '{value}') > 0"
        )

        fake_artifact_result = {
            'match_count': 6,
            'earliest': '2026-01-27 11:39:56',
            'latest': '2026-01-28 03:14:10',
            'artifact_types': {'evtx': 6},
        }
        client = _LookupIOCClient()

        with patch.object(self.chat_tools, 'get_fresh_client', return_value=client), \
             patch.dict(sys.modules, {
                 'models.ioc': fake_ioc_module,
                 'utils.ioc_artifact_tagger': fake_ioc_artifact_tagger,
             }), \
             patch.object(fake_ioc_artifact_tagger, 'search_artifacts_for_ioc', return_value=fake_artifact_result):
            result = self.chat_tools.lookup_ioc(9, '10.20.30.11')

        self.assertEqual(result['matched_hosts']['ACMAT-DC'], 4)
        self.assertEqual(result['ip_logon_context']['successful_users']['Support'], 2)
        self.assertEqual(result['ip_logon_context']['source_workstations']['WS-44'], 3)
        self.assertEqual(result['ip_logon_context']['source_remote_hosts']['vpn-gw-01'], 3)
        self.assertEqual(result['ip_logon_context']['successful_logons'][0]['user'], 'Support')


if __name__ == '__main__':
    unittest.main()
