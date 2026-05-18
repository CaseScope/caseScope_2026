import importlib.util
import os
import unittest
import sys
import types
from unittest.mock import Mock, patch


os.environ.setdefault("SECRET_KEY", "test-secret")

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
    fake_clickhouse.get_client = lambda: None
    fake_clickhouse.clickhouse_string_literal = lambda value: f"'{value}'"
    fake_clickhouse.clickhouse_bool_literal = lambda value: 'true' if value else 'false'
    fake_clickhouse.clickhouse_nullable_string_literal = lambda value: 'NULL' if value is None else f"'{value}'"
    fake_clickhouse.clickhouse_string_array_literal = (
        lambda values: "[" + ", ".join(f"'{value}'" for value in values) + "]"
    )
    fake_clickhouse.run_events_update = lambda *_args, **_kwargs: True

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
    fake_network_log.get_pcap_stats = lambda _case_id: []

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
            'utils.event_selector',
            'utils.event_ioc_state',
            'utils.event_noise_state',
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
    selector_module = _load_module(
        'utils.event_selector',
        '/opt/casescope/utils/event_selector.py',
    )
    sys.modules['utils.event_selector'] = selector_module
    fake_utils.event_selector = selector_module
    ioc_state_module = _load_module(
        'utils.event_ioc_state',
        '/opt/casescope/utils/event_ioc_state.py',
    )
    sys.modules['utils.event_ioc_state'] = ioc_state_module
    fake_utils.event_ioc_state = ioc_state_module
    noise_state_module = _load_module(
        'utils.event_noise_state',
        '/opt/casescope/utils/event_noise_state.py',
    )
    sys.modules['utils.event_noise_state'] = noise_state_module
    fake_utils.event_noise_state = noise_state_module
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


class _ProcessTreeClient:
    def __init__(self):
        self.calls = []

    def query(self, query, parameters=None):
        self.calls.append((query, parameters or {}))
        parameters = parameters or {}
        if 'parent_pid' in parameters:
            if parameters['parent_pid'] == 4242:
                return _FakeResult([
                    ('HOST-1', 5000, 'powershell.exe', '2026-04-01 10:01:00', 4242, 'cmd.exe', 'powershell.exe -enc AAAA', 'alice'),
                ])
            return _FakeResult([])
        if parameters.get('pid') == 4242:
            return _FakeResult([
                ('HOST-1', 4242, 'cmd.exe', '2026-04-01 10:00:00', 1000, 'explorer.exe', 'cmd.exe /c whoami', 'alice', r'C:\Windows\System32\cmd.exe'),
            ])
        return _FakeResult([])


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


class _FakeMemoryMatch:
    def __init__(self, job_id, payload):
        self.job_id = job_id
        self._payload = payload

    def to_dict(self, **_kwargs):
        return dict(self._payload)


class _PredicateField:
    def contains(self, _value):
        return self

    def ilike(self, _value):
        return self

    def in_(self, _value):
        return self

    def __eq__(self, _value):
        return self


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
        fake_result = {
            'success': True,
            'logs': [{'log_type': 'http'}],
            'total': 1,
            'provenance_summary': {'highest_provenance': 'SYSTEM_DERIVED'},
            '_provenance': {'emitted_provenance': 'SYSTEM_DERIVED'},
        }

        with patch.object(self.chat_tools, 'search_network_logs_for_case', return_value=fake_result) as search_mock:
            result = self.chat_tools.search_network_logs(
                27,
                search='evil.exe',
                log_type='http',
                time_start='2026-05-14T00:00:00Z',
                time_end='2026-05-15T00:00:00Z',
                source_availability_status='available',
                limit=12,
            )

        self.assertEqual(result['total'], 1)
        self.assertEqual(result['provenance_summary']['highest_provenance'], 'SYSTEM_DERIVED')
        search_mock.assert_called_once_with(
            27,
            search='evil.exe',
            log_type='http',
            pcap_id=None,
            src_ip='',
            dst_ip='',
            time_start='2026-05-14T00:00:00Z',
            time_end='2026-05-15T00:00:00Z',
            limit=12,
            source_availability_status='available',
            missing_sources=[],
            limitations=[],
        )

    def test_search_network_logs_for_case_emits_provenance_metadata(self):
        fake_result = {
            'success': True,
            'logs': [{
                'log_type': 'http',
                'timestamp': '2026-04-01 10:00:00',
                'uid': 'C1',
                'source_host': 'HOST-1',
                'pcap_id': 12,
                'host': 'example.test',
                'uri': '/evil.exe',
            }],
            'total': 1,
        }

        pcap_stats = [{
            'pcap_id': 12,
            'source_host': 'HOST-1',
            'by_type': {'http': 1},
            'total': 1,
        }]

        with patch.object(self.forensic_chat_sources.network_log, 'query_logs', return_value=fake_result) as query_mock, \
             patch.object(self.forensic_chat_sources.network_log, 'get_pcap_stats', return_value=pcap_stats):
            result = self.forensic_chat_sources.search_network_logs_for_case(
                9,
                search='evil.exe',
                log_type='http',
                time_start='2026-04-01T00:00:00Z',
                time_end='2026-04-02T00:00:00Z',
                source_availability_status='available',
                limit=10,
            )

        self.assertEqual(result['total'], 1)
        self.assertEqual(result['returned_count'], 1)
        self.assertEqual(result['network_query']['time_start'], '2026-04-01T00:00:00Z')
        self.assertEqual(result['coverage_status'], 'complete')
        self.assertEqual(result['coverage_detail']['source_metadata']['reviewed_pcap_ids'], [12])
        self.assertEqual(result['coverage_detail']['source_metadata']['reviewed_log_types'], ['http'])
        query_mock.assert_called_once()
        self.assertEqual(query_mock.call_args.kwargs['time_start'], '2026-04-01T00:00:00Z')
        self.assertEqual(query_mock.call_args.kwargs['time_end'], '2026-04-02T00:00:00Z')
        self.assertEqual(result['provenance_summary']['highest_provenance'], 'ARTIFACT_TAINTED')
        self.assertEqual(result['logs'][0]['field_provenance']['source_host'], 'SYSTEM_DERIVED')
        self.assertEqual(result['logs'][0]['field_provenance']['uid'], 'SYSTEM_DERIVED')
        self.assertEqual(result['logs'][0]['field_provenance']['uri'], 'ARTIFACT_TAINTED')
        self.assertEqual(result['_provenance']['emitted_provenance'], 'ARTIFACT_TAINTED')

    def test_search_network_logs_for_case_requires_time_bounds(self):
        result = self.forensic_chat_sources.search_network_logs_for_case(
            9,
            search='evil.exe',
            log_type='http',
            source_availability_status='available',
            limit=10,
        )

        self.assertFalse(result['success'])
        self.assertEqual(result['total'], 0)
        self.assertEqual(result['coverage_status'], 'insufficient')
        self.assertIn('time_start', result['error'])

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

    def test_get_processes_emits_provenance_for_event_rows(self):
        client = _ChatToolClient([
            (
                'HOST-1',
                4242,
                'cmd.exe',
                '2026-04-01 10:00:00',
                1000,
                'explorer.exe',
                'cmd.exe /c whoami',
                'alice',
                r'C:\Windows\System32\cmd.exe',
                3,
            )
        ])
        memory_job_query = Mock()
        memory_job_query.filter_by.return_value = memory_job_query
        memory_job_query.filter.return_value = memory_job_query
        memory_job_query.all.return_value = []

        with patch.object(self.forensic_chat_sources.Case, 'get_by_id', return_value=_DummyCase()), \
             patch.object(self.forensic_chat_sources, 'get_fresh_client', return_value=client), \
             patch.object(self.forensic_chat_sources.MemoryJob, 'query', memory_job_query, create=True):
            result = self.forensic_chat_sources.get_unified_process_list(
                9,
                source='events',
                limit=10,
            )

        self.assertEqual(result['total'], 1)
        self.assertEqual(result['provenance_summary']['highest_provenance'], 'ARTIFACT_TAINTED')
        self.assertEqual(result['processes'][0]['field_provenance']['hostname'], 'SYSTEM_DERIVED')
        self.assertEqual(result['processes'][0]['field_provenance']['pid'], 'SYSTEM_DERIVED')
        self.assertEqual(result['processes'][0]['field_provenance']['command_line'], 'ARTIFACT_TAINTED')
        self.assertEqual(result['_provenance']['emitted_provenance'], 'ARTIFACT_TAINTED')

    def test_get_process_tree_emits_provenance_for_root_and_children(self):
        client = _ProcessTreeClient()
        memory_job_query = Mock()
        memory_job_query.filter_by.return_value = memory_job_query
        memory_job_query.all.return_value = []

        with patch.object(self.forensic_chat_sources.Case, 'get_by_id', return_value=_DummyCase()), \
             patch.object(self.forensic_chat_sources, 'get_fresh_client', return_value=client), \
             patch.object(self.forensic_chat_sources.MemoryJob, 'query', memory_job_query, create=True):
            result = self.forensic_chat_sources.get_unified_process_tree(
                9,
                hostname='HOST-1',
                pid=4242,
                process_name='cmd.exe',
                include_parent=False,
            )

        self.assertEqual(result['provenance_summary']['highest_provenance'], 'ARTIFACT_TAINTED')
        self.assertEqual(result['process']['field_provenance']['hostname'], 'SYSTEM_DERIVED')
        self.assertEqual(result['process']['field_provenance']['command_line'], 'ARTIFACT_TAINTED')
        self.assertEqual(result['process']['children'][0]['field_provenance']['pid'], 'SYSTEM_DERIVED')
        self.assertEqual(result['process']['children'][0]['field_provenance']['command_line'], 'ARTIFACT_TAINTED')
        self.assertEqual(result['_provenance']['emitted_provenance'], 'ARTIFACT_TAINTED')

    def test_search_memory_artifacts_emits_group_and_match_provenance(self):
        fake_job = type('MemoryJobRecord', (), {
            'id': 77,
            'hostname': 'HOST-1',
            'memory_timestamp': type('Ts', (), {'isoformat': lambda self: '2026-04-01T10:00:00'})(),
        })()
        job_query = Mock()
        job_query.filter_by.return_value = job_query
        job_query.filter.return_value = job_query
        job_query.all.return_value = [fake_job]

        process_query = Mock()
        process_query.filter.return_value = process_query
        process_query.limit.return_value = process_query
        process_query.all.return_value = [
            _FakeMemoryMatch(77, {
                'pid': 4242,
                'ppid': 1000,
                'name': 'cmd.exe',
                'cmdline': 'cmd.exe /c whoami',
                'path': r'C:\Windows\System32\cmd.exe',
            })
        ]

        with patch.object(self.forensic_chat_sources.Case, 'get_by_id', return_value=_DummyCase()), \
             patch.object(self.forensic_chat_sources.MemoryJob, 'query', job_query, create=True), \
             patch.object(self.forensic_chat_sources.MemoryProcess, 'case_id', _PredicateField(), create=True), \
             patch.object(self.forensic_chat_sources.MemoryProcess, 'job_id', _PredicateField(), create=True), \
             patch.object(self.forensic_chat_sources.MemoryProcess, 'name_lower', _PredicateField(), create=True), \
             patch.object(self.forensic_chat_sources.MemoryProcess, 'cmdline', _PredicateField(), create=True), \
             patch.object(self.forensic_chat_sources.MemoryProcess, 'path', _PredicateField(), create=True), \
             patch.object(self.forensic_chat_sources.MemoryProcess, 'query', process_query, create=True):
            result = self.forensic_chat_sources.search_memory_artifacts(
                9,
                search='cmd.exe',
                search_type='process',
            )

        self.assertEqual(result['jobs_matched'], 1)
        self.assertEqual(result['provenance_summary']['highest_provenance'], 'ARTIFACT_TAINTED')
        self.assertEqual(result['results'][0]['field_provenance']['job_id'], 'SYSTEM_DERIVED')
        self.assertEqual(result['results'][0]['matches'][0]['field_provenance']['pid'], 'SYSTEM_DERIVED')
        self.assertEqual(result['results'][0]['matches'][0]['field_provenance']['cmdline'], 'ARTIFACT_TAINTED')
        self.assertEqual(result['_provenance']['emitted_provenance'], 'ARTIFACT_TAINTED')

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
        self.assertEqual(result['provenance_summary']['highest_provenance'], 'ARTIFACT_TAINTED')
        self.assertEqual(result['events'][0]['field_provenance']['host'], 'SYSTEM_DERIVED')
        self.assertEqual(result['events'][0]['field_provenance']['cmdline'], 'ARTIFACT_TAINTED')
        self.assertEqual(result['_provenance']['emitted_provenance'], 'ARTIFACT_TAINTED')

    def test_count_events_accepts_source_group_aliases(self):
        client = _ChatToolClient([('WS-44', 2)])

        with patch.object(self.chat_tools, 'get_fresh_client', return_value=client):
            result = self.chat_tools.count_events(case_id=7, event_id='4624', group_by='workstation')

        query, _ = client.calls[0]
        self.assertIn('SELECT workstation_name, count() as cnt', query)
        self.assertEqual(result['grouped_by'], 'workstation_name')
        self.assertEqual(result['groups'][0]['value'], 'WS-44')
        self.assertEqual(result['groups'][0]['count'], 2)
        self.assertEqual(result['provenance_summary']['highest_provenance'], 'ARTIFACT_TAINTED')
        self.assertEqual(result['_provenance']['emitted_provenance'], 'ARTIFACT_TAINTED')

    def test_get_findings_emits_model_provenance_when_reasoning_is_present(self):
        fake_result = {
            'findings': [{
                'pattern_name': 'Suspicious PowerShell',
                'category': 'execution',
                'severity': 'high',
                'confidence': 92,
                'source_label': 'AI Correlation',
                'source_host': 'HOST-1',
                'event_count': 4,
                'first_seen': '2026-01-01 00:00:00',
                'reasoning': 'Correlated child process and encoded command patterns',
            }],
            'summary': {'total': 1},
        }

        fake_module = types.ModuleType('utils.unified_findings')
        fake_module.get_unified_findings = lambda **_kwargs: fake_result

        with patch.dict(sys.modules, {'utils.unified_findings': fake_module}):
            result = self.chat_tools.get_findings(9, min_confidence=50)

        self.assertEqual(result['summary']['total'], 1)
        self.assertEqual(result['provenance_summary']['highest_provenance'], 'MODEL_SYNTHESIZED')
        self.assertEqual(result['findings'][0]['field_provenance']['host'], 'SYSTEM_DERIVED')
        self.assertEqual(result['findings'][0]['field_provenance']['reasoning'], 'MODEL_SYNTHESIZED')
        self.assertEqual(result['_provenance']['emitted_provenance'], 'MODEL_SYNTHESIZED')

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
        self.assertEqual(result['provenance_summary']['highest_provenance'], 'ARTIFACT_TAINTED')
        self.assertEqual(result['ip_logon_context']['successful_logons'][0]['field_provenance']['user'], 'SYSTEM_DERIVED')
        self.assertEqual(result['ip_logon_context']['successful_logons'][0]['field_provenance']['remote_host'], 'ARTIFACT_TAINTED')
        self.assertEqual(result['_provenance']['emitted_provenance'], 'ARTIFACT_TAINTED')

    def test_lookup_threat_intel_emits_elevated_provenance_for_ioc_results(self):
        fake_opencti_context = types.ModuleType('utils.opencti_context')

        class _Provider:
            def __init__(self, case_id):
                self.case_id = case_id

            def is_available(self):
                return True

            def enrich_ioc(self, value, _ioc_type):
                return {
                    'found': True,
                    'score': 88,
                    'labels': ['phishing'],
                    'description': f'Intel for {value}',
                    'match_category': 'indicator',
                    'providers_found': ['OpenCTI'],
                    'available_connectors': [{'name': 'MISP'}],
                    'external_references': [{'source_name': 'VirusTotal'}],
                }

        fake_opencti_context.OpenCTIContextProvider = _Provider

        with patch.dict(sys.modules, {'utils.opencti_context': fake_opencti_context}):
            result = self.chat_tools.lookup_threat_intel(9, 'ioc', 'evil.test')

        self.assertTrue(result['found'])
        self.assertEqual(result['provenance_summary']['highest_provenance'], 'ELEVATED_RISK')
        self.assertEqual(result['_provenance']['emitted_provenance'], 'ELEVATED_RISK')
        self.assertEqual(result['available_connectors'], ['MISP'])

    def test_lookup_ioc_uses_shared_threat_intel_gate_for_optional_enrichment(self):
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
        fake_ioc_module.detect_ioc_type_from_value = lambda _value: 'Domain'
        fake_ioc_module.detect_match_type = lambda _value, _ioc_type: 'token'

        fake_ioc_artifact_tagger = types.ModuleType('utils.ioc_artifact_tagger')
        fake_ioc_artifact_tagger.search_artifacts_for_ioc = lambda **_kwargs: {'match_count': 0, 'artifact_types': {}}
        fake_ioc_artifact_tagger.build_ioc_match_clause = lambda *_args, **_kwargs: "1=0"

        gate_calls = []
        fake_feature_availability = types.ModuleType('utils.feature_availability')
        fake_feature_availability.FeatureAvailability = type('FeatureAvailability', (), {
            'is_ioc_threat_intel_enrichment_enabled': staticmethod(lambda: gate_calls.append('checked') or False),
        })

        opencti_calls = []
        fake_opencti = types.ModuleType('utils.opencti')
        fake_opencti.lookup_threat_intel = lambda *_args, **_kwargs: opencti_calls.append('called') or {'found': True}

        with patch.dict(sys.modules, {
            'models.ioc': fake_ioc_module,
            'utils.ioc_artifact_tagger': fake_ioc_artifact_tagger,
            'utils.feature_availability': fake_feature_availability,
            'utils.opencti': fake_opencti,
        }):
            result = self.chat_tools.lookup_ioc(9, 'evil.test')

        self.assertEqual(gate_calls, ['checked'])
        self.assertEqual(opencti_calls, [])
        self.assertEqual(result['opencti'], {})


if __name__ == '__main__':
    unittest.main()
