import os
import sys
import sqlite3
import tempfile
import importlib
import importlib.util
import types
import json
import unittest
from unittest.mock import patch

os.environ.setdefault('SECRET_KEY', 'test-secret')

clickhouse_stub = type(sys)('clickhouse_connect')
clickhouse_stub.get_client = lambda *args, **kwargs: None
sys.modules.setdefault('clickhouse_connect', clickhouse_stub)

base_module = importlib.import_module('parsers.base')
browser_module = importlib.import_module('parsers.browser_parsers')
windows_module = importlib.import_module('parsers.windows_parsers')
log_module = importlib.import_module('parsers.log_parsers')
dissect_module = importlib.import_module('parsers.dissect_parsers')

utils_package = types.ModuleType('utils')
sys.modules.setdefault('utils', utils_package)

clickhouse_spec = importlib.util.spec_from_file_location(
    'utils.clickhouse',
    os.path.join(os.path.dirname(os.path.dirname(__file__)), 'utils', 'clickhouse.py'),
)
clickhouse_module = importlib.util.module_from_spec(clickhouse_spec)
sys.modules['utils.clickhouse'] = clickhouse_module
clickhouse_spec.loader.exec_module(clickhouse_module)
utils_package.clickhouse = clickhouse_module

BaseParser = base_module.BaseParser
BrowserSQLiteParser = browser_module.BrowserSQLiteParser
ActivitiesCacheParser = windows_module.ActivitiesCacheParser
HuntressParser = log_module.HuntressParser
PowerShellHistoryParser = log_module.PowerShellHistoryParser
HostsFileParser = log_module.HostsFileParser
SetupApiLogParser = log_module.SetupApiLogParser
EvtxECmdParser = importlib.import_module('parsers.evtx_parser').EvtxECmdParser
ParserRegistry = importlib.import_module('parsers.registry').ParserRegistry
RegistryParser = dissect_module.RegistryParser
PrefetchParser = dissect_module.PrefetchParser


class _DummyParser(BaseParser):
    @property
    def artifact_type(self):
        return 'dummy'

    def can_parse(self, file_path):
        return True

    def parse(self, file_path):
        if False:
            yield file_path


class _BlankError(Exception):
    def __str__(self):
        return ''


class _FakeClient:
    def __init__(self):
        self.commands = []
        self.fail_buffer = False

    def command(self, sql):
        self.commands.append(sql)
        if self.fail_buffer and 'events_buffer' in sql:
            raise RuntimeError("Table engine Buffer doesn't support mutations")


class ParserHardeningTestCase(unittest.TestCase):
    def test_validate_ip_accepts_ipv6(self):
        parser = _DummyParser(case_id=1)
        self.assertEqual(
            parser.validate_ip('2001:db8::1'),
            '2001:db8::1',
        )

    def test_validate_ipv4_rejects_ipv6(self):
        parser = _DummyParser(case_id=1)
        self.assertIsNone(parser.validate_ipv4('::1'))

    def test_format_exception_falls_back_to_type_name(self):
        parser = _DummyParser(case_id=1)
        self.assertEqual(
            parser.format_exception(_BlankError(), context='Failed to parse'),
            'Failed to parse: _BlankError',
        )

    def test_fallback_timestamp_prefers_file_mtime(self):
        parser = _DummyParser(case_id=1)

        with tempfile.NamedTemporaryFile(delete=False) as handle:
            file_path = handle.name

        try:
            expected = 1700000000
            os.utime(file_path, (expected, expected))
            fallback = parser.fallback_timestamp(file_path=file_path, reason='test fallback')
            self.assertEqual(int(fallback.timestamp()), expected)
            self.assertTrue(any('file_mtime_utc' in warning for warning in parser.warnings))
        finally:
            os.remove(file_path)

    def test_browser_cookie_detection_uses_cookie_columns(self):
        parser = BrowserSQLiteParser(case_id=1)

        with tempfile.NamedTemporaryFile(suffix='.sqlite', delete=False) as handle:
            db_path = handle.name

        try:
            conn = sqlite3.connect(db_path)
            conn.execute(
                'CREATE TABLE cookies (host_key TEXT, name TEXT, path TEXT, value TEXT)'
            )
            conn.commit()
            conn.close()

            self.assertEqual(parser._identify_browser_db(db_path), 'chrome_cookies')
        finally:
            os.remove(db_path)

    def test_activities_cache_handles_missing_activity_table(self):
        parser = ActivitiesCacheParser(case_id=1)

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, 'ActivitiesCache.db')
            conn = sqlite3.connect(db_path)
            conn.execute(
                '''
                CREATE TABLE ActivityOperation (
                    OperationOrder INTEGER,
                    AppId TEXT,
                    ActivityType INTEGER,
                    CreatedTime INTEGER,
                    EndTime INTEGER,
                    LastModifiedTime INTEGER,
                    OperationType TEXT,
                    Payload TEXT,
                    ClipboardPayload TEXT
                )
                '''
            )
            conn.execute(
                '''
                INSERT INTO ActivityOperation (
                    OperationOrder, AppId, ActivityType, CreatedTime, EndTime,
                    LastModifiedTime, OperationType, Payload, ClipboardPayload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (1, 'browser.exe', 10, 0, 0, 0, 'copy', '{}', '{}'),
            )
            conn.commit()
            conn.close()

            events = list(parser.parse(db_path))

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].artifact_type, 'activity_operation')
        self.assertIn('Error querying Activity table', ' '.join(parser.warnings))

    def test_huntress_parser_keeps_elevation_type_out_of_logon_type(self):
        parser = HuntressParser(case_id=1)
        event = {
            '@timestamp': '2026-03-13T10:00:00Z',
            'process': {
                'name': 'cmd.exe',
                'pid': 1234,
                'elevation_type': 'limited',
                'user': {
                    'name': 'alice',
                    'domain': 'CORP',
                    'id': 'S-1-5-21',
                },
            },
            'host': {'hostname': 'HOST1'},
            'event': {'kind': 'event', 'category': 'process'},
        }

        parsed = parser._parse_ecs_event(
            event=event,
            source_file='huntress.ndjson',
            file_path='/tmp/huntress.ndjson',
            default_hostname='HOST1',
            raw_line='{}',
        )

        self.assertIsNotNone(parsed)
        self.assertIsNone(parsed.logon_type)
        self.assertEqual(parsed.elevated_token, 'limited')

    def test_delete_file_events_cleans_buffer_and_main_tables(self):
        client = _FakeClient()

        with patch.object(clickhouse_module, 'get_client', return_value=client):
            clickhouse_module.delete_file_events(99)

        self.assertEqual(
            client.commands,
            [
                'ALTER TABLE events DELETE WHERE case_file_id = 99',
                'ALTER TABLE events_buffer DELETE WHERE case_file_id = 99',
            ],
        )

    def test_delete_file_events_ignores_buffer_mutation_rejection(self):
        client = _FakeClient()
        client.fail_buffer = True

        with patch.object(clickhouse_module, 'get_client', return_value=client):
            clickhouse_module.delete_file_events(55)

        self.assertEqual(
            client.commands,
            [
                'ALTER TABLE events DELETE WHERE case_file_id = 55',
                'ALTER TABLE events_buffer DELETE WHERE case_file_id = 55',
            ],
        )

    def test_evtx_transform_preserves_ipv6_without_populating_src_ip(self):
        parser = object.__new__(EvtxECmdParser)
        BaseParser.__init__(parser, case_id=1, source_host='HOST1', case_file_id=55, case_tz='UTC')

        event = {
            'TimeCreated': '2026-03-14T12:00:00Z',
            'EventId': 4624,
            'Channel': 'Security',
            'Computer': 'HOST1',
            'EventRecordId': '77',
            'Provider': 'Microsoft-Windows-Security-Auditing',
            'Payload': json.dumps({
                'EventData': {
                    'Data': [
                        {'@Name': 'IpAddress', '#text': '::1'},
                        {'@Name': 'TargetUserName', '#text': 'alice'},
                        {'@Name': 'TargetDomainName', '#text': 'CORP'},
                    ]
                }
            }),
        }

        parsed = parser._transform_evtxecmd_event(
            event=event,
            file_path='/tmp/Security.evtx',
            source_file='Security.evtx',
            detections={},
        )

        self.assertIsNotNone(parsed)
        self.assertIsNone(parsed.src_ip)
        self.assertEqual(parsed.remote_host, '::1')
        self.assertIn('::1', parsed.search_blob)
        self.assertEqual(json.loads(parsed.extra_fields)['src_ip_raw'], '::1')

    def test_registry_falls_back_to_generic_json_when_firefox_json_rejects(self):
        registry = ParserRegistry()

        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, 'RecommendationsFilterList.json')
            with open(file_path, 'w', encoding='utf-8') as handle:
                json.dump([{'name': 'entry', 'value': 1}], handle)

            artifact_type, parser = registry.resolve_parser_for_file(
                file_path=file_path,
                case_id=1,
            )

        self.assertEqual(artifact_type, 'json_log')
        self.assertIsNotNone(parser)
        self.assertEqual(parser.artifact_type, 'json_log')

    def test_registry_prefers_firefox_json_for_profile_artifacts(self):
        registry = ParserRegistry()

        with tempfile.TemporaryDirectory() as tmpdir:
            profile_dir = os.path.join(tmpdir, 'AppData', 'Roaming', 'Mozilla', 'Firefox', 'Profiles', 'abcd.default-release')
            os.makedirs(profile_dir, exist_ok=True)
            file_path = os.path.join(profile_dir, 'handlers.json')
            with open(file_path, 'w', encoding='utf-8') as handle:
                json.dump({'schemes': {}, 'mimeTypes': {}}, handle)

            artifact_type, parser = registry.resolve_parser_for_file(
                file_path=file_path,
                case_id=1,
            )

        self.assertEqual(artifact_type, 'firefox_json')
        self.assertIsNotNone(parser)
        self.assertEqual(parser.artifact_type, 'firefox_json')

    def test_powershell_history_parser_emits_commands(self):
        parser = PowerShellHistoryParser(case_id=1)

        with tempfile.TemporaryDirectory() as tmpdir:
            history_dir = os.path.join(
                tmpdir, 'Users', 'alice', 'AppData', 'Roaming', 'Microsoft',
                'Windows', 'PowerShell', 'PSReadLine'
            )
            os.makedirs(history_dir, exist_ok=True)
            file_path = os.path.join(history_dir, 'ConsoleHost_history.txt')
            with open(file_path, 'w', encoding='utf-8') as handle:
                handle.write('Get-Process\n\nwhoami\n')

            events = list(parser.parse(file_path))

        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].artifact_type, 'powershell_history')
        self.assertEqual(events[0].command_line, 'Get-Process')
        self.assertEqual(events[1].command_line, 'whoami')

    def test_hosts_file_parser_emits_mappings(self):
        parser = HostsFileParser(case_id=1)

        with tempfile.TemporaryDirectory() as tmpdir:
            hosts_dir = os.path.join(tmpdir, 'Windows', 'System32', 'drivers', 'etc')
            os.makedirs(hosts_dir, exist_ok=True)
            file_path = os.path.join(hosts_dir, 'hosts')
            with open(file_path, 'w', encoding='utf-8') as handle:
                handle.write('# comment\n127.0.0.1 localhost local\n')

            events = list(parser.parse(file_path))

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].artifact_type, 'hosts')
        self.assertEqual(events[0].remote_host, '127.0.0.1')
        self.assertEqual(events[0].target_path, 'localhost local')

    def test_setupapi_log_parser_emits_timestamped_actions(self):
        parser = SetupApiLogParser(case_id=1, case_tz='America/New_York')

        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, 'setupapi.dev.log')
            with open(file_path, 'w', encoding='utf-8') as handle:
                handle.write('[Boot Session: 2026/02/10 23:45:13.500]\n')
                handle.write('>>>  [Unstage Driver Updates]\n')
                handle.write('>>>  Section start 2026/02/10 23:45:32.314\n')
                handle.write('sto: {Unstage Driver Package: C:\\\\Windows\\\\example.inf} 23:45:32.386\n')

            events = list(parser.parse(file_path))

        self.assertGreaterEqual(len(events), 2)
        self.assertTrue(all(event.artifact_type == 'setupapi' for event in events))
        self.assertTrue(all(event.timestamp_source_tz == 'America/New_York' for event in events))
        self.assertTrue(any('Unstage Driver Updates' in event.search_blob for event in events))
        self.assertTrue(any(event.target_path.endswith('example.inf') for event in events))

    def test_registry_interesting_keys_include_hive_specific_targets(self):
        parser = object.__new__(RegistryParser)
        BaseParser.__init__(parser, case_id=1, source_host='', case_file_id=None, case_tz='UTC')

        sam_keys = parser._interesting_keys_for_hive('SAM')
        amcache_keys = parser._interesting_keys_for_hive('AMCACHE')
        usrclass_keys = parser._interesting_keys_for_hive('USRCLASS.DAT')

        self.assertIn(r'SAM\Domains\Account\Users', sam_keys)
        self.assertIn(r'Root\InventoryApplicationFile', amcache_keys)
        self.assertIn(r'Local Settings\Software\Microsoft\Windows\Shell\BagMRU', usrclass_keys)

    def test_firefox_extensions_parser_handles_null_nested_fields(self):
        parser = browser_module.FirefoxJSONParser(case_id=1)

        with tempfile.TemporaryDirectory() as tmpdir:
            profile_dir = os.path.join(
                tmpdir, 'AppData', 'Roaming', 'Mozilla', 'Firefox', 'Profiles', 'abcd.default-release'
            )
            os.makedirs(profile_dir, exist_ok=True)
            file_path = os.path.join(profile_dir, 'extensions.json')
            with open(file_path, 'w', encoding='utf-8') as handle:
                json.dump({
                    'addons': [{
                        'id': 'addon@example.test',
                        'defaultLocale': None,
                        'userPermissions': None,
                        'updateDate': 1710000000000,
                        'active': True,
                    }]
                }, handle)

            events = list(parser.parse(file_path))

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].artifact_type, 'firefox_addon')
        event_data = json.loads(events[0].raw_json)
        self.assertEqual(event_data['name'], 'addon@example.test')
        self.assertEqual(event_data['permissions'], [])
        self.assertEqual(parser.errors, [])

    def test_browser_sqlite_parses_firefox_origin_storage_db(self):
        parser = BrowserSQLiteParser(case_id=1)

        with tempfile.TemporaryDirectory() as tmpdir:
            storage_dir = os.path.join(
                tmpdir, 'AppData', 'Roaming', 'Mozilla', 'Firefox', 'Profiles',
                'abcd.default-release', 'storage', 'default', 'https+++example.com', 'idb'
            )
            os.makedirs(storage_dir, exist_ok=True)
            file_path = os.path.join(storage_dir, '12183338011.sqlite')
            conn = sqlite3.connect(file_path)
            conn.execute('CREATE TABLE records (created TEXT, payload TEXT)')
            conn.execute(
                'INSERT INTO records (created, payload) VALUES (?, ?)',
                ('2026-03-15 12:00:00', 'cached-value'),
            )
            conn.commit()
            conn.close()

            events = list(parser.parse(file_path))

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].artifact_type, 'sqlite_firefox_indexeddb')
        self.assertIn('cached-value', events[0].search_blob)
        self.assertEqual(parser.errors, [])

    def test_prefetch_parser_reports_unsupported_variant_cleanly(self):
        class _UnsupportedPrefetch:
            def __init__(self, _fh):
                raise NotImplementedError('variant not supported')

        parser = object.__new__(PrefetchParser)
        BaseParser.__init__(parser, case_id=1, source_host='HOST1', case_file_id=7, case_tz='UTC')
        parser._prefetch_class = _UnsupportedPrefetch

        with tempfile.NamedTemporaryFile(suffix='.pf', delete=False) as handle:
            handle.write(b'SCCA')
            file_path = handle.name

        try:
            events = list(parser.parse(file_path))
        finally:
            os.remove(file_path)

        self.assertEqual(events, [])
        self.assertEqual(parser.errors, [])
        self.assertEqual(len(parser.warnings), 1)
        self.assertIn('Unsupported Prefetch variant', parser.warnings[0])
        self.assertIn('variant not supported', parser.warnings[0])

    def test_activities_cache_missing_sidecar_becomes_warning(self):
        parser = ActivitiesCacheParser(case_id=1)

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, 'ActivitiesCache.db')
            conn = sqlite3.connect(db_path)
            conn.execute('CREATE TABLE Activity (Id TEXT)')
            conn.commit()
            conn.close()

            with patch.object(
                windows_module.sqlite3,
                'connect',
                side_effect=sqlite3.OperationalError(f"unable to open database file: '{db_path}-wal'"),
            ):
                events = list(parser.parse(db_path))

        self.assertEqual(events, [])
        self.assertEqual(parser.errors, [])
        self.assertEqual(len(parser.warnings), 1)
        self.assertIn('sidecar unavailable', parser.warnings[0].lower())


if __name__ == '__main__':
    unittest.main()
