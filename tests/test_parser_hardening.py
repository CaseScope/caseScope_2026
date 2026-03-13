import os
import sys
import sqlite3
import tempfile
import importlib
import importlib.util
import types
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


class _DummyParser(BaseParser):
    @property
    def artifact_type(self):
        return 'dummy'

    def can_parse(self, file_path):
        return True

    def parse(self, file_path):
        if False:
            yield file_path


class _FakeClient:
    def __init__(self):
        self.commands = []

    def command(self, sql):
        self.commands.append(sql)


class ParserHardeningTestCase(unittest.TestCase):
    def test_validate_ip_accepts_ipv6(self):
        parser = _DummyParser(case_id=1)
        self.assertEqual(
            parser.validate_ip('2001:db8::1'),
            '2001:db8::1',
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


if __name__ == '__main__':
    unittest.main()
