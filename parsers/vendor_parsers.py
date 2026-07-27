"""Vendor-specific parsers built on the standard CaseScope event model."""
import csv
import json
import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any, Dict, Generator, Iterable, List, Optional

from parsers.base import BaseParser, ParsedEvent
from parsers.log_parsers import CSVLogParser, FirewallLogParser, GenericJSONParser


# Vendor exports name the same concepts differently, and a generic CSV or JSON
# reader has no way to know that CrowdStrike's LocalAddressIP4 is a source
# address. Without this table a delegated export reaches ClickHouse with every
# typed column empty and is searchable only as free text.
_VENDOR_FIELD_ALIASES: Dict[str, tuple] = {
    'username': (
        'username', 'user_name', 'user', 'username_string', 'accountname',
        'account_name', 'usernamestring', 'sourceaccountname', 'loginuser',
        'initiatingprocessaccountname', 'srcprocuser', 'userprincipalname',
    ),
    'domain': (
        'domain', 'accountdomain', 'account_domain', 'userdomain',
        'domainname', 'initiatingprocessaccountdomain',
    ),
    'sid': ('sid', 'usersid', 'user_sid', 'accountsid', 'sidstring', 'securityid'),
    'process_name': (
        'process_name', 'processname', 'imagefilename', 'filename',
        'image_file_name', 'srcprocname', 'processdisplayname', 'application',
        'process', 'exename', 'parentbaseprocessname',
    ),
    'process_path': (
        'process_path', 'processpath', 'imagepath', 'image_path', 'filepath',
        'file_path', 'srcprocimagepath', 'processimagepath', 'executable',
    ),
    'command_line': (
        'command_line', 'commandline', 'cmdline', 'processcommandline',
        'srcproccmdline', 'commandlineparameters', 'args',
    ),
    'parent_process': (
        'parent_process', 'parentprocessname', 'parentbasefilename',
        'parentimagefilename', 'tgtprocparentname', 'parentprocessimagepath',
    ),
    'target_path': (
        'target_path', 'targetfilename', 'targetpath', 'filepath', 'file_path',
        'targetfilepath', 'url', 'remoteurl', 'objectname', 'path',
    ),
    'file_hash_md5': ('md5', 'md5hash', 'filemd5', 'md5string', 'hash_md5'),
    'file_hash_sha1': ('sha1', 'sha1hash', 'filesha1', 'sha1string', 'hash_sha1'),
    'file_hash_sha256': (
        'sha256', 'sha256hash', 'filesha256', 'sha256string', 'hash_sha256',
        'sha256hashdata',
    ),
    'src_ip': (
        'src_ip', 'srcip', 'source_ip', 'sourceip', 'sourceaddress',
        'localaddressip4', 'localip', 'local_ip', 'clientip', 'client_ip',
        'srcipaddr', 'source_address',
    ),
    'dst_ip': (
        'dst_ip', 'dstip', 'destination_ip', 'destinationip',
        'destinationaddress', 'remoteaddressip4', 'remoteip', 'remote_ip',
        'serverip', 'dstipaddr', 'destination_address',
    ),
    'src_port': (
        'src_port', 'srcport', 'source_port', 'sourceport', 'localport',
        'local_port', 'clientport',
    ),
    'dst_port': (
        'dst_port', 'dstport', 'destination_port', 'destinationport',
        'remoteport', 'remote_port', 'serverport',
    ),
    'event_id': (
        'event_id', 'eventid', 'event_simplename', 'eventtype', 'event_type',
        'eventname', 'actiontype', 'activitytype',
    ),
    'rule_title': (
        'rule_title', 'detectname', 'detectdescription', 'threatname',
        'threat_name', 'rulename', 'rule_name', 'signature', 'title',
        'alertname', 'detectionname',
    ),
    'rule_level': (
        'rule_level', 'severity', 'severityname', 'threatlevel', 'risklevel',
        'confidence', 'priority', 'level',
    ),
    'source_host': (
        'source_host', 'computername', 'computer_name', 'devicename',
        'device_name', 'hostname', 'host_name', 'machinename', 'endpointname',
        'agentcomputername', 'aid_computer_name',
    ),
    'file_size': ('file_size', 'filesize', 'size', 'bytes', 'total_bytes'),
    'process_id': ('process_id', 'processid', 'pid', 'rawprocessid', 'srcprocpid'),
    'parent_pid': ('parent_pid', 'parentprocessid', 'ppid', 'parentpid'),
}

# Filled by clamping helpers rather than assigned as free text.
_VENDOR_UINT16_FIELDS = ('src_port', 'dst_port')
_VENDOR_UINT64_FIELDS = ('file_size', 'process_id', 'parent_pid')
_VENDOR_IP_FIELDS = ('src_ip', 'dst_ip')


class _DelegatingVendorParser(BaseParser):
    """Route vendor exports into the appropriate generic parser when possible."""

    JSON_EXTENSIONS = ('.json', '.jsonl', '.ndjson')
    CSV_EXTENSIONS = ('.csv',)
    LOG_EXTENSIONS = ('.log', '.txt')
    FORENSIC_BINARY_EXTENSIONS = (
        '.etl', '.etlgz', '.evtx', '.pf', '.lnk', '.automaticdestinations-ms',
        '.customdestinations-ms', '.dat', '.db', '.hve', '.dmp',
    )
    FILENAME_MARKERS: List[str] = []
    CONTENT_MARKERS: List[str] = []
    # Names this vendor uses that the shared table does not cover, or that
    # should win over it. Merged ahead of _VENDOR_FIELD_ALIASES.
    FIELD_ALIASES: Dict[str, tuple] = {}

    def _file_sample(self, file_path: str, size: int = 8192) -> str:
        # A KAPE target or EvtxECmd map names vendors and artifacts in plain
        # text, so sniffing it for vendor markers produces false positives.
        if self.is_tool_configuration(file_path):
            return ''
        try:
            with open(file_path, 'rb') as handle:
                raw = handle.read(size)
        except OSError:
            return ''
        # Decoding a database or a binary blob with errors='replace' produces
        # text that matches vendor markers by chance. A log has no NUL bytes.
        if b'\x00' in raw:
            return ''
        return raw.decode('utf-8-sig', errors='replace')

    def _matches_filename(self, file_path: str) -> bool:
        if self.is_tool_configuration(file_path):
            return False
        file_name = os.path.basename(file_path).lower()
        return any(marker in file_name for marker in self.FILENAME_MARKERS)

    def _is_forensic_binary_extension(self, file_path: str) -> bool:
        lower_name = os.path.basename(file_path).lower()
        return lower_name.endswith(self.FORENSIC_BINARY_EXTENSIONS)

    def _matches_sample(self, sample: str) -> bool:
        sample_lower = sample.lower()
        return any(marker in sample_lower for marker in self.CONTENT_MARKERS)

    def _delegate_parser(self, parser_cls, **kwargs):
        return parser_cls(
            case_id=self.case_id,
            source_host=self.source_host,
            case_file_id=self.case_file_id,
            case_tz=self.case_tz,
            artifact_type_override=self.artifact_type,
            **kwargs,
        )

    def _alias_table(self) -> Dict[str, tuple]:
        if not self.FIELD_ALIASES:
            return _VENDOR_FIELD_ALIASES
        merged = dict(_VENDOR_FIELD_ALIASES)
        for column, names in self.FIELD_ALIASES.items():
            merged[column] = tuple(names) + tuple(merged.get(column, ()))
        return merged

    @staticmethod
    def _flatten_record(record: Any, into: Dict[str, Any], depth: int = 0) -> None:
        """Index a record by lowercased leaf key, so nesting does not hide fields."""
        if depth > 4 or not isinstance(record, dict):
            return
        for key, value in record.items():
            if isinstance(value, dict):
                _DelegatingVendorParser._flatten_record(value, into, depth + 1)
                continue
            if isinstance(value, (list, tuple)):
                continue
            normalized = str(key).strip().lower().replace(' ', '_')
            if normalized and normalized not in into:
                into[normalized] = value

    def _typed_fields(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Map a vendor record onto the typed ParsedEvent columns."""
        flat: Dict[str, Any] = {}
        self._flatten_record(record, flat)
        if not flat:
            return {}

        resolved: Dict[str, Any] = {}
        for column, candidates in self._alias_table().items():
            for candidate in candidates:
                if candidate not in flat:
                    continue
                if column in _VENDOR_IP_FIELDS:
                    address, _ = self.normalize_ip_for_storage(flat[candidate])
                    if address:
                        resolved[column] = address
                        break
                    continue
                if column in _VENDOR_UINT16_FIELDS:
                    number = self.safe_uint16(flat[candidate])
                    if number is not None:
                        resolved[column] = number
                        break
                    continue
                if column in _VENDOR_UINT64_FIELDS:
                    number = self.safe_uint64(flat[candidate])
                    if number is not None:
                        resolved[column] = number
                        break
                    continue
                text = self.safe_str(flat[candidate])
                if text:
                    resolved[column] = text
                    break
        return resolved

    def _enrich(self, event: ParsedEvent) -> ParsedEvent:
        """Populate typed columns the generic delegate could not know about."""
        try:
            record = json.loads(event.raw_json) if event.raw_json else {}
        except (TypeError, ValueError):
            return event
        if not isinstance(record, dict):
            return event

        for column, value in self._typed_fields(record).items():
            current = getattr(event, column, None)
            # The delegate falls back to the directory name for the host, which
            # is a guess the record itself can improve on.
            if column == 'source_host' and current == 'unknown':
                current = ''
            # Only fill a column the delegate left empty; never overwrite a
            # value the generic parser was able to determine itself.
            if current in (None, '', 0):
                setattr(event, column, value)
        if event.rule_level:
            event.rule_level = event.rule_level.lower()
        return event

    def _delegate_parse(self, file_path: str, parser_cls) -> Generator[ParsedEvent, None, None]:
        delegate = self._delegate_parser(parser_cls)
        for event in delegate.parse(file_path):
            yield self._enrich(event)
        self.errors.extend(delegate.errors)
        self.warnings.extend(delegate.warnings)


class DefenderAvParser(_DelegatingVendorParser):
    VERSION = '1.1.0'
    ARTIFACT_TYPE = 'defender_av'
    FIELD_ALIASES = {
        'rule_title': ('threatname', 'threat_name'),
        'rule_level': ('severityid', 'severity', 'threatseverity'),
        'target_path': ('path', 'resources', 'filepath'),
        'process_name': ('processname', 'process'),
        'source_host': ('computername', 'devicename'),
        'username': ('domainuser', 'user', 'username'),
        'event_id': ('detectionid', 'actiontype'),
    }
    FILENAME_MARKERS = ['defender', 'threat', 'protection', 'windowsdefender']
    CONTENT_MARKERS = ['threatname', 'severityid', 'detectiontime', 'windows defender']

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        if not os.path.isfile(file_path):
            return False
        if self._is_forensic_binary_extension(file_path):
            return False
        if self._matches_filename(file_path):
            return True
        return self._matches_sample(self._file_sample(file_path))

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        lower_path = file_path.lower()
        if lower_path.endswith(self.CSV_EXTENSIONS):
            yield from self._delegate_parse(file_path, CSVLogParser)
        else:
            yield from self._delegate_parse(file_path, GenericJSONParser)


class MdeXdrParser(BaseParser):
    VERSION = '1.1.0'
    ARTIFACT_TYPE = 'mde_xdr'
    # Report the first few bad lines individually, then only the total
    MAX_REPORTED_BAD_LINES = 5
    # Never use bare 'mde' — substring match inside Windows jump-list names (customdestinations-ms).
    FILENAME_MARKERS = ['advancedhunting', 'mdexdr', 'defender_xdr', 'microsoft_defender']
    REQUIRED_COLUMNS = {'Timestamp', 'DeviceName', 'ActionType'}
    _JUMPLIST_SUFFIXES = ('.customdestinations-ms', '.automaticdestinations-ms')

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        if not os.path.isfile(file_path) or self.is_tool_configuration(file_path):
            return False
        lower_name = os.path.basename(file_path).lower()
        if lower_name.endswith(self._JUMPLIST_SUFFIXES):
            return False
        if any(marker in lower_name for marker in self.FILENAME_MARKERS):
            return True
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as handle:
                sample = handle.read(4096)
        except Exception:
            return False
        return all(token.lower() in sample.lower() for token in ('timestamp', 'devicename', 'actiontype'))

    def _iter_records(self, file_path: str) -> Iterable[Dict[str, Any]]:
        if file_path.lower().endswith('.csv'):
            with open(file_path, 'r', encoding='utf-8-sig', errors='replace', newline='') as handle:
                sample = handle.read(4096)
                handle.seek(0)
                try:
                    dialect = csv.Sniffer().sniff(sample)
                except csv.Error:
                    dialect = csv.excel
                reader = csv.DictReader(handle, dialect=dialect)
                for row in reader:
                    if row:
                        yield row
            return

        with open(file_path, 'r', encoding='utf-8-sig', errors='replace') as handle:
            first_char = ''
            while True:
                char = handle.read(1)
                if not char:
                    return
                if not char.isspace():
                    first_char = char
                    break

            if first_char == '[':
                # An array has to be materialised to be parsed, unlike NDJSON
                handle.seek(0)
                try:
                    data = json.load(handle)
                except ValueError as exc:
                    self.errors.append(f'{os.path.basename(file_path)} is not valid JSON: {exc}')
                    return
                for item in data if isinstance(data, list) else []:
                    if isinstance(item, dict):
                        yield item
                return

            # NDJSON: a single malformed line used to raise out of this
            # generator and abandon every remaining record in the file
            handle.seek(0)
            malformed = 0
            for line_number, line in enumerate(handle, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except ValueError:
                    malformed += 1
                    if malformed <= self.MAX_REPORTED_BAD_LINES:
                        self.warnings.append(
                            f'{os.path.basename(file_path)} line {line_number} is not valid JSON'
                        )
                    continue
                if isinstance(item, dict):
                    yield item

            if malformed > self.MAX_REPORTED_BAD_LINES:
                self.warnings.append(
                    f'{os.path.basename(file_path)} had {malformed} unparseable JSON lines in total'
                )

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        if not self.can_parse(file_path):
            self.errors.append(f'Cannot parse file: {file_path}')
            return

        source_file = os.path.basename(file_path)
        default_host = self.extract_hostname(file_path)

        for row_num, record in enumerate(self._iter_records(file_path), 1):
            try:
                timestamp = self.parse_timestamp(
                    record.get('Timestamp') or record.get('timestamp') or record.get('@timestamp')
                ) or self.fallback_timestamp(file_path=file_path, reason='mde xdr event missing timestamp')

                source_host = self.safe_str(
                    record.get('DeviceName') or record.get('deviceName') or record.get('ComputerName') or default_host
                )
                username = self.safe_str(
                    record.get('AccountName')
                    or record.get('InitiatingProcessAccountName')
                    or record.get('UserName')
                )
                process_name = self.safe_str(
                    record.get('FileName')
                    or record.get('InitiatingProcessFileName')
                    or record.get('ProcessName')
                )
                command_line = self.safe_str(
                    record.get('ProcessCommandLine')
                    or record.get('InitiatingProcessCommandLine')
                )
                target_path = self.safe_str(
                    record.get('FolderPath')
                    or record.get('FilePath')
                    or record.get('RemoteUrl')
                    or record.get('Url')
                )
                src_ip, src_ip_raw = self.normalize_ip_for_storage(
                    record.get('LocalIP') or record.get('IPAddress')
                )
                dst_ip, dst_ip_raw = self.normalize_ip_for_storage(record.get('RemoteIP'))
                src_port = self.safe_uint16(record.get('LocalPort'))
                dst_port = self.safe_uint16(record.get('RemotePort'))
                action = self.safe_str(record.get('ActionType'))
                severity = self.safe_str(record.get('Severity') or record.get('AlertSeverity'))
                sha256 = self.safe_str(record.get('SHA256') or record.get('InitiatingProcessSHA256'))

                search_blob = self.build_search_blob(record)
                if target_path:
                    search_blob = f'{search_blob} target_path:{target_path}'.strip()

                extra = {
                    'report_id': record.get('ReportId'),
                    'table': record.get('TableName'),
                    'device_group': record.get('DeviceGroup'),
                    'threat_name': record.get('ThreatName'),
                    'remote_url': record.get('RemoteUrl') or record.get('Url'),
                }
                if src_ip_raw:
                    extra['src_ip_raw'] = src_ip_raw
                if dst_ip_raw:
                    extra['dst_ip_raw'] = dst_ip_raw
                extra = {k: v for k, v in extra.items() if v not in (None, '', [])}

                yield ParsedEvent(
                    case_id=self.case_id,
                    artifact_type=self.artifact_type,
                    timestamp=timestamp,
                    timestamp_source_tz=self.get_source_tz(),
                    source_file=source_file,
                    source_path=file_path,
                    source_host=source_host,
                    case_file_id=self.case_file_id,
                    username=username,
                    process_name=process_name,
                    command_line=command_line,
                    target_path=target_path,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    file_hash_sha256=sha256,
                    rule_title=action,
                    rule_level=severity.lower(),
                    raw_json=json.dumps(record, default=str),
                    search_blob=search_blob,
                    extra_fields=json.dumps(extra, default=str),
                    parser_version=self.parser_version,
                )
            except Exception as exc:
                self.warnings.append(f'Error processing MDE row {row_num}: {exc}')


class PaloAltoParser(BaseParser):
    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'palo_alto'
    HEADER_MARKERS = {'Receive Time', 'Source address', 'Destination address'}
    FILENAME_RE = re.compile(r'(^|[^a-z0-9])(palo|pan-?os|pan_|panw)([^a-z0-9]|$)', re.IGNORECASE)

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        if not os.path.isfile(file_path) or self.is_tool_configuration(file_path):
            return False
        lower_name = os.path.basename(file_path).lower()
        extension = os.path.splitext(lower_name)[1]
        if extension != '.csv':
            return False
        if self.FILENAME_RE.search(lower_name):
            return True
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as handle:
                header = handle.readline()
        except Exception:
            return False
        return all(marker in header for marker in self.HEADER_MARKERS)

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        if not self.can_parse(file_path):
            self.errors.append(f'Cannot parse file: {file_path}')
            return

        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)

        with open(file_path, 'r', encoding='utf-8', errors='replace', newline='') as handle:
            reader = csv.DictReader(handle)
            for row_num, row in enumerate(reader, 1):
                try:
                    timestamp = self.parse_timestamp(
                        row.get('Receive Time') or row.get('Generated Time') or row.get('Start Time')
                    ) or self.fallback_timestamp(file_path=file_path, reason='palo alto event missing timestamp')

                    rule_title = self.safe_str(row.get('Action') or row.get('Threat/Content Name') or row.get('Rule'))
                    severity = self.safe_str(row.get('Severity') or row.get('risk_of_app'))
                    target_path = self.safe_str(row.get('URL/Filename') or row.get('Path'))
                    process_name = self.safe_str(row.get('Application'))
                    username = self.safe_str(row.get('Source User'))

                    src_ip, src_ip_raw = self.normalize_ip_for_storage(row.get('Source address'))
                    dst_ip, dst_ip_raw = self.normalize_ip_for_storage(row.get('Destination address'))
                    extra = {
                        'rule': row.get('Rule'),
                        'app': row.get('Application'),
                        'session_end_reason': row.get('Session End Reason'),
                        'virtual_system': row.get('Virtual System'),
                        'destination_zone': row.get('Destination Zone'),
                        'source_zone': row.get('Source Zone'),
                    }
                    if src_ip_raw:
                        extra['src_ip_raw'] = src_ip_raw
                    if dst_ip_raw:
                        extra['dst_ip_raw'] = dst_ip_raw
                    extra = {k: v for k, v in extra.items() if v}

                    yield ParsedEvent(
                        case_id=self.case_id,
                        artifact_type=self.artifact_type,
                        timestamp=timestamp,
                        timestamp_source_tz=self.get_source_tz(),
                        source_file=source_file,
                        source_path=file_path,
                        source_host=self.safe_str(row.get('Serial Number') or hostname),
                        case_file_id=self.case_file_id,
                        username=username,
                        process_name=process_name,
                        target_path=target_path,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=self.safe_uint16(row.get('Source Port')),
                        dst_port=self.safe_uint16(row.get('Destination Port')),
                        rule_title=rule_title,
                        rule_level=severity.lower(),
                        raw_json=json.dumps(row, default=str),
                        search_blob=self.build_search_blob(row),
                        extra_fields=json.dumps(extra, default=str),
                        parser_version=self.parser_version,
                    )
                except Exception as exc:
                    self.warnings.append(f'Error processing Palo Alto row {row_num}: {exc}')


class FortiGateParser(_DelegatingVendorParser):
    VERSION = '1.1.0'
    ARTIFACT_TYPE = 'fortigate'
    FIELD_ALIASES = {
        'src_ip': ('srcip',),
        'dst_ip': ('dstip',),
        'src_port': ('srcport',),
        'dst_port': ('dstport',),
        'username': ('user', 'srcname', 'unauthuser'),
        'source_host': ('devname', 'devid'),
        'rule_title': ('action', 'attack', 'msg'),
        'rule_level': ('level', 'severity', 'crlevel'),
        'event_id': ('logid', 'subtype'),
        'target_path': ('url', 'hostname', 'filename'),
        'process_name': ('app', 'service'),
    }
    FILENAME_MARKERS = ['fortigate', 'fortinet']
    CONTENT_MARKERS = ['devname=', 'devid=', 'logid=', 'srcip=', 'dstip=']

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        if not os.path.isfile(file_path):
            return False
        if self._is_forensic_binary_extension(file_path):
            return False
        if self._matches_filename(file_path):
            return True
        return self._matches_sample(self._file_sample(file_path))

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        yield from self._delegate_parse(file_path, FirewallLogParser)


class SonicWallSyslogParser(_DelegatingVendorParser):
    VERSION = '1.1.0'
    ARTIFACT_TYPE = 'sonicwall_syslog'
    FIELD_ALIASES = {
        'src_ip': ('src', 'srcip'),
        'dst_ip': ('dst', 'dstip'),
        'username': ('usr', 'user'),
        'source_host': ('fw', 'sn'),
        'rule_title': ('fw_action', 'msg', 'action'),
        'rule_level': ('pri', 'sev'),
        'event_id': ('m', 'c', 'cat'),
        'target_path': ('dstname', 'url'),
        'process_name': ('app', 'appName'),
    }
    # Filename: sonicwall only — bare 'syslog' matches Linux /var/log/syslog basenames.
    FILENAME_MARKERS = ['sonicwall']
    _CONTENT_HINT = re.compile(
        r'fw_action=|\bsonicwall\b|cfsaction=|\bcfs_|%sonicos-|\bmsg=\s*"?sonicwall',
        re.IGNORECASE,
    )

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        if not os.path.isfile(file_path):
            return False
        if self._matches_filename(file_path):
            return True
        sample = self._file_sample(file_path)
        return bool(self._CONTENT_HINT.search(sample))

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        yield from self._delegate_parse(file_path, FirewallLogParser)


class PfSenseParser(BaseParser):
    VERSION = '1.1.0'
    ARTIFACT_TYPE = 'pfsense'
    SYSLOG_RE = re.compile(
        r'^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<host>\S+)\s+'
        r'(?P<program>[^:\[]+)(?:\[(?P<pid>\d+)\])?:\s*'
        r'(?P<msg>.*)$'
    )
    FILTERLOG_RE = re.compile(r'\bfilterlog(?:\[\d+\])?:\s*(?P<body>.+)$', re.IGNORECASE)
    NGINX_RE = re.compile(
        r'^(?P<client_ip>\S+)\s+\S+\s+\S+\s+\[(?P<request_ts>[^\]]+)\]\s+'
        r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+(?P<http_version>[^"]+))?"\s+'
        r'(?P<status>\d{3})\s+(?P<bytes>\S+)\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
    )
    DHCP_LEASE_RE = re.compile(r'^lease\s+(?P<ip>\S+)\s+\{')
    DHCP_LOG_EVENT_RE = re.compile(r'\b(?P<action>DHCPDISCOVER|DHCPOFFER|DHCPREQUEST|DHCPACK|DHCPNAK)\b')
    MAC_RE = re.compile(r'(?i)\b([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b')
    IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    KNOWN_LOG_FILENAMES = {
        'auth.log', 'dhcpd.log', 'filter.log', 'gateways.log', 'nginx.log',
        'resolver.log', 'routing.log', 'system.log', 'ipsec.log', 'l2tps.log',
        'ntpd.log', 'openvpn.log', 'poes.log', 'portalauth.log', 'ppp.log',
        'vpn.log', 'wireless.log',
    }

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        if not os.path.isfile(file_path) or self.is_tool_configuration(file_path):
            return False
        lower_name = os.path.basename(file_path).lower()
        if (
            any(lower_name.endswith(name) for name in self.KNOWN_LOG_FILENAMES)
            or lower_name.startswith('filter.log.')
            or lower_name.endswith(('dhcpd.leases', 'dhcpd6.leases', 'config.xml'))
            or any(marker in lower_name for marker in ('pfsense', 'opnsense', 'filterlog'))
        ):
            return True
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as handle:
                sample = handle.read(4096).lower()
        except Exception:
            return False
        return (
            'filterlog[' in sample
            or 'filterlog:' in sample
            or '<pfsense>' in sample
            or 'this lease file was written by isc-dhcp' in sample
            or bool(self.SYSLOG_RE.search(sample) and ' pfsense ' in f' {sample} ')
        )

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        if not self.can_parse(file_path):
            self.errors.append(f'Cannot parse file: {file_path}')
            return

        source_file = os.path.basename(file_path)
        lower_name = source_file.lower()

        if lower_name.endswith('config.xml'):
            yield from self._parse_config_xml(file_path)
            return
        if lower_name.endswith(('dhcpd.leases', 'dhcpd6.leases')):
            yield from self._parse_dhcp_leases(file_path)
            return

        yield from self._parse_syslog_file(file_path)

    def _timestamp_from_syslog(self, payload: Dict[str, str], file_path: str) -> datetime:
        return self.first_timestamp(
            self.parse_timestamp(payload.get('ts', '')),
            file_path=file_path,
            reason='pfSense syslog line missing timestamp',
        )

    def _extract_ips_from_fields(self, fields: List[str]) -> List[str]:
        ips: List[str] = []
        for field in fields:
            candidate = field.strip()
            if self.validate_ip(candidate):
                ips.append(candidate)
        return ips

    def _format_endpoint(self, ip_value: Any, port_value: Any = None) -> str:
        ip_text = self.safe_str(ip_value)
        if not ip_text:
            return ''
        if port_value in (None, '', '-'):
            return ip_text
        return f'{ip_text}:{port_value}'

    def _pfsense_action_label(self, action: str) -> str:
        normalized = self.safe_str(action).lower()
        if normalized == 'block':
            return 'blocked'
        if normalized == 'pass':
            return 'allowed'
        if normalized == 'match':
            return 'matched'
        return normalized or 'recorded'

    def _plural_count(self, count: int, singular: str, plural: Optional[str] = None) -> str:
        label = singular if count == 1 else (plural or f'{singular}s')
        return f'{count} {label}'

    def _event_id_for_program(self, program: str, message: str) -> str:
        program = (program or '').lower()
        message_lower = (message or '').lower()
        if program == 'filterlog':
            return 'pfsense_filterlog'
        if program in {'dhcpd', 'dhclient', 'dhcp6c'}:
            match = self.DHCP_LOG_EVENT_RE.search(message)
            return f"pfsense_{match.group('action').lower()}" if match else 'pfsense_dhcp'
        if program == 'nginx':
            return 'pfsense_webgui_access'
        if 'successful login' in message_lower:
            return 'pfsense_login_success'
        if 'configuration change' in message_lower:
            return 'pfsense_config_change'
        if 'rebooted by' in message_lower or 'bootup complete' in message_lower:
            return 'pfsense_system_boot'
        return f'pfsense_{program}' if program else 'pfsense_syslog'

    def _parse_filterlog_event(
        self,
        payload: Dict[str, str],
        fields: List[str],
        file_path: str,
        source_file: str,
        line: str,
    ) -> ParsedEvent:
        ips = self._extract_ips_from_fields(fields)
        src_ip, src_ip_raw = self.normalize_ip_for_storage(ips[0] if len(ips) >= 1 else None)
        dst_ip, dst_ip_raw = self.normalize_ip_for_storage(ips[1] if len(ips) >= 2 else None)
        lowered_fields = [field.lower() for field in fields]
        if 'block' in lowered_fields:
            action = fields[lowered_fields.index('block')]
        elif 'pass' in lowered_fields:
            action = fields[lowered_fields.index('pass')]
        elif 'match' in lowered_fields:
            action = fields[lowered_fields.index('match')]
        else:
            action = ''
        direction = next((field for field in fields if field.lower() in {'in', 'out'}), '')
        protocol_idx = next(
            (idx for idx, field in enumerate(lowered_fields) if field in {'tcp', 'udp', 'icmp', 'icmp6'}),
            None,
        )
        protocol = fields[protocol_idx].lower() if protocol_idx is not None else ''
        ip_indices = [idx for idx, field in enumerate(fields) if self.validate_ip(field)]
        dst_index = ip_indices[1] if len(ip_indices) >= 2 else None
        src_port = self.safe_uint16(fields[dst_index + 1]) if dst_index is not None and len(fields) > dst_index + 1 else None
        dst_port = self.safe_uint16(fields[dst_index + 2]) if dst_index is not None and len(fields) > dst_index + 2 else None
        interface = fields[4] if len(fields) > 4 else ''
        rule_id = fields[3] if len(fields) > 3 else ''
        extra = {
            'log_subtype': 'filter',
            'program': payload.get('program', ''),
            'pid': payload.get('pid', ''),
            'interface': interface,
            'rule_id': rule_id,
            'direction': direction,
            'protocol': protocol,
            'parts': fields,
        }
        if src_ip_raw:
            extra['src_ip_raw'] = src_ip_raw
        if dst_ip_raw:
            extra['dst_ip_raw'] = dst_ip_raw
        src_endpoint = self._format_endpoint(src_ip or src_ip_raw, src_port)
        dst_endpoint = self._format_endpoint(dst_ip or dst_ip_raw, dst_port)
        direction_label = {'in': 'inbound', 'out': 'outbound'}.get(direction.lower(), direction)
        context = ' '.join(
            part for part in [
                protocol.upper() if protocol else '',
                direction_label,
                f'on {interface}' if interface else '',
            ]
            if part
        )
        extra['display'] = {
            'subtype': 'filter',
            'badge': action or 'filter',
            'primary': (
                f"Firewall {self._pfsense_action_label(action)} {context}: "
                f"{src_endpoint} -> {dst_endpoint}"
            ).strip().rstrip(':'),
            'secondary': f"rule {rule_id} | {', '.join(part for part in [interface, direction, protocol] if part)}",
        }
        return ParsedEvent(
            case_id=self.case_id,
            artifact_type=self.artifact_type,
            timestamp=self._timestamp_from_syslog(payload, file_path),
            timestamp_source_tz=self.get_source_tz(),
            source_file=source_file,
            source_path=file_path,
            source_host=payload.get('host') or self.extract_hostname(file_path),
            case_file_id=self.case_file_id,
            event_id='pfsense_filterlog',
            provider=payload.get('program', ''),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            rule_title=action,
            raw_json=json.dumps({'line': line, **payload}, default=str),
            search_blob=self.build_search_blob({'line': line, 'parts': fields}),
            extra_fields=json.dumps(extra, default=str),
            parser_version=self.parser_version,
        )

    def _parse_nginx_event(
        self,
        payload: Dict[str, str],
        file_path: str,
        source_file: str,
        line: str,
    ) -> ParsedEvent:
        message = payload.get('msg', '')
        match = self.NGINX_RE.match(message)
        request = match.groupdict(default='') if match else {}
        src_ip, src_ip_raw = self.normalize_ip_for_storage(request.get('client_ip'))
        timestamp = self.parse_timestamp(request.get('request_ts', ''), formats=['%d/%b/%Y:%H:%M:%S %z']) if request else None
        extra = {
            'log_subtype': 'nginx',
            'program': payload.get('program', ''),
            'pid': payload.get('pid', ''),
            **request,
        }
        if src_ip_raw:
            extra['src_ip_raw'] = src_ip_raw
        method = request.get('method', '')
        path = request.get('path', '')
        status = request.get('status', '')
        client_ip = request.get('client_ip') or src_ip or src_ip_raw
        request_label = ' '.join(part for part in [method, path] if part) or 'request'
        extra['display'] = {
            'subtype': 'web',
            'badge': 'web',
            'primary': (
                f"WebConfigurator {request_label}"
                f"{f' from {client_ip}' if client_ip else ''}"
                f"{f' returned {status}' if status else ''}"
            ),
            'secondary': request.get('user_agent', ''),
        }
        return ParsedEvent(
            case_id=self.case_id,
            artifact_type=self.artifact_type,
            timestamp=timestamp or self._timestamp_from_syslog(payload, file_path),
            timestamp_source_tz=self.get_source_tz(),
            source_file=source_file,
            source_path=file_path,
            source_host=payload.get('host') or self.extract_hostname(file_path),
            case_file_id=self.case_file_id,
            event_id='pfsense_webgui_access',
            provider=payload.get('program', ''),
            src_ip=src_ip,
            raw_json=json.dumps({'line': line, **payload, **request}, default=str),
            search_blob=self.build_search_blob({'line': line, **payload, **request}),
            extra_fields=json.dumps(extra, default=str),
            parser_version=self.parser_version,
        )

    def _parse_generic_syslog_event(
        self,
        payload: Dict[str, str],
        file_path: str,
        source_file: str,
        line: str,
    ) -> ParsedEvent:
        message = payload.get('msg') or payload.get('message') or line
        ips = self.IPV4_RE.findall(message)
        src_ip, src_ip_raw = self.normalize_ip_for_storage(ips[0] if ips else None)
        extra = {
            'log_subtype': os.path.splitext(source_file)[0],
            'program': payload.get('program', ''),
            'pid': payload.get('pid', ''),
        }
        macs = self.MAC_RE.findall(message)
        if macs:
            extra['mac_addresses'] = macs
        dhcp_match = self.DHCP_LOG_EVENT_RE.search(message)
        if dhcp_match:
            extra['dhcp_action'] = dhcp_match.group('action')
        if src_ip_raw:
            extra['src_ip_raw'] = src_ip_raw
        dhcp_action = extra.get('dhcp_action', '')
        if dhcp_action:
            mac = macs[0] if macs else ''
            hostname_match = re.search(r'\(([^)]+)\)', message)
            hostname = hostname_match.group(1) if hostname_match else ''
            target = hostname or mac or 'client'
            lease_ip = src_ip or (ips[0] if ips else '')
            extra['display'] = {
                'subtype': 'dhcp',
                'badge': dhcp_action.lower(),
                'primary': (
                    f"{dhcp_action} for {lease_ip} to {target}"
                    f"{f' ({mac})' if hostname and mac else ''}"
                ).replace('for  to', 'for'),
                'secondary': message,
            }
        elif 'login' in self._event_id_for_program(payload.get('program', ''), message):
            extra['display'] = {
                'subtype': 'auth',
                'badge': 'auth',
                'primary': 'Successful pfSense login',
                'secondary': message,
            }
        return ParsedEvent(
            case_id=self.case_id,
            artifact_type=self.artifact_type,
            timestamp=self._timestamp_from_syslog(payload, file_path),
            timestamp_source_tz=self.get_source_tz(),
            source_file=source_file,
            source_path=file_path,
            source_host=payload.get('host') or self.extract_hostname(file_path),
            case_file_id=self.case_file_id,
            event_id=self._event_id_for_program(payload.get('program', ''), message),
            provider=payload.get('program', ''),
            src_ip=src_ip,
            remote_host=ips[0] if ips else '',
            raw_json=json.dumps({'line': line, **payload}, default=str),
            search_blob=self.build_search_blob({'line': line, **payload}),
            extra_fields=json.dumps(extra, default=str),
            parser_version=self.parser_version,
        )

    def _parse_syslog_file(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        source_file = os.path.basename(file_path)
        with open(file_path, 'r', encoding='utf-8', errors='replace') as handle:
            for line_num, line in enumerate(handle, 1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    match = self.SYSLOG_RE.match(stripped)
                    payload = {'line_number': str(line_num), 'message': stripped}
                    if match:
                        payload.update(match.groupdict(default=''))
                    else:
                        payload['msg'] = stripped

                    filter_match = self.FILTERLOG_RE.search(stripped)
                    if filter_match:
                        fields = [part.strip() for part in filter_match.group('body').split(',')]
                        yield self._parse_filterlog_event(payload, fields, file_path, source_file, stripped)
                    elif (payload.get('program') or '').lower() == 'nginx':
                        yield self._parse_nginx_event(payload, file_path, source_file, stripped)
                    else:
                        yield self._parse_generic_syslog_event(payload, file_path, source_file, stripped)
                except Exception as exc:
                    self.warnings.append(f'Error processing pfSense row {line_num}: {exc}')

    def _parse_dhcp_leases(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        source_file = os.path.basename(file_path)
        with open(file_path, 'r', encoding='utf-8', errors='replace') as handle:
            current: Optional[Dict[str, Any]] = None
            for line_num, line in enumerate(handle, 1):
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    continue
                match = self.DHCP_LEASE_RE.match(stripped)
                if match:
                    current = {'lease_ip': match.group('ip'), 'line_number': line_num}
                    continue
                if current is None:
                    continue
                if stripped == '}':
                    ip_value = current.get('lease_ip')
                    src_ip, src_ip_raw = self.normalize_ip_for_storage(ip_value)
                    extra = {'log_subtype': 'dhcp_leases', **current}
                    if src_ip_raw:
                        extra['src_ip_raw'] = src_ip_raw
                    owner = current.get('client_hostname') or current.get('hardware_ethernet') or 'client'
                    mac = current.get('hardware_ethernet', '')
                    state = current.get('binding_state') or 'lease'
                    extra['display'] = {
                        'subtype': 'dhcp',
                        'badge': state,
                        'primary': (
                            f"DHCP {state}: {ip_value} assigned to {owner}"
                            f"{f' ({mac})' if current.get('client_hostname') and mac else ''}"
                        ),
                        'secondary': ' | '.join(
                            part for part in [
                                f"starts {current.get('starts', '')}" if current.get('starts') else '',
                                f"ends {current.get('ends', '')}" if current.get('ends') else '',
                            ]
                            if part
                        ),
                    }
                    yield ParsedEvent(
                        case_id=self.case_id,
                        artifact_type=self.artifact_type,
                        timestamp=self.parse_timestamp(current.get('cltt', '')) or self.fallback_timestamp(
                            file_path=file_path,
                            reason='pfSense DHCP lease missing timestamp',
                        ),
                        timestamp_source_tz='UTC',
                        source_file=source_file,
                        source_path=file_path,
                        source_host=self.extract_hostname(file_path),
                        case_file_id=self.case_file_id,
                        event_id='pfsense_dhcp_lease',
                        provider='dhcpd',
                        # ISC dhcpd writes lease times in UTC unless the server
                        # is configured for db-time-format local, so applying the
                        # case offset shifted every lease a second time.
                        src_ip=src_ip,
                        remote_host=ip_value or '',
                        workstation_name=current.get('client_hostname', ''),
                        raw_json=json.dumps(current, default=str),
                        search_blob=self.build_search_blob(current),
                        extra_fields=json.dumps(extra, default=str),
                        parser_version=self.parser_version,
                    )
                    current = None
                    continue
                key_value = stripped.rstrip(';')
                if key_value.startswith('starts '):
                    current['starts'] = ' '.join(key_value.split()[2:])
                elif key_value.startswith('ends '):
                    current['ends'] = ' '.join(key_value.split()[2:])
                elif key_value.startswith('cltt '):
                    current['cltt'] = ' '.join(key_value.split()[2:])
                elif key_value.startswith('binding state '):
                    current['binding_state'] = key_value.replace('binding state ', '', 1)
                elif key_value.startswith('hardware ethernet '):
                    current['hardware_ethernet'] = key_value.replace('hardware ethernet ', '', 1)
                elif key_value.startswith('client-hostname '):
                    current['client_hostname'] = key_value.replace('client-hostname ', '', 1).strip('"')
                elif key_value.startswith('set vendor-class-identifier = '):
                    current['vendor_class_identifier'] = key_value.replace('set vendor-class-identifier = ', '', 1).strip('"')

    def _count_children(self, root: ET.Element, path: str) -> int:
        element = root.find(path)
        return len(list(element)) if element is not None else 0

    def _parse_config_xml(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        source_file = os.path.basename(file_path)
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
        except Exception as exc:
            self.errors.append(f'Error processing pfSense config XML: {exc}')
            return
        if root.tag.lower() != 'pfsense':
            self.errors.append(f'Cannot parse non-pfSense config XML: {file_path}')
            return

        system = root.find('system')
        interfaces = root.find('interfaces')
        summary = {
            'log_subtype': 'config',
            'hostname': system.findtext('hostname', default='') if system is not None else '',
            'domain': system.findtext('domain', default='') if system is not None else '',
            'timezone': system.findtext('timezone', default='') if system is not None else '',
            'ssh_enabled': system.find('ssh/enable') is not None if system is not None else False,
            'users': [user.findtext('name', default='') for user in root.findall('./system/user')],
            'password_hash_present': any(bool(user.findtext('bcrypt-hash')) for user in root.findall('./system/user')),
            'interfaces': [
                {
                    'name': interface.tag,
                    'descr': interface.findtext('descr', default=''),
                    'if': interface.findtext('if', default=''),
                    'ipaddr': interface.findtext('ipaddr', default=''),
                    'subnet': interface.findtext('subnet', default=''),
                }
                for interface in list(interfaces) if interfaces is not None
            ],
            'dhcp_ranges': [
                {
                    'interface': dhcp_interface.tag,
                    'from': dhcp_interface.findtext('range/from', default=''),
                    'to': dhcp_interface.findtext('range/to', default=''),
                }
                for dhcp_interface in root.findall('./dhcpd/*')
            ],
            'filter_rule_count': self._count_children(root, 'filter'),
            'nat_rule_count': self._count_children(root, 'nat'),
            'openvpn_configured': root.find('openvpn') is not None and len(list(root.find('openvpn'))) > 0,
            'ipsec_configured': root.find('ipsec') is not None and len(list(root.find('ipsec'))) > 0,
            'certificate_count': len(root.findall('cert')),
            'ca_count': len(root.findall('ca')),
        }
        summary['display'] = {
            'subtype': 'config',
            'badge': 'config',
            'primary': (
                f"Config summary: {self._plural_count(len(summary['interfaces']), 'interface')}, "
                f"{self._plural_count(summary['filter_rule_count'], 'firewall rule')}, "
                f"{'SSH enabled' if summary['ssh_enabled'] else 'SSH disabled'}, "
                f"{self._plural_count(len(summary['users']), 'user')}"
            ),
            'secondary': (
                f"timezone {summary['timezone'] or 'unknown'} | "
                f"{len(summary['dhcp_ranges'])} DHCP ranges | "
                f"{summary['certificate_count']} certificates"
            ),
        }
        yield ParsedEvent(
            case_id=self.case_id,
            artifact_type=self.artifact_type,
            timestamp=self.fallback_timestamp(file_path=file_path, reason='pfSense config XML missing timestamp'),
            timestamp_source_tz=self.get_source_tz(),
            source_file=source_file,
            source_path=file_path,
            source_host=summary.get('hostname') or self.extract_hostname(file_path),
            case_file_id=self.case_file_id,
            event_id='pfsense_config_summary',
            provider='config.xml',
            raw_json=json.dumps(summary, default=str),
            search_blob=self.build_search_blob(summary),
            extra_fields=json.dumps(summary, default=str),
            parser_version=self.parser_version,
        )


class CiscoAsaParser(_DelegatingVendorParser):
    VERSION = '1.1.0'
    ARTIFACT_TYPE = 'cisco_asa'
    FIELD_ALIASES = {
        'event_id': ('asa_message_id', 'message_id'),
        'rule_title': ('action', 'msg'),
        'source_host': ('host', 'device'),
        'username': ('user', 'username'),
    }
    # Omit bare 'asa' — substring in unrelated paths (e.g. plasma, database names).
    FILENAME_MARKERS = ['cisco', 'ftd']
    CONTENT_MARKERS = ['%asa-', '%ftd-', 'cisco asa']

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        if not os.path.isfile(file_path):
            return False
        if self._is_forensic_binary_extension(file_path):
            return False
        if self._matches_filename(file_path):
            return True
        return self._matches_sample(self._file_sample(file_path))

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        yield from self._delegate_parse(file_path, FirewallLogParser)


class SuricataEveParser(BaseParser):
    VERSION = '1.1.0'
    ARTIFACT_TYPE = 'suricata'
    # alert.severity is a Suricata priority, where 1 is the most severe. Stored
    # raw it sorted and filtered against the words every other parser writes.
    SEVERITY_NAMES = {1: 'high', 2: 'medium', 3: 'low', 4: 'informational'}

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def _severity_name(self, value: Any) -> str:
        """Translate a numeric Suricata priority into the shared level vocabulary."""
        if value is None or isinstance(value, bool):
            return ''
        try:
            return self.SEVERITY_NAMES.get(int(value), 'informational')
        except (TypeError, ValueError):
            return self.safe_str(value).lower()

    def can_parse(self, file_path: str) -> bool:
        if not os.path.isfile(file_path) or self.is_tool_configuration(file_path):
            return False
        lower_name = os.path.basename(file_path).lower()
        # Avoid matching 'eve' inside unrelated names (e.g. steve.json).
        if lower_name.endswith(('.json', '.jsonl', '.ndjson')):
            if re.search(r'(^|[^a-z])eve([^a-z]|$)', lower_name):
                return True
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as handle:
                sample = handle.read(2048).lower()
        except Exception:
            return False
        return '"event_type"' in sample and ('"suricata"' in sample or '"alert"' in sample or '"flow_id"' in sample)

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        if not self.can_parse(file_path):
            self.errors.append(f'Cannot parse file: {file_path}')
            return

        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)

        with open(file_path, 'r', encoding='utf-8', errors='replace') as handle:
            for line_num, line in enumerate(handle, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    if not isinstance(record, dict):
                        continue

                    alert = record.get('alert') or {}
                    src_ip, src_ip_raw = self.normalize_ip_for_storage(record.get('src_ip'))
                    dst_ip, dst_ip_raw = self.normalize_ip_for_storage(record.get('dest_ip'))
                    src_port = self.safe_uint16(record.get('src_port'))
                    dst_port = self.safe_uint16(record.get('dest_port'))
                    event_type = self.safe_str(record.get('event_type'))
                    rule_title = self.safe_str(alert.get('signature') or event_type)
                    raw_severity = alert.get('severity')
                    severity = self._severity_name(raw_severity) or self.safe_str(alert.get('category'))
                    target_path = self.safe_str(
                        (record.get('http') or {}).get('url')
                        or (record.get('dns') or {}).get('rrname')
                        or (record.get('fileinfo') or {}).get('filename')
                    )
                    raw_data = dict(record)
                    raw_data['event_type'] = event_type
                    extra = {
                        'alert_category': alert.get('category'),
                        'alert_severity': raw_severity,
                        'alert_signature_id': alert.get('signature_id'),
                        'app_proto': record.get('app_proto'),
                        'flow_id': record.get('flow_id'),
                        'proto': record.get('proto'),
                        'dns_query': (record.get('dns') or {}).get('rrname'),
                        'http_hostname': (record.get('http') or {}).get('hostname'),
                    }
                    if src_ip_raw:
                        extra['src_ip_raw'] = src_ip_raw
                    if dst_ip_raw:
                        extra['dst_ip_raw'] = dst_ip_raw
                    extra = {k: v for k, v in extra.items() if v not in (None, '', [])}

                    yield ParsedEvent(
                        case_id=self.case_id,
                        artifact_type=self.artifact_type,
                        timestamp=self.parse_timestamp(record.get('timestamp')) or self.fallback_timestamp(
                            file_path=file_path,
                            reason='suricata eve event missing timestamp',
                        ),
                        timestamp_source_tz=self.get_source_tz(),
                        source_file=source_file,
                        source_path=file_path,
                        source_host=self.safe_str((record.get('host') or {}).get('name') or hostname),
                        case_file_id=self.case_file_id,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        target_path=target_path,
                        rule_title=rule_title,
                        rule_level=severity.lower(),
                        raw_json=json.dumps(raw_data, default=str),
                        search_blob=self.build_search_blob(raw_data),
                        extra_fields=json.dumps(extra, default=str),
                        parser_version=self.parser_version,
                    )
                except Exception as exc:
                    self.warnings.append(f'Error processing Suricata row {line_num}: {exc}')


class VelociraptorParser(_DelegatingVendorParser):
    VERSION = '1.1.0'
    ARTIFACT_TYPE = 'velociraptor'
    FIELD_ALIASES = {
        'source_host': ('fqdn', 'hostname', 'client_id', 'clientid'),
        'target_path': ('osspath', 'fullpath', '_source', 'name'),
        'process_name': ('name', 'exe'),
        'command_line': ('commandline', 'cmdline'),
        'process_id': ('pid',),
        'parent_pid': ('ppid',),
        'username': ('username', 'user', 'owner'),
        'event_id': ('artifactname', 'artifact'),
    }
    FILENAME_MARKERS = ['velociraptor']
    # Avoid loose 'clientid' / 'artifact' — they appear in Firefox telemetry and generic JSON.
    _VR_JSON_KEYS = re.compile(
        r'"(?:ClientId|FlowId|ArtifactName|VQLResponse|VQLResponseArray)"\s*:',
        re.IGNORECASE,
    )
    _VR_FLOW_CLIENT = re.compile(
        r'"ClientId"\s*:\s*"C\.[^"]+|"FlowId"\s*:\s*"F\.[^"]+',
        re.IGNORECASE,
    )

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        if not os.path.isfile(file_path):
            return False
        if self._matches_filename(file_path):
            return True
        sample = self._file_sample(file_path)
        sl = sample.lower()
        if 'velociraptor' in sl:
            return True
        if self._VR_FLOW_CLIENT.search(sample):
            return True
        if self._VR_JSON_KEYS.search(sample) and ('vql' in sl or 'artifactname' in sl):
            return True
        return False

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        lower_path = file_path.lower()
        if lower_path.endswith(self.CSV_EXTENSIONS):
            yield from self._delegate_parse(file_path, CSVLogParser)
        else:
            yield from self._delegate_parse(file_path, GenericJSONParser)


class PlasoParser(_DelegatingVendorParser):
    VERSION = '1.1.0'
    ARTIFACT_TYPE = 'plaso'
    FIELD_ALIASES = {
        'target_path': ('display_name', 'filename', 'path_spec'),
        'source_host': ('hostname', 'computer_name'),
        'event_id': ('data_type', 'timestamp_desc'),
        'rule_title': ('source_long', 'source'),
        'username': ('username', 'user'),
    }
    FILENAME_MARKERS = ['plaso', 'log2timeline', 'l2t']
    CONTENT_MARKERS = ['timestamp_desc', 'display_name', 'parser']

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        if not os.path.isfile(file_path):
            return False
        if self._matches_filename(file_path):
            return True
        return self._matches_sample(self._file_sample(file_path))

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        lower_path = file_path.lower()
        if lower_path.endswith(self.CSV_EXTENSIONS):
            yield from self._delegate_parse(file_path, CSVLogParser)
        else:
            yield from self._delegate_parse(file_path, GenericJSONParser)


class CrowdStrikeParser(_DelegatingVendorParser):
    VERSION = '1.1.0'
    ARTIFACT_TYPE = 'crowdstrike'
    FIELD_ALIASES = {
        'event_id': ('event_simplename',),
        'process_name': ('imagefilename', 'filename'),
        'process_path': ('imagefilename',),
        'command_line': ('commandline',),
        'parent_process': ('parentbasefilename', 'parentimagefilename'),
        'src_ip': ('localaddressip4', 'localaddress'),
        'dst_ip': ('remoteaddressip4', 'remoteaddress'),
        'username': ('username', 'usernamestring', 'useridstring'),
        'sid': ('usersid', 'usersidstring'),
        'source_host': ('computername', 'aid_computer_name'),
        'process_id': ('rawprocessid', 'targetprocessid'),
        'parent_pid': ('parentprocessid',),
        'rule_title': ('detectname', 'detectdescription'),
        'rule_level': ('severityname', 'severity'),
    }
    FILENAME_MARKERS = ['crowdstrike', 'falcon']
    # 'aid' is a three letter key that browser extension manifests and plenty
    # of other JSON also use, and on its own it claimed 27 such files. Only
    # event_simpleName is unmistakably CrowdStrike; the rest need corroboration.
    DISTINCTIVE_MARKERS = ('event_simplename', 'aid_computer_name', 'falconhostlink')
    # Deliberately excludes 'name' and 'timestamp': they corroborate nothing
    # because almost every JSON document has them.
    CORROBORATING_MARKERS = (
        'cid', 'devicename', 'computername', 'agentipaddress', 'agentversion',
        'commandline', 'imagefilename', 'targetprocessid', 'rawprocessid',
        'event_platform', 'eventtype', 'localaddressip4', 'usersid',
    )

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        if not os.path.isfile(file_path):
            return False
        if self._matches_filename(file_path):
            return True
        if not file_path.lower().endswith(self.JSON_EXTENSIONS + self.CSV_EXTENSIONS):
            return False
        return self._matches_structured_export(file_path)

    def _keys_look_like_crowdstrike(self, keys: Iterable[str]) -> bool:
        """A record is CrowdStrike if it is unmistakable or corroborated twice."""
        normalized = {str(key).strip().lower() for key in keys}
        if normalized & set(self.DISTINCTIVE_MARKERS):
            return True
        if 'aid' not in normalized:
            return False
        return len(normalized & set(self.CORROBORATING_MARKERS)) >= 2

    def _matches_structured_export(self, file_path: str) -> bool:
        try:
            if file_path.lower().endswith(self.CSV_EXTENSIONS):
                with open(file_path, 'r', encoding='utf-8-sig', errors='replace', newline='') as handle:
                    reader = csv.reader(handle)
                    headers = next(reader, [])
                return self._keys_look_like_crowdstrike(headers)

            with open(file_path, 'r', encoding='utf-8', errors='replace') as handle:
                content = handle.read().strip()
            if not content:
                return False
            records = []
            if content.startswith('['):
                data = json.loads(content)
                if isinstance(data, list):
                    records = [item for item in data[:5] if isinstance(item, dict)]
            elif content.startswith('{'):
                data = json.loads(content)
                if isinstance(data, dict):
                    records = [data]
            else:
                for line in content.splitlines()[:5]:
                    line = line.strip()
                    if not line:
                        continue
                    item = json.loads(line)
                    if isinstance(item, dict):
                        records.append(item)
            for record in records:
                if self._keys_look_like_crowdstrike(record.keys()):
                    return True
        except Exception:
            return False
        return False

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        lower_path = file_path.lower()
        if lower_path.endswith(self.CSV_EXTENSIONS):
            yield from self._delegate_parse(file_path, CSVLogParser)
        else:
            yield from self._delegate_parse(file_path, GenericJSONParser)


class SentinelOneParser(_DelegatingVendorParser):
    VERSION = '1.1.0'
    ARTIFACT_TYPE = 'sentinelone'
    FIELD_ALIASES = {
        'process_name': ('srcprocname', 'tgtprocname', 'processname'),
        'process_path': ('srcprocimagepath', 'tgtprocimagepath'),
        'command_line': ('srcproccmdline', 'tgtproccmdline'),
        'parent_process': ('srcprocparentname', 'tgtprocparentname'),
        'process_id': ('srcprocpid', 'tgtprocpid'),
        'parent_pid': ('srcprocparentpid',),
        'username': ('srcprocuser', 'tgtprocuser', 'agentuseremail'),
        'source_host': ('endpointname', 'agentcomputername', 'computername'),
        'target_path': ('tgtfilepath', 'filepath'),
        'file_hash_sha1': ('tgtfilesha1', 'sha1'),
        'file_hash_sha256': ('tgtfilesha256', 'sha256'),
        'rule_title': ('threatname', 'alertname'),
        'rule_level': ('threatconfidencelevel', 'severity'),
    }
    FILENAME_MARKERS = ['sentinelone', 'sentinel_one']
    CONTENT_MARKERS = ['agentuuid', 'sitename', 'threatname']

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        if not os.path.isfile(file_path):
            return False
        if self._matches_filename(file_path):
            return True
        return self._matches_sample(self._file_sample(file_path))

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        lower_path = file_path.lower()
        if lower_path.endswith(self.CSV_EXTENSIONS):
            yield from self._delegate_parse(file_path, CSVLogParser)
        else:
            yield from self._delegate_parse(file_path, GenericJSONParser)


class SophosParser(_DelegatingVendorParser):
    VERSION = '1.1.0'
    ARTIFACT_TYPE = 'sophos'
    FIELD_ALIASES = {
        'source_host': ('endpoint_id', 'endpoint_name', 'hostname'),
        'rule_title': ('threat', 'name', 'detection_identity_name'),
        'rule_level': ('severity', 'threat_severity'),
        'target_path': ('location', 'path', 'file_path'),
        'username': ('user', 'user_name', 'source_info_user'),
    }
    FILENAME_MARKERS = ['sophos', 'interceptx', 'intercept_x']
    CONTENT_MARKERS = ['endpoint_type', 'threat_id', 'sophos']

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        if not os.path.isfile(file_path):
            return False
        if self._matches_filename(file_path):
            return True
        return self._matches_sample(self._file_sample(file_path))

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        lower_path = file_path.lower()
        if lower_path.endswith(self.CSV_EXTENSIONS):
            yield from self._delegate_parse(file_path, CSVLogParser)
        else:
            yield from self._delegate_parse(file_path, GenericJSONParser)
