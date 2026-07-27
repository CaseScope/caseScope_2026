"""Linux and Unix artifact parsers."""
import bz2
import gzip
import json
import lzma
import os
import re
import struct
import subprocess
from datetime import datetime, timedelta, timezone
from typing import Dict, Generator, Optional

from parsers.base import BaseParser, ParsedEvent


class LinuxSyslogAuthParser(BaseParser):
    VERSION = '1.1.0'
    ARTIFACT_TYPE = 'linux_syslog'
    SYSLOG_RE = re.compile(r'^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<program>[^:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$')
    # rsyslog and systemd increasingly emit RFC 5424 / ISO-8601 stamps, which the
    # BSD pattern above cannot match at all.
    RFC5424_RE = re.compile(
        r'^(?:<\d{1,3}>\d?\s*)?'
        r'(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+'
        r'(?P<host>\S+)\s+'
        r'(?P<program>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:?\s+'
        r'(?P<msg>.*)$'
    )
    LOG_BASENAMES = ('auth.log', 'secure', 'syslog', 'messages', 'kern.log', 'daemon.log')
    # Most history lives in the rotated copies: auth.log.1, syslog.2.gz, ...
    ROTATED_RE = re.compile(
        r'^(?:%s)(?:\.\d+)?(?:\.gz|\.bz2|\.xz)?$' % '|'.join(re.escape(n) for n in LOG_BASENAMES)
    )
    # sshd names the account and the source port on every authentication line.
    # Without these the events cannot be pivoted on user or correlated to a flow.
    SSH_USER_RE = re.compile(
        r'\bfor\s+(?:invalid\s+user\s+|illegal\s+user\s+)?(?P<user>[^\s]+)\s+from\b',
        re.IGNORECASE,
    )
    INVALID_USER_RE = re.compile(r'\b(?:invalid|illegal)\s+user\s+(?P<user>[^\s]+)', re.IGNORECASE)
    SUDO_USER_RE = re.compile(r'^\s*(?P<user>[A-Za-z0-9._-]+)\s*:\s*(?:TTY|USER|PWD)=')
    SUDO_TARGET_RE = re.compile(r'\bUSER=(?P<user>[^\s;]+)')
    SUDO_COMMAND_RE = re.compile(r'\bCOMMAND=(?P<command>.+)$')
    PORT_RE = re.compile(r'\bport\s+(?P<port>\d{1,5})\b', re.IGNORECASE)
    IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    # IPv6 never matched the IPv4-only scan, so v6 sources were invisible
    IPV6_RE = re.compile(
        r'(?<![:.\w])'
        r'(?:'
        r'(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}'
        r'|(?:[A-Fa-f0-9]{1,4}:){1,7}:'
        r'|(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}'
        r'|(?:[A-Fa-f0-9]{1,4}:){1,5}(?::[A-Fa-f0-9]{1,4}){1,2}'
        r'|(?:[A-Fa-f0-9]{1,4}:){1,4}(?::[A-Fa-f0-9]{1,4}){1,3}'
        r'|(?:[A-Fa-f0-9]{1,4}:){1,3}(?::[A-Fa-f0-9]{1,4}){1,4}'
        r'|(?:[A-Fa-f0-9]{1,4}:){1,2}(?::[A-Fa-f0-9]{1,4}){1,5}'
        r'|[A-Fa-f0-9]{1,4}:(?::[A-Fa-f0-9]{1,4}){1,6}'
        r'|::(?:[A-Fa-f0-9]{1,4}:){0,6}[A-Fa-f0-9]{1,4}'
        r')'
        r'(?![:.\w])'
    )
    _reference_mtime: Optional[datetime] = None

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        filename = os.path.basename(file_path).lower()
        normalized = file_path.replace('\\', '/').lower()
        return os.path.isfile(file_path) and (
            bool(self.ROTATED_RE.match(filename))
            or '/var/log/auth' in normalized
        )

    def _open_text(self, file_path: str):
        """Open a log, transparently decompressing rotated archives."""
        lowered = file_path.lower()
        if lowered.endswith('.gz'):
            return gzip.open(file_path, 'rt', encoding='utf-8', errors='replace')
        if lowered.endswith('.bz2'):
            return bz2.open(file_path, 'rt', encoding='utf-8', errors='replace')
        if lowered.endswith('.xz'):
            return lzma.open(file_path, 'rt', encoding='utf-8', errors='replace')
        return open(file_path, 'r', encoding='utf-8', errors='replace')

    def _reference_time(self, file_path: str) -> datetime:
        """Return the log's own mtime, used to date year-less syslog lines."""
        if self._reference_mtime is None:
            try:
                self._reference_mtime = datetime.fromtimestamp(
                    os.path.getmtime(file_path), timezone.utc
                ).replace(tzinfo=None)
            except OSError:
                self._reference_mtime = datetime.utcnow()
        return self._reference_mtime

    def _syslog_timestamp(self, raw: str, file_path: str) -> Optional[datetime]:
        """Resolve a BSD syslog timestamp, which carries no year.

        The year comes from the log's own mtime rather than today's date, so a
        December log ingested in January is not dated a year into the future.
        """
        try:
            parsed = datetime.strptime(' '.join(raw.split()), '%b %d %H:%M:%S')
        except ValueError:
            return None

        reference = self._reference_time(file_path)
        for year in (reference.year, reference.year - 1):
            try:
                candidate = parsed.replace(year=year)
            except ValueError:
                # Feb 29 against a non-leap year
                continue
            # A log line cannot postdate the file holding it by more than the
            # slack between local time and the UTC mtime.
            if candidate <= reference + timedelta(days=1):
                return candidate
        return None

    def _event_id(self, msg: str) -> str:
        lowered = msg.lower()
        if 'failed password' in lowered:
            return 'ssh_failed_password'
        if 'accepted password' in lowered or 'accepted publickey' in lowered:
            return 'ssh_accepted'
        if 'sudo:' in lowered:
            return 'sudo'
        if 'cron' in lowered:
            return 'cron'
        return 'linux_syslog'

    def _extract_address(self, message: str) -> str:
        """Return the remote address, preferring the one named by 'from'."""
        anchored = re.search(r'\bfrom\s+(?P<host>\S+)', message, re.IGNORECASE)
        if anchored:
            candidate = anchored.group('host').strip('.,;')
            if self.IPV4_RE.fullmatch(candidate) or self.IPV6_RE.fullmatch(candidate):
                return candidate
        match = self.IPV4_RE.search(message) or self.IPV6_RE.search(message)
        return match.group(0) if match else ''

    def _extract_username(self, message: str) -> str:
        for pattern in (self.SSH_USER_RE, self.INVALID_USER_RE, self.SUDO_USER_RE):
            match = pattern.search(message)
            if match:
                user = match.group('user').strip('.,;:')
                # 'for <ip> from' would otherwise capture an address as a user
                if user and not self.IPV4_RE.fullmatch(user):
                    return user
        return ''

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        self._reference_mtime = None
        with self._open_text(file_path) as handle:
            for line_num, line in enumerate(handle, 1):
                line = line.strip()
                if not line:
                    continue
                payload: Dict[str, str] = {'line_number': str(line_num), 'message': line}
                match = self.SYSLOG_RE.match(line)
                if match:
                    payload.update(match.groupdict(default=''))
                    line_timestamp = self._syslog_timestamp(payload.get('ts', ''), file_path)
                else:
                    match = self.RFC5424_RE.match(line)
                    if match:
                        payload.update(match.groupdict(default=''))
                        line_timestamp = self.parse_timestamp(payload.get('ts', ''))
                    else:
                        line_timestamp = None
                msg = payload.get('msg') or line
                remote_host = self._extract_address(msg)
                src_ip, src_ip_raw = self.normalize_ip_for_storage(remote_host)
                username = self._extract_username(msg)
                port_match = self.PORT_RE.search(msg)
                src_port = self.safe_uint16(port_match.group('port')) if port_match else None

                extra = {'program': payload.get('program', '')}
                if src_ip_raw:
                    extra['src_ip_raw'] = src_ip_raw
                if username:
                    payload['username'] = username
                if remote_host:
                    payload['remote_host'] = remote_host
                if src_port is not None:
                    payload['src_port'] = str(src_port)

                command_line = ''
                sudo_command = self.SUDO_COMMAND_RE.search(msg)
                if sudo_command:
                    command_line = sudo_command.group('command').strip()
                    payload['command'] = command_line
                sudo_target = self.SUDO_TARGET_RE.search(msg)
                if sudo_target:
                    extra['target_user'] = sudo_target.group('user')

                yield ParsedEvent(
                    case_id=self.case_id,
                    artifact_type=self.artifact_type,
                    timestamp=self.first_timestamp(line_timestamp, file_path=file_path, reason='Linux syslog line missing timestamp'),
                    timestamp_source_tz=self.get_source_tz(),
                    source_file=os.path.basename(file_path),
                    source_path=file_path,
                    source_host=payload.get('host') or self.extract_hostname(file_path),
                    case_file_id=self.case_file_id,
                    provider=payload.get('program', ''),
                    event_id=self._event_id(msg),
                    username=username,
                    src_ip=src_ip,
                    src_port=src_port,
                    command_line=command_line,
                    remote_host=remote_host,
                    raw_json=json.dumps(payload, default=str),
                    search_blob=self.build_search_blob(payload),
                    extra_fields=json.dumps(extra, default=str),
                    parser_version=self.parser_version,
                )


class LinuxUtmpParser(BaseParser):
    VERSION = '1.1.0'
    ARTIFACT_TYPE = 'linux_utmp'
    RECORD_SIZE = 384
    # lastlog is a different structure: int32 time, char line[32], char host[256],
    # indexed by UID. Reading it with the utmp stride misaligned every record.
    LASTLOG_RECORD_SIZE = 292

    UT_TYPES = {
        0: 'EMPTY', 1: 'RUN_LVL', 2: 'BOOT_TIME', 3: 'NEW_TIME', 4: 'OLD_TIME',
        5: 'INIT_PROCESS', 6: 'LOGIN_PROCESS', 7: 'USER_PROCESS',
        8: 'DEAD_PROCESS', 9: 'ACCOUNTING',
    }

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        return os.path.isfile(file_path) and os.path.basename(file_path).lower() in {'utmp', 'wtmp', 'btmp', 'lastlog'}

    @staticmethod
    def _decode_addr_v6(raw: bytes) -> str:
        """Render ut_addr_v6, which holds an IPv4 address in its first word."""
        import ipaddress
        if len(raw) < 16 or not any(raw):
            return ''
        try:
            if not any(raw[4:]):
                return str(ipaddress.IPv4Address(raw[:4]))
            return str(ipaddress.IPv6Address(raw))
        except ValueError:
            return ''

    def _parse_lastlog(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        """lastlog is a flat array indexed by UID with no username field."""
        size = self.LASTLOG_RECORD_SIZE
        with open(file_path, 'rb') as handle:
            uid = -1
            while True:
                record = handle.read(size)
                if len(record) < size:
                    break
                uid += 1
                try:
                    ll_time = struct.unpack_from('<i', record, 0)[0]
                    line = record[4:36].split(b'\x00', 1)[0].decode('utf-8', errors='replace')
                    host = record[36:292].split(b'\x00', 1)[0].decode('utf-8', errors='replace')
                except Exception:
                    continue
                # Every UID has a slot; only the used ones carry a time
                if ll_time <= 0:
                    continue

                payload = {'uid': uid, 'line': line, 'host': host,
                           'last_login': str(datetime.fromtimestamp(ll_time, timezone.utc))}
                src_ip, src_ip_raw = self.normalize_ip_for_storage(host)
                extra = {'uid': uid}
                if src_ip_raw:
                    extra['src_ip_raw'] = src_ip_raw
                yield ParsedEvent(
                    case_id=self.case_id,
                    artifact_type=self.artifact_type,
                    timestamp=datetime.fromtimestamp(ll_time, timezone.utc).replace(tzinfo=None),
                    source_file=os.path.basename(file_path),
                    source_path=file_path,
                    source_host=self.extract_hostname(file_path),
                    case_file_id=self.case_file_id,
                    remote_host=host,
                    src_ip=src_ip,
                    event_id='linux_last_login',
                    raw_json=json.dumps(payload, default=str),
                    search_blob=self.build_search_blob(payload),
                    extra_fields=json.dumps(extra, default=str),
                    parser_version=self.parser_version,
                )

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        if os.path.basename(file_path).lower() == 'lastlog':
            yield from self._parse_lastlog(file_path)
            return

        with open(file_path, 'rb') as handle:
            index = 0
            while True:
                record = handle.read(self.RECORD_SIZE)
                if len(record) < self.RECORD_SIZE:
                    break
                index += 1
                try:
                    ut_type = struct.unpack_from('<h', record, 0)[0]
                    ut_pid = struct.unpack_from('<i', record, 4)[0]
                    user = record[44:76].split(b'\x00', 1)[0].decode('utf-8', errors='replace')
                    line = record[8:40].split(b'\x00', 1)[0].decode('utf-8', errors='replace')
                    ut_id = record[40:44].split(b'\x00', 1)[0].decode('utf-8', errors='replace')
                    host = record[76:332].split(b'\x00', 1)[0].decode('utf-8', errors='replace')
                    ut_session = struct.unpack_from('<i', record, 336)[0]
                    tv_sec = struct.unpack_from('<i', record, 340)[0]
                    tv_usec = struct.unpack_from('<i', record, 344)[0]
                    addr_v6 = self._decode_addr_v6(record[348:364])
                    timestamp = (
                        datetime.fromtimestamp(tv_sec, timezone.utc).replace(
                            tzinfo=None, microsecond=min(max(tv_usec, 0), 999999)
                        )
                        if tv_sec > 0
                        else self.fallback_timestamp(file_path=file_path, reason='utmp record missing timestamp')
                    )
                except Exception:
                    continue
                if not any((user, line, host, addr_v6)):
                    continue

                type_name = self.UT_TYPES.get(ut_type, str(ut_type))
                payload = {
                    'record_number': index,
                    'user': user,
                    'line': line,
                    'host': host,
                    'ut_type': ut_type,
                    'ut_type_name': type_name,
                    'ut_pid': ut_pid,
                    'ut_id': ut_id,
                    'ut_session': ut_session,
                }
                if addr_v6:
                    payload['ut_addr'] = addr_v6

                # ut_addr_v6 is the numeric source and survives a truncated
                # ut_host, so it is the better address when both are present
                src_ip, src_ip_raw = self.normalize_ip_for_storage(addr_v6 or host)
                extra = {'ut_type_name': type_name, 'ut_pid': ut_pid, 'ut_session': ut_session}
                if src_ip_raw:
                    extra['src_ip_raw'] = src_ip_raw
                yield ParsedEvent(
                    case_id=self.case_id,
                    artifact_type=self.artifact_type,
                    timestamp=timestamp,
                    source_file=os.path.basename(file_path),
                    source_path=file_path,
                    source_host=self.extract_hostname(file_path),
                    case_file_id=self.case_file_id,
                    username=user,
                    remote_host=host or addr_v6,
                    src_ip=src_ip,
                    process_id=self.safe_uint64(ut_pid) if ut_pid > 0 else None,
                    event_id='linux_logon_record',
                    raw_json=json.dumps(payload, default=str),
                    search_blob=self.build_search_blob(payload),
                    extra_fields=json.dumps(extra, default=str),
                    parser_version=self.parser_version,
                )


class LinuxJournalParser(BaseParser):
    VERSION = '1.1.0'
    ARTIFACT_TYPE = 'linux_journal'
    JOURNALCTL = '/usr/bin/journalctl'
    # journalctl reads a foreign journal file directly, which is the only
    # practical decoder for the binary format
    TIMEOUT_SECONDS = 1800

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        return os.path.isfile(file_path) and file_path.lower().endswith('.journal')

    def _iter_journal_records(self, file_path: str) -> Generator[Dict, None, None]:
        process = subprocess.Popen(
            [self.JOURNALCTL, '--file', file_path, '--output', 'json', '--no-pager'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors='replace',
        )
        try:
            for line in process.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if isinstance(record, dict):
                    yield record
        finally:
            process.stdout.close()
            stderr = process.stderr.read()
            process.stderr.close()
            if process.wait() != 0 and stderr.strip():
                self.warnings.append(f"journalctl reported: {stderr.strip()[:300]}")

    @staticmethod
    def _journal_timestamp(record: Dict) -> Optional[datetime]:
        # __REALTIME_TIMESTAMP is microseconds since the Unix epoch
        raw = record.get('__REALTIME_TIMESTAMP')
        try:
            return datetime.fromtimestamp(int(raw) / 1_000_000, timezone.utc).replace(tzinfo=None)
        except (TypeError, ValueError, OSError, OverflowError):
            return None

    @staticmethod
    def _journal_text(value) -> str:
        # A field can arrive as a list of byte values when it is not valid UTF-8
        if isinstance(value, list):
            try:
                return bytes(int(item) for item in value).decode('utf-8', errors='replace')
            except (TypeError, ValueError):
                return ''
        return '' if value is None else str(value)

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        if not os.path.exists(self.JOURNALCTL):
            self.warnings.append(
                f"journalctl is not installed, so {os.path.basename(file_path)} was recorded as present only"
            )
            yield self._presence_event(file_path)
            return

        emitted = 0
        try:
            for record in self._iter_journal_records(file_path):
                message = self._journal_text(record.get('MESSAGE'))
                unit = self._journal_text(record.get('_SYSTEMD_UNIT') or record.get('UNIT'))
                identifier = self._journal_text(
                    record.get('SYSLOG_IDENTIFIER') or record.get('_COMM')
                )
                payload = {
                    key: self._journal_text(value)
                    for key, value in record.items()
                    if not key.startswith('__')
                }
                yield ParsedEvent(
                    case_id=self.case_id,
                    artifact_type=self.artifact_type,
                    timestamp=self.first_timestamp(
                        self._journal_timestamp(record),
                        file_path=file_path,
                        reason='journal record missing realtime timestamp',
                    ),
                    source_file=os.path.basename(file_path),
                    source_path=file_path,
                    source_host=self._journal_text(record.get('_HOSTNAME')) or self.extract_hostname(file_path),
                    case_file_id=self.case_file_id,
                    provider=identifier or unit,
                    event_id='linux_journal_entry',
                    process_id=self.safe_uint64(record.get('_PID')),
                    process_name=identifier,
                    command_line=self._journal_text(record.get('_CMDLINE')),
                    raw_json=json.dumps(payload, default=str),
                    search_blob=self.build_search_blob(payload),
                    extra_fields=json.dumps({
                        'unit': unit,
                        'identifier': identifier,
                        'uid': self._journal_text(record.get('_UID')),
                        'message': message,
                    }, default=str),
                    parser_version=self.parser_version,
                )
                emitted += 1
        except (OSError, subprocess.SubprocessError) as exc:
            self.warnings.append(f"journalctl could not read {os.path.basename(file_path)}: {exc}")

        if emitted == 0:
            # Falling back keeps the file visible in the case rather than
            # reporting a successful parse of nothing
            yield self._presence_event(file_path)

    def _presence_event(self, file_path: str) -> ParsedEvent:
        payload = {
            'path': file_path,
            'file_size': os.path.getsize(file_path),
            'note': 'journald binary collected but no records could be decoded',
        }
        return ParsedEvent(
            case_id=self.case_id,
            artifact_type=self.artifact_type,
            timestamp=self.fallback_timestamp(file_path=file_path, reason='journald binary uses file mtime'),
            source_file=os.path.basename(file_path),
            source_path=file_path,
            source_host=self.extract_hostname(file_path),
            case_file_id=self.case_file_id,
            event_id='linux_journal_present',
            raw_json=json.dumps(payload, default=str),
            search_blob=self.build_search_blob(payload),
            parser_version=self.parser_version,
        )


class LinuxCronParser(BaseParser):
    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'linux_cron'

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        normalized = file_path.replace('\\', '/').lower()
        return os.path.isfile(file_path) and ('/cron.' in normalized or '/cron/' in normalized or '/spool/cron/' in normalized or os.path.basename(normalized) == 'crontab')

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as handle:
            for line_num, line in enumerate(handle, 1):
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    continue
                payload = {'line_number': line_num, 'entry': stripped}
                yield ParsedEvent(
                    case_id=self.case_id,
                    artifact_type=self.artifact_type,
                    timestamp=self.fallback_timestamp(file_path=file_path, reason='cron entry uses file mtime'),
                    timestamp_source_tz=self.get_source_tz(),
                    source_file=os.path.basename(file_path),
                    source_path=file_path,
                    source_host=self.extract_hostname(file_path),
                    case_file_id=self.case_file_id,
                    event_id='cron_persistence',
                    command_line=stripped,
                    raw_json=json.dumps(payload, default=str),
                    search_blob=self.build_search_blob(payload),
                    parser_version=self.parser_version,
                )


class LinuxSshArtifactParser(LinuxCronParser):
    ARTIFACT_TYPE = 'linux_ssh'

    def can_parse(self, file_path: str) -> bool:
        filename = os.path.basename(file_path).lower()
        normalized = file_path.replace('\\', '/').lower()
        return os.path.isfile(file_path) and ('/.ssh/' in normalized or filename in {'sshd_config', 'ssh_config', 'authorized_keys', 'known_hosts'})

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        for line_num, line in enumerate(open(file_path, 'r', encoding='utf-8', errors='replace'), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            payload = {'line_number': line_num, 'entry': stripped, 'file': os.path.basename(file_path)}
            yield ParsedEvent(
                case_id=self.case_id,
                artifact_type=self.artifact_type,
                timestamp=self.fallback_timestamp(file_path=file_path, reason='SSH artifact entry uses file mtime'),
                source_file=os.path.basename(file_path),
                source_path=file_path,
                source_host=self.extract_hostname(file_path),
                case_file_id=self.case_file_id,
                event_id='ssh_artifact',
                raw_json=json.dumps(payload, default=str),
                search_blob=self.build_search_blob(payload),
                parser_version=self.parser_version,
            )


class LinuxShellHistoryParser(LinuxCronParser):
    VERSION = '1.1.0'
    ARTIFACT_TYPE = 'linux_shell_history'
    # zsh extended history: ": <epoch>:<elapsed>;<command>"
    EXT_TS_RE = re.compile(r'^:\s*(?P<epoch>\d{9,11})')
    # bash with HISTTIMEFORMAT set writes the epoch as a comment line of its own
    # before each command. Unhandled, every one of those timestamps was lost and
    # the comment line was stored as if it were a command.
    BASH_TS_RE = re.compile(r'^#(?P<epoch>\d{9,11})\s*$')

    @staticmethod
    def _epoch_to_datetime(epoch: str) -> Optional[datetime]:
        try:
            return datetime.fromtimestamp(int(epoch), timezone.utc).replace(tzinfo=None)
        except (ValueError, OSError, OverflowError):
            return None

    def can_parse(self, file_path: str) -> bool:
        filename = os.path.basename(file_path).lower()
        return os.path.isfile(file_path) and filename in {'.bash_history', '.zsh_history', '.sh_history', 'bash_history', 'zsh_history'}

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        pending_ts = None
        with open(file_path, 'r', encoding='utf-8', errors='replace') as handle:
            for line_num, line in enumerate(handle, 1):
                stripped = line.rstrip('\n')
                if not stripped:
                    continue

                bash_match = self.BASH_TS_RE.match(stripped)
                if bash_match:
                    pending_ts = self._epoch_to_datetime(bash_match.group('epoch'))
                    continue

                match = self.EXT_TS_RE.match(stripped)
                if match:
                    pending_ts = self._epoch_to_datetime(match.group('epoch'))
                    command = stripped.split(';', 1)[1] if ';' in stripped else ''
                else:
                    command = stripped
                if not command:
                    continue
                payload = {'line_number': line_num, 'command': command}
                yield ParsedEvent(
                    case_id=self.case_id,
                    artifact_type=self.artifact_type,
                    timestamp=self.first_timestamp(pending_ts, file_path=file_path, reason='shell history entry missing timestamp'),
                    timestamp_source_tz='UTC' if pending_ts else self.get_source_tz(),
                    source_file=os.path.basename(file_path),
                    source_path=file_path,
                    source_host=self.extract_hostname(file_path),
                    case_file_id=self.case_file_id,
                    event_id='shell_history_command',
                    command_line=command,
                    raw_json=json.dumps(payload, default=str),
                    search_blob=self.build_search_blob(payload),
                    parser_version=self.parser_version,
                )
                pending_ts = None
