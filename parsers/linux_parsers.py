"""Linux and Unix artifact parsers."""
import bz2
import gzip
import json
import lzma
import os
import re
import struct
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
                ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', msg)
                src_ip, src_ip_raw = self.normalize_ip_for_storage(ips[0] if ips else '')
                extra = {'program': payload.get('program', '')}
                if src_ip_raw:
                    extra['src_ip_raw'] = src_ip_raw
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
                    src_ip=src_ip,
                    remote_host=ips[0] if ips else '',
                    raw_json=json.dumps(payload, default=str),
                    search_blob=self.build_search_blob(payload),
                    extra_fields=json.dumps(extra, default=str),
                    parser_version=self.parser_version,
                )


class LinuxUtmpParser(BaseParser):
    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'linux_utmp'
    RECORD_SIZE = 384

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        return os.path.isfile(file_path) and os.path.basename(file_path).lower() in {'utmp', 'wtmp', 'btmp', 'lastlog'}

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        with open(file_path, 'rb') as handle:
            index = 0
            while True:
                record = handle.read(self.RECORD_SIZE)
                if len(record) < self.RECORD_SIZE:
                    break
                index += 1
                try:
                    user = record[44:76].split(b'\x00', 1)[0].decode('utf-8', errors='replace')
                    line = record[8:40].split(b'\x00', 1)[0].decode('utf-8', errors='replace')
                    host = record[76:332].split(b'\x00', 1)[0].decode('utf-8', errors='replace')
                    tv_sec = struct.unpack_from('<i', record, 340)[0]
                    timestamp = datetime.fromtimestamp(tv_sec, timezone.utc).replace(tzinfo=None) if tv_sec > 0 else self.fallback_timestamp(file_path=file_path, reason='utmp record missing timestamp')
                except Exception:
                    continue
                if not any((user, line, host)):
                    continue
                payload = {'record_number': index, 'user': user, 'line': line, 'host': host}
                src_ip, src_ip_raw = self.normalize_ip_for_storage(host)
                extra = {'src_ip_raw': src_ip_raw} if src_ip_raw else {}
                yield ParsedEvent(
                    case_id=self.case_id,
                    artifact_type=self.artifact_type,
                    timestamp=timestamp,
                    source_file=os.path.basename(file_path),
                    source_path=file_path,
                    source_host=self.extract_hostname(file_path),
                    case_file_id=self.case_file_id,
                    username=user,
                    remote_host=host,
                    src_ip=src_ip,
                    event_id='linux_logon_record',
                    raw_json=json.dumps(payload, default=str),
                    search_blob=self.build_search_blob(payload),
                    extra_fields=json.dumps(extra, default=str),
                    parser_version=self.parser_version,
                )


class LinuxJournalParser(BaseParser):
    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'linux_journal'

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        return os.path.isfile(file_path) and file_path.lower().endswith('.journal')

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        payload = {'path': file_path, 'file_size': os.path.getsize(file_path), 'note': 'journald binary collected; full journal export parsing should use systemd journal export format'}
        yield ParsedEvent(
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
    ARTIFACT_TYPE = 'linux_shell_history'
    EXT_TS_RE = re.compile(r'^:\s*(?P<epoch>\d{10})')

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
                match = self.EXT_TS_RE.match(stripped)
                if match:
                    pending_ts = datetime.fromtimestamp(int(match.group('epoch')), timezone.utc).replace(tzinfo=None)
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
