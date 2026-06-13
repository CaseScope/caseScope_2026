"""Remote monitoring and management application log parsers."""
import json
import os
import re
from datetime import datetime
from typing import Dict, Generator, Optional

from parsers.base import BaseParser, ParsedEvent


class _RmmTextParser(BaseParser):
    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'rmm_log'
    VENDOR = 'RMM'
    FILENAME_PATTERNS = ()

    TIMESTAMP_PATTERNS = (
        re.compile(r'(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)'),
        re.compile(r'(?P<ts>\d{2}/\d{2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s*(?:AM|PM)?)', re.I),
        re.compile(r'(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'),
    )
    IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        if not os.path.isfile(file_path):
            return False
        normalized = file_path.replace('\\', '/').lower()
        filename = os.path.basename(normalized)
        return any(pattern in normalized or pattern in filename for pattern in self.FILENAME_PATTERNS)

    def _timestamp_for_line(self, line: str, file_path: str) -> datetime:
        for pattern in self.TIMESTAMP_PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            parsed = self.parse_timestamp(match.group('ts'))
            if parsed:
                return parsed
        return self.fallback_timestamp(file_path=file_path, reason=f'{self.VENDOR} log line missing timestamp')

    def _classify_action(self, line: str) -> str:
        lowered = line.lower()
        for keyword in ('connect', 'disconnect', 'login', 'logout', 'session', 'file transfer', 'command', 'error'):
            if keyword in lowered:
                return keyword.replace(' ', '_')
        return 'log'

    def _row_for_line(self, line: str) -> Dict[str, str]:
        ips = self.IP_RE.findall(line)
        return {
            'vendor': self.VENDOR,
            'action': self._classify_action(line),
            'message': line,
            'ip_addresses': ips,
        }

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
                row = self._row_for_line(line)
                row['line_number'] = str(line_num)
                first_ip = row['ip_addresses'][0] if row['ip_addresses'] else ''
                src_ip, src_ip_raw = self.normalize_ip_for_storage(first_ip)
                extra = {'vendor': self.VENDOR, 'action': row['action']}
                if src_ip_raw:
                    extra['src_ip_raw'] = src_ip_raw
                yield ParsedEvent(
                    case_id=self.case_id,
                    artifact_type=self.artifact_type,
                    timestamp=self._timestamp_for_line(line, file_path),
                    timestamp_source_tz=self.get_source_tz(),
                    source_file=source_file,
                    source_path=file_path,
                    source_host=hostname,
                    case_file_id=self.case_file_id,
                    provider=self.VENDOR,
                    event_id=f'{self.VENDOR.lower()}_{row["action"]}',
                    src_ip=src_ip,
                    remote_host=first_ip,
                    raw_json=json.dumps(row, default=str),
                    search_blob=self.build_search_blob(row),
                    extra_fields=json.dumps(extra, default=str),
                    parser_version=self.parser_version,
                )


class AnyDeskTraceParser(_RmmTextParser):
    ARTIFACT_TYPE = 'rmm_anydesk'
    VENDOR = 'AnyDesk'
    FILENAME_PATTERNS = ('anydesk', 'ad.trace', 'ad_svc.trace', 'connection_trace.txt')


class TeamViewerLogParser(_RmmTextParser):
    ARTIFACT_TYPE = 'rmm_teamviewer'
    VENDOR = 'TeamViewer'
    FILENAME_PATTERNS = ('teamviewer', 'connections_incoming.txt', 'teamviewer_logfile')


class ScreenConnectLogParser(_RmmTextParser):
    ARTIFACT_TYPE = 'rmm_screenconnect'
    VENDOR = 'ScreenConnect'
    FILENAME_PATTERNS = ('screenconnect', 'connectwise control', 'connectwisecontrol')
