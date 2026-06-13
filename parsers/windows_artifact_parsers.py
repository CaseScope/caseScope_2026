"""Additional Windows artifact parsers for KAPE/CyLR coverage gaps."""
import gzip
import json
import os
import re
import sqlite3
import struct
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from typing import Any, Dict, Generator, Iterable, List, Optional

from parsers.base import BaseParser, ParsedEvent


def _read_text(file_path: str, limit: int = 2 * 1024 * 1024) -> str:
    with open(file_path, 'rb') as handle:
        data = handle.read(limit)
    if data.startswith(b'\xff\xfe') or data[1:2] == b'\x00':
        return data.decode('utf-16-le', errors='replace')
    return data.decode('utf-8', errors='replace')


def _strings(data: bytes, limit: int = 200) -> List[str]:
    values = [s.decode('utf-8', errors='replace') for s in re.findall(rb'[\x20-\x7e]{4,}', data)]
    values.extend(s.decode('utf-16-le', errors='replace').rstrip('\x00') for s in re.findall(rb'(?:[\x20-\x7e]\x00){4,}', data))
    seen = []
    for value in values:
        cleaned = ' '.join(value.split())
        if cleaned and cleaned not in seen:
            seen.append(cleaned)
        if len(seen) >= limit:
            break
    return seen


class _SingleEventFileParser(BaseParser):
    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'windows_artifact'
    EVENT_ID = 'windows_artifact'

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        return os.path.isfile(file_path)

    def _payload(self, file_path: str) -> Dict[str, Any]:
        return {'path': file_path}

    def _timestamp(self, payload: Dict[str, Any], file_path: str) -> datetime:
        for key in ('timestamp', 'last_modified', 'created', 'last_run', 'start_time', 'end_time'):
            if payload.get(key):
                parsed = self.parse_timestamp(payload.get(key))
                if parsed:
                    return parsed
        return self.fallback_timestamp(file_path=file_path, reason=f'{self.artifact_type} uses file mtime')

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        if not self.can_parse(file_path):
            self.errors.append(f'Cannot parse file: {file_path}')
            return
        payload = self._payload(file_path)
        source_file = os.path.basename(file_path)
        yield ParsedEvent(
            case_id=self.case_id,
            artifact_type=self.artifact_type,
            timestamp=self._timestamp(payload, file_path),
            timestamp_source_tz=self.get_source_tz(),
            source_file=source_file,
            source_path=file_path,
            source_host=self.extract_hostname(file_path),
            case_file_id=self.case_file_id,
            event_id=self.EVENT_ID,
            target_path=payload.get('target_path', '') or payload.get('path', '') or file_path,
            process_name=payload.get('process_name', ''),
            process_path=payload.get('process_path', ''),
            command_line=payload.get('command_line', ''),
            username=payload.get('username', ''),
            raw_json=json.dumps(payload, default=str),
            search_blob=self.build_search_blob(payload),
            extra_fields=json.dumps({'parser_family': 'windows_gap'}, default=str),
            parser_version=self.parser_version,
        )


class PcaParser(BaseParser):
    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'pca_execution'

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        name = os.path.basename(file_path).lower()
        normalized = file_path.replace('\\', '/').lower()
        return os.path.isfile(file_path) and '/appcompat/pca/' in normalized and name.startswith('pca')

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        text = _read_text(file_path)
        for line_num, line in enumerate(text.splitlines(), 1):
            line = line.strip('\ufeff ')
            if not line:
                continue
            parts = [part.strip() for part in line.split('|')]
            path = next((part for part in parts if '\\' in part or '/' in part or part.lower().endswith('.exe')), parts[0])
            timestamp = next((self.parse_timestamp(part) for part in parts if self.parse_timestamp(part)), None)
            payload = {'line_number': line_num, 'parts': parts, 'path': path, 'raw_line': line}
            yield ParsedEvent(
                case_id=self.case_id,
                artifact_type=self.artifact_type,
                timestamp=self.first_timestamp(timestamp, file_path=file_path, reason='PCA record missing timestamp'),
                source_file=os.path.basename(file_path),
                source_path=file_path,
                source_host=self.extract_hostname(file_path),
                case_file_id=self.case_file_id,
                event_id='pca_execution',
                process_path=path,
                process_name=os.path.basename(path.replace('\\', '/')),
                target_path=path,
                raw_json=json.dumps(payload, default=str),
                search_blob=self.build_search_blob(payload),
                parser_version=self.parser_version,
            )


class NotepadTabStateParser(_SingleEventFileParser):
    ARTIFACT_TYPE = 'notepad_tabstate'
    EVENT_ID = 'notepad_tabstate'

    def can_parse(self, file_path: str) -> bool:
        normalized = file_path.replace('\\', '/').lower()
        return os.path.isfile(file_path) and '/tabstate/' in normalized and file_path.lower().endswith('.bin')

    def _payload(self, file_path: str) -> Dict[str, Any]:
        with open(file_path, 'rb') as handle:
            data = handle.read(1024 * 1024)
        values = _strings(data, limit=100)
        return {'path': file_path, 'recovered_text': '\n'.join(values), 'strings': values, 'byte_length': len(data)}


class PowerShellTranscriptParser(BaseParser):
    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'powershell_transcript'

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        filename = os.path.basename(file_path).lower()
        return os.path.isfile(file_path) and filename.startswith('powershell_transcript') and filename.endswith('.txt')

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        text = _read_text(file_path)
        command = ''
        for line_num, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.lower().startswith(('ps>', 'command start time', 'start time')):
                command = stripped
            payload = {'line_number': line_num, 'message': stripped, 'command': command}
            yield ParsedEvent(
                case_id=self.case_id,
                artifact_type=self.artifact_type,
                timestamp=self.fallback_timestamp(file_path=file_path, reason='PowerShell transcript line uses file mtime'),
                timestamp_source_tz=self.get_source_tz(),
                source_file=os.path.basename(file_path),
                source_path=file_path,
                source_host=self.extract_hostname(file_path),
                case_file_id=self.case_file_id,
                event_id='powershell_transcript_line',
                command_line=command or stripped,
                raw_json=json.dumps(payload, default=str),
                search_blob=self.build_search_blob(payload),
                parser_version=self.parser_version,
            )


class _SQLiteSummaryParser(BaseParser):
    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'sqlite_artifact'
    FILE_NAMES = ()
    TABLE_HINTS = ()

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        return os.path.isfile(file_path) and os.path.basename(file_path).lower() in self.FILE_NAMES

    def _iter_rows(self, file_path: str) -> Iterable[Dict[str, Any]]:
        conn = sqlite3.connect(f'file:{file_path}?mode=ro', uri=True)
        conn.row_factory = sqlite3.Row
        try:
            tables = [
                row['name'] for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                )
            ]
            for table in tables:
                if self.TABLE_HINTS and not any(hint.lower() in table.lower() for hint in self.TABLE_HINTS):
                    continue
                try:
                    for row in conn.execute(f'SELECT * FROM "{table}" LIMIT 5000'):
                        payload = {key: row[key] for key in row.keys()}
                        payload['table'] = table
                        yield payload
                except Exception:
                    continue
        finally:
            conn.close()

    def _timestamp(self, row: Dict[str, Any], file_path: str) -> datetime:
        for key, value in row.items():
            if 'time' not in key.lower() and 'date' not in key.lower():
                continue
            parsed = self.parse_timestamp(value)
            if parsed:
                return parsed
        return self.fallback_timestamp(file_path=file_path, reason=f'{self.artifact_type} row missing timestamp')

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        for row in self._iter_rows(file_path):
            yield ParsedEvent(
                case_id=self.case_id,
                artifact_type=self.artifact_type,
                timestamp=self._timestamp(row, file_path),
                source_file=os.path.basename(file_path),
                source_path=file_path,
                source_host=self.extract_hostname(file_path),
                case_file_id=self.case_file_id,
                event_id=f'{self.artifact_type}_row',
                raw_json=json.dumps(row, default=str),
                search_blob=self.build_search_blob(row),
                extra_fields=json.dumps({'table': row.get('table', '')}, default=str),
                parser_version=self.parser_version,
            )


class WindowsNotificationsParser(_SQLiteSummaryParser):
    ARTIFACT_TYPE = 'windows_notifications'
    FILE_NAMES = ('wpndatabase.db',)


class EventTranscriptDbParser(_SQLiteSummaryParser):
    ARTIFACT_TYPE = 'eventtranscript'
    FILE_NAMES = ('eventtranscript.db',)


class CopilotRecallParser(_SQLiteSummaryParser):
    ARTIFACT_TYPE = 'copilot_recall'
    FILE_NAMES = ('ukg.db', 'recall.db', 'snapshot.db')

    def can_parse(self, file_path: str) -> bool:
        normalized = file_path.replace('\\', '/').lower()
        return os.path.isfile(file_path) and ('recall' in normalized or '/coreai/' in normalized) and file_path.lower().endswith(('.db', '.sqlite'))


class BitsParser(_SingleEventFileParser):
    ARTIFACT_TYPE = 'bits_queue'
    EVENT_ID = 'bits_queue'

    def can_parse(self, file_path: str) -> bool:
        filename = os.path.basename(file_path).lower()
        return os.path.isfile(file_path) and filename in {'qmgr.db', 'qmgr0.dat', 'qmgr1.dat'}

    def _payload(self, file_path: str) -> Dict[str, Any]:
        try:
            if os.path.basename(file_path).lower().endswith('.db'):
                rows = []
                from dissect.esedb import EseDB
                with open(file_path, 'rb') as handle:
                    db = EseDB(handle)
                    for table in db.tables():
                        count = 0
                        for _record in table.records():
                            count += 1
                            if count >= 10000:
                                break
                        rows.append({'table': table.name, 'row_count': count})
                return {'path': file_path, 'tables': rows}
        except Exception as exc:
            return {'path': file_path, 'error': str(exc), 'strings': _strings(open(file_path, 'rb').read(512000))}
        with open(file_path, 'rb') as handle:
            return {'path': file_path, 'strings': _strings(handle.read(512000))}


class RecentFileCacheParser(_SingleEventFileParser):
    ARTIFACT_TYPE = 'recentfilecache'
    EVENT_ID = 'recentfilecache'

    def can_parse(self, file_path: str) -> bool:
        return os.path.basename(file_path).lower() == 'recentfilecache.bcf'

    def _payload(self, file_path: str) -> Dict[str, Any]:
        with open(file_path, 'rb') as handle:
            return {'path': file_path, 'recent_files': _strings(handle.read(), limit=500)}


class SchedLgUParser(_SingleEventFileParser):
    ARTIFACT_TYPE = 'schedlgu'
    EVENT_ID = 'legacy_scheduled_task_log'

    def can_parse(self, file_path: str) -> bool:
        return os.path.basename(file_path).lower() == 'schedlgu.txt'

    def _payload(self, file_path: str) -> Dict[str, Any]:
        return {'path': file_path, 'text': _read_text(file_path)}


class StartupInfoParser(_SingleEventFileParser):
    ARTIFACT_TYPE = 'startupinfo'
    EVENT_ID = 'startupinfo'

    def can_parse(self, file_path: str) -> bool:
        normalized = file_path.replace('\\', '/').lower()
        return os.path.isfile(file_path) and '/startupinfo/' in normalized and file_path.lower().endswith('.xml')

    def _payload(self, file_path: str) -> Dict[str, Any]:
        try:
            root = ET.parse(file_path).getroot()
            return {'path': file_path, 'xml_root': root.tag, 'text': ''.join(root.itertext())[:5000]}
        except Exception as exc:
            return {'path': file_path, 'error': str(exc), 'text': _read_text(file_path)}


class NetClrUsageLogParser(_SingleEventFileParser):
    ARTIFACT_TYPE = 'netclr_usage'
    EVENT_ID = 'netclr_usage'

    def can_parse(self, file_path: str) -> bool:
        normalized = file_path.replace('\\', '/').lower()
        return os.path.isfile(file_path) and '/usage logs/' in normalized and 'clr_v' in normalized

    def _payload(self, file_path: str) -> Dict[str, Any]:
        name = os.path.basename(file_path)
        return {'path': file_path, 'process_name': name.rsplit('.', 1)[0], 'text': _read_text(file_path)}


class ThumbcacheIconcacheParser(_SingleEventFileParser):
    ARTIFACT_TYPE = 'thumb_icon_cache'
    EVENT_ID = 'thumb_icon_cache'

    def can_parse(self, file_path: str) -> bool:
        filename = os.path.basename(file_path).lower()
        return os.path.isfile(file_path) and (filename.startswith(('thumbcache_', 'iconcache_')) and filename.endswith('.db'))

    def _payload(self, file_path: str) -> Dict[str, Any]:
        with open(file_path, 'rb') as handle:
            data = handle.read(1024 * 1024)
        return {'path': file_path, 'cache_type': os.path.basename(file_path).split('_', 1)[0], 'strings': _strings(data)}


class RdpBitmapCacheParser(_SingleEventFileParser):
    ARTIFACT_TYPE = 'rdp_bitmap_cache'
    EVENT_ID = 'rdp_bitmap_cache'

    def can_parse(self, file_path: str) -> bool:
        normalized = file_path.replace('\\', '/').lower()
        filename = os.path.basename(file_path).lower()
        return os.path.isfile(file_path) and 'terminal server client/cache' in normalized and filename.endswith('.bin')

    def _payload(self, file_path: str) -> Dict[str, Any]:
        return {'path': file_path, 'byte_length': os.path.getsize(file_path), 'note': 'RDP bitmap cache collected; image tile extraction pending viewer support'}


class RegistryPolParser(_SingleEventFileParser):
    ARTIFACT_TYPE = 'registry_pol'
    EVENT_ID = 'registry_pol'

    def can_parse(self, file_path: str) -> bool:
        return os.path.basename(file_path).lower() == 'registry.pol'

    def _payload(self, file_path: str) -> Dict[str, Any]:
        with open(file_path, 'rb') as handle:
            return {'path': file_path, 'strings': _strings(handle.read(), limit=500)}


class MofParser(_SingleEventFileParser):
    ARTIFACT_TYPE = 'mof_file'
    EVENT_ID = 'mof_file'

    def can_parse(self, file_path: str) -> bool:
        normalized = file_path.replace('\\', '/').lower()
        return os.path.isfile(file_path) and '/wbem/mof' in normalized and file_path.lower().endswith('.mof')

    def _payload(self, file_path: str) -> Dict[str, Any]:
        text = _read_text(file_path)
        suspicious = [term for term in ('CommandLineEventConsumer', 'ActiveScriptEventConsumer', 'powershell', 'cmd.exe') if term.lower() in text.lower()]
        return {'path': file_path, 'text': text[:20000], 'persistence_terms': suspicious}


class SdbParser(_SingleEventFileParser):
    ARTIFACT_TYPE = 'shim_database'
    EVENT_ID = 'shim_database'

    def can_parse(self, file_path: str) -> bool:
        return os.path.isfile(file_path) and file_path.lower().endswith('.sdb')

    def _payload(self, file_path: str) -> Dict[str, Any]:
        with open(file_path, 'rb') as handle:
            return {'path': file_path, 'strings': _strings(handle.read(1024 * 1024), limit=500)}


class SensitiveWindowsFileParser(_SingleEventFileParser):
    ARTIFACT_TYPE = 'sensitive_windows_file'
    EVENT_ID = 'sensitive_windows_file_present'
    FILENAMES = {'ntds.dit', 'hiberfil.sys', 'pagefile.sys', 'swapfile.sys'}

    def can_parse(self, file_path: str) -> bool:
        return os.path.isfile(file_path) and os.path.basename(file_path).lower() in self.FILENAMES

    def _payload(self, file_path: str) -> Dict[str, Any]:
        filename = os.path.basename(file_path).lower()
        risk = 'active_directory_secrets' if filename == 'ntds.dit' else 'memory_residue'
        return {'path': file_path, 'risk': risk, 'file_size': os.path.getsize(file_path)}


class WindowsServerLogParser(BaseParser):
    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'windows_server_log'

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        normalized = file_path.replace('\\', '/').lower()
        filename = os.path.basename(normalized)
        return os.path.isfile(file_path) and (
            '/exchange' in normalized
            or filename in {'dns.log'}
            or ('dhcp' in normalized and filename.endswith('.log'))
        )

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        for line_num, line in enumerate(_read_text(file_path).splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            payload = {'line_number': line_num, 'message': line, 'source_family': 'exchange_dns_dhcp'}
            yield ParsedEvent(
                case_id=self.case_id,
                artifact_type=self.artifact_type,
                timestamp=self.fallback_timestamp(file_path=file_path, reason='server log line missing timestamp'),
                timestamp_source_tz=self.get_source_tz(),
                source_file=os.path.basename(file_path),
                source_path=file_path,
                source_host=self.extract_hostname(file_path),
                case_file_id=self.case_file_id,
                event_id='windows_server_log_line',
                raw_json=json.dumps(payload, default=str),
                search_blob=self.build_search_blob(payload),
                parser_version=self.parser_version,
            )
