"""Additional Windows artifact parsers for KAPE/CyLR coverage gaps."""
import json
import os
import re
import sqlite3
import struct
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any, Dict, Generator, Iterable, List, Tuple

from parsers.base import BaseParser, ParsedEvent


# Reading a whole artifact into memory has to be bounded, but the previous
# bounds were low enough to cut real logs in half, and exceeding them left no
# trace. The bounds are now higher and _truncation records what was dropped.
MAX_TEXT_BYTES = 64 * 1024 * 1024
MAX_BINARY_BYTES = 16 * 1024 * 1024
MAX_ROWS_PER_TABLE = 200000


def _read_text(file_path: str, limit: int = MAX_TEXT_BYTES) -> str:
    with open(file_path, 'rb') as handle:
        data = handle.read(limit)
    if data.startswith(b'\xff\xfe') or data[1:2] == b'\x00':
        return data.decode('utf-16-le', errors='replace')
    return data.decode('utf-8', errors='replace')


def _truncation(file_path: str, limit: int) -> Dict[str, Any]:
    """Describe bytes left unread, so a capped payload is not silently partial."""
    try:
        size = os.path.getsize(file_path)
    except OSError:
        return {}
    if size <= limit:
        return {}
    return {'truncated': True, 'bytes_read': limit, 'bytes_total': size}


def _decode_binary_text(data: bytes) -> str:
    """Render both encodings of a binary blob so text scans see either one."""
    return '\n'.join((
        data.decode('utf-16-le', errors='replace'),
        data.decode('utf-8', errors='replace'),
    ))


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
                parsed = self.probe_timestamp(payload.get(key))
                if parsed:
                    return parsed
        return self.fallback_timestamp(file_path=file_path, reason=f'{self.artifact_type} uses file mtime')

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        if not self.can_parse(file_path):
            self.errors.append(f'Cannot parse file: {file_path}')
            return
        payload = self._payload(file_path)
        source_file = os.path.basename(file_path)
        if payload.get('file_size') is None:
            try:
                payload['file_size'] = os.path.getsize(file_path)
            except OSError:
                pass
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
            file_hash_sha256=payload.get('file_hash_sha256', ''),
            # Several payloads compute a size that was then dropped on the floor
            file_size=self.safe_uint64(payload.get('file_size')),
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
            timestamp = next((probed for part in parts if (probed := self.probe_timestamp(part))), None)
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
            data = handle.read(MAX_BINARY_BYTES)
        values = _strings(data, limit=100)
        return {'path': file_path, 'recovered_text': '\n'.join(values), 'strings': values,
                'byte_length': len(data), **_truncation(file_path, MAX_BINARY_BYTES)}


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
                    row_count = 0
                    for row in conn.execute(
                        f'SELECT * FROM "{table}" LIMIT {MAX_ROWS_PER_TABLE + 1}'
                    ):
                        row_count += 1
                        if row_count > MAX_ROWS_PER_TABLE:
                            self.warnings.append(
                                f"Table {table} in {os.path.basename(file_path)} exceeded "
                                f"{MAX_ROWS_PER_TABLE} rows; the remainder was not ingested"
                            )
                            break
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
            parsed = self.probe_timestamp(value)
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
        if not os.path.isfile(file_path) or not file_path.lower().endswith(('.db', '.sqlite')):
            return False
        normalized = file_path.replace('\\', '/').lower()
        # Match 'recall' as a path segment rather than as a substring of any
        # folder or database name that happens to contain it
        in_recall_tree = '/coreai/' in normalized or '/recall/' in normalized
        if not (in_recall_tree or os.path.basename(normalized) in self.FILE_NAMES):
            return False
        try:
            with open(file_path, 'rb') as handle:
                return handle.read(16).startswith(b'SQLite format 3')
        except OSError:
            return False


class BitsParser(_SingleEventFileParser):
    VERSION = '1.1.0'
    ARTIFACT_TYPE = 'bits_queue'
    EVENT_ID = 'bits_queue'
    MAX_JOBS = 5000
    # A BITS job is interesting for where it fetched from and wrote to. Counting
    # the rows and discarding their contents recorded neither.
    URL_RE = re.compile(r'(?:https?|ftp)://[^\s\x00"<>]{4,2048}', re.IGNORECASE)
    LOCAL_PATH_RE = re.compile(r'[A-Za-z]:\\\\?[^\s\x00"<>|*?]{3,260}')

    def can_parse(self, file_path: str) -> bool:
        filename = os.path.basename(file_path).lower()
        return os.path.isfile(file_path) and filename in {'qmgr.db', 'qmgr0.dat', 'qmgr1.dat'}

    def _job_fields(self, text: str) -> Dict[str, Any]:
        """Pull the remote URLs and local destinations out of decoded job text."""
        urls, paths = [], []
        for match in self.URL_RE.finditer(text):
            value = match.group(0)
            if value not in urls:
                urls.append(value)
            if len(urls) >= self.MAX_JOBS:
                break
        for match in self.LOCAL_PATH_RE.finditer(text):
            value = match.group(0)
            if value not in paths:
                paths.append(value)
            if len(paths) >= self.MAX_JOBS:
                break
        return {'job_urls': urls, 'job_local_paths': paths,
                'job_url_count': len(urls), 'job_path_count': len(paths)}

    def _ese_jobs(self, file_path: str) -> Dict[str, Any]:
        from dissect.esedb import EseDB
        tables: List[Dict[str, Any]] = []
        text_parts: List[str] = []
        with open(file_path, 'rb') as handle:
            db = EseDB(handle)
            for table in db.tables():
                count = 0
                for record in table.records():
                    count += 1
                    if count > self.MAX_JOBS:
                        break
                    for column in table.columns:
                        try:
                            value = record.get(column.name)
                        except Exception:
                            continue
                        if isinstance(value, bytes):
                            text_parts.append(value.decode('utf-16-le', errors='replace'))
                            text_parts.append(value.decode('utf-8', errors='replace'))
                        elif isinstance(value, str):
                            text_parts.append(value)
                tables.append({'table': table.name, 'row_count': count})
        payload: Dict[str, Any] = {'path': file_path, 'tables': tables}
        payload.update(self._job_fields('\n'.join(text_parts)))
        return payload

    def _payload(self, file_path: str) -> Dict[str, Any]:
        if os.path.basename(file_path).lower().endswith('.db'):
            try:
                return self._ese_jobs(file_path)
            except Exception as exc:
                error = str(exc)
            with open(file_path, 'rb') as handle:
                data = handle.read(MAX_BINARY_BYTES)
            payload = {'path': file_path, 'error': error, 'strings': _strings(data),
                       **_truncation(file_path, MAX_BINARY_BYTES)}
            payload.update(self._job_fields(_decode_binary_text(data)))
            return payload

        with open(file_path, 'rb') as handle:
            data = handle.read(MAX_BINARY_BYTES)
        payload = {'path': file_path, 'strings': _strings(data),
                   **_truncation(file_path, MAX_BINARY_BYTES)}
        payload.update(self._job_fields(_decode_binary_text(data)))
        return payload


class RecentFileCacheParser(_SingleEventFileParser):
    ARTIFACT_TYPE = 'recentfilecache'
    EVENT_ID = 'recentfilecache'

    def can_parse(self, file_path: str) -> bool:
        return os.path.basename(file_path).lower() == 'recentfilecache.bcf'

    def _payload(self, file_path: str) -> Dict[str, Any]:
        with open(file_path, 'rb') as handle:
            return {'path': file_path,
                    'recent_files': _strings(handle.read(MAX_BINARY_BYTES), limit=500),
                    **_truncation(file_path, MAX_BINARY_BYTES)}


class SchedLgUParser(_SingleEventFileParser):
    ARTIFACT_TYPE = 'schedlgu'
    EVENT_ID = 'legacy_scheduled_task_log'

    def can_parse(self, file_path: str) -> bool:
        return os.path.basename(file_path).lower() == 'schedlgu.txt'

    def _payload(self, file_path: str) -> Dict[str, Any]:
        return {'path': file_path, 'text': _read_text(file_path),
                **_truncation(file_path, MAX_TEXT_BYTES)}


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
            return {'path': file_path, 'error': str(exc), 'text': _read_text(file_path),
                    **_truncation(file_path, MAX_TEXT_BYTES)}


class NetClrUsageLogParser(_SingleEventFileParser):
    ARTIFACT_TYPE = 'netclr_usage'
    EVENT_ID = 'netclr_usage'

    def can_parse(self, file_path: str) -> bool:
        normalized = file_path.replace('\\', '/').lower()
        return os.path.isfile(file_path) and '/usage logs/' in normalized and 'clr_v' in normalized

    def _payload(self, file_path: str) -> Dict[str, Any]:
        name = os.path.basename(file_path)
        return {'path': file_path, 'process_name': name.rsplit('.', 1)[0],
                'text': _read_text(file_path), **_truncation(file_path, MAX_TEXT_BYTES)}


class ThumbcacheIconcacheParser(_SingleEventFileParser):
    ARTIFACT_TYPE = 'thumb_icon_cache'
    EVENT_ID = 'thumb_icon_cache'

    def can_parse(self, file_path: str) -> bool:
        filename = os.path.basename(file_path).lower()
        return os.path.isfile(file_path) and (filename.startswith(('thumbcache_', 'iconcache_')) and filename.endswith('.db'))

    def _payload(self, file_path: str) -> Dict[str, Any]:
        with open(file_path, 'rb') as handle:
            data = handle.read(MAX_BINARY_BYTES)
        return {'path': file_path, 'cache_type': os.path.basename(file_path).split('_', 1)[0],
                'strings': _strings(data), **_truncation(file_path, MAX_BINARY_BYTES)}


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
    VERSION = '1.1.0'
    ARTIFACT_TYPE = 'registry_pol'
    EVENT_ID = 'registry_pol'
    supports_manifest_protocol = True
    manifest_ordering_contract = 'registry-pol:physical-record-offset-order:v1'

    REGFILE_SIGNATURE = b'PReg'
    FORMAT_VERSION = 1
    MAX_DATA_SIZE = 65535
    _OPEN_RECORD = b'[\x00'
    _SEPARATOR = b';\x00'
    _CLOSE_RECORD = b']\x00'
    _REG_TYPE_NAMES = {
        0: 'REG_NONE',
        1: 'REG_SZ',
        2: 'REG_EXPAND_SZ',
        3: 'REG_BINARY',
        4: 'REG_DWORD',
        5: 'REG_DWORD_BIG_ENDIAN',
        6: 'REG_LINK',
        7: 'REG_MULTI_SZ',
        11: 'REG_QWORD',
    }

    def manifest_producer_version(self) -> str:
        return f'{self.parser_version};registry_pol_format=1;record_offsets=physical'

    def can_parse(self, file_path: str) -> bool:
        if os.path.basename(file_path).lower() != 'registry.pol' or not os.path.isfile(file_path):
            return False
        try:
            with open(file_path, 'rb') as handle:
                return handle.read(4) == self.REGFILE_SIGNATURE
        except OSError:
            return False

    @staticmethod
    def _read_utf16le_z(data: bytes, offset: int) -> Tuple[str, int]:
        cursor = offset
        while cursor + 1 < len(data):
            if data[cursor:cursor + 2] == b'\x00\x00':
                return data[offset:cursor].decode('utf-16-le', errors='replace'), cursor + 2
            cursor += 2
        raise ValueError('unterminated UTF-16LE string')

    @staticmethod
    def _decode_data(value_type: int, raw_data: bytes) -> Dict[str, Any]:
        if value_type in (1, 2, 6):
            text = raw_data.decode('utf-16-le', errors='replace').rstrip('\x00')
            return {'decoded_as': 'utf-16-le', 'text': text, 'search_text': text}
        if value_type == 7:
            text = raw_data.decode('utf-16-le', errors='replace').rstrip('\x00')
            items = [item for item in text.split('\x00') if item]
            return {
                'decoded_as': 'utf-16-le-multi-sz',
                'items': items,
                'text': ';'.join(items),
                'search_text': ' '.join(items),
            }
        if value_type == 4 and len(raw_data) >= 4:
            value = struct.unpack_from('<I', raw_data, 0)[0]
            return {'decoded_as': 'uint32-le', 'integer': value, 'text': str(value), 'search_text': str(value)}
        if value_type == 5 and len(raw_data) >= 4:
            value = struct.unpack_from('>I', raw_data, 0)[0]
            return {'decoded_as': 'uint32-be', 'integer': value, 'text': str(value), 'search_text': str(value)}
        if value_type == 11 and len(raw_data) >= 8:
            value = struct.unpack_from('<Q', raw_data, 0)[0]
            return {'decoded_as': 'uint64-le', 'integer': value, 'text': str(value), 'search_text': str(value)}
        hex_value = raw_data.hex()
        return {'decoded_as': 'hex', 'hex': hex_value, 'text': hex_value, 'search_text': hex_value}

    def _parse_record(self, data: bytes, offset: int) -> Tuple[Dict[str, Any], int]:
        record_offset = offset
        if data[offset:offset + 2] != self._OPEN_RECORD:
            raise ValueError('missing Registry.pol record opener')
        offset += 2

        key_path, offset = self._read_utf16le_z(data, offset)
        if data[offset:offset + 2] != self._SEPARATOR:
            raise ValueError('missing separator after key path')
        offset += 2

        value_name, offset = self._read_utf16le_z(data, offset)
        if data[offset:offset + 2] != self._SEPARATOR:
            raise ValueError('missing separator after value name')
        offset += 2

        if offset + 4 > len(data):
            raise ValueError('truncated registry value type')
        value_type = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        if data[offset:offset + 2] != self._SEPARATOR:
            raise ValueError('missing separator after value type')
        offset += 2

        if offset + 4 > len(data):
            raise ValueError('truncated data size')
        data_size = struct.unpack_from('<I', data, offset)[0]
        if data_size > self.MAX_DATA_SIZE:
            raise ValueError(f'data size {data_size} exceeds Registry.pol maximum')
        offset += 4
        if data[offset:offset + 2] != self._SEPARATOR:
            raise ValueError('missing separator after data size')
        offset += 2

        data_offset = offset
        data_end = offset + data_size
        if data_end > len(data):
            raise ValueError('truncated registry data')
        raw_data = data[offset:data_end]
        offset = data_end
        if data[offset:offset + 2] != self._CLOSE_RECORD:
            raise ValueError('missing Registry.pol record closer')
        offset += 2

        decoded = self._decode_data(value_type, raw_data)
        return {
            'record_offset': record_offset,
            'data_offset': data_offset,
            'record_length': offset - record_offset,
            'key_path': key_path,
            'value_name': value_name,
            'value_type': value_type,
            'value_type_name': self._REG_TYPE_NAMES.get(value_type, f'REG_TYPE_{value_type}'),
            'data_size': data_size,
            'data': decoded,
        }, offset

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        if not self.can_parse(file_path):
            self.errors.append(f'Cannot parse file: {file_path}')
            return

        with open(file_path, 'rb') as handle:
            data = handle.read(MAX_BINARY_BYTES)

        if len(data) < 8:
            self.errors.append(f'Failed to parse {file_path}: Registry.pol header is truncated')
            return

        version = struct.unpack_from('<I', data, 4)[0]
        if version != self.FORMAT_VERSION:
            self.errors.append(f'Failed to parse {file_path}: unsupported Registry.pol version {version}')
            return

        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        timestamp = self.fallback_timestamp(file_path=file_path, reason='registry_pol records do not carry timestamps')
        offset = 8
        record_index = 0
        truncated = _truncation(file_path, MAX_BINARY_BYTES)

        while offset < len(data):
            if data[offset:] in (b'', b'\x00' * (len(data) - offset)):
                break
            if data[offset:offset + 2] != self._OPEN_RECORD:
                self.warnings.append(f'Stopped Registry.pol parsing at offset {offset}: expected record opener')
                break
            try:
                record, next_offset = self._parse_record(data, offset)
            except Exception as exc:
                self.warnings.append(f'Stopped Registry.pol parsing at offset {offset}: {exc}')
                break

            record_index += 1
            record['record_index'] = record_index
            if truncated:
                record.update(truncated)
            display_value_name = record['value_name'] or '(Default)'
            data_text = record['data'].get('search_text', '')
            raw_json = json.dumps(record, default=str, sort_keys=True)
            extra = {
                'record_index': record_index,
                'record_offset': record['record_offset'],
                'data_offset': record['data_offset'],
                'record_length': record['record_length'],
                'value_type': record['value_type'],
                'value_type_name': record['value_type_name'],
                'data_size': record['data_size'],
            }
            yield ParsedEvent(
                case_id=self.case_id,
                artifact_type=self.artifact_type,
                timestamp=timestamp,
                timestamp_source_tz=self.get_source_tz(),
                source_file=source_file,
                source_path=file_path,
                source_host=hostname,
                case_file_id=self.case_file_id,
                event_id=self.EVENT_ID,
                target_path=record['key_path'],
                reg_key=record['key_path'],
                reg_value=display_value_name,
                reg_data=self.safe_str(record['data'].get('text', '')),
                raw_json=raw_json,
                search_blob=' '.join(str(part) for part in (
                    source_file,
                    record['key_path'],
                    display_value_name,
                    record['value_type_name'],
                    data_text,
                ) if part),
                extra_fields=json.dumps(extra, default=str, sort_keys=True),
                parser_version=self.parser_version,
                source_record_identifier_authoritative=True,
                source_record_identifier_type='registry_pol_record_offset',
                source_record_identifier_value=str(record['record_offset']),
            )
            offset = next_offset


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
            return {'path': file_path, 'strings': _strings(handle.read(MAX_BINARY_BYTES), limit=500),
                    **_truncation(file_path, MAX_BINARY_BYTES)}


class SensitiveWindowsFileParser(_SingleEventFileParser):
    VERSION = '1.1.0'
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

    # An Exchange install tree is full of binaries and configuration; only the
    # text logs in it belong to this parser.
    LOG_EXTENSIONS = ('.log', '.txt', '.csv')

    def can_parse(self, file_path: str) -> bool:
        if not os.path.isfile(file_path) or self.is_tool_configuration(file_path):
            return False
        normalized = file_path.replace('\\', '/').lower()
        filename = os.path.basename(normalized)
        if not filename.endswith(self.LOG_EXTENSIONS):
            return False
        return (
            '/exchange' in normalized
            or filename in {'dns.log'}
            or 'dhcp' in normalized
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
