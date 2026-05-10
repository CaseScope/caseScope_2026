"""Parsers for KAPE artifact families not covered by specialized parsers.

These parsers intentionally emit concise timeline/security metadata. Large
binary payloads, diagnostic traces, and collection logs are preserved as files;
the emitted events make them searchable and reviewable without dumping content
into ClickHouse.
"""
import csv
import gzip
import hashlib
import json
import os
import re
import sqlite3
import struct
import zipfile
from datetime import datetime, timedelta
from typing import Any, Dict, Generator, List, Optional, Set, Tuple

from parsers.base import BaseParser, ParsedEvent


def _windows_filetime_to_datetime(value: int) -> Optional[datetime]:
    if not value or value <= 0:
        return None
    try:
        return datetime(1601, 1, 1) + timedelta(microseconds=value / 10)
    except (OverflowError, ValueError):
        return None


def _hash_file(file_path: str) -> Dict[str, str]:
    hashes = {
        'md5': hashlib.md5(),
        'sha1': hashlib.sha1(),
        'sha256': hashlib.sha256(),
    }
    with open(file_path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            for digest in hashes.values():
                digest.update(chunk)
    return {name: digest.hexdigest() for name, digest in hashes.items()}


def _read_sample(file_path: str, limit: int = 65536) -> bytes:
    with open(file_path, 'rb') as handle:
        return handle.read(limit)


def _text_sample(file_path: str, limit: int = 65536) -> str:
    data = _read_sample(file_path, limit=limit)
    return data.decode('utf-8', errors='replace')


def _decode_text(data: bytes) -> str:
    encodings = ['utf-8-sig', 'utf-8', 'latin-1']
    if data[:512].count(b'\x00') > 4:
        encodings.insert(0, 'utf-16-le')
    for encoding in encodings:
        try:
            text = data.decode(encoding)
            if text.count('\x00') < max(1, len(text) // 10):
                return text
        except UnicodeDecodeError:
            continue
    return data.decode('utf-8', errors='replace')


def _read_text_file(file_path: str, limit: int = 1024 * 1024) -> str:
    return _decode_text(_read_sample(file_path, limit=limit))


def _extract_strings(data: bytes, limit: int = 100) -> List[str]:
    ascii_strings = re.findall(rb'[\x20-\x7e]{5,}', data)
    utf16_strings = re.findall(rb'(?:[\x20-\x7e]\x00){5,}', data)
    values = [
        value.decode('ascii', errors='ignore')
        for value in ascii_strings
    ]
    values.extend(
        value.decode('utf-16-le', errors='ignore')
        for value in utf16_strings
    )
    seen: Set[str] = set()
    deduped = []
    for value in values:
        normalized = value.strip()
        if normalized and normalized not in seen:
            seen.add(normalized)
            deduped.append(normalized)
        if len(deduped) >= limit:
            break
    return deduped


def _extract_iocs(text: str) -> Dict[str, List[str]]:
    urls = sorted(set(re.findall(r'https?://[^\s\'"<>]+', text, flags=re.IGNORECASE)))[:50]
    ips = sorted(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)))[:50]
    paths = sorted(set(re.findall(r'[A-Za-z]:\\[^\r\n\t"\']{3,}', text)))[:50]
    return {'urls': urls, 'ips': ips, 'paths': paths}


def _chrome_time_to_datetime(value: Any) -> Optional[datetime]:
    try:
        integer = int(value)
    except (TypeError, ValueError):
        return None
    if integer <= 0:
        return None
    try:
        return datetime(1601, 1, 1) + timedelta(microseconds=integer)
    except (OverflowError, ValueError):
        return None


class RecycleBinParser(BaseParser):
    """Parse Windows Recycle Bin $I metadata records."""

    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'recycle_bin'

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        if not os.path.isfile(file_path):
            return False
        path_lower = file_path.lower().replace('\\', '/')
        filename = os.path.basename(file_path)
        return '/$recycle.bin/' in path_lower and filename.startswith('$I') and len(filename) > 2

    def _parse_original_path(self, data: bytes, version: int) -> str:
        if version == 1:
            raw_path = data[24:544]
        else:
            path_length = struct.unpack_from('<I', data, 24)[0] if len(data) >= 28 else 0
            raw_path = data[28:28 + path_length] if path_length else data[28:]
        return raw_path.decode('utf-16-le', errors='replace').rstrip('\x00').strip()

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return

        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        try:
            data = _read_sample(file_path, limit=4096)
            if len(data) < 24:
                self.errors.append(f"Recycle Bin $I file too small: {file_path}")
                return

            version = struct.unpack_from('<Q', data, 0)[0]
            deleted_size = struct.unpack_from('<Q', data, 8)[0]
            deletion_filetime = struct.unpack_from('<Q', data, 16)[0]
            deletion_time = _windows_filetime_to_datetime(deletion_filetime)
            original_path = self._parse_original_path(data, version)
            sid = ''
            parts = file_path.replace('\\', '/').split('/')
            for index, part in enumerate(parts):
                if part.lower() == '$recycle.bin' and index + 1 < len(parts):
                    sid = parts[index + 1]
                    break

            suffix = source_file[2:]
            companion_name = f"$R{suffix}"
            companion_path = os.path.join(os.path.dirname(file_path), companion_name)
            companion_exists = os.path.exists(companion_path)

            raw_data = {
                'version': version,
                'deleted_size': deleted_size,
                'deletion_filetime': deletion_filetime,
                'original_path': original_path,
                'recycle_sid': sid,
                'companion_name': companion_name,
                'companion_path': companion_path if companion_exists else '',
                'companion_exists': companion_exists,
            }
            search_parts = [source_file, original_path, sid, companion_name]

            yield ParsedEvent(
                case_id=self.case_id,
                artifact_type=self.artifact_type,
                timestamp=self.first_timestamp(
                    deletion_time,
                    file_path=file_path,
                    reason='recycle bin record missing deletion timestamp',
                ),
                source_file=source_file,
                source_path=file_path,
                source_host=hostname,
                case_file_id=self.case_file_id,
                username=sid,
                target_path=original_path,
                file_size=deleted_size,
                raw_json=json.dumps(raw_data, default=str),
                search_blob=' '.join(str(part) for part in search_parts if part),
                extra_fields=json.dumps({
                    'recycle_sid': sid,
                    'companion_exists': companion_exists,
                    'companion_name': companion_name,
                }, default=str),
                parser_version=self.parser_version,
            )
        except Exception as exc:
            self.errors.append(self.format_exception(exc, context=f"Failed to parse {file_path}"))


class PayloadTriageParser(BaseParser):
    """Emit security metadata for collected binaries, scripts, archives, and raw payloads."""

    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'file_triage'
    SUPPORTED_EXTENSIONS = {
        '.exe', '.dll', '.sys', '.com', '.scr', '.cpl', '.ocx',
        '.msi', '.ps1', '.psm1', '.bat', '.cmd', '.vbs', '.vbe',
        '.js', '.jse', '.wsf', '.hta', '.jar', '.zip', '.7z', '.rar',
        '.raw', '.bin',
    }
    SCRIPT_EXTENSIONS = {'.ps1', '.psm1', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta'}
    SUSPICIOUS_SCRIPT_TERMS = [
        'downloadstring', 'invoke-expression', 'iex', 'encodedcommand',
        'frombase64string', 'webclient', 'start-process', 'regsvr32',
        'rundll32', 'powershell', 'bitsadmin', 'certutil',
    ]

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        if not os.path.isfile(file_path):
            return False
        filename = os.path.basename(file_path).lower()
        extension = os.path.splitext(filename)[1]
        if extension in self.SUPPORTED_EXTENSIONS:
            return True
        try:
            magic = _read_sample(file_path, limit=4)
            return magic.startswith((b'MZ', b'PK\x03\x04', b'7z\xbc\xaf'))
        except Exception:
            return False

    def _pe_metadata(self, file_path: str) -> Dict[str, Any]:
        data = _read_sample(file_path, limit=8192)
        if not data.startswith(b'MZ') or len(data) < 0x40:
            return {}
        pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
        if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b'PE\x00\x00':
            return {'mz_header': True, 'pe_header_found': False}
        machine, section_count, timestamp = struct.unpack_from('<HHI', data, pe_offset + 4)
        return {
            'mz_header': True,
            'pe_header_found': True,
            'machine': hex(machine),
            'section_count': section_count,
            'compile_timestamp': str(datetime.utcfromtimestamp(timestamp)) if timestamp else '',
        }

    def _script_metadata(self, file_path: str) -> Dict[str, Any]:
        text = _text_sample(file_path).lower()
        urls = sorted(set(re.findall(r'https?://[^\s\'"<>]+', text)))[:25]
        ips = sorted(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)))[:25]
        terms = [term for term in self.SUSPICIOUS_SCRIPT_TERMS if term in text]
        return {
            'sample_length': len(text),
            'urls': urls,
            'ips': ips,
            'suspicious_terms': terms,
        }

    def _archive_metadata(self, file_path: str) -> Dict[str, Any]:
        if not zipfile.is_zipfile(file_path):
            return {}
        try:
            with zipfile.ZipFile(file_path, 'r') as archive:
                infos = archive.infolist()
                return {
                    'archive_type': 'zip',
                    'member_count': len(infos),
                    'compression_methods': sorted({info.compress_type for info in infos}),
                    'sample_members': [info.filename for info in infos[:25]],
                }
        except Exception as exc:
            return {'archive_type': 'zip', 'archive_error': str(exc)}

    def _yara_matches(self, file_path: str) -> List[str]:
        rules_dir = '/opt/casescope/rules/yara'
        if not os.path.isdir(rules_dir):
            return []
        try:
            import yara  # type: ignore
        except Exception:
            return []
        filepaths = {}
        for root, _, filenames in os.walk(rules_dir):
            for filename in filenames:
                if filename.lower().endswith(('.yar', '.yara')):
                    namespace = re.sub(r'[^A-Za-z0-9_]', '_', os.path.splitext(filename)[0])
                    filepaths[namespace] = os.path.join(root, filename)
        if not filepaths:
            return []
        try:
            rules = yara.compile(filepaths=filepaths)
            return [str(match.rule) for match in rules.match(file_path, timeout=30)]
        except Exception:
            return []

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return

        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        extension = os.path.splitext(source_file.lower())[1]
        try:
            hashes = _hash_file(file_path)
            file_size = os.path.getsize(file_path)
            metadata: Dict[str, Any] = {
                'filename': source_file,
                'extension': extension,
                'file_size': file_size,
                'hashes': hashes,
            }
            metadata.update(self._pe_metadata(file_path))
            if extension in self.SCRIPT_EXTENSIONS:
                metadata['script'] = self._script_metadata(file_path)
            archive_metadata = self._archive_metadata(file_path)
            if archive_metadata:
                metadata['archive'] = archive_metadata
            yara_matches = self._yara_matches(file_path)
            if yara_matches:
                metadata['yara_matches'] = yara_matches

            search_parts = [
                source_file, file_path, extension,
                hashes['md5'], hashes['sha1'], hashes['sha256'],
                *metadata.get('script', {}).get('suspicious_terms', []),
                *metadata.get('script', {}).get('urls', []),
                *yara_matches,
            ]
            yield ParsedEvent(
                case_id=self.case_id,
                artifact_type=self.artifact_type,
                timestamp=self.fallback_timestamp(file_path=file_path, reason='file triage uses file mtime'),
                source_file=source_file,
                source_path=file_path,
                source_host=hostname,
                case_file_id=self.case_file_id,
                target_path=file_path,
                process_name=source_file,
                file_hash_md5=hashes['md5'],
                file_hash_sha1=hashes['sha1'],
                file_hash_sha256=hashes['sha256'],
                file_size=file_size,
                rule_title=' | '.join(yara_matches),
                raw_json=json.dumps(metadata, default=str),
                search_blob=' '.join(str(part) for part in search_parts if part),
                extra_fields=json.dumps({
                    'extension': extension,
                    'has_pe_header': bool(metadata.get('pe_header_found')),
                    'yara_match_count': len(yara_matches),
                }, default=str),
                parser_version=self.parser_version,
            )
        except Exception as exc:
            self.errors.append(self.format_exception(exc, context=f"Failed to triage {file_path}"))


class KapeLogParser(BaseParser):
    """Parse KAPE copy and skip CSV logs as acquisition audit events."""

    VERSION = '1.1.0'
    ARTIFACT_TYPE = 'kape_log'

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        if not os.path.isfile(file_path):
            return False
        filename = os.path.basename(file_path).lower()
        return filename.endswith('.csv') and ('_copylog' in filename or '_skiplog' in filename)

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return
        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        log_kind = 'copy' if '_copylog' in source_file.lower() else 'skip'
        deduped_count = 0
        deduped_samples = []
        try:
            with open(file_path, 'r', encoding='utf-8-sig', errors='replace', newline='') as handle:
                reader = csv.DictReader(handle)
                for index, row in enumerate(reader, 1):
                    timestamp = None
                    for value in row.values():
                        timestamp = self.parse_timestamp(value)
                        if timestamp:
                            break
                    target = (
                        row.get('Source') or row.get('source') or
                        row.get('SourceFile') or row.get('sourcefile') or
                        row.get('File') or row.get('file') or ''
                    )
                    reason = row.get('Reason') or row.get('reason') or row.get('Message') or row.get('message') or ''
                    if log_kind == 'skip' and str(reason).strip().lower() == 'deduped':
                        deduped_count += 1
                        if len(deduped_samples) < 25:
                            deduped_samples.append(row)
                        continue
                    yield ParsedEvent(
                        case_id=self.case_id,
                        artifact_type=self.artifact_type,
                        timestamp=self.first_timestamp(
                            timestamp,
                            file_path=file_path,
                            reason='kape log row missing timestamp',
                        ),
                        source_file=source_file,
                        source_path=file_path,
                        source_host=hostname,
                        case_file_id=self.case_file_id,
                        event_id=log_kind,
                        record_id=index,
                        target_path=self.safe_str(target),
                        raw_json=json.dumps(row, default=str),
                        search_blob=self.build_search_blob(row),
                        extra_fields=json.dumps({'log_kind': log_kind, 'row_number': index, 'reason': reason}),
                        parser_version=self.parser_version,
                    )
            if deduped_count:
                summary = {
                    'log_kind': log_kind,
                    'reason': 'Deduped',
                    'deduped_row_count': deduped_count,
                    'sample_rows': deduped_samples,
                    'parser_note': 'Deduped KAPE skip rows are summarized to avoid flooding the event timeline',
                }
                yield ParsedEvent(
                    case_id=self.case_id,
                    artifact_type=self.artifact_type,
                    timestamp=self.fallback_timestamp(file_path=file_path, reason='kape dedupe summary uses file mtime'),
                    source_file=source_file,
                    source_path=file_path,
                    source_host=hostname,
                    case_file_id=self.case_file_id,
                    event_id='skip_deduped_summary',
                    record_id=deduped_count,
                    target_path=file_path,
                    raw_json=json.dumps(summary, default=str),
                    search_blob=self.build_search_blob(summary),
                    extra_fields=json.dumps({'log_kind': log_kind, 'reason': 'Deduped', 'deduped_row_count': deduped_count}),
                    parser_version=self.parser_version,
                )
        except Exception as exc:
            self.errors.append(self.format_exception(exc, context=f"Failed to parse {file_path}"))


class OfficeAutosaveParser(BaseParser):
    """Emit metadata for Office autosave/recovery files."""

    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'office_autosave'
    EXTENSIONS = {'.asd', '.wbk'}

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        return os.path.isfile(file_path) and os.path.splitext(file_path.lower())[1] in self.EXTENSIONS

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return
        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        try:
            hashes = _hash_file(file_path)
            sample = _read_sample(file_path, limit=256)
            raw_data = {
                'filename': source_file,
                'extension': os.path.splitext(source_file)[1].lower(),
                'file_size': os.path.getsize(file_path),
                'hashes': hashes,
                'magic_hex': sample[:16].hex(),
            }
            yield ParsedEvent(
                case_id=self.case_id,
                artifact_type=self.artifact_type,
                timestamp=self.fallback_timestamp(file_path=file_path, reason='office autosave uses file mtime'),
                source_file=source_file,
                source_path=file_path,
                source_host=hostname,
                case_file_id=self.case_file_id,
                target_path=file_path,
                file_hash_md5=hashes['md5'],
                file_hash_sha1=hashes['sha1'],
                file_hash_sha256=hashes['sha256'],
                file_size=raw_data['file_size'],
                raw_json=json.dumps(raw_data, default=str),
                search_blob=f"{source_file} {file_path} {hashes['sha256']}",
                extra_fields=json.dumps({'extension': raw_data['extension']}),
                parser_version=self.parser_version,
            )
        except Exception as exc:
            self.errors.append(self.format_exception(exc, context=f"Failed to parse {file_path}"))


class WindowsSearchDbParser(BaseParser):
    """Summarize Windows Search databases without dumping every row."""

    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'windows_search_db'

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        if not os.path.isfile(file_path):
            return False
        path_lower = file_path.lower().replace('\\', '/')
        filename = os.path.basename(path_lower)
        return '/microsoft/search/data/applications/windows/' in path_lower and filename.endswith('.db')

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return
        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        table_summaries = []
        try:
            conn = sqlite3.connect(f'file:{file_path}?mode=ro', uri=True)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            for (table_name,) in cursor.fetchall():
                if table_name.startswith('sqlite_'):
                    continue
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM [{table_name}]")
                    count = cursor.fetchone()[0]
                except Exception:
                    count = None
                table_summaries.append({'table': table_name, 'row_count': count})
            conn.close()
        except Exception as exc:
            self.warnings.append(f"Could not query Windows Search DB as SQLite: {exc}")

        raw_data = {
            'filename': source_file,
            'file_size': os.path.getsize(file_path),
            'tables': table_summaries,
        }
        yield ParsedEvent(
            case_id=self.case_id,
            artifact_type=self.artifact_type,
            timestamp=self.fallback_timestamp(file_path=file_path, reason='windows search db uses file mtime'),
            source_file=source_file,
            source_path=file_path,
            source_host=hostname,
            case_file_id=self.case_file_id,
            target_path=file_path,
            file_size=raw_data['file_size'],
            raw_json=json.dumps(raw_data, default=str),
            search_blob=f"{source_file} {file_path} " + ' '.join(t['table'] for t in table_summaries),
            extra_fields=json.dumps({'table_count': len(table_summaries)}),
            parser_version=self.parser_version,
        )


class DiagnosticLogParser(BaseParser):
    """Metadata/sample parser for ETL, ODL, and compressed diagnostic logs."""

    VERSION = '1.1.0'
    ARTIFACT_TYPE = 'diagnostic_log'
    EXTENSIONS = {'.etl', '.etlgz', '.odl', '.odlgz', '.loggz', '.aodl', '.odlsent'}
    ETL_EXTENSIONS = {'.etl', '.etlgz'}
    ETL_DESCRIPTION = 'Windows ETL trace file metadata preserved.'
    ETL_DECODER = 'dissect.etl'
    MAX_ETL_DECODE_RECORDS = 10000
    MAX_ETL_CHILD_EVENTS = 5000
    ETL_STRUCTURAL_KEYS = {
        'TimeStamp', 'timestamp', 'EventDescriptor', 'ProviderId', 'ProviderName',
        'KernelTime', 'UserTime', 'ProcessorTime', 'ActivityId', 'RelatedActivityId',
    }
    ETL_PID_KEYS = ('ProcessId', 'ProcessID', 'process_id', 'pid')
    ETL_TID_KEYS = ('ThreadId', 'ThreadID', 'thread_id', 'tid')
    ETL_EVENT_ID_KEYS = ('EventId', 'EventID', 'Id', 'ID', 'event_id')
    ETL_OPCODE_KEYS = ('Opcode', 'opcode')
    ETL_TASK_KEYS = ('Task', 'task')
    ETL_LEVEL_KEYS = ('Level', 'level')

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        return os.path.isfile(file_path) and os.path.splitext(file_path.lower())[1] in self.EXTENSIONS

    def _sample(self, file_path: str) -> str:
        filename = file_path.lower()
        try:
            if filename.endswith(('gz', '.loggz', '.odlgz', '.etlgz')):
                with gzip.open(file_path, 'rb') as handle:
                    return handle.read(4096).decode('utf-8', errors='replace')
            return _text_sample(file_path, limit=4096)
        except Exception:
            return ''

    def _open_etl_for_decode(self, file_path: str):
        if file_path.lower().endswith('.etlgz'):
            return gzip.open(file_path, 'rb')
        return open(file_path, 'rb')

    def _safe_etl_value(self, value: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, bytes):
            return None
        if isinstance(value, bytearray):
            return None
        if isinstance(value, memoryview):
            return None
        if isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, list):
            safe_values = [self._safe_etl_value(item) for item in value[:50]]
            return [item for item in safe_values if item is not None]
        if isinstance(value, tuple):
            safe_values = [self._safe_etl_value(item) for item in value[:50]]
            return [item for item in safe_values if item is not None]
        if isinstance(value, dict):
            safe_dict = {}
            for key, item in list(value.items())[:100]:
                safe_item = self._safe_etl_value(item)
                if safe_item is not None:
                    safe_dict[str(key)] = safe_item
            return safe_dict
        if hasattr(value, 'isoformat'):
            return value.isoformat()
        return str(value)

    def _first_etl_value(self, payload: Dict[str, Any], keys: Tuple[str, ...]) -> Any:
        for key in keys:
            value = payload.get(key)
            if value not in (None, ''):
                return value
        return None

    def _int_or_none(self, value: Any) -> Optional[int]:
        if value in (None, ''):
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _payload_has_searchable_value(self, payload: Dict[str, Any]) -> bool:
        for key, value in payload.items():
            if key in self.ETL_STRUCTURAL_KEYS:
                continue
            if isinstance(value, str) and len(value.strip()) >= 3:
                return True
            if isinstance(value, list) and any(isinstance(item, str) and len(item.strip()) >= 3 for item in value):
                return True
            if isinstance(value, dict) and self._payload_has_searchable_value(value):
                return True
        return False

    def _etl_search_parts(self, values: List[Any]) -> List[str]:
        search_parts: List[str] = []
        for value in values:
            if value in (None, ''):
                continue
            if isinstance(value, dict):
                for dict_value in value.values():
                    search_parts.extend(self._etl_search_parts([dict_value]))
            elif isinstance(value, list):
                search_parts.extend(self._etl_search_parts(value))
            elif isinstance(value, bytes):
                continue
            else:
                text = str(value).strip()
                if text and len(text) <= 500:
                    search_parts.append(text)
        return search_parts

    def _normalize_dissect_etl_event(self, etl_event: Any, source_file: str, file_path: str, hostname: str,
                                     case_file_id: Optional[int], index: int) -> Optional[ParsedEvent]:
        event_time = etl_event.ts()
        provider_name = etl_event.provider_name() or ''
        provider_guid = str(etl_event.provider_id() or '')
        event_type = etl_event.symbol() or ''

        raw_values = etl_event.event_values() or {}
        payload = {}
        skipped_binary_fields = []
        for key, value in raw_values.items():
            if isinstance(value, (bytes, bytearray, memoryview)):
                skipped_binary_fields.append(str(key))
                continue
            safe_value = self._safe_etl_value(value)
            if safe_value not in (None, '', [], {}):
                payload[str(key)] = safe_value

        event_id = self._first_etl_value(payload, self.ETL_EVENT_ID_KEYS)
        opcode = self._first_etl_value(payload, self.ETL_OPCODE_KEYS)
        task = self._first_etl_value(payload, self.ETL_TASK_KEYS)
        level = self._first_etl_value(payload, self.ETL_LEVEL_KEYS)
        process_id = self._int_or_none(self._first_etl_value(payload, self.ETL_PID_KEYS))
        thread_id = self._int_or_none(self._first_etl_value(payload, self.ETL_TID_KEYS))

        has_event_identity = any(value not in (None, '') for value in (provider_name, event_type, event_id, opcode, task, level))
        if not (event_time and (has_event_identity or self._payload_has_searchable_value(payload))):
            return None

        description = f"ETL event from provider {provider_name or provider_guid or 'unknown provider'}"
        if event_type:
            description = f"{description}: {event_type}"

        extra_fields = {
            'parent_event_type': 'etl_metadata',
            'decoder': self.ETL_DECODER,
            'provider_name': provider_name,
            'provider_guid': provider_guid,
            'event_type': event_type,
            'event_id': str(event_id or ''),
            'opcode': str(opcode or ''),
            'task': str(task or ''),
            'level': str(level or ''),
            'process_id': process_id,
            'thread_id': thread_id,
            'payload': payload,
            'decoded_record_index': index,
            'skipped_binary_fields': skipped_binary_fields,
        }
        raw_json = {
            'description': description,
            **extra_fields,
        }
        search_parts = self._etl_search_parts([
            source_file,
            file_path,
            'windows_etl_event',
            self.ETL_DECODER,
            provider_name,
            provider_guid,
            event_type,
            event_id,
            opcode,
            task,
            level,
            payload,
        ])

        return ParsedEvent(
            case_id=self.case_id,
            artifact_type='windows_etl_event',
            timestamp=event_time,
            source_file=source_file,
            source_path=file_path,
            source_host=hostname,
            case_file_id=case_file_id,
            event_id=str(event_id or event_type or ''),
            provider=provider_name or provider_guid,
            level=str(level or ''),
            process_id=process_id,
            thread_id=thread_id,
            target_path=file_path,
            raw_json=json.dumps(raw_json, default=str),
            search_blob=' '.join(search_parts),
            extra_fields=json.dumps(extra_fields, default=str),
            parser_version=self.parser_version,
        )

    def _try_decode_etl_with_dissect(self, file_path: str, source_file: str, hostname: str) -> Dict[str, Any]:
        result = {
            'decoder': None,
            'status': 'metadata_only',
            'warning': 'ETL metadata only; dissect.etl is not installed.',
            'total_records': 0,
            'decoded_record_count': 0,
            'skipped_record_count': 0,
            'records_limited': False,
            'children': [],
        }
        try:
            from dissect.etl import ETL  # type: ignore
        except ImportError:
            return result

        result['decoder'] = self.ETL_DECODER
        result['warning'] = ''
        try:
            with self._open_etl_for_decode(file_path) as handle:
                etl_file = ETL(handle)
                for index, event_record in enumerate(etl_file):
                    if index >= self.MAX_ETL_DECODE_RECORDS:
                        result['records_limited'] = True
                        break
                    result['total_records'] += 1
                    try:
                        child = self._normalize_dissect_etl_event(
                            event_record.event,
                            source_file,
                            file_path,
                            hostname,
                            self.case_file_id,
                            index,
                        )
                    except Exception:
                        result['skipped_record_count'] += 1
                        continue
                    if child is None:
                        result['skipped_record_count'] += 1
                        continue
                    if len(result['children']) < self.MAX_ETL_CHILD_EVENTS:
                        result['children'].append(child)
                        result['decoded_record_count'] += 1
                    else:
                        result['records_limited'] = True
        except Exception as exc:
            result['status'] = 'parse_error'
            result['warning'] = f"ETL parse error with dissect.etl: {exc}"
            result['children'] = []
            result['decoded_record_count'] = 0
            return result

        if result['total_records'] == 0:
            result['status'] = 'empty_or_no_records'
            result['warning'] = 'ETL decode completed with no records.'
        elif result['decoded_record_count'] == 0:
            result['status'] = 'unsupported_provider_payload'
            result['warning'] = 'ETL metadata only: provider payload unsupported or not meaningful.'
        elif result['skipped_record_count'] or result['records_limited']:
            result['status'] = 'partial_decode'
            result['warning'] = (
                f"ETL partial decode: {result['decoded_record_count']} searchable records emitted, "
                f"{result['skipped_record_count']} records skipped."
            )
        else:
            result['status'] = 'decoded'
            result['warning'] = f"ETL decoded: {result['decoded_record_count']} records using dissect.etl."
        return result

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return
        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        extension = os.path.splitext(source_file.lower())[1]
        is_etl = extension in self.ETL_EXTENSIONS
        log_family = 'windows_etl' if is_etl else 'odl_diagnostic'
        file_size = os.path.getsize(file_path)
        hashes = _hash_file(file_path)
        raw_data = {
            'filename': source_file,
            'extension': extension,
            'log_family': log_family,
            'file_size': file_size,
            'hashes': hashes,
        }
        extra_fields = {
            'extension': extension,
            'log_family': log_family,
        }
        if is_etl:
            decode_result = self._try_decode_etl_with_dissect(file_path, source_file, hostname)
            parser_status = decode_result['status']
            parser_warning = decode_result['warning']
            raw_data.update({
                'legacy_artifact_type': 'etl_trace',
                'description': self.ETL_DESCRIPTION,
                'parser_status': parser_status,
                'parser_warning': parser_warning,
                'decoder': decode_result['decoder'],
                'total_record_count': decode_result['total_records'],
                'decoded_record_count': decode_result['decoded_record_count'],
                'skipped_record_count': decode_result['skipped_record_count'],
                'records_limited': decode_result['records_limited'],
            })
            extra_fields.update({
                'parent_event_type': 'etl_metadata',
                'legacy_artifact_type': 'etl_trace',
                'parser_status': parser_status,
                'decoder': decode_result['decoder'],
                'total_record_count': decode_result['total_records'],
                'decoded_record_count': decode_result['decoded_record_count'],
                'skipped_record_count': decode_result['skipped_record_count'],
                'records_limited': decode_result['records_limited'],
                'parser_warning': parser_warning,
            })
            search_parts = [
                source_file,
                file_path,
                extension,
                'windows_etl',
                'etl_trace',
                parser_status,
                'windows etl trace',
                hashes['md5'],
                hashes['sha1'],
                hashes['sha256'],
            ]
        else:
            sample = self._sample(file_path)
            raw_data['sample'] = sample[:2000]
            search_parts = [source_file, file_path, log_family, sample[:1000]]

        yield ParsedEvent(
            case_id=self.case_id,
            artifact_type='windows_etl' if is_etl else self.artifact_type,
            timestamp=self.fallback_timestamp(file_path=file_path, reason='diagnostic log uses file mtime'),
            source_file=source_file,
            source_path=file_path,
            source_host=hostname,
            case_file_id=self.case_file_id,
            provider=log_family,
            target_path=file_path,
            file_hash_md5=hashes['md5'],
            file_hash_sha1=hashes['sha1'],
            file_hash_sha256=hashes['sha256'],
            file_size=file_size,
            raw_json=json.dumps(raw_data, default=str),
            search_blob=' '.join(str(part) for part in search_parts if part),
            extra_fields=json.dumps(extra_fields, default=str),
            parser_version=self.parser_version,
        )
        if is_etl:
            yield from decode_result['children']


class NtfsMetadataParser(BaseParser):
    """Emit metadata events for NTFS metadata files not handled by MFT/USN."""

    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'ntfs_metadata'
    FILENAMES = {'$logfile', '$boot', '$secure_$sds', '$max', '$t'}

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        if not os.path.isfile(file_path):
            return False
        filename = os.path.basename(file_path).lower()
        path_lower = file_path.lower().replace('\\', '/')
        return filename in self.FILENAMES or '/$extend/$rmmetadata/$txflog/' in path_lower

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return
        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        artifact_type = 'ntfs_logfile' if source_file.lower() == '$logfile' else self.artifact_type
        raw_data = {
            'filename': source_file,
            'file_size': os.path.getsize(file_path),
            'metadata_kind': artifact_type,
            'parser_note': 'metadata event; full transaction reconstruction is not enabled',
        }
        yield ParsedEvent(
            case_id=self.case_id,
            artifact_type=artifact_type,
            timestamp=self.fallback_timestamp(file_path=file_path, reason='ntfs metadata uses file mtime'),
            source_file=source_file,
            source_path=file_path,
            source_host=hostname,
            case_file_id=self.case_file_id,
            provider='NTFS',
            target_path=file_path,
            file_size=raw_data['file_size'],
            raw_json=json.dumps(raw_data, default=str),
            search_blob=f"{source_file} {file_path} {artifact_type}",
            extra_fields=json.dumps({'metadata_kind': artifact_type}),
            parser_version=self.parser_version,
        )


class WerReportParser(BaseParser):
    """Parse Windows Error Reporting Report.wer key/value files."""

    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'windows_error_report'

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        return os.path.isfile(file_path) and os.path.basename(file_path).lower().endswith('.wer')

    def _parse_fields(self, file_path: str) -> Dict[str, str]:
        text = _read_text_file(file_path)
        fields: Dict[str, str] = {}
        for line in text.splitlines():
            if not line or '=' not in line:
                continue
            key, value = line.split('=', 1)
            key = key.strip()
            if key:
                fields[key] = value.strip()
        return fields

    def _event_time(self, fields: Dict[str, str]) -> Optional[datetime]:
        for key in ('EventTime', 'ReportTime', 'Time'):
            value = fields.get(key)
            if not value:
                continue
            parsed = self.parse_timestamp(value)
            if parsed:
                return parsed
            try:
                return _windows_filetime_to_datetime(int(value))
            except (TypeError, ValueError):
                continue
        return None

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return

        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        try:
            fields = self._parse_fields(file_path)
            hashes = _hash_file(file_path)
            app_name = fields.get('AppName') or fields.get('FriendlyEventName') or ''
            app_path = fields.get('AppPath') or fields.get('ApplicationPath') or ''
            process_name = app_path.replace('\\', '/').rsplit('/', 1)[-1] if app_path else app_name
            event_name = fields.get('EventType') or fields.get('EventName') or fields.get('FriendlyEventName') or ''
            bucket = fields.get('Bucket') or fields.get('Response.BucketId') or fields.get('ReportIdentifier') or ''
            fault_module = fields.get('FaultingModule') or fields.get('Sig[3].Name') or ''
            raw_data = {
                'fields': fields,
                'hashes': hashes,
                'file_size': os.path.getsize(file_path),
            }
            yield ParsedEvent(
                case_id=self.case_id,
                artifact_type=self.artifact_type,
                timestamp=self.first_timestamp(
                    self._event_time(fields),
                    file_path=file_path,
                    reason='WER report missing event timestamp',
                ),
                source_file=source_file,
                source_path=file_path,
                source_host=hostname,
                case_file_id=self.case_file_id,
                event_id=event_name,
                provider='Windows Error Reporting',
                process_name=process_name,
                process_path=app_path,
                target_path=app_path or file_path,
                file_hash_md5=hashes['md5'],
                file_hash_sha1=hashes['sha1'],
                file_hash_sha256=hashes['sha256'],
                file_size=raw_data['file_size'],
                payload_data1=app_name,
                payload_data2=fault_module,
                payload_data3=bucket,
                raw_json=json.dumps(raw_data, default=str),
                search_blob=self.build_search_blob(fields, [source_file, file_path, app_name, app_path, event_name, bucket]),
                extra_fields=json.dumps({
                    'event_name': event_name,
                    'bucket': bucket,
                    'fault_module': fault_module,
                    'field_count': len(fields),
                }, default=str),
                parser_version=self.parser_version,
            )
        except Exception as exc:
            self.errors.append(self.format_exception(exc, context=f"Failed to parse {file_path}"))


class CrashDumpTriageParser(BaseParser):
    """Emit header, hash, and string metadata for Windows crash dumps."""

    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'crash_dump_triage'

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        if not os.path.isfile(file_path) or not os.path.basename(file_path).lower().endswith('.dmp'):
            return False
        path_lower = file_path.lower().replace('\\', '/')
        return '/crashdumps/' in path_lower or '/wer/' in path_lower or _read_sample(file_path, 4) in {b'MDMP', b'PAGE'}

    def _minidump_header(self, data: bytes) -> Dict[str, Any]:
        if len(data) < 32 or not data.startswith(b'MDMP'):
            return {'format': 'unknown', 'signature': data[:4].hex()}
        signature, version, stream_count, stream_directory_rva, checksum, timestamp, flags = struct.unpack_from('<IIIIIIIQ'[:0], data)  # type: ignore
        return {}

    def _dump_metadata(self, file_path: str) -> Dict[str, Any]:
        data = _read_sample(file_path, limit=1024 * 1024)
        metadata: Dict[str, Any] = {
            'signature': data[:4].decode('ascii', errors='replace') if data else '',
            'sample_strings': _extract_strings(data, limit=100),
        }
        if len(data) >= 32 and data.startswith(b'MDMP'):
            signature, version, stream_count, stream_directory_rva, checksum, timestamp, flags = struct.unpack_from('<IIIIIIQ', data, 0)
            metadata.update({
                'format': 'minidump',
                'signature_value': signature,
                'version': version,
                'stream_count': stream_count,
                'stream_directory_rva': stream_directory_rva,
                'checksum': checksum,
                'header_timestamp': str(datetime.utcfromtimestamp(timestamp)) if timestamp else '',
                'flags': flags,
            })
            streams = []
            for index in range(min(stream_count, 64)):
                offset = stream_directory_rva + (index * 12)
                if offset + 12 > len(data):
                    break
                stream_type, data_size, rva = struct.unpack_from('<III', data, offset)
                streams.append({'type': stream_type, 'size': data_size, 'rva': rva})
            metadata['streams'] = streams
        elif data.startswith(b'PAGE'):
            metadata['format'] = 'kernel_or_full_dump'
        else:
            metadata['format'] = 'unknown_dump'
        return metadata

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return
        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        try:
            hashes = _hash_file(file_path)
            metadata = self._dump_metadata(file_path)
            header_time = self.parse_timestamp(metadata.get('header_timestamp', ''))
            strings = metadata.get('sample_strings', [])
            yield ParsedEvent(
                case_id=self.case_id,
                artifact_type=self.artifact_type,
                timestamp=self.first_timestamp(
                    header_time,
                    file_path=file_path,
                    reason='crash dump missing header timestamp',
                ),
                source_file=source_file,
                source_path=file_path,
                source_host=hostname,
                case_file_id=self.case_file_id,
                provider='Windows Error Reporting',
                process_name=source_file.rsplit('.', 2)[0],
                target_path=file_path,
                file_hash_md5=hashes['md5'],
                file_hash_sha1=hashes['sha1'],
                file_hash_sha256=hashes['sha256'],
                file_size=os.path.getsize(file_path),
                raw_json=json.dumps({**metadata, 'hashes': hashes}, default=str),
                search_blob=' '.join([source_file, file_path, *strings[:30], hashes['sha256']]),
                extra_fields=json.dumps({
                    'dump_format': metadata.get('format', ''),
                    'stream_count': metadata.get('stream_count'),
                    'sample_string_count': len(strings),
                }, default=str),
                parser_version=self.parser_version,
            )
        except Exception as exc:
            self.errors.append(self.format_exception(exc, context=f"Failed to triage {file_path}"))


class WbemRepositoryParser(BaseParser):
    """Summarize WBEM/WMI repository files and extract persistence-oriented strings."""

    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'wbem_repository'
    FILENAMES = {'objects.data', 'index.btr', 'mapping1.map', 'mapping2.map', 'mapping3.map'}
    SUSPICIOUS_TERMS = [
        'ActiveScriptEventConsumer', 'CommandLineEventConsumer', '__EventFilter',
        '__FilterToConsumerBinding', 'powershell', 'cmd.exe', 'wscript', 'cscript',
        'rundll32', 'regsvr32', 'DownloadString',
    ]

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        if not os.path.isfile(file_path):
            return False
        path_lower = file_path.lower().replace('\\', '/')
        return '/wbem/repository/' in path_lower and os.path.basename(path_lower) in self.FILENAMES

    def _cim_summary(self, file_path: str) -> Dict[str, Any]:
        if os.path.basename(file_path).lower() != 'objects.data':
            return {}
        repo_dir = os.path.dirname(file_path)
        index_path = os.path.join(repo_dir, 'INDEX.BTR')
        mapping_paths = [os.path.join(repo_dir, f'MAPPING{idx}.MAP') for idx in (1, 2, 3)]
        if not os.path.exists(index_path):
            return {'cim_available': False, 'reason': 'INDEX.BTR missing'}
        try:
            from dissect.cim import CIM  # type: ignore
            with open(index_path, 'rb') as index_handle, open(file_path, 'rb') as objects_handle:
                mapping_handles = [open(path, 'rb') for path in mapping_paths if os.path.exists(path)]
                try:
                    cim = CIM(index_handle, objects_handle, mapping_handles)
                    summary = {
                        'cim_available': True,
                        'mapping_count': len(mapping_handles),
                    }
                    for query in ('root', 'root/subscription', 'root/default'):
                        try:
                            result = cim.query(query)
                            summary[f'query_{query.replace("/", "_")}'] = type(result).__name__
                        except Exception as exc:
                            summary[f'query_{query.replace("/", "_")}_error'] = str(exc)[:200]
                    return summary
                finally:
                    for handle in mapping_handles:
                        handle.close()
        except Exception as exc:
            return {'cim_available': False, 'reason': str(exc)[:500]}

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return

        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        try:
            sample = _read_sample(file_path, limit=2 * 1024 * 1024)
            strings = _extract_strings(sample, limit=250)
            text = '\n'.join(strings)
            iocs = _extract_iocs(text)
            suspicious_terms = [term for term in self.SUSPICIOUS_TERMS if term.lower() in text.lower()]
            hashes = _hash_file(file_path)
            raw_data = {
                'filename': source_file,
                'file_size': os.path.getsize(file_path),
                'hashes': hashes,
                'cim_summary': self._cim_summary(file_path),
                'sample_strings': strings,
                'iocs': iocs,
                'suspicious_terms': suspicious_terms,
            }
            yield ParsedEvent(
                case_id=self.case_id,
                artifact_type=self.artifact_type,
                timestamp=self.fallback_timestamp(file_path=file_path, reason='WBEM repository uses file mtime'),
                source_file=source_file,
                source_path=file_path,
                source_host=hostname,
                case_file_id=self.case_file_id,
                provider='WMI',
                target_path=file_path,
                file_hash_md5=hashes['md5'],
                file_hash_sha1=hashes['sha1'],
                file_hash_sha256=hashes['sha256'],
                file_size=raw_data['file_size'],
                rule_title=' | '.join(suspicious_terms),
                raw_json=json.dumps(raw_data, default=str),
                search_blob=' '.join([source_file, file_path, *strings[:100], *iocs['urls'], *iocs['ips'], *suspicious_terms]),
                extra_fields=json.dumps({
                    'repository_file': source_file,
                    'suspicious_term_count': len(suspicious_terms),
                    'sample_string_count': len(strings),
                    'cim_available': raw_data['cim_summary'].get('cim_available'),
                }, default=str),
                parser_version=self.parser_version,
            )
        except Exception as exc:
            self.errors.append(self.format_exception(exc, context=f"Failed to summarize {file_path}"))


class BrowserStateParser(BaseParser):
    """Parse browser profile state files not covered by SQLite parsers."""

    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'browser_state'
    JSON_FILENAMES = {
        'preferences', 'secure preferences', 'local state', 'bookmarks',
        'downloadmetadata', 'network persistent state',
    }
    BINARY_PREFIXES = ('session_', 'tabs_')

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        if not os.path.isfile(file_path):
            return False
        path_lower = file_path.lower().replace('\\', '/')
        filename = os.path.basename(path_lower)
        in_browser_profile = any(part in path_lower for part in (
            '/google/chrome/user data/', '/microsoft/edge/user data/',
            '/brave-browser/user data/', '/chromium/user data/',
        ))
        if not in_browser_profile:
            return False
        if filename in self.JSON_FILENAMES or filename in {'favicons', 'historyembeddings'}:
            return True
        return filename.startswith(self.BINARY_PREFIXES)

    def _flatten_bookmarks(self, node: Any, output: List[Dict[str, Any]]) -> None:
        if not isinstance(node, dict):
            return
        if node.get('type') == 'url':
            output.append({
                'name': node.get('name', ''),
                'url': node.get('url', ''),
                'date_added': node.get('date_added', ''),
            })
        for child in node.get('children', []) or []:
            self._flatten_bookmarks(child, output)

    def _json_metadata(self, file_path: str, filename: str) -> Tuple[Dict[str, Any], List[str], Optional[datetime]]:
        text = _read_text_file(file_path, limit=5 * 1024 * 1024)
        data = json.loads(text)
        search_parts: List[str] = []
        timestamp = None
        metadata: Dict[str, Any] = {'json_type': filename}
        if filename == 'bookmarks':
            bookmarks: List[Dict[str, Any]] = []
            self._flatten_bookmarks(data.get('roots', {}), bookmarks)
            metadata['bookmark_count'] = len(bookmarks)
            metadata['sample_bookmarks'] = bookmarks[:100]
            search_parts.extend([item.get('url', '') for item in bookmarks[:200]])
            search_parts.extend([item.get('name', '') for item in bookmarks[:200]])
            timestamps = [_chrome_time_to_datetime(item.get('date_added')) for item in bookmarks]
            timestamp = next((value for value in timestamps if value), None)
        elif filename in {'preferences', 'secure preferences', 'local state'}:
            profile = data.get('profile', {}) if isinstance(data, dict) else {}
            account_info = data.get('account_info', []) if isinstance(data, dict) else []
            download = profile.get('default_content_setting_values', {}) if isinstance(profile, dict) else {}
            extensions = data.get('extensions', {}).get('settings', {}) if isinstance(data.get('extensions', {}), dict) else {}
            metadata.update({
                'profile_name': profile.get('name', '') if isinstance(profile, dict) else '',
                'account_count': len(account_info) if isinstance(account_info, list) else 0,
                'extension_count': len(extensions) if isinstance(extensions, dict) else 0,
                'extension_ids': list(extensions.keys())[:100] if isinstance(extensions, dict) else [],
                'download_settings': download,
                'sync': data.get('sync', {}) if isinstance(data, dict) else {},
            })
            search_parts.extend(metadata.get('extension_ids', []))
            search_parts.append(metadata.get('profile_name', ''))
            search_parts.append(json.dumps(account_info[:10] if isinstance(account_info, list) else account_info, default=str))
        else:
            metadata['top_level_keys'] = list(data.keys())[:100] if isinstance(data, dict) else []
            metadata['sample'] = data if isinstance(data, list) else {}
            search_parts.append(json.dumps(data, default=str)[:5000])
        return metadata, search_parts, timestamp

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return

        source_file = os.path.basename(file_path)
        filename = source_file.lower()
        hostname = self.extract_hostname(file_path)
        try:
            hashes = _hash_file(file_path)
            metadata: Dict[str, Any] = {
                'filename': source_file,
                'file_size': os.path.getsize(file_path),
                'hashes': hashes,
            }
            search_parts = [source_file, file_path, hashes['sha256']]
            timestamp = None
            if filename in self.JSON_FILENAMES:
                try:
                    json_metadata, json_search, timestamp = self._json_metadata(file_path, filename)
                    metadata.update(json_metadata)
                    search_parts.extend(json_search)
                except Exception as exc:
                    metadata['json_parse_error'] = str(exc)
                    sample = _read_text_file(file_path, limit=16384)
                    metadata['sample'] = sample[:4000]
                    search_parts.append(sample)
            else:
                sample = _read_sample(file_path, limit=1024 * 1024)
                strings = _extract_strings(sample, limit=150)
                metadata.update({'state_format': 'binary_or_sqlite', 'sample_strings': strings})
                search_parts.extend(strings[:100])
            yield ParsedEvent(
                case_id=self.case_id,
                artifact_type=self.artifact_type,
                timestamp=self.first_timestamp(timestamp, file_path=file_path, reason='browser state uses file mtime'),
                source_file=source_file,
                source_path=file_path,
                source_host=hostname,
                case_file_id=self.case_file_id,
                provider='Browser Profile',
                target_path=source_file,
                file_hash_md5=hashes['md5'],
                file_hash_sha1=hashes['sha1'],
                file_hash_sha256=hashes['sha256'],
                file_size=metadata['file_size'],
                raw_json=json.dumps(metadata, default=str),
                search_blob=' '.join(str(part) for part in search_parts if part),
                extra_fields=json.dumps({
                    'state_file': filename,
                    'extension_count': metadata.get('extension_count'),
                    'bookmark_count': metadata.get('bookmark_count'),
                }, default=str),
                parser_version=self.parser_version,
            )
        except Exception as exc:
            self.errors.append(self.format_exception(exc, context=f"Failed to parse browser state {file_path}"))


class CloudMetadataParser(BaseParser):
    """Parse lightweight cloud sync metadata files, primarily OneDrive support artifacts."""

    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'cloud_metadata'
    EXTENSIONS = {'.ini', '.txt', '.keystore', '.otc', '.cookie'}

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        if not os.path.isfile(file_path):
            return False
        path_lower = file_path.lower().replace('\\', '/')
        extension = os.path.splitext(os.path.basename(path_lower))[1]
        return '/microsoft/onedrive/' in path_lower and extension in self.EXTENSIONS

    def _metadata(self, file_path: str) -> Dict[str, Any]:
        sample = _read_sample(file_path, limit=2 * 1024 * 1024)
        text = _decode_text(sample)
        metadata: Dict[str, Any] = {
            'sample': text[:4000],
            'iocs': _extract_iocs(text),
        }
        try:
            parsed = json.loads(text)
            metadata['json'] = parsed
            metadata['json_keys'] = list(parsed.keys())[:100] if isinstance(parsed, dict) else []
        except Exception:
            pass
        if sample.startswith(b'SQLite format 3'):
            try:
                conn = sqlite3.connect(f'file:{file_path}?mode=ro', uri=True)
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [row[0] for row in cursor.fetchall()]
                metadata['sqlite_tables'] = tables[:100]
                conn.close()
            except Exception as exc:
                metadata['sqlite_error'] = str(exc)
        return metadata

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return

        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        try:
            hashes = _hash_file(file_path)
            metadata = {
                'filename': source_file,
                'file_size': os.path.getsize(file_path),
                'hashes': hashes,
                **self._metadata(file_path),
            }
            iocs = metadata.get('iocs', {})
            yield ParsedEvent(
                case_id=self.case_id,
                artifact_type=self.artifact_type,
                timestamp=self.fallback_timestamp(file_path=file_path, reason='cloud metadata uses file mtime'),
                source_file=source_file,
                source_path=file_path,
                source_host=hostname,
                case_file_id=self.case_file_id,
                provider='OneDrive',
                target_path=file_path,
                file_hash_md5=hashes['md5'],
                file_hash_sha1=hashes['sha1'],
                file_hash_sha256=hashes['sha256'],
                file_size=metadata['file_size'],
                raw_json=json.dumps(metadata, default=str),
                search_blob=' '.join([source_file, file_path, metadata.get('sample', ''), *iocs.get('urls', []), *iocs.get('ips', [])]),
                extra_fields=json.dumps({
                    'metadata_file': source_file,
                    'url_count': len(iocs.get('urls', [])),
                    'sqlite_table_count': len(metadata.get('sqlite_tables', [])),
                }, default=str),
                parser_version=self.parser_version,
            )
        except Exception as exc:
            self.errors.append(self.format_exception(exc, context=f"Failed to parse cloud metadata {file_path}"))


class TransactionSidecarParser(BaseParser):
    """Emit metadata for database/registry transaction sidecars preserved with source artifacts."""

    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'transaction_sidecar'
    EXTENSIONS = {'.log1', '.log2', '.db-wal', '.db-shm', '.db-journal', '.otc-wal', '.otc-shm', '.jfm', '.chk'}

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        if not os.path.isfile(file_path):
            return False
        filename = os.path.basename(file_path).lower()
        return any(filename.endswith(extension) for extension in self.EXTENSIONS)

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return

        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        try:
            hashes = _hash_file(file_path)
            sample = _read_sample(file_path, limit=65536)
            strings = _extract_strings(sample, limit=50)
            extension = next((ext for ext in self.EXTENSIONS if source_file.lower().endswith(ext)), os.path.splitext(source_file)[1].lower())
            raw_data = {
                'filename': source_file,
                'extension': extension,
                'file_size': os.path.getsize(file_path),
                'hashes': hashes,
                'magic_hex': sample[:16].hex(),
                'sample_strings': strings,
                'parser_note': 'metadata only; sidecar is preserved for parent artifact recovery',
            }
            yield ParsedEvent(
                case_id=self.case_id,
                artifact_type=self.artifact_type,
                timestamp=self.fallback_timestamp(file_path=file_path, reason='transaction sidecar uses file mtime'),
                source_file=source_file,
                source_path=file_path,
                source_host=hostname,
                case_file_id=self.case_file_id,
                target_path=file_path,
                file_hash_md5=hashes['md5'],
                file_hash_sha1=hashes['sha1'],
                file_hash_sha256=hashes['sha256'],
                file_size=raw_data['file_size'],
                raw_json=json.dumps(raw_data, default=str),
                search_blob=' '.join([source_file, file_path, extension, hashes['sha256'], *strings]),
                extra_fields=json.dumps({'extension': extension, 'sample_string_count': len(strings)}),
                parser_version=self.parser_version,
            )
        except Exception as exc:
            self.errors.append(self.format_exception(exc, context=f"Failed to summarize sidecar {file_path}"))
