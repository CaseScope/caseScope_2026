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
import shlex
import sqlite3
import struct
import subprocess
import tempfile
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

    VERSION = '1.2.0'
    ARTIFACT_TYPE = 'diagnostic_log'
    EXTENSIONS = {'.etl', '.etlgz', '.odl', '.odlgz', '.loggz', '.aodl', '.odlsent'}
    ETL_EXTENSIONS = {'.etl', '.etlgz'}
    ETL_DESCRIPTION = 'Windows ETL trace file metadata preserved.'
    DISSECT_ETL_DECODER = 'dissect.etl'
    AIRBUS_ETL_DECODER = 'airbus.etl-parser'
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
    ETL_COMMAND_LINE_KEYS = ('CommandLine', 'command_line', 'Command', 'command')
    ETL_PROCESS_PATH_KEYS = ('ImageName', 'ImagePath', 'ProcessName', 'ProcessPath', 'process_path', 'image_name')
    ETL_TARGET_PATH_KEYS = (
        'FileName', 'FilePath', 'Path', 'TargetFilename', 'TargetFileName',
        'ObjectName', 'RegistryKey', 'KeyName', 'ValueName', 'Url', 'URL',
    )
    ETL_PROVIDER_CATEGORY_RULES = (
        ('defender', 'security', 'Microsoft Defender or endpoint security ETL provider'),
        ('antimalware', 'security', 'Microsoft Defender or endpoint security ETL provider'),
        ('security', 'security', 'Security-related ETL provider'),
        ('powershell', 'powershell', 'PowerShell ETL provider'),
        ('winrm', 'remote_access', 'Windows Remote Management ETL provider'),
        ('terminalservices', 'remote_access', 'Remote Desktop Services ETL provider'),
        ('rdp', 'remote_access', 'Remote Desktop ETL provider'),
        ('wmi', 'wmi', 'Windows Management Instrumentation ETL provider'),
        ('wbem', 'wmi', 'WBEM/WMI ETL provider'),
        ('tcpip', 'network', 'TCP/IP network ETL provider'),
        ('network', 'network', 'Network ETL provider'),
        ('nettrace', 'network', 'Network trace ETL provider'),
        ('ndis', 'network', 'Network driver ETL provider'),
        ('dns', 'network', 'DNS ETL provider'),
        ('dhcp', 'network', 'DHCP ETL provider'),
        ('kernel-process', 'process', 'Kernel process ETL provider'),
        ('process', 'process', 'Process ETL provider'),
        ('kernel-file', 'filesystem', 'Kernel file I/O ETL provider'),
        ('fileio', 'filesystem', 'File I/O ETL provider'),
        ('ntfs', 'filesystem', 'NTFS ETL provider'),
        ('registry', 'registry', 'Registry ETL provider'),
        ('explorer', 'shell', 'Windows Explorer shell ETL provider'),
        ('shell', 'shell', 'Windows shell ETL provider'),
        ('wdi', 'diagnostics', 'Windows Diagnostic Infrastructure ETL provider'),
        ('diagnostic', 'diagnostics', 'Windows diagnostic ETL provider'),
        ('boot', 'diagnostics', 'Boot diagnostic ETL provider'),
        ('shutdown', 'diagnostics', 'Shutdown diagnostic ETL provider'),
        ('perf', 'performance', 'Performance ETL provider'),
    )

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
        if hasattr(value, 'items'):
            safe_dict = {}
            for key, item in list(value.items())[:100]:
                safe_item = self._safe_etl_value(item)
                if safe_item is not None:
                    safe_dict[str(key)] = safe_item
            return safe_dict
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

    def _coerce_etl_datetime(self, value: Any) -> Optional[datetime]:
        if value in (None, ''):
            return None
        if isinstance(value, datetime):
            return value
        if hasattr(value, 'isoformat') and not isinstance(value, str):
            try:
                return self.parse_timestamp(value.isoformat())
            except Exception:
                return None
        if isinstance(value, str):
            return self.parse_timestamp(value)
        return None

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

    def _basename_from_windows_path(self, value: Any) -> str:
        text = str(value or '').replace('/', '\\').rstrip('\\')
        if not text:
            return ''
        return text.rsplit('\\', 1)[-1]

    def _classify_etl_provider(self, provider_name: str, provider_guid: str, event_type: str,
                               payload: Dict[str, Any]) -> Tuple[str, str]:
        haystack = ' '.join(
            str(part or '')
            for part in (
                provider_name,
                provider_guid,
                event_type,
                payload.get('event_kind'),
                payload.get('event_class'),
                payload.get('message_parser'),
            )
        ).lower()
        for needle, category, summary in self.ETL_PROVIDER_CATEGORY_RULES:
            if needle in haystack:
                return category, summary
        return 'unknown', 'Unclassified ETL provider'

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

    def _normalize_etl_payload_event(self, *, decoder: str, source_file: str, file_path: str, hostname: str,
                                     case_file_id: Optional[int], index: int, event_time: Any,
                                     provider_name: Any = '', provider_guid: Any = '',
                                     event_type: Any = '', raw_values: Optional[Dict[str, Any]] = None,
                                     skipped_binary_fields: Optional[List[str]] = None) -> Optional[ParsedEvent]:
        event_time = self._coerce_etl_datetime(event_time)
        provider_name = str(provider_name or '')
        provider_guid = str(provider_guid or '')
        event_type = str(event_type or '')
        raw_values = raw_values or {}
        payload = {}
        skipped_binary_fields = skipped_binary_fields or []
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
        command_line = str(self._first_etl_value(payload, self.ETL_COMMAND_LINE_KEYS) or '')
        process_path = str(self._first_etl_value(payload, self.ETL_PROCESS_PATH_KEYS) or '')
        process_name = self._basename_from_windows_path(process_path)
        decoded_target_path = str(self._first_etl_value(payload, self.ETL_TARGET_PATH_KEYS) or '')
        provider_category, provider_summary = self._classify_etl_provider(
            provider_name,
            provider_guid,
            event_type,
            payload,
        )

        has_event_identity = any(value not in (None, '') for value in (provider_name, event_type, event_id, opcode, task, level))
        if not (event_time and (has_event_identity or self._payload_has_searchable_value(payload))):
            return None

        description = f"ETL event from provider {provider_name or provider_guid or 'unknown provider'}"
        if event_type:
            description = f"{description}: {event_type}"

        extra_fields = {
            'parent_event_type': 'etl_metadata',
            'decoder': decoder,
            'provider_name': provider_name,
            'provider_guid': provider_guid,
            'event_type': event_type,
            'event_id': str(event_id or ''),
            'opcode': str(opcode or ''),
            'task': str(task or ''),
            'level': str(level or ''),
            'process_id': process_id,
            'thread_id': thread_id,
            'command_line': command_line,
            'process_path': process_path,
            'process_name': process_name,
            'decoded_target_path': decoded_target_path,
            'provider_category': provider_category,
            'provider_summary': provider_summary,
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
            decoder,
            provider_name,
            provider_guid,
            event_type,
            provider_category,
            provider_summary,
            event_id,
            opcode,
            task,
            level,
            command_line,
            process_path,
            process_name,
            decoded_target_path,
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
            process_name=process_name,
            process_path=process_path,
            process_id=process_id,
            thread_id=thread_id,
            command_line=command_line,
            target_path=decoded_target_path or file_path,
            raw_json=json.dumps(raw_json, default=str),
            search_blob=' '.join(search_parts),
            extra_fields=json.dumps(extra_fields, default=str),
            parser_version=self.parser_version,
        )

    def _normalize_dissect_etl_event(self, etl_event: Any, source_file: str, file_path: str, hostname: str,
                                     case_file_id: Optional[int], index: int) -> Optional[ParsedEvent]:
        return self._normalize_etl_payload_event(
            decoder=self.DISSECT_ETL_DECODER,
            source_file=source_file,
            file_path=file_path,
            hostname=hostname,
            case_file_id=case_file_id,
            index=index,
            event_time=etl_event.ts(),
            provider_name=etl_event.provider_name() or '',
            provider_guid=str(etl_event.provider_id() or ''),
            event_type=etl_event.symbol() or '',
            raw_values=etl_event.event_values() or {},
        )

    def _new_etl_decode_result(self, missing_warning: str) -> Dict[str, Any]:
        return {
            'decoder': None,
            'status': 'metadata_only',
            'warning': missing_warning,
            'total_records': 0,
            'decoded_record_count': 0,
            'skipped_record_count': 0,
            'records_limited': False,
            'children': [],
        }

    def _finalize_etl_decode_result(self, result: Dict[str, Any], decoder_label: str) -> Dict[str, Any]:
        if result['total_records'] == 0:
            result['status'] = 'empty_or_no_records'
            result['warning'] = f'ETL decode completed with no records using {decoder_label}.'
        elif result['decoded_record_count'] == 0:
            result['status'] = 'unsupported_provider_payload'
            result['warning'] = f'ETL metadata only: provider payload unsupported or not meaningful using {decoder_label}.'
        elif result['skipped_record_count'] or result['records_limited']:
            result['status'] = 'partial_decode'
            result['warning'] = (
                f"ETL partial decode: {result['decoded_record_count']} searchable records emitted, "
                f"{result['skipped_record_count']} records skipped using {decoder_label}."
            )
        else:
            result['status'] = 'decoded'
            result['warning'] = f"ETL decoded: {result['decoded_record_count']} records using {decoder_label}."
        return result

    def _try_decode_etl_with_dissect(self, file_path: str, source_file: str, hostname: str) -> Dict[str, Any]:
        result = self._new_etl_decode_result('ETL metadata only; dissect.etl is not installed.')
        try:
            from dissect.etl import ETL  # type: ignore
        except ImportError:
            return result

        result['decoder'] = self.DISSECT_ETL_DECODER
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

        return self._finalize_etl_decode_result(result, self.DISSECT_ETL_DECODER)

    def _airbus_public_values(self, value: Any) -> Dict[str, Any]:
        values: Dict[str, Any] = {}
        if hasattr(value, '__dict__'):
            for key, item in value.__dict__.items():
                if not key.startswith('_'):
                    values[key] = item
        for key in (
            'timestamp', 'time_stamp', 'TimeStamp', 'process_id', 'ProcessId',
            'thread_id', 'ThreadId', 'provider_name', 'ProviderName', 'provider',
            'provider_id', 'ProviderId', 'provider_guid', 'event_id', 'EventId',
            'event_type', 'EventType', 'opcode', 'Opcode', 'task', 'Task',
            'level', 'Level',
        ):
            try:
                item = getattr(value, key)
            except Exception:
                continue
            if item not in (None, ''):
                values[key] = item
        return values

    def _try_parse_airbus_message(self, event: Any, method_name: str) -> Any:
        method = getattr(event, method_name, None)
        if not callable(method):
            return None
        try:
            return method()
        except Exception:
            return None

    def _normalize_airbus_etl_event(self, event: Any, event_kind: str, source_file: str, file_path: str,
                                    hostname: str, case_file_id: Optional[int], index: int) -> Optional[ParsedEvent]:
        raw_values = {
            'event_kind': event_kind,
            'event_class': event.__class__.__name__,
            **self._airbus_public_values(event),
        }
        message = None
        for method_name in ('parse_tracelogging', 'parse_etw', 'get_mof'):
            message = self._try_parse_airbus_message(event, method_name)
            if message is not None:
                raw_values['message_parser'] = method_name
                raw_values['message'] = self._safe_etl_value(message)
                raw_values.update({
                    f'message_{key}': value
                    for key, value in self._airbus_public_values(message).items()
                })
                break

        event_time = self._first_etl_value(raw_values, (
            'timestamp', 'time_stamp', 'TimeStamp', 'ts', 'event_time', 'datetime',
        ))
        provider_name = self._first_etl_value(raw_values, (
            'ProviderName', 'provider_name', 'provider', 'name',
        )) or event_kind
        provider_guid = self._first_etl_value(raw_values, (
            'ProviderId', 'provider_id', 'provider_guid', 'guid',
        )) or ''
        event_type = self._first_etl_value(raw_values, (
            'EventType', 'event_type', 'symbol', 'message_parser', 'event_class',
        )) or event.__class__.__name__

        return self._normalize_etl_payload_event(
            decoder=self.AIRBUS_ETL_DECODER,
            source_file=source_file,
            file_path=file_path,
            hostname=hostname,
            case_file_id=case_file_id,
            index=index,
            event_time=event_time,
            provider_name=provider_name,
            provider_guid=provider_guid,
            event_type=event_type,
            raw_values=raw_values,
        )

    def _try_decode_etl_with_airbus(self, file_path: str, source_file: str, hostname: str) -> Dict[str, Any]:
        result = self._new_etl_decode_result('ETL metadata only; Airbus etl-parser is not installed.')
        try:
            from etl.etl import IEtlFileObserver, build_from_stream  # type: ignore
        except ImportError:
            return result

        parser = self

        class CaseScopeAirbusObserver(IEtlFileObserver):
            def _handle(self, event: Any, event_kind: str) -> None:
                if result['total_records'] >= parser.MAX_ETL_DECODE_RECORDS:
                    result['records_limited'] = True
                    return
                index = result['total_records']
                result['total_records'] += 1
                try:
                    child = parser._normalize_airbus_etl_event(
                        event,
                        event_kind,
                        source_file,
                        file_path,
                        hostname,
                        parser.case_file_id,
                        index,
                    )
                except Exception:
                    result['skipped_record_count'] += 1
                    return
                if child is None:
                    result['skipped_record_count'] += 1
                    return
                if len(result['children']) < parser.MAX_ETL_CHILD_EVENTS:
                    result['children'].append(child)
                    result['decoded_record_count'] += 1
                else:
                    result['records_limited'] = True

            def on_system_trace(self, event: Any) -> None:
                self._handle(event, 'system_trace')

            def on_perfinfo_trace(self, event: Any) -> None:
                self._handle(event, 'perfinfo_trace')

            def on_trace_record(self, event: Any) -> None:
                self._handle(event, 'trace_record')

            def on_event_record(self, event: Any) -> None:
                self._handle(event, 'event_record')

            def on_win_trace(self, event: Any) -> None:
                self._handle(event, 'win_trace')

        result['decoder'] = self.AIRBUS_ETL_DECODER
        result['warning'] = ''
        try:
            with self._open_etl_for_decode(file_path) as handle:
                etl_reader = build_from_stream(handle.read())
            etl_reader.parse(CaseScopeAirbusObserver())
        except Exception as exc:
            result['status'] = 'parse_error'
            result['warning'] = f"ETL parse error with Airbus etl-parser: {exc}"
            result['children'] = []
            result['decoded_record_count'] = 0
            return result

        return self._finalize_etl_decode_result(result, self.AIRBUS_ETL_DECODER)

    def _try_decode_etl(self, file_path: str, source_file: str, hostname: str) -> Dict[str, Any]:
        primary_result = self._try_decode_etl_with_dissect(file_path, source_file, hostname)
        if primary_result.get('decoded_record_count', 0) > 0:
            return primary_result

        fallback_result = self._try_decode_etl_with_airbus(file_path, source_file, hostname)
        if fallback_result.get('decoded_record_count', 0) > 0:
            fallback_result['primary_decoder_status'] = primary_result.get('status')
            fallback_result['primary_decoder_warning'] = primary_result.get('warning')
            return fallback_result

        primary_warning = primary_result.get('warning') or ''
        fallback_warning = fallback_result.get('warning') or ''
        if fallback_warning:
            primary_result['warning'] = '; '.join(
                warning for warning in (primary_warning, fallback_warning) if warning
            )
        if fallback_result.get('decoder') or primary_result.get('decoder') is None:
            fallback_result['warning'] = '; '.join(
                warning for warning in (primary_warning, fallback_warning) if warning
            )
            return fallback_result
        return primary_result

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
            decode_result = self._try_decode_etl(file_path, source_file, hostname)
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
                'primary_decoder_status': decode_result.get('primary_decoder_status'),
                'primary_decoder_warning': decode_result.get('primary_decoder_warning'),
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
                'primary_decoder_status': decode_result.get('primary_decoder_status'),
                'primary_decoder_warning': decode_result.get('primary_decoder_warning'),
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
    LOGFILE_EVENT_TYPE = 'ntfs_logfile_event'
    LOG_TRACKER_BACKEND = 'NTFS Log Tracker'
    LOG_TRACKER_SOURCE = 'ntfs_log_tracker_adapter'
    LOG_TRACKER_ENV = 'NTFS_LOG_TRACKER_CMD'
    LOG_TRACKER_MAX_CHILD_EVENTS = 100000
    LOG_TRACKER_EVENT_MAP = {
        'create': 'file_create',
        'created': 'file_create',
        'creating': 'file_create',
        'creating_file_directory': 'file_create',
        'creating_file_or_directory': 'file_create',
        'file_create': 'file_create',
        'directory_create': 'file_create',
        'delete': 'file_delete',
        'deleted': 'file_delete',
        'deleting': 'file_delete',
        'deleting_file_directory': 'file_delete',
        'deleting_file_or_directory': 'file_delete',
        'file_delete': 'file_delete',
        'directory_delete': 'file_delete',
        'rename': 'file_rename',
        'renamed': 'file_rename',
        'renaming': 'file_rename',
        'renaming_file_directory': 'file_rename',
        'renaming_file_or_directory': 'file_rename',
        'file_rename': 'file_rename',
        'move': 'file_move',
        'moved': 'file_move',
        'moving': 'file_move',
        'moving_file_directory': 'file_move',
        'moving_file_or_directory': 'file_move',
        'file_move': 'file_move',
        'resident_write': 'file_write_resident',
        'write_resident': 'file_write_resident',
        'writing_resident_data': 'file_write_resident',
        'file_write_resident': 'file_write_resident',
        'nonresident_write': 'file_write_nonresident',
        'non_resident_write': 'file_write_nonresident',
        'write_nonresident': 'file_write_nonresident',
        'writing_nonresident_data': 'file_write_nonresident',
        'writing_non_resident_data': 'file_write_nonresident',
        'file_write_nonresident': 'file_write_nonresident',
        'updating_modified_time': 'directory_timestamp_update',
        'updating_mft_modified_time': 'directory_timestamp_update',
        'directory_timestamp_update': 'directory_timestamp_update',
        'directory_index_update': 'directory_index_update',
    }
    LOG_TRACKER_TIMESTAMP_KEYS = (
        'timestamp', 'event_time', 'time', 'datetime', 'date_time',
        'event time', 'event date/time', 'date time', 'time_created',
        'standard_information_modified', 'mft_modified_time',
    )
    LOG_TRACKER_EVENT_KEYS = (
        'event_type', 'event', 'operation', 'operation_type', 'action',
        'event_info', 'event info', 'semantic_event', 'type',
    )
    LOG_TRACKER_PATH_KEYS = (
        'file_path', 'path', 'full_path', 'filename', 'name',
        'full path', 'file/directory name', 'file directory name',
        'file_name', 'file name', 'target_path', 'new_path',
    )
    LOG_TRACKER_OLD_PATH_KEYS = (
        'old_path', 'old path', 'source_path', 'source path',
        'previous_path', 'previous path', 'from_path', 'from path',
    )
    LOG_TRACKER_NEW_PATH_KEYS = (
        'new_path', 'new path', 'destination_path', 'destination path',
        'target_path', 'target path', 'to_path', 'to path',
    )
    LOG_TRACKER_MFT_KEYS = (
        'mft_reference', 'mft_ref', 'file_reference', 'file reference',
        'filereferencenumber', 'file_reference_number', 'file reference number',
        'frn', 'record_number', 'record number',
    )
    LOG_TRACKER_PARENT_MFT_KEYS = (
        'parent_mft_reference', 'parent_mft_ref', 'parent_file_reference',
        'parent file reference', 'parentfilereferencenumber',
        'parent_file_reference_number', 'parent file reference number',
        'parent_frn', 'parent_record_number', 'parent record number',
    )
    LOG_TRACKER_RECORD_ID_KEYS = (
        'backend_record_id', 'record_id', 'record id', 'id',
        'lsn', 'current_lsn', 'current lsn',
    )
    LOG_TRACKER_CONFIDENCE_KEYS = ('confidence', 'confidence_level')
    LOG_TRACKER_TRANSACTION_KEYS = (
        'transaction_reference', 'transaction reference',
        'transaction_lsn', 'transaction lsn', 'transaction_id',
        'transaction id', 'mft_lsn', 'mft lsn', 'first_lsn',
        'first lsn', 'last_lsn', 'last lsn',
    )

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        if not os.path.isfile(file_path):
            return False
        filename = os.path.basename(file_path).lower()
        path_lower = file_path.lower().replace('\\', '/')
        return filename in self.FILENAMES or '/$extend/$rmmetadata/$txflog/' in path_lower

    def _is_logfile(self, file_path: str) -> bool:
        return os.path.basename(file_path).lower() == '$logfile'

    def _new_log_tracker_result(self, status: str, warning: str = '') -> Dict[str, Any]:
        return {
            'decoder': None,
            'status': status,
            'warning': warning,
            'total_records': 0,
            'decoded_record_count': 0,
            'skipped_record_count': 0,
            'records_limited': False,
            'children': [],
            'companion_artifacts': {'mft': False, 'usnjrnl_j': False},
            'parser_statuses': [status],
        }

    def _first_mapping_value(self, row: Dict[str, Any], keys: Tuple[str, ...]) -> Any:
        for key in keys:
            if key in row and row[key] not in (None, ''):
                return row[key]
        normalized = {
            str(key).strip().lower().replace(' ', '_'): value
            for key, value in row.items()
        }
        for key in keys:
            value = normalized.get(key)
            if value not in (None, ''):
                return value
        compact = {
            re.sub(r'[^a-z0-9]', '', str(key).strip().lower()): value
            for key, value in row.items()
        }
        for key in keys:
            value = compact.get(re.sub(r'[^a-z0-9]', '', key.lower()))
            if value not in (None, ''):
                return value
        return None

    def _normalize_event_type(self, value: Any, row: Dict[str, Any]) -> str:
        raw_value = str(value or '').strip().lower().replace(' ', '_').replace('-', '_')
        if raw_value in self.LOG_TRACKER_EVENT_MAP:
            return self.LOG_TRACKER_EVENT_MAP[raw_value]
        operation = ' '.join(str(part or '').lower() for part in row.values())
        if 'renam' in operation:
            return 'file_rename'
        if 'move' in operation or 'moving' in operation:
            return 'file_move'
        if 'nonresident' in operation or 'non_resident' in operation or 'non-resident' in operation:
            return 'file_write_nonresident'
        if 'resident' in operation and ('write' in operation or 'writing' in operation):
            return 'file_write_resident'
        if 'delet' in operation:
            return 'file_delete'
        if 'creat' in operation:
            return 'file_create'
        if 'timestamp' in operation and 'director' in operation:
            return 'directory_timestamp_update'
        if 'index' in operation and 'director' in operation:
            return 'directory_index_update'
        return raw_value or 'ntfs_logfile_operation'

    def _log_tracker_search_parts(self, values: List[Any]) -> List[str]:
        search_parts: List[str] = []
        for value in values:
            if value in (None, ''):
                continue
            if isinstance(value, dict):
                for item in value.values():
                    search_parts.extend(self._log_tracker_search_parts([item]))
            elif isinstance(value, list):
                search_parts.extend(self._log_tracker_search_parts(value))
            elif isinstance(value, bytes):
                continue
            else:
                text = str(value).strip()
                if text and len(text) <= 500:
                    search_parts.append(text)
        return search_parts

    def _normalize_log_tracker_row(
        self,
        row: Dict[str, Any],
        *,
        source_file: str,
        file_path: str,
        hostname: str,
        index: int,
        companion_artifacts: Dict[str, bool],
    ) -> Optional[ParsedEvent]:
        event_type = self._normalize_event_type(
            self._first_mapping_value(row, self.LOG_TRACKER_EVENT_KEYS),
            row,
        )
        timestamp = self.parse_timestamp(self._first_mapping_value(row, self.LOG_TRACKER_TIMESTAMP_KEYS))
        if timestamp is None:
            timestamp = self.fallback_timestamp(file_path=file_path, reason='ntfs logfile event missing timestamp')

        file_path_value = self.safe_str(self._first_mapping_value(row, self.LOG_TRACKER_PATH_KEYS))
        old_path = self.safe_str(self._first_mapping_value(row, self.LOG_TRACKER_OLD_PATH_KEYS))
        new_path = self.safe_str(self._first_mapping_value(row, self.LOG_TRACKER_NEW_PATH_KEYS))
        target_path = new_path or file_path_value or old_path
        mft_reference = self.safe_str(self._first_mapping_value(row, self.LOG_TRACKER_MFT_KEYS))
        parent_mft_reference = self.safe_str(self._first_mapping_value(row, self.LOG_TRACKER_PARENT_MFT_KEYS))
        backend_record_id = self.safe_str(self._first_mapping_value(row, self.LOG_TRACKER_RECORD_ID_KEYS)) or str(index)
        transaction_reference = self.safe_str(self._first_mapping_value(row, self.LOG_TRACKER_TRANSACTION_KEYS))
        confidence = self.safe_str(self._first_mapping_value(row, self.LOG_TRACKER_CONFIDENCE_KEYS), 'medium')
        if not target_path and not mft_reference and not transaction_reference:
            return None

        raw_operation = self.safe_str(
            self._first_mapping_value(row, (
                'raw_operation', 'raw operation', 'operation', 'operation_type',
                'operation type', 'source_info', 'source info', 'redo_undo',
                'redo undo', 'redo_operation', 'redo operation', 'undo_operation',
                'undo operation', 'opcode',
            ))
        )
        parser_status = 'decoded' if target_path else 'path_resolution_partial'
        parser_statuses = [parser_status]
        if not companion_artifacts.get('mft'):
            parser_statuses.append('missing_companion_mft')
        if not companion_artifacts.get('usnjrnl_j'):
            parser_statuses.append('missing_companion_usnjrnl')
        if not target_path:
            parser_statuses.append('path_resolution_partial')

        extra_fields = {
            'parent_event_type': 'ntfs_logfile_metadata',
            'source_parser': self.LOG_TRACKER_SOURCE,
            'source_artifact_type': 'ntfs_logfile',
            'event_type': event_type,
            'backend_tool': self.LOG_TRACKER_BACKEND,
            'backend_record_id': backend_record_id,
            'companion_artifacts': companion_artifacts,
            'parser_status': parser_status,
            'parser_statuses': list(dict.fromkeys(parser_statuses)),
            'confidence': confidence,
            'mft_reference': mft_reference,
            'parent_mft_reference': parent_mft_reference,
            'transaction_reference': transaction_reference,
            'old_path': old_path,
            'new_path': new_path,
            'raw_operation': raw_operation,
            'resident_write': event_type == 'file_write_resident',
            'nonresident_write': event_type == 'file_write_nonresident',
            'notes': self._log_tracker_notes(companion_artifacts, target_path),
            'raw_backend_row': row,
        }
        raw_json = {
            'description': f"NTFS $LogFile {event_type}",
            **extra_fields,
            'file_path': target_path,
        }
        search_parts = self._log_tracker_search_parts([
            source_file,
            self.LOGFILE_EVENT_TYPE,
            event_type,
            target_path,
            old_path,
            new_path,
            mft_reference,
            parent_mft_reference,
            transaction_reference,
            confidence,
            raw_operation,
        ])

        return ParsedEvent(
            case_id=self.case_id,
            artifact_type=self.LOGFILE_EVENT_TYPE,
            timestamp=timestamp,
            source_file=source_file,
            source_path=file_path,
            source_host=hostname,
            case_file_id=self.case_file_id,
            event_id=event_type,
            provider='NTFS $LogFile',
            record_id=self.safe_int(backend_record_id),
            target_path=self.safe_str(target_path),
            raw_json=json.dumps(raw_json, default=str),
            search_blob=' '.join(search_parts),
            extra_fields=json.dumps(extra_fields, default=str),
            parser_version=self.parser_version,
        )

    def _log_tracker_notes(self, companion_artifacts: Dict[str, bool], target_path: str) -> str:
        notes = []
        if target_path and companion_artifacts.get('mft'):
            notes.append('Path resolved with companion $MFT context.')
        elif target_path:
            notes.append('Path emitted by backend without companion $MFT context.')
        else:
            notes.append('Path unresolved; preserve MFT reference for analyst review.')
        if not companion_artifacts.get('usnjrnl_j'):
            notes.append('No $UsnJrnl:$J correlation available.')
        return ' '.join(notes)

    def _row_has_log_tracker_semantics(self, row: Dict[str, Any]) -> bool:
        if not row:
            return False
        has_event = self._first_mapping_value(row, self.LOG_TRACKER_EVENT_KEYS) not in (None, '')
        has_path = any(
            self._first_mapping_value(row, keys) not in (None, '')
            for keys in (
                self.LOG_TRACKER_PATH_KEYS,
                self.LOG_TRACKER_OLD_PATH_KEYS,
                self.LOG_TRACKER_NEW_PATH_KEYS,
            )
        )
        has_reference = any(
            self._first_mapping_value(row, keys) not in (None, '')
            for keys in (
                self.LOG_TRACKER_MFT_KEYS,
                self.LOG_TRACKER_PARENT_MFT_KEYS,
                self.LOG_TRACKER_RECORD_ID_KEYS,
                self.LOG_TRACKER_TRANSACTION_KEYS,
            )
        )
        return has_event and (has_path or has_reference)

    def _candidate_companion_roots(self, file_path: str) -> List[str]:
        roots: List[str] = []
        current = os.path.dirname(os.path.abspath(file_path))
        for _ in range(4):
            if current == os.path.abspath(os.sep):
                break
            if current and current not in roots:
                roots.append(current)
            parent = os.path.dirname(current)
            if not parent or parent == current:
                break
            if parent == os.path.abspath(tempfile.gettempdir()):
                break
            current = parent
        return roots

    def _find_companion_artifacts(self, file_path: str) -> Dict[str, Optional[str]]:
        companions: Dict[str, Optional[str]] = {'mft': None, 'usnjrnl_j': None}
        scanned = 0
        for root in self._candidate_companion_roots(file_path):
            for dirpath, _, filenames in os.walk(root):
                scanned += len(filenames)
                if scanned > 3000:
                    return companions
                for filename in filenames:
                    lower = filename.lower()
                    candidate = os.path.join(dirpath, filename)
                    normalized_candidate = candidate.lower().replace('\\', '/')
                    if companions['mft'] is None and lower in ('$mft', 'mft'):
                        companions['mft'] = candidate
                    if companions['usnjrnl_j'] is None and (
                        lower in ('$j', '$usnjrnl:$j', 'usnjrnl.bin')
                        or '$extend/$usnjrnl' in normalized_candidate
                    ):
                        companions['usnjrnl_j'] = candidate
                    if companions['mft'] and companions['usnjrnl_j']:
                        return companions
        return companions

    def _build_log_tracker_command(
        self,
        template: str,
        *,
        file_path: str,
        output_dir: str,
        companions: Dict[str, Optional[str]],
    ) -> List[str]:
        replacements = {
            'logfile': file_path,
            'output_dir': output_dir,
            'mft': companions.get('mft') or '',
            'usnjrnl': companions.get('usnjrnl_j') or '',
        }
        return shlex.split(template.format(**replacements))

    def _run_ntfs_log_tracker(
        self,
        file_path: str,
        source_file: str,
        hostname: str,
        companions: Dict[str, Optional[str]],
    ) -> Dict[str, Any]:
        command_template = os.environ.get(self.LOG_TRACKER_ENV, '').strip()
        result = self._new_log_tracker_result(
            'backend_unavailable',
            f'{self.LOG_TRACKER_BACKEND} metadata only; {self.LOG_TRACKER_ENV} is not configured.',
        )
        result['companion_artifacts'] = {
            'mft': bool(companions.get('mft')),
            'usnjrnl_j': bool(companions.get('usnjrnl_j')),
        }
        if not command_template:
            result['parser_statuses'].extend(self._companion_statuses(result['companion_artifacts']))
            return result

        with tempfile.TemporaryDirectory(prefix='casescope_ntfs_log_tracker_') as output_dir:
            command = self._build_log_tracker_command(
                command_template,
                file_path=file_path,
                output_dir=output_dir,
                companions=companions,
            )
            result['decoder'] = self.LOG_TRACKER_SOURCE
            try:
                subprocess.run(
                    command,
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=1800,
                )
            except subprocess.CalledProcessError as exc:
                result['status'] = 'backend_error'
                result['warning'] = f'{self.LOG_TRACKER_BACKEND} failed: {exc.stderr or exc.stdout or exc}'
                result['parser_statuses'] = ['backend_error']
                result['parser_statuses'].extend(self._companion_statuses(result['companion_artifacts']))
                return result
            except (OSError, subprocess.TimeoutExpired) as exc:
                result['status'] = 'backend_error'
                result['warning'] = f'{self.LOG_TRACKER_BACKEND} could not run: {exc}'
                result['parser_statuses'] = ['backend_error']
                result['parser_statuses'].extend(self._companion_statuses(result['companion_artifacts']))
                return result

            rows = self._read_log_tracker_outputs(output_dir)
            result['total_records'] = len(rows)
            for index, row in enumerate(rows):
                if len(result['children']) >= self.LOG_TRACKER_MAX_CHILD_EVENTS:
                    result['records_limited'] = True
                    break
                child = self._normalize_log_tracker_row(
                    row,
                    source_file=source_file,
                    file_path=file_path,
                    hostname=hostname,
                    index=index,
                    companion_artifacts=result['companion_artifacts'],
                )
                if child is None:
                    result['skipped_record_count'] += 1
                    continue
                result['children'].append(child)
                result['decoded_record_count'] += 1

        if result['decoded_record_count'] == 0:
            result['status'] = 'metadata_only'
            result['warning'] = f'{self.LOG_TRACKER_BACKEND} completed without normalized $LogFile events.'
        elif result['skipped_record_count'] or result['records_limited']:
            result['status'] = 'partial_decode'
            result['warning'] = (
                f"{self.LOG_TRACKER_BACKEND} partial decode: {result['decoded_record_count']} events emitted, "
                f"{result['skipped_record_count']} records skipped."
            )
        else:
            result['status'] = 'decoded'
            result['warning'] = f"{self.LOG_TRACKER_BACKEND} decoded {result['decoded_record_count']} events."
        result['parser_statuses'] = [result['status']]
        result['parser_statuses'].extend(self._companion_statuses(result['companion_artifacts']))
        if any(
            json.loads(child.extra_fields).get('parser_status') == 'path_resolution_partial'
            for child in result['children']
        ):
            result['parser_statuses'].append('path_resolution_partial')
        result['parser_statuses'] = list(dict.fromkeys(result['parser_statuses']))
        return result

    def _companion_statuses(self, companion_artifacts: Dict[str, bool]) -> List[str]:
        statuses = []
        if not companion_artifacts.get('mft'):
            statuses.append('missing_companion_mft')
        if not companion_artifacts.get('usnjrnl_j'):
            statuses.append('missing_companion_usnjrnl')
        return statuses

    def _read_log_tracker_outputs(self, output_dir: str) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        preferred_files: List[str] = []
        fallback_files: List[str] = []
        for dirpath, _, filenames in os.walk(output_dir):
            for filename in filenames:
                candidate = os.path.join(dirpath, filename)
                lower = filename.lower()
                if lower in ('ntfs_logfile_events.csv', 'casescope_ntfs_logfile_events.csv'):
                    preferred_files.append(candidate)
                elif lower.endswith('.csv'):
                    fallback_files.append(candidate)
                elif lower.endswith(('.db', '.sqlite', '.sqlite3')):
                    fallback_files.append(candidate)
        output_files = preferred_files or [
            candidate for candidate in fallback_files
            if os.path.basename(candidate).lower() not in {
                'ntfsparse_transactions.csv',
                'logfile_transactions.csv',
                'logfile.csv',
            }
        ]
        for candidate in output_files:
            lower = candidate.lower()
            if lower.endswith('.csv'):
                rows.extend(self._read_log_tracker_csv(candidate))
            elif lower.endswith(('.db', '.sqlite', '.sqlite3')):
                rows.extend(self._read_log_tracker_sqlite(candidate))
        return rows

    def _read_log_tracker_csv(self, file_path: str) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        with open(file_path, newline='', encoding='utf-8-sig', errors='replace') as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                if row:
                    rows.append({str(key or '').strip(): value for key, value in row.items()})
        return rows

    def _read_log_tracker_sqlite(self, file_path: str) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        with sqlite3.connect(file_path) as conn:
            table_names = [
                table_row[0]
                for table_row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            ]
            for table_name in table_names:
                try:
                    cursor = conn.execute(f'SELECT * FROM "{table_name}"')
                except sqlite3.Error:
                    continue
                columns = [description[0] for description in cursor.description or []]
                for values in cursor.fetchall():
                    row = dict(zip(columns, values))
                    row.setdefault('backend_table', table_name)
                    rows.append(row)
        return rows

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return
        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        artifact_type = 'ntfs_logfile' if source_file.lower() == '$logfile' else self.artifact_type
        decode_result = None
        if artifact_type == 'ntfs_logfile':
            companions = self._find_companion_artifacts(file_path)
            decode_result = self._run_ntfs_log_tracker(file_path, source_file, hostname, companions)
        raw_data = {
            'filename': source_file,
            'file_size': os.path.getsize(file_path),
            'metadata_kind': artifact_type,
            'parser_note': 'metadata event; full transaction reconstruction requires NTFS Log Tracker adapter output',
        }
        extra_fields = {'metadata_kind': artifact_type}
        search_parts = [source_file, file_path, artifact_type]
        if decode_result:
            raw_data.update({
                'source_artifact_type': 'ntfs_logfile',
                'source_parser': self.LOG_TRACKER_SOURCE,
                'parser_status': decode_result['status'],
                'parser_statuses': decode_result['parser_statuses'],
                'parser_warning': decode_result['warning'],
                'decoder': decode_result['decoder'],
                'total_record_count': decode_result['total_records'],
                'decoded_record_count': decode_result['decoded_record_count'],
                'skipped_record_count': decode_result['skipped_record_count'],
                'records_limited': decode_result['records_limited'],
                'companion_artifacts': decode_result['companion_artifacts'],
            })
            extra_fields.update({
                'parent_event_type': 'ntfs_logfile_metadata',
                'source_artifact_type': 'ntfs_logfile',
                'source_parser': self.LOG_TRACKER_SOURCE,
                'parser_status': decode_result['status'],
                'parser_statuses': decode_result['parser_statuses'],
                'parser_warning': decode_result['warning'],
                'decoder': decode_result['decoder'],
                'total_record_count': decode_result['total_records'],
                'decoded_record_count': decode_result['decoded_record_count'],
                'skipped_record_count': decode_result['skipped_record_count'],
                'records_limited': decode_result['records_limited'],
                'companion_artifacts': decode_result['companion_artifacts'],
            })
            search_parts.extend([
                'ntfs logfile',
                self.LOG_TRACKER_SOURCE,
                decode_result['status'],
                *decode_result['parser_statuses'],
            ])
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
            search_blob=' '.join(str(part) for part in search_parts if part),
            extra_fields=json.dumps(extra_fields, default=str),
            parser_version=self.parser_version,
        )
        if decode_result:
            yield from decode_result['children']


class NtfsLogTrackerExportParser(NtfsMetadataParser):
    """Parse exported NTFS Log Tracker CSV/SQLite output as normalized events."""

    ARTIFACT_TYPE = 'ntfs_log_tracker_export'
    EXPORT_SOURCE = 'ntfs_log_tracker_export'
    EXPORT_BACKEND = 'NTFS Log Tracker Export'
    EXPORT_EXTENSIONS = {'.csv', '.db', '.sqlite', '.sqlite3'}
    EXPORT_FILENAME_HINTS = (
        'ntfs_log_tracker',
        'ntfs-log-tracker',
        'ntfslogtracker',
        'ntfs_logfile_events',
        'casescope_ntfs_logfile_events',
        'logfile',
    )

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        if not os.path.isfile(file_path):
            return False
        filename = os.path.basename(file_path).lower()
        extension = os.path.splitext(filename)[1].lower()
        if extension not in self.EXPORT_EXTENSIONS:
            return False
        if not any(hint in filename for hint in self.EXPORT_FILENAME_HINTS):
            return False
        return any(self._row_has_log_tracker_semantics(row) for row in self._read_export_preview(file_path))

    def _read_export_preview(self, file_path: str, limit: int = 25) -> List[Dict[str, Any]]:
        extension = os.path.splitext(file_path)[1].lower()
        try:
            if extension == '.csv':
                rows: List[Dict[str, Any]] = []
                with open(file_path, newline='', encoding='utf-8-sig', errors='replace') as handle:
                    reader = csv.DictReader(handle)
                    for row in reader:
                        if row:
                            rows.append({str(key or '').strip(): value for key, value in row.items()})
                        if len(rows) >= limit:
                            break
                return rows
            if extension in {'.db', '.sqlite', '.sqlite3'}:
                rows = []
                with sqlite3.connect(file_path) as conn:
                    table_names = [
                        table_row[0]
                        for table_row in conn.execute(
                            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                        )
                    ]
                    for table_name in table_names:
                        cursor = conn.execute(f'SELECT * FROM "{table_name}" LIMIT {int(limit)}')
                        columns = [description[0] for description in cursor.description or []]
                        for values in cursor.fetchall():
                            row = dict(zip(columns, values))
                            row.setdefault('backend_table', table_name)
                            rows.append(row)
                            if len(rows) >= limit:
                                return rows
                return rows
        except (OSError, csv.Error, sqlite3.Error):
            return []
        return []

    def _read_export_rows(self, file_path: str) -> List[Dict[str, Any]]:
        extension = os.path.splitext(file_path)[1].lower()
        if extension == '.csv':
            return self._read_log_tracker_csv(file_path)
        if extension in {'.db', '.sqlite', '.sqlite3'}:
            return self._read_log_tracker_sqlite(file_path)
        return []

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return

        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        companions = self._find_companion_artifacts(file_path)
        companion_artifacts = {
            'mft': bool(companions.get('mft')),
            'usnjrnl_j': bool(companions.get('usnjrnl_j')),
        }
        rows = self._read_export_rows(file_path)
        children: List[ParsedEvent] = []
        skipped_record_count = 0
        records_limited = False
        for index, row in enumerate(rows):
            if len(children) >= self.LOG_TRACKER_MAX_CHILD_EVENTS:
                records_limited = True
                break
            child = self._normalize_log_tracker_row(
                row,
                source_file=source_file,
                file_path=file_path,
                hostname=hostname,
                index=index,
                companion_artifacts=companion_artifacts,
            )
            if child is None:
                skipped_record_count += 1
                continue
            child_extra = json.loads(child.extra_fields)
            child_extra.update({
                'source_parser': self.EXPORT_SOURCE,
                'backend_tool': self.EXPORT_BACKEND,
                'source_artifact_type': self.ARTIFACT_TYPE,
                'export_source_file': source_file,
            })
            child_raw = json.loads(child.raw_json)
            child_raw.update({
                'source_parser': self.EXPORT_SOURCE,
                'backend_tool': self.EXPORT_BACKEND,
                'source_artifact_type': self.ARTIFACT_TYPE,
                'export_source_file': source_file,
            })
            child.extra_fields = json.dumps(child_extra, default=str)
            child.raw_json = json.dumps(child_raw, default=str)
            children.append(child)

        parser_status = 'decoded' if children else 'metadata_only'
        if skipped_record_count or records_limited:
            parser_status = 'partial_decode' if children else 'metadata_only'
        parser_statuses = [parser_status, *self._companion_statuses(companion_artifacts)]
        if any(json.loads(child.extra_fields).get('parser_status') == 'path_resolution_partial' for child in children):
            parser_statuses.append('path_resolution_partial')
        parser_statuses = list(dict.fromkeys(parser_statuses))
        warning = (
            f"{self.EXPORT_BACKEND} decoded {len(children)} events from exported output."
            if children else
            f"{self.EXPORT_BACKEND} did not contain normalized NTFS $LogFile events."
        )
        if skipped_record_count or records_limited:
            warning = (
                f"{self.EXPORT_BACKEND} partial decode: {len(children)} events emitted, "
                f"{skipped_record_count} records skipped."
            )

        raw_data = {
            'filename': source_file,
            'file_size': os.path.getsize(file_path),
            'metadata_kind': self.ARTIFACT_TYPE,
            'source_artifact_type': self.ARTIFACT_TYPE,
            'source_parser': self.EXPORT_SOURCE,
            'parser_status': parser_status,
            'parser_statuses': parser_statuses,
            'parser_warning': warning,
            'decoder': self.EXPORT_SOURCE,
            'total_record_count': len(rows),
            'decoded_record_count': len(children),
            'skipped_record_count': skipped_record_count,
            'records_limited': records_limited,
            'companion_artifacts': companion_artifacts,
        }
        extra_fields = {
            'parent_event_type': 'ntfs_log_tracker_export_metadata',
            'source_artifact_type': self.ARTIFACT_TYPE,
            'source_parser': self.EXPORT_SOURCE,
            'backend_tool': self.EXPORT_BACKEND,
            'parser_status': parser_status,
            'parser_statuses': parser_statuses,
            'parser_warning': warning,
            'decoder': self.EXPORT_SOURCE,
            'total_record_count': len(rows),
            'decoded_record_count': len(children),
            'skipped_record_count': skipped_record_count,
            'records_limited': records_limited,
            'companion_artifacts': companion_artifacts,
        }
        search_parts = [
            source_file,
            file_path,
            self.ARTIFACT_TYPE,
            self.EXPORT_SOURCE,
            parser_status,
            *parser_statuses,
        ]
        yield ParsedEvent(
            case_id=self.case_id,
            artifact_type=self.ARTIFACT_TYPE,
            timestamp=self.fallback_timestamp(file_path=file_path, reason='ntfs log tracker export uses file mtime'),
            source_file=source_file,
            source_path=file_path,
            source_host=hostname,
            case_file_id=self.case_file_id,
            provider=self.EXPORT_BACKEND,
            target_path=file_path,
            file_size=os.path.getsize(file_path),
            raw_json=json.dumps(raw_data, default=str),
            search_blob=' '.join(str(part) for part in search_parts if part),
            extra_fields=json.dumps(extra_fields, default=str),
            parser_version=self.parser_version,
        )
        yield from children


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
