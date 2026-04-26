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
from typing import Any, Dict, Generator, List, Optional

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

    VERSION = '1.0.0'
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
        try:
            with open(file_path, 'r', encoding='utf-8-sig', errors='replace', newline='') as handle:
                reader = csv.DictReader(handle)
                for index, row in enumerate(reader, 1):
                    timestamp = None
                    for value in row.values():
                        timestamp = self.parse_timestamp(value)
                        if timestamp:
                            break
                    target = row.get('Source') or row.get('source') or row.get('File') or row.get('file') or ''
                    reason = row.get('Reason') or row.get('reason') or row.get('Message') or row.get('message') or ''
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

    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'diagnostic_log'
    EXTENSIONS = {'.etl', '.etlgz', '.odl', '.odlgz', '.loggz', '.aodl', '.odlsent'}

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

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        if not self.can_parse(file_path):
            self.errors.append(f"Cannot parse file: {file_path}")
            return
        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        extension = os.path.splitext(source_file.lower())[1]
        log_family = 'etl_trace' if extension in {'.etl', '.etlgz'} else 'odl_diagnostic'
        sample = self._sample(file_path)
        raw_data = {
            'filename': source_file,
            'extension': extension,
            'log_family': log_family,
            'file_size': os.path.getsize(file_path),
            'sample': sample[:2000],
        }
        yield ParsedEvent(
            case_id=self.case_id,
            artifact_type='etl_trace' if log_family == 'etl_trace' else self.artifact_type,
            timestamp=self.fallback_timestamp(file_path=file_path, reason='diagnostic log uses file mtime'),
            source_file=source_file,
            source_path=file_path,
            source_host=hostname,
            case_file_id=self.case_file_id,
            provider=log_family,
            target_path=file_path,
            file_size=raw_data['file_size'],
            raw_json=json.dumps(raw_data, default=str),
            search_blob=f"{source_file} {file_path} {log_family} {sample[:1000]}",
            extra_fields=json.dumps({'extension': extension, 'log_family': log_family}),
            parser_version=self.parser_version,
        )


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
