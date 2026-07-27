"""macOS artifact parsers."""
import gzip
import json
import os
import plistlib
import re
import struct
import zlib
from typing import Any, Dict, Generator, List, Optional

from parsers.base import BaseParser, ParsedEvent

# ASL records are uncompressed, so a generous bound still yields useful text.
# Exceeding it is recorded by _truncation rather than passing unnoticed.
MAX_ASL_BYTES = 64 * 1024 * 1024


def _read_bytes(file_path: str, limit: int = MAX_ASL_BYTES) -> bytes:
    with open(file_path, 'rb') as handle:
        return handle.read(limit)


def _truncation(file_path: str, limit: int) -> Dict[str, Any]:
    """Describe bytes left unread, so a capped payload is not silently partial."""
    try:
        size = os.path.getsize(file_path)
    except OSError:
        return {}
    if size <= limit:
        return {}
    return {'truncated': True, 'bytes_read': limit, 'bytes_total': size}


def _strings(data: bytes, limit: int = 200) -> List[str]:
    seen = []
    for raw in re.findall(rb'[\x20-\x7e]{4,}', data):
        text = raw.decode('utf-8', errors='replace')
        if text not in seen:
            seen.append(text)
        if len(seen) >= limit:
            break
    return seen


class MacPlistParser(BaseParser):
    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'macos_plist'

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        return os.path.isfile(file_path) and file_path.lower().endswith('.plist')

    def _flatten(self, value: Any, prefix: str = '') -> Dict[str, Any]:
        if isinstance(value, dict):
            result = {}
            for key, child in value.items():
                next_prefix = f'{prefix}.{key}' if prefix else str(key)
                result.update(self._flatten(child, next_prefix))
            return result
        if isinstance(value, list):
            # Lists of dictionaries are common in launchd plists; stringifying
            # them buries the nested keys where nothing can search them.
            result: Dict[str, Any] = {}
            scalars = []
            for index, item in enumerate(value[:50]):
                if isinstance(item, (dict, list)):
                    result.update(self._flatten(item, f'{prefix}[{index}]'))
                else:
                    scalars.append(str(item))
            if scalars:
                result[prefix] = scalars
            return result
        return {prefix: str(value)}

    def _command_line(self, values: Dict[str, Any]) -> str:
        """Render ProgramArguments as a command line rather than a Python list."""
        arguments = values.get('ProgramArguments')
        if isinstance(arguments, list):
            return ' '.join(str(argument) for argument in arguments)
        return str(arguments or values.get('Program', '') or '')

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        try:
            with open(file_path, 'rb') as handle:
                plist = plistlib.load(handle)
        except Exception as exc:
            self.errors.append(f'Failed to parse plist: {exc}')
            return
        normalized = file_path.replace('\\', '/').lower()
        persistence = any(marker in normalized for marker in ('/launchagents/', '/launchdaemons/', '/startupitems/'))
        payload = {
            'path': file_path,
            'persistence': persistence,
            'keys': list(plist.keys())[:100] if isinstance(plist, dict) else [],
            'values': self._flatten(plist) if isinstance(plist, dict) else {'value': str(plist)},
        }
        yield ParsedEvent(
            case_id=self.case_id,
            artifact_type=self.artifact_type,
            timestamp=self.fallback_timestamp(file_path=file_path, reason='plist uses file mtime'),
            source_file=os.path.basename(file_path),
            source_path=file_path,
            source_host=self.extract_hostname(file_path),
            case_file_id=self.case_file_id,
            event_id='macos_launchd_plist' if persistence else 'macos_plist',
            command_line=self._command_line(payload['values']),
            raw_json=json.dumps(payload, default=str),
            search_blob=self.build_search_blob(payload),
            extra_fields=json.dumps({'persistence': persistence}, default=str),
            parser_version=self.parser_version,
        )


class MacFseventsdParser(BaseParser):
    VERSION = '1.1.0'
    ARTIFACT_TYPE = 'macos_fsevents'

    # DLS block magics. Each block holds a run of records: a NUL-terminated
    # path, a 64-bit event ID and a 32-bit flag word, plus a node ID from DLS2.
    DLS_MAGICS = (b'1SLD', b'2SLD', b'3SLD')
    FSEVENT_FLAGS = {
        0x00000001: 'FolderEvent',
        0x00000002: 'Mount',
        0x00000004: 'Unmount',
        0x00000020: 'EndOfTransaction',
        0x00000800: 'LastHardLinkRemoved',
        0x00001000: 'HardLink',
        0x00004000: 'SymbolicLink',
        0x00008000: 'FileEvent',
        0x00010000: 'PermissionChange',
        0x00020000: 'ExtendedAttrModified',
        0x00040000: 'ExtendedAttrRemoved',
        0x00100000: 'DocumentRevision',
        0x00400000: 'ItemCloned',
        0x01000000: 'Created',
        0x02000000: 'Removed',
        0x04000000: 'InodeMetaMod',
        0x08000000: 'Renamed',
        0x10000000: 'Modified',
        0x20000000: 'Exchange',
        0x40000000: 'FinderInfoMod',
        0x80000000: 'FolderCreated',
    }

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        normalized = file_path.replace('\\', '/').lower()
        return os.path.isfile(file_path) and '/.fseventsd/' in normalized

    def _decompress(self, file_path: str) -> Optional[bytes]:
        """Return the decoded block, or None if it could not be decompressed.

        The previous read was capped, which truncated the gzip stream, and the
        failure was swallowed so the compressed bytes were scanned as if they
        were text.
        """
        with open(file_path, 'rb') as handle:
            head = handle.read(2)
            handle.seek(0)
            if head != b'\x1f\x8b':
                return handle.read()
            try:
                # fsevents files can hold several concatenated gzip members
                with gzip.GzipFile(fileobj=handle) as decompressed:
                    return decompressed.read()
            except (OSError, EOFError, zlib.error) as exc:
                self.errors.append(
                    f"{os.path.basename(file_path)} is gzip but could not be decompressed: {exc}"
                )
                return None

    def _decode_flags(self, flags: int) -> List[str]:
        return [name for bit, name in self.FSEVENT_FLAGS.items() if flags & bit]

    def _iter_records(self, data: bytes) -> Generator[Dict[str, Any], None, None]:
        offset = 0
        while offset + 12 <= len(data):
            magic = data[offset:offset + 4]
            if magic not in self.DLS_MAGICS:
                break
            block_length = struct.unpack_from('<I', data, offset + 8)[0]
            if block_length < 12:
                break
            block_end = min(offset + block_length, len(data))
            # Trailing fields after the path: event ID and flags, plus a node ID
            # from DLS2 onwards
            fields_size = 20 if magic in (b'2SLD', b'3SLD') else 12
            cursor = offset + 12

            while cursor < block_end:
                terminator = data.find(b'\x00', cursor, block_end)
                if terminator < 0 or terminator + 1 + fields_size > block_end:
                    break
                path = data[cursor:terminator].decode('utf-8', errors='replace')
                fields = terminator + 1
                event_id = struct.unpack_from('<Q', data, fields)[0]
                flags = struct.unpack_from('<I', data, fields + 8)[0]
                node_id = (
                    struct.unpack_from('<Q', data, fields + 12)[0]
                    if fields_size == 20 else None
                )
                cursor = fields + fields_size

                if path:
                    yield {
                        'path': path,
                        'event_id': event_id,
                        'flags': flags,
                        'flag_names': self._decode_flags(flags),
                        'node_id': node_id,
                        'dls_version': magic.decode('ascii', errors='replace'),
                    }

            offset = block_end

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        data = self._decompress(file_path)
        if data is None:
            return

        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        # fsevents records carry no wall-clock time; the event ID orders them
        timestamp = self.fallback_timestamp(
            file_path=file_path, reason='fsevents records carry no wall clock time'
        )

        emitted = 0
        for record in self._iter_records(data):
            emitted += 1
            yield ParsedEvent(
                case_id=self.case_id,
                artifact_type=self.artifact_type,
                timestamp=timestamp,
                source_file=source_file,
                source_path=file_path,
                source_host=hostname,
                case_file_id=self.case_file_id,
                event_id='macos_fsevents_record',
                target_path=self.safe_str(record['path']),
                raw_json=json.dumps(record, default=str),
                search_blob=' '.join([record['path'], *record['flag_names']]),
                extra_fields=json.dumps({
                    'fsevent_id': record['event_id'],
                    'flag_names': record['flag_names'],
                    'node_id': record['node_id'],
                    'timestamp_synthetic': True,
                }, default=str),
                parser_version=self.parser_version,
            )

        if emitted:
            return

        # Not a DLS block: fall back to reporting the file rather than claiming
        # a successful parse of nothing
        paths = [value for value in _strings(data, limit=1000) if value.startswith('/')]
        self.warnings.append(f"{source_file} held no decodable fsevents records")
        payload = {'path': file_path, 'paths': paths[:500], 'record_count_estimate': len(paths)}
        yield ParsedEvent(
            case_id=self.case_id,
            artifact_type=self.artifact_type,
            timestamp=timestamp,
            source_file=source_file,
            source_path=file_path,
            source_host=hostname,
            case_file_id=self.case_file_id,
            event_id='macos_fsevents_chunk',
            raw_json=json.dumps(payload, default=str),
            search_blob=self.build_search_blob(payload),
            parser_version=self.parser_version,
        )


class MacAslParser(BaseParser):
    VERSION = '1.1.0'
    ARTIFACT_TYPE = 'macos_asl'

    # tracev3 chunk framing: a 32-bit tag, a 32-bit subtag and a 64-bit payload
    # length, padded to an 8-byte boundary.
    TRACEV3_CHUNK_TAGS = {
        0x00001000: 'header',
        0x00006001: 'firehose',
        0x00006002: 'oversize',
        0x00006003: 'statedump',
        0x00006004: 'simpledump',
        0x0000600B: 'catalog',
        0x0000600D: 'chunkset',
    }

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        return os.path.isfile(file_path) and file_path.lower().endswith(('.asl', '.tracev3'))

    def _survey_tracev3(self, file_path: str) -> Dict[str, Any]:
        """Report the chunk inventory without pretending to decode the log.

        The Apple Unified Log stores its messages LZ4 compressed and its format
        strings in separate .uuidtext and dsc catalogs, so a real decode needs a
        dedicated implementation. Scraping ASCII out of the compressed payload
        produced noise rather than log lines, so it is no longer done.
        """
        counts: Dict[str, int] = {}
        chunks = 0
        offset = 0
        size = os.path.getsize(file_path)
        with open(file_path, 'rb') as handle:
            while offset + 16 <= size:
                handle.seek(offset)
                header = handle.read(16)
                if len(header) < 16:
                    break
                tag, _subtag, data_size = struct.unpack('<IIQ', header)
                name = self.TRACEV3_CHUNK_TAGS.get(tag)
                if name is None:
                    break
                counts[name] = counts.get(name, 0) + 1
                chunks += 1
                advance = 16 + data_size
                advance += (-advance) % 8
                if advance <= 0:
                    break
                offset += advance
                if chunks > 100000:
                    break
        return {'chunk_count': chunks, 'chunk_types': counts, 'bytes_scanned': offset}

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        source_file = os.path.basename(file_path)
        is_tracev3 = file_path.lower().endswith('.tracev3')

        if is_tracev3:
            survey = self._survey_tracev3(file_path)
            payload = {
                'path': file_path,
                'file_size': os.path.getsize(file_path),
                'mode': 'tracev3_undecoded',
                'decoded': False,
                'decode_note': (
                    'Apple Unified Log content is LZ4 compressed with its format strings '
                    'held in separate uuidtext and dsc catalogs; a dedicated decoder is required'
                ),
                **survey,
            }
            self.warnings.append(
                f"{source_file} is an Apple Unified Log: {survey['chunk_count']} chunks catalogued "
                f"but message content was not decoded"
            )
        else:
            # ASL records are not compressed, so recovered text is meaningful
            data = _read_bytes(file_path, limit=MAX_ASL_BYTES)
            payload = {
                'path': file_path,
                'file_size': os.path.getsize(file_path),
                'strings': _strings(data, limit=500),
                'mode': 'asl_strings',
                **_truncation(file_path, MAX_ASL_BYTES),
            }

        yield ParsedEvent(
            case_id=self.case_id,
            artifact_type=self.artifact_type,
            timestamp=self.fallback_timestamp(file_path=file_path, reason='macOS log artifact uses file mtime'),
            source_file=source_file,
            source_path=file_path,
            source_host=self.extract_hostname(file_path),
            case_file_id=self.case_file_id,
            event_id='macos_log_artifact',
            raw_json=json.dumps(payload, default=str),
            search_blob=self.build_search_blob(payload),
            parser_version=self.parser_version,
        )
