"""macOS artifact parsers."""
import gzip
import json
import os
import plistlib
import re
from typing import Any, Dict, Generator, List

from parsers.base import BaseParser, ParsedEvent


def _read_bytes(file_path: str, limit: int = 2 * 1024 * 1024) -> bytes:
    with open(file_path, 'rb') as handle:
        return handle.read(limit)


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
            return {prefix: [str(item) for item in value[:50]]}
        return {prefix: str(value)}

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
            command_line=str(payload['values'].get('ProgramArguments', '') or payload['values'].get('Program', '')),
            raw_json=json.dumps(payload, default=str),
            search_blob=self.build_search_blob(payload),
            extra_fields=json.dumps({'persistence': persistence}, default=str),
            parser_version=self.parser_version,
        )


class MacFseventsdParser(BaseParser):
    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'macos_fsevents'

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        normalized = file_path.replace('\\', '/').lower()
        return os.path.isfile(file_path) and '/.fseventsd/' in normalized

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        data = _read_bytes(file_path, limit=4 * 1024 * 1024)
        if data.startswith(b'\x1f\x8b'):
            try:
                data = gzip.decompress(data)
            except Exception:
                pass
        paths = [value for value in _strings(data, limit=1000) if value.startswith('/')]
        payload = {'path': file_path, 'paths': paths[:500], 'record_count_estimate': len(paths)}
        yield ParsedEvent(
            case_id=self.case_id,
            artifact_type=self.artifact_type,
            timestamp=self.fallback_timestamp(file_path=file_path, reason='fsevents chunk uses file mtime'),
            source_file=os.path.basename(file_path),
            source_path=file_path,
            source_host=self.extract_hostname(file_path),
            case_file_id=self.case_file_id,
            event_id='macos_fsevents_chunk',
            raw_json=json.dumps(payload, default=str),
            search_blob=self.build_search_blob(payload),
            parser_version=self.parser_version,
        )


class MacAslParser(BaseParser):
    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'macos_asl'

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        return os.path.isfile(file_path) and file_path.lower().endswith(('.asl', '.tracev3'))

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        data = _read_bytes(file_path, limit=2 * 1024 * 1024)
        payload = {
            'path': file_path,
            'strings': _strings(data, limit=500),
            'mode': 'tracev3_flag' if file_path.lower().endswith('.tracev3') else 'asl_strings',
        }
        yield ParsedEvent(
            case_id=self.case_id,
            artifact_type=self.artifact_type,
            timestamp=self.fallback_timestamp(file_path=file_path, reason='macOS log artifact uses file mtime'),
            source_file=os.path.basename(file_path),
            source_path=file_path,
            source_host=self.extract_hostname(file_path),
            case_file_id=self.case_file_id,
            event_id='macos_log_artifact',
            raw_json=json.dumps(payload, default=str),
            search_blob=self.build_search_blob(payload),
            parser_version=self.parser_version,
        )
