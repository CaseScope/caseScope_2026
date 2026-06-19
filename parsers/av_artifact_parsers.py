"""On-disk antivirus artifact parsers."""
import json
import os
import re
from typing import Dict, Generator, List

from parsers.base import BaseParser, ParsedEvent


def _extract_printable_strings(data: bytes, limit: int = 200) -> List[str]:
    ascii_strings = re.findall(rb'[\x20-\x7e]{4,}', data)
    utf16_strings = re.findall((rb'(?:[\x20-\x7e]\x00){4,}'), data)
    values = [item.decode('utf-8', errors='replace') for item in ascii_strings]
    values.extend(item.decode('utf-16-le', errors='replace').rstrip('\x00') for item in utf16_strings)
    seen = []
    for value in values:
        cleaned = ' '.join(value.split())
        if cleaned and cleaned not in seen:
            seen.append(cleaned)
        if len(seen) >= limit:
            break
    return seen


class DefenderDetectionHistoryParser(BaseParser):
    """Best-effort parser for Defender DetectionHistory binary records."""

    VERSION = '1.0.0'
    ARTIFACT_TYPE = 'defender_detectionhistory'

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        normalized = file_path.replace('\\', '/').lower()
        return os.path.isfile(file_path) and '/detectionhistory/' in normalized

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        if not self.can_parse(file_path):
            self.errors.append(f'Cannot parse file: {file_path}')
            return

        with open(file_path, 'rb') as handle:
            data = handle.read()

        strings = _extract_printable_strings(data)
        threat_terms = [s for s in strings if any(token in s.lower() for token in ('threat', 'trojan', 'virus', 'malware', 'hacktool', 'pua:'))]
        paths = [s for s in strings if '\\' in s or '/' in s][:25]
        hashes = re.findall(r'\b[a-fA-F0-9]{32,64}\b', ' '.join(strings))[:25]
        payload = {
            'artifact': 'Defender DetectionHistory',
            'strings': strings[:100],
            'threat_terms': threat_terms[:25],
            'paths': paths,
            'hashes': hashes,
            'byte_length': len(data),
        }
        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        yield ParsedEvent(
            case_id=self.case_id,
            artifact_type=self.artifact_type,
            timestamp=self.fallback_timestamp(file_path=file_path, reason='DetectionHistory binary uses file mtime'),
            source_file=source_file,
            source_path=file_path,
            source_host=hostname,
            case_file_id=self.case_file_id,
            provider='Microsoft Defender',
            event_id='defender_detectionhistory_record',
            target_path=paths[0] if paths else '',
            rule_title=' | '.join(threat_terms[:3]),
            file_hash_sha256=next((h for h in hashes if len(h) == 64), ''),
            raw_json=json.dumps(payload, default=str),
            search_blob=self.build_search_blob(payload),
            extra_fields=json.dumps({'parser_mode': 'binary_strings'}, default=str),
            parser_version=self.parser_version,
        )


class MpLogParser(BaseParser):
    """Parse Microsoft Defender MPLog text logs."""

    VERSION = '1.0.1'
    ARTIFACT_TYPE = 'defender_mplog'
    TS_RE = re.compile(r'(?P<ts>\d{4}-\d{2}-\d{2}T?\s?\d{2}:\d{2}:\d{2}(?:\.\d+)?)')

    @property
    def artifact_type(self) -> str:
        return self.ARTIFACT_TYPE

    def can_parse(self, file_path: str) -> bool:
        filename = os.path.basename(file_path).lower()
        return os.path.isfile(file_path) and filename.startswith('mplog') and filename.endswith(('.log', '.txt'))

    def _line_timestamp(self, line: str, file_path: str):
        match = self.TS_RE.search(line)
        if match:
            parsed = self.parse_timestamp(match.group('ts').replace('T ', ' '))
            if parsed:
                return parsed
        return self.fallback_timestamp(file_path=file_path, reason='MPLog line missing timestamp')

    def _read_lines(self, file_path: str) -> List[str]:
        with open(file_path, 'rb') as handle:
            data = handle.read()

        sample = data[:4096]
        nul_ratio = (sample.count(b'\x00') / len(sample)) if sample else 0
        encodings = ['utf-8-sig']
        if data.startswith((b'\xff\xfe', b'\xfe\xff')) or nul_ratio > 0.1:
            encodings = ['utf-16', 'utf-16-le', 'utf-8-sig']

        for encoding in encodings:
            try:
                text = data.decode(encoding)
                break
            except UnicodeDecodeError:
                continue
        else:
            text = data.decode('utf-8', errors='replace')

        return [
            ' '.join(line.replace('\x00', '').split())
            for line in text.splitlines()
        ]

    def parse(self, file_path: str) -> Generator[ParsedEvent, None, None]:
        if not self.can_parse(file_path):
            self.errors.append(f'Cannot parse file: {file_path}')
            return

        source_file = os.path.basename(file_path)
        hostname = self.extract_hostname(file_path)
        for line_num, line in enumerate(self._read_lines(file_path), 1):
            if not line:
                continue
            lowered = line.lower()
            action = 'log'
            for keyword in ('threat', 'quarantine', 'remediation', 'scan', 'signature', 'error'):
                if keyword in lowered:
                    action = keyword
                    break
            payload: Dict[str, object] = {
                'line_number': line_num,
                'action': action,
                'message': line,
            }
            yield ParsedEvent(
                case_id=self.case_id,
                artifact_type=self.artifact_type,
                timestamp=self._line_timestamp(line, file_path),
                source_file=source_file,
                source_path=file_path,
                source_host=hostname,
                case_file_id=self.case_file_id,
                provider='Microsoft Defender',
                event_id=f'defender_mplog_{action}',
                raw_json=json.dumps(payload, default=str),
                search_blob=self.build_search_blob(payload),
                extra_fields=json.dumps({'action': action}, default=str),
                parser_version=self.parser_version,
            )
