"""Deterministic IOC text normalization helpers shared across the stack."""

from __future__ import annotations

import re
from typing import Any, Optional, Tuple


DEFANG_PATTERNS = [
    (re.compile(r'hxxps://', re.I), 'https://'),
    (re.compile(r'hxxp://', re.I), 'http://'),
    (re.compile(r'hxxps\[://\]', re.I), 'https://'),
    (re.compile(r'hxxp\[://\]', re.I), 'http://'),
    (re.compile(r'hxxps\[:\]//', re.I), 'https://'),
    (re.compile(r'hxxp\[:\]//', re.I), 'http://'),
    (re.compile(r'\[://\]'), '://'),
    (re.compile(r'\[:\]//'), '://'),
    (re.compile(r'\[\.+\]'), '.'),
    (re.compile(r'\(\.+\)'), '.'),
    (re.compile(r'\{\.+\}'), '.'),
    (re.compile(r'\[dot\]', re.I), '.'),
    (re.compile(r'\(dot\)', re.I), '.'),
    (re.compile(r'\{dot\}', re.I), '.'),
    (re.compile(r'\[d0t\]', re.I), '.'),
    (re.compile(r'\(d0t\)', re.I), '.'),
    (re.compile(r'\[at\]', re.I), '@'),
    (re.compile(r'\(at\)', re.I), '@'),
    (re.compile(r'\[@\]'), '@'),
    (re.compile(r'\{at\}', re.I), '@'),
    (re.compile(r'\[:\]'), ':'),
    (re.compile(r'\(:\)'), ':'),
]

HUNTRESS_PATH_SUFFIX_PATTERN = re.compile(
    r'\s+\+\s+(?:pid|sha256|name|parameters|value|remediation)(?::.*)?$',
    re.IGNORECASE,
)
TRAILING_FILE_STATUS_NOTE_PATTERN = re.compile(
    r'^(?P<path>.*?\.[A-Za-z0-9]{1,8})\s+\((?P<note>'
    r'quarantined by [^)]+|blocked by [^)]+|deleted by [^)]+|'
    r'removed by [^)]+|detected by [^)]+'
    r')\)$',
    re.IGNORECASE,
)


def _defang_text(value: str) -> str:
    """Normalize common defanged IOC encodings."""
    if not isinstance(value, str):
        return value
    for pattern, replacement in DEFANG_PATTERNS:
        value = pattern.sub(replacement, value)
    return value


def _normalize_extracted_file_path(value: Any) -> Tuple[Optional[str], str]:
    """Strip Huntress remediation/status annotations from a captured file path."""
    if value is None:
        return None, ''

    cleaned = str(value).strip().strip('"').strip("'").rstrip('.,;: ')
    if not cleaned:
        return None, ''

    note = ''
    note_match = TRAILING_FILE_STATUS_NOTE_PATTERN.match(cleaned)
    if note_match:
        cleaned = note_match.group('path').strip()
        note = note_match.group('note').strip()

    cleaned = HUNTRESS_PATH_SUFFIX_PATTERN.sub('', cleaned)
    cleaned = cleaned.replace('\\\\', '\\').rstrip('.,;: ')

    return (cleaned or None), note
