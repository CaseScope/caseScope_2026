"""Typed native source locators for non-event graph relationship support.

ERK v2 remains mandatory for normalized-event support. Native memory/PCAP rows
use a versioned locator instead of fabricated ERKs.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, Optional

from utils.graph_identity import GraphSourceRefType


LOCATOR_VERSION = 1
NATIVE_SUPPORT_KEY_PREFIX = 'native:v1:'
EVIDENCE_RECORD_KEY_RE = re.compile(r'^erk:v2:[0-9a-f]{64}$')
NATIVE_SUPPORT_KEY_RE = re.compile(
    r'^native:v1:[a-z0-9_]+:[0-9]+:[0-9]+(?::[A-Za-z0-9._:-]+)?$'
)

SOURCE_TYPE_MEMORY_PROCESS = 'memory_process'
SOURCE_TYPE_MEMORY_NETWORK = 'memory_network'
SOURCE_TYPE_MEMORY_MODULE = 'memory_module'
SOURCE_TYPE_MEMORY_SERVICE = 'memory_service'
SOURCE_TYPE_MEMORY_SID = 'memory_sid'
SOURCE_TYPE_ZEEK_DNS = 'zeek_dns'

MEMORY_SOURCE_TYPES = {
    SOURCE_TYPE_MEMORY_PROCESS,
    SOURCE_TYPE_MEMORY_NETWORK,
    SOURCE_TYPE_MEMORY_MODULE,
    SOURCE_TYPE_MEMORY_SERVICE,
    SOURCE_TYPE_MEMORY_SID,
}


def _clean(value: Any) -> str:
    return str(value or '').strip()


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def is_evidence_record_key(value: Any) -> bool:
    return bool(EVIDENCE_RECORD_KEY_RE.fullmatch(_clean(value)))


def is_native_support_key(value: Any) -> bool:
    return bool(NATIVE_SUPPORT_KEY_RE.fullmatch(_clean(value)))


def build_native_support_key(
    *,
    source_type: str,
    source_ref_id: int,
    record_id: int,
    extra: str = '',
) -> str:
    source = _clean(source_type).lower()
    if not source:
        raise ValueError('Native support key requires source_type')
    key = f'{NATIVE_SUPPORT_KEY_PREFIX}{source}:{int(source_ref_id)}:{int(record_id)}'
    extra_clean = _clean(extra)
    if extra_clean:
        key = f'{key}:{extra_clean}'
    if not is_native_support_key(key):
        # Fall back to digest when extra contains unsafe characters.
        digest = hashlib.sha256(extra_clean.encode('utf-8')).hexdigest()[:24]
        key = f'{NATIVE_SUPPORT_KEY_PREFIX}{source}:{int(source_ref_id)}:{int(record_id)}:{digest}'
    return key


def build_memory_locator(
    *,
    source_type: str,
    case_id: int,
    memory_job_id: int,
    record_id: int,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    if source_type not in MEMORY_SOURCE_TYPES:
        raise ValueError(f'Unsupported memory source_type: {source_type}')
    locator = {
        'locator_version': LOCATOR_VERSION,
        'source_type': source_type,
        'case_id': int(case_id),
        'memory_job_id': int(memory_job_id),
        'record_id': int(record_id),
    }
    if extra:
        locator['extra'] = extra
    return locator


def build_zeek_dns_locator(
    *,
    case_id: int,
    pcap_id: int,
    uid: str,
    trans_id: str = '',
    query: str = '',
    answer: str = '',
    record_identity: str = '',
) -> Dict[str, Any]:
    uid_clean = _clean(uid)
    if not uid_clean:
        raise ValueError('Zeek DNS locator requires uid')
    trans_id_clean = _clean(trans_id)
    if not _clean(record_identity) and not trans_id_clean:
        raise ValueError('Zeek DNS locator requires trans_id or exact record_identity')
    identity = _clean(record_identity) or _stable_json(
        {
            'pcap_id': int(pcap_id),
            'uid': uid_clean,
            'trans_id': trans_id_clean,
            'query': _clean(query).lower(),
            'answer': _clean(answer),
        }
    )
    return {
        'locator_version': LOCATOR_VERSION,
        'source_type': SOURCE_TYPE_ZEEK_DNS,
        'case_id': int(case_id),
        'pcap_id': int(pcap_id),
        'uid': uid_clean,
        'trans_id': trans_id_clean,
        'query': _clean(query),
        'answer': _clean(answer),
        'record_identity': identity,
    }


def support_key_for_locator(locator: Dict[str, Any]) -> str:
    source_type = _clean(locator.get('source_type')).lower()
    if source_type in MEMORY_SOURCE_TYPES:
        return build_native_support_key(
            source_type=source_type,
            source_ref_id=int(locator['memory_job_id']),
            record_id=int(locator['record_id']),
        )
    if source_type == SOURCE_TYPE_ZEEK_DNS:
        digest = hashlib.sha256(_clean(locator.get('record_identity')).encode('utf-8')).hexdigest()[:24]
        return build_native_support_key(
            source_type=source_type,
            source_ref_id=int(locator['pcap_id']),
            record_id=0,
            extra=digest,
        )
    raise ValueError(f'Cannot build support key for source_type={source_type}')


def source_ref_from_locator(locator: Dict[str, Any]) -> tuple[str, int]:
    source_type = _clean(locator.get('source_type')).lower()
    if source_type in MEMORY_SOURCE_TYPES:
        return GraphSourceRefType.MEMORY_JOB, int(locator['memory_job_id'])
    if source_type == SOURCE_TYPE_ZEEK_DNS:
        return GraphSourceRefType.PCAP_FILE, int(locator['pcap_id'])
    raise ValueError(f'Cannot derive source_ref from source_type={source_type}')


def validate_support_provenance(
    *,
    evidence_record_key: str,
    source_table: str,
    support_locator: Optional[Dict[str, Any]] = None,
) -> None:
    """Accept either ERK v2 (events) or a typed native locator (non-events)."""
    key = _clean(evidence_record_key)
    table = _clean(source_table) or 'events'
    if table == 'events' or is_evidence_record_key(key):
        if not is_evidence_record_key(key):
            raise ValueError('Graph relationship provenance requires Evidence Identity v2 key')
        return
    if not support_locator:
        raise ValueError('Native graph support requires a typed support locator')
    if int(support_locator.get('locator_version') or 0) != LOCATOR_VERSION:
        raise ValueError('Unsupported support locator version')
    expected = support_key_for_locator(support_locator)
    if key != expected:
        raise ValueError('Native graph support key does not match locator')
