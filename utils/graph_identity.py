"""Deterministic identity contracts for the investigative graph."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import posixpath
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from urllib.parse import quote, unquote, urlsplit, urlunsplit


class GraphEntityType:
    HOST = 'HOST'
    USER = 'USER'
    PROCESS = 'PROCESS'
    FILE_PATH = 'FILE_PATH'
    FILE_HASH = 'FILE_HASH'
    IP_ADDRESS = 'IP_ADDRESS'
    DOMAIN = 'DOMAIN'
    URL = 'URL'
    REGISTRY_KEY = 'REGISTRY_KEY'
    SERVICE = 'SERVICE'
    LOGON_SESSION = 'LOGON_SESSION'

    ALL = {
        HOST,
        USER,
        PROCESS,
        FILE_PATH,
        FILE_HASH,
        IP_ADDRESS,
        DOMAIN,
        URL,
        REGISTRY_KEY,
        SERVICE,
        LOGON_SESSION,
    }


class GraphRelationshipType:
    RUNS_IMAGE = 'RUNS_IMAGE'
    CONNECTED_TO = 'CONNECTED_TO'
    OWNS_IP = 'OWNS_IP'
    LOGGED_ON_TO = 'LOGGED_ON_TO'
    LOGON_AS = 'LOGON_AS'
    ON_HOST = 'ON_HOST'
    HAD_CONTENT = 'HAD_CONTENT'
    REFERENCES = 'REFERENCES'

    ALL = {
        RUNS_IMAGE,
        CONNECTED_TO,
        OWNS_IP,
        LOGGED_ON_TO,
        LOGON_AS,
        ON_HOST,
        HAD_CONTENT,
        REFERENCES,
    }


class GraphDerivationType:
    OBSERVED = 'OBSERVED'
    DETERMINISTIC = 'DETERMINISTIC'
    ANALYST_ASSERTED = 'ANALYST_ASSERTED'
    INFERRED = 'INFERRED'
    MODEL_SUGGESTED = 'MODEL_SUGGESTED'

    AUTHORITATIVE_EXTRACTOR_TYPES = {OBSERVED, DETERMINISTIC}


class GraphValidationState:
    ACTIVE = 'ACTIVE'
    INVALIDATED = 'INVALIDATED'


@dataclass(frozen=True)
class EntitySpec:
    entity_type: str
    raw_value: str
    display_value: str = ''
    hints: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EntityIdentity:
    entity_type: str
    entity_key: str
    display_value: str
    canonical_value: str
    metadata: Dict[str, Any] = field(default_factory=dict)


def _clean(value: Any) -> str:
    return str(value or '').strip()


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def _short_digest(value: Any) -> str:
    return hashlib.sha256(_stable_json(value).encode('utf-8')).hexdigest()[:24]


def normalize_hostname(value: Any) -> str:
    hostname = _clean(value).rstrip('.')
    return hostname.upper()


def normalize_user_authority(value: Any) -> str:
    return _clean(value).upper()


def normalize_username(value: Any) -> str:
    return _clean(value).upper()


def normalize_windows_path(value: Any) -> str:
    path = _clean(value).replace('/', '\\')
    path = re.sub(r'\\+', r'\\', path)
    if len(path) >= 2 and path[1] == ':':
        path = path[0].upper() + path[1:]
    # Windows paths are case-insensitive for the supported initial sources.
    return path.upper()


def normalize_file_hash(algorithm: Any, value: Any) -> tuple[str, str]:
    algo = _clean(algorithm).lower()
    digest = _clean(value).lower()
    expected_lengths = {'md5': 32, 'sha1': 40, 'sha256': 64}
    if algo not in expected_lengths:
        raise ValueError(f'Unsupported hash algorithm: {algorithm}')
    if not re.fullmatch(r'[0-9a-f]+', digest) or len(digest) != expected_lengths[algo]:
        raise ValueError(f'Invalid {algo} hash value')
    return algo, digest


def normalize_ip(value: Any) -> str:
    return str(ipaddress.ip_address(_clean(value)))


def normalize_domain(value: Any) -> str:
    domain = _clean(value).rstrip('.').lower()
    if not domain or any(part == '' for part in domain.split('.')):
        raise ValueError('Invalid domain value')
    return domain


def normalize_url(value: Any) -> str:
    raw = _clean(value)
    parts = urlsplit(raw)
    scheme = parts.scheme.lower()
    netloc = parts.netloc.lower()
    path = quote(unquote(parts.path or ''), safe='/%:@')
    # Preserve query ordering and fragments; both can be semantically meaningful.
    return urlunsplit((scheme, netloc, path, parts.query, parts.fragment))


REGISTRY_ROOT_ALIASES = {
    'HKLM': 'HKEY_LOCAL_MACHINE',
    'HKCU': 'HKEY_CURRENT_USER',
    'HKCR': 'HKEY_CLASSES_ROOT',
    'HKU': 'HKEY_USERS',
    'HKCC': 'HKEY_CURRENT_CONFIG',
}


def normalize_registry_key(value: Any) -> str:
    key = _clean(value).replace('/', '\\')
    key = re.sub(r'\\+', r'\\', key).strip('\\')
    if not key:
        raise ValueError('Invalid registry key value')
    parts = key.split('\\', 1)
    root = REGISTRY_ROOT_ALIASES.get(parts[0].upper(), parts[0].upper())
    remainder = parts[1] if len(parts) > 1 else ''
    return f'{root}\\{remainder}'.upper() if remainder else root


def build_host_entity(
    hostname: Any = '',
    *,
    known_system_id: Optional[int] = None,
    source_context: Any = '',
) -> EntityIdentity:
    display = _clean(hostname) or f'Known system {known_system_id}'
    if known_system_id is not None:
        key = f'known_system:{int(known_system_id)}'
        canonical = key
        strategy = 'known_system'
    else:
        normalized = normalize_hostname(hostname)
        if not normalized:
            raise ValueError('Host identity requires hostname or known_system_id')
        context = _clean(source_context)
        if not context:
            raise ValueError('Observed host identity requires source context')
        key = f'observed_host:{_short_digest({"host": normalized, "context": context})}'
        canonical = normalized
        strategy = 'observed_host_with_source_context'
    return EntityIdentity(
        GraphEntityType.HOST,
        key,
        display,
        canonical,
        {'identity_strategy': strategy, 'observed_hostname': _clean(hostname), 'source_context': _clean(source_context)},
    )


def build_user_entity(username: Any = '', *, sid: Any = '', domain: Any = '', host_key: Any = '') -> EntityIdentity:
    sid_value = _clean(sid).upper()
    user_value = normalize_username(username)
    domain_value = normalize_user_authority(domain)
    if sid_value:
        key = f'sid:{sid_value}'
        canonical = sid_value
        strategy = 'sid'
    elif domain_value and user_value:
        key = f'authority:{domain_value}:user:{user_value}'
        canonical = f'{domain_value}\\{user_value}'
        strategy = 'authority_username'
    elif host_key and user_value:
        key = f'local:{_clean(host_key)}:user:{user_value}'
        canonical = f'{_clean(host_key)}\\{user_value}'
        strategy = 'host_local_username'
    else:
        raise ValueError('User identity requires SID or scoped username authority')
    display = _clean(username) or canonical
    if domain_value and user_value and '\\' not in display and '@' not in display:
        display = f'{domain_value}\\{display}'
    return EntityIdentity(
        GraphEntityType.USER,
        key,
        display,
        canonical,
        {'identity_strategy': strategy, 'sid': sid_value, 'domain': domain_value, 'username': user_value},
    )


def build_process_entity(
    *,
    host_key: Any,
    pid: Any,
    start_time: Any = '',
    evidence_record_key: Any = '',
    process_name: Any = '',
    process_path: Any = '',
) -> EntityIdentity:
    host = _clean(host_key)
    if not host:
        raise ValueError('Process identity requires host identity')
    try:
        pid_int = int(pid)
    except (TypeError, ValueError):
        raise ValueError('Process identity requires PID')
    if pid_int < 0:
        raise ValueError('Process identity requires non-negative PID')
    start_anchor = _clean(start_time)
    evidence_anchor = _clean(evidence_record_key)
    if start_anchor:
        anchor_type = 'start_time'
        anchor = start_anchor
    elif evidence_anchor:
        anchor_type = 'evidence_record_key'
        anchor = evidence_anchor
    else:
        raise ValueError('Process identity requires start time or durable evidence anchor')
    key = f'host:{host}:pid:{pid_int}:{anchor_type}:{anchor}'
    name = _clean(process_name) or posixpath.basename(_clean(process_path).replace('\\', '/')) or 'process'
    return EntityIdentity(
        GraphEntityType.PROCESS,
        key,
        f'{name} (PID {pid_int})',
        key,
        {
            'identity_strategy': f'host_pid_{anchor_type}',
            'host_key': host,
            'pid': pid_int,
            'process_name': _clean(process_name),
            'process_path': _clean(process_path),
        },
    )


def build_file_path_entity(path: Any, *, host_key: Any = '') -> EntityIdentity:
    normalized = normalize_windows_path(path)
    scope = _clean(host_key)
    key = f'host:{scope}:path:{normalized}' if scope else f'path:{normalized}'
    return EntityIdentity(
        GraphEntityType.FILE_PATH,
        key,
        _clean(path),
        normalized,
        {'identity_strategy': 'host_scoped_path' if scope else 'path_value', 'host_key': scope},
    )


def build_file_hash_entity(algorithm: Any, value: Any) -> EntityIdentity:
    algo, digest = normalize_file_hash(algorithm, value)
    key = f'{algo}:{digest}'
    return EntityIdentity(GraphEntityType.FILE_HASH, key, digest, key, {'algorithm': algo})


def build_ip_entity(value: Any) -> EntityIdentity:
    normalized = normalize_ip(value)
    return EntityIdentity(GraphEntityType.IP_ADDRESS, f'ip:{normalized}', normalized, normalized, {})


def build_domain_entity(value: Any) -> EntityIdentity:
    normalized = normalize_domain(value)
    return EntityIdentity(GraphEntityType.DOMAIN, f'domain:{normalized}', _clean(value), normalized, {})


def build_url_entity(value: Any) -> EntityIdentity:
    normalized = normalize_url(value)
    return EntityIdentity(GraphEntityType.URL, f'url:{normalized}', _clean(value), normalized, {})


def build_registry_key_entity(value: Any, *, host_key: Any = '') -> EntityIdentity:
    normalized = normalize_registry_key(value)
    scope = _clean(host_key)
    key = f'host:{scope}:registry:{normalized}' if scope else f'registry:{normalized}'
    return EntityIdentity(
        GraphEntityType.REGISTRY_KEY,
        key,
        _clean(value),
        normalized,
        {'identity_strategy': 'host_scoped_registry_key' if scope else 'registry_key_value', 'host_key': scope},
    )


def build_service_entity(name: Any, *, host_key: Any = '') -> EntityIdentity:
    service = _clean(name)
    if not service:
        raise ValueError('Service identity requires service name')
    scope = _clean(host_key)
    normalized = service.upper()
    key = f'host:{scope}:service:{normalized}' if scope else f'service:{normalized}'
    return EntityIdentity(GraphEntityType.SERVICE, key, service, normalized, {'host_key': scope})


def build_logon_session_entity(logon_id: Any, *, host_key: Any, user_key: Any = '') -> EntityIdentity:
    host = _clean(host_key)
    session = _clean(logon_id).upper()
    if not host or not session:
        raise ValueError('Logon session identity requires host and logon_id')
    user = _clean(user_key)
    key = f'host:{host}:logon_id:{session}:user:{user}' if user else f'host:{host}:logon_id:{session}'
    return EntityIdentity(
        GraphEntityType.LOGON_SESSION,
        key,
        f'Logon {session}',
        key,
        {'host_key': host, 'user_key': user, 'logon_id': session},
    )
