"""Cloud AI Privacy Mode alias extraction and vault population."""
from __future__ import annotations

import ipaddress
import json
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable

from models.database import db
from models.privacy_alias import PrivacyAlias, PrivacyAliasCounter

EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
FQDN_RE = re.compile(
    r"\b(?=.{4,253}\b)(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+"
    r"(?:LOCAL|LAN|INTERNAL|CORP|COM|NET|ORG|EDU|GOV|MIL|IO|CO|US|CA|UK)\b",
    re.IGNORECASE,
)
WINDOWS_ACCOUNT_RE = re.compile(
    r"\b([A-Z0-9_.-]{2,64})\\([A-Z0-9$_.-]{1,128})\b",
    re.IGNORECASE,
)
UNC_RE = re.compile(r"\\\\([^\\/\s]+)\\([^\\/\s]+)(?:\\[^\s'\"]*)?", re.IGNORECASE)
WINDOWS_PROFILE_RE = re.compile(r"(?i)(?:^|[\\/])Users[\\/]([^\\/\s:'\"]+)")
LINUX_HOME_RE = re.compile(r"(?i)(?:^|\s)/home/([^/\s:'\"]+)")
BARE_HOST_CONTEXT_RE = re.compile(
    r"(?ix)"
    r"\b(?:host|hostname|computer|machine|endpoint|workstation)\b"
    r"(?:\s+(?:name|id))?"
    r"\s*(?:"
    r"(?:[:=]|\bis\b)\s*[\"']?([A-Z0-9][A-Z0-9_.-]{1,63})[\"']?"
    r"|[\"']([A-Z0-9][A-Z0-9_.-]{1,63})[\"']"
    r")"
)

SKIP_VALUES = {'', '-', '--', '---', 'none', 'null', 'n/a', 'na', 'unknown', '(null)'}
SKIP_DOMAINS = {'nt authority', 'builtin', 'window manager', 'font driver host'}
SKIP_HOSTS = {'localhost', 'localhost.localdomain'}
FILE_LIKE_SUFFIXES = {'.exe', '.dll', '.sys', '.dat', '.log', '.json', '.csv', '.xml', '.txt'}

STRUCTURED_TEXT_FIELDS = {
    'command_line',
    'process_path',
    'parent_process',
    'target_path',
    'source_path',
    'reg_data',
    'payload_data1',
    'payload_data2',
    'payload_data3',
    'payload_data4',
    'payload_data5',
    'payload_data6',
    'raw_json',
}

EVENT_COLUMNS = [
    'timestamp_utc',
    'username',
    'domain',
    'source_host',
    'remote_host',
    'workstation_name',
    'src_ip',
    'dst_ip',
    'command_line',
    'process_path',
    'parent_process',
    'target_path',
    'source_path',
    'reg_data',
    'payload_data1',
    'payload_data2',
    'payload_data3',
    'payload_data4',
    'payload_data5',
    'payload_data6',
    'raw_json',
]


PRIVACY_SCOPE_CASE_CONTENT = 'case_content'
PRIVACY_SCOPE_NON_CONTENT_ADMIN = 'non_content_admin'
PRIVACY_SCOPE_TEST_ONLY = 'test_only'
PRIVACY_LEVEL_OFF = 'off'
PRIVACY_LEVEL_BASIC = 'basic'
PRIVACY_LEVEL_CMMC_CUI = 'cmmc_cui'
PRIVACY_LEVEL_STRICT = 'strict'
PRIVACY_LEVELS = {
    PRIVACY_LEVEL_OFF,
    PRIVACY_LEVEL_BASIC,
    PRIVACY_LEVEL_CMMC_CUI,
    PRIVACY_LEVEL_STRICT,
}
PRIVACY_ENTITY_TYPES_BY_LEVEL = {
    PRIVACY_LEVEL_OFF: set(),
    PRIVACY_LEVEL_BASIC: {
        'USERNAME', 'ACCOUNT', 'EMAIL', 'HOSTNAME', 'FQDN', 'DOMAIN', 'INTERNAL_IPV4',
    },
    PRIVACY_LEVEL_CMMC_CUI: {
        'USERNAME', 'ACCOUNT', 'EMAIL', 'HOSTNAME', 'FQDN', 'DOMAIN', 'INTERNAL_IPV4',
        'CLIENT_PUBLIC_IPV4', 'TENANT_ID', 'OBJECT_ID', 'SID', 'UNC_PATH', 'SHARE',
        'FILEPATH', 'CLIENT_NAME', 'PERSON_NAME', 'COMPANY_NAME', 'CASE_NAME',
    },
    PRIVACY_LEVEL_STRICT: {
        'USERNAME', 'ACCOUNT', 'EMAIL', 'HOSTNAME', 'FQDN', 'DOMAIN', 'INTERNAL_IPV4',
        'CLIENT_PUBLIC_IPV4', 'TENANT_ID', 'OBJECT_ID', 'SID', 'UNC_PATH', 'SHARE',
        'FILEPATH', 'CLIENT_NAME', 'PERSON_NAME', 'COMPANY_NAME', 'CASE_NAME',
        'EXTERNAL_IPV4', 'EXTERNAL_DOMAIN', 'URL',
    },
}
PRIVACY_CACHE_TTL_SECONDS = 60
_ALIAS_CACHE: dict[tuple[int, str], tuple[float, list[PrivacyAlias]]] = {}
STRUCTURAL_AI_PAYLOAD_KEYS = {
    'role',
    'type',
    'id',
    'name',
    'tool_call_id',
    'tool_name',
    'cache_control',
    'tool_choice',
    'required_params',
    'approval_options',
    'permission',
    'tier',
    'provenance',
    'status',
}


class PrivacyContextRequiredError(RuntimeError):
    """Raised when case-content AI egress lacks required privacy context."""

    error_code = 'privacy_context_required'


@dataclass(frozen=True)
class AIPrivacyContext:
    """Machine-readable privacy contract for AI provider egress."""

    case_id: int | None = None
    content_scope: str = PRIVACY_SCOPE_CASE_CONTENT
    privacy_level: str | None = None
    retention_policy: str = 'store_aliased'
    allow_local_bypass: bool = False
    tenant_id: str | None = None

    @classmethod
    def case_content(
        cls,
        case_id: int,
        *,
        privacy_level: str | None = None,
        retention_policy: str = 'store_aliased',
        allow_local_bypass: bool = False,
        tenant_id: str | None = None,
    ) -> 'AIPrivacyContext':
        return cls(
            case_id=case_id,
            content_scope=PRIVACY_SCOPE_CASE_CONTENT,
            privacy_level=privacy_level,
            retention_policy=retention_policy,
            allow_local_bypass=allow_local_bypass,
            tenant_id=tenant_id,
        )

    @classmethod
    def non_content_admin(cls) -> 'AIPrivacyContext':
        return cls(case_id=None, content_scope=PRIVACY_SCOPE_NON_CONTENT_ADMIN, privacy_level=PRIVACY_LEVEL_OFF)

    @classmethod
    def test_only(cls) -> 'AIPrivacyContext':
        return cls(case_id=None, content_scope=PRIVACY_SCOPE_TEST_ONLY, privacy_level=PRIVACY_LEVEL_OFF)


@dataclass
class SanitizedPayload:
    """Sanitized payload plus metadata for provider/runtime auditing."""

    value: Any
    metadata: dict[str, Any]


def is_local_provider(provider: Any) -> bool:
    """Return True when a provider is local enough for explicit bypass policy."""
    provider_type = provider.provider_type() if hasattr(provider, 'provider_type') else ''
    if provider_type == 'local':
        return True
    if provider_type == 'openai_compatible' and hasattr(provider, '_is_local_endpoint'):
        try:
            return bool(provider._is_local_endpoint())
        except Exception:
            return False
    return False


def normalize_privacy_level(value: str | None, *, provider_type: str | None = None) -> str:
    """Normalize a configured privacy level, applying conservative defaults."""
    normalized = str(value or '').strip().lower()
    if normalized in PRIVACY_LEVELS:
        return normalized
    if provider_type in {'openai', 'claude'}:
        return PRIVACY_LEVEL_CMMC_CUI
    if provider_type == 'openai_compatible':
        return PRIVACY_LEVEL_BASIC
    return PRIVACY_LEVEL_OFF


def get_configured_privacy_level(provider_type: str | None = None) -> str:
    """Read active AI obfuscation level from system settings."""
    try:
        from models.system_settings import SettingKeys, SystemSettings
        value = SystemSettings.get(SettingKeys.AI_PRIVACY_OBFUSCATION_LEVEL, None)
    except Exception:
        value = None
    return normalize_privacy_level(value, provider_type=provider_type)


def _effective_privacy_level(context: AIPrivacyContext | None, provider: Any) -> str:
    provider_type = provider.provider_type() if hasattr(provider, 'provider_type') else None
    if context and context.privacy_level:
        return normalize_privacy_level(context.privacy_level, provider_type=provider_type)
    return get_configured_privacy_level(provider_type)


def _allowed_entity_types(level: str) -> set[str]:
    return set(PRIVACY_ENTITY_TYPES_BY_LEVEL.get(normalize_privacy_level(level), set()))


def _privacy_metadata(level: str, context: AIPrivacyContext | None, aliases_applied: int, categories: set[str], duration_ms: int) -> dict[str, Any]:
    return {
        'enabled': level != PRIVACY_LEVEL_OFF,
        'privacy_level': level,
        'case_id': context.case_id if context else None,
        'content_scope': context.content_scope if context else None,
        'aliases_applied': aliases_applied,
        'entity_categories': sorted(categories),
        'duration_ms': duration_ms,
    }


def _ensure_context_allowed(context: AIPrivacyContext | None, provider: Any, level: str) -> None:
    if level == PRIVACY_LEVEL_OFF:
        return
    if context and context.content_scope in {PRIVACY_SCOPE_NON_CONTENT_ADMIN, PRIVACY_SCOPE_TEST_ONLY}:
        return
    if context and context.content_scope == PRIVACY_SCOPE_CASE_CONTENT and context.case_id:
        return
    if is_local_provider(provider) and context and context.allow_local_bypass:
        return
    if not is_local_provider(provider):
        raise PrivacyContextRequiredError('Cloud AI case-content calls require AIPrivacyContext with case_id')


def _string_leaves(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        leaves: list[str] = []
        for item in value.values():
            leaves.extend(_string_leaves(item))
        return leaves
    if isinstance(value, (list, tuple)):
        leaves = []
        for item in value:
            leaves.extend(_string_leaves(item))
        return leaves
    return []


def extract_alias_candidates_from_text(text: Any, *, case_id: int | None = None) -> dict[AliasKey, AliasCandidate]:
    """Extract protected alias candidates from arbitrary AI-bound text."""
    candidates: dict[AliasKey, AliasCandidate] = {}
    _extract_text_entities(candidates, text, 'ai_egress_text', None, None)
    if case_id:
        try:
            from models.case import Case
            case = Case.query.get(case_id)
            if case:
                for attr, entity_type in (
                    ('name', 'CASE_NAME'),
                    ('company', 'COMPANY_NAME'),
                    ('description', 'CLIENT_NAME'),
                ):
                    value = getattr(case, attr, None)
                    if value and str(value).strip() and str(value).strip() in str(text):
                        _add_candidate(candidates, entity_type, value, f'case.{attr}', None)
                client = getattr(case, 'client', None)
                client_name = getattr(client, 'name', None)
                if client_name and str(client_name).strip() in str(text):
                    _add_candidate(candidates, 'CLIENT_NAME', client_name, 'case.client.name', None)
        except Exception:
            pass
    return candidates


def _load_aliases_for_case(case_id: int, level: str) -> list[PrivacyAlias]:
    cache_key = (int(case_id), normalize_privacy_level(level))
    now = time.time()
    cached = _ALIAS_CACHE.get(cache_key)
    if cached and now - cached[0] < PRIVACY_CACHE_TTL_SECONDS:
        return list(cached[1])
    allowed_types = _allowed_entity_types(level)
    if not allowed_types:
        return []
    rows = PrivacyAlias.query.filter(
        PrivacyAlias.case_id == case_id,
        PrivacyAlias.entity_type.in_(sorted(allowed_types)),
    ).all()
    if level == PRIVACY_LEVEL_STRICT:
        rows = [row for row in rows if row.sensitivity_classification != 'threat_intel_preserve']
    _ALIAS_CACHE[cache_key] = (now, list(rows))
    return list(rows)


def _invalidate_alias_cache(case_id: int) -> None:
    for key in list(_ALIAS_CACHE):
        if key[0] == int(case_id):
            _ALIAS_CACHE.pop(key, None)


def _ensure_aliases_for_payload(case_id: int, payload: Any, level: str) -> dict[str, Any]:
    allowed_types = _allowed_entity_types(level)
    if not allowed_types:
        return {'created': 0, 'updated': 0, 'candidate_by_type': {}}
    merged: dict[AliasKey, AliasCandidate] = {}
    for text in _string_leaves(payload):
        _merge_candidate_maps(merged, extract_alias_candidates_from_text(text, case_id=case_id))
    filtered = {key: candidate for key, candidate in merged.items() if key.entity_type in allowed_types}
    if not filtered:
        return {'created': 0, 'updated': 0, 'candidate_by_type': {}}
    summary = upsert_alias_candidates(case_id, filtered, source='ai_privacy_egress_lazy', commit_every=0)
    if summary.get('created') or summary.get('updated'):
        _invalidate_alias_cache(case_id)
    return summary


def _replace_aliases_in_text(text: str, aliases: list[PrivacyAlias]) -> tuple[str, int, set[str]]:
    result = text
    replacements = 0
    categories: set[str] = set()
    for row in sorted(aliases, key=lambda item: len(item.original_value or ''), reverse=True):
        original = row.original_value or ''
        alias = row.alias_value or ''
        if not original or not alias or original not in result:
            continue
        count = result.count(original)
        result = result.replace(original, alias)
        replacements += count
        categories.add(row.entity_type)
    return result, replacements, categories


def _apply_aliases(value: Any, aliases: list[PrivacyAlias], *, parent_key: str | None = None) -> tuple[Any, int, set[str]]:
    if parent_key in STRUCTURAL_AI_PAYLOAD_KEYS:
        return value, 0, set()
    if isinstance(value, str):
        return _replace_aliases_in_text(value, aliases)
    if isinstance(value, dict):
        total = 0
        categories: set[str] = set()
        updated = {}
        for key, item in value.items():
            new_item, count, item_categories = _apply_aliases(item, aliases, parent_key=str(key))
            updated[key] = new_item
            total += count
            categories.update(item_categories)
        return updated, total, categories
    if isinstance(value, list):
        total = 0
        categories: set[str] = set()
        updated_items = []
        for item in value:
            new_item, count, item_categories = _apply_aliases(item, aliases, parent_key=parent_key)
            updated_items.append(new_item)
            total += count
            categories.update(item_categories)
        return updated_items, total, categories
    if isinstance(value, tuple):
        new_list, count, categories = _apply_aliases(list(value), aliases, parent_key=parent_key)
        return tuple(new_list), count, categories
    return value, 0, set()


def sanitize_for_ai_egress(value: Any, *, context: AIPrivacyContext | None, provider: Any) -> SanitizedPayload:
    """Sanitize AI-bound payloads using case-scoped aliases."""
    started = time.time()
    level = _effective_privacy_level(context, provider)
    _ensure_context_allowed(context, provider, level)
    if level == PRIVACY_LEVEL_OFF or not context or context.content_scope != PRIVACY_SCOPE_CASE_CONTENT or not context.case_id:
        duration = int((time.time() - started) * 1000)
        return SanitizedPayload(value=value, metadata=_privacy_metadata(level, context, 0, set(), duration))
    _ensure_aliases_for_payload(context.case_id, value, level)
    aliases = _load_aliases_for_case(context.case_id, level)
    sanitized, replacements, categories = _apply_aliases(value, aliases)
    duration = int((time.time() - started) * 1000)
    return SanitizedPayload(value=sanitized, metadata=_privacy_metadata(level, context, replacements, categories, duration))


def rehydrate_for_display(case_id: int, payload: Any, privacy_context: AIPrivacyContext | None = None) -> Any:
    """Rehydrate alias tokens for authorized local display boundaries."""
    aliases = PrivacyAlias.query.filter_by(case_id=case_id).all()
    by_alias = sorted(aliases, key=lambda item: len(item.alias_value or ''), reverse=True)

    def rehydrate_text(text: str) -> str:
        result = text
        for row in by_alias:
            if not row.alias_value or not row.original_value:
                continue
            if row.original_value.endswith('$'):
                machine_account_alias = f'{row.alias_value}$'
                if machine_account_alias in result:
                    result = result.replace(machine_account_alias, row.original_value)
            if row.alias_value in result:
                result = result.replace(row.alias_value, row.original_value)
        return result

    if isinstance(payload, str):
        return rehydrate_text(payload)
    if isinstance(payload, dict):
        return {key: rehydrate_for_display(case_id, value, privacy_context) for key, value in payload.items()}
    if isinstance(payload, list):
        return [rehydrate_for_display(case_id, item, privacy_context) for item in payload]
    if isinstance(payload, tuple):
        return tuple(rehydrate_for_display(case_id, item, privacy_context) for item in payload)
    return payload


@dataclass(frozen=True)
class AliasKey:
    entity_type: str
    normalized_value: str


@dataclass
class AliasCandidate:
    entity_type: str
    original_value: str
    normalized_value: str
    sensitivity_classification: str = 'protected'
    source_fields: set[str] = field(default_factory=set)
    seen_count: int = 0
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None

    @property
    def key(self) -> AliasKey:
        return AliasKey(self.entity_type, self.normalized_value)


def _clean(value: Any) -> str:
    text = str(value or '').replace('\x00', '').strip().strip('\"\'`')
    text = ''.join(ch for ch in text if ch in {'\t', '\n', '\r'} or ord(ch) >= 32)
    return text.strip()


def _is_skip(value: Any) -> bool:
    text = _clean(value)
    return not text or text.lower() in SKIP_VALUES


def _normalize(entity_type: str, value: str) -> str:
    text = _clean(value)
    if entity_type in {'USERNAME', 'ACCOUNT', 'HOSTNAME', 'DOMAIN', 'FQDN', 'EMAIL', 'SHARE'}:
        return text.lower()
    if entity_type.endswith('IPV4'):
        return str(ipaddress.ip_address(text))
    if entity_type in {'UNC_PATH', 'FILEPATH'}:
        return text.replace('/', '\\').lower()
    return text.lower()


def _valid_ipv4(value: Any) -> str | None:
    try:
        ip_obj = ipaddress.ip_address(_clean(value))
    except ValueError:
        return None
    if ip_obj.version != 4:
        return None
    return str(ip_obj)


def _ip_type(value: Any, client_public_ips: set[str] | None = None) -> str | None:
    normalized = _valid_ipv4(value)
    if not normalized:
        return None
    if normalized in (client_public_ips or set()):
        return 'CLIENT_PUBLIC_IPV4'
    ip_obj = ipaddress.ip_address(normalized)
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
        return 'INTERNAL_IPV4'
    return 'EXTERNAL_IPV4'


def _looks_like_fqdn(value: str) -> bool:
    text = _clean(value).strip('.').lower()
    if '.' not in text or any(text.endswith(suffix) for suffix in FILE_LIKE_SUFFIXES):
        return False
    return bool(FQDN_RE.fullmatch(text))


def _split_fqdn(value: str) -> tuple[str | None, str | None]:
    text = _clean(value).strip('.').lower()
    if not _looks_like_fqdn(text):
        return None, None
    hostname, domain = text.split('.', 1)
    return hostname, domain


def _add_candidate(
    candidates: dict[AliasKey, AliasCandidate],
    entity_type: str,
    value: Any,
    source_field: str,
    timestamp: datetime | None = None,
    sensitivity_classification: str = 'protected',
) -> None:
    if _is_skip(value):
        return
    original = _clean(value)
    try:
        normalized = _normalize(entity_type, original)
    except ValueError:
        return
    if not normalized or normalized.lower() in SKIP_VALUES:
        return
    key = AliasKey(entity_type, normalized)
    existing = candidates.get(key)
    if existing is None:
        existing = AliasCandidate(
            entity_type=entity_type,
            original_value=original,
            normalized_value=normalized,
            sensitivity_classification=sensitivity_classification,
        )
        candidates[key] = existing
    existing.seen_count += 1
    existing.source_fields.add(source_field)
    if timestamp:
        if existing.first_seen_at is None or timestamp < existing.first_seen_at:
            existing.first_seen_at = timestamp
        if existing.last_seen_at is None or timestamp > existing.last_seen_at:
            existing.last_seen_at = timestamp


def _add_username(candidates: dict[AliasKey, AliasCandidate], value: Any, source_field: str, timestamp: datetime | None) -> None:
    if _is_skip(value):
        return
    text = _clean(value)
    if EMAIL_RE.fullmatch(text):
        _add_candidate(candidates, 'EMAIL', text, source_field, timestamp)
        local, domain = text.split('@', 1)
        _add_candidate(candidates, 'USERNAME', local, source_field, timestamp)
        _add_candidate(candidates, 'DOMAIN', domain, source_field, timestamp)
        return
    if '\\' in text:
        domain, username = text.split('\\', 1)
        if domain.strip().lower() not in SKIP_DOMAINS:
            _add_candidate(candidates, 'DOMAIN', domain, source_field, timestamp)
        _add_candidate(candidates, 'ACCOUNT', text, source_field, timestamp)
        _add_candidate(candidates, 'USERNAME', username, source_field, timestamp)
        return
    _add_candidate(candidates, 'USERNAME', text, source_field, timestamp)


def _add_domain(candidates: dict[AliasKey, AliasCandidate], value: Any, source_field: str, timestamp: datetime | None) -> None:
    if _is_skip(value):
        return
    text = _clean(value)
    if text.lower() in SKIP_DOMAINS:
        return
    _add_candidate(candidates, 'DOMAIN', text, source_field, timestamp)


def _add_host(candidates: dict[AliasKey, AliasCandidate], value: Any, source_field: str, timestamp: datetime | None) -> None:
    if _is_skip(value):
        return
    text = _clean(value).strip('.')
    ip_type = _ip_type(text)
    if ip_type:
        _add_candidate(candidates, ip_type, text, source_field, timestamp)
        return
    if text.lower() in SKIP_HOSTS:
        return
    hostname, domain = _split_fqdn(text)
    if hostname and domain:
        _add_candidate(candidates, 'FQDN', text, source_field, timestamp)
        _add_candidate(candidates, 'HOSTNAME', hostname, source_field, timestamp)
        _add_candidate(candidates, 'DOMAIN', domain, source_field, timestamp)
        return
    if ' ' not in text and len(text) <= 255:
        _add_candidate(candidates, 'HOSTNAME', text, source_field, timestamp)


def _extract_text_entities(
    candidates: dict[AliasKey, AliasCandidate],
    text: Any,
    source_field: str,
    timestamp: datetime | None,
    client_public_ips: set[str] | None,
) -> None:
    if _is_skip(text):
        return
    haystack = _clean(text)

    for match in EMAIL_RE.finditer(haystack):
        _add_username(candidates, match.group(0), source_field, timestamp)

    for match in WINDOWS_ACCOUNT_RE.finditer(haystack):
        _add_username(candidates, f'{match.group(1)}\\{match.group(2)}', source_field, timestamp)

    for match in UNC_RE.finditer(haystack):
        unc_path = match.group(0)
        host = match.group(1)
        share = match.group(2)
        _add_candidate(candidates, 'UNC_PATH', unc_path, source_field, timestamp)
        _add_host(candidates, host, source_field, timestamp)
        _add_candidate(candidates, 'SHARE', share, source_field, timestamp)

    for match in WINDOWS_PROFILE_RE.finditer(haystack):
        _add_candidate(candidates, 'USERNAME', match.group(1), source_field, timestamp)

    for match in LINUX_HOME_RE.finditer(haystack):
        _add_candidate(candidates, 'USERNAME', match.group(1), source_field, timestamp)

    for match in BARE_HOST_CONTEXT_RE.finditer(haystack):
        _add_host(candidates, match.group(1) or match.group(2), source_field, timestamp)

    for match in IPV4_RE.finditer(haystack):
        entity_type = _ip_type(match.group(0), client_public_ips=client_public_ips)
        if entity_type:
            _add_candidate(candidates, entity_type, match.group(0), source_field, timestamp)

    for match in FQDN_RE.finditer(haystack):
        fqdn = match.group(0).strip('.')
        hostname, domain = _split_fqdn(fqdn)
        if hostname and domain:
            _add_candidate(candidates, 'FQDN', fqdn, source_field, timestamp)
            _add_candidate(candidates, 'HOSTNAME', hostname, source_field, timestamp)
            _add_candidate(candidates, 'DOMAIN', domain, source_field, timestamp)


def _row_timestamp(value: Any) -> datetime | None:
    return value if isinstance(value, datetime) else None


def extract_alias_candidates_from_event_rows(
    rows: Iterable[dict[str, Any]],
    *,
    client_public_ips: set[str] | None = None,
) -> dict[AliasKey, AliasCandidate]:
    """Extract protected alias candidates from ClickHouse event rows."""
    candidates: dict[AliasKey, AliasCandidate] = {}
    for row in rows:
        timestamp = _row_timestamp(row.get('timestamp_utc'))
        _add_username(candidates, row.get('username'), 'username', timestamp)
        _add_domain(candidates, row.get('domain'), 'domain', timestamp)
        _add_host(candidates, row.get('source_host'), 'source_host', timestamp)
        _add_host(candidates, row.get('remote_host'), 'remote_host', timestamp)
        _add_host(candidates, row.get('workstation_name'), 'workstation_name', timestamp)

        for ip_field in ('src_ip', 'dst_ip'):
            entity_type = _ip_type(row.get(ip_field), client_public_ips=client_public_ips)
            if entity_type:
                _add_candidate(candidates, entity_type, row.get(ip_field), ip_field, timestamp)

        for field_name in STRUCTURED_TEXT_FIELDS:
            _extract_text_entities(
                candidates,
                row.get(field_name),
                field_name,
                timestamp,
                client_public_ips,
            )
    return candidates


def _next_alias_value(case_id: int, entity_type: str) -> str:
    counter = PrivacyAliasCounter.query.filter_by(
        case_id=case_id,
        entity_type=entity_type,
    ).with_for_update().first()
    if counter is None:
        counter = PrivacyAliasCounter(case_id=case_id, entity_type=entity_type, next_number=1)
        db.session.add(counter)
        db.session.flush()
    number = counter.next_number
    counter.next_number += 1
    return f'{entity_type}_{number:04d}'


def upsert_alias_candidates(
    case_id: int,
    candidates: dict[AliasKey, AliasCandidate],
    *,
    source: str = 'ai_privacy_event_backfill',
    commit_every: int = 500,
) -> dict[str, Any]:
    """Upsert candidates into the PostgreSQL alias vault."""
    created = 0
    updated = 0
    by_type = Counter()

    ordered_candidates = sorted(
        candidates.values(),
        key=lambda item: (item.entity_type, item.normalized_value),
    )
    for index, candidate in enumerate(ordered_candidates, start=1):
        existing = PrivacyAlias.query.filter_by(
            case_id=case_id,
            entity_type=candidate.entity_type,
            normalized_value=candidate.normalized_value,
        ).first()
        sample_fields = sorted(candidate.source_fields)[:20]
        if existing:
            existing.seen_count = int(existing.seen_count or 0) + int(candidate.seen_count or 0)
            existing.last_seen_at = candidate.last_seen_at or existing.last_seen_at
            existing.first_seen_at = existing.first_seen_at or candidate.first_seen_at
            existing.sample_fields = sorted(set(existing.sample_fields or []) | set(sample_fields))[:20]
            existing.updated_at = datetime.utcnow()
            updated += 1
        else:
            alias_value = _next_alias_value(case_id, candidate.entity_type)
            db.session.add(PrivacyAlias(
                case_id=case_id,
                entity_type=candidate.entity_type,
                original_value=candidate.original_value,
                normalized_value=candidate.normalized_value,
                alias_value=alias_value,
                sensitivity_classification=candidate.sensitivity_classification,
                source=source,
                seen_count=candidate.seen_count,
                first_seen_at=candidate.first_seen_at,
                last_seen_at=candidate.last_seen_at,
                sample_fields=sample_fields,
            ))
            created += 1
        by_type[candidate.entity_type] += 1
        if commit_every and index % commit_every == 0:
            db.session.commit()

    db.session.commit()
    return {
        'created': created,
        'updated': updated,
        'candidate_count': len(candidates),
        'candidate_by_type': dict(sorted(by_type.items())),
    }


def _client_public_ips_for_case(case: Any) -> set[str]:
    values = []
    for raw in (getattr(case, 'router_ips', None), getattr(case, 'vpn_ips', None)):
        if raw:
            values.extend(re.split(r'[,\s]+', str(raw)))
    public_ips = set()
    for value in values:
        normalized = _valid_ipv4(value)
        if not normalized:
            continue
        ip_obj = ipaddress.ip_address(normalized)
        if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local):
            public_ips.add(normalized)
    return public_ips


def _merge_candidate_maps(
    target: dict[AliasKey, AliasCandidate],
    source: dict[AliasKey, AliasCandidate],
) -> None:
    for key, candidate in source.items():
        existing = target.get(key)
        if existing is None:
            target[key] = candidate
            continue
        existing.seen_count += candidate.seen_count
        existing.source_fields.update(candidate.source_fields)
        if candidate.first_seen_at and (existing.first_seen_at is None or candidate.first_seen_at < existing.first_seen_at):
            existing.first_seen_at = candidate.first_seen_at
        if candidate.last_seen_at and (existing.last_seen_at is None or candidate.last_seen_at > existing.last_seen_at):
            existing.last_seen_at = candidate.last_seen_at


def _scan_distinct_field(
    *,
    client: Any,
    case_id: int,
    field_name: str,
    extractor,
    client_public_ips: set[str],
    candidates: dict[AliasKey, AliasCandidate],
) -> int:
    value_sql = f"ifNull(toString({field_name}), '')" if field_name in {'src_ip', 'dst_ip'} else field_name
    result = client.query(
        f"""
        SELECT
            {value_sql} AS value,
            count() AS seen_count,
            min(timestamp_utc) AS first_seen_at,
            max(timestamp_utc) AS last_seen_at
        FROM events
        WHERE case_id = {{case_id:UInt32}}
          AND {value_sql} != ''
        GROUP BY value
        """,
        parameters={'case_id': case_id},
    )
    distinct_count = 0
    for value, seen_count, first_seen_at, last_seen_at in result.result_rows:
        temp_candidates: dict[AliasKey, AliasCandidate] = {}
        extractor(temp_candidates, value, field_name, _row_timestamp(first_seen_at))
        for temp_candidate in temp_candidates.values():
            temp_candidate.seen_count = int(seen_count or 0)
            temp_candidate.first_seen_at = _row_timestamp(first_seen_at)
            temp_candidate.last_seen_at = _row_timestamp(last_seen_at)
        _merge_candidate_maps(candidates, temp_candidates)
        distinct_count += 1
    return distinct_count


def _scan_distinct_ip_field(
    *,
    client: Any,
    case_id: int,
    field_name: str,
    client_public_ips: set[str],
    candidates: dict[AliasKey, AliasCandidate],
) -> int:
    value_sql = f"ifNull(toString({field_name}), '')"
    result = client.query(
        f"""
        SELECT
            {value_sql} AS value,
            count() AS seen_count,
            min(timestamp_utc) AS first_seen_at,
            max(timestamp_utc) AS last_seen_at
        FROM events
        WHERE case_id = {{case_id:UInt32}}
          AND {value_sql} != ''
        GROUP BY value
        """,
        parameters={'case_id': case_id},
    )
    distinct_count = 0
    for value, seen_count, first_seen_at, last_seen_at in result.result_rows:
        entity_type = _ip_type(value, client_public_ips=client_public_ips)
        if entity_type:
            key = AliasKey(entity_type, _normalize(entity_type, value))
            candidate = candidates.get(key)
            if candidate is None:
                candidate = AliasCandidate(
                    entity_type=entity_type,
                    original_value=_clean(value),
                    normalized_value=key.normalized_value,
                    seen_count=0,
                )
                candidates[key] = candidate
            candidate.seen_count += int(seen_count or 0)
            candidate.source_fields.add(field_name)
            candidate.first_seen_at = candidate.first_seen_at or _row_timestamp(first_seen_at)
            candidate.last_seen_at = _row_timestamp(last_seen_at) or candidate.last_seen_at
        distinct_count += 1
    return distinct_count


def scan_clickhouse_case_alias_candidates(case_id: int, *, batch_size: int = 5000) -> dict[str, Any]:
    """Scan original ClickHouse indexed fields for a case and return alias candidates.

    This uses ClickHouse aggregation over distinct indexed/event columns instead of
    replaying every event row through Python. It keeps ClickHouse original data intact
    and models the aliases that would be available at the AI egress boundary.
    """
    from models.case import Case
    from utils.clickhouse import get_client

    case = Case.get_by_id(case_id)
    if not case:
        raise ValueError(f'Case {case_id} not found')

    client_public_ips = _client_public_ips_for_case(case)
    client = get_client()
    count_result = client.query(
        'SELECT count() FROM events WHERE case_id = {case_id:UInt32}',
        parameters={'case_id': case_id},
    )
    event_count = count_result.result_rows[0][0] if count_result.result_rows else 0

    candidates: dict[AliasKey, AliasCandidate] = {}
    distinct_sources = {}
    distinct_sources['username'] = _scan_distinct_field(
        client=client,
        case_id=case_id,
        field_name='username',
        extractor=_add_username,
        client_public_ips=client_public_ips,
        candidates=candidates,
    )
    distinct_sources['domain'] = _scan_distinct_field(
        client=client,
        case_id=case_id,
        field_name='domain',
        extractor=_add_domain,
        client_public_ips=client_public_ips,
        candidates=candidates,
    )
    for host_field in ('source_host', 'remote_host', 'workstation_name'):
        distinct_sources[host_field] = _scan_distinct_field(
            client=client,
            case_id=case_id,
            field_name=host_field,
            extractor=_add_host,
            client_public_ips=client_public_ips,
            candidates=candidates,
        )
    for ip_field in ('src_ip', 'dst_ip'):
        distinct_sources[ip_field] = _scan_distinct_ip_field(
            client=client,
            case_id=case_id,
            field_name=ip_field,
            client_public_ips=client_public_ips,
            candidates=candidates,
        )

    by_type = Counter(candidate.entity_type for candidate in candidates.values())
    return {
        'case_id': case_id,
        'event_count': event_count,
        'client_public_ips': sorted(client_public_ips),
        'distinct_source_values': dict(sorted(distinct_sources.items())),
        'scan_mode': 'clickhouse_distinct_indexed_fields',
        'candidates': candidates,
        'candidate_count': len(candidates),
        'candidate_by_type': dict(sorted(by_type.items())),
    }


def stored_alias_summary(case_id: int) -> dict[str, Any]:
    """Return stored alias counts for a case."""
    rows = PrivacyAlias.query.filter_by(case_id=case_id).all()
    by_type = Counter(row.entity_type for row in rows)
    return {
        'stored_count': len(rows),
        'stored_by_type': dict(sorted(by_type.items())),
    }


def compare_candidates_to_stored(case_id: int, candidates: dict[AliasKey, AliasCandidate]) -> dict[str, Any]:
    """Compare extracted candidate keys with stored alias rows."""
    stored_rows = PrivacyAlias.query.filter_by(case_id=case_id).all()
    candidate_keys = {(key.entity_type, key.normalized_value) for key in candidates}
    stored_keys = {(row.entity_type, row.normalized_value) for row in stored_rows}
    missing = sorted(candidate_keys - stored_keys)[:25]
    extra = sorted(stored_keys - candidate_keys)[:25]
    return {
        'candidate_unique': len(candidate_keys),
        'stored_unique': len(stored_keys),
        'missing_count': len(candidate_keys - stored_keys),
        'extra_count': len(stored_keys - candidate_keys),
        'missing_sample': missing,
        'extra_sample': extra,
    }


def populate_case_privacy_aliases(
    case_id: int,
    *,
    batch_size: int = 5000,
    reset_generated: bool = False,
) -> dict[str, Any]:
    """Populate the alias vault for a case from original ClickHouse event data."""
    if reset_generated:
        PrivacyAlias.query.filter_by(case_id=case_id, source='ai_privacy_event_backfill').delete()
        PrivacyAliasCounter.query.filter_by(case_id=case_id).delete()
        db.session.commit()

    scan = scan_clickhouse_case_alias_candidates(case_id, batch_size=batch_size)
    upsert = upsert_alias_candidates(case_id, scan['candidates'])
    stored = stored_alias_summary(case_id)
    comparison = compare_candidates_to_stored(case_id, scan['candidates'])
    return {
        'case_id': case_id,
        'event_count': scan['event_count'],
        'client_public_ips': scan['client_public_ips'],
        'extracted': {
            'candidate_count': scan['candidate_count'],
            'candidate_by_type': scan['candidate_by_type'],
            'distinct_source_values': scan.get('distinct_source_values', {}),
            'scan_mode': scan.get('scan_mode'),
        },
        'upsert': upsert,
        'stored': stored,
        'comparison': comparison,
    }


def summary_as_json(summary: dict[str, Any]) -> str:
    """Serialize a population summary for CLI output."""
    return json.dumps(summary, indent=2, sort_keys=True, default=str)
