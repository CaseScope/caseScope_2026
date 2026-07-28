"""Cloud AI Privacy Mode alias extraction and vault population."""
from __future__ import annotations

import ipaddress
import json
import logging
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Iterable

from models.database import db
from models.privacy_alias import PrivacyAlias, PrivacyAliasCounter

logger = logging.getLogger(__name__)

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
IPV6_RE = re.compile(
    r"(?<![0-9A-Za-z:.])(?:"
    r"(?:[0-9A-F]{1,4}:){7}[0-9A-F]{1,4}"
    r"|(?:[0-9A-F]{1,4}:){1,7}:"
    r"|(?:[0-9A-F]{1,4}:){1,6}:[0-9A-F]{1,4}"
    r"|(?:[0-9A-F]{1,4}:){1,5}(?::[0-9A-F]{1,4}){1,2}"
    r"|(?:[0-9A-F]{1,4}:){1,4}(?::[0-9A-F]{1,4}){1,3}"
    r"|(?:[0-9A-F]{1,4}:){1,3}(?::[0-9A-F]{1,4}){1,4}"
    r"|(?:[0-9A-F]{1,4}:){1,2}(?::[0-9A-F]{1,4}){1,5}"
    r"|[0-9A-F]{1,4}:(?::[0-9A-F]{1,4}){1,6}"
    r"|:(?::[0-9A-F]{1,4}){1,7}"
    r"|::"
    r")(?![0-9A-Za-z:.])",
    re.IGNORECASE,
)
SID_RE = re.compile(r"\bS-1-(?:\d{1,10}-){1,14}\d{1,10}\b", re.IGNORECASE)
GUID_RE = re.compile(
    r"\b[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\b",
    re.IGNORECASE,
)
GUID_TENANT_CONTEXT_RE = re.compile(r"(?i)\b(?:tenant(?:_?id)?|tid|directory_?id)\b")
GUID_OBJECT_CONTEXT_RE = re.compile(
    r"(?i)\b(?:object_?id|oid|principal_?id|app_?id|client_?id|user_?id)\b"
)
WINDOWS_PATH_RE = re.compile(r"(?i)\b[A-Z]:\\[^\s\"'<>|?*]+")
URL_RE = re.compile(r"(?i)\bhttps?://([A-Z0-9._-]+(?::\d{1,5})?)(/[^\s\"'<>]*)?")
# Only the dotted 'first.last' convention is treated as a person name. The
# underscore form is overwhelmingly service accounts (svc_backup, sql_agent).
PERSON_NAME_LOCALPART_RE = re.compile(r"^([A-Z]{2,})\.([A-Z]{2,})$", re.IGNORECASE)
NON_PERSON_NAME_TOKENS = {
    'svc', 'service', 'services', 'srv', 'server', 'admin', 'adm',
    'administrator', 'sys', 'system', 'sa', 'backup', 'sql', 'web', 'app',
    'test', 'dev', 'prod', 'qa', 'mail', 'smtp', 'noreply', 'no', 'reply',
    'info', 'support', 'help', 'helpdesk', 'sales', 'billing', 'root',
    'guest', 'user', 'account', 'accounts', 'team', 'group', 'daemon',
    'monitor', 'scan', 'scanner', 'print', 'printer', 'task', 'job', 'bot',
}

# SIDs that identify a well-known local principal rather than a person or a
# tenant. Aliasing these would strip the meaning the AI needs to recognise
# SYSTEM, LocalService and the built-in groups, and they disclose nothing.
WELL_KNOWN_SID_PREFIXES = ('s-1-5-32-', 's-1-5-80-', 's-1-5-82-', 's-1-5-90-')
WELL_KNOWN_SIDS = {
    's-1-0-0', 's-1-1-0', 's-1-2-0', 's-1-2-1', 's-1-3-0', 's-1-3-1',
    's-1-3-2', 's-1-3-3', 's-1-3-4', 's-1-5-1', 's-1-5-2', 's-1-5-3',
    's-1-5-4', 's-1-5-6', 's-1-5-7', 's-1-5-8', 's-1-5-9', 's-1-5-10',
    's-1-5-11', 's-1-5-12', 's-1-5-13', 's-1-5-14', 's-1-5-15', 's-1-5-17',
    's-1-5-18', 's-1-5-19', 's-1-5-20', 's-1-5-113', 's-1-5-114',
    's-1-16-0', 's-1-16-4096', 's-1-16-8192', 's-1-16-12288',
    's-1-16-16384', 's-1-16-20480', 's-1-16-28672',
}

# Path segments that describe the OS layout rather than the customer. These are
# preserved so directory-shape signals such as \Temp\ or \AppData\ survive.
PRESERVED_PATH_SEGMENTS = {
    'windows', 'winnt', 'system32', 'syswow64', 'wbem', 'sysnative',
    'program files', 'program files (x86)', 'programdata', 'users', 'user',
    'appdata', 'local', 'locallow', 'roaming', 'temp', 'tmp', 'public',
    'default', 'desktop', 'documents', 'downloads', 'pictures', 'music',
    'videos', 'favorites', 'startup', 'start menu', 'programs',
    'perflogs', 'inetpub', 'recycle.bin', '$recycle.bin', 'drivers', 'etc',
    'config', 'logs', 'temporary internet files', 'microsoft', 'common files',
    'windowsapps', 'assembly', 'installer', 'tasks', 'spool', 'prefetch',
}

# Executable and system artefact names are the substance of an attack narrative
# and are not customer content, so they stay readable. Document and data files
# are named after the work they contain and are aliased.
PRESERVED_FILE_EXTENSIONS = {
    '.exe', '.dll', '.sys', '.ocx', '.scr', '.com', '.cpl', '.drv',
    '.ps1', '.psm1', '.bat', '.cmd', '.vbs', '.js', '.jse', '.wsf', '.hta',
    '.msi', '.msp', '.lnk', '.reg', '.inf', '.tmp', '.log', '.evtx', '.etl',
}

SKIP_VALUES = {'', '-', '--', '---', 'none', 'null', 'n/a', 'na', 'unknown', '(null)'}
SKIP_DOMAINS = {'nt authority', 'builtin', 'window manager', 'font driver host'}
SKIP_HOSTS = {'localhost', 'localhost.localdomain'}
FILE_LIKE_SUFFIXES = {'.exe', '.dll', '.sys', '.dat', '.log', '.json', '.csv', '.xml', '.txt'}

# Path segments that WINDOWS_ACCOUNT_RE would otherwise read as DOMAIN\USERNAME.
PATH_SEGMENT_TOKENS = {
    'users', 'user', 'programdata', 'program files', 'program files (x86)',
    'documents', 'downloads', 'desktop', 'appdata', 'windows', 'system32',
    'syswow64', 'temp', 'tmp', 'public', 'perflogs', 'inetpub', 'recycle.bin',
    '$recycle.bin', 'local', 'locallow', 'roaming', 'winnt',
}

# Substituting a very short or very common value corrupts unrelated text, so
# these are extracted and vaulted but never swapped into an AI-bound payload.
MIN_ALIAS_REPLACEMENT_LENGTH = 3
ALIAS_REPLACEMENT_STOPWORDS = {
    'cui', 'admin', 'administrator', 'system', 'guest', 'user', 'users',
    'local', 'network', 'service', 'default', 'public', 'data', 'temp',
    'test', 'none', 'null', 'true', 'false', 'domain', 'group', 'host',
    'documents', 'desktop', 'downloads', 'windows', 'program', 'file',
}

# Event pipelines put free prose into the normalized username and domain
# columns, so ordinary words enter the vault as protected identifiers and are
# then swapped into every AI payload, rewriting "you are a DFIR analyst
# assistant" into alias tokens and degrading the instructions the model reads.
#
# Only dotless single-label values are tested against this list, and only for
# the account-shaped types, so a NetBIOS domain such as CORP, any dotted name,
# and every hostname remain protected. Words that plausibly name a machine or
# a service account (server, gateway, proxy, mail, web, agent, backup) are
# deliberately absent: over-protecting those is cheap, under-protecting is not.
GENERIC_IDENTIFIER_ENTITY_TYPES = {'DOMAIN', 'USERNAME', 'ACCOUNT'}
GENERIC_IDENTIFIER_WORDS = frozenset({
    # Function words and ordinary prose.
    'a', 'about', 'above', 'after', 'again', 'against', 'all', 'also', 'am',
    'an', 'and', 'any', 'are', 'as', 'at', 'be', 'because', 'been', 'before',
    'being', 'below', 'between', 'both', 'but', 'by', 'can', 'could', 'did',
    'do', 'does', 'down', 'during', 'each', 'few', 'for', 'from', 'further',
    'had', 'has', 'have', 'he', 'her', 'here', 'hers', 'him', 'his', 'how',
    'if', 'in', 'into', 'is', 'it', 'its', 'just', 'me', 'more', 'most', 'my',
    'no', 'nor', 'not', 'now', 'of', 'off', 'on', 'once', 'only', 'or',
    'other', 'ought', 'our', 'ours', 'out', 'over', 'own', 'same', 'she',
    'should', 'so', 'some', 'such', 'than', 'that', 'the', 'their', 'theirs',
    'them', 'then', 'there', 'these', 'they', 'this', 'those', 'through',
    'to', 'too', 'under', 'until', 'up', 'very', 'was', 'we', 'were', 'what',
    'when', 'where', 'which', 'while', 'who', 'whom', 'why', 'will', 'with',
    'would', 'you', 'your', 'yours',
    # Generic analysis and logging vocabulary.
    'account', 'accounts', 'action', 'activity', 'address', 'alert', 'alerts',
    'allowed', 'analysis', 'analyst', 'answer', 'application', 'argument',
    'arguments', 'assistant', 'attempt', 'attempts', 'audit', 'authentication',
    'blocked', 'category', 'change', 'changed', 'code', 'command', 'comment',
    'computer', 'condition', 'configuration', 'connection', 'content',
    'context', 'count', 'created', 'critical', 'current', 'date', 'day',
    'defined', 'deleted', 'denied', 'description', 'detail', 'details',
    'detection', 'device', 'directory', 'disabled', 'duration', 'enabled',
    'entry', 'error', 'errors', 'evidence', 'event', 'events', 'execution',
    'failed', 'failure', 'field', 'filename', 'filter', 'finding', 'findings',
    'folder', 'format', 'header', 'hour', 'identifier', 'image', 'inbound',
    'index', 'info', 'information', 'input', 'instance', 'internal', 'item',
    'items', 'key', 'label', 'level', 'line', 'list', 'log', 'logged',
    'logoff', 'logon', 'logs', 'match', 'matched', 'message', 'messages',
    'method', 'minute', 'mode', 'month', 'name', 'note', 'notice', 'number',
    'object', 'offline', 'online', 'operation', 'option', 'options', 'order',
    'origin', 'outbound', 'output', 'owner', 'packet', 'page', 'parameter',
    'parent', 'password', 'path', 'pattern', 'pending', 'permission', 'policy',
    'port', 'priority', 'privilege', 'process', 'product', 'profile',
    'protocol', 'query', 'question', 'reason', 'record', 'records', 'remote',
    'report', 'request', 'requested', 'resource', 'response', 'result',
    'results', 'role', 'route', 'rule', 'rules', 'schedule', 'scope', 'score',
    'script', 'search', 'second', 'section', 'session', 'setting', 'settings',
    'severity', 'signature', 'size', 'source', 'stage', 'state', 'statistics',
    'status', 'step', 'string', 'subject', 'success', 'successful', 'summary',
    'table', 'tag', 'target', 'task', 'text', 'thread', 'threat', 'time',
    'timeline', 'timeout', 'title', 'total', 'trace', 'traffic', 'transfer',
    'trigger', 'type', 'unknown', 'update', 'usage', 'value', 'values',
    'vendor', 'version', 'view', 'volume', 'warning', 'week', 'year', 'zone',
    # Investigation prose. CaseScope's own role and behaviour instructions are
    # sanitized alongside case content, so these words reached the model as
    # alias tokens even though they never came from the evidence.
    'abnormal', 'always', 'answered', 'artifact', 'artifacts', 'ask', 'asked',
    'attack', 'attacker', 'based', 'begin', 'benign', 'called', 'case', 'cases',
    'chain', 'check', 'checked', 'compromise', 'confirm', 'confirmed',
    'correct', 'custody', 'cyber', 'describe', 'described', 'determine',
    'determined', 'digital', 'either', 'end', 'expected', 'explain', 'find',
    'first', 'forensic', 'forensics', 'found', 'give', 'given', 'high',
    'hunt', 'hunting', 'identified', 'identify', 'include', 'included',
    'includes', 'including', 'incident', 'indicator', 'indicators', 'invalid',
    'known', 'large', 'last', 'likely', 'listed', 'look', 'low', 'made',
    'make', 'malicious', 'malware', 'many', 'medium', 'might', 'multiple',
    'must', 'need', 'needed', 'never', 'next', 'normal', 'often', 'possible',
    'potential', 'previous', 'procedure', 'provide', 'provided', 'ransomware',
    'reply', 'response', 'return', 'returns', 'review', 'reviewed', 'said',
    'say', 'see', 'seen', 'several', 'shall', 'show', 'shown', 'single',
    'small', 'start', 'stop', 'suspicious', 'tactic', 'take', 'taken',
    'technique', 'tell', 'told', 'triage', 'unexpected', 'unusual', 'use',
    'used', 'using', 'valid', 'verified', 'verify', 'victim', 'want',
    'window', 'yes',
})


def _is_generic_identifier_word(entity_type: str, value: Any) -> bool:
    """Report whether an account-shaped value is really an ordinary word.

    Applied both when vaulting a candidate and when deciding whether an
    already-vaulted row may be substituted, so rows harvested before this
    check existed stop corrupting payloads without needing a data migration.
    """
    if entity_type not in GENERIC_IDENTIFIER_ENTITY_TYPES:
        return False
    text = str(value or '').strip().lower()
    if not text or any(character in text for character in '.\\@/'):
        return False
    return text in GENERIC_IDENTIFIER_WORDS


# Alias values must not match inside a larger identifier. A bare '.' is allowed
# on either side (sentence punctuation) unless it joins another alphanumeric,
# which would mean we are sitting inside a dotted name or IP address.
ALIAS_TOKEN_RE = re.compile(r'[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*_\d{3,}', re.IGNORECASE)
ALIAS_BOUNDARY_CHARS = r'A-Za-z0-9_\-'
ALIAS_LEADING_GUARD = rf'(?<![{ALIAS_BOUNDARY_CHARS}])(?<![A-Za-z0-9]\.)'
ALIAS_TRAILING_GUARD = rf'(?![{ALIAS_BOUNDARY_CHARS}])(?!\.[A-Za-z0-9])'

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

# Free-text columns scanned when building the vault. raw_json is excluded: it
# duplicates the parsed columns and its cardinality makes the scan unbounded.
SCANNED_TEXT_FIELDS = tuple(sorted(STRUCTURED_TEXT_FIELDS - {'raw_json'}))
TEXT_FIELD_SCAN_LIMIT = 20000
# The typed columns are higher cardinality than the free-text ones on network
# evidence: a case carrying firewall or proxy logs has one distinct dst_ip per
# address contacted. Scanning them unbounded produced vaults of several hundred
# thousand rows, which the substitution matcher cannot work with.
TYPED_FIELD_SCAN_LIMIT = 20000
# Substitution is linear in vault size, so the vault has to stay small enough
# to compile and match against. Candidates are kept by descending seen_count,
# so what survives truncation is what the evidence actually talks about.
MAX_CASE_VAULT_CANDIDATES = 50000
# A value longer than this cannot be a useful alias: it will not recur verbatim
# often enough to be worth a token, and the unique index over normalized_value
# is a btree, which rejects an index row above roughly 2704 bytes. Long URLs
# carrying OIDC tokens hit both limits.
MAX_VAULTED_VALUE_LENGTH = 512

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
        'USERNAME', 'ACCOUNT', 'EMAIL', 'HOSTNAME', 'FQDN', 'DOMAIN',
        'INTERNAL_IPV4', 'INTERNAL_IPV6',
    },
    PRIVACY_LEVEL_CMMC_CUI: {
        'USERNAME', 'ACCOUNT', 'EMAIL', 'HOSTNAME', 'FQDN', 'DOMAIN',
        'INTERNAL_IPV4', 'INTERNAL_IPV6',
        'CLIENT_PUBLIC_IPV4', 'CLIENT_PUBLIC_IPV6', 'TENANT_ID', 'OBJECT_ID',
        'SID', 'UNC_PATH', 'SHARE',
        'FILEPATH', 'CLIENT_NAME', 'PERSON_NAME', 'COMPANY_NAME', 'CASE_NAME',
    },
    PRIVACY_LEVEL_STRICT: {
        'USERNAME', 'ACCOUNT', 'EMAIL', 'HOSTNAME', 'FQDN', 'DOMAIN',
        'INTERNAL_IPV4', 'INTERNAL_IPV6',
        'CLIENT_PUBLIC_IPV4', 'CLIENT_PUBLIC_IPV6', 'TENANT_ID', 'OBJECT_ID',
        'SID', 'UNC_PATH', 'SHARE',
        'FILEPATH', 'CLIENT_NAME', 'PERSON_NAME', 'COMPANY_NAME', 'CASE_NAME',
        'EXTERNAL_IPV4', 'EXTERNAL_IPV6', 'EXTERNAL_DOMAIN', 'URL',
    },
}
PRIVACY_CACHE_TTL_SECONDS = 60
_ALIAS_CACHE: dict[tuple[int, str], tuple[float, list[PrivacyAlias]]] = {}
_MATCHER_CACHE: dict[tuple[int, str], tuple[float, Any]] = {}

# Marks a message whose case-derived content was already aliased and verified
# by whoever composed it. Substitution and verification both skip it, so
# CaseScope's own prompt text is not rewritten by a vault that holds ordinary
# words. The key never reaches a provider: the sanitizer strips it on the way
# out. Only set this on a message you have already put through
# sanitize_case_text.
PRESANITIZED_MESSAGE_KEY = '_privacy_presanitized'
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


class PrivacyEgressLeakError(RuntimeError):
    """Raised when a sanitized payload still carries protected values.

    Reports only the entity categories involved, never the values, so that
    failing this check does not itself write regulated data to a log.
    """

    error_code = 'privacy_egress_residual_leak'

    def __init__(self, categories: set[str], case_id: int | None):
        self.categories = sorted(categories)
        self.case_id = case_id
        super().__init__(
            'Cloud AI egress blocked: sanitized payload still contains '
            f'protected values of type {", ".join(self.categories)}'
        )


class PrivacySanitizerUnavailableError(RuntimeError):
    """Raised when the sanitizer cannot run for a cloud provider."""

    error_code = 'privacy_sanitizer_unavailable'


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


def _privacy_metadata(
    level: str,
    context: AIPrivacyContext | None,
    aliases_applied: int,
    categories: set[str],
    duration_ms: int,
    *,
    residual_categories: set[str] | None = None,
    fail_closed: bool | None = None,
) -> dict[str, Any]:
    return {
        'enabled': level != PRIVACY_LEVEL_OFF,
        'privacy_level': level,
        'case_id': context.case_id if context else None,
        'content_scope': context.content_scope if context else None,
        'retention_policy': context.retention_policy if context else None,
        'aliases_applied': aliases_applied,
        'entity_categories': sorted(categories),
        'residual_categories': sorted(residual_categories or set()),
        'fail_closed': fail_closed,
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


def _is_presanitized(value: Any) -> bool:
    """Report whether a message was already aliased and verified by its composer."""
    return isinstance(value, dict) and bool(value.get(PRESANITIZED_MESSAGE_KEY))


def _strip_presanitized_markers(value: Any) -> Any:
    """Remove the pre-sanitized marker so it never reaches a provider."""
    if isinstance(value, dict):
        return {
            key: _strip_presanitized_markers(item)
            for key, item in value.items()
            if key != PRESANITIZED_MESSAGE_KEY
        }
    if isinstance(value, list):
        return [_strip_presanitized_markers(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_strip_presanitized_markers(item) for item in value)
    return value


def _string_leaves(value: Any, *, parent_key: str | None = None) -> list[str]:
    """Collect string leaves, skipping the keys substitution deliberately skips.

    Structural keys carry protocol literals we generate ('assistant', a tool
    name, a generated call id), never case content. They must be excluded here
    too: alias substitution ignores them, so scanning them would report a
    residual that no substitution pass is able to clear.
    """
    if parent_key in STRUCTURAL_AI_PAYLOAD_KEYS:
        return []
    if _is_presanitized(value):
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        leaves: list[str] = []
        for key, item in value.items():
            leaves.extend(_string_leaves(item, parent_key=str(key)))
        return leaves
    if isinstance(value, (list, tuple)):
        leaves = []
        for item in value:
            leaves.extend(_string_leaves(item, parent_key=parent_key))
        return leaves
    return []


def extract_alias_candidates_from_text(
    text: Any,
    *,
    case_id: int | None = None,
    client_public_ips: set[str] | None = None,
) -> dict[AliasKey, AliasCandidate]:
    """Extract protected alias candidates from arbitrary AI-bound text."""
    candidates: dict[AliasKey, AliasCandidate] = {}
    _extract_text_entities(candidates, text, 'ai_egress_text', None, client_public_ips)
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
    for key in list(_MATCHER_CACHE):
        if key[0] == int(case_id):
            _MATCHER_CACHE.pop(key, None)


def _cached_matcher_for_case(
    case_id: int,
    level: str,
    aliases: list[PrivacyAlias],
) -> tuple[re.Pattern[str] | None, dict[str, PrivacyAlias]]:
    """Return the compiled matcher for a case, building it at most once per TTL.

    Compiling the alternation costs seconds against a vault of tens of
    thousands of aliases, and a single request now sanitizes case context at
    composition time and the remaining messages at the router.
    """
    cache_key = (int(case_id), normalize_privacy_level(level))
    now = time.time()
    cached = _MATCHER_CACHE.get(cache_key)
    if cached and now - cached[0] < PRIVACY_CACHE_TTL_SECONDS:
        return cached[1]
    matcher = _build_alias_matcher(aliases)
    _MATCHER_CACHE[cache_key] = (now, matcher)
    return matcher


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


def _is_replaceable_alias(row: PrivacyAlias) -> bool:
    """Reject alias rows too short or too generic to substitute safely."""
    original = (row.original_value or '').strip()
    if not original or not (row.alias_value or '').strip():
        return False
    if len(original) < MIN_ALIAS_REPLACEMENT_LENGTH:
        return False
    if _is_generic_identifier_word(getattr(row, 'entity_type', ''), original):
        return False
    return original.lower() not in ALIAS_REPLACEMENT_STOPWORDS


def _build_alias_matcher(
    aliases: list[PrivacyAlias],
) -> tuple[re.Pattern[str] | None, dict[str, PrivacyAlias]]:
    """Compile one boundary-guarded, case-insensitive matcher for every alias.

    Longest originals are alternated first so that a longer value always wins
    over a shorter one that prefixes it, and the surrounding character guards
    keep a short alias from matching inside an unrelated identifier.
    """
    by_original: dict[str, PrivacyAlias] = {}
    for row in aliases:
        if not _is_replaceable_alias(row):
            continue
        key = row.original_value.lower()
        existing = by_original.get(key)
        if existing is None or len(row.alias_value or '') < len(existing.alias_value or ''):
            by_original[key] = row
    if not by_original:
        return None, {}

    pattern = re.compile(
        ALIAS_LEADING_GUARD + _alias_trie_pattern(by_original) + ALIAS_TRAILING_GUARD,
        re.IGNORECASE,
    )
    return pattern, by_original


def _alias_trie_pattern(originals: Iterable[str]) -> str:
    """Compile alias originals into a prefix trie rather than a flat alternation.

    A flat alternation makes the engine try every alias at every offset, which
    is O(text length x vault size) and cost seconds per scan on a vault of tens
    of thousands of values. A trie walks only as far as the text agrees, so the
    scan no longer scales with the size of the vault.

    Match semantics are preserved. Sibling branches start with distinct
    characters, so their order cannot change the outcome, and continuations are
    tried before the empty option so the longest alias still wins - the same
    preference the length-sorted alternation provided.
    """
    trie: dict[str, Any] = {}
    for original in originals:
        node = trie
        for character in original:
            node = node.setdefault(character, {})
        node[''] = True
    return _render_trie_node(trie)


def _render_trie_node(node: dict[str, Any]) -> str:
    # A run of single-child nodes becomes one literal rather than nested
    # groups, which keeps the pattern's parenthesis nesting shallow enough for
    # long values such as file paths.
    literal: list[str] = []
    while len(node) == 1 and '' not in node:
        character, child = next(iter(node.items()))
        literal.append(character)
        node = child

    prefix = re.escape(''.join(literal))
    terminal = '' in node
    branches = [
        re.escape(character) + _render_trie_node(child)
        for character, child in sorted(node.items())
        if character != ''
    ]

    if not branches:
        return prefix
    grouped = '(?:' + '|'.join(branches) + ')'
    if terminal:
        # Greedy, so a longer alias is preferred over ending here.
        grouped += '?'
    return prefix + grouped


def _replace_aliases_in_text(
    text: str,
    aliases: list[PrivacyAlias],
    matcher: tuple[re.Pattern[str] | None, dict[str, PrivacyAlias]] | None = None,
) -> tuple[str, int, set[str]]:
    pattern, by_original = matcher if matcher is not None else _build_alias_matcher(aliases)
    if pattern is None:
        return text, 0, set()

    replacements = 0
    categories: set[str] = set()

    def substitute(match: re.Match[str]) -> str:
        nonlocal replacements
        row = by_original.get(match.group(0).lower())
        if row is None:
            return match.group(0)
        replacements += 1
        categories.add(row.entity_type)
        return row.alias_value

    return pattern.sub(substitute, text), replacements, categories


def _apply_aliases(
    value: Any,
    aliases: list[PrivacyAlias],
    *,
    parent_key: str | None = None,
    matcher: tuple[re.Pattern[str] | None, dict[str, PrivacyAlias]] | None = None,
) -> tuple[Any, int, set[str]]:
    # Compiling the alternation costs about three seconds against a vault of
    # fifty thousand aliases. Building it once per payload rather than once per
    # string leaf is the difference between a request completing and timing out.
    if matcher is None:
        matcher = _build_alias_matcher(aliases)
    if parent_key in STRUCTURAL_AI_PAYLOAD_KEYS:
        return value, 0, set()
    if _is_presanitized(value):
        return value, 0, set()
    if isinstance(value, str):
        return _replace_aliases_in_text(value, aliases, matcher)
    if isinstance(value, dict):
        total = 0
        categories: set[str] = set()
        updated = {}
        for key, item in value.items():
            new_item, count, item_categories = _apply_aliases(
                item, aliases, parent_key=str(key), matcher=matcher
            )
            updated[key] = new_item
            total += count
            categories.update(item_categories)
        return updated, total, categories
    if isinstance(value, list):
        total = 0
        categories: set[str] = set()
        updated_items = []
        for item in value:
            new_item, count, item_categories = _apply_aliases(
                item, aliases, parent_key=parent_key, matcher=matcher
            )
            updated_items.append(new_item)
            total += count
            categories.update(item_categories)
        return updated_items, total, categories
    if isinstance(value, tuple):
        new_list, count, categories = _apply_aliases(
            list(value), aliases, parent_key=parent_key, matcher=matcher
        )
        return tuple(new_list), count, categories
    return value, 0, set()


def is_egress_fail_closed() -> bool:
    """Report whether a residual protected value should block provider egress."""
    try:
        from models.system_settings import SettingKeys, SystemSettings
        return bool(SystemSettings.get(SettingKeys.AI_PRIVACY_FAIL_CLOSED, True))
    except Exception:
        # A settings lookup failure must not silently downgrade the control.
        return True


def _find_residual_protected_values(
    payload: Any,
    aliases: list[PrivacyAlias],
    level: str,
    matcher: tuple[re.Pattern[str] | None, dict[str, PrivacyAlias]] | None = None,
) -> set[str]:
    """Return protected entity categories still present after substitution.

    This verifies the control rather than assuming it worked, in two passes.
    The first re-runs the alias matcher over the sanitized text: anything it
    still matches is a known vault value that substitution failed to replace.
    The second re-extracts entities to catch protected values the vault never
    held at all.

    Values we deliberately decline to substitute are excluded: alias tokens
    themselves, and originals rejected as too short or too generic to swap.
    """
    allowed_types = _allowed_entity_types(level)
    if not allowed_types:
        return set()

    residual: set[str] = set()
    texts = _string_leaves(payload)

    pattern, by_original = matcher if matcher is not None else _build_alias_matcher(aliases)
    if pattern is not None:
        for text in texts:
            for match in pattern.finditer(text):
                row = by_original.get(match.group(0).lower())
                if row is not None and row.entity_type in allowed_types:
                    residual.add(row.entity_type)

    alias_tokens = {
        (row.alias_value or '').lower() for row in aliases if row.alias_value
    }
    unsubstitutable = {
        (row.original_value or '').lower()
        for row in aliases
        if not _is_replaceable_alias(row)
    }

    for text in texts:
        for key in extract_alias_candidates_from_text(text):
            if key.entity_type not in allowed_types:
                continue
            value = key.normalized_value.lower()
            if value in alias_tokens or value in unsubstitutable:
                continue
            if len(value) < MIN_ALIAS_REPLACEMENT_LENGTH:
                continue
            if value in ALIAS_REPLACEMENT_STOPWORDS:
                continue
            if ALIAS_TOKEN_RE.fullmatch(key.normalized_value):
                continue
            residual.add(key.entity_type)
    return residual


def sanitize_for_ai_egress(value: Any, *, context: AIPrivacyContext | None, provider: Any) -> SanitizedPayload:
    """Sanitize AI-bound payloads using case-scoped aliases."""
    started = time.time()
    level = _effective_privacy_level(context, provider)
    _ensure_context_allowed(context, provider, level)
    if level == PRIVACY_LEVEL_OFF or not context or context.content_scope != PRIVACY_SCOPE_CASE_CONTENT or not context.case_id:
        duration = int((time.time() - started) * 1000)
        return SanitizedPayload(
            value=_strip_presanitized_markers(value),
            metadata=_privacy_metadata(level, context, 0, set(), duration),
        )
    _ensure_aliases_for_payload(context.case_id, value, level)
    aliases = _load_aliases_for_case(context.case_id, level)
    matcher = _cached_matcher_for_case(context.case_id, level, aliases)
    sanitized, replacements, categories = _apply_aliases(value, aliases, matcher=matcher)

    fail_closed = is_egress_fail_closed()
    residual: set[str] = set()
    if not is_local_provider(provider):
        residual = _find_residual_protected_values(sanitized, aliases, level, matcher)

    duration = int((time.time() - started) * 1000)
    metadata = _privacy_metadata(
        level,
        context,
        replacements,
        categories,
        duration,
        residual_categories=residual,
        fail_closed=fail_closed,
    )
    if residual and fail_closed:
        raise PrivacyEgressLeakError(residual, context.case_id)
    return SanitizedPayload(value=_strip_presanitized_markers(sanitized), metadata=metadata)


def sanitize_case_context_blocks(
    case_id: int,
    blocks: list[str],
    *,
    provider: Any,
) -> list[str]:
    """Alias and verify case-derived prompt text before it is composed.

    Sanitizing the assembled prompt at the router cannot tell CaseScope's own
    instructions from case content, so a vault holding ordinary words rewrites
    the instructions themselves. Callers sanitize the case-derived blocks here
    and mark the resulting message with PRESANITIZED_MESSAGE_KEY; authored text
    then never reaches the sanitizer at all.

    The blocks are sanitized in one call because the matcher is compiled per
    call. Verification and the fail-closed check still apply, so a block that
    slips through unaliased raises rather than being sent.
    """
    if not blocks:
        return []
    sanitized = sanitize_for_ai_egress(
        list(blocks),
        context=AIPrivacyContext.case_content(case_id),
        provider=provider,
    )
    values = sanitized.value
    if not isinstance(values, list) or len(values) != len(blocks):
        raise RuntimeError('Cloud AI egress blocked: case context sanitization returned an unexpected shape')
    return [str(item) for item in values]


def build_display_rehydrator(case_id: int) -> Callable[[str], str]:
    """Return a reusable text rehydrator with the case alias vault loaded once.

    Streaming callers rehydrate many small fragments, so the vault read must not
    be repeated per fragment.
    """
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

    return rehydrate_text


def _rehydrate_payload(payload: Any, rehydrate_text: Callable[[str], str]) -> Any:
    if isinstance(payload, str):
        return rehydrate_text(payload)
    if isinstance(payload, dict):
        return {key: _rehydrate_payload(value, rehydrate_text) for key, value in payload.items()}
    if isinstance(payload, list):
        return [_rehydrate_payload(item, rehydrate_text) for item in payload]
    if isinstance(payload, tuple):
        return tuple(_rehydrate_payload(item, rehydrate_text) for item in payload)
    return payload


def rehydrate_for_display(case_id: int, payload: Any, privacy_context: AIPrivacyContext | None = None) -> Any:
    """Rehydrate alias tokens for authorized local display boundaries."""
    return _rehydrate_payload(payload, build_display_rehydrator(case_id))


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
    if entity_type.endswith('IPV4') or entity_type.endswith('IPV6'):
        return str(ipaddress.ip_address(text))
    if entity_type in {'UNC_PATH', 'FILEPATH'}:
        return text.replace('/', '\\').lower()
    return text.lower()


def _valid_ip(value: Any) -> str | None:
    """Return the normalized form of an IPv4 or IPv6 literal, or None."""
    try:
        return str(ipaddress.ip_address(_clean(value)))
    except ValueError:
        return None


def _valid_ipv4(value: Any) -> str | None:
    normalized = _valid_ip(value)
    if normalized is None or ipaddress.ip_address(normalized).version != 4:
        return None
    return normalized


def _ip_type(value: Any, client_public_ips: set[str] | None = None) -> str | None:
    normalized = _valid_ip(value)
    if not normalized:
        return None
    ip_obj = ipaddress.ip_address(normalized)
    suffix = 'IPV4' if ip_obj.version == 4 else 'IPV6'
    if normalized in (client_public_ips or set()):
        return f'CLIENT_PUBLIC_{suffix}'
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
        return f'INTERNAL_{suffix}'
    return f'EXTERNAL_{suffix}'


def is_well_known_sid(value: Any) -> bool:
    """Report whether a SID names a built-in principal rather than an account."""
    text = _clean(value).lower()
    if not text:
        return False
    return text in WELL_KNOWN_SIDS or text.startswith(WELL_KNOWN_SID_PREFIXES)


def _add_sid(
    candidates: dict[AliasKey, AliasCandidate],
    value: Any,
    source_field: str,
    timestamp: datetime | None,
) -> None:
    if is_well_known_sid(value):
        return
    _add_candidate(candidates, 'SID', value, source_field, timestamp)


def _guid_entity_type(haystack: str, start: int) -> str | None:
    """Classify a GUID from the label immediately preceding it.

    An unlabelled GUID is not treated as a directory identifier. Windows paths
    are full of volume, servicing and component GUIDs, and classifying those as
    OBJECT_ID both aliased away detail an analyst needs and buried the real
    identifiers: they accounted for the largest single share of the vault.
    """
    window = haystack[max(0, start - 40):start]
    if GUID_TENANT_CONTEXT_RE.search(window):
        return 'TENANT_ID'
    if GUID_OBJECT_CONTEXT_RE.search(window):
        return 'OBJECT_ID'
    return None


def _add_person_name_from_localpart(
    candidates: dict[AliasKey, AliasCandidate],
    local_part: Any,
    source_field: str,
    timestamp: datetime | None,
) -> None:
    """Register 'first.last' style identifiers as a person name."""
    match = PERSON_NAME_LOCALPART_RE.match(_clean(local_part))
    if not match:
        return
    first, last = match.group(1), match.group(2)
    if first.lower() in NON_PERSON_NAME_TOKENS or last.lower() in NON_PERSON_NAME_TOKENS:
        return
    _add_candidate(candidates, 'PERSON_NAME', f'{first} {last}', source_field, timestamp)


def _add_filepath_segments(
    candidates: dict[AliasKey, AliasCandidate],
    path: Any,
    source_field: str,
    timestamp: datetime | None,
) -> None:
    """Alias the customer-specific parts of a path, keeping its OS shape.

    Directory names that describe the Windows layout are preserved so that
    location signals such as \\Temp\\ or \\AppData\\ still reach the model,
    while project, client and document names are replaced.
    """
    text = _clean(path).replace('/', '\\')
    if not text:
        return
    segments = [segment for segment in text.split('\\') if segment]
    for index, segment in enumerate(segments):
        lowered = segment.lower()
        if lowered in PRESERVED_PATH_SEGMENTS or lowered in SKIP_VALUES:
            continue
        if index == 0 and len(segment) == 2 and segment.endswith(':'):
            continue
        if any(lowered.endswith(suffix) for suffix in PRESERVED_FILE_EXTENSIONS):
            continue
        _add_candidate(candidates, 'FILEPATH', segment, source_field, timestamp)


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
    if _is_generic_identifier_word(entity_type, normalized):
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
        _add_person_name_from_localpart(candidates, local, source_field, timestamp)
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


def _is_path_account_match(match: re.Match[str], path_spans: list[tuple[int, int]]) -> bool:
    """Report whether a DOMAIN\\USERNAME hit is really a filesystem path segment."""
    start, end = match.span()
    if any(start >= span_start and end <= span_end for span_start, span_end in path_spans):
        return True
    if match.group(1).strip().lower() in PATH_SEGMENT_TOKENS:
        return True
    if match.group(2).strip().lower() in PATH_SEGMENT_TOKENS:
        return True
    # A drive-letter prefix ('C:\\Users\\...') or a further path separator after
    # the pair means we are walking a path, not reading an account name.
    prefix = match.string[max(0, start - 2):start]
    return prefix.endswith(':\\') or prefix.endswith('\\')


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

    # UNC and profile paths are matched first so their spans can be excluded
    # from the DOMAIN\USERNAME pass, which would otherwise read a path segment
    # pair such as 'Documents\CUI' as an account.
    unc_matches = list(UNC_RE.finditer(haystack))
    profile_matches = list(WINDOWS_PROFILE_RE.finditer(haystack))
    path_spans = [match.span() for match in (*unc_matches, *profile_matches)]

    for match in WINDOWS_ACCOUNT_RE.finditer(haystack):
        if _is_path_account_match(match, path_spans):
            continue
        _add_username(candidates, f'{match.group(1)}\\{match.group(2)}', source_field, timestamp)

    for match in unc_matches:
        unc_path = match.group(0)
        host = match.group(1)
        share = match.group(2)
        _add_candidate(candidates, 'UNC_PATH', unc_path, source_field, timestamp)
        _add_host(candidates, host, source_field, timestamp)
        _add_candidate(candidates, 'SHARE', share, source_field, timestamp)

    for match in profile_matches:
        _add_candidate(candidates, 'USERNAME', match.group(1), source_field, timestamp)

    for match in LINUX_HOME_RE.finditer(haystack):
        _add_candidate(candidates, 'USERNAME', match.group(1), source_field, timestamp)

    for match in BARE_HOST_CONTEXT_RE.finditer(haystack):
        _add_host(candidates, match.group(1) or match.group(2), source_field, timestamp)

    for match in IPV4_RE.finditer(haystack):
        entity_type = _ip_type(match.group(0), client_public_ips=client_public_ips)
        if entity_type:
            _add_candidate(candidates, entity_type, match.group(0), source_field, timestamp)

    for match in IPV6_RE.finditer(haystack):
        entity_type = _ip_type(match.group(0), client_public_ips=client_public_ips)
        if entity_type:
            _add_candidate(candidates, entity_type, match.group(0), source_field, timestamp)

    for match in SID_RE.finditer(haystack):
        _add_sid(candidates, match.group(0), source_field, timestamp)

    for match in GUID_RE.finditer(haystack):
        guid_type = _guid_entity_type(haystack, match.start())
        if guid_type:
            _add_candidate(
                candidates,
                guid_type,
                match.group(0),
                source_field,
                timestamp,
            )

    for match in WINDOWS_PATH_RE.finditer(haystack):
        _add_filepath_segments(candidates, match.group(0), source_field, timestamp)

    url_host_spans: list[tuple[int, int]] = []
    for match in URL_RE.finditer(haystack):
        _add_candidate(candidates, 'URL', match.group(0), source_field, timestamp)
        host = match.group(1).rsplit(':', 1)[0] if match.group(1) else ''
        if host and not _valid_ip(host) and _looks_like_fqdn(host):
            url_host_spans.append(match.span(1))
            _add_candidate(candidates, 'EXTERNAL_DOMAIN', host, source_field, timestamp)

    for match in FQDN_RE.finditer(haystack):
        # A host reached over http(s) is an internet destination, already
        # recorded as EXTERNAL_DOMAIN rather than an internal AD name.
        if any(
            match.start() >= start and match.end() <= end
            for start, end in url_host_spans
        ):
            continue
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


def _highest_alias_number(case_id: int, entity_type: str) -> int:
    """Return the highest alias number already issued for this case and type.

    Alias values are '{ENTITY_TYPE}_{number}', so the number is recoverable from
    the vault itself. Read it rather than trusting the counter row to exist.
    """
    highest = db.session.query(
        db.func.max(
            db.cast(
                db.func.substring(PrivacyAlias.alias_value, r'_(\d+)$'),
                db.Integer,
            )
        )
    ).filter(
        PrivacyAlias.case_id == case_id,
        PrivacyAlias.entity_type == entity_type,
    ).scalar()
    return int(highest or 0)


def _next_alias_value(case_id: int, entity_type: str) -> str:
    counter = PrivacyAliasCounter.query.filter_by(
        case_id=case_id,
        entity_type=entity_type,
    ).with_for_update().first()
    if counter is None:
        # A missing counter does not mean an empty vault. A --reset drops every
        # counter but keeps aliases it did not create, and a restore can lose
        # the counter too. Starting at 1 then reissues a number that is already
        # taken and the unique constraint on (case_id, alias_value) aborts the
        # whole rebuild, so resume above what the vault already holds.
        counter = PrivacyAliasCounter(
            case_id=case_id,
            entity_type=entity_type,
            next_number=_highest_alias_number(case_id, entity_type) + 1,
        )
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


def _candidate_is_vaultable(
    candidate: AliasCandidate,
    allowed_types: set[str] | None,
) -> bool:
    """Reject a candidate the configured level would never substitute."""
    if allowed_types is not None and candidate.entity_type not in allowed_types:
        return False
    return len(candidate.normalized_value or '') <= MAX_VAULTED_VALUE_LENGTH


def _scan_distinct_field(
    *,
    client: Any,
    case_id: int,
    field_name: str,
    extractor,
    client_public_ips: set[str],
    candidates: dict[AliasKey, AliasCandidate],
    limit: int | None = None,
    allowed_types: set[str] | None = None,
) -> int:
    value_sql = f"ifNull(toString({field_name}), '')" if field_name in {'src_ip', 'dst_ip'} else field_name
    limit_sql = f'ORDER BY seen_count DESC LIMIT {int(limit)}' if limit else ''
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
        {limit_sql}
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
        _merge_candidate_maps(candidates, {
            key: temp_candidate
            for key, temp_candidate in temp_candidates.items()
            if _candidate_is_vaultable(temp_candidate, allowed_types)
        })
        distinct_count += 1
    return distinct_count


def _scan_distinct_ip_field(
    *,
    client: Any,
    case_id: int,
    field_name: str,
    client_public_ips: set[str],
    candidates: dict[AliasKey, AliasCandidate],
    limit: int | None = None,
    allowed_types: set[str] | None = None,
) -> int:
    value_sql = f"ifNull(toString({field_name}), '')"
    limit_sql = f'ORDER BY seen_count DESC LIMIT {int(limit)}' if limit else ''
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
        {limit_sql}
        """,
        parameters={'case_id': case_id},
    )
    distinct_count = 0
    for value, seen_count, first_seen_at, last_seen_at in result.result_rows:
        entity_type = _ip_type(value, client_public_ips=client_public_ips)
        if entity_type and (allowed_types is None or entity_type in allowed_types):
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


def scan_clickhouse_case_alias_candidates(
    case_id: int,
    *,
    batch_size: int = 5000,
    privacy_level: str | None = None,
) -> dict[str, Any]:
    """Scan original ClickHouse indexed fields for a case and return alias candidates.

    This uses ClickHouse aggregation over distinct indexed/event columns instead of
    replaying every event row through Python. It keeps ClickHouse original data intact
    and models the aliases that would be available at the AI egress boundary.

    Only the entity types the configured privacy level actually substitutes are
    vaulted. Vaulting the rest builds a large index of values that are never
    swapped: on a cmmc_cui install, external addresses and URLs alone accounted
    for most of the rows. Raising the level later requires a rescan.
    """
    from models.case import Case
    from utils.clickhouse import get_client

    case = Case.get_by_id(case_id)
    if not case:
        raise ValueError(f'Case {case_id} not found')

    level = normalize_privacy_level(privacy_level) if privacy_level else get_configured_privacy_level()
    allowed_types = set(PRIVACY_ENTITY_TYPES_BY_LEVEL.get(level, set()))
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
        limit=TYPED_FIELD_SCAN_LIMIT,
        allowed_types=allowed_types,
    )
    distinct_sources['domain'] = _scan_distinct_field(
        client=client,
        case_id=case_id,
        field_name='domain',
        extractor=_add_domain,
        client_public_ips=client_public_ips,
        candidates=candidates,
        limit=TYPED_FIELD_SCAN_LIMIT,
        allowed_types=allowed_types,
    )
    for host_field in ('source_host', 'remote_host', 'workstation_name'):
        distinct_sources[host_field] = _scan_distinct_field(
            client=client,
            case_id=case_id,
            field_name=host_field,
            extractor=_add_host,
            client_public_ips=client_public_ips,
            candidates=candidates,
            limit=TYPED_FIELD_SCAN_LIMIT,
            allowed_types=allowed_types,
        )
    # Free-text columns carry the SIDs, GUIDs and paths that the typed columns
    # never expose. These are high cardinality, so only the most frequent
    # distinct values are scanned.
    for text_field in SCANNED_TEXT_FIELDS:
        def _extract_text(temp, value, field, ts, _ips=client_public_ips):
            _extract_text_entities(temp, value, field, ts, _ips)

        distinct_sources[text_field] = _scan_distinct_field(
            client=client,
            case_id=case_id,
            field_name=text_field,
            extractor=_extract_text,
            client_public_ips=client_public_ips,
            candidates=candidates,
            limit=TEXT_FIELD_SCAN_LIMIT,
            allowed_types=allowed_types,
        )
    for ip_field in ('src_ip', 'dst_ip'):
        distinct_sources[ip_field] = _scan_distinct_ip_field(
            client=client,
            case_id=case_id,
            field_name=ip_field,
            client_public_ips=client_public_ips,
            candidates=candidates,
            limit=TYPED_FIELD_SCAN_LIMIT,
            allowed_types=allowed_types,
        )

    truncated = max(0, len(candidates) - MAX_CASE_VAULT_CANDIDATES)
    if truncated:
        logger.warning(
            'Case %s produced %s alias candidates; keeping the %s most frequent. '
            'A vault larger than this cannot be substituted in reasonable time.',
            case_id,
            len(candidates),
            MAX_CASE_VAULT_CANDIDATES,
        )
        candidates = dict(
            sorted(
                candidates.items(),
                key=lambda item: item[1].seen_count,
                reverse=True,
            )[:MAX_CASE_VAULT_CANDIDATES]
        )

    by_type = Counter(candidate.entity_type for candidate in candidates.values())
    return {
        'case_id': case_id,
        'event_count': event_count,
        'client_public_ips': sorted(client_public_ips),
        'privacy_level': level,
        'distinct_source_values': dict(sorted(distinct_sources.items())),
        'scan_mode': 'clickhouse_distinct_indexed_fields',
        'candidates': candidates,
        'candidate_count': len(candidates),
        'candidates_truncated': truncated,
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
    privacy_level: str | None = None,
) -> dict[str, Any]:
    """Populate the alias vault for a case from original ClickHouse event data."""
    if reset_generated:
        PrivacyAlias.query.filter_by(case_id=case_id, source='ai_privacy_event_backfill').delete()
        PrivacyAliasCounter.query.filter_by(case_id=case_id).delete()
        db.session.commit()

    scan = scan_clickhouse_case_alias_candidates(
        case_id,
        batch_size=batch_size,
        privacy_level=privacy_level,
    )
    upsert = upsert_alias_candidates(case_id, scan['candidates'])
    stored = stored_alias_summary(case_id)
    comparison = compare_candidates_to_stored(case_id, scan['candidates'])
    return {
        'case_id': case_id,
        'event_count': scan['event_count'],
        'client_public_ips': scan['client_public_ips'],
        'privacy_level': scan.get('privacy_level'),
        'extracted': {
            'candidate_count': scan['candidate_count'],
            'candidate_by_type': scan['candidate_by_type'],
            'candidates_truncated': scan.get('candidates_truncated', 0),
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
