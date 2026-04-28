"""Cloud AI Privacy Mode alias extraction and vault population."""
from __future__ import annotations

import ipaddress
import json
import re
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
