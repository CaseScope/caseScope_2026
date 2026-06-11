"""Shared forensic retrieval helpers for Chat Agent."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from models.case import Case
from models.case_file import CaseFile
from models.database import db
from models.memory_data import (
    MemoryCredential,
    MemoryMalfind,
    MemoryModule,
    MemoryNetwork,
    MemoryProcess,
    MemoryService,
)
from models.memory_job import MemoryJob
from models import network_log
from utils.clickhouse import get_fresh_client
from utils.event_ioc_state import build_ioc_projection, ensure_event_ioc_state_tables
from utils.event_noise_state import build_effective_not_noise_clause, ensure_event_noise_state_tables
from utils.provenance import (
    apply_record_provenance,
    annotate_artifact_records,
    attach_payload_provenance,
    build_record_provenance_summary,
)
from utils.timezone import format_for_display


def _normalize_host_filters(hostname: Any) -> List[str]:
    """Normalize host filters from tool inputs into a clean string list."""
    if not hostname:
        return []

    if isinstance(hostname, str):
        raw = hostname.strip()
        if not raw:
            return []
        if raw.startswith('['):
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, list):
                    return [str(item).strip() for item in parsed if str(item).strip()]
            except (TypeError, ValueError, json.JSONDecodeError):
                pass
        return [part.strip() for part in raw.split(',') if part.strip()]

    if isinstance(hostname, (list, tuple, set)):
        return [str(item).strip() for item in hostname if str(item).strip()]

    normalized = str(hostname).strip()
    return [normalized] if normalized else []


def normalize_forensic_search_terms(search: Any, *, max_terms: int = 8) -> List[str]:
    """Expand analyst-style OR term lists while preserving literal paths and URLs."""
    raw = str(search or '').strip()
    if not raw:
        return []

    path_like = bool(re.search(r'([a-zA-Z]:\\|\\\\|://)', raw))
    split_pattern = r'\s*(?:,|;|\||\bor\b)\s*'
    if not path_like:
        split_pattern = r'\s*(?:/|,|;|\||\bor\b)\s*'

    parts = [
        part.strip().strip('"\'')
        for part in re.split(split_pattern, raw, flags=re.IGNORECASE)
        if part.strip().strip('"\'')
    ]
    if len(parts) <= 1:
        return [raw]

    terms: List[str] = []
    seen = set()
    for part in parts:
        if len(part) < 2:
            continue
        normalized = part.lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        terms.append(part)
        if len(terms) >= max_terms:
            break
    return terms or [raw]


def build_case_insensitive_any_clause(
    expression_sql: str,
    param_prefix: str,
    terms: List[str],
    params: Dict[str, Any],
) -> str:
    """Build a bound OR predicate for matching any search term."""
    clauses = []
    for index, term in enumerate(terms):
        key = f"{param_prefix}_{index}"
        params[key] = term
        clauses.append(f"positionCaseInsensitive({expression_sql}, {{{key}:String}}) > 0")
    return "(" + " OR ".join(clauses) + ")" if clauses else "1 = 0"


def _case_and_timezone(case_id: int):
    case = Case.get_by_id(case_id)
    if not case:
        raise ValueError('Case not found')
    return case, case.timezone or 'UTC'


def build_event_corpus_coverage(
    client: Any,
    case_id: int,
    *,
    reviewed_filters: Optional[Dict[str, Any]] = None,
    result_metadata: Optional[Dict[str, Any]] = None,
    source_table: str = 'events',
) -> Dict[str, Any]:
    """Return compact case corpus metadata so empty results do not imply no coverage."""
    try:
        coverage_result = client.query(
            """
            SELECT
                count() AS total_events,
                min(COALESCE(timestamp_utc, timestamp)) AS first_seen,
                max(COALESCE(timestamp_utc, timestamp)) AS last_seen,
                groupUniqArray(25)(source_host) AS source_hosts,
                groupUniqArray(25)(artifact_type) AS artifact_types
            FROM events
            WHERE case_id = {case_id:UInt32}
            """,
            parameters={'case_id': int(case_id)},
        )
        row = coverage_result.result_rows[0] if coverage_result.result_rows else None
    except Exception:
        row = None

    if not row or len(row) < 5:
        source_metadata = {
            'source_table': source_table,
            'source_availability_status': 'unknown',
            'reviewed_filters': reviewed_filters or {},
        }
        return {
            'coverage_status': 'unknown',
            'source_availability_status': 'unknown',
            'coverage_detail': {
                'source_metadata': source_metadata,
                'result_metadata': result_metadata or {},
            },
        }

    total_events, first_seen, last_seen, source_hosts, artifact_types = row[:5]
    try:
        total_events = int(total_events or 0)
    except (TypeError, ValueError):
        source_metadata = {
            'source_table': source_table,
            'source_availability_status': 'unknown',
            'reviewed_filters': reviewed_filters or {},
        }
        return {
            'coverage_status': 'unknown',
            'source_availability_status': 'unknown',
            'coverage_detail': {
                'source_metadata': source_metadata,
                'result_metadata': result_metadata or {},
            },
        }
    normalized_hosts = sorted(str(value) for value in (source_hosts or []) if value)
    normalized_artifacts = sorted(str(value) for value in (artifact_types or []) if value)
    source_status = 'available' if total_events else 'not_available'
    coverage_status = 'complete' if total_events else 'not_available'

    source_metadata = {
        'source_table': source_table,
        'source_availability_status': source_status,
        'case_event_count': total_events,
        'ingested_time_start': str(first_seen) if first_seen else None,
        'ingested_time_end': str(last_seen) if last_seen else None,
        'source_hosts': normalized_hosts,
        'artifact_types_present': normalized_artifacts,
        'reviewed_filters': reviewed_filters or {},
    }
    return {
        'coverage_status': coverage_status,
        'source_availability_status': source_status,
        'coverage_detail': {
            'source_metadata': source_metadata,
            'result_metadata': result_metadata or {},
        },
    }


def _merge_extra_field_provenance(record: Dict[str, Any], extra_fields: Any) -> Dict[str, Any]:
    """Carry parser-emitted provenance from stored event metadata into tool payloads."""
    return apply_record_provenance(record, extra_fields)


def search_artifacts(
    case_id: int,
    *,
    search: str,
    artifact_type: str = '',
    host: str = '',
    username: str = '',
    limit: int = 25,
    include_noise: bool = True,
) -> Dict[str, Any]:
    """Search the normalized events table across forensic artifact types."""
    if not search:
        return {"error": "search is required"}

    _, case_tz = _case_and_timezone(case_id)
    client = get_fresh_client()
    ensure_event_noise_state_tables(client)
    ensure_event_ioc_state_tables(client)
    ioc_projection = build_ioc_projection(alias='e')
    limit = min(max(limit or 25, 1), 50)
    search_terms = normalize_forensic_search_terms(search)

    artifact_types = [artifact_type.strip() for artifact_type in artifact_type.split(',') if artifact_type.strip()]

    params: Dict[str, Any] = {
        'case_id': int(case_id),
        'limit': limit,
    }
    where_parts = [
        "e.case_id = {case_id:UInt32}",
        build_case_insensitive_any_clause("e.search_blob", "search_term", search_terms, params),
    ]
    if not include_noise:
        where_parts.insert(1, build_effective_not_noise_clause(alias='e', case_id_sql='e.case_id'))

    if host:
        params['host'] = host
        where_parts.append("lower(e.source_host) = lower({host:String})")
    if username:
        params['username'] = username
        where_parts.append(
            "(lower(e.username) = lower({username:String}) OR positionCaseInsensitive(e.search_blob, {username:String}) > 0)"
        )
    if artifact_types:
        params['artifact_types'] = artifact_types
        where_parts.append("has({artifact_types:Array(String)}, e.artifact_type)")

    where_sql = ' AND '.join(where_parts)

    count_result = client.query(
        f"SELECT count() FROM events AS e {ioc_projection['join_sql']} WHERE {where_sql}",
        parameters=params,
    )
    total_matches = count_result.result_rows[0][0] if count_result.result_rows else 0

    type_result = client.query(
        f"""
        SELECT artifact_type, count() as cnt
        FROM events AS e
        {ioc_projection["join_sql"]}
        WHERE {where_sql}
        GROUP BY artifact_type
        ORDER BY cnt DESC
        """,
        parameters=params,
    )
    artifact_breakdown = {row[0] or 'unknown': row[1] for row in type_result.result_rows}

    row_result = client.query(
        f"""
        SELECT
            COALESCE(e.timestamp_utc, e.timestamp) as ts,
            e.artifact_type,
            e.source_host,
            e.username,
            e.event_id,
            e.process_name,
            e.target_path,
            e.command_line,
            e.rule_title,
            e.source_file,
            {ioc_projection["ioc_types_sql"]} as ioc_types,
            e.extra_fields,
            substring(e.search_blob, 1, 220) as summary
        FROM events AS e
        {ioc_projection["join_sql"]}
        WHERE {where_sql}
        ORDER BY ts DESC
        LIMIT {{limit:UInt32}}
        """,
        parameters=params,
    )

    artifacts = []
    for row in row_result.result_rows:
        if len(row) >= 13:
            ts, art_type, source_host, user, event_id, process_name, target_path, command_line, rule_title, source_file, ioc_types, extra_fields, summary = row[:13]
        else:
            ts, art_type, source_host, user, event_id, process_name, target_path, command_line, rule_title, source_file, ioc_types, summary = row
            extra_fields = {}
        artifact = {
            '_artifact_type': art_type or '',
            'timestamp': format_for_display(ts, case_tz) if ts else '',
            'artifact_type': art_type or '',
            'host': source_host or '',
            'username': user or '',
            'event_id': event_id or '',
            'process_name': process_name or '',
            'target_path': target_path or '',
            'command_line': (command_line or '')[:180],
            'rule_title': rule_title or '',
            'source_file': source_file or '',
            'ioc_types': list(ioc_types) if ioc_types else [],
            'summary': summary or '',
        }
        _merge_extra_field_provenance(artifact, extra_fields)
        artifacts.append(artifact)

    annotate_artifact_records(
        artifacts,
        artifact_type_key='_artifact_type',
        fields=[
            'timestamp',
            'artifact_type',
            'host',
            'username',
            'event_id',
            'process_name',
            'target_path',
            'command_line',
            'rule_title',
            'source_file',
            'ioc_types',
            'summary',
        ],
    )
    provenance_summary = build_record_provenance_summary(artifacts)
    returned_count = len(artifacts)
    result_metadata = {
        'total_matches': int(total_matches or 0),
        'returned_count': returned_count,
        'limit': limit,
        'truncated': int(total_matches or 0) > returned_count,
        'noise_filter': 'included' if include_noise else 'excluded',
        'expanded_search_terms': search_terms,
    }
    coverage = build_event_corpus_coverage(
        client,
        case_id,
        reviewed_filters={
            'search': search,
            'expanded_search_terms': search_terms,
            'artifact_filter': artifact_types,
            'host': host or '',
            'username': username or '',
            'include_noise': include_noise,
        },
        result_metadata=result_metadata,
    )

    return attach_payload_provenance({
        'search': search,
        'expanded_search_terms': search_terms,
        'artifact_filter': artifact_types,
        'total_matches': total_matches,
        'returned_count': returned_count,
        'truncated': result_metadata['truncated'],
        'noise_filter': result_metadata['noise_filter'],
        'artifact_types': artifact_breakdown,
        'artifacts': artifacts,
        **coverage,
    }, summary=provenance_summary)


def get_browser_download_rows(
    case_id: int,
    *,
    host: str = '',
    username: str = '',
    filename: str = '',
    url: str = '',
    search: str = '',
    limit: int = 50,
) -> Dict[str, Any]:
    """Return browser download artifacts for a case."""
    _, case_tz = _case_and_timezone(case_id)
    client = get_fresh_client()
    ensure_event_ioc_state_tables(client)
    ioc_projection = build_ioc_projection(alias='e')
    limit = min(max(limit or 50, 1), 200)
    search_terms = normalize_forensic_search_terms(search)

    where_parts = [
        "e.case_id = {case_id:UInt32}",
        "e.artifact_type = 'browser_download'",
    ]
    params: Dict[str, Any] = {'case_id': int(case_id), 'limit': limit * 5}
    if host:
        params['host'] = host
        where_parts.append("positionCaseInsensitive(e.source_host, {host:String}) > 0")
    if username:
        params['username'] = username
        where_parts.append("positionCaseInsensitive(e.username, {username:String}) > 0")
    if filename:
        params['filename'] = filename
        where_parts.append(
            "positionCaseInsensitive(concat(COALESCE(e.raw_json, ''), ' ', COALESCE(e.target_path, ''), ' ', COALESCE(e.search_blob, '')), {filename:String}) > 0"
        )
    if url:
        params['url'] = url
        where_parts.append(
            "positionCaseInsensitive(concat(COALESCE(e.raw_json, ''), ' ', COALESCE(e.search_blob, '')), {url:String}) > 0"
        )
    if search_terms:
        where_parts.append(
            build_case_insensitive_any_clause(
                "concat(COALESCE(e.raw_json, ''), ' ', COALESCE(e.target_path, ''), ' ', COALESCE(e.search_blob, ''), ' ', COALESCE(e.source_host, ''), ' ', COALESCE(e.username, ''))",
                "search_term",
                search_terms,
                params,
            )
        )
    where_sql = ' AND '.join(where_parts)

    count_result = client.query(
        f"""
        SELECT count()
        FROM events AS e
        {ioc_projection["join_sql"]}
        WHERE {where_sql}
        """,
        parameters=params,
    )
    total_matches = int(count_result.result_rows[0][0]) if count_result.result_rows else 0

    result = client.query(
        f"""
        SELECT
            COALESCE(e.timestamp_utc, e.timestamp) as ts,
            e.source_host,
            e.target_path,
            e.username,
            e.raw_json,
            e.extra_fields,
            {ioc_projection["ioc_types_sql"]} as ioc_types,
            e.source_file,
            e.case_file_id
        FROM events AS e
        {ioc_projection["join_sql"]}
        WHERE {where_sql}
        ORDER BY e.timestamp DESC
        LIMIT {{limit:UInt32}}
        """,
        parameters=params,
    )

    case_file_ids = {row[8] for row in result.result_rows if row[8]}
    case_file_usernames: Dict[int, str] = {}
    if case_file_ids:
        case_files = CaseFile.query.filter(CaseFile.id.in_(case_file_ids)).all()
        for case_file in case_files:
            if case_file.filename:
                match = re.search(r'[/\\]Users[/\\]([^/\\]+)[/\\]', case_file.filename, re.IGNORECASE)
                if match:
                    case_file_usernames[case_file.id] = match.group(1)

    downloads: List[Dict[str, Any]] = []
    search_lowers = [term.lower() for term in search_terms]
    filename_lower = filename.lower().strip()
    url_lower = url.lower().strip()
    username_lower = username.lower().strip()
    host_lower = host.lower().strip()

    for row in result.result_rows:
        timestamp, source_host, target_path, event_username, raw_json_str, extra_fields_str, ioc_types, source_file, case_file_id = row

        try:
            raw_json = json.loads(raw_json_str) if raw_json_str else {}
        except (TypeError, json.JSONDecodeError):
            raw_json = {}
        try:
            extra_fields = json.loads(extra_fields_str) if extra_fields_str else {}
        except (TypeError, json.JSONDecodeError):
            extra_fields = {}

        file_path = raw_json.get('file_path', raw_json.get('target_path', raw_json.get('current_path', target_path or '')))
        source_url = raw_json.get('url', raw_json.get('source_url', extra_fields.get('url', '')))
        entry_filename = raw_json.get('filename', '')
        if not entry_filename and file_path:
            entry_filename = file_path.split('\\')[-1].split('/')[-1]

        display_username = event_username or ''
        if not display_username and case_file_id:
            display_username = case_file_usernames.get(case_file_id, '')

        if host_lower and host_lower not in (source_host or '').lower():
            continue
        if username_lower and username_lower not in display_username.lower():
            continue
        if filename_lower and filename_lower not in entry_filename.lower():
            continue
        if url_lower and url_lower not in (source_url or '').lower():
            continue
        if search_lowers:
            haystack = ' '.join([
                source_host or '',
                display_username or '',
                entry_filename or '',
                file_path or '',
                source_url or '',
            ]).lower()
            if not any(term in haystack for term in search_lowers):
                continue

        downloads.append({
            '_artifact_type': 'browser_download',
            'timestamp': format_for_display(timestamp, case_tz) if timestamp else '',
            'source_host': source_host or '',
            'username': display_username,
            'filename': entry_filename or '(unknown)',
            'file_path': file_path or '',
            'source_url': source_url or '',
            'source_file': source_file or '',
            'ioc_types': list(ioc_types) if ioc_types else [],
            'has_ioc': bool(ioc_types),
        })
        _merge_extra_field_provenance(downloads[-1], extra_fields)
        if len(downloads) >= limit:
            break

    annotate_artifact_records(
        downloads,
        artifact_type_key='_artifact_type',
        fields=[
            'timestamp',
            'source_host',
            'username',
            'filename',
            'file_path',
            'source_url',
            'source_file',
            'ioc_types',
        ],
    )
    provenance_summary = build_record_provenance_summary(downloads)
    returned_count = len(downloads)
    result_metadata = {
        'total_matches': total_matches,
        'returned_count': returned_count,
        'limit': limit,
        'truncated': total_matches > returned_count,
    }
    coverage = build_event_corpus_coverage(
        client,
        case_id,
        reviewed_filters={
            'artifact_type': 'browser_download',
            'host': host or '',
            'username': username or '',
            'filename': filename or '',
            'url': url or '',
            'search': search or '',
            'expanded_search_terms': search_terms,
        },
        result_metadata=result_metadata,
    )

    return attach_payload_provenance({
        'downloads': downloads,
        'total': total_matches,
        'total_matches': total_matches,
        'returned_count': returned_count,
        'truncated': total_matches > returned_count,
        'expanded_search_terms': search_terms,
        **coverage,
    }, summary=provenance_summary)


def search_memory_artifacts(
    case_id: int,
    *,
    search: str,
    search_type: str = 'process',
    hostname: str = '',
    limit: int = 25,
) -> Dict[str, Any]:
    """Search memory-derived artifacts for a case."""
    if not search or len(search.strip()) < 2:
        return {"error": "Search term too short"}

    _case_and_timezone(case_id)
    limit = min(max(limit or 25, 1), 50)
    search = search.strip()
    search_lower = search.lower()
    host_filters = _normalize_host_filters(hostname)

    job_query = MemoryJob.query.filter_by(case_id=case_id, status='completed')
    if len(host_filters) == 1:
        job_query = job_query.filter(MemoryJob.hostname == host_filters[0])
    elif host_filters:
        job_query = job_query.filter(MemoryJob.hostname.in_(host_filters))
    jobs = job_query.all()
    job_ids = [job.id for job in jobs]
    job_map = {job.id: job for job in jobs}

    if not job_ids:
        return attach_payload_provenance({
            'search': search,
            'search_type': search_type,
            'results': [],
            'jobs_matched': 0,
            'total_jobs': 0,
            'total_matches': 0,
            'returned_count': 0,
            'truncated': False,
            'coverage_status': 'not_available',
            'source_availability_status': 'not_available',
            'coverage_detail': {
                'source_metadata': {
                    'source_table': 'memory_analysis',
                    'source_availability_status': 'not_available',
                    'source_hosts': host_filters,
                    'reviewed_filters': {
                        'search': search,
                        'search_type': search_type,
                        'hostname': hostname or '',
                    },
                },
                'result_metadata': {
                    'total_matches': 0,
                    'returned_count': 0,
                    'limit': limit,
                    'truncated': False,
                    'total_matches_exact': True,
                },
            },
        }, summary=build_record_provenance_summary([]))

    def _grouped_results(matches: List[Any], serializer):
        grouped: Dict[int, Dict[str, Any]] = {}
        for match in matches:
            if match.job_id not in grouped:
                job = job_map.get(match.job_id)
                grouped[match.job_id] = {
                    'job_id': match.job_id,
                    'hostname': job.hostname if job else 'Unknown',
                    'memory_time': job.memory_timestamp.isoformat() if job and job.memory_timestamp else None,
                    'matches': [],
                }
            grouped[match.job_id]['matches'].append(serializer(match))
        return list(grouped.values())

    results: List[Dict[str, Any]] = []
    if search_type == 'process':
        query = MemoryProcess.query.filter(
            MemoryProcess.case_id == case_id,
            MemoryProcess.job_id.in_(job_ids),
            db.or_(
                MemoryProcess.name_lower.contains(search_lower),
                MemoryProcess.cmdline.ilike(f'%{search}%'),
                MemoryProcess.path.ilike(f'%{search}%'),
            ),
        ).limit(limit).all()
        results = _grouped_results(query, lambda item: item.to_dict())
    elif search_type == 'network':
        query = MemoryNetwork.query.filter(
            MemoryNetwork.case_id == case_id,
            MemoryNetwork.job_id.in_(job_ids),
            db.or_(
                MemoryNetwork.foreign_addr.contains(search),
                MemoryNetwork.local_addr.contains(search),
                MemoryNetwork.owner.ilike(f'%{search}%'),
            ),
        ).limit(limit).all()
        results = _grouped_results(query, lambda item: item.to_dict())
    elif search_type == 'service':
        query = MemoryService.query.filter(
            MemoryService.case_id == case_id,
            MemoryService.job_id.in_(job_ids),
            db.or_(
                MemoryService.name_lower.contains(search_lower),
                MemoryService.display_name.ilike(f'%{search}%'),
                MemoryService.binary_path.ilike(f'%{search}%'),
            ),
        ).limit(limit).all()
        results = _grouped_results(query, lambda item: item.to_dict())
    elif search_type == 'path':
        proc_matches = MemoryProcess.query.filter(
            MemoryProcess.case_id == case_id,
            MemoryProcess.job_id.in_(job_ids),
            db.or_(
                MemoryProcess.path.ilike(f'%{search}%'),
                MemoryProcess.cmdline.ilike(f'%{search}%'),
            ),
        ).limit(limit).all()
        mod_matches = MemoryModule.query.filter(
            MemoryModule.case_id == case_id,
            MemoryModule.job_id.in_(job_ids),
            MemoryModule.mapped_path.ilike(f'%{search}%'),
        ).limit(limit).all()
        grouped: Dict[int, Dict[str, Any]] = {}
        for proc in proc_matches:
            if proc.job_id not in grouped:
                job = job_map.get(proc.job_id)
                grouped[proc.job_id] = {
                    'job_id': proc.job_id,
                    'hostname': job.hostname if job else 'Unknown',
                    'memory_time': job.memory_timestamp.isoformat() if job and job.memory_timestamp else None,
                    'process_matches': [],
                    'module_matches': [],
                }
            grouped[proc.job_id]['process_matches'].append(proc.to_dict())
        for module in mod_matches:
            if module.job_id not in grouped:
                job = job_map.get(module.job_id)
                grouped[module.job_id] = {
                    'job_id': module.job_id,
                    'hostname': job.hostname if job else 'Unknown',
                    'memory_time': job.memory_timestamp.isoformat() if job and job.memory_timestamp else None,
                    'process_matches': [],
                    'module_matches': [],
                }
            grouped[module.job_id]['module_matches'].append(module.to_dict())
        results = list(grouped.values())
    elif search_type == 'module':
        query = MemoryModule.query.filter(
            MemoryModule.case_id == case_id,
            MemoryModule.job_id.in_(job_ids),
            db.or_(
                MemoryModule.mapped_path.ilike(f'%{search}%'),
                MemoryModule.process_name.ilike(f'%{search}%'),
            ),
        ).limit(limit).all()
        results = _grouped_results(query, lambda item: item.to_dict())
    elif search_type == 'credential':
        query = MemoryCredential.query.filter(
            MemoryCredential.case_id == case_id,
            MemoryCredential.job_id.in_(job_ids),
            db.or_(
                MemoryCredential.username.ilike(f'%{search}%'),
                MemoryCredential.domain.ilike(f'%{search}%'),
                MemoryCredential.nt_hash.ilike(f'%{search}%'),
                MemoryCredential.cached_hash.ilike(f'%{search}%'),
            ),
        ).limit(limit).all()
        results = _grouped_results(query, lambda item: item.to_dict(mask_secrets=True))
    elif search_type == 'malfind':
        query = MemoryMalfind.query.filter(
            MemoryMalfind.case_id == case_id,
            MemoryMalfind.job_id.in_(job_ids),
            db.or_(
                MemoryMalfind.process_name.ilike(f'%{search}%'),
                MemoryMalfind.notes.ilike(f'%{search}%'),
                MemoryMalfind.disasm.ilike(f'%{search}%'),
            ),
        ).limit(limit).all()
        results = _grouped_results(query, lambda item: item.to_dict())
    else:
        return {"error": f"Unsupported search_type: {search_type}"}

    annotated_records: List[Dict[str, Any]] = []
    annotate_artifact_records(
        results,
        fields=['job_id', 'hostname', 'memory_time'],
    )
    annotated_records.extend(results)
    for group in results:
        for key in ('matches', 'process_matches', 'module_matches'):
            nested_records = group.get(key)
            if isinstance(nested_records, list) and nested_records:
                annotate_artifact_records(nested_records)
                annotated_records.extend(nested_records)
    provenance_summary = build_record_provenance_summary(annotated_records)
    returned_count = sum(
        len(group.get(key) or [])
        for group in results
        for key in ('matches', 'process_matches', 'module_matches')
        if isinstance(group.get(key), list)
    )
    truncated = returned_count >= limit

    return attach_payload_provenance({
        'search': search,
        'search_type': search_type,
        'results': results,
        'jobs_matched': len(results),
        'total_jobs': len(job_ids),
        'total_matches': returned_count,
        'returned_count': returned_count,
        'truncated': truncated,
        'coverage_status': 'complete',
        'source_availability_status': 'available',
        'coverage_detail': {
            'source_metadata': {
                'source_table': 'memory_analysis',
                'source_availability_status': 'available',
                'source_hosts': sorted(str(job.hostname) for job in jobs if getattr(job, 'hostname', None)),
                'reviewed_filters': {
                    'search': search,
                    'search_type': search_type,
                    'hostname': hostname or '',
                },
            },
            'result_metadata': {
                'total_matches': returned_count,
                'returned_count': returned_count,
                'limit': limit,
                'truncated': truncated,
                'total_matches_exact': False,
            },
        },
    }, summary=provenance_summary)


def get_unified_process_list(
    case_id: int,
    *,
    search: str = '',
    hostname: str = '',
    source: str = '',
    limit: int = 25,
) -> Dict[str, Any]:
    """Return a bounded unified process view across events and memory."""
    _, case_tz = _case_and_timezone(case_id)
    limit = min(max(limit or 25, 1), 50)
    source_filter = source.strip().lower()
    host_filters = _normalize_host_filters(hostname)
    search_terms = normalize_forensic_search_terms(search)
    processes: List[Dict[str, Any]] = []

    if source_filter in ('', 'all', 'events'):
        client = get_fresh_client()
        params: Dict[str, Any] = {'case_id': case_id, 'limit': limit}
        where_parts = [
            "case_id = {case_id:UInt32}",
            "process_name != ''",
            "process_id > 0",
            "("
            "process_name LIKE '%.exe' OR process_name LIKE '%.dll' OR process_name LIKE '%.bat' OR "
            "process_name LIKE '%.cmd' OR process_name LIKE '%.ps1' OR process_name LIKE '%.vbs' OR "
            "process_name LIKE '%.com' OR process_name LIKE '%.msi' OR process_name LIKE '%.js' OR process_name LIKE '%.wsf'"
            ")",
        ]
        if len(host_filters) == 1:
            params['hostname'] = host_filters[0]
            where_parts.append("source_host = {hostname:String}")
        elif host_filters:
            params['hostnames'] = host_filters
            where_parts.append("has({hostnames:Array(String)}, source_host)")
        if search_terms:
            clauses = []
            for index, term in enumerate(search_terms):
                key = f"search_term_{index}"
                params[key] = f"%{term}%"
                clauses.append(
                    f"(process_name ILIKE {{{key}:String}} OR command_line ILIKE {{{key}:String}} OR parent_process ILIKE {{{key}:String}})"
                )
            where_parts.append("(" + " OR ".join(clauses) + ")")

        result = client.query(
            f"""
            SELECT
                source_host,
                process_id,
                process_name,
                max(COALESCE(timestamp_utc, timestamp)) as latest_ts,
                argMax(parent_pid, COALESCE(timestamp_utc, timestamp)) as ppid_val,
                argMax(parent_process, COALESCE(timestamp_utc, timestamp)) as parent_proc_val,
                argMax(command_line, COALESCE(timestamp_utc, timestamp)) as cmdline_val,
                argMax(username, COALESCE(timestamp_utc, timestamp)) as username_val,
                argMax(process_path, COALESCE(timestamp_utc, timestamp)) as proc_path_val,
                argMax(artifact_type, COALESCE(timestamp_utc, timestamp)) as artifact_type_val,
                argMax(extra_fields, COALESCE(timestamp_utc, timestamp)) as extra_fields_val,
                count() as event_count
            FROM events
            WHERE {' AND '.join(where_parts)}
            GROUP BY source_host, process_id, process_name
            ORDER BY latest_ts DESC
            LIMIT {{limit:UInt32}}
            """,
            parameters=params,
        )
        for row in result.result_rows:
            if len(row) >= 12:
                hostname_val, pid, proc_name, latest_ts, ppid, parent_proc, cmdline, username_val, proc_path, artifact_type_val, extra_fields_val, event_count = row[:12]
            else:
                hostname_val, pid, proc_name, latest_ts, ppid, parent_proc, cmdline, username_val, proc_path, event_count = row
                artifact_type_val = ''
                extra_fields_val = {}
            process_record = {
                'source': 'events',
                '_artifact_type': artifact_type_val or '',
                'hostname': hostname_val,
                'pid': pid,
                'ppid': ppid,
                'process_name': proc_name or '',
                'parent_process': parent_proc or '',
                'command_line': cmdline or '',
                'username': username_val or '',
                'process_path': proc_path or '',
                'timestamp': format_for_display(latest_ts, case_tz) if latest_ts else '',
                'event_count': event_count,
            }
            _merge_extra_field_provenance(process_record, extra_fields_val)
            processes.append(process_record)

    if source_filter in ('', 'all', 'memory'):
        job_query = MemoryJob.query.filter_by(case_id=case_id, status='completed')
        if len(host_filters) == 1:
            job_query = job_query.filter(MemoryJob.hostname == host_filters[0])
        elif host_filters:
            job_query = job_query.filter(MemoryJob.hostname.in_(host_filters))
        job_ids = [job.id for job in job_query.all()]
        if job_ids:
            query = MemoryProcess.query.filter(
                MemoryProcess.case_id == case_id,
                MemoryProcess.job_id.in_(job_ids),
            )
            if search_terms:
                memory_clauses = []
                for term in search_terms:
                    memory_clauses.extend([
                        MemoryProcess.name.ilike(f'%{term}%'),
                        MemoryProcess.cmdline.ilike(f'%{term}%'),
                        MemoryProcess.path.ilike(f'%{term}%'),
                    ])
                query = query.filter(db.or_(*memory_clauses))
            for proc in query.order_by(MemoryProcess.create_time.desc()).limit(limit).all():
                processes.append({
                    'source': 'memory',
                    'hostname': proc.hostname,
                    'pid': proc.pid,
                    'ppid': proc.ppid,
                    'process_name': proc.name or '',
                    'parent_process': '',
                    'command_line': proc.cmdline or '',
                    'username': '',
                    'process_path': proc.path or '',
                    'timestamp': format_for_display(proc.create_time, case_tz) if proc.create_time else '',
                    'event_count': 1,
                    'cross_memory_count': proc.cross_memory_count,
                    'cross_events_count': proc.cross_events_count,
                })

    processes.sort(key=lambda item: item.get('timestamp', ''), reverse=True)
    annotate_artifact_records(
        processes,
        artifact_type_key='_artifact_type',
        fields=[
            'source',
            'hostname',
            'pid',
            'ppid',
            'process_name',
            'parent_process',
            'command_line',
            'username',
            'process_path',
            'timestamp',
            'event_count',
            'cross_memory_count',
            'cross_events_count',
        ],
    )
    provenance_summary = build_record_provenance_summary(processes)

    returned_processes = processes[:limit]
    returned_count = len(returned_processes)
    total_matches = len(processes)
    return attach_payload_provenance({
        'processes': returned_processes,
        'total': total_matches,
        'total_matches': total_matches,
        'returned_count': returned_count,
        'truncated': total_matches > returned_count,
        'source': source_filter or 'all',
        'search': search or '',
        'expanded_search_terms': search_terms,
    }, summary=provenance_summary)


def get_unified_process_tree(
    case_id: int,
    *,
    hostname: str,
    pid: int,
    process_name: str = '',
    include_parent: bool = True,
    max_depth: int = 4,
) -> Dict[str, Any]:
    """Return a process tree view across event and memory sources."""
    _, case_tz = _case_and_timezone(case_id)
    max_depth = min(max(max_depth or 4, 1), 8)
    client = get_fresh_client()
    provenance_fields = [
        'source',
        'hostname',
        'pid',
        'ppid',
        'process_name',
        'parent_process',
        'command_line',
        'username',
        'process_path',
        'timestamp',
    ]

    def _annotate_tree_nodes(nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        flattened: List[Dict[str, Any]] = []

        def _walk(node_list: List[Dict[str, Any]]):
            annotate_artifact_records(
                node_list,
                artifact_type_key='_artifact_type',
                fields=provenance_fields,
            )
            for node in node_list:
                flattened.append(node)
                children = node.get('children')
                if isinstance(children, list) and children:
                    _walk(children)

        _walk(nodes)
        return flattened

    def _from_events(host: str, proc_id: int, proc_name: str = ''):
        params = {'case_id': case_id, 'hostname': host, 'pid': proc_id}
        query = """
            SELECT
                source_host,
                process_id,
                process_name,
                max(COALESCE(timestamp_utc, timestamp)) as latest_ts,
                argMax(parent_pid, COALESCE(timestamp_utc, timestamp)) as ppid_val,
                argMax(parent_process, COALESCE(timestamp_utc, timestamp)) as parent_proc_val,
                argMax(command_line, COALESCE(timestamp_utc, timestamp)) as cmdline_val,
                argMax(username, COALESCE(timestamp_utc, timestamp)) as username_val,
                argMax(process_path, COALESCE(timestamp_utc, timestamp)) as proc_path_val,
                argMax(artifact_type, COALESCE(timestamp_utc, timestamp)) as artifact_type_val,
                argMax(extra_fields, COALESCE(timestamp_utc, timestamp)) as extra_fields_val
            FROM events
            WHERE case_id = {case_id:UInt32}
              AND source_host = {hostname:String}
              AND process_id = {pid:UInt64}
              AND process_name != ''
        """
        if proc_name:
            query += " AND process_name = {process_name:String}"
            params['process_name'] = proc_name
        query += " GROUP BY source_host, process_id, process_name LIMIT 1"

        result = client.query(query, parameters=params)
        if not result.result_rows:
            return None
        row = result.result_rows[0]
        artifact_type_val = row[9] if len(row) >= 11 else ''
        extra_fields_val = row[10] if len(row) >= 11 else {}
        record = {
            'source': 'events',
            '_artifact_type': artifact_type_val or '',
            'hostname': row[0],
            'pid': row[1],
            'process_name': row[2] or '',
            'timestamp': format_for_display(row[3], case_tz) if row[3] else '',
            'ppid': row[4],
            'parent_process': row[5] or '',
            'command_line': row[6] or '',
            'username': row[7] or '',
            'process_path': row[8] or '',
        }
        _merge_extra_field_provenance(record, extra_fields_val)
        return record

    def _children_from_events(host: str, parent_pid: int, parent_name: str, depth: int = 0):
        if depth >= max_depth:
            return []
        result = client.query(
            """
            SELECT
                source_host,
                process_id,
                process_name,
                max(COALESCE(timestamp_utc, timestamp)) as latest_ts,
                argMax(parent_pid, COALESCE(timestamp_utc, timestamp)) as ppid_val,
                argMax(parent_process, COALESCE(timestamp_utc, timestamp)) as parent_proc_val,
                argMax(command_line, COALESCE(timestamp_utc, timestamp)) as cmdline_val,
                argMax(username, COALESCE(timestamp_utc, timestamp)) as username_val,
                argMax(artifact_type, COALESCE(timestamp_utc, timestamp)) as artifact_type_val,
                argMax(extra_fields, COALESCE(timestamp_utc, timestamp)) as extra_fields_val
            FROM events
            WHERE case_id = {case_id:UInt32}
              AND source_host = {hostname:String}
              AND parent_pid = {parent_pid:UInt64}
              AND parent_process = {parent_process:String}
              AND process_name != ''
            GROUP BY source_host, process_id, process_name
            ORDER BY latest_ts ASC
            LIMIT 50
            """,
            parameters={
                'case_id': case_id,
                'hostname': host,
                'parent_pid': parent_pid,
                'parent_process': parent_name or '',
            },
        )
        children = []
        for row in result.result_rows:
            artifact_type_val = row[8] if len(row) >= 10 else ''
            extra_fields_val = row[9] if len(row) >= 10 else {}
            child = {
                'source': 'events',
                '_artifact_type': artifact_type_val or '',
                'hostname': row[0],
                'pid': row[1],
                'process_name': row[2] or '',
                'timestamp': format_for_display(row[3], case_tz) if row[3] else '',
                'ppid': row[4],
                'parent_process': row[5] or '',
                'command_line': row[6] or '',
                'username': row[7] or '',
                'children': _children_from_events(host, row[1], row[2], depth + 1),
            }
            _merge_extra_field_provenance(child, extra_fields_val)
            children.append(child)
        return children

    def _from_memory(host: str, proc_id: int):
        jobs = MemoryJob.query.filter_by(case_id=case_id, status='completed').all()
        job_ids = [job.id for job in jobs]
        if not job_ids:
            return None
        match = MemoryProcess.query.filter(
            MemoryProcess.job_id.in_(job_ids),
            MemoryProcess.hostname == host,
            MemoryProcess.pid == proc_id,
        ).first()
        if not match:
            return None
        return {
            'source': 'memory',
            'hostname': match.hostname,
            'pid': match.pid,
            'process_name': match.name or '',
            'timestamp': format_for_display(match.create_time, case_tz) if match.create_time else '',
            'ppid': match.ppid,
            'parent_process': '',
            'command_line': match.cmdline or '',
            'username': '',
            'process_path': match.path or '',
        }

    def _children_from_memory(host: str, parent_pid: int, depth: int = 0):
        if depth >= max_depth:
            return []
        jobs = MemoryJob.query.filter_by(case_id=case_id, status='completed').all()
        job_ids = [job.id for job in jobs]
        if not job_ids:
            return []
        matches = MemoryProcess.query.filter(
            MemoryProcess.job_id.in_(job_ids),
            MemoryProcess.hostname == host,
            MemoryProcess.ppid == parent_pid,
        ).all()
        children = []
        for match in matches:
            children.append({
                'source': 'memory',
                'hostname': match.hostname,
                'pid': match.pid,
                'process_name': match.name or '',
                'timestamp': format_for_display(match.create_time, case_tz) if match.create_time else '',
                'ppid': match.ppid,
                'parent_process': '',
                'command_line': match.cmdline or '',
                'username': '',
                'children': _children_from_memory(host, match.pid, depth + 1),
            })
        return children

    process = _from_events(hostname, pid, process_name) or _from_memory(hostname, pid)
    if not process:
        return {'error': 'Process not found'}

    all_children = []
    seen = set()
    for child in _children_from_events(hostname, pid, process_name) + _children_from_memory(hostname, pid):
        key = (child['source'], child['pid'], child['process_name'])
        if key not in seen:
            seen.add(key)
            all_children.append(child)
    process['children'] = all_children

    parent_chain = []
    if include_parent and process.get('ppid'):
        current_ppid = process.get('ppid')
        current_parent_name = process.get('parent_process', '')
        for _ in range(max_depth):
            if not current_ppid or current_ppid <= 0:
                break
            parent = _from_events(hostname, current_ppid, current_parent_name) or _from_memory(hostname, current_ppid)
            if not parent:
                break
            parent_chain.append(parent)
            current_ppid = parent.get('ppid')
            current_parent_name = parent.get('parent_process', '')

    annotated_nodes = _annotate_tree_nodes([process])
    if parent_chain:
        annotated_nodes.extend(_annotate_tree_nodes(parent_chain))
    provenance_summary = build_record_provenance_summary(annotated_nodes)

    return attach_payload_provenance({
        'process': process,
        'parent_chain': parent_chain,
        'hostname': hostname,
    }, summary=provenance_summary)


def search_network_logs_for_case(
    case_id: int,
    *,
    search: str = '',
    log_type: str = '',
    pcap_id: Optional[int] = None,
    src_ip: str = '',
    dst_ip: str = '',
    time_start: str = '',
    time_end: str = '',
    limit: int = 25,
    source_availability_status: str = 'available',
    missing_sources: Optional[List[Any]] = None,
    limitations: Optional[List[Any]] = None,
) -> Dict[str, Any]:
    """Search indexed network logs for a case."""
    time_start = str(time_start or '').strip()
    time_end = str(time_end or '').strip()
    if not time_start or not time_end:
        return {
            'success': False,
            'error': 'time_start and time_end are required for search_network_logs',
            'logs': [],
            'total': 0,
            'returned_count': 0,
            'coverage_status': 'insufficient',
            'source_availability_status': 'unknown',
            'coverage_detail': {
                'source_metadata': {
                    'source_table': 'network_logs',
                    'reviewed_time_start': time_start or None,
                    'reviewed_time_end': time_end or None,
                    'source_availability_status': 'unknown',
                    'missing_sources': missing_sources or [],
                    'limitations': limitations or [],
                },
                'eligibility_blocked': True,
                'eligibility_block_reason': 'explicit_time_bounds_required',
            },
        }

    limit = min(max(limit or 25, 1), 100)
    result: Dict[str, Any]
    if search and not log_type and not src_ip and not dst_ip:
        result = network_log.search_all_logs(
            case_id=case_id,
            search=search,
            page=1,
            per_page=limit,
            pcap_id=pcap_id,
            time_start=time_start,
            time_end=time_end,
        )
    else:
        result = network_log.query_logs(
            case_id=case_id,
            log_type=log_type or 'conn',
            page=1,
            per_page=limit,
            search=search,
            pcap_id=pcap_id,
            src_ip=src_ip or None,
            dst_ip=dst_ip or None,
            time_start=time_start,
            time_end=time_end,
            order_by='timestamp',
            order_dir='DESC',
        )

    logs = result.get('logs')
    if isinstance(logs, list) and logs:
        annotate_artifact_records(logs)
    total = int(result.get('total') or 0)
    returned_count = len(logs or [])
    pcap_stats = []
    try:
        pcap_stats = network_log.get_pcap_stats(case_id) or []
    except Exception:
        pcap_stats = []

    available_log_types = sorted({
        str(log_type_key)
        for pcap in pcap_stats
        for log_type_key in (pcap.get('by_type') or {}).keys()
        if log_type_key
    })
    reviewed_log_types = sorted({
        str(item.get('log_type'))
        for item in (logs or [])
        if isinstance(item, dict) and item.get('log_type')
    })
    if log_type:
        reviewed_log_types = [log_type]
    elif not reviewed_log_types and available_log_types:
        reviewed_log_types = available_log_types

    reviewed_pcap_ids = sorted({
        int(value)
        for value in (
            [pcap_id] if pcap_id is not None else [
                item.get('pcap_id')
                for item in (logs or [])
                if isinstance(item, dict) and item.get('pcap_id') is not None
            ] + [
                pcap.get('pcap_id')
                for pcap in pcap_stats
                if pcap.get('pcap_id') is not None
            ]
        )
        if value is not None
    })

    normalized_source_status = str(source_availability_status or 'unknown').strip().lower()
    if normalized_source_status not in {'available', 'partial', 'not_available', 'unknown'}:
        normalized_source_status = 'unknown'
    if not available_log_types and not logs:
        normalized_source_status = 'not_available'

    coverage_status = {
        'available': 'complete',
        'partial': 'partial',
        'not_available': 'not_available',
        'unknown': 'unknown',
    }.get(normalized_source_status, 'unknown')

    source_metadata = {
        'source_table': 'network_logs',
        'reviewed_time_start': time_start,
        'reviewed_time_end': time_end,
        'reviewed_pcap_ids': reviewed_pcap_ids,
        'reviewed_log_types': reviewed_log_types,
        'available_log_types': available_log_types,
        'source_hosts': sorted({
            str(value)
            for value in (
                [
                    item.get('source_host')
                    for item in (logs or [])
                    if isinstance(item, dict) and item.get('source_host')
                ] + [
                    pcap.get('source_host')
                    for pcap in pcap_stats
                    if pcap.get('source_host')
                ]
            )
            if value
        }),
        'source_availability_status': normalized_source_status,
        'missing_sources': list(missing_sources or []),
        'limitations': list(limitations or []),
    }
    result.update({
        'network_logs': logs or [],
        'coverage_status': coverage_status,
        'source_availability_status': normalized_source_status,
        'returned_count': returned_count,
        'truncated': total > returned_count,
        'network_query': {
            'search': search or '',
            'log_type': log_type or '',
            'src_ip': src_ip or '',
            'dst_ip': dst_ip or '',
            'pcap_id': pcap_id,
            'time_start': time_start,
            'time_end': time_end,
            'limit': limit,
        },
        'coverage_detail': {
            'source_metadata': source_metadata,
            'result_metadata': {
                'total': total,
                'returned_count': returned_count,
                'page': result.get('page'),
                'per_page': result.get('per_page'),
                'total_pages': result.get('total_pages'),
                'truncated': total > returned_count,
            },
        },
        'result_summary': (
            f"total={total}; returned={returned_count}; log_type={log_type or result.get('log_type') or 'all'}; "
            f"pcap_id={pcap_id if pcap_id is not None else 'all'}; time_start={time_start}; "
            f"time_end={time_end}; search={search or ''}"
        ),
    })

    provenance_summary = build_record_provenance_summary(logs or [])
    return attach_payload_provenance(result, summary=provenance_summary)
