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
from utils.provenance import (
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


def _case_and_timezone(case_id: int):
    case = Case.get_by_id(case_id)
    if not case:
        raise ValueError('Case not found')
    return case, case.timezone or 'UTC'


def search_artifacts(
    case_id: int,
    *,
    search: str,
    artifact_type: str = '',
    host: str = '',
    username: str = '',
    limit: int = 25,
) -> Dict[str, Any]:
    """Search the normalized events table across forensic artifact types."""
    if not search:
        return {"error": "search is required"}

    _, case_tz = _case_and_timezone(case_id)
    client = get_fresh_client()
    limit = min(max(limit or 25, 1), 50)

    artifact_types = [artifact_type.strip() for artifact_type in artifact_type.split(',') if artifact_type.strip()]

    where_parts = [
        "case_id = {case_id:UInt32}",
        "(noise_matched = false OR noise_matched IS NULL)",
        "positionCaseInsensitive(search_blob, {search:String}) > 0",
    ]
    params: Dict[str, Any] = {
        'case_id': int(case_id),
        'search': search,
        'limit': limit,
    }

    if host:
        params['host'] = host
        where_parts.append("lower(source_host) = lower({host:String})")
    if username:
        params['username'] = username
        where_parts.append("lower(username) = lower({username:String})")
    if artifact_types:
        params['artifact_types'] = artifact_types
        where_parts.append("has({artifact_types:Array(String)}, artifact_type)")

    where_sql = ' AND '.join(where_parts)

    count_result = client.query(
        f"SELECT count() FROM events WHERE {where_sql}",
        parameters=params,
    )
    total_matches = count_result.result_rows[0][0] if count_result.result_rows else 0

    type_result = client.query(
        f"""
        SELECT artifact_type, count() as cnt
        FROM events
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
            COALESCE(timestamp_utc, timestamp) as ts,
            artifact_type,
            source_host,
            username,
            event_id,
            process_name,
            target_path,
            command_line,
            rule_title,
            source_file,
            ioc_types,
            substring(search_blob, 1, 220) as summary
        FROM events
        WHERE {where_sql}
        ORDER BY ts DESC
        LIMIT {{limit:UInt32}}
        """,
        parameters=params,
    )

    artifacts = []
    for row in row_result.result_rows:
        ts, art_type, source_host, user, event_id, process_name, target_path, command_line, rule_title, source_file, ioc_types, summary = row
        artifacts.append({
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
        })

    annotate_artifact_records(
        artifacts,
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

    return attach_payload_provenance({
        'search': search,
        'artifact_filter': artifact_types,
        'total_matches': total_matches,
        'artifact_types': artifact_breakdown,
        'artifacts': artifacts,
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
    limit = min(max(limit or 50, 1), 200)

    result = client.query(
        """
        SELECT
            COALESCE(timestamp_utc, timestamp) as ts,
            source_host,
            target_path,
            username,
            raw_json,
            extra_fields,
            ioc_types,
            source_file,
            case_file_id
        FROM events
        WHERE case_id = {case_id:UInt32}
          AND artifact_type = 'browser_download'
        ORDER BY timestamp DESC
        LIMIT {limit:UInt32}
        """,
        parameters={'case_id': int(case_id), 'limit': limit * 5},
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
    search_lower = search.lower().strip()
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
        if search_lower:
            haystack = ' '.join([
                source_host or '',
                display_username or '',
                entry_filename or '',
                file_path or '',
                source_url or '',
            ]).lower()
            if search_lower not in haystack:
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

    return attach_payload_provenance({
        'downloads': downloads,
        'total': len(downloads),
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

    return attach_payload_provenance({
        'search': search,
        'search_type': search_type,
        'results': results,
        'jobs_matched': len(results),
        'total_jobs': len(job_ids),
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
        if search:
            params['search'] = f'%{search}%'
            where_parts.append("(process_name ILIKE {search:String} OR command_line ILIKE {search:String} OR parent_process ILIKE {search:String})")

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
            hostname_val, pid, proc_name, latest_ts, ppid, parent_proc, cmdline, username_val, proc_path, event_count = row
            processes.append({
                'source': 'events',
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
            })

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
            if search:
                query = query.filter(db.or_(
                    MemoryProcess.name.ilike(f'%{search}%'),
                    MemoryProcess.cmdline.ilike(f'%{search}%'),
                    MemoryProcess.path.ilike(f'%{search}%'),
                ))
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

    return attach_payload_provenance({
        'processes': processes[:limit],
        'total': len(processes),
        'source': source_filter or 'all',
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
            annotate_artifact_records(node_list, fields=provenance_fields)
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
                argMax(process_path, COALESCE(timestamp_utc, timestamp)) as proc_path_val
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
        return {
            'source': 'events',
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
                argMax(username, COALESCE(timestamp_utc, timestamp)) as username_val
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
            child = {
                'source': 'events',
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
    limit: int = 25,
) -> Dict[str, Any]:
    """Search indexed network logs for a case."""
    limit = min(max(limit or 25, 1), 100)
    if search and not log_type and not src_ip and not dst_ip:
        return network_log.search_all_logs(
            case_id=case_id,
            search=search,
            page=1,
            per_page=limit,
            pcap_id=pcap_id,
        )

    return network_log.query_logs(
        case_id=case_id,
        log_type=log_type or 'conn',
        page=1,
        per_page=limit,
        search=search,
        pcap_id=pcap_id,
        src_ip=src_ip or None,
        dst_ip=dst_ip or None,
        order_by='timestamp',
        order_dir='DESC',
    )
