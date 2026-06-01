"""Network Log utilities for PCAP/Zeek data in ClickHouse

Provides helper functions for querying and inserting Zeek log data
stored in ClickHouse network_logs table.
"""
import json
import logging
import time
import uuid
from contextlib import contextmanager
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from ipaddress import IPv4Address, IPv6Address, ip_address

from utils.clickhouse import get_client, get_fresh_client, wait_for_mutation_completion
from config import Config

logger = logging.getLogger(__name__)

IP_DISPLAY_COLUMNS = {'src_ip', 'dst_ip'}

# Zeek log types we support
SUPPORTED_LOG_TYPES = [
    'conn',      # Connection logs
    'dns',       # DNS queries
    'http',      # HTTP requests
    'ssl',       # SSL/TLS handshakes
    'files',     # File transfers
    'x509',      # X.509 certificates
    'smtp',      # SMTP email
    'ftp',       # FTP transfers
    'ssh',       # SSH connections
    'dhcp',      # DHCP leases
    'ntp',       # NTP traffic
    'rdp',       # RDP connections
    'smb',       # SMB file shares
    'dce_rpc',   # DCE/RPC calls
    'kerberos',  # Kerberos auth
    'ntlm',      # NTLM auth
]

# Column mapping for each log type
LOG_TYPE_COLUMNS = {
    'conn': [
        'timestamp', 'uid', 'src_ip', 'src_port', 'dst_ip', 'dst_port',
        'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes',
        'conn_state', 'missed_bytes', 'orig_pkts', 'resp_pkts'
    ],
    'dns': [
        'timestamp', 'uid', 'src_ip', 'src_port', 'dst_ip', 'dst_port',
        'proto', 'query', 'qtype', 'qtype_name', 'rcode', 'rcode_name',
        'answers', 'ttls', 'rejected'
    ],
    'http': [
        'timestamp', 'uid', 'src_ip', 'src_port', 'dst_ip', 'dst_port',
        'method', 'host', 'uri', 'referrer', 'user_agent',
        'request_body_len', 'response_body_len', 'status_code', 'status_msg',
        'resp_mime_type'
    ],
    'ssl': [
        'timestamp', 'uid', 'src_ip', 'src_port', 'dst_ip', 'dst_port',
        'ssl_version', 'cipher', 'server_name', 'subject', 'issuer',
        'validation_status', 'ja3', 'ja3s'
    ],
    'files': [
        'timestamp', 'uid', 'src_ip', 'dst_ip', 'fuid', 'file_source',
        'analyzers', 'mime_type', 'filename', 'file_size', 'md5', 'sha1',
        'sha256', 'extracted'
    ],
    'ntp': [
        'timestamp', 'uid', 'src_ip', 'src_port', 'dst_ip', 'dst_port',
        'proto'
    ],
}

# Display columns for UI tables
DISPLAY_COLUMNS = {
    'conn': ['timestamp', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'proto', 'service', 'duration', 'conn_state', 'orig_bytes', 'resp_bytes'],
    'dns': ['timestamp', 'src_ip', 'dst_ip', 'query', 'qtype_name', 'rcode_name', 'answers'],
    'http': ['timestamp', 'src_ip', 'dst_ip', 'method', 'host', 'uri', 'status_code', 'user_agent'],
    'ssl': ['timestamp', 'src_ip', 'dst_ip', 'server_name', 'ssl_version', 'cipher', 'ja3', 'validation_status'],
    'files': ['timestamp', 'src_ip', 'dst_ip', 'filename', 'mime_type', 'file_size', 'md5', 'sha256'],
    'ntp': ['timestamp', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'proto'],
}
_NETWORK_LOG_REWRITE_LOCK_KEY = 'clickhouse:network_logs_destructive_rewrite'
_NETWORK_LOG_REWRITE_LOCK_TTL_SECONDS = max(
    int(getattr(Config, 'CLICKHOUSE_NETWORK_LOG_REWRITE_LOCK_TTL_SECONDS', 21600) or 0),
    300,
)


class NetworkLogMutationGuardActive(RuntimeError):
    """Raised when another destructive network-log rewrite is already active."""

    def __init__(self, holder):
        self.holder = holder or {}
        operation = self.holder.get('operation') or 'another destructive network-log rewrite'
        case_id = self.holder.get('case_id')
        pcap_id = self.holder.get('pcap_id')
        started_at = self.holder.get('started_at')
        details = [operation]
        if case_id is not None:
            details.append(f'case_id={case_id}')
        if pcap_id is not None:
            details.append(f'pcap_id={pcap_id}')
        if started_at:
            details.append(f'started_at={started_at}')
        super().__init__(
            'Another ClickHouse destructive network-log rewrite is already active '
            f"({' '.join(details)}); wait for it to finish before starting a new one"
        )


def _get_network_log_rewrite_redis_client():
    try:
        from utils.progress import get_redis_client

        return get_redis_client()
    except Exception:
        return None


def _decode_network_log_rewrite_payload(raw_payload):
    if not raw_payload:
        return None
    if isinstance(raw_payload, bytes):
        raw_payload = raw_payload.decode('utf-8', errors='replace')
    try:
        payload = json.loads(raw_payload)
    except Exception:
        return {'raw': str(raw_payload)}
    if isinstance(payload, dict):
        return payload
    return {'raw': payload}


def get_active_destructive_network_log_rewrite():
    """Return metadata for the active destructive network-log rewrite, if any."""
    client = _get_network_log_rewrite_redis_client()
    if client is None:
        return None
    try:
        return _decode_network_log_rewrite_payload(client.get(_NETWORK_LOG_REWRITE_LOCK_KEY))
    except Exception:
        return None


@contextmanager
def destructive_network_log_rewrite_guard(operation, *, case_id=None, pcap_id=None, ttl_seconds=None):
    """Serialize explicit destructive rewrites against `network_logs`."""
    client = _get_network_log_rewrite_redis_client()
    if client is None:
        yield None
        return

    ttl = max(int(ttl_seconds or _NETWORK_LOG_REWRITE_LOCK_TTL_SECONDS), 300)
    payload = {
        'token': str(uuid.uuid4()),
        'operation': str(operation),
        'case_id': int(case_id) if case_id is not None else None,
        'pcap_id': int(pcap_id) if pcap_id is not None else None,
        'started_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    }
    serialized = json.dumps(payload)

    try:
        acquired = client.set(_NETWORK_LOG_REWRITE_LOCK_KEY, serialized, nx=True, ex=ttl)
    except Exception:
        acquired = True

    if not acquired:
        raise NetworkLogMutationGuardActive(get_active_destructive_network_log_rewrite())

    try:
        yield payload
    finally:
        try:
            release_script = """
            local key = KEYS[1]
            local expected = ARGV[1]
            local current = redis.call('GET', key)
            if current == expected then
                return redis.call('DEL', key)
            end
            return 0
            """
            client.eval(release_script, 1, _NETWORK_LOG_REWRITE_LOCK_KEY, serialized)
        except Exception:
            pass


def _sql_quote_string(value: str) -> str:
    escaped = str(value).replace("\\", "\\\\").replace("'", "\\'")
    return f"'{escaped}'"


def normalize_ip_for_display(value):
    """Render IPv4-mapped IPv6 values as dotted IPv4 for analyst-facing APIs."""
    if value is None:
        return None

    if isinstance(value, IPv4Address):
        return str(value)

    if isinstance(value, IPv6Address):
        mapped = value.ipv4_mapped
        return str(mapped) if mapped else str(value)

    text = str(value)
    try:
        addr = ip_address(text)
    except ValueError:
        return text

    if isinstance(addr, IPv6Address) and addr.ipv4_mapped:
        return str(addr.ipv4_mapped)
    return str(addr)


def _append_ip_filter(where_parts, params, column, value, zeek_field):
    """Filter stored IPv6 values while preserving dotted IPv4 prefix matching."""
    if not value:
        return

    param_name = column
    where = f"toString({column}) LIKE {{{param_name}:String}}"
    params[param_name] = f'{value}%'

    if '.' in value:
        search_param = f'{column}_search'
        where = f"({where} OR search_blob ILIKE {{{search_param}:String}})"
        params[search_param] = f'%{zeek_field}:{value}%'

    where_parts.append(where)


def _list_case_log_types(client, case_id: int) -> List[str]:
    result = client.query(
        """
        SELECT DISTINCT log_type
        FROM network_logs
        WHERE case_id = {case_id:UInt32}
        """,
        parameters={'case_id': int(case_id)},
    )
    return [str(row[0]) for row in result.result_rows if row and row[0]]


def _wait_for_case_log_absence(
    client,
    case_id: int,
    *,
    timeout_seconds: int = 300,
    poll_interval_seconds: float = 1.0,
):
    deadline = time.monotonic() + max(timeout_seconds, 1)
    while True:
        result = client.query(
            "SELECT count() FROM network_logs WHERE case_id = {case_id:UInt32}",
            parameters={'case_id': int(case_id)},
        )
        remaining = result.result_rows[0][0] if result.result_rows else 0
        if remaining == 0:
            return True
        if time.monotonic() >= deadline:
            raise TimeoutError(
                f"Timed out waiting for ClickHouse network_logs removal for case_id={case_id}"
            )
        time.sleep(max(poll_interval_seconds, 0.1))


def get_network_stats(case_id: int) -> Dict[str, Any]:
    """Get network log statistics for a case
    
    Args:
        case_id: PostgreSQL case ID
        
    Returns:
        Dict with counts per log type and totals
    """
    client = get_client()
    
    # Count by log type
    result = client.query("""
        SELECT log_type, count() as cnt
        FROM network_logs
        WHERE case_id = {case_id:UInt32}
        GROUP BY log_type
        ORDER BY cnt DESC
    """, parameters={'case_id': case_id})
    
    by_type = {row[0]: row[1] for row in result.result_rows}
    total = sum(by_type.values())
    
    # Time range
    time_result = client.query("""
        SELECT min(timestamp), max(timestamp)
        FROM network_logs
        WHERE case_id = {case_id:UInt32}
    """, parameters={'case_id': case_id})
    
    earliest = None
    latest = None
    if time_result.result_rows and time_result.result_rows[0][0]:
        earliest = time_result.result_rows[0][0]
        latest = time_result.result_rows[0][1]
    
    # Unique IPs
    ip_result = client.query("""
        SELECT 
            uniq(src_ip) as unique_src,
            uniq(dst_ip) as unique_dst
        FROM network_logs
        WHERE case_id = {case_id:UInt32}
    """, parameters={'case_id': case_id})
    
    unique_src = ip_result.result_rows[0][0] if ip_result.result_rows else 0
    unique_dst = ip_result.result_rows[0][1] if ip_result.result_rows else 0
    
    return {
        'total': total,
        'by_type': by_type,
        'earliest': earliest.isoformat() if earliest else None,
        'latest': latest.isoformat() if latest else None,
        'unique_src_ips': unique_src,
        'unique_dst_ips': unique_dst,
    }


def get_pcap_stats(case_id: int) -> List[Dict[str, Any]]:
    """Get log counts per PCAP file
    
    Args:
        case_id: PostgreSQL case ID
        
    Returns:
        List of dicts with pcap_id and counts
    """
    client = get_client()
    
    result = client.query("""
        SELECT pcap_id, source_host, log_type, count() as cnt
        FROM network_logs
        WHERE case_id = {case_id:UInt32}
        GROUP BY pcap_id, source_host, log_type
        ORDER BY pcap_id, log_type
    """, parameters={'case_id': case_id})
    
    # Group by pcap_id
    pcap_stats = {}
    for row in result.result_rows:
        pcap_id = row[0]
        if pcap_id not in pcap_stats:
            pcap_stats[pcap_id] = {
                'pcap_id': pcap_id,
                'source_host': row[1],
                'by_type': {},
                'total': 0
            }
        pcap_stats[pcap_id]['by_type'][row[2]] = row[3]
        pcap_stats[pcap_id]['total'] += row[3]
    
    return list(pcap_stats.values())


def query_logs(
    case_id: int,
    log_type: str,
    page: int = 1,
    per_page: int = 50,
    search: str = '',
    pcap_id: Optional[int] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    time_start: Optional[str] = None,
    time_end: Optional[str] = None,
    order_by: str = 'timestamp',
    order_dir: str = 'DESC'
) -> Dict[str, Any]:
    """Query network logs with pagination and filters
    
    Args:
        case_id: PostgreSQL case ID
        log_type: Log type (conn, dns, http, ssl, files)
        page: Page number (1-indexed)
        per_page: Results per page
        search: Search term for search_blob
        pcap_id: Filter by specific PCAP file
        src_ip: Filter by source IP
        dst_ip: Filter by destination IP
        time_start: Start time filter (ISO format)
        time_end: End time filter (ISO format)
        order_by: Column to order by
        order_dir: ASC or DESC
        
    Returns:
        Dict with logs, pagination info, and total count
    """
    client = get_client()
    
    # Build WHERE clause
    where_parts = ["case_id = {case_id:UInt32}", "log_type = {log_type:String}"]
    params = {'case_id': case_id, 'log_type': log_type}
    
    if pcap_id:
        where_parts.append("pcap_id = {pcap_id:UInt32}")
        params['pcap_id'] = pcap_id
    
    if search:
        where_parts.append("search_blob ILIKE {search:String}")
        params['search'] = f'%{search}%'
    
    _append_ip_filter(where_parts, params, 'src_ip', src_ip, 'id.orig_h')
    _append_ip_filter(where_parts, params, 'dst_ip', dst_ip, 'id.resp_h')
    
    if time_start:
        where_parts.append("timestamp >= {time_start:DateTime64(6)}")
        params['time_start'] = time_start
    
    if time_end:
        where_parts.append("timestamp <= {time_end:DateTime64(6)}")
        params['time_end'] = time_end
    
    where_clause = " AND ".join(where_parts)
    
    # Sanitize order_by against displayable network log columns before using it in SQL.
    allowed_order = {
        'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
        'duration', 'orig_bytes', 'resp_bytes', 'pcap_id', 'source_host',
    }
    for display_cols in DISPLAY_COLUMNS.values():
        allowed_order.update(display_cols)
    if order_by not in allowed_order:
        order_by = 'timestamp'
    order_dir = 'DESC' if order_dir.upper() == 'DESC' else 'ASC'
    
    # Get total count
    count_query = f"SELECT count() FROM network_logs WHERE {where_clause}"
    count_result = client.query(count_query, parameters=params)
    total = count_result.result_rows[0][0] if count_result.result_rows else 0
    
    # Calculate pagination
    offset = (page - 1) * per_page
    total_pages = (total + per_page - 1) // per_page if total > 0 else 1
    
    # Get display columns for this log type
    columns = DISPLAY_COLUMNS.get(log_type, ['timestamp', 'src_ip', 'dst_ip', 'uid', 'raw_json'])
    
    # Query data
    select_cols = ', '.join(columns) + ', raw_json, uid, pcap_id, source_host'
    data_query = f"""
        SELECT {select_cols}
        FROM network_logs
        WHERE {where_clause}
        ORDER BY {order_by} {order_dir}, timestamp DESC, uid ASC
        LIMIT {per_page} OFFSET {offset}
    """
    
    result = client.query(data_query, parameters=params)
    
    # Format results
    logs = []
    all_columns = columns + ['raw_json', 'uid', 'pcap_id', 'source_host']
    
    for row in result.result_rows:
        log_entry = {}
        for i, col in enumerate(all_columns):
            value = row[i]
            # Convert special types
            if value is None:
                log_entry[col] = None
            elif hasattr(value, 'isoformat'):
                log_entry[col] = value.isoformat()
            elif col in IP_DISPLAY_COLUMNS:
                log_entry[col] = normalize_ip_for_display(value)
            elif isinstance(value, (IPv4Address, IPv6Address)):
                log_entry[col] = str(value)
            elif hasattr(value, 'packed'):
                log_entry[col] = str(value)
            elif isinstance(value, (list, tuple)):
                log_entry[col] = [str(v) if hasattr(v, 'packed') else v for v in value]
            else:
                log_entry[col] = value
        logs.append(log_entry)
    
    return {
        'success': True,
        'logs': logs,
        'columns': columns,
        'page': page,
        'per_page': per_page,
        'total': total,
        'total_pages': total_pages,
        'log_type': log_type,
        'order_by': order_by,
        'order_dir': order_dir,
    }


def search_all_logs(
    case_id: int,
    search: str,
    page: int = 1,
    per_page: int = 50,
    pcap_id: Optional[int] = None,
    time_start: Optional[str] = None,
    time_end: Optional[str] = None,
    order_by: str = 'timestamp',
    order_dir: str = 'DESC',
) -> Dict[str, Any]:
    """Search across all log types
    
    Args:
        case_id: PostgreSQL case ID
        search: Search term
        page: Page number
        per_page: Results per page
        pcap_id: Optional PCAP filter
        time_start: Start time filter (ISO format)
        time_end: End time filter (ISO format)
        
    Returns:
        Dict with results and pagination
    """
    client = get_client()
    
    where_parts = ["case_id = {case_id:UInt32}", "search_blob ILIKE {search:String}"]
    params = {'case_id': case_id, 'search': f'%{search}%'}
    
    if pcap_id:
        where_parts.append("pcap_id = {pcap_id:UInt32}")
        params['pcap_id'] = pcap_id

    if time_start:
        where_parts.append("timestamp >= {time_start:DateTime64(6)}")
        params['time_start'] = time_start

    if time_end:
        where_parts.append("timestamp <= {time_end:DateTime64(6)}")
        params['time_end'] = time_end
    
    where_clause = " AND ".join(where_parts)
    allowed_order = {'log_type', 'timestamp', 'uid', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'source_host'}
    if order_by not in allowed_order:
        order_by = 'timestamp'
    order_dir = 'DESC' if order_dir.upper() == 'DESC' else 'ASC'
    
    # Get total count
    count_query = f"SELECT count() FROM network_logs WHERE {where_clause}"
    count_result = client.query(count_query, parameters=params)
    total = count_result.result_rows[0][0] if count_result.result_rows else 0
    
    offset = (page - 1) * per_page
    total_pages = (total + per_page - 1) // per_page if total > 0 else 1
    
    # Query with common columns
    data_query = f"""
        SELECT log_type, timestamp, uid, src_ip, src_port, dst_ip, dst_port,
               source_host, pcap_id, raw_json
        FROM network_logs
        WHERE {where_clause}
        ORDER BY {order_by} {order_dir}, timestamp DESC, uid ASC
        LIMIT {per_page} OFFSET {offset}
    """
    
    result = client.query(data_query, parameters=params)
    
    logs = []
    columns = ['log_type', 'timestamp', 'uid', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'source_host', 'pcap_id', 'raw_json']
    
    for row in result.result_rows:
        log_entry = {}
        for i, col in enumerate(columns):
            value = row[i]
            if value is None:
                log_entry[col] = None
            elif hasattr(value, 'isoformat'):
                log_entry[col] = value.isoformat()
            elif col in IP_DISPLAY_COLUMNS:
                log_entry[col] = normalize_ip_for_display(value)
            elif hasattr(value, 'packed') or isinstance(value, (IPv4Address, IPv6Address)):
                log_entry[col] = str(value)
            else:
                log_entry[col] = value
        logs.append(log_entry)
    
    return {
        'success': True,
        'logs': logs,
        'columns': columns,
        'page': page,
        'per_page': per_page,
        'total': total,
        'total_pages': total_pages,
        'search': search,
        'order_by': order_by,
        'order_dir': order_dir,
    }


def delete_pcap_logs(pcap_id: int, case_id: int, *, wait: bool = False):
    """Delete all network logs for a specific PCAP file
    
    Args:
        pcap_id: PCAP file ID
        case_id: Case ID for safety
        
    Returns:
        True if delete was issued
    """
    client = get_client()
    command_fragment = f"DELETE WHERE pcap_id = {pcap_id} AND case_id = {case_id}"
    with destructive_network_log_rewrite_guard(
        'pcap_network_log_delete',
        case_id=case_id,
        pcap_id=pcap_id,
    ):
        client.command(f"ALTER TABLE network_logs {command_fragment}")
        if wait:
            wait_for_mutation_completion('network_logs', command_fragment, client=client)
        return True


def delete_case_logs(case_id: int, *, wait: bool = False):
    """Delete all network logs for a case
    
    Args:
        case_id: Case ID
        
    Returns:
        True if delete was issued
    """
    client = get_client()
    command_fragment = f"DELETE WHERE case_id = {case_id}"
    with destructive_network_log_rewrite_guard(
        'case_network_log_delete',
        case_id=case_id,
    ):
        log_types = _list_case_log_types(client, case_id)
        if not log_types:
            return True

        try:
            for log_type in log_types:
                partition_expr = f"tuple({int(case_id)}, {_sql_quote_string(log_type)})"
                client.command(f"ALTER TABLE network_logs DROP PARTITION {partition_expr}")
            if wait:
                _wait_for_case_log_absence(client, case_id)
            return True
        except Exception as exc:
            logger.warning(
                "Falling back to network_logs mutation delete for case %s after partition-drop failure: %s",
                case_id,
                exc,
            )
            client.command(f"ALTER TABLE network_logs {command_fragment}")
            if wait:
                wait_for_mutation_completion('network_logs', command_fragment, client=client)
            return True


def insert_logs(logs: List[Tuple], column_names: List[str]) -> int:
    """Bulk insert network logs into ClickHouse
    
    Args:
        logs: List of tuples containing log data
        column_names: List of column names matching the data order
        
    Returns:
        Number of rows inserted
    """
    if not logs:
        return 0
    
    client = get_fresh_client()
    
    # Use buffer table for faster ingestion
    table = 'network_logs_buffer' if Config.CLICKHOUSE_USE_BUFFER else 'network_logs'
    
    client.insert(table, logs, column_names=column_names)
    return len(logs)
