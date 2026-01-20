"""Network Log utilities for PCAP/Zeek data in ClickHouse

Provides helper functions for querying and inserting Zeek log data
stored in ClickHouse network_logs table.
"""
import json
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from ipaddress import IPv4Address, IPv6Address

from utils.clickhouse import get_client, get_fresh_client
from config import Config

logger = logging.getLogger(__name__)

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
}

# Display columns for UI tables
DISPLAY_COLUMNS = {
    'conn': ['timestamp', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'proto', 'service', 'duration', 'conn_state', 'orig_bytes', 'resp_bytes'],
    'dns': ['timestamp', 'src_ip', 'dst_ip', 'query', 'qtype_name', 'rcode_name', 'answers'],
    'http': ['timestamp', 'src_ip', 'dst_ip', 'method', 'host', 'uri', 'status_code', 'user_agent'],
    'ssl': ['timestamp', 'src_ip', 'dst_ip', 'server_name', 'ssl_version', 'cipher', 'ja3', 'validation_status'],
    'files': ['timestamp', 'src_ip', 'dst_ip', 'filename', 'mime_type', 'file_size', 'md5', 'sha256'],
}


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
    
    if src_ip:
        where_parts.append("toString(src_ip) LIKE {src_ip:String}")
        params['src_ip'] = f'{src_ip}%'
    
    if dst_ip:
        where_parts.append("toString(dst_ip) LIKE {dst_ip:String}")
        params['dst_ip'] = f'{dst_ip}%'
    
    if time_start:
        where_parts.append("timestamp >= {time_start:DateTime64(6)}")
        params['time_start'] = time_start
    
    if time_end:
        where_parts.append("timestamp <= {time_end:DateTime64(6)}")
        params['time_end'] = time_end
    
    where_clause = " AND ".join(where_parts)
    
    # Sanitize order_by
    allowed_order = ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'duration', 'orig_bytes', 'resp_bytes']
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
        ORDER BY {order_by} {order_dir}
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
    }


def search_all_logs(
    case_id: int,
    search: str,
    page: int = 1,
    per_page: int = 50,
    pcap_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Search across all log types
    
    Args:
        case_id: PostgreSQL case ID
        search: Search term
        page: Page number
        per_page: Results per page
        pcap_id: Optional PCAP filter
        
    Returns:
        Dict with results and pagination
    """
    client = get_client()
    
    where_parts = ["case_id = {case_id:UInt32}", "search_blob ILIKE {search:String}"]
    params = {'case_id': case_id, 'search': f'%{search}%'}
    
    if pcap_id:
        where_parts.append("pcap_id = {pcap_id:UInt32}")
        params['pcap_id'] = pcap_id
    
    where_clause = " AND ".join(where_parts)
    
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
        ORDER BY timestamp DESC
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
    }


def delete_pcap_logs(pcap_id: int, case_id: int):
    """Delete all network logs for a specific PCAP file
    
    Args:
        pcap_id: PCAP file ID
        case_id: Case ID for safety
        
    Returns:
        True if delete was issued
    """
    client = get_client()
    client.command(
        f"ALTER TABLE network_logs DELETE WHERE pcap_id = {pcap_id} AND case_id = {case_id}"
    )
    return True


def delete_case_logs(case_id: int):
    """Delete all network logs for a case
    
    Args:
        case_id: Case ID
        
    Returns:
        True if delete was issued
    """
    client = get_client()
    client.command(
        f"ALTER TABLE network_logs DELETE WHERE case_id = {case_id}"
    )
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
