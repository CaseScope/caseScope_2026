"""PCAP Processing Tasks - Zeek analysis for network captures

Thread-safe with cached Flask app instance for connection pool efficiency.
"""
import os
import json
import subprocess
import shutil
import logging
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from ipaddress import ip_address
from celery import shared_task

from models.database import db
from models.pcap_file import PcapFile, PcapFileStatus
from config import Config

logger = logging.getLogger(__name__)

# Cached Flask app instance to avoid creating new connection pools for each task
_flask_app = None
_flask_app_lock = threading.Lock()

def get_flask_app():
    """Get or create a shared Flask app instance for Celery tasks (thread-safe)"""
    global _flask_app
    if _flask_app is None:
        with _flask_app_lock:
            if _flask_app is None:
                from app import create_app
                _flask_app = create_app()
    return _flask_app

# Zeek binary path
ZEEK_BIN = '/opt/zeek/bin/zeek'
ZEEK_CUT_BIN = '/opt/zeek/bin/zeek-cut'

# Zeek log types we index
INDEXED_LOG_TYPES = ['conn', 'dns', 'http', 'ssl', 'files', 'x509', 'smtp', 'ssh', 'dhcp', 'ftp', 'rdp', 'smb', 'dce_rpc', 'kerberos', 'ntlm']

# Field mappings from Zeek column names to our ClickHouse columns
ZEEK_FIELD_MAP = {
    # Connection fields
    'ts': 'timestamp',
    'uid': 'uid',
    'id.orig_h': 'src_ip',
    'id.orig_p': 'src_port',
    'id.resp_h': 'dst_ip',
    'id.resp_p': 'dst_port',
    'proto': 'proto',
    'service': 'service',
    'duration': 'duration',
    'orig_bytes': 'orig_bytes',
    'resp_bytes': 'resp_bytes',
    'conn_state': 'conn_state',
    'missed_bytes': 'missed_bytes',
    'orig_pkts': 'orig_pkts',
    'resp_pkts': 'resp_pkts',
    # DNS fields
    'query': 'query',
    'qtype': 'qtype',
    'qtype_name': 'qtype_name',
    'rcode': 'rcode',
    'rcode_name': 'rcode_name',
    'answers': 'answers',
    'TTLs': 'ttls',
    'rejected': 'rejected',
    # HTTP fields
    'method': 'method',
    'host': 'host',
    'uri': 'uri',
    'referrer': 'referrer',
    'user_agent': 'user_agent',
    'request_body_len': 'request_body_len',
    'response_body_len': 'response_body_len',
    'status_code': 'status_code',
    'status_msg': 'status_msg',
    'resp_mime_types': 'resp_mime_type',
    # SSL fields
    'version': 'ssl_version',
    'cipher': 'cipher',
    'server_name': 'server_name',
    'subject': 'subject',
    'issuer': 'issuer',
    'validation_status': 'validation_status',
    'ja3': 'ja3',
    'ja3s': 'ja3s',
    # Files fields
    'fuid': 'fuid',
    'source': 'file_source',
    'analyzers': 'analyzers',
    'mime_type': 'mime_type',
    'filename': 'filename',
    'seen_bytes': 'file_size',
    'total_bytes': 'file_size',
    'md5': 'md5',
    'sha1': 'sha1',
    'sha256': 'sha256',
    'extracted': 'extracted',
}


def get_zeek_output_dir(case_uuid: str, pcap_id: int) -> str:
    """Get the Zeek output directory for a PCAP file
    
    Output path: /opt/casescope/storage/{case_uuid}/pcap/zeek_{pcap_id}/
    """
    base_path = os.path.join(Config.STORAGE_FOLDER, case_uuid, 'pcap', f'zeek_{pcap_id}')
    os.makedirs(base_path, exist_ok=True)
    
    try:
        shutil.chown(base_path, user='casescope', group='casescope')
    except (PermissionError, LookupError):
        pass
    
    return base_path


@shared_task(bind=True, name='tasks.process_pcap_with_zeek')
def process_pcap_with_zeek(self, pcap_id: int):
    """Process a PCAP file with Zeek to generate network logs
    
    Zeek generates various log files:
    - conn.log: Connection records
    - dns.log: DNS queries/responses
    - http.log: HTTP requests
    - ssl.log: SSL/TLS handshakes
    - files.log: File transfers
    - and more...
    
    Args:
        pcap_id: ID of the PcapFile record
        
    Returns:
        dict with processing results
    """
    app = get_flask_app()
    
    with app.app_context():
        pcap_file = db.session.get(PcapFile, pcap_id)
        if not pcap_file:
            logger.error(f"PCAP file {pcap_id} not found")
            return {'success': False, 'error': 'PCAP file not found'}
        
        if not pcap_file.file_path or not os.path.exists(pcap_file.file_path):
            pcap_file.status = PcapFileStatus.ERROR
            pcap_file.error_message = 'PCAP file not found on disk'
            db.session.commit()
            return {'success': False, 'error': 'PCAP file not found on disk'}
        
        # Update status to processing
        pcap_file.status = PcapFileStatus.PROCESSING
        db.session.commit()
        
        try:
            # Create output directory
            output_dir = get_zeek_output_dir(pcap_file.case_uuid, pcap_id)
            
            # Clear any existing output
            for item in os.listdir(output_dir):
                item_path = os.path.join(output_dir, item)
                if os.path.isfile(item_path):
                    os.remove(item_path)
            
            # Run Zeek on the PCAP file
            # Using -r to read from file, -C to ignore checksums
            cmd = [
                ZEEK_BIN,
                '-r', pcap_file.file_path,
                '-C',  # Ignore checksum errors (common in captures)
                'local'  # Load local policy scripts
            ]
            
            logger.info(f"Running Zeek on {pcap_file.filename}: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                cwd=output_dir,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout for large files
            )
            
            if result.returncode != 0:
                error_msg = result.stderr[:500] if result.stderr else 'Unknown Zeek error'
                logger.error(f"Zeek failed for {pcap_file.filename}: {error_msg}")
                pcap_file.status = PcapFileStatus.ERROR
                pcap_file.error_message = f"Zeek error: {error_msg}"
                db.session.commit()
                return {'success': False, 'error': error_msg}
            
            # Count generated log files
            log_files = []
            for item in os.listdir(output_dir):
                if item.endswith('.log'):
                    log_path = os.path.join(output_dir, item)
                    log_size = os.path.getsize(log_path)
                    log_files.append({
                        'name': item,
                        'path': log_path,
                        'size': log_size
                    })
            
            # Update PCAP record with results
            pcap_file.status = PcapFileStatus.DONE
            pcap_file.zeek_output_path = output_dir
            pcap_file.logs_generated = len(log_files)
            pcap_file.processed_at = datetime.utcnow()
            pcap_file.error_message = None
            db.session.commit()
            
            logger.info(f"Zeek completed for {pcap_file.filename}: {len(log_files)} logs generated")
            
            return {
                'success': True,
                'pcap_id': pcap_id,
                'filename': pcap_file.filename,
                'output_dir': output_dir,
                'logs_generated': len(log_files),
                'log_files': log_files
            }
            
        except subprocess.TimeoutExpired:
            pcap_file.status = PcapFileStatus.ERROR
            pcap_file.error_message = 'Zeek processing timed out (>1 hour)'
            db.session.commit()
            return {'success': False, 'error': 'Processing timeout'}
            
        except Exception as e:
            logger.exception(f"Error processing PCAP {pcap_id}")
            pcap_file.status = PcapFileStatus.ERROR
            pcap_file.error_message = str(e)[:500]
            db.session.commit()
            return {'success': False, 'error': str(e)}


@shared_task(bind=True, name='tasks.process_case_pcaps')
def process_case_pcaps(self, case_uuid: str):
    """Process all pending PCAP files for a case
    
    Args:
        case_uuid: Case UUID
        
    Returns:
        dict with queued task info
    """
    app = get_flask_app()
    
    with app.app_context():
        # Get all pending PCAP files
        pending = PcapFile.query.filter(
            PcapFile.case_uuid == case_uuid,
            PcapFile.is_archive == False,
            PcapFile.status == PcapFileStatus.NEW
        ).all()
        
        queued = []
        for pcap in pending:
            pcap.status = PcapFileStatus.QUEUED
            db.session.commit()
            
            # Queue individual processing task
            task = process_pcap_with_zeek.delay(pcap.id)
            queued.append({
                'pcap_id': pcap.id,
                'filename': pcap.filename,
                'task_id': task.id
            })
        
        return {
            'success': True,
            'case_uuid': case_uuid,
            'queued_count': len(queued),
            'queued': queued
        }


def get_zeek_log_content(pcap_id: int, log_name: str, limit: int = 1000) -> dict:
    """Get content of a Zeek log file
    
    Args:
        pcap_id: PCAP file ID
        log_name: Log file name (e.g., 'conn.log', 'dns.log')
        limit: Maximum number of lines to return
        
    Returns:
        dict with log content and metadata
    """
    pcap_file = db.session.get(PcapFile, pcap_id)
    if not pcap_file or not pcap_file.zeek_output_path:
        return {'success': False, 'error': 'PCAP or Zeek output not found'}
    
    log_path = os.path.join(pcap_file.zeek_output_path, log_name)
    if not os.path.exists(log_path):
        return {'success': False, 'error': f'Log file {log_name} not found'}
    
    try:
        lines = []
        headers = []
        
        with open(log_path, 'r') as f:
            for i, line in enumerate(f):
                if i >= limit + 10:  # Account for header lines
                    break
                
                line = line.strip()
                if line.startswith('#'):
                    # Parse header lines
                    if line.startswith('#fields'):
                        headers = line.replace('#fields\t', '').split('\t')
                    continue
                
                if len(lines) < limit:
                    lines.append(line.split('\t'))
        
        return {
            'success': True,
            'log_name': log_name,
            'headers': headers,
            'lines': lines,
            'total_lines': len(lines),
            'truncated': len(lines) >= limit
        }
        
    except Exception as e:
        return {'success': False, 'error': str(e)}


def get_zeek_log_with_cut(pcap_id: int, log_name: str, columns: list = None, limit: int = 1000) -> dict:
    """Get Zeek log content using zeek-cut for specific columns
    
    Args:
        pcap_id: PCAP file ID
        log_name: Log file name
        columns: List of column names to extract (None = all)
        limit: Maximum lines
        
    Returns:
        dict with log content
    """
    pcap_file = db.session.get(PcapFile, pcap_id)
    if not pcap_file or not pcap_file.zeek_output_path:
        return {'success': False, 'error': 'PCAP or Zeek output not found'}
    
    log_path = os.path.join(pcap_file.zeek_output_path, log_name)
    if not os.path.exists(log_path):
        return {'success': False, 'error': f'Log file {log_name} not found'}
    
    try:
        cmd = ['cat', log_path, '|', ZEEK_CUT_BIN]
        if columns:
            cmd.extend(columns)
        
        # Use shell to handle pipe
        shell_cmd = f"cat '{log_path}' | {ZEEK_CUT_BIN}"
        if columns:
            shell_cmd += ' ' + ' '.join(columns)
        shell_cmd += f" | head -n {limit}"
        
        result = subprocess.run(
            shell_cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        lines = []
        for line in result.stdout.strip().split('\n'):
            if line:
                lines.append(line.split('\t'))
        
        return {
            'success': True,
            'log_name': log_name,
            'columns': columns or ['all'],
            'lines': lines,
            'total_lines': len(lines)
        }
        
    except Exception as e:
        return {'success': False, 'error': str(e)}


# =============================================================================
# ZEEK LOG INDEXING TO CLICKHOUSE
# =============================================================================

def parse_zeek_timestamp(ts_str: str) -> Optional[datetime]:
    """Parse Zeek timestamp (Unix epoch with microseconds)
    
    Args:
        ts_str: Timestamp string like '1609459200.123456'
        
    Returns:
        datetime object or None
    """
    if not ts_str or ts_str == '-':
        return None
    try:
        return datetime.utcfromtimestamp(float(ts_str))
    except (ValueError, TypeError):
        return None


def parse_zeek_ip(ip_str: str) -> Optional[str]:
    """Parse and validate IP address
    
    Args:
        ip_str: IP address string
        
    Returns:
        Validated IP string or None
    """
    if not ip_str or ip_str == '-':
        return None
    try:
        # Validate and normalize
        addr = ip_address(ip_str)
        return str(addr)
    except ValueError:
        return None


def parse_zeek_int(val_str: str) -> Optional[int]:
    """Parse Zeek integer field"""
    if not val_str or val_str == '-':
        return None
    try:
        return int(val_str)
    except (ValueError, TypeError):
        return None


def parse_zeek_float(val_str: str) -> Optional[float]:
    """Parse Zeek float field"""
    if not val_str or val_str == '-':
        return None
    try:
        return float(val_str)
    except (ValueError, TypeError):
        return None


def parse_zeek_array(val_str: str) -> List[str]:
    """Parse Zeek array field (comma-separated)"""
    if not val_str or val_str == '-' or val_str == '(empty)':
        return []
    return [v.strip() for v in val_str.split(',') if v.strip()]


def parse_zeek_log_file(log_path: str, log_type: str, case_id: int, pcap_id: int, 
                        source_host: str, batch_size: int = 5000) -> Tuple[int, List[str]]:
    """Parse a Zeek log file and insert into ClickHouse
    
    Args:
        log_path: Path to log file
        log_type: Type of log (conn, dns, http, etc.)
        case_id: PostgreSQL case ID
        pcap_id: PostgreSQL pcap_file ID
        source_host: Hostname from PCAP
        batch_size: Number of records per insert batch
        
    Returns:
        Tuple of (records_inserted, errors)
    """
    from models.network_log import insert_logs
    
    if not os.path.exists(log_path):
        return 0, [f'Log file not found: {log_path}']
    
    # Parse header to get column names
    headers = []
    separator = '\t'
    
    with open(log_path, 'r', errors='replace') as f:
        for line in f:
            line = line.strip()
            if line.startswith('#separator'):
                # Parse separator (usually \x09 for tab)
                sep_part = line.split(' ', 1)
                if len(sep_part) > 1:
                    sep_hex = sep_part[1].strip()
                    if sep_hex.startswith('\\x'):
                        separator = bytes.fromhex(sep_hex[2:]).decode('utf-8')
            elif line.startswith('#fields'):
                headers = line.replace('#fields', '').strip().split(separator)
                break
            elif not line.startswith('#'):
                # No header found, use defaults
                break
    
    if not headers:
        return 0, [f'Could not parse headers from {log_path}']
    
    # Column names for ClickHouse insert
    ch_columns = [
        'case_id', 'log_type', 'timestamp', 'pcap_id', 'source_host', 'uid',
        'src_ip', 'src_port', 'dst_ip', 'dst_port', 'proto', 'service',
        'duration', 'orig_bytes', 'resp_bytes', 'conn_state', 'missed_bytes',
        'orig_pkts', 'resp_pkts', 'query', 'qtype', 'qtype_name', 'rcode',
        'rcode_name', 'answers', 'ttls', 'rejected', 'method', 'host', 'uri',
        'referrer', 'user_agent', 'request_body_len', 'response_body_len',
        'status_code', 'status_msg', 'resp_mime_type', 'ssl_version', 'cipher',
        'server_name', 'subject', 'issuer', 'validation_status', 'ja3', 'ja3s',
        'fuid', 'file_source', 'analyzers', 'mime_type', 'filename', 'file_size',
        'md5', 'sha1', 'sha256', 'extracted', 'raw_json', 'search_blob'
    ]
    
    batch = []
    total_inserted = 0
    errors = []
    
    with open(log_path, 'r', errors='replace') as f:
        for line_num, line in enumerate(f):
            line = line.strip()
            
            # Skip header/comment lines
            if line.startswith('#') or not line:
                continue
            
            try:
                values = line.split(separator)
                
                # Build record dict from Zeek fields
                zeek_data = {}
                for i, header in enumerate(headers):
                    if i < len(values):
                        zeek_data[header] = values[i] if values[i] != '-' else None
                    else:
                        zeek_data[header] = None
                
                # Build search blob for full-text search
                search_parts = []
                for key, val in zeek_data.items():
                    if val:
                        search_parts.append(f"{key}:{val}")
                search_blob = ' '.join(search_parts)
                
                # Convert to JSON for raw storage
                raw_json = json.dumps(zeek_data, default=str)
                
                # Build ClickHouse record
                record = {
                    'case_id': case_id,
                    'log_type': log_type,
                    'timestamp': parse_zeek_timestamp(zeek_data.get('ts')),
                    'pcap_id': pcap_id,
                    'source_host': source_host or '',
                    'uid': zeek_data.get('uid') or '',
                    'src_ip': parse_zeek_ip(zeek_data.get('id.orig_h')),
                    'src_port': parse_zeek_int(zeek_data.get('id.orig_p')),
                    'dst_ip': parse_zeek_ip(zeek_data.get('id.resp_h')),
                    'dst_port': parse_zeek_int(zeek_data.get('id.resp_p')),
                    'proto': zeek_data.get('proto'),
                    'service': zeek_data.get('service'),
                    'duration': parse_zeek_float(zeek_data.get('duration')),
                    'orig_bytes': parse_zeek_int(zeek_data.get('orig_bytes')),
                    'resp_bytes': parse_zeek_int(zeek_data.get('resp_bytes')),
                    'conn_state': zeek_data.get('conn_state'),
                    'missed_bytes': parse_zeek_int(zeek_data.get('missed_bytes')),
                    'orig_pkts': parse_zeek_int(zeek_data.get('orig_pkts')),
                    'resp_pkts': parse_zeek_int(zeek_data.get('resp_pkts')),
                    # DNS
                    'query': zeek_data.get('query'),
                    'qtype': parse_zeek_int(zeek_data.get('qtype')),
                    'qtype_name': zeek_data.get('qtype_name'),
                    'rcode': parse_zeek_int(zeek_data.get('rcode')),
                    'rcode_name': zeek_data.get('rcode_name'),
                    'answers': parse_zeek_array(zeek_data.get('answers', '')),
                    'ttls': [parse_zeek_int(t) or 0 for t in parse_zeek_array(zeek_data.get('TTLs', ''))],
                    'rejected': 1 if zeek_data.get('rejected') == 'T' else 0,
                    # HTTP
                    'method': zeek_data.get('method'),
                    'host': zeek_data.get('host'),
                    'uri': zeek_data.get('uri'),
                    'referrer': zeek_data.get('referrer'),
                    'user_agent': zeek_data.get('user_agent'),
                    'request_body_len': parse_zeek_int(zeek_data.get('request_body_len')),
                    'response_body_len': parse_zeek_int(zeek_data.get('response_body_len')),
                    'status_code': parse_zeek_int(zeek_data.get('status_code')),
                    'status_msg': zeek_data.get('status_msg'),
                    'resp_mime_type': zeek_data.get('resp_mime_types'),
                    # SSL
                    'ssl_version': zeek_data.get('version'),
                    'cipher': zeek_data.get('cipher'),
                    'server_name': zeek_data.get('server_name'),
                    'subject': zeek_data.get('subject'),
                    'issuer': zeek_data.get('issuer'),
                    'validation_status': zeek_data.get('validation_status'),
                    'ja3': zeek_data.get('ja3'),
                    'ja3s': zeek_data.get('ja3s'),
                    # Files
                    'fuid': zeek_data.get('fuid'),
                    'file_source': zeek_data.get('source'),
                    'analyzers': parse_zeek_array(zeek_data.get('analyzers', '')),
                    'mime_type': zeek_data.get('mime_type'),
                    'filename': zeek_data.get('filename'),
                    'file_size': parse_zeek_int(zeek_data.get('seen_bytes') or zeek_data.get('total_bytes')),
                    'md5': zeek_data.get('md5'),
                    'sha1': zeek_data.get('sha1'),
                    'sha256': zeek_data.get('sha256'),
                    'extracted': zeek_data.get('extracted'),
                    # Meta
                    'raw_json': raw_json,
                    'search_blob': search_blob,
                }
                
                # Convert to tuple in column order
                row_tuple = tuple(record.get(col) for col in ch_columns)
                batch.append(row_tuple)
                
                # Insert batch when full
                if len(batch) >= batch_size:
                    try:
                        insert_logs(batch, ch_columns)
                        total_inserted += len(batch)
                        batch = []
                    except Exception as e:
                        errors.append(f"Batch insert error at line {line_num}: {str(e)[:100]}")
                        batch = []
                
            except Exception as e:
                errors.append(f"Line {line_num}: {str(e)[:100]}")
                if len(errors) > 100:
                    errors.append("... (truncated, too many errors)")
                    break
    
    # Insert remaining batch
    if batch:
        try:
            insert_logs(batch, ch_columns)
            total_inserted += len(batch)
        except Exception as e:
            errors.append(f"Final batch insert error: {str(e)[:100]}")
    
    return total_inserted, errors


@shared_task(bind=True, name='tasks.index_zeek_logs')
def index_zeek_logs(self, pcap_id: int):
    """Index Zeek log files into ClickHouse for hunting
    
    Called after process_pcap_with_zeek completes successfully.
    
    Args:
        pcap_id: ID of the PcapFile record
        
    Returns:
        dict with indexing results
    """
    from models.case import Case
    
    app = get_flask_app()
    
    with app.app_context():
        pcap_file = db.session.get(PcapFile, pcap_id)
        if not pcap_file:
            logger.error(f"PCAP file {pcap_id} not found for indexing")
            return {'success': False, 'error': 'PCAP file not found'}
        
        if not pcap_file.zeek_output_path or not os.path.exists(pcap_file.zeek_output_path):
            logger.error(f"Zeek output not found for PCAP {pcap_id}")
            return {'success': False, 'error': 'Zeek output not found'}
        
        # Get case ID
        case = Case.get_by_uuid(pcap_file.case_uuid)
        if not case:
            return {'success': False, 'error': 'Case not found'}
        
        logger.info(f"Indexing Zeek logs for PCAP {pcap_id} ({pcap_file.filename})")
        
        total_indexed = 0
        all_errors = []
        log_stats = {}
        
        try:
            # Find all log files
            for item in os.listdir(pcap_file.zeek_output_path):
                if not item.endswith('.log'):
                    continue
                
                log_type = item.replace('.log', '')
                log_path = os.path.join(pcap_file.zeek_output_path, item)
                
                # Only index supported log types
                if log_type not in INDEXED_LOG_TYPES:
                    logger.debug(f"Skipping unsupported log type: {log_type}")
                    continue
                
                logger.info(f"Indexing {log_type}.log for PCAP {pcap_id}")
                
                indexed, errors = parse_zeek_log_file(
                    log_path=log_path,
                    log_type=log_type,
                    case_id=case.id,
                    pcap_id=pcap_id,
                    source_host=pcap_file.hostname or ''
                )
                
                log_stats[log_type] = indexed
                total_indexed += indexed
                
                if errors:
                    all_errors.extend([f"{log_type}: {e}" for e in errors[:5]])
            
            # Update PCAP record
            pcap_file.indexed_at = datetime.utcnow()
            pcap_file.logs_indexed = total_indexed
            db.session.commit()
            
            logger.info(f"Indexed {total_indexed} records from PCAP {pcap_id}")
            
            return {
                'success': True,
                'pcap_id': pcap_id,
                'total_indexed': total_indexed,
                'by_log_type': log_stats,
                'errors': all_errors[:20] if all_errors else []
            }
            
        except Exception as e:
            logger.exception(f"Error indexing PCAP {pcap_id}")
            return {'success': False, 'error': str(e)}


@shared_task(bind=True, name='tasks.process_and_index_pcap')
def process_and_index_pcap(self, pcap_id: int):
    """Process PCAP with Zeek and then index to ClickHouse
    
    Convenience task that chains processing and indexing.
    
    Args:
        pcap_id: ID of the PcapFile record
        
    Returns:
        dict with combined results
    """
    # First process with Zeek
    process_result = process_pcap_with_zeek(pcap_id)
    
    if not process_result.get('success'):
        return process_result
    
    # Then index to ClickHouse
    index_result = index_zeek_logs(pcap_id)
    
    return {
        'success': index_result.get('success', False),
        'pcap_id': pcap_id,
        'zeek_result': process_result,
        'index_result': index_result
    }


@shared_task(bind=True, name='tasks.reindex_pcap_logs')
def reindex_pcap_logs(self, pcap_id: int):
    """Re-index Zeek logs for a PCAP (delete existing and re-insert)
    
    Args:
        pcap_id: ID of the PcapFile record
        
    Returns:
        dict with reindexing results
    """
    from models.network_log import delete_pcap_logs
    from models.case import Case
    
    app = get_flask_app()
    
    with app.app_context():
        pcap_file = db.session.get(PcapFile, pcap_id)
        if not pcap_file:
            return {'success': False, 'error': 'PCAP file not found'}
        
        case = Case.get_by_uuid(pcap_file.case_uuid)
        if not case:
            return {'success': False, 'error': 'Case not found'}
        
        # Delete existing logs
        logger.info(f"Deleting existing logs for PCAP {pcap_id}")
        delete_pcap_logs(pcap_id, case.id)
        
        # Re-index
        return index_zeek_logs(pcap_id)
