"""PCAP Processing Tasks - Zeek analysis for network captures

Thread-safe with cached Flask app instance for connection pool efficiency.
"""
import os
import json
import subprocess
import shutil
import logging
import threading
import zipfile
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


def _cleanup_empty_staging_dirs(path: str, staging_prefix: str) -> None:
    """Remove empty parent directories under the shared staging root."""
    current_dir = os.path.dirname(path)
    real_staging = os.path.realpath(staging_prefix)
    while current_dir and os.path.realpath(current_dir).startswith(real_staging):
        if os.path.realpath(current_dir) == real_staging:
            break
        try:
            os.rmdir(current_dir)
        except OSError:
            break
        current_dir = os.path.dirname(current_dir)


def _finalize_pcap_working_copy(pcap_file: Optional[PcapFile]) -> None:
    """Remove staged working PCAPs once Zeek has finished with them."""
    if not pcap_file or not pcap_file.file_path:
        return

    file_path = pcap_file.file_path
    staging_prefix = Config.STAGING_FOLDER
    if not file_path.startswith(staging_prefix):
        return

    if os.path.exists(file_path):
        os.remove(file_path)
        _cleanup_empty_staging_dirs(file_path, staging_prefix)

    if pcap_file.source_path and not pcap_file.is_extracted:
        pcap_file.file_path = pcap_file.source_path
    else:
        pcap_file.file_path = None


def _set_indexing_error(pcap_file: Optional[PcapFile], message: str) -> None:
    """Persist a network indexing failure without masking Zeek success."""
    if not pcap_file:
        return

    pcap_file.indexed_at = None
    pcap_file.logs_indexed = 0
    pcap_file.error_message = f"Indexing error: {message[:450]}"
    db.session.commit()


def _get_case_for_task(case_uuid: str):
    """Load a case directly for background task use."""
    from models.case import Case

    return Case.query.filter_by(uuid=case_uuid).first()

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


def get_zeek_output_dir(case_uuid: str, pcap_id: int, unique: bool = False) -> str:
    """Get the Zeek output directory for a PCAP file
    
    Output path: /opt/casescope/storage/{case_uuid}/pcap/zeek_{pcap_id}/
    
    Args:
        case_uuid: Case UUID
        pcap_id: PCAP file ID
        unique: If True, adds timestamp+uuid suffix for unique directory per run
                This prevents file conflicts when re-processing the same PCAP
                
    Returns:
        Path to output directory
    """
    if unique:
        # Create unique directory for this processing run
        import uuid as uuid_lib
        from datetime import datetime
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        unique_suffix = str(uuid_lib.uuid4())[:8]
        base_path = os.path.join(
            Config.STORAGE_FOLDER, case_uuid, 'pcap', 
            f'zeek_{pcap_id}_{timestamp}_{unique_suffix}'
        )
    else:
        base_path = os.path.join(Config.STORAGE_FOLDER, case_uuid, 'pcap', f'zeek_{pcap_id}')
    
    os.makedirs(base_path, exist_ok=True)
    
    try:
        shutil.chown(base_path, user='casescope', group='casescope')
    except (PermissionError, LookupError):
        pass
    
    return base_path


def _log_pcap_rebuild(case_uuid: str, entity_name: str, details: Dict[str, Any]) -> None:
    """Write an audit record for PCAP rebuild actions."""
    try:
        from models.audit_log import AuditAction, AuditEntityType, AuditLog

        AuditLog.log(
            entity_type=AuditEntityType.CASE_FILE,
            entity_id=case_uuid,
            entity_name=entity_name,
            action=AuditAction.REINDEXED,
            case_uuid=case_uuid,
            details=details,
        )
    except Exception as exc:
        logger.warning(f"Failed to write PCAP rebuild audit log for {case_uuid}: {exc}")


def _delete_pcap_scope(case_uuid: str, case_id: int, records: List[PcapFile]) -> Dict[str, int]:
    """Delete derived PCAP state while keeping retained originals."""
    from models.network_log import delete_pcap_logs
    from utils.artifact_paths import ensure_case_artifact_paths, is_within_root

    case_paths = ensure_case_artifact_paths(case_uuid)
    deleted_ids = set()
    logs_deleted = 0
    zeek_deleted = 0

    for record in records:
        if not record or record.id in deleted_ids:
            continue
        try:
            delete_pcap_logs(record.id, case_id)
            logs_deleted += record.logs_indexed or 0
        except Exception as exc:
            logger.warning(f"Failed to delete network logs for PCAP {record.id}: {exc}")

        if record.zeek_output_path and os.path.isdir(record.zeek_output_path):
            shutil.rmtree(record.zeek_output_path, ignore_errors=True)
            zeek_deleted += 1

        if record.file_path and is_within_root(record.file_path, case_paths['pcap_staging']):
            try:
                os.remove(record.file_path)
            except OSError:
                pass

        deleted_ids.add(record.id)
        db.session.delete(record)

    db.session.commit()
    return {
        'records_deleted': len(deleted_ids),
        'logs_deleted': logs_deleted,
        'zeek_deleted': zeek_deleted,
    }


def _ingest_pcap_rebuild_entries(case_uuid: str, uploaded_by: str, rebuild_entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Register rebuilt PCAP files and queue Zeek/index processing."""
    from utils.artifact_paths import copy_to_directory, ensure_case_artifact_paths

    case_paths = ensure_case_artifact_paths(case_uuid)
    staging_path = case_paths['pcap_staging']
    created_archives = 0
    created_records = 0
    queued_count = 0
    errors: List[str] = []

    for entry in rebuild_entries:
        workspace_path = entry.get('workspace_path')
        retained_original_path = entry.get('retained_original_path')
        filename = entry.get('name') or os.path.basename(retained_original_path or workspace_path or '')
        hostname = (entry.get('hostname') or '').upper()

        if not workspace_path or not os.path.exists(workspace_path):
            errors.append(f'Missing rebuild workspace file: {filename}')
            continue

        if entry.get('is_zip'):
            archive_hash = PcapFile.calculate_sha256(workspace_path)
            archive_size = os.path.getsize(workspace_path)
            archive_record = PcapFile(
                case_uuid=case_uuid,
                filename=filename,
                original_filename=filename,
                file_path=retained_original_path,
                source_path=retained_original_path,
                file_size=archive_size,
                sha256_hash=archive_hash,
                hostname=hostname,
                upload_source='rebuild',
                is_archive=True,
                extraction_status='pending',
                status=PcapFileStatus.DONE,
                retention_state='archived',
                uploaded_by=uploaded_by,
                processed_at=datetime.utcnow(),
            )
            db.session.add(archive_record)
            db.session.flush()
            created_archives += 1

            extract_root = os.path.join(staging_path, f'_rebuild_{archive_record.id}')
            os.makedirs(extract_root, exist_ok=True)
            try:
                with zipfile.ZipFile(workspace_path, 'r') as archive:
                    for member in archive.infolist():
                        if member.filename.endswith('/'):
                            continue
                        target_path = os.path.realpath(os.path.join(extract_root, member.filename))
                        if not target_path.startswith(os.path.realpath(extract_root) + os.sep):
                            errors.append(f'{filename}: blocked path traversal member {member.filename}')
                            continue
                        archive.extract(member, extract_root)

                archive_record.extraction_status = 'full'

                for root, _, extracted_names in os.walk(extract_root):
                    for extracted_name in extracted_names:
                        extracted_path = os.path.join(root, extracted_name)
                        if not PcapFile.is_pcap_file(extracted_path):
                            continue
                        file_hash = PcapFile.calculate_sha256(extracted_path)
                        existing = PcapFile.find_by_hash(file_hash, case_uuid)
                        pcap_record = PcapFile(
                            case_uuid=case_uuid,
                            parent_id=archive_record.id,
                            duplicate_of_id=existing.id if existing else None,
                            filename=extracted_name,
                            original_filename=extracted_name,
                            file_path=None if existing else extracted_path,
                            source_path=retained_original_path,
                            file_size=os.path.getsize(extracted_path),
                            sha256_hash=file_hash,
                            hostname=hostname,
                            upload_source='rebuild',
                            is_archive=False,
                            is_extracted=True,
                            pcap_type=PcapFile.detect_pcap_type(extracted_path),
                            status=PcapFileStatus.DUPLICATE if existing else PcapFileStatus.QUEUED,
                            retention_state='duplicate_retained' if existing else 'retained',
                            uploaded_by=uploaded_by,
                            error_message=f'Duplicate of PCAP #{existing.id}' if existing else None,
                        )
                        db.session.add(pcap_record)
                        db.session.flush()
                        created_records += 1
                        if existing:
                            os.remove(extracted_path)
                        else:
                            task = process_and_index_pcap.delay(pcap_record.id)
                            queued_count += 1
                db.session.commit()
            except Exception as exc:
                archive_record.status = PcapFileStatus.ERROR
                archive_record.error_message = str(exc)[:500]
                archive_record.extraction_status = 'fail'
                errors.append(f'{filename}: {exc}')
                db.session.commit()
            continue

        working_copy = copy_to_directory(workspace_path, staging_path, filename)
        if not working_copy:
            errors.append(f'Failed to create staging copy for {filename}')
            continue

        file_hash = PcapFile.calculate_sha256(working_copy)
        existing = PcapFile.find_by_hash(file_hash, case_uuid)
        pcap_record = PcapFile(
            case_uuid=case_uuid,
            parent_id=None,
            duplicate_of_id=existing.id if existing else None,
            filename=os.path.basename(working_copy),
            original_filename=filename,
            file_path=None if existing else working_copy,
            source_path=retained_original_path,
            file_size=os.path.getsize(working_copy),
            sha256_hash=file_hash,
            hostname=hostname,
            upload_source='rebuild',
            is_archive=False,
            is_extracted=False,
            pcap_type=PcapFile.detect_pcap_type(working_copy),
            status=PcapFileStatus.DUPLICATE if existing else PcapFileStatus.QUEUED,
            retention_state='duplicate_retained' if existing else 'retained',
            uploaded_by=uploaded_by,
            error_message=f'Duplicate of PCAP #{existing.id}' if existing else None,
        )
        db.session.add(pcap_record)
        db.session.commit()
        created_records += 1

        if existing:
            os.remove(working_copy)
        else:
            process_and_index_pcap.delay(pcap_record.id)
            queued_count += 1

    return {
        'created_archives': created_archives,
        'created_records': created_records,
        'queued_count': queued_count,
        'errors': errors,
    }


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
        
        # Reset prior indexing metadata before a fresh processing run.
        pcap_file.status = PcapFileStatus.PROCESSING
        pcap_file.indexed_at = None
        pcap_file.logs_indexed = 0
        db.session.commit()
        
        try:
            # Create unique output directory for this processing run
            # This prevents file conflicts when re-processing or concurrent access
            output_dir = get_zeek_output_dir(pcap_file.case_uuid, pcap_id, unique=True)
            
            # No need to clear existing output - unique directory is always empty
            
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
            _finalize_pcap_working_copy(pcap_file)
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
            _finalize_pcap_working_copy(pcap_file)
            pcap_file.status = PcapFileStatus.ERROR
            pcap_file.error_message = 'Zeek processing timed out (>1 hour)'
            db.session.commit()
            return {'success': False, 'error': 'Processing timeout'}
            
        except Exception as e:
            logger.exception(f"Error processing PCAP {pcap_id}")
            _finalize_pcap_working_copy(pcap_file)
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
            
            # Queue individual processing + indexing task
            task = process_and_index_pcap.delay(pcap.id)
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
    app = get_flask_app()
    
    with app.app_context():
        pcap_file = db.session.get(PcapFile, pcap_id)
        if not pcap_file:
            logger.error(f"PCAP file {pcap_id} not found for indexing")
            return {'success': False, 'error': 'PCAP file not found'}
        
        if not pcap_file.zeek_output_path or not os.path.exists(pcap_file.zeek_output_path):
            logger.error(f"Zeek output not found for PCAP {pcap_id}")
            _set_indexing_error(pcap_file, 'Zeek output not found')
            return {'success': False, 'error': 'Zeek output not found'}
        
        # Load directly from the database; background tasks have no request user.
        case = _get_case_for_task(pcap_file.case_uuid)
        if not case:
            _set_indexing_error(pcap_file, 'Case not found')
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
            pcap_file.error_message = None
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
            _set_indexing_error(pcap_file, str(e))
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
    process_result = process_pcap_with_zeek.run(pcap_id)
    
    if not process_result.get('success'):
        return process_result
    
    # Then index to ClickHouse
    index_result = index_zeek_logs.run(pcap_id)
    
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
    app = get_flask_app()
    
    with app.app_context():
        pcap_file = db.session.get(PcapFile, pcap_id)
        if not pcap_file:
            return {'success': False, 'error': 'PCAP file not found'}
        
        case = _get_case_for_task(pcap_file.case_uuid)
        if not case:
            return {'success': False, 'error': 'Case not found'}
        
        # Delete existing logs
        logger.info(f"Deleting existing logs for PCAP {pcap_id}")
        delete_pcap_logs(pcap_id, case.id)
        
        # Re-index
        return index_zeek_logs.run(pcap_id)


@shared_task(bind=True, name='tasks.rebuild_pcap_from_originals')
def rebuild_pcap_from_originals(self, pcap_id: int, username: str = 'system'):
    """Rebuild a single PCAP or archive from retained originals."""
    from utils.rebuilds import build_rebuild_audit_details, create_rebuild_run_id, ensure_case_rebuild_workspace, copy_file_to_workspace, remove_path_if_exists

    app = get_flask_app()
    with app.app_context():
        pcap_file = db.session.get(PcapFile, pcap_id)
        if not pcap_file:
            return {'success': False, 'error': 'PCAP file not found'}

        case = _get_case_for_task(pcap_file.case_uuid)
        if not case:
            return {'success': False, 'error': 'Case not found'}

        rebuild_target = pcap_file.parent if pcap_file.is_extracted and pcap_file.parent else pcap_file
        retained_original_path = rebuild_target.source_path or rebuild_target.file_path
        if not retained_original_path or not os.path.exists(retained_original_path):
            return {'success': False, 'error': 'Retained original not found on disk'}

        if rebuild_target.is_archive:
            records_to_delete = [rebuild_target] + list(rebuild_target.extracted_files)
        else:
            records_to_delete = [rebuild_target]

        delete_summary = _delete_pcap_scope(rebuild_target.case_uuid, case.id, records_to_delete)
        run_id = create_rebuild_run_id('pcap_file')
        workspace_root = ensure_case_rebuild_workspace(rebuild_target.case_uuid, 'pcap', run_id)
        workspace_file = copy_file_to_workspace(
            retained_original_path,
            workspace_root,
            rebuild_target.original_filename or os.path.basename(retained_original_path),
        )
        if not workspace_file:
            remove_path_if_exists(workspace_root)
            return {'success': False, 'error': 'Failed to create rebuild workspace copy'}

        ingest_result = _ingest_pcap_rebuild_entries(
            case_uuid=rebuild_target.case_uuid,
            uploaded_by=username,
            rebuild_entries=[{
                'name': rebuild_target.original_filename or os.path.basename(retained_original_path),
                'retained_original_path': retained_original_path,
                'workspace_path': workspace_file,
                'is_zip': PcapFile.is_zip_file(workspace_file),
                'hostname': rebuild_target.hostname or '',
            }],
        )
        remove_path_if_exists(workspace_root)

        _log_pcap_rebuild(
            rebuild_target.case_uuid,
            'PCAP rebuild',
            {
                **build_rebuild_audit_details(run_id, 'single_file', 'retained_original', [retained_original_path]),
                'requested_pcap_id': pcap_id,
                'records_deleted': delete_summary['records_deleted'],
                'logs_deleted': delete_summary['logs_deleted'],
                'zeek_deleted': delete_summary['zeek_deleted'],
                'created_archives': ingest_result['created_archives'],
                'created_records': ingest_result['created_records'],
                'queued_count': ingest_result['queued_count'],
                'errors': ingest_result['errors'][:20],
            },
        )

        return {
            'success': True,
            'pcap_id': pcap_id,
            'run_id': run_id,
            'records_deleted': delete_summary['records_deleted'],
            'queued_count': ingest_result['queued_count'],
            'errors': ingest_result['errors'],
        }


@shared_task(bind=True, name='tasks.rebuild_case_pcaps_from_originals')
def rebuild_case_pcaps_from_originals(self, case_uuid: str, username: str = 'system'):
    """Rebuild all retained PCAP originals for a case."""
    from models.network_log import delete_case_logs
    from utils.rebuilds import build_rebuild_audit_details, create_rebuild_run_id, ensure_case_rebuild_workspace, copy_tree_to_workspace, remove_path_if_exists
    from utils.artifact_paths import ensure_case_artifact_paths

    app = get_flask_app()
    with app.app_context():
        case = _get_case_for_task(case_uuid)
        if not case:
            return {'success': False, 'error': 'Case not found'}

        records = PcapFile.query.filter_by(case_uuid=case_uuid).all()
        delete_summary = _delete_pcap_scope(case_uuid, case.id, records)
        try:
            delete_case_logs(case.id)
        except Exception as exc:
            logger.warning(f"Failed to issue case-level network log delete for {case_uuid}: {exc}")

        case_paths = ensure_case_artifact_paths(case_uuid)
        run_id = create_rebuild_run_id('pcap_case')
        workspace_root = ensure_case_rebuild_workspace(case_uuid, 'pcap', run_id)
        copied = copy_tree_to_workspace(
            case_paths['pcap_originals'],
            workspace_root,
            skip_top_level=('cleared_uploads',),
        )
        if not copied:
            remove_path_if_exists(workspace_root)
            return {'success': False, 'error': 'No retained PCAP originals found'}

        rebuild_entries = [{
            'name': os.path.basename(entry['relative_path']),
            'retained_original_path': entry['source_path'],
            'workspace_path': entry['workspace_path'],
            'is_zip': PcapFile.is_zip_file(entry['workspace_path']),
            'hostname': '',
        } for entry in copied]

        ingest_result = _ingest_pcap_rebuild_entries(case_uuid, username, rebuild_entries)
        remove_path_if_exists(workspace_root)

        _log_pcap_rebuild(
            case_uuid,
            'PCAP case rebuild',
            {
                **build_rebuild_audit_details(run_id, 'case', 'retained_original', [entry['source_path'] for entry in copied]),
                'records_deleted': delete_summary['records_deleted'],
                'logs_deleted': delete_summary['logs_deleted'],
                'zeek_deleted': delete_summary['zeek_deleted'],
                'created_archives': ingest_result['created_archives'],
                'created_records': ingest_result['created_records'],
                'queued_count': ingest_result['queued_count'],
                'errors': ingest_result['errors'][:20],
            },
        )

        return {
            'success': True,
            'case_uuid': case_uuid,
            'run_id': run_id,
            'records_deleted': delete_summary['records_deleted'],
            'queued_count': ingest_result['queued_count'],
            'errors': ingest_result['errors'],
        }
