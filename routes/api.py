"""API routes for CaseScope"""
import os
import json
import logging
import platform
import subprocess
import shutil
import zipfile
from datetime import datetime
from flask import Blueprint, jsonify, request, Response, stream_with_context
from flask_login import login_required, current_user
from models.database import db
from models.user import User
from models.case import Case
from models.case_file import CaseFile, ExtractionStatus
from models.file_audit_log import FileAuditLog
from config import Config

logger = logging.getLogger(__name__)

api_bp = Blueprint('api', __name__, url_prefix='/api')

# Default paths for settings (also used by helper functions)
DEFAULT_ARCHIVE_PATH = '/archive'
DEFAULT_ORIGINALS_PATH = '/originals'

# =============================================================================
# FIELD:VALUE SEARCH MAPPING
# =============================================================================
# Maps search field aliases to (column_name, match_type)
# match_type: 'eq' = exact match, 'like' = ILIKE substring, 'blob' = search in search_blob
# If value is None, searches search_blob for "Field:value" pattern
SEARCH_FIELD_MAP = {
    # Event identification
    'eventid': ('event_id', 'eq'),
    'event_id': ('event_id', 'eq'),
    'id': ('event_id', 'eq'),
    'channel': ('channel', 'like'),
    'provider': ('provider', 'like'),
    'level': ('level', 'eq'),
    'recordid': ('record_id', 'eq'),
    
    # Source/Host
    'host': ('source_host', 'like'),
    'hostname': ('source_host', 'like'),
    'source_host': ('source_host', 'like'),
    'computer': ('source_host', 'like'),
    'artifact': ('artifact_type', 'eq'),
    'parser': ('artifact_type', 'eq'),
    'type': ('artifact_type', 'eq'),
    
    # User/Identity
    'user': ('username', 'like'),
    'username': ('username', 'like'),
    'domain': ('domain', 'like'),
    'sid': ('sid', 'like'),
    'logontype': ('logon_type', 'eq'),
    'logon_type': ('logon_type', 'eq'),
    
    # Process
    'process': ('process_name', 'like'),
    'process_name': ('process_name', 'like'),
    'proc': ('process_name', 'like'),
    'cmd': ('command_line', 'like'),
    'commandline': ('command_line', 'like'),
    'command_line': ('command_line', 'like'),
    'parent': ('parent_process', 'like'),
    'parent_process': ('parent_process', 'like'),
    'pid': ('process_id', 'eq'),
    'ppid': ('parent_pid', 'eq'),
    
    # File/Path
    'path': ('target_path', 'like'),
    'file': ('target_path', 'like'),
    'target_path': ('target_path', 'like'),
    'filename': ('target_path', 'like'),
    
    # Hashes
    'md5': ('file_hash_md5', 'eq'),
    'sha1': ('file_hash_sha1', 'eq'),
    'sha256': ('file_hash_sha256', 'eq'),
    'hash': ('file_hash_sha256', 'like'),  # partial match any hash
    
    # Network
    'ip': ('src_ip', 'eq'),  # Default to src_ip
    'srcip': ('src_ip', 'eq'),
    'src_ip': ('src_ip', 'eq'),
    'dstip': ('dst_ip', 'eq'),
    'dst_ip': ('dst_ip', 'eq'),
    'port': ('dst_port', 'eq'),
    'srcport': ('src_port', 'eq'),
    'dstport': ('dst_port', 'eq'),
    
    # Registry
    'regkey': ('reg_key', 'like'),
    'reg_key': ('reg_key', 'like'),
    'registry': ('reg_key', 'like'),
    'regvalue': ('reg_value', 'like'),
    'regdata': ('reg_data', 'like'),
    
    # Detection/Rules
    'rule': ('rule_title', 'like'),
    'rule_title': ('rule_title', 'like'),
    'severity': ('rule_level', 'eq'),
    'rule_level': ('rule_level', 'eq'),
    
    # EventData fields (search in search_blob as FieldName:Value)
    # These are the fields we backfilled from EVTX EventData
    'keylength': None,
    'authpackage': None,
    'authenticationpackagename': None,
    'logonprocess': None,
    'logonprocessname': None,
    'workstationname': None,
    'ipaddress': None,
    'ipport': None,
    'targetusername': None,
    'subjectusername': None,
    'targetdomainname': None,
    'targetusersid': None,
    'subjectusersid': None,
    'targetlogonid': None,
    'subjectlogonid': None,
    'status': None,
    'substatus': None,
    'failurereason': None,
    'elevatedtoken': None,
    'servicename': None,
    'servicefilename': None,
    'taskname': None,
    'objectname': None,
    'objecttype': None,
    'accessmask': None,
    'privilegelist': None,
    'newprocessname': None,
    'parentprocessname': None,
    'targetfilename': None,
    'hashes': None,
}


def _move_to_storage(file_path: str, case_uuid: str) -> str:
    """Move a file from staging to storage, preserving path structure.
    
    Args:
        file_path: Current file path in staging
        case_uuid: Case UUID for context
        
    Returns:
        New file path in storage, or original path if move failed
    """
    if not file_path or not os.path.exists(file_path):
        return file_path
    
    staging_prefix = Config.STAGING_FOLDER
    if not file_path.startswith(staging_prefix):
        return file_path  # Already not in staging
    
    # Build storage path by replacing staging prefix with storage prefix
    relative_path = file_path[len(staging_prefix):].lstrip(os.sep)
    storage_path = os.path.join(Config.STORAGE_FOLDER, relative_path)
    
    try:
        # Create destination directory if needed
        storage_dir = os.path.dirname(storage_path)
        os.makedirs(storage_dir, exist_ok=True)
        
        # Set permissions
        try:
            shutil.chown(storage_dir, user='casescope', group='casescope')
        except (PermissionError, LookupError):
            pass
        
        # Move the file
        shutil.move(file_path, storage_path)
        logger.info(f"Moved file to storage: {file_path} -> {storage_path}")
        
        return storage_path
        
    except Exception as e:
        logger.error(f"Failed to move file to storage: {file_path}: {e}")
        return file_path  # Return original path on failure


def _move_to_originals(file_path: str, case_uuid: str, filename: str) -> str:
    """Move an original uploaded file (e.g., ZIP) to the originals archive folder.
    
    Args:
        file_path: Current file path in uploads
        case_uuid: Case UUID for folder structure
        filename: Original filename to preserve
        
    Returns:
        New file path in originals folder, or None if move failed
    """
    from models.system_settings import SystemSettings, SettingKeys
    
    if not file_path or not os.path.exists(file_path):
        return None
    
    # Get originals path from settings
    originals_base = SystemSettings.get(SettingKeys.ORIGINALS_PATH, DEFAULT_ORIGINALS_PATH)
    
    # Build destination: {originals_path}/{case_uuid}/{filename}
    originals_dir = os.path.join(originals_base, case_uuid)
    dest_path = os.path.join(originals_dir, filename)
    
    try:
        # Create destination directory if needed
        os.makedirs(originals_dir, exist_ok=True)
        
        # Set permissions on directory
        try:
            shutil.chown(originals_dir, user='casescope', group='casescope')
        except (PermissionError, LookupError):
            pass
        
        # Handle filename collision (same filename uploaded multiple times)
        if os.path.exists(dest_path):
            base, ext = os.path.splitext(filename)
            counter = 1
            while os.path.exists(dest_path):
                dest_path = os.path.join(originals_dir, f"{base}_{counter}{ext}")
                counter += 1
        
        # Move the file
        shutil.move(file_path, dest_path)
        
        # Set permissions on file
        try:
            shutil.chown(dest_path, user='casescope', group='casescope')
        except (PermissionError, LookupError):
            pass
        
        logger.info(f"Moved original file to archive: {file_path} -> {dest_path}")
        return dest_path
        
    except Exception as e:
        logger.error(f"Failed to move original file to archive: {file_path}: {e}")
        return None


def get_folder_size_gb(path):
    """Get folder size in GB"""
    try:
        if not os.path.exists(path):
            return 0.0
        total = 0
        for dirpath, dirnames, filenames in os.walk(path):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                try:
                    total += os.path.getsize(fp)
                except (OSError, FileNotFoundError):
                    pass
        return round(total / (1024 ** 3), 2)
    except Exception:
        return 0.0


def get_software_version(command):
    """Get software version from command"""
    try:
        result = subprocess.run(
            command, 
            shell=True, 
            capture_output=True, 
            text=True, 
            timeout=5
        )
        version = result.stdout.strip().split('\n')[0] if result.stdout else 'Not installed'
        return version if version else 'Not installed'
    except Exception:
        return 'Not installed'


@api_bp.route('/dashboard/stats')
@login_required
def dashboard_stats():
    """Get dashboard statistics"""
    try:
        import psutil
        
        # System info
        hostname = platform.node()
        os_info = f"{platform.system()} {platform.release()}"
        
        # CPU
        cpu_percent = psutil.cpu_percent(interval=0.1)
        cpu_cores = psutil.cpu_count()
        
        # RAM
        ram = psutil.virtual_memory()
        ram_total_gb = round(ram.total / (1024 ** 3), 2)
        ram_used_gb = round(ram.used / (1024 ** 3), 2)
        
        # Disks
        disks = []
        for partition in psutil.disk_partitions():
            if partition.device.startswith('/dev/') and not partition.mountpoint.startswith('/snap'):
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disks.append({
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'total_gb': round(usage.total / (1024 ** 3), 2),
                        'used_gb': round(usage.used / (1024 ** 3), 2),
                        'percent': usage.percent
                    })
                except PermissionError:
                    pass
        
        # Case storage
        live_gb = get_folder_size_gb(Config.STORAGE_FOLDER)
        archive_gb = get_folder_size_gb(os.path.join(Config.BASE_DIR, 'archive'))
        
        # Software versions - all pulled live from system
        # CaseScope version from version.json
        casescope_version = 'Unknown'
        try:
            with open(os.path.join(Config.BASE_DIR, 'version.json'), 'r') as f:
                casescope_version = json.load(f).get('version', 'Unknown')
        except Exception:
            pass
        
        # Get software versions using importlib.metadata (gunicorn restricts shell commands)
        from importlib.metadata import version as pkg_version, PackageNotFoundError
        
        def safe_pkg_version(package_name):
            """Safely get package version, return 'Not installed' if not found"""
            try:
                return pkg_version(package_name)
            except PackageNotFoundError:
                return 'Not installed'
        
        # Hayabusa version from binary (uses 'help' command, version in first line)
        hayabusa_ver = get_software_version('/opt/casescope/bin/hayabusa help 2>/dev/null | head -1')
        if hayabusa_ver and hayabusa_ver != 'Not installed':
            # Extract version from output like "Hayabusa v3.7.0 - CODE BLUE Release"
            import re
            match = re.search(r'v(\d+\.\d+\.\d+)', hayabusa_ver)
            hayabusa_ver = match.group(1) if match else 'Not installed'
        
        # Zeek version from binary
        zeek_ver = get_software_version('zeek --version')
        if zeek_ver and zeek_ver != 'Not installed':
            # Extract version from output like "zeek version 8.0.5"
            parts = zeek_ver.replace('zeek version ', '').strip()
            zeek_ver = parts if parts else zeek_ver
        
        # ClickHouse server version via Python client
        clickhouse_ver = 'Not available'
        try:
            import clickhouse_connect
            ch_client = clickhouse_connect.get_client(host='localhost')
            result = ch_client.query("SELECT version()")
            clickhouse_ver = result.result_rows[0][0]
        except Exception:
            pass
        
        # PostgreSQL server version via database query
        postgres_ver = 'Not available'
        try:
            result = db.session.execute(db.text("SELECT version()"))
            pg_version_str = result.scalar()
            # Extract version number from string like "PostgreSQL 15.4 (Ubuntu 15.4-1.pgdg22.04+1) on x86_64..."
            if pg_version_str:
                import re
                match = re.search(r'PostgreSQL (\d+\.\d+(?:\.\d+)?)', pg_version_str)
                postgres_ver = match.group(1) if match else pg_version_str.split()[1]
        except Exception:
            pass
        
        # Qdrant server version via client
        qdrant_ver = 'Not available'
        try:
            from qdrant_client import QdrantClient
            qdrant = QdrantClient(host='localhost', port=6333, timeout=2)
            info = qdrant.get_collections()
            # If we can connect, try to get version from server info
            try:
                import requests
                resp = requests.get('http://localhost:6333/', timeout=2)
                if resp.ok:
                    qdrant_ver = resp.json().get('version', 'Connected')
            except Exception:
                qdrant_ver = 'Connected'
        except Exception:
            pass
        
        software = {
            'casescope': casescope_version,
            'python': platform.python_version(),
            'flask': safe_pkg_version('flask'),
            'celery': safe_pkg_version('celery'),
            'gunicorn': safe_pkg_version('gunicorn'),
            'postgresql': postgres_ver,
            'clickhouse': clickhouse_ver,
            'redis': safe_pkg_version('redis'),
            'qdrant': qdrant_ver,
            'hayabusa': hayabusa_ver,
            'zeek': zeek_ver,
            'volatility3': safe_pkg_version('volatility3'),
            'dissect': safe_pkg_version('dissect.util'),
            'sqlalchemy': safe_pkg_version('sqlalchemy'),
        }
        
        # Case statistics - pulled live from database and ClickHouse
        total_cases = Case.query.count()
        total_users = User.query.count()
        
        # Total events from ClickHouse
        total_events = 0
        try:
            from utils.clickhouse import get_client
            ch_client = get_client()
            result = ch_client.query("SELECT count() FROM events")
            total_events = result.result_rows[0][0] if result.result_rows else 0
        except Exception:
            pass
        
        return jsonify({
            'timestamp': datetime.utcnow().isoformat(),
            'system': {
                'hostname': hostname,
                'os': os_info,
                'cpu': {
                    'usage_percent': cpu_percent,
                    'cores': cpu_cores
                },
                'ram': {
                    'total_gb': ram_total_gb,
                    'used_gb': ram_used_gb,
                    'percent': ram.percent
                },
                'disks': disks,
                'case_storage': {
                    'live_gb': live_gb,
                    'archive_gb': archive_gb
                }
            },
            'cases': {
                'total_cases': total_cases,
                'total_events': total_events,
                'total_users': total_users
            },
            'software': software
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================
# File Upload API Endpoints
# ============================================

# Upload directories
WEB_UPLOAD_DIR = '/opt/casescope/uploads/web'
SFTP_UPLOAD_DIR = '/opt/casescope/uploads/sftp'
CHUNK_TEMP_DIR = '/opt/casescope/uploads/temp'
STAGING_DIR = '/opt/casescope/staging'


def ensure_upload_dirs(case_uuid):
    """Ensure upload directories exist for a case"""
    web_path = os.path.join(WEB_UPLOAD_DIR, case_uuid)
    sftp_path = os.path.join(SFTP_UPLOAD_DIR, case_uuid)
    staging_path = os.path.join(STAGING_DIR, case_uuid)
    
    os.makedirs(web_path, exist_ok=True)
    os.makedirs(sftp_path, exist_ok=True)
    os.makedirs(staging_path, exist_ok=True)
    os.makedirs(CHUNK_TEMP_DIR, exist_ok=True)
    
    # Set permissions to casescope user with group write and setgid
    for path in [web_path, sftp_path, staging_path]:
        try:
            shutil.chown(path, user='casescope', group='casescope')
            os.chmod(path, 0o2775)  # rwxrwsr-x - group write + setgid
        except (PermissionError, LookupError):
            pass  # May not have permission to chown/chmod
    
    return web_path, sftp_path, staging_path


@api_bp.route('/upload/scan/<case_uuid>')
@login_required
def scan_upload_folder(case_uuid):
    """Scan the SFTP folder for uploaded files"""
    try:
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        _, sftp_path, _ = ensure_upload_dirs(case_uuid)
        
        files = []
        if os.path.exists(sftp_path):
            for filename in os.listdir(sftp_path):
                filepath = os.path.join(sftp_path, filename)
                if os.path.isfile(filepath):
                    stat = os.stat(filepath)
                    files.append({
                        'name': filename,
                        'path': filepath,
                        'size': stat.st_size,
                        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                    })
        
        return jsonify({
            'success': True,
            'path': sftp_path,
            'files': files
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/upload/chunk', methods=['POST'])
@login_required
def upload_chunk():
    """Handle chunked file upload
    
    Thread-safe with file-based locking to prevent race conditions
    when multiple requests try to combine chunks simultaneously.
    """
    import fcntl
    
    try:
        chunk = request.files.get('chunk')
        chunk_index = int(request.form.get('chunkIndex', 0))
        total_chunks = int(request.form.get('totalChunks', 1))
        upload_id = request.form.get('uploadId')
        filename = request.form.get('filename')
        case_uuid = request.form.get('caseUuid')
        
        if not all([chunk, upload_id, filename, case_uuid]):
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400
        
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Ensure directories exist
        web_path, _, _ = ensure_upload_dirs(case_uuid)
        
        # Create temp directory for this upload
        temp_dir = os.path.join(CHUNK_TEMP_DIR, upload_id)
        os.makedirs(temp_dir, exist_ok=True)
        
        # Save chunk
        chunk_path = os.path.join(temp_dir, f'chunk_{chunk_index:06d}')
        chunk.save(chunk_path)
        
        # Check if all chunks are uploaded
        existing_chunks = len([f for f in os.listdir(temp_dir) if f.startswith('chunk_')])
        
        if existing_chunks >= total_chunks:
            # Use file-based locking to prevent race condition during chunk combination
            lock_file_path = os.path.join(temp_dir, '.combine_lock')
            try:
                with open(lock_file_path, 'w') as lock_file:
                    # Try to acquire exclusive lock (non-blocking)
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    
                    # Double-check chunks after acquiring lock
                    existing_chunks = len([f for f in os.listdir(temp_dir) if f.startswith('chunk_')])
                    if existing_chunks < total_chunks:
                        # Another request already combined, let it handle
                        return jsonify({
                            'success': True,
                            'complete': False,
                            'chunksReceived': existing_chunks
                        })
                    
                    # Combine chunks
                    final_path = os.path.join(web_path, filename)
                    
                    # Avoid filename collisions
                    if os.path.exists(final_path):
                        base, ext = os.path.splitext(filename)
                        counter = 1
                        while os.path.exists(final_path):
                            final_path = os.path.join(web_path, f'{base}_{counter}{ext}')
                            counter += 1
                    
                    with open(final_path, 'wb') as outfile:
                        for i in range(total_chunks):
                            chunk_file = os.path.join(temp_dir, f'chunk_{i:06d}')
                            with open(chunk_file, 'rb') as infile:
                                outfile.write(infile.read())
                    
                    # Set file ownership
                    try:
                        shutil.chown(final_path, user='casescope', group='casescope')
                    except (PermissionError, LookupError):
                        pass
                    
                    # Clean up temp directory (after releasing lock implicitly)
                    shutil.rmtree(temp_dir, ignore_errors=True)
                    
                    return jsonify({
                        'success': True,
                        'complete': True,
                        'path': final_path
                    })
                    
            except BlockingIOError:
                # Another request is combining chunks, return current status
                return jsonify({
                    'success': True,
                    'complete': False,
                    'chunksReceived': existing_chunks,
                    'combining': True
                })
        
        return jsonify({
            'success': True,
            'complete': False,
            'chunksReceived': existing_chunks
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/upload/preflight', methods=['POST'])
@login_required
def preflight_check():
    """Check for duplicate files before ingestion
    
    Calculates hashes for all files and checks against existing records.
    Returns list of duplicates for user confirmation.
    """
    try:
        data = request.get_json()
        case_uuid = data.get('caseUuid')
        files = data.get('files', [])
        
        if not case_uuid:
            return jsonify({'success': False, 'error': 'Case UUID required'}), 400
        
        if not files:
            return jsonify({'success': False, 'error': 'No files to check'}), 400
        
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        web_path, sftp_path, _ = ensure_upload_dirs(case_uuid)
        
        duplicates = []
        file_hashes = {}  # Map filename -> hash for later use
        
        for file_info in files:
            filename = file_info.get('name')
            source = file_info.get('source', 'web')
            
            # Determine source path
            if source == 'folder':
                source_path = file_info.get('path')
            else:
                source_path = os.path.join(web_path, filename)
            
            if not source_path or not os.path.exists(source_path):
                continue
            
            # Calculate hash
            try:
                file_hash = CaseFile.calculate_sha256(source_path)
                file_hashes[filename] = file_hash
                
                # Check for existing file with same hash (within this case only)
                existing = CaseFile.find_by_hash(file_hash, case_uuid=case_uuid)
                if existing:
                    duplicates.append({
                        'new_file': filename,
                        'new_hash': file_hash,
                        'existing_file': existing.filename,
                        'existing_hash': existing.sha256_hash,
                        'existing_case': existing.case_uuid,
                        'uploaded_at': existing.uploaded_at.strftime('%Y-%m-%d %H:%M:%S'),
                        'source': source
                    })
            except Exception as e:
                # Hash calculation failed - will handle during ingestion
                pass
        
        return jsonify({
            'success': True,
            'duplicates': duplicates,
            'file_hashes': file_hashes,
            'has_duplicates': len(duplicates) > 0
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/upload/ingest', methods=['POST'])
@login_required
def ingest_files():
    """Process and ingest files with streaming progress updates"""
    # Get request data before entering generator (request context needed)
    data = request.get_json()
    case_uuid = data.get('caseUuid')
    files = data.get('files', [])
    skip_files = data.get('skipFiles', [])  # Files user chose not to reingest
    file_hashes = data.get('fileHashes', {})  # Pre-calculated hashes from preflight
    uploaded_by = current_user.username
    
    # Validate upfront
    if not case_uuid:
        return jsonify({'success': False, 'error': 'Case UUID required'}), 400
    
    if not files:
        return jsonify({'success': False, 'error': 'No files to ingest'}), 400
    
    case = Case.get_by_uuid(case_uuid)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    def generate_progress():
        """Generator that yields NDJSON progress updates"""
        from flask import current_app
        
        web_path, sftp_path, staging_path = ensure_upload_dirs(case_uuid)
        
        ingested_count = 0
        extracted_count = 0
        duplicates_skipped = 0
        duplicates_deleted = 0
        extraction_failures = []
        errors = []
        processed_files = []  # Track files for hash stage
        zip_files = []  # Track zip files for extraction stage
        zip_records = {}  # Map zip unique_key -> {'record': CaseFile, 'source_path': str, 'filename': str}
        non_zip_files = []  # Track non-zip files for move stage
        
        # =============================================
        # PHASE 1: Identify files and check existence
        # =============================================
        for file_info in files:
            filename = file_info.get('name')
            source = file_info.get('source', 'web')
            
            # Skip files user chose not to reingest
            if filename in skip_files:
                duplicates_skipped += 1
                continue
            
            if source == 'folder':
                source_path = file_info.get('path')
            else:
                source_path = os.path.join(web_path, filename)
            
            if not source_path or not os.path.exists(source_path):
                errors.append(f'File not found: {filename}')
                continue
            
            # Check if it's a zip file
            is_zip = CaseFile.is_zip_file(source_path)
            
            file_data = {
                'name': filename,
                'source_path': source_path,
                'file_info': file_info,
                'is_zip': is_zip,
                'hash': file_hashes.get(filename)  # May be None if not pre-calculated
            }
            
            if is_zip:
                zip_files.append(file_data)
            else:
                non_zip_files.append(file_data)
        
        # =============================================
        # PHASE 2: Extract ZIP files directly to staging
        # =============================================
        if zip_files:
            total_zips = len(zip_files)
            for idx, zf in enumerate(zip_files):
                yield json.dumps({
                    'stage': 'extract',
                    'current': idx + 1,
                    'total': total_zips,
                    'filename': zf['name']
                }) + '\n'
                
                source_path = zf['source_path']
                filename = zf['name']
                file_info = zf['file_info']
                
                # Calculate hash if not already done
                zip_hash = zf.get('hash')
                if not zip_hash:
                    try:
                        zip_hash = CaseFile.calculate_sha256(source_path)
                    except Exception as e:
                        errors.append(f'Error hashing {filename}: {str(e)}')
                        continue
                
                # Get file size before extraction
                zip_size = os.path.getsize(source_path)
                
                # Create extraction directory: staging/case_uuid/zipname_hashprefix/
                # Use hash prefix to make unique (handles duplicate filenames from different dates)
                hash_prefix = zip_hash[:8] if zip_hash else str(int(datetime.utcnow().timestamp()))
                unique_zip_key = f"{filename}_{hash_prefix}"
                extract_dir = os.path.join(staging_path, unique_zip_key)
                os.makedirs(extract_dir, exist_ok=True)
                
                try:
                    shutil.chown(extract_dir, user='casescope', group='casescope')
                except (PermissionError, LookupError):
                    pass
                
                # Attempt extraction
                extraction_status = ExtractionStatus.FAIL
                extracted_file_count = 0
                
                try:
                    with zipfile.ZipFile(source_path, 'r') as zfile:
                        zfile.extractall(extract_dir)
                    extraction_status = ExtractionStatus.FULL
                    
                    # Track extracted files
                    for root, dirs, extracted_files_list in os.walk(extract_dir):
                        for extracted_name in extracted_files_list:
                            extracted_path = os.path.join(root, extracted_name)
                            rel_path = os.path.relpath(extracted_path, extract_dir)
                            processed_files.append({
                                'path': extracted_path,
                                'filename': rel_path,
                                'original_filename': extracted_name,
                                'file_info': file_info,
                                'is_archive': CaseFile.is_zip_file(extracted_path),
                                'is_extracted': True,
                                'parent_zip': unique_zip_key,  # Unique key for parent linking
                                'parent_zip_name': filename  # Original name for display
                            })
                            extracted_file_count += 1
                    
                except zipfile.BadZipFile:
                    extraction_status = ExtractionStatus.FAIL
                    extraction_failures.append(f'{filename}: Invalid ZIP file')
                    # Treat as regular file
                    non_zip_files.append(zf)
                except Exception as e:
                    # Check if partial extraction occurred
                    extracted_count_check = sum(1 for _ in os.walk(extract_dir) for _ in _[2])
                    if extracted_count_check > 0:
                        extraction_status = ExtractionStatus.PARTIAL
                        extraction_failures.append(f'{filename}: Partial extraction - {str(e)}')
                    else:
                        extraction_status = ExtractionStatus.FAIL
                        extraction_failures.append(f'{filename}: {str(e)}')
                
                # Record ZIP file in database (even if extraction failed)
                # file_path will be updated after moving to originals folder
                zip_record = CaseFile(
                    case_uuid=case_uuid,
                    parent_id=None,
                    filename=filename,
                    original_filename=filename,
                    file_path=None,  # Will be set after moving to originals
                    file_size=zip_size,
                    sha256_hash=zip_hash,
                    hostname=file_info.get('host', ''),
                    file_type=file_info.get('type', 'Other'),
                    upload_source=file_info.get('source', 'web'),
                    is_archive=True,
                    is_extracted=False,
                    extraction_status=extraction_status,
                    status='new',
                    uploaded_by=uploaded_by
                )
                db.session.add(zip_record)
                db.session.flush()
                # Store record with source path for moving to originals later
                zip_records[unique_zip_key] = {
                    'record': zip_record,
                    'source_path': source_path,
                    'filename': filename
                }
                ingested_count += 1
        
        # =============================================
        # PHASE 3: Move non-zip files to staging
        # =============================================
        if non_zip_files:
            total_non_zip = len(non_zip_files)
            for idx, nzf in enumerate(non_zip_files):
                yield json.dumps({
                    'stage': 'move',
                    'current': idx + 1,
                    'total': total_non_zip,
                    'filename': nzf['name']
                }) + '\n'
                
                try:
                    import uuid as uuid_module
                    
                    source_path = nzf['source_path']
                    filename = nzf['name']
                    file_info = nzf['file_info']
                    
                    # Use atomic move pattern: move to unique temp location first,
                    # then rename to final name. This prevents TOCTOU race conditions.
                    temp_filename = f".tmp_{uuid_module.uuid4().hex}_{filename}"
                    temp_path = os.path.join(staging_path, temp_filename)
                    
                    # Move to unique temp location (guaranteed no collision)
                    shutil.move(source_path, temp_path)
                    
                    # Now determine final destination with collision handling
                    dest_path = os.path.join(staging_path, filename)
                    final_filename = filename
                    
                    if os.path.exists(dest_path):
                        base, ext = os.path.splitext(filename)
                        counter = 1
                        while os.path.exists(dest_path):
                            final_filename = f'{base}_{counter}{ext}'
                            dest_path = os.path.join(staging_path, final_filename)
                            counter += 1
                    
                    # Atomic rename on same filesystem
                    os.rename(temp_path, dest_path)
                    
                    try:
                        shutil.chown(dest_path, user='casescope', group='casescope')
                    except (PermissionError, LookupError):
                        pass
                    
                    processed_files.append({
                        'path': dest_path,
                        'filename': os.path.basename(dest_path),
                        'original_filename': filename,
                        'file_info': file_info,
                        'is_archive': False,
                        'is_extracted': False,
                        'parent_zip': None,
                        'parent_zip_name': None,
                        'hash': nzf.get('hash')
                    })
                    
                    ingested_count += 1
                    
                except Exception as e:
                    # Clean up temp file if it exists
                    if 'temp_path' in locals() and os.path.exists(temp_path):
                        try:
                            os.remove(temp_path)
                        except:
                            pass
                    errors.append(f'Error moving {nzf["name"]}: {str(e)}')
        
        # =============================================
        # PHASE 4: Calculate hashes and record metadata
        # =============================================
        total_processed = len(processed_files)
        
        for idx, pf in enumerate(processed_files):
            yield json.dumps({
                'stage': 'hash',
                'current': idx + 1,
                'total': total_processed,
                'filename': pf['filename']
            }) + '\n'
            
            try:
                file_path = pf['path']
                file_size = os.path.getsize(file_path)
                
                # Use pre-calculated hash or calculate now
                sha256_hash = pf.get('hash')
                if not sha256_hash:
                    sha256_hash = CaseFile.calculate_sha256(file_path)
                
                # Check for duplicate (within this case only)
                # Use original filename (without zip prefix) for comparison
                original_name = pf['original_filename']
                dup_type, existing = CaseFile.check_duplicate_type(original_name, sha256_hash, case_uuid)
                
                # Get parent ZIP record if this is an extracted file
                parent_id = None
                parent_zip_key = pf.get('parent_zip')  # Unique key with hash
                parent_zip_name = pf.get('parent_zip_name')  # Original filename for display
                if parent_zip_key and parent_zip_key in zip_records:
                    parent_id = zip_records[parent_zip_key]['record'].id
                
                # Build filename with zip prefix for extracted files (use original name for display)
                display_filename = pf['filename']
                if parent_zip_name:
                    display_filename = f"{parent_zip_name}/{pf['filename']}"
                
                if dup_type == 'true':
                    # TRUE DUPLICATE: same filename + same hash
                    # Delete the file and log the deletion
                    try:
                        FileAuditLog.log_deleted_duplicate(
                            case_uuid=case_uuid,
                            filename=display_filename,
                            sha256_hash=sha256_hash,
                            file_path=file_path,
                            file_size=file_size,
                            performed_by=uploaded_by,
                            original_file_id=existing.id
                        )
                        os.remove(file_path)
                        duplicates_deleted += 1
                    except Exception as e:
                        errors.append(f'Error deleting duplicate {display_filename}: {str(e)}')
                    continue
                
                elif dup_type == 'hash_only':
                    # PARTIAL DUPLICATE: same hash, different filename
                    # Keep file (don't parse - already indexed), move to storage, create record
                    
                    # Move to storage immediately (won't go through parsing queue)
                    storage_path = _move_to_storage(file_path, case_uuid)
                    
                    case_file = CaseFile(
                        case_uuid=case_uuid,
                        parent_id=parent_id,
                        duplicate_of_id=existing.id,
                        filename=display_filename,
                        original_filename=original_name,
                        file_path=storage_path or file_path,  # Use storage path if move succeeded
                        file_size=file_size,
                        sha256_hash=sha256_hash,
                        hostname=pf['file_info'].get('host', ''),
                        file_type=pf['file_info'].get('type', 'Other'),
                        upload_source=pf['file_info'].get('source', 'web'),
                        is_archive=pf['is_archive'],
                        is_extracted=pf['is_extracted'],
                        extraction_status=ExtractionStatus.NA,
                        status='duplicate',  # Not parsed since content already indexed
                        ingestion_status='not_done',
                        uploaded_by=uploaded_by
                    )
                    db.session.add(case_file)
                    db.session.flush()
                    continue
                
                # dup_type == 'name_only' or None: treat as new file
                # (name_only means same filename but different hash - different file version)
                
                case_file = CaseFile(
                    case_uuid=case_uuid,
                    parent_id=parent_id,
                    filename=display_filename,
                    original_filename=pf['original_filename'],
                    file_path=file_path,
                    file_size=file_size,
                    sha256_hash=sha256_hash,
                    hostname=pf['file_info'].get('host', ''),
                    file_type=pf['file_info'].get('type', 'Other'),
                    upload_source=pf['file_info'].get('source', 'web'),
                    is_archive=pf['is_archive'],
                    is_extracted=pf['is_extracted'],
                    extraction_status=ExtractionStatus.NA,
                    status='new',
                    uploaded_by=uploaded_by
                )
                
                db.session.add(case_file)
                db.session.flush()
                
                if parent_zip_key:
                    extracted_count += 1
                    
            except Exception as e:
                errors.append(f'Error hashing {pf["filename"]}: {str(e)}')
                # Still create CaseFile record to maintain forensic integrity
                # Files with errors are moved to storage and tracked
                try:
                    parent_id = None
                    parent_zip_key = pf.get('parent_zip')
                    parent_zip_name = pf.get('parent_zip_name')
                    if parent_zip_key and parent_zip_key in zip_records:
                        parent_id = zip_records[parent_zip_key]['record'].id
                    
                    display_filename = pf['filename']
                    if parent_zip_name:
                        display_filename = f"{parent_zip_name}/{pf['filename']}"
                    
                    # Move to storage even on error
                    storage_path = _move_to_storage(pf['path'], case_uuid)
                    
                    case_file = CaseFile(
                        case_uuid=case_uuid,
                        parent_id=parent_id,
                        filename=display_filename,
                        original_filename=pf['original_filename'],
                        file_path=storage_path or pf['path'],
                        file_size=0,  # Unknown due to error
                        sha256_hash=None,
                        hostname=pf['file_info'].get('host', ''),
                        file_type=pf['file_info'].get('type', 'Other'),
                        upload_source=pf['file_info'].get('source', 'web'),
                        is_archive=pf.get('is_archive', False),
                        is_extracted=pf.get('is_extracted', False),
                        extraction_status=ExtractionStatus.NA,
                        status='error',
                        ingestion_status='error',
                        uploaded_by=uploaded_by
                    )
                    db.session.add(case_file)
                    db.session.flush()
                except Exception as inner_e:
                    logger.warning(f"Failed to create error record for {pf['filename']}: {inner_e}")
        
        # =============================================
        # PHASE 5: Move ZIPs to originals, cleanup remaining files
        # =============================================
        yield json.dumps({'stage': 'cleanup'}) + '\n'
        
        # Build set of zip source paths to preserve (move instead of delete)
        zip_source_paths = set()
        for zr_data in zip_records.values():
            zip_source_paths.add(zr_data['source_path'])
        
        try:
            # Move zip files to originals folder and update CaseFile records
            for unique_key, zr_data in zip_records.items():
                source_path = zr_data['source_path']
                filename = zr_data['filename']
                record = zr_data['record']
                
                if source_path and os.path.exists(source_path):
                    originals_path = _move_to_originals(source_path, case_uuid, filename)
                    if originals_path:
                        # Update the CaseFile record with the new path
                        record.file_path = originals_path
                        logger.info(f"Archived original ZIP: {filename} -> {originals_path}")
                    else:
                        errors.append(f'Failed to archive original: {filename}')
            
            # Clean up remaining files in web upload directory (non-zip files)
            for f in os.listdir(web_path):
                fpath = os.path.join(web_path, f)
                if os.path.isfile(fpath) and fpath not in zip_source_paths:
                    os.remove(fpath)
            
            # Clean up remaining files in sftp upload directory (non-zip files)
            for f in os.listdir(sftp_path):
                fpath = os.path.join(sftp_path, f)
                if os.path.isfile(fpath) and fpath not in zip_source_paths:
                    os.remove(fpath)
        except Exception as e:
            errors.append(f'Cleanup error: {str(e)}')
        
        # Commit all database changes
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            errors.append(f'Database error: {str(e)}')
        
        # =============================================
        # PHASE 6: Trigger parsing for all staged files
        # =============================================
        yield json.dumps({'stage': 'parsing', 'message': 'Queuing files for parsing...'}) + '\n'
        
        try:
            from tasks.celery_tasks import parse_file_task
            from models.case import Case
            from utils.progress import init_progress
            
            case = Case.get_by_uuid(case_uuid)
            if case:
                # Get all pending files for this case
                pending_files = CaseFile.query.filter_by(
                    case_uuid=case_uuid,
                    status='new'
                ).filter(
                    CaseFile.is_archive == False  # Don't parse ZIP files themselves
                ).all()
                
                # Count files to be queued
                files_to_queue = [cf for cf in pending_files if cf.file_path and os.path.exists(cf.file_path)]
                
                # Initialize Redis progress tracking for this batch
                if files_to_queue:
                    init_progress(case_uuid, len(files_to_queue))
                
                queued_count = 0
                for cf in files_to_queue:
                    cf.status = 'queued'
                    db.session.flush()
                    
                    parse_file_task.delay(
                        file_path=cf.file_path,
                        case_id=case.id,
                        source_host=cf.hostname or '',
                        case_file_id=cf.id,
                    )
                    queued_count += 1
                
                # Handle nested archives (e.g., .xpi files) - move to storage without parsing
                # These files have is_archive=True and are excluded from parsing queue above
                nested_archives = CaseFile.query.filter_by(
                    case_uuid=case_uuid,
                    status='new',
                    is_archive=True,
                    is_extracted=True  # Only extracted archives, not original uploads
                ).all()
                
                nested_archive_count = 0
                for cf in nested_archives:
                    if cf.file_path and os.path.exists(cf.file_path):
                        # Move to storage
                        storage_path = _move_to_storage(cf.file_path, case_uuid)
                        if storage_path:
                            cf.file_path = storage_path
                        cf.status = 'done'
                        cf.ingestion_status = 'no_parser'
                        cf.processed_at = datetime.utcnow()
                        nested_archive_count += 1
                
                if nested_archive_count > 0:
                    logger.info(f"Moved {nested_archive_count} nested archive files to storage for case {case_uuid}")
                
                db.session.commit()
                yield json.dumps({
                    'stage': 'parsing_queued',
                    'queued_count': queued_count
                }) + '\n'
        except Exception as e:
            yield json.dumps({
                'stage': 'parsing_error',
                'error': str(e)
            }) + '\n'
        
        # =============================================
        # COMPLETE
        # =============================================
        yield json.dumps({
            'stage': 'complete',
            'ingested': ingested_count,
            'extracted': extracted_count,
            'duplicates_skipped': duplicates_skipped,
            'duplicates_deleted': duplicates_deleted,
            'extraction_failures': extraction_failures,
            'errors': errors
        }) + '\n'
    
    return Response(
        stream_with_context(generate_progress()),
        mimetype='application/x-ndjson',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )


# ============================================
# File Management API Endpoints
# ============================================

@api_bp.route('/files/stats/<case_uuid>')
@login_required
def get_file_stats(case_uuid):
    """Get file statistics for a case"""
    try:
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        stats = CaseFile.get_stats(case_uuid)
        stats['success'] = True
        stats['case_uuid'] = case_uuid
        
        return jsonify(stats)
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/case/statistics/<case_uuid>')
@login_required
def get_case_statistics(case_uuid):
    """Get comprehensive statistics for a case dashboard
    
    Returns file statistics, artifact statistics, entity counts,
    memory forensics stats, PCAP processing stats, network logs, and evidence files.
    """
    try:
        from models.case_file import CaseFile
        from models.ioc import IOC
        from models.known_system import KnownSystem
        from models.known_user import KnownUser
        from models.pcap_file import PcapFile
        from models.memory_job import MemoryJob
        from models.evidence_file import EvidenceFile
        from models import network_log
        from utils.clickhouse import get_client
        
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # === FILE STATISTICS ===
        file_stats = CaseFile.get_stats(case_uuid)
        
        # Get file type breakdown
        file_type_counts = db.session.query(
            CaseFile.file_type, db.func.count(CaseFile.id)
        ).filter(
            CaseFile.case_uuid == case_uuid,
            CaseFile.is_archive == False,
            CaseFile.status != 'duplicate'
        ).group_by(CaseFile.file_type).all()
        
        file_types = {ft or 'Unknown': count for ft, count in file_type_counts}
        
        # === ARTIFACT STATISTICS (from ClickHouse) ===
        artifact_stats = {
            'total': 0,
            'by_type': {},
            'analyst_tagged': 0,
            'ioc_tagged': 0,
            'sigma_tagged': 0,
            'noise_matched': 0
        }
        
        try:
            client = get_client()
            
            # Total artifacts
            result = client.query(
                "SELECT count() FROM events WHERE case_id = {case_id:UInt32}",
                parameters={'case_id': case.id}
            )
            artifact_stats['total'] = result.result_rows[0][0] if result.result_rows else 0
            
            # Artifacts by type
            result = client.query(
                """SELECT artifact_type, count() as cnt 
                   FROM events 
                   WHERE case_id = {case_id:UInt32}
                   GROUP BY artifact_type 
                   ORDER BY cnt DESC""",
                parameters={'case_id': case.id}
            )
            for row in result.result_rows:
                artifact_stats['by_type'][row[0] or 'unknown'] = row[1]
            
            # Analyst tagged count
            result = client.query(
                "SELECT count() FROM events WHERE case_id = {case_id:UInt32} AND analyst_tagged = true",
                parameters={'case_id': case.id}
            )
            artifact_stats['analyst_tagged'] = result.result_rows[0][0] if result.result_rows else 0
            
            # IOC tagged count (events with at least one IOC type)
            result = client.query(
                "SELECT count() FROM events WHERE case_id = {case_id:UInt32} AND length(ioc_types) > 0",
                parameters={'case_id': case.id}
            )
            artifact_stats['ioc_tagged'] = result.result_rows[0][0] if result.result_rows else 0
            
            # Sigma tagged count (events with rule_title)
            result = client.query(
                "SELECT count() FROM events WHERE case_id = {case_id:UInt32} AND rule_title IS NOT NULL AND rule_title != ''",
                parameters={'case_id': case.id}
            )
            artifact_stats['sigma_tagged'] = result.result_rows[0][0] if result.result_rows else 0
            
            # Noise matched count
            result = client.query(
                "SELECT count() FROM events WHERE case_id = {case_id:UInt32} AND noise_matched = true",
                parameters={'case_id': case.id}
            )
            artifact_stats['noise_matched'] = result.result_rows[0][0] if result.result_rows else 0
            
        except Exception as ch_error:
            # ClickHouse may not be available, continue with zeros
            pass
        
        # === ENTITY COUNTS ===
        ioc_count = IOC.query.filter(
            IOC.case_id == case.id,
            IOC.false_positive == False
        ).count()
        
        system_count = KnownSystem.query.filter_by(case_id=case.id).count()
        user_count = KnownUser.query.filter_by(case_id=case.id).count()
        
        # === PCAP STATISTICS ===
        pcap_stats = PcapFile.get_stats(case_uuid)
        
        # === NETWORK LOGS STATISTICS (Zeek indexed data in ClickHouse) ===
        network_stats = {
            'total': 0,
            'by_type': {},
            'unique_src_ips': 0,
            'unique_dst_ips': 0
        }
        
        try:
            net_stats = network_log.get_network_stats(case.id)
            network_stats['total'] = net_stats.get('total', 0)
            network_stats['by_type'] = net_stats.get('by_type', {})
            network_stats['unique_src_ips'] = net_stats.get('unique_src_ips', 0)
            network_stats['unique_dst_ips'] = net_stats.get('unique_dst_ips', 0)
        except Exception:
            # Network logs table may not exist or be empty
            pass
        
        # === MEMORY FORENSICS STATISTICS ===
        memory_stats = {
            'total': 0,
            'completed': 0,
            'running': 0,
            'pending': 0,
            'failed': 0,
            'total_plugins_run': 0
        }
        
        try:
            memory_jobs = MemoryJob.query.filter_by(case_id=case.id).all()
            memory_stats['total'] = len(memory_jobs)
            
            for job in memory_jobs:
                if job.status == 'completed':
                    memory_stats['completed'] += 1
                    # Count completed plugins
                    if job.plugins_completed:
                        memory_stats['total_plugins_run'] += len(job.plugins_completed)
                elif job.status == 'running':
                    memory_stats['running'] += 1
                elif job.status == 'pending':
                    memory_stats['pending'] += 1
                elif job.status == 'failed':
                    memory_stats['failed'] += 1
        except Exception:
            # Memory jobs table may not exist yet
            pass
        
        # === EVIDENCE FILES STATISTICS (non-processed archival files) ===
        evidence_stats = {
            'total_files': 0,
            'total_size': 0,
            'total_size_display': '0 B',
            'by_type': {}
        }
        
        try:
            ev_stats = EvidenceFile.get_case_stats(case_uuid)
            evidence_stats['total_files'] = ev_stats.get('total_files', 0)
            evidence_stats['total_size'] = ev_stats.get('total_size', 0)
            evidence_stats['by_type'] = ev_stats.get('file_types', {})
            # Human-readable size
            size = evidence_stats['total_size']
            if size < 1024:
                evidence_stats['total_size_display'] = f"{size} B"
            elif size < 1024 * 1024:
                evidence_stats['total_size_display'] = f"{size / 1024:.1f} KB"
            elif size < 1024 * 1024 * 1024:
                evidence_stats['total_size_display'] = f"{size / (1024 * 1024):.1f} MB"
            else:
                evidence_stats['total_size_display'] = f"{size / (1024 * 1024 * 1024):.2f} GB"
        except Exception:
            # Evidence files table may not exist yet
            pass
        
        return jsonify({
            'success': True,
            'case_uuid': case_uuid,
            'file_stats': {
                'total': file_stats['total'],
                'fully_indexed': file_stats['fully_indexed'],
                'partially_indexed': file_stats['partially_indexed'],
                'no_parser': file_stats['no_parser'],
                'parse_error': file_stats['parse_error'],
                'error': file_stats['error'],
                'pending': file_stats['pending'],
                'by_type': file_types
            },
            'artifact_stats': artifact_stats,
            'entity_counts': {
                'iocs': ioc_count,
                'systems': system_count,
                'users': user_count
            },
            'pcap_stats': pcap_stats,
            'network_stats': network_stats,
            'memory_stats': memory_stats,
            'evidence_stats': evidence_stats
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/files/list/<case_uuid>')
@login_required
def get_file_list(case_uuid):
    """Get paginated file list for a case"""
    try:
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 25, type=int)
        search = request.args.get('search', '', type=str).strip()
        include_duplicates = request.args.get('include_duplicates', 'false', type=str).lower() == 'true'
        
        # Limit per_page to reasonable values
        per_page = min(max(per_page, 10), 200)
        
        # Build query
        query = CaseFile.query.filter_by(case_uuid=case_uuid)
        
        # Exclude duplicates by default
        if not include_duplicates:
            query = query.filter(CaseFile.status != 'duplicate')
        
        # Apply search filter
        if search:
            search_filter = f'%{search}%'
            query = query.filter(
                db.or_(
                    CaseFile.filename.ilike(search_filter),
                    CaseFile.hostname.ilike(search_filter),
                    CaseFile.file_type.ilike(search_filter),
                    CaseFile.uploaded_by.ilike(search_filter),
                    CaseFile.parser_type.ilike(search_filter)
                )
            )
        
        # Order by uploaded_at desc
        query = query.order_by(CaseFile.uploaded_at.desc())
        
        # Get total count before pagination
        total = query.count()
        
        # Apply pagination
        files = query.offset((page - 1) * per_page).limit(per_page).all()
        
        # Build file list with parent filename lookup
        file_list = []
        parent_cache = {}
        
        for cf in files:
            # Get parent filename if exists
            parent_filename = None
            if cf.parent_id:
                if cf.parent_id not in parent_cache:
                    parent = CaseFile.query.get(cf.parent_id)
                    parent_cache[cf.parent_id] = parent.filename if parent else None
                parent_filename = parent_cache[cf.parent_id]
            
            file_list.append({
                'id': cf.id,
                'parent_filename': parent_filename,
                'filename': cf.filename,
                'file_size': cf.file_size,
                'hostname': cf.hostname or '-',
                'file_type': cf.file_type or '-',
                'upload_source': cf.upload_source,
                'uploaded_by': cf.uploaded_by,
                'uploaded_at': cf.uploaded_at.strftime('%Y-%m-%d %H:%M') if cf.uploaded_at else '-',
                'status': cf.status,
                'ingestion_status': cf.ingestion_status,
                'parser_type': cf.parser_type or '-',
                'events_indexed': cf.events_indexed,
                'error_message': cf.error_message
            })
        
        return jsonify({
            'success': True,
            'case_uuid': case_uuid,
            'files': file_list,
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': (total + per_page - 1) // per_page
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/files/progress/<case_uuid>')
@login_required
def get_processing_progress(case_uuid):
    """Get processing progress for a case
    
    Returns progress for all phases: files, systems discovery, users discovery
    """
    try:
        from tasks.celery_tasks import celery_app
        from utils.progress import get_progress
        
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Get progress from Redis (tracks current batch)
        progress = get_progress(case_uuid)
        
        if progress:
            # Active batch in progress
            phase = progress.get('phase', 'files')
            status = progress.get('status', 'idle')
            current_item = progress.get('current_item', '')
            
            # File progress
            files_data = progress.get('files', {})
            total_files = files_data.get('total', 0)
            processed_files = files_data.get('completed', 0)
            
            # Post-processing phase progress
            dedup_data = progress.get('deduplication', {})
            systems_data = progress.get('systems', {})
            users_data = progress.get('users', {})
            
            # Determine state
            is_processing = status == 'processing'
            is_completing = status in ('flushing_buffer', 'deduplicating', 'discovering_systems', 'discovering_users')
            
            # Map new status to legacy completion_phase for backward compatibility
            completion_phase_map = {
                'flushing_buffer': 'flushing_buffer',
                'deduplicating': 'deduplicating',
                'discovering_systems': 'discovering_systems',
                'discovering_users': 'discovering_users'
            }
            completion_phase = completion_phase_map.get(status)
        else:
            # No active batch - idle state
            phase = 'idle'
            status = 'idle'
            current_item = ''
            total_files = 0
            processed_files = 0
            dedup_data = {'total': 0, 'completed': 0}
            systems_data = {'total': 0, 'completed': 0}
            users_data = {'total': 0, 'completed': 0}
            is_processing = False
            is_completing = False
            completion_phase = None
        
        # Get active workers processing this case
        workers = []
        try:
            # Get active tasks
            inspect = celery_app.control.inspect()
            active = inspect.active() or {}
            
            for worker_name, tasks in active.items():
                for task in tasks:
                    if task.get('name') == 'tasks.parse_file':
                        args = task.get('args', [])
                        kwargs = task.get('kwargs', {})
                        
                        # Check if this task is for our case
                        case_file_id = kwargs.get('case_file_id') or (args[3] if len(args) > 3 else None)
                        if case_file_id:
                            cf = CaseFile.query.get(case_file_id)
                            if cf and cf.case_uuid == case_uuid:
                                workers.append({
                                    'worker': worker_name.split('@')[-1],
                                    'file': cf.filename,
                                    'task_id': task.get('id')
                                })
        except Exception:
            # Celery inspect may fail if no workers
            pass
        
        return jsonify({
            'success': True,
            'case_uuid': case_uuid,
            # Legacy fields for backward compatibility
            'total_files': total_files,
            'processed_files': processed_files,
            'workers': workers,
            'is_processing': is_processing,
            'is_completing': is_completing,
            'completion_phase': completion_phase,
            # New phase-based progress
            'phase': phase,
            'status': status,
            'current_item': current_item,
            'files': {
                'total': total_files,
                'completed': processed_files
            },
            'deduplication': dedup_data,
            'systems': systems_data,
            'users': users_data
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/files/reindex/<case_uuid>', methods=['POST'])
@login_required
def reindex_case_files(case_uuid):
    """Reindex all files for a case - wipes ClickHouse and DB data, re-scans storage"""
    try:
        from tasks.celery_tasks import reindex_case_task
        
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Check storage directory exists
        storage_path = os.path.join(Config.STORAGE_FOLDER, case_uuid)
        if not os.path.isdir(storage_path):
            return jsonify({
                'success': False, 
                'error': 'No storage directory found for this case'
            }), 404
        
        # Count files to be reindexed
        file_count = 0
        for root, dirs, files in os.walk(storage_path):
            file_count += len(files)
        
        if file_count == 0:
            return jsonify({
                'success': False,
                'error': 'No files found in storage directory'
            }), 404
        
        # Queue the reindex task
        task = reindex_case_task.delay(
            case_uuid=case_uuid,
            case_id=case.id,
            username=current_user.username
        )
        
        return jsonify({
            'success': True,
            'task_id': task.id,
            'case_uuid': case_uuid,
            'files_queued': file_count,
            'message': 'Reindex started'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================
# Event Deduplication Endpoints
# ============================================

@api_bp.route('/events/duplicates/preview/<case_uuid>')
@login_required
def preview_duplicate_events(case_uuid):
    """Preview duplicate events for a case without deleting them
    
    Returns a summary of potential duplicates by artifact type.
    """
    try:
        from utils.event_deduplication import get_duplicate_summary
        
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        summary = get_duplicate_summary(case.id)
        
        return jsonify({
            'success': True,
            'case_uuid': case_uuid,
            'case_id': case.id,
            'total_duplicates': summary.get('total_duplicates', 0),
            'by_artifact_type': summary.get('by_artifact_type', {})
        })
        
    except Exception as e:
        logger.error(f"Error previewing duplicates for case {case_uuid}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/events/duplicates/remove/<case_uuid>', methods=['POST'])
@login_required
def remove_duplicate_events(case_uuid):
    """Remove duplicate events from a case
    
    Runs deduplication synchronously (for small cases) or async (for large cases).
    For each artifact type, keeps the earliest indexed event and deletes duplicates.
    """
    try:
        from utils.event_deduplication import deduplicate_case_events
        
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Run deduplication
        result = deduplicate_case_events(
            case_id=case.id,
            case_uuid=case_uuid,
            track_progress=False  # Don't track - this is a manual action
        )
        
        return jsonify({
            'success': result.get('success', False),
            'case_uuid': case_uuid,
            'case_id': case.id,
            'artifact_types_checked': result.get('artifact_types_checked', 0),
            'total_duplicates_found': result.get('total_duplicates_found', 0),
            'total_duplicates_deleted': result.get('total_duplicates_deleted', 0),
            'details': result.get('details', []),
            'message': result.get('message', ''),
            'errors': result.get('errors')
        })
        
    except Exception as e:
        logger.error(f"Error removing duplicates for case {case_uuid}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================
# Staging Orphan Management Endpoints
# ============================================

@api_bp.route('/files/staging/check/<case_uuid>')
@login_required
def check_staging_orphans(case_uuid):
    """Check for orphan files in staging directory for a case
    
    Orphan files are files on disk that have no corresponding database record.
    """
    try:
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        staging_path = os.path.join(Config.STAGING_FOLDER, case_uuid)
        
        if not os.path.isdir(staging_path):
            return jsonify({
                'success': True,
                'has_orphans': False,
                'orphan_count': 0,
                'orphans': []
            })
        
        # Collect all files in staging
        staging_files = []
        for root, dirs, files in os.walk(staging_path):
            for filename in files:
                file_path = os.path.join(root, filename)
                rel_path = os.path.relpath(file_path, staging_path)
                staging_files.append({
                    'path': file_path,
                    'rel_path': rel_path,
                    'filename': filename,
                    'size': os.path.getsize(file_path)
                })
        
        if not staging_files:
            return jsonify({
                'success': True,
                'has_orphans': False,
                'orphan_count': 0,
                'orphans': []
            })
        
        # Get all file paths from database for this case
        db_files = CaseFile.query.filter_by(case_uuid=case_uuid).with_entities(CaseFile.file_path).all()
        db_paths = {f.file_path for f in db_files if f.file_path}
        
        # Find orphans (files in staging not in database)
        orphans = []
        for sf in staging_files:
            if sf['path'] not in db_paths:
                orphans.append({
                    'path': sf['path'],
                    'rel_path': sf['rel_path'],
                    'filename': sf['filename'],
                    'size': sf['size']
                })
        
        return jsonify({
            'success': True,
            'has_orphans': len(orphans) > 0,
            'orphan_count': len(orphans),
            'orphans': orphans[:100]  # Limit response size, show first 100
        })
        
    except Exception as e:
        logger.exception(f"Error checking staging orphans for case {case_uuid}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/files/staging/import/<case_uuid>', methods=['POST'])
@login_required
def import_staging_orphans(case_uuid):
    """Import orphan files from staging into the case
    
    Creates CaseFile records for orphan files and queues them for parsing.
    """
    try:
        from tasks.celery_tasks import parse_file_task
        from utils.progress import init_progress
        
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        staging_path = os.path.join(Config.STAGING_FOLDER, case_uuid)
        
        if not os.path.isdir(staging_path):
            return jsonify({'success': False, 'error': 'No staging directory found'}), 404
        
        # Collect orphan files
        staging_files = []
        for root, dirs, files in os.walk(staging_path):
            for filename in files:
                file_path = os.path.join(root, filename)
                rel_path = os.path.relpath(file_path, staging_path)
                staging_files.append({
                    'path': file_path,
                    'rel_path': rel_path,
                    'filename': filename
                })
        
        # Get all file paths from database for this case
        db_files = CaseFile.query.filter_by(case_uuid=case_uuid).with_entities(CaseFile.file_path).all()
        db_paths = {f.file_path for f in db_files if f.file_path}
        
        # Find and import orphans
        imported = []
        files_to_queue = []
        
        for sf in staging_files:
            if sf['path'] not in db_paths:
                try:
                    file_path = sf['path']
                    file_size = os.path.getsize(file_path)
                    sha256_hash = CaseFile.calculate_sha256(file_path)
                    is_archive = CaseFile.is_zip_file(file_path)
                    
                    case_file = CaseFile(
                        case_uuid=case_uuid,
                        parent_id=None,
                        filename=sf['rel_path'],
                        original_filename=sf['filename'],
                        file_path=file_path,
                        file_size=file_size,
                        sha256_hash=sha256_hash,
                        hostname='',
                        file_type='Other',
                        upload_source='staging_import',
                        is_archive=is_archive,
                        is_extracted=False,
                        extraction_status='n/a',
                        status='new',
                        uploaded_by=current_user.username
                    )
                    
                    db.session.add(case_file)
                    db.session.flush()
                    
                    if not is_archive:
                        files_to_queue.append(case_file)
                    
                    imported.append(sf['rel_path'])
                    
                except Exception as e:
                    logger.warning(f"Failed to import staging file {sf['path']}: {e}")
                    continue
        
        db.session.commit()
        
        # Queue files for parsing
        if files_to_queue:
            init_progress(case_uuid, len(files_to_queue))
            
            for cf in files_to_queue:
                cf.status = 'queued'
                db.session.flush()
                
                parse_file_task.delay(
                    file_path=cf.file_path,
                    case_id=case.id,
                    source_host=cf.hostname or '',
                    case_file_id=cf.id,
                )
            
            db.session.commit()
        
        return jsonify({
            'success': True,
            'imported_count': len(imported),
            'queued_for_parsing': len(files_to_queue),
            'imported': imported[:50]  # Return first 50 filenames
        })
        
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error importing staging orphans for case {case_uuid}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/files/staging/delete/<case_uuid>', methods=['POST'])
@login_required
def delete_staging_orphans(case_uuid):
    """Delete orphan files from staging directory
    
    Only available to administrators.
    """
    try:
        # Check admin permission
        if current_user.permission_level != 'administrator':
            return jsonify({'success': False, 'error': 'Administrator access required'}), 403
        
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        staging_path = os.path.join(Config.STAGING_FOLDER, case_uuid)
        
        if not os.path.isdir(staging_path):
            return jsonify({'success': False, 'error': 'No staging directory found'}), 404
        
        # Collect all files in staging
        staging_files = []
        for root, dirs, files in os.walk(staging_path):
            for filename in files:
                file_path = os.path.join(root, filename)
                staging_files.append(file_path)
        
        # Get all file paths from database for this case
        db_files = CaseFile.query.filter_by(case_uuid=case_uuid).with_entities(CaseFile.file_path).all()
        db_paths = {f.file_path for f in db_files if f.file_path}
        
        # Delete orphans
        deleted = []
        for file_path in staging_files:
            if file_path not in db_paths:
                try:
                    os.remove(file_path)
                    deleted.append(file_path)
                except Exception as e:
                    logger.warning(f"Failed to delete staging file {file_path}: {e}")
        
        # Clean up empty directories
        for root, dirs, files in os.walk(staging_path, topdown=False):
            for d in dirs:
                dir_path = os.path.join(root, d)
                try:
                    if not os.listdir(dir_path):
                        os.rmdir(dir_path)
                except Exception:
                    pass
        
        return jsonify({
            'success': True,
            'deleted_count': len(deleted)
        })
        
    except Exception as e:
        logger.exception(f"Error deleting staging orphans for case {case_uuid}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/files/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_case_file(file_id):
    """Delete a case file and all associated data
    
    This endpoint:
    - Deletes all events from ClickHouse for this file
    - Deletes child files (extracted from archives) and their events
    - Removes the file from disk
    - Removes the CaseFile record from PostgreSQL
    - Logs the deletion in the audit log
    
    Only available to administrators.
    """
    try:
        from utils.clickhouse import delete_file_events, count_file_events
        from models.file_audit_log import FileAuditLog
        
        # Check admin permission
        if current_user.permission_level != 'administrator':
            return jsonify({'success': False, 'error': 'Administrator access required'}), 403
        
        # Get the file record
        case_file = CaseFile.query.get(file_id)
        if not case_file:
            return jsonify({'success': False, 'error': 'File not found'}), 404
        
        # Verify case exists
        case = Case.get_by_uuid(case_file.case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Collect stats for response
        deleted_stats = {
            'file_id': file_id,
            'filename': case_file.filename,
            'events_deleted': 0,
            'child_files_deleted': 0,
            'disk_file_deleted': False
        }
        
        # Get count of events before deletion
        try:
            deleted_stats['events_deleted'] = count_file_events(file_id)
        except Exception as e:
            logger.warning(f"Could not count events for file {file_id}: {e}")
        
        # Delete events from ClickHouse for this file
        try:
            delete_file_events(file_id)
            logger.info(f"Deleted ClickHouse events for file_id={file_id}")
        except Exception as e:
            logger.error(f"Failed to delete ClickHouse events for file_id={file_id}: {e}")
            # Continue with deletion even if ClickHouse fails
        
        # Handle child files (extracted from archives)
        child_files = CaseFile.query.filter_by(parent_id=file_id).all()
        for child in child_files:
            try:
                # Delete child's events from ClickHouse
                delete_file_events(child.id)
                logger.info(f"Deleted ClickHouse events for child file_id={child.id}")
            except Exception as e:
                logger.warning(f"Failed to delete ClickHouse events for child file {child.id}: {e}")
            
            # Delete child file from disk
            if child.file_path and os.path.exists(child.file_path):
                try:
                    os.remove(child.file_path)
                    logger.info(f"Deleted child file from disk: {child.file_path}")
                except Exception as e:
                    logger.warning(f"Failed to delete child file {child.file_path}: {e}")
            
            # Delete child record from database
            db.session.delete(child)
            deleted_stats['child_files_deleted'] += 1
        
        # Delete the file from disk
        if case_file.file_path and os.path.exists(case_file.file_path):
            try:
                os.remove(case_file.file_path)
                deleted_stats['disk_file_deleted'] = True
                logger.info(f"Deleted file from disk: {case_file.file_path}")
            except Exception as e:
                logger.error(f"Failed to delete file from disk {case_file.file_path}: {e}")
        
        # Log the deletion in audit log
        audit_entry = FileAuditLog(
            case_uuid=case_file.case_uuid,
            filename=case_file.filename,
            sha256_hash=case_file.sha256_hash,
            file_path=case_file.file_path,
            file_size=case_file.file_size,
            action='deleted_manual',
            performed_by=current_user.username,
            notes=f"Deleted via Case Files page. Events deleted: {deleted_stats['events_deleted']}, Child files: {deleted_stats['child_files_deleted']}"
        )
        db.session.add(audit_entry)
        
        # Delete the CaseFile record
        db.session.delete(case_file)
        db.session.commit()
        
        logger.info(f"User {current_user.username} deleted file {file_id} ({case_file.filename}) from case {case_file.case_uuid}")
        
        return jsonify({
            'success': True,
            'message': f'File "{case_file.filename}" deleted successfully',
            **deleted_stats
        })
        
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error deleting file {file_id}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================
# Hunting API Endpoints
# ============================================

@api_bp.route('/hunting/events/<int:case_id>')
@login_required
def get_hunting_events(case_id):
    """Get paginated events for hunting page"""
    try:
        from utils.clickhouse import get_client
        from utils.timezone import format_for_display
        
        # Verify case exists
        case = Case.query.get(case_id)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Get case timezone for display conversion
        case_tz = case.timezone or 'UTC'
        
        # Pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        search = request.args.get('search', '', type=str).strip()
        artifact_types = request.args.get('types', '', type=str).strip()
        alert_mode = request.args.get('alert_mode', 'all', type=str).strip()
        sigma_filter_param = request.args.get('sigma_filter', '', type=str).strip()
        ioc_filter_param = request.args.get('ioc_filter', '', type=str).strip()
        analyst_filter_param = request.args.get('analyst_filter', '', type=str).strip()
        severity_levels_param = request.args.get('severity_levels', '', type=str).strip()
        show_noise = request.args.get('show_noise', 'false', type=str).strip().lower() == 'true'
        
        # Time range filter parameters
        time_range = request.args.get('time_range', 'none', type=str).strip()
        time_start = request.args.get('time_start', '', type=str).strip()
        time_end = request.args.get('time_end', '', type=str).strip()
        
        # Limit per_page to reasonable values
        per_page = min(max(per_page, 10), 500)
        offset = (page - 1) * per_page
        
        client = get_client()
        
        # Build artifact type filter
        type_filter = ""
        if artifact_types:
            # Split comma-separated types and build IN clause
            types_list = [t.strip() for t in artifact_types.split(',') if t.strip()]
            if types_list:
                # Use tuple format for ClickHouse IN clause
                quoted_types = "', '".join(types_list)
                type_filter = f" AND artifact_type IN ('{quoted_types}')"
        
        # Build alert type filters based on mode
        # 'all' mode: show all events, unchecking a type hides those events (AND logic - exclusion)
        # 'only' mode: show only events matching ANY checked type (OR logic - inclusion)
        sigma_filter = ""
        ioc_filter = ""
        analyst_filter = ""
        alert_type_filter = ""
        
        if alert_mode == 'only':
            # "Only These" mode - build OR condition for checked types
            # Events must match AT LEAST ONE of the checked alert types
            or_conditions = []
            
            if sigma_filter_param == 'only':
                or_conditions.append("(rule_level IS NOT NULL AND rule_level != '')")
            
            if ioc_filter_param == 'only':
                or_conditions.append("(length(ioc_types) > 0)")
            
            if analyst_filter_param == 'only':
                or_conditions.append("(analyst_tagged = true)")
            
            if or_conditions:
                # Show events matching ANY of the checked types
                alert_type_filter = f" AND ({' OR '.join(or_conditions)})"
            else:
                # No types checked in "Only These" mode - show nothing (impossible condition)
                alert_type_filter = " AND 1=0"
        else:
            # "All Events" mode - use AND logic to exclude unchecked types
            if sigma_filter_param == 'exclude':
                sigma_filter = " AND (rule_level IS NULL OR rule_level = '')"
            
            if ioc_filter_param == 'exclude':
                ioc_filter = " AND length(ioc_types) = 0"
            
            if analyst_filter_param == 'exclude':
                analyst_filter = " AND analyst_tagged = false"
        
        # Build severity level filter
        # This filters which SIGMA severity levels to show/hide
        severity_filter = ""
        if severity_levels_param:
            levels_list = [l.strip().lower() for l in severity_levels_param.split(',') if l.strip()]
            if levels_list:
                # Build filter: show events with no rule_level OR rule_level in the allowed list
                quoted_levels = "', '".join(levels_list)
                severity_filter = f" AND (rule_level IS NULL OR rule_level = '' OR lower(rule_level) IN ('{quoted_levels}'))"
        
        # Build noise filter - by default, exclude noise events unless show_noise is true
        noise_filter = ""
        if not show_noise:
            noise_filter = " AND (noise_matched = false OR noise_matched IS NULL)"
        
        # Build time range filter
        # Time values come in case timezone, need to convert to UTC for query
        # Preset ranges (1d, 3d, etc.) are relative to the MOST RECENT artifact, not today
        time_filter = ""
        if time_range and time_range != 'none':
            from utils.timezone import to_utc
            from datetime import timedelta
            
            if time_range in ('1d', '3d', '7d', '30d'):
                # Get the most recent timestamp for this case to use as reference
                # Use COALESCE to handle events where timestamp_utc might be NULL (pre-migration)
                max_ts_query = "SELECT max(COALESCE(timestamp_utc, timestamp)) FROM events WHERE case_id = {case_id:UInt32}"
                max_ts_result = client.query(max_ts_query, parameters={'case_id': case_id})
                max_timestamp = max_ts_result.result_rows[0][0] if max_ts_result.result_rows and max_ts_result.result_rows[0][0] else None
                
                if max_timestamp:
                    # Calculate range based on most recent artifact
                    days_map = {'1d': 1, '3d': 3, '7d': 7, '30d': 30}
                    days = days_map.get(time_range, 1)
                    start_utc = max_timestamp - timedelta(days=days)
                    # Use COALESCE to handle events where timestamp_utc might be NULL (pre-migration)
                    time_filter = f" AND COALESCE(timestamp_utc, timestamp) >= '{start_utc.strftime('%Y-%m-%d %H:%M:%S')}'"
            elif time_range == 'custom' and time_start and time_end:
                # Convert user's case timezone input to UTC
                try:
                    # Parse the datetime-local format (YYYY-MM-DDTHH:MM)
                    start_local = datetime.strptime(time_start, '%Y-%m-%dT%H:%M')
                    end_local = datetime.strptime(time_end, '%Y-%m-%dT%H:%M')
                    
                    # Convert from case timezone to UTC using to_utc
                    start_utc = to_utc(start_local, case_tz)
                    end_utc = to_utc(end_local, case_tz)
                    
                    # Use COALESCE to handle events where timestamp_utc might be NULL (pre-migration)
                    time_filter = f" AND COALESCE(timestamp_utc, timestamp) >= '{start_utc.strftime('%Y-%m-%d %H:%M:%S')}' AND COALESCE(timestamp_utc, timestamp) <= '{end_utc.strftime('%Y-%m-%d %H:%M:%S')}'"
                except (ValueError, Exception) as e:
                    logger.warning(f"Invalid time range format: {e}")
        
        # Build query with optional search and type filter
        # All columns to fetch for event details modal
        # Note: timestamp_utc is used for display (converted to case TZ), timestamp is kept for forensic integrity
        event_columns = """
            timestamp, timestamp_utc, artifact_type, source_file, source_path, source_host,
            event_id, channel, provider, record_id, level,
            username, domain, sid, logon_type,
            process_name, process_path, process_id, parent_process, parent_pid, command_line,
            target_path, file_hash_md5, file_hash_sha1, file_hash_sha256, file_size,
            src_ip, dst_ip, src_port, dst_port,
            reg_key, reg_value, reg_data,
            rule_title, rule_level, rule_file, mitre_tactics, mitre_tags,
            search_blob, extra_fields, raw_json, ioc_types, noise_matched,
            analyst_tagged, analyst_tags, analyst_notes
        """
        
        if search:
            # Advanced search parser with per-group exclusions
            # Syntax:
            #   term1 term2 = AND (both must match)
            #   term1|term2 = OR (either can match)
            #   -term or -"quoted term" = exclude
            #   (group) = group terms together
            #   (grp1)|(grp2) = OR between groups
            #   Exclusions inside () apply to that group only
            #   Exclusions outside () apply globally
            import re
            
            params = {
                'case_id': case_id,
                'limit': per_page,
                'offset': offset
            }
            
            # Pattern to find exclusions: -"quoted" or -unquoted
            exclude_pattern = re.compile(r'-"([^"]+)"|-([^\s|()]+)')
            
            def parse_field_value(field, value, param_prefix):
                """Parse a field:value pair and return SQL condition"""
                field_lower = field.lower()
                mapping = SEARCH_FIELD_MAP.get(field_lower)
                
                if mapping is None and field_lower in SEARCH_FIELD_MAP:
                    # Field maps to search_blob with original case preserved
                    # Search for "FieldName:value" pattern in search_blob
                    param_name = f'{param_prefix}_blob'
                    # Use the original field name with proper casing for common fields
                    field_cased = field  # Keep user's casing
                    params[param_name] = f'%{field_cased}:{value}%'
                    return f"search_blob ilike {{{param_name}:String}}"
                elif mapping:
                    column, match_type = mapping
                    param_name = f'{param_prefix}_fld'
                    
                    if match_type == 'eq':
                        params[param_name] = value
                        # Handle numeric columns
                        if column in ('logon_type', 'process_id', 'parent_pid', 'record_id', 
                                      'src_port', 'dst_port', 'file_size'):
                            return f"{column} = {{{param_name}:String}}"
                        elif column in ('src_ip', 'dst_ip'):
                            return f"toString({column}) = {{{param_name}:String}}"
                        else:
                            return f"{column} = {{{param_name}:String}}"
                    else:  # like
                        params[param_name] = f'%{value}%'
                        return f"{column} ilike {{{param_name}:String}}"
                else:
                    # Unknown field - search in search_blob as "field:value"
                    param_name = f'{param_prefix}_blob'
                    params[param_name] = f'%{field}:{value}%'
                    return f"search_blob ilike {{{param_name}:String}}"
            
            def parse_term(term, prefix):
                """Parse a single term (may contain | for OR). Returns (conditions_list, is_exclusion)"""
                conditions = []
                
                # Check if this is an exclusion term
                if term.startswith('-'):
                    excl_match = exclude_pattern.match(term)
                    if excl_match:
                        excl_term = excl_match.group(1) or excl_match.group(2)
                        if excl_term:
                            # Check if exclusion term is field:value syntax
                            excl_fv_match = re.match(r'^([a-zA-Z_][a-zA-Z0-9_]*):(.+)$', excl_term)
                            if excl_fv_match and '://' not in excl_term:
                                # Parse as field:value and negate
                                cond = parse_field_value(excl_fv_match.group(1), excl_fv_match.group(2), f'{prefix}_excl')
                                if cond:
                                    return ([f"NOT ({cond})"], True)
                            else:
                                # Generic search_blob exclusion
                                param_name = f'{prefix}_excl'
                                params[param_name] = f'%{excl_term}%'
                                return ([f"NOT search_blob ilike {{{param_name}:String}}"], True)
                    return ([], False)
                
                # Check for field:value syntax (but not URLs with ://)
                field_value_match = re.match(r'^([a-zA-Z_][a-zA-Z0-9_]*):(.+)$', term)
                if field_value_match and '://' not in term:
                    field = field_value_match.group(1)
                    value = field_value_match.group(2)
                    
                    # Handle OR within value (field:val1|val2 or field:val1|field2:val2)
                    if '|' in value:
                        or_parts = [p.strip() for p in value.split('|') if p.strip()]
                        if or_parts:
                            or_conds = []
                            for k, part in enumerate(or_parts):
                                # Check if this part is itself a field:value pair
                                part_fv_match = re.match(r'^([a-zA-Z_][a-zA-Z0-9_]*):(.+)$', part)
                                if part_fv_match and '://' not in part:
                                    # Use this part's field and value
                                    cond = parse_field_value(part_fv_match.group(1), part_fv_match.group(2), f'{prefix}_or{k}')
                                else:
                                    # Use original field with this part as value
                                    cond = parse_field_value(field, part, f'{prefix}_or{k}')
                                if cond:
                                    or_conds.append(cond)
                            if or_conds:
                                conditions.append(f"({' OR '.join(or_conds)})")
                    else:
                        cond = parse_field_value(field, value, prefix)
                        if cond:
                            conditions.append(cond)
                    return (conditions, False)
                
                # Handle OR within term (pipe-separated, no spaces)
                if '|' in term:
                    or_parts = [p.strip() for p in term.split('|') if p.strip()]
                    if or_parts:
                        or_conds = []
                        for k, part in enumerate(or_parts):
                            or_param = f'{prefix}_or{k}'
                            # Check if part is field:value
                            fv_match = re.match(r'^([a-zA-Z_][a-zA-Z0-9_]*):(.+)$', part)
                            if fv_match and '://' not in part:
                                cond = parse_field_value(fv_match.group(1), fv_match.group(2), f'{prefix}_or{k}')
                                if cond:
                                    or_conds.append(cond)
                            elif part.isdigit():
                                params[or_param] = part
                                or_conds.append(f"event_id = {{{or_param}:String}}")
                            else:
                                params[or_param] = f'%{part}%'
                                or_conds.append(f"search_blob ilike {{{or_param}:String}}")
                        if or_conds:
                            conditions.append(f"({' OR '.join(or_conds)})")
                elif term.isdigit():
                    param_name = f'{prefix}_id'
                    params[param_name] = term
                    conditions.append(f"event_id = {{{param_name}:String}}")
                else:
                    param_name = f'{prefix}_txt'
                    params[param_name] = f'%{term}%'
                    conditions.append(f"search_blob ilike {{{param_name}:String}}")
                
                return (conditions, False)
            
            def parse_group(group_str, prefix):
                """Parse a group string, returning (positive_conditions, exclusion_conditions)"""
                positive_conds = []
                exclusion_conds = []
                
                # Tokenize: handle quoted strings and regular terms
                # Match: -"quoted", "quoted", -term, or term (including those with |)
                token_pattern = re.compile(r'-"[^"]+"|-[^\s|()]+|"[^"]+"|[^\s()]+')
                tokens = token_pattern.findall(group_str)
                
                for j, token in enumerate(tokens):
                    # Skip standalone pipes used as separators between groups
                    if token == '|':
                        continue
                    
                    # Remove surrounding quotes from quoted terms (non-exclusion)
                    if token.startswith('"') and token.endswith('"'):
                        token = token[1:-1]
                    
                    term_conds, is_exclusion = parse_term(token, f'{prefix}_{j}')
                    if is_exclusion:
                        exclusion_conds.extend(term_conds)
                    else:
                        positive_conds.extend(term_conds)
                
                return (positive_conds, exclusion_conds)
            
            def build_group_sql(positive_conds, exclusion_conds):
                """Combine positive and exclusion conditions for a group"""
                all_conds = positive_conds + exclusion_conds
                if all_conds:
                    return f"({' AND '.join(all_conds)})"
                return None
            
            # Find parenthesized groups and content outside them
            # Pattern matches: (content) or bare content between groups
            paren_pattern = re.compile(r'\(([^)]+)\)')
            paren_groups = paren_pattern.findall(search)
            
            # Get content outside parentheses (global terms/exclusions)
            outside_content = paren_pattern.sub(' ', search).strip()
            
            # Parse global terms (outside all parentheses)
            global_positive = []
            global_exclusions = []
            if outside_content:
                # Remove stray pipes that were between groups
                outside_clean = re.sub(r'\s*\|\s*', ' ', outside_content).strip()
                if outside_clean:
                    gp, ge = parse_group(outside_clean, 'global')
                    global_positive = gp
                    global_exclusions = ge
            
            search_conditions = []
            
            if paren_groups:
                # We have parenthesized groups
                # Check if there are | between groups or between group and term (OR relationship)
                # Patterns: (grp)|(grp), (grp)|term, term|(grp)
                has_group_or = bool(re.search(r'\)\s*\|\s*\(', search))  # (grp)|(grp)
                has_mixed_or = bool(re.search(r'\)\s*\|(?!\s*\()', search)) or bool(re.search(r'(?<!\))\|\s*\(', search))  # (grp)|term or term|(grp)
                
                group_sqls = []
                for i, group_content in enumerate(paren_groups):
                    pos_conds, excl_conds = parse_group(group_content.strip(), f'g{i}')
                    group_sql = build_group_sql(pos_conds, excl_conds)
                    if group_sql:
                        group_sqls.append(group_sql)
                
                if has_mixed_or:
                    # Mixed OR: (group)|term or term|(group)
                    # Parse the terms connected by | outside parens and include in OR clause
                    # Extract OR-connected parts from outside content (before pipe cleanup)
                    or_terms_outside = []
                    if outside_content:
                        # Split by | but keep non-empty parts
                        outside_parts = [p.strip() for p in outside_content.split('|') if p.strip()]
                        for k, part in enumerate(outside_parts):
                            # Skip exclusions - they stay global
                            if part.startswith('-'):
                                continue
                            pos_conds, _ = parse_group(part, f'mixed_or_{k}')
                            for cond in pos_conds:
                                or_terms_outside.append(cond)
                    
                    # Combine group sqls with OR-connected outside terms
                    all_or_parts = group_sqls + or_terms_outside
                    if all_or_parts:
                        search_conditions.append(f"({' OR '.join(all_or_parts)})")
                    
                    # Only add exclusions from global (they apply to everything)
                    search_conditions.extend(global_exclusions)
                elif group_sqls:
                    if has_group_or or len(group_sqls) > 1:
                        # Multiple groups with OR between them
                        search_conditions.append(f"({' OR '.join(group_sqls)})")
                    else:
                        # Single group, just add its conditions
                        search_conditions.append(group_sqls[0])
                    
                    # Add global positive conditions (terms outside parens that aren't exclusions)
                    search_conditions.extend(global_positive)
                    # Add global exclusions
                    search_conditions.extend(global_exclusions)
            else:
                # No parenthesized groups - simple search
                pos_conds, excl_conds = parse_group(search, 'simple')
                search_conditions.extend(pos_conds)
                search_conditions.extend(excl_conds)
            
            # Combine conditions
            if search_conditions:
                search_filter = " AND ".join(search_conditions)
                search_clause = f" AND {search_filter}"
            else:
                search_clause = ""
            
            count_query = f"""
                SELECT count() FROM events 
                WHERE case_id = {{case_id:UInt32}}{search_clause}{type_filter}{alert_type_filter}{sigma_filter}{ioc_filter}{analyst_filter}{severity_filter}{noise_filter}{time_filter}
            """
            data_query = f"""
                SELECT {event_columns}
                FROM events 
                WHERE case_id = {{case_id:UInt32}}{search_clause}{type_filter}{alert_type_filter}{sigma_filter}{ioc_filter}{analyst_filter}{severity_filter}{noise_filter}{time_filter}
                ORDER BY timestamp DESC
                LIMIT {{limit:UInt32}} OFFSET {{offset:UInt32}}
            """
        else:
            count_query = f"SELECT count() FROM events WHERE case_id = {{case_id:UInt32}}{type_filter}{alert_type_filter}{sigma_filter}{ioc_filter}{analyst_filter}{severity_filter}{noise_filter}{time_filter}"
            data_query = f"""
                SELECT {event_columns}
                FROM events 
                WHERE case_id = {{case_id:UInt32}}{type_filter}{alert_type_filter}{sigma_filter}{ioc_filter}{analyst_filter}{severity_filter}{noise_filter}{time_filter}
                ORDER BY timestamp DESC
                LIMIT {{limit:UInt32}} OFFSET {{offset:UInt32}}
            """
            params = {
                'case_id': case_id,
                'limit': per_page,
                'offset': offset
            }
        
        # Get total count
        count_result = client.query(count_query, parameters=params)
        total = count_result.result_rows[0][0] if count_result.result_rows else 0
        
        # Get events
        data_result = client.query(data_query, parameters=params)
        
        events = []
        for row in data_result.result_rows:
            (timestamp, timestamp_utc, artifact_type, source_file, source_path, source_host,
             event_id, channel, provider, record_id, level,
             username, domain, sid, logon_type,
             process_name, process_path, process_id, parent_process, parent_pid, command_line,
             target_path, file_hash_md5, file_hash_sha1, file_hash_sha256, file_size,
             src_ip, dst_ip, src_port, dst_port,
             reg_key, reg_value, reg_data,
             rule_title, rule_level, rule_file, mitre_tactics, mitre_tags,
             search_blob, extra_fields, raw_json, ioc_types, noise_matched,
             analyst_tagged, analyst_tags, analyst_notes) = row
            
            # Build description from available fields
            description = build_event_description(
                artifact_type, channel, provider, username, 
                process_name, command_line, target_path, search_blob
            )
            
            # Use timestamp_utc for display (converted to case TZ), fall back to timestamp
            display_ts = timestamp_utc if timestamp_utc else timestamp
            
            events.append({
                # Display fields (for table) - convert UTC to case timezone
                'timestamp': format_for_display(display_ts, case_tz) if display_ts else '-',
                # Raw UTC timestamp for lookups (ISO format) - used by raw event fetch
                'timestamp_utc_raw': display_ts.strftime('%Y-%m-%d %H:%M:%S') if display_ts else '',
                'artifact_type': artifact_type or '-',
                'source_host': source_host or '-',
                'description': description,
                'rule_level': rule_level or '',
                
                # Full details (for modal)
                'source_file': source_file or '',
                'source_path': source_path or '',
                'event_id': event_id or '',
                'channel': channel or '',
                'provider': provider or '',
                'record_id': record_id,
                'level': level or '',
                'username': username or '',
                'domain': domain or '',
                'sid': sid or '',
                'logon_type': logon_type,
                'process_name': process_name or '',
                'process_path': process_path or '',
                'process_id': process_id,
                'parent_process': parent_process or '',
                'parent_pid': parent_pid,
                'command_line': command_line or '',
                'target_path': target_path or '',
                'file_hash_md5': file_hash_md5 or '',
                'file_hash_sha1': file_hash_sha1 or '',
                'file_hash_sha256': file_hash_sha256 or '',
                'file_size': file_size,
                'src_ip': str(src_ip) if src_ip else '',
                'dst_ip': str(dst_ip) if dst_ip else '',
                'src_port': src_port,
                'dst_port': dst_port,
                'reg_key': reg_key or '',
                'reg_value': reg_value or '',
                'reg_data': reg_data or '',
                'rule_title': rule_title or '',
                'rule_file': rule_file or '',
                'mitre_tactics': list(mitre_tactics) if mitre_tactics else [],
                'mitre_tags': list(mitre_tags) if mitre_tags else [],
                'search_blob': search_blob or '',
                'extra_fields': extra_fields or '{}',
                'raw_json': raw_json or '',
                'ioc_types': list(ioc_types) if ioc_types else [],
                'noise_matched': bool(noise_matched) if noise_matched else False,
                'analyst_tagged': bool(analyst_tagged) if analyst_tagged else False,
                'analyst_tags': list(analyst_tags) if analyst_tags else [],
                'analyst_notes': analyst_notes or ''
            })
        
        total_pages = (total + per_page - 1) // per_page if total > 0 else 1
        
        return jsonify({
            'success': True,
            'case_id': case_id,
            'events': events,
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': total_pages
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


def build_event_description(artifact_type, channel, provider, username, process_name, command_line, target_path, search_blob):
    """Build a human-readable description for an event"""
    parts = []
    
    # Add channel/provider for EVTX
    if artifact_type == 'evtx':
        if channel:
            parts.append(f"[{channel}]")
        if provider:
            parts.append(provider)
    
    # Add username if present
    if username and username != '-':
        parts.append(f"User: {username}")
    
    # Add process info if present
    if process_name and process_name != '-':
        parts.append(f"Process: {process_name}")
    
    # Add command line (truncated) if present
    if command_line and command_line != '-':
        cmd = command_line[:100] + '...' if len(command_line) > 100 else command_line
        parts.append(cmd)
    
    # Add target path if present and no command line
    if target_path and target_path != '-' and not command_line:
        parts.append(target_path)
    
    # If still empty, use first part of search_blob
    if not parts and search_blob:
        blob_preview = search_blob[:150] + '...' if len(search_blob) > 150 else search_blob
        return blob_preview
    
    return ' | '.join(parts) if parts else '-'


@api_bp.route('/hunting/event/raw/<int:case_id>')
@login_required
def get_raw_event_data(case_id):
    """Get full raw data for a specific event from ClickHouse"""
    try:
        from utils.clickhouse import get_client
        import json
        from datetime import datetime, timedelta, timezone
        
        # Verify case exists
        case = Case.query.get(case_id)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Get event identifiers from query params
        timestamp = request.args.get('timestamp', '', type=str).strip()
        source_host = request.args.get('source_host', '', type=str).strip()
        record_id = request.args.get('record_id', '', type=str).strip()
        artifact_type = request.args.get('artifact_type', '', type=str).strip()
        event_id = request.args.get('event_id', '', type=str).strip()
        
        if not timestamp:
            return jsonify({'success': False, 'error': 'Timestamp is required'}), 400
        
        client = get_client()
        
        # Build query to fetch all columns for this specific event
        conditions = ["case_id = {case_id:UInt32}"]
        params = {'case_id': case_id}
        
        # Parse timestamp - use a 2-second window to handle sub-second precision
        # ClickHouse stores DateTime64 with microseconds, we only have seconds
        # Query against timestamp_utc (normalized UTC) since that's what frontend uses for display
        try:
            ts = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
            # Make timezone-aware (UTC) - the timestamp should be in UTC already
            ts = ts.replace(tzinfo=timezone.utc)
            ts_end = ts + timedelta(seconds=2)
            params['ts_start'] = ts
            params['ts_end'] = ts_end
            # Use COALESCE to handle events where timestamp_utc might be NULL (pre-migration)
            conditions.append("COALESCE(timestamp_utc, timestamp) >= {ts_start:DateTime64} AND COALESCE(timestamp_utc, timestamp) < {ts_end:DateTime64}")
        except ValueError:
            return jsonify({'success': False, 'error': 'Invalid timestamp format'}), 400
        
        if source_host and source_host != '-':
            params['source_host'] = source_host
            conditions.append("source_host = {source_host:String}")
        
        # record_id is the most reliable identifier if present and not 0
        if record_id and record_id != '0':
            try:
                rid = int(record_id)
                if rid > 0:
                    params['record_id'] = rid
                    conditions.append("record_id = {record_id:UInt64}")
            except (ValueError, TypeError):
                pass
        
        if artifact_type and artifact_type != '-':
            params['artifact_type'] = artifact_type
            conditions.append("artifact_type = {artifact_type:String}")
        
        # event_id can help narrow down the search
        if event_id and event_id != '-':
            params['event_id'] = event_id
            conditions.append("event_id = {event_id:String}")
        
        where_clause = " AND ".join(conditions)
        
        # Fetch all columns
        query = f"SELECT * FROM events WHERE {where_clause} LIMIT 1"
        
        # Debug logging
        import logging
        logging.info(f"Raw event query: {query}")
        logging.info(f"Raw event params: {params}")
        
        result = client.query(query, parameters=params)
        
        logging.info(f"Raw event result rows: {len(result.result_rows)}")
        
        if not result.result_rows:
            return jsonify({'success': False, 'error': 'Event not found'}), 404
        
        # Get column names and build a dict
        column_names = result.column_names
        row = result.result_rows[0]
        
        raw_data = {}
        for i, col_name in enumerate(column_names):
            value = row[i]
            
            # Convert special types to JSON-serializable format
            if value is None:
                raw_data[col_name] = None
            elif hasattr(value, 'isoformat'):
                # datetime objects
                raw_data[col_name] = value.isoformat()
            elif isinstance(value, (list, tuple)):
                # Convert list items that might be IP addresses
                raw_data[col_name] = [str(v) if hasattr(v, 'packed') else v for v in value]
            elif isinstance(value, bytes):
                raw_data[col_name] = value.decode('utf-8', errors='replace')
            elif hasattr(value, 'packed'):
                # IPv4Address/IPv6Address objects have a 'packed' attribute
                raw_data[col_name] = str(value)
            elif col_name == 'extra_fields' and value:
                # Parse extra_fields JSON if present
                try:
                    raw_data[col_name] = json.loads(value) if isinstance(value, str) else value
                except json.JSONDecodeError:
                    raw_data[col_name] = value
            else:
                raw_data[col_name] = value
        
        return jsonify({
            'success': True,
            'raw_data': raw_data
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================
# Analyst Tagging API Endpoints
# ============================================

@api_bp.route('/hunting/event/tag/<int:case_id>', methods=['POST'])
@login_required
def update_analyst_tag(case_id):
    """Update analyst tagging for a specific event in ClickHouse
    
    Request JSON:
        timestamp: Event timestamp (required)
        source_host: Source hostname
        record_id: Record ID for precise identification
        artifact_type: Artifact type
        analyst_tagged: Boolean - whether event is tagged
        analyst_tags: Array of tag strings (optional)
        analyst_notes: String notes (optional)
    """
    try:
        from utils.clickhouse import get_client
        from datetime import datetime, timedelta, timezone
        
        # Verify case exists
        case = Case.query.get(case_id)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        # Get identifiers from request
        event_id = data.get('event_id', '').strip() if data.get('event_id') else ''
        record_id = data.get('record_id', '')
        source_file = data.get('source_file', '').strip() if data.get('source_file') else ''
        timestamp = data.get('timestamp', '').strip()
        source_host = data.get('source_host', '').strip()
        artifact_type = data.get('artifact_type', '').strip()
        
        # Tag values
        analyst_tagged = data.get('analyst_tagged', False)
        analyst_tags = data.get('analyst_tags', [])
        analyst_notes = data.get('analyst_notes', '')
        
        # Build update conditions - case_id is always required
        conditions = ["case_id = {case_id:UInt32}"]
        params = {'case_id': case_id}
        
        # Use the most precise identifier available:
        # 1. event_id (UUID) - unique for Huntress/EDR events
        # 2. record_id + source_file - unique for EVTX events (record_id is per-file)
        # 3. Fall back to timestamp only if neither available
        
        has_unique_id = False
        
        # event_id is unique for Huntress/EDR events (UUID format)
        if event_id and event_id != '-':
            params['event_id'] = event_id
            conditions.append("event_id = {event_id:String}")
            has_unique_id = True
        
        # record_id + source_file + source_host is unique for EVTX events
        # (same filename like Security.evtx exists on multiple hosts)
        if record_id and str(record_id) != '0':
            try:
                rid = int(record_id)
                if rid > 0:
                    params['record_id'] = rid
                    conditions.append("record_id = {record_id:UInt64}")
                    # CRITICAL: Need source_file AND source_host - same filename exists on multiple hosts
                    if source_file and source_host and source_host != '-':
                        params['source_file'] = source_file
                        params['source_host'] = source_host
                        conditions.append("source_file = {source_file:String}")
                        conditions.append("source_host = {source_host:String}")
                        has_unique_id = True
            except (ValueError, TypeError):
                pass
        
        # Only use timestamp window if we don't have a unique ID
        if not has_unique_id:
            if not timestamp:
                return jsonify({'success': False, 'error': 'No unique identifier available'}), 400
            try:
                ts = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
                ts = ts.replace(tzinfo=timezone.utc)
                ts_end = ts + timedelta(seconds=2)
                params['ts_start'] = ts
                params['ts_end'] = ts_end
                # Use COALESCE to handle events where timestamp_utc might be NULL (pre-migration)
                conditions.append("COALESCE(timestamp_utc, timestamp) >= {ts_start:DateTime64} AND COALESCE(timestamp_utc, timestamp) < {ts_end:DateTime64}")
                
                # Need additional fields to narrow down when using timestamp
                if source_host and source_host != '-':
                    params['source_host'] = source_host
                    conditions.append("source_host = {source_host:String}")
                
                if artifact_type and artifact_type != '-':
                    params['artifact_type'] = artifact_type
                    conditions.append("artifact_type = {artifact_type:String}")
            except ValueError:
                return jsonify({'success': False, 'error': 'Invalid timestamp format'}), 400
        
        where_clause = " AND ".join(conditions)
        
        # Build update statement
        client = get_client()
        
        # Prepare tag values for ClickHouse
        tags_array = [str(t).strip() for t in analyst_tags if t and str(t).strip()]
        notes_value = str(analyst_notes).strip() if analyst_notes else None
        
        # Build SET clause
        set_parts = [f"analyst_tagged = {1 if analyst_tagged else 0}"]
        
        if tags_array:
            # Escape single quotes in tags
            escaped_tags = [t.replace("'", "\\'") for t in tags_array]
            tags_str = ", ".join([f"'{t}'" for t in escaped_tags])
            set_parts.append(f"analyst_tags = [{tags_str}]")
        else:
            set_parts.append("analyst_tags = []")
        
        if notes_value:
            escaped_notes = notes_value.replace("'", "\\'").replace("\\", "\\\\")
            set_parts.append(f"analyst_notes = '{escaped_notes}'")
        else:
            set_parts.append("analyst_notes = NULL")
        
        set_clause = ", ".join(set_parts)
        
        query = f"ALTER TABLE events UPDATE {set_clause} WHERE {where_clause}"
        
        logger.info(f"Analyst tag update query: {query}")
        logger.info(f"Analyst tag update params: {params}")
        
        client.query(query, parameters=params)
        
        return jsonify({
            'success': True,
            'message': 'Event tag updated successfully',
            'analyst_tagged': analyst_tagged,
            'analyst_tags': tags_array,
            'analyst_notes': notes_value
        })
        
    except Exception as e:
        logger.error(f"Error updating analyst tag: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/hunting/events/bulk-tag/<int:case_id>', methods=['POST'])
@login_required
def bulk_analyst_tag(case_id):
    """Bulk update analyst tagging for multiple events
    
    Request JSON:
        events: Array of event identifiers (each with timestamp, source_host, record_id, etc.)
        analyst_tagged: Boolean - whether events should be tagged
        analyst_tags: Array of tag strings (optional)
        analyst_notes: String notes (optional)
    """
    try:
        from utils.clickhouse import get_client
        from datetime import datetime, timedelta, timezone
        
        case = Case.query.get(case_id)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        data = request.get_json()
        if not data or 'events' not in data:
            return jsonify({'success': False, 'error': 'No events provided'}), 400
        
        events = data.get('events', [])
        analyst_tagged = data.get('analyst_tagged', True)
        analyst_tags = data.get('analyst_tags', [])
        analyst_notes = data.get('analyst_notes', '')
        
        if not events:
            return jsonify({'success': False, 'error': 'Empty events list'}), 400
        
        client = get_client()
        updated_count = 0
        
        # Prepare tag values
        tags_array = [str(t).strip() for t in analyst_tags if t and str(t).strip()]
        notes_value = str(analyst_notes).strip() if analyst_notes else None
        
        # Build SET clause
        set_parts = [f"analyst_tagged = {1 if analyst_tagged else 0}"]
        
        if tags_array:
            escaped_tags = [t.replace("'", "\\'") for t in tags_array]
            tags_str = ", ".join([f"'{t}'" for t in escaped_tags])
            set_parts.append(f"analyst_tags = [{tags_str}]")
        else:
            set_parts.append("analyst_tags = []")
        
        if notes_value:
            escaped_notes = notes_value.replace("'", "\\'").replace("\\", "\\\\")
            set_parts.append(f"analyst_notes = '{escaped_notes}'")
        else:
            set_parts.append("analyst_notes = NULL")
        
        set_clause = ", ".join(set_parts)
        
        # Process each event
        for event in events:
            event_id = event.get('event_id', '').strip() if event.get('event_id') else ''
            record_id = event.get('record_id', '')
            source_file = event.get('source_file', '').strip() if event.get('source_file') else ''
            source_host = event.get('source_host', '').strip() if event.get('source_host') else ''
            timestamp = event.get('timestamp', '').strip() if event.get('timestamp') else ''
            artifact_type = event.get('artifact_type', '').strip() if event.get('artifact_type') else ''
            
            conditions = ["case_id = {case_id:UInt32}"]
            params = {'case_id': case_id}
            
            has_unique_id = False
            
            # Use most precise identifier
            if event_id and event_id != '-':
                params['event_id'] = event_id
                conditions.append("event_id = {event_id:String}")
                has_unique_id = True
            
            if record_id and str(record_id) != '0':
                try:
                    rid = int(record_id)
                    if rid > 0:
                        params['record_id'] = rid
                        conditions.append("record_id = {record_id:UInt64}")
                        if source_file and source_host and source_host != '-':
                            params['source_file'] = source_file
                            params['source_host'] = source_host
                            conditions.append("source_file = {source_file:String}")
                            conditions.append("source_host = {source_host:String}")
                            has_unique_id = True
                except (ValueError, TypeError):
                    pass
            
            if not has_unique_id and timestamp:
                try:
                    ts = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
                    ts = ts.replace(tzinfo=timezone.utc)
                    ts_end = ts + timedelta(seconds=2)
                    params['ts_start'] = ts
                    params['ts_end'] = ts_end
                    conditions.append("COALESCE(timestamp_utc, timestamp) >= {ts_start:DateTime64} AND COALESCE(timestamp_utc, timestamp) < {ts_end:DateTime64}")
                    
                    if source_host and source_host != '-':
                        params['source_host'] = source_host
                        conditions.append("source_host = {source_host:String}")
                    
                    if artifact_type and artifact_type != '-':
                        params['artifact_type'] = artifact_type
                        conditions.append("artifact_type = {artifact_type:String}")
                except ValueError:
                    continue  # Skip invalid timestamps
            elif not has_unique_id:
                continue  # Skip events without identifiers
            
            where_clause = " AND ".join(conditions)
            query = f"ALTER TABLE events UPDATE {set_clause} WHERE {where_clause}"
            
            try:
                client.query(query, parameters=params)
                updated_count += 1
            except Exception as e:
                logger.warning(f"Failed to update event: {e}")
                continue
        
        return jsonify({
            'success': True,
            'updated': updated_count,
            'total': len(events),
            'message': f'Successfully tagged {updated_count} event(s)'
        })
        
    except Exception as e:
        logger.error(f"Error in bulk analyst tag: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/hunting/events/bulk-noise/<int:case_id>', methods=['POST'])
@login_required
def bulk_noise_tag(case_id):
    """Bulk mark events as noise
    
    Request JSON:
        events: Array of event identifiers (each with timestamp, source_host, record_id, etc.)
    """
    try:
        from utils.clickhouse import get_client
        from datetime import datetime, timedelta, timezone
        
        case = Case.query.get(case_id)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        data = request.get_json()
        if not data or 'events' not in data:
            return jsonify({'success': False, 'error': 'No events provided'}), 400
        
        events = data.get('events', [])
        
        if not events:
            return jsonify({'success': False, 'error': 'Empty events list'}), 400
        
        client = get_client()
        updated_count = 0
        
        # Process each event
        for event in events:
            event_id = event.get('event_id', '').strip() if event.get('event_id') else ''
            record_id = event.get('record_id', '')
            source_file = event.get('source_file', '').strip() if event.get('source_file') else ''
            source_host = event.get('source_host', '').strip() if event.get('source_host') else ''
            timestamp = event.get('timestamp', '').strip() if event.get('timestamp') else ''
            artifact_type = event.get('artifact_type', '').strip() if event.get('artifact_type') else ''
            
            conditions = ["case_id = {case_id:UInt32}"]
            params = {'case_id': case_id}
            
            has_unique_id = False
            
            # Use most precise identifier
            if event_id and event_id != '-':
                params['event_id'] = event_id
                conditions.append("event_id = {event_id:String}")
                has_unique_id = True
            
            if record_id and str(record_id) != '0':
                try:
                    rid = int(record_id)
                    if rid > 0:
                        params['record_id'] = rid
                        conditions.append("record_id = {record_id:UInt64}")
                        if source_file and source_host and source_host != '-':
                            params['source_file'] = source_file
                            params['source_host'] = source_host
                            conditions.append("source_file = {source_file:String}")
                            conditions.append("source_host = {source_host:String}")
                            has_unique_id = True
                except (ValueError, TypeError):
                    pass
            
            if not has_unique_id and timestamp:
                try:
                    ts = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
                    ts = ts.replace(tzinfo=timezone.utc)
                    ts_end = ts + timedelta(seconds=2)
                    params['ts_start'] = ts
                    params['ts_end'] = ts_end
                    conditions.append("COALESCE(timestamp_utc, timestamp) >= {ts_start:DateTime64} AND COALESCE(timestamp_utc, timestamp) < {ts_end:DateTime64}")
                    
                    if source_host and source_host != '-':
                        params['source_host'] = source_host
                        conditions.append("source_host = {source_host:String}")
                    
                    if artifact_type and artifact_type != '-':
                        params['artifact_type'] = artifact_type
                        conditions.append("artifact_type = {artifact_type:String}")
                except ValueError:
                    continue
            elif not has_unique_id:
                continue
            
            where_clause = " AND ".join(conditions)
            query = f"ALTER TABLE events UPDATE is_noise = 1 WHERE {where_clause}"
            
            try:
                client.query(query, parameters=params)
                updated_count += 1
            except Exception as e:
                logger.warning(f"Failed to mark event as noise: {e}")
                continue
        
        return jsonify({
            'success': True,
            'updated': updated_count,
            'total': len(events),
            'message': f'Successfully marked {updated_count} event(s) as noise'
        })
        
    except Exception as e:
        logger.error(f"Error in bulk noise tag: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/hunting/events/export-tagged/<int:case_id>')
@login_required
def export_tagged_events(case_id):
    """Export all analyst-tagged events with full data (no truncation)
    
    Returns JSON with all columns for tagged events.
    """
    try:
        from utils.clickhouse import get_client
        
        case = Case.query.get(case_id)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        client = get_client()
        
        # Get all tagged events with ALL columns
        query = """
            SELECT *
            FROM events
            WHERE case_id = {case_id:UInt32}
            AND analyst_tagged = true
            ORDER BY timestamp DESC
        """
        
        result = client.query(query, parameters={'case_id': case_id})
        
        events = []
        column_names = result.column_names
        
        for row in result.result_rows:
            event_data = {}
            for i, col_name in enumerate(column_names):
                value = row[i]
                
                # Convert special types to JSON-serializable format
                if value is None:
                    event_data[col_name] = None
                elif hasattr(value, 'isoformat'):
                    # datetime objects
                    event_data[col_name] = value.isoformat()
                elif isinstance(value, (list, tuple)):
                    # Convert list items that might be IP addresses
                    event_data[col_name] = [str(v) if hasattr(v, 'packed') else v for v in value]
                elif isinstance(value, bytes):
                    event_data[col_name] = value.decode('utf-8', errors='replace')
                elif hasattr(value, 'packed'):
                    # IPv4Address/IPv6Address objects
                    event_data[col_name] = str(value)
                elif col_name == 'raw_json' and value:
                    # Parse raw_json to include as object, not string
                    try:
                        event_data[col_name] = json.loads(value) if isinstance(value, str) else value
                    except json.JSONDecodeError:
                        event_data[col_name] = value
                elif col_name == 'extra_fields' and value:
                    # Parse extra_fields JSON
                    try:
                        event_data[col_name] = json.loads(value) if isinstance(value, str) else value
                    except json.JSONDecodeError:
                        event_data[col_name] = value
                else:
                    event_data[col_name] = value
            
            events.append(event_data)
        
        return jsonify({
            'success': True,
            'case_id': case_id,
            'case_name': case.name,
            'export_timestamp': datetime.utcnow().isoformat(),
            'total_count': len(events),
            'events': events
        })
        
    except Exception as e:
        logger.error(f"Error exporting tagged events: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/hunting/events/export-view/<int:case_id>')
@login_required
def export_view_events(case_id):
    """Export all events matching current view filters with full data (no truncation)
    
    Accepts the same filter parameters as get_hunting_events but exports ALL matching
    events (no pagination limit) with all fields intact.
    """
    try:
        from utils.clickhouse import get_client
        from utils.timezone import to_utc
        import re
        
        case = Case.query.get(case_id)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        case_tz = case.timezone or 'UTC'
        client = get_client()
        
        # Get all filter parameters (same as get_hunting_events)
        search = request.args.get('search', '', type=str).strip()
        artifact_types = request.args.get('types', '', type=str).strip()
        alert_mode = request.args.get('alert_mode', 'all', type=str).strip()
        sigma_filter_param = request.args.get('sigma_filter', '', type=str).strip()
        ioc_filter_param = request.args.get('ioc_filter', '', type=str).strip()
        analyst_filter_param = request.args.get('analyst_filter', '', type=str).strip()
        severity_levels_param = request.args.get('severity_levels', '', type=str).strip()
        show_noise = request.args.get('show_noise', 'false', type=str).strip().lower() == 'true'
        time_range = request.args.get('time_range', 'none', type=str).strip()
        time_start = request.args.get('time_start', '', type=str).strip()
        time_end = request.args.get('time_end', '', type=str).strip()
        
        # Build artifact type filter
        type_filter = ""
        if artifact_types:
            types_list = [t.strip() for t in artifact_types.split(',') if t.strip()]
            if types_list:
                quoted_types = "', '".join(types_list)
                type_filter = f" AND artifact_type IN ('{quoted_types}')"
        
        # Build alert type filters
        sigma_filter = ""
        ioc_filter = ""
        analyst_filter = ""
        alert_type_filter = ""
        
        if alert_mode == 'only':
            or_conditions = []
            if sigma_filter_param == 'only':
                or_conditions.append("(rule_level IS NOT NULL AND rule_level != '')")
            if ioc_filter_param == 'only':
                or_conditions.append("(length(ioc_types) > 0)")
            if analyst_filter_param == 'only':
                or_conditions.append("(analyst_tagged = true)")
            if or_conditions:
                alert_type_filter = f" AND ({' OR '.join(or_conditions)})"
            else:
                alert_type_filter = " AND 1=0"
        else:
            if sigma_filter_param == 'exclude':
                sigma_filter = " AND (rule_level IS NULL OR rule_level = '')"
            if ioc_filter_param == 'exclude':
                ioc_filter = " AND length(ioc_types) = 0"
            if analyst_filter_param == 'exclude':
                analyst_filter = " AND analyst_tagged = false"
        
        # Build severity level filter
        severity_filter = ""
        if severity_levels_param:
            levels_list = [l.strip().lower() for l in severity_levels_param.split(',') if l.strip()]
            if levels_list:
                quoted_levels = "', '".join(levels_list)
                severity_filter = f" AND (rule_level IS NULL OR rule_level = '' OR lower(rule_level) IN ('{quoted_levels}'))"
        
        # Build noise filter
        noise_filter = ""
        if not show_noise:
            noise_filter = " AND (noise_matched = false OR noise_matched IS NULL)"
        
        # Build time range filter
        time_filter = ""
        if time_range and time_range != 'none':
            from datetime import timedelta
            
            if time_range in ('1d', '3d', '7d', '30d'):
                # Use COALESCE to handle events where timestamp_utc might be NULL (pre-migration)
                max_ts_query = "SELECT max(COALESCE(timestamp_utc, timestamp)) FROM events WHERE case_id = {case_id:UInt32}"
                max_ts_result = client.query(max_ts_query, parameters={'case_id': case_id})
                max_timestamp = max_ts_result.result_rows[0][0] if max_ts_result.result_rows and max_ts_result.result_rows[0][0] else None
                
                if max_timestamp:
                    days_map = {'1d': 1, '3d': 3, '7d': 7, '30d': 30}
                    days = days_map.get(time_range, 1)
                    start_utc = max_timestamp - timedelta(days=days)
                    time_filter = f" AND COALESCE(timestamp_utc, timestamp) >= '{start_utc.strftime('%Y-%m-%d %H:%M:%S')}'"
            elif time_range == 'custom' and time_start and time_end:
                try:
                    start_local = datetime.strptime(time_start, '%Y-%m-%dT%H:%M')
                    end_local = datetime.strptime(time_end, '%Y-%m-%dT%H:%M')
                    start_utc = to_utc(start_local, case_tz)
                    end_utc = to_utc(end_local, case_tz)
                    # Use COALESCE to handle events where timestamp_utc might be NULL (pre-migration)
                    time_filter = f" AND COALESCE(timestamp_utc, timestamp) >= '{start_utc.strftime('%Y-%m-%d %H:%M:%S')}' AND COALESCE(timestamp_utc, timestamp) <= '{end_utc.strftime('%Y-%m-%d %H:%M:%S')}'"
                except (ValueError, Exception) as e:
                    logger.warning(f"Invalid time range format: {e}")
        
        params = {'case_id': case_id}
        
        # Build search filter (same logic as get_hunting_events)
        search_clause = ""
        if search:
            exclude_pattern = re.compile(r'-"([^"]+)"|-([^\s|()]+)')
            
            def parse_field_value(field, value, param_prefix):
                """Parse a field:value pair and return SQL condition"""
                field_lower = field.lower()
                mapping = SEARCH_FIELD_MAP.get(field_lower)
                
                if mapping is None and field_lower in SEARCH_FIELD_MAP:
                    param_name = f'{param_prefix}_blob'
                    field_cased = field
                    params[param_name] = f'%{field_cased}:{value}%'
                    return f"search_blob ilike {{{param_name}:String}}"
                elif mapping:
                    column, match_type = mapping
                    param_name = f'{param_prefix}_fld'
                    
                    if match_type == 'eq':
                        params[param_name] = value
                        if column in ('logon_type', 'process_id', 'parent_pid', 'record_id', 
                                      'src_port', 'dst_port', 'file_size'):
                            return f"{column} = {{{param_name}:String}}"
                        elif column in ('src_ip', 'dst_ip'):
                            return f"toString({column}) = {{{param_name}:String}}"
                        else:
                            return f"{column} = {{{param_name}:String}}"
                    else:
                        params[param_name] = f'%{value}%'
                        return f"{column} ilike {{{param_name}:String}}"
                else:
                    param_name = f'{param_prefix}_blob'
                    params[param_name] = f'%{field}:{value}%'
                    return f"search_blob ilike {{{param_name}:String}}"
            
            def parse_term(term, prefix):
                conditions = []
                if term.startswith('-'):
                    excl_match = exclude_pattern.match(term)
                    if excl_match:
                        excl_term = excl_match.group(1) or excl_match.group(2)
                        if excl_term:
                            param_name = f'{prefix}_excl'
                            params[param_name] = f'%{excl_term}%'
                            return ([f"NOT search_blob ilike {{{param_name}:String}}"], True)
                    return ([], False)
                
                # Check for field:value syntax (but not URLs with ://)
                field_value_match = re.match(r'^([a-zA-Z_][a-zA-Z0-9_]*):(.+)$', term)
                if field_value_match and '://' not in term:
                    field = field_value_match.group(1)
                    value = field_value_match.group(2)
                    
                    if '|' in value:
                        or_parts = [p.strip() for p in value.split('|') if p.strip()]
                        if or_parts:
                            or_conds = []
                            for k, part in enumerate(or_parts):
                                cond = parse_field_value(field, part, f'{prefix}_or{k}')
                                if cond:
                                    or_conds.append(cond)
                            if or_conds:
                                conditions.append(f"({' OR '.join(or_conds)})")
                    else:
                        cond = parse_field_value(field, value, prefix)
                        if cond:
                            conditions.append(cond)
                    return (conditions, False)
                
                if '|' in term:
                    or_parts = [p.strip() for p in term.split('|') if p.strip()]
                    if or_parts:
                        or_conds = []
                        for k, part in enumerate(or_parts):
                            or_param = f'{prefix}_or{k}'
                            fv_match = re.match(r'^([a-zA-Z_][a-zA-Z0-9_]*):(.+)$', part)
                            if fv_match and '://' not in part:
                                cond = parse_field_value(fv_match.group(1), fv_match.group(2), f'{prefix}_or{k}')
                                if cond:
                                    or_conds.append(cond)
                            elif part.isdigit():
                                params[or_param] = part
                                or_conds.append(f"event_id = {{{or_param}:String}}")
                            else:
                                params[or_param] = f'%{part}%'
                                or_conds.append(f"search_blob ilike {{{or_param}:String}}")
                        if or_conds:
                            conditions.append(f"({' OR '.join(or_conds)})")
                elif term.isdigit():
                    param_name = f'{prefix}_id'
                    params[param_name] = term
                    conditions.append(f"event_id = {{{param_name}:String}}")
                else:
                    param_name = f'{prefix}_txt'
                    params[param_name] = f'%{term}%'
                    conditions.append(f"search_blob ilike {{{param_name}:String}}")
                
                return (conditions, False)
            
            def parse_group(group_str, prefix):
                positive_conds = []
                exclusion_conds = []
                token_pattern = re.compile(r'-"[^"]+"|-[^\s|()]+|"[^"]+"|[^\s()]+')
                tokens = token_pattern.findall(group_str)
                
                for j, token in enumerate(tokens):
                    if token == '|':
                        continue
                    if token.startswith('"') and token.endswith('"'):
                        token = token[1:-1]
                    term_conds, is_exclusion = parse_term(token, f'{prefix}_{j}')
                    if is_exclusion:
                        exclusion_conds.extend(term_conds)
                    else:
                        positive_conds.extend(term_conds)
                
                return (positive_conds, exclusion_conds)
            
            def build_group_sql(positive_conds, exclusion_conds):
                all_conds = positive_conds + exclusion_conds
                if all_conds:
                    return f"({' AND '.join(all_conds)})"
                return None
            
            paren_pattern = re.compile(r'\(([^)]+)\)')
            paren_groups = paren_pattern.findall(search)
            outside_content = paren_pattern.sub(' ', search).strip()
            
            global_positive = []
            global_exclusions = []
            if outside_content:
                outside_clean = re.sub(r'\s*\|\s*', ' ', outside_content).strip()
                if outside_clean:
                    gp, ge = parse_group(outside_clean, 'global')
                    global_positive = gp
                    global_exclusions = ge
            
            search_conditions = []
            
            if paren_groups:
                has_group_or = bool(re.search(r'\)\s*\|\s*\(', search))
                group_sqls = []
                for i, group_content in enumerate(paren_groups):
                    pos_conds, excl_conds = parse_group(group_content.strip(), f'g{i}')
                    group_sql = build_group_sql(pos_conds, excl_conds)
                    if group_sql:
                        group_sqls.append(group_sql)
                
                if group_sqls:
                    if has_group_or or len(group_sqls) > 1:
                        search_conditions.append(f"({' OR '.join(group_sqls)})")
                    else:
                        search_conditions.append(group_sqls[0])
                
                search_conditions.extend(global_positive)
                search_conditions.extend(global_exclusions)
            else:
                pos_conds, excl_conds = parse_group(search, 'simple')
                search_conditions.extend(pos_conds)
                search_conditions.extend(excl_conds)
            
            if search_conditions:
                search_filter = " AND ".join(search_conditions)
                search_clause = f" AND {search_filter}"
        
        # Query all matching events with ALL columns
        query = f"""
            SELECT *
            FROM events
            WHERE case_id = {{case_id:UInt32}}{search_clause}{type_filter}{alert_type_filter}{sigma_filter}{ioc_filter}{analyst_filter}{severity_filter}{noise_filter}{time_filter}
            ORDER BY timestamp DESC
        """
        
        result = client.query(query, parameters=params)
        
        events = []
        column_names = result.column_names
        
        for row in result.result_rows:
            event_data = {}
            for i, col_name in enumerate(column_names):
                value = row[i]
                
                # Convert special types to JSON-serializable format
                if value is None:
                    event_data[col_name] = None
                elif hasattr(value, 'isoformat'):
                    event_data[col_name] = value.isoformat()
                elif isinstance(value, (list, tuple)):
                    event_data[col_name] = [str(v) if hasattr(v, 'packed') else v for v in value]
                elif isinstance(value, bytes):
                    event_data[col_name] = value.decode('utf-8', errors='replace')
                elif hasattr(value, 'packed'):
                    event_data[col_name] = str(value)
                elif col_name == 'raw_json' and value:
                    try:
                        event_data[col_name] = json.loads(value) if isinstance(value, str) else value
                    except json.JSONDecodeError:
                        event_data[col_name] = value
                elif col_name == 'extra_fields' and value:
                    try:
                        event_data[col_name] = json.loads(value) if isinstance(value, str) else value
                    except json.JSONDecodeError:
                        event_data[col_name] = value
                else:
                    event_data[col_name] = value
            
            events.append(event_data)
        
        return jsonify({
            'success': True,
            'case_id': case_id,
            'case_name': case.name,
            'export_timestamp': datetime.utcnow().isoformat(),
            'total_count': len(events),
            'events': events
        })
        
    except Exception as e:
        logger.error(f"Error exporting view events: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================
# Process Tree API Endpoints
# ============================================

@api_bp.route('/hunting/process/children/<int:case_id>')
@login_required
def get_process_children(case_id):
    """Get child processes of a given process
    
    Searches for events where parent_pid and parent_process match the given process.
    """
    try:
        from utils.clickhouse import get_client
        from utils.timezone import format_for_display
        
        case = Case.query.get(case_id)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Get case timezone for display conversion
        case_tz = case.timezone or 'UTC'
        
        hostname = request.args.get('host', '', type=str).strip()
        parent_pid = request.args.get('parent_pid', 0, type=int)
        parent_process = request.args.get('parent_process', '', type=str).strip()
        
        if not hostname or not parent_pid:
            return jsonify({'success': False, 'error': 'host and parent_pid are required'}), 400
        
        client = get_client()
        
        # Query for child processes - events where parent_pid matches
        query = """
            SELECT 
                COALESCE(timestamp_utc, timestamp) as ts,
                process_name,
                process_path,
                process_id,
                parent_process,
                parent_pid,
                command_line,
                username
            FROM events
            WHERE case_id = {case_id:UInt32}
            AND source_host = {hostname:String}
            AND parent_pid = {parent_pid:UInt64}
            AND process_name != ''
        """
        
        params = {
            'case_id': case_id,
            'hostname': hostname,
            'parent_pid': parent_pid
        }
        
        # Optionally filter by parent process name for more accuracy
        if parent_process:
            query += " AND parent_process = {parent_process:String}"
            params['parent_process'] = parent_process
        
        query += " ORDER BY timestamp ASC LIMIT 100"
        
        result = client.query(query, parameters=params)
        
        children = []
        for row in result.result_rows:
            ts, proc_name, proc_path, pid, par_proc, par_pid, cmdline, username = row
            
            # Check if this process has children (for tree expansion indicator)
            child_count_result = client.query(
                """SELECT count() FROM events 
                   WHERE case_id = {case_id:UInt32} 
                   AND source_host = {hostname:String}
                   AND parent_pid = {pid:UInt64}
                   AND process_name != ''
                   LIMIT 1""",
                parameters={'case_id': case_id, 'hostname': hostname, 'pid': pid or 0}
            )
            child_count = child_count_result.result_rows[0][0] if child_count_result.result_rows else 0
            
            children.append({
                'timestamp': format_for_display(ts, case_tz) if ts else '',
                'process_name': proc_name or '',
                'process_path': proc_path or '',
                'pid': pid,
                'parent_process': par_proc or '',
                'parent_pid': par_pid,
                'command_line': cmdline or '',
                'username': username or '',
                'child_count': child_count
            })
        
        return jsonify({
            'success': True,
            'children': children,
            'parent_pid': parent_pid,
            'parent_process': parent_process,
            'hostname': hostname
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/hunting/process/parent/<int:case_id>')
@login_required
def get_process_parent(case_id):
    """Get parent process and siblings
    
    Finds the parent process and all its children (siblings of the original process).
    """
    try:
        from utils.clickhouse import get_client
        from utils.timezone import format_for_display
        
        case = Case.query.get(case_id)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Get case timezone for display conversion
        case_tz = case.timezone or 'UTC'
        
        hostname = request.args.get('host', '', type=str).strip()
        pid = request.args.get('pid', 0, type=int)
        process_name = request.args.get('process_name', '', type=str).strip()
        
        if not hostname:
            return jsonify({'success': False, 'error': 'host is required'}), 400
        
        client = get_client()
        
        # First, find the parent process
        parent = None
        if pid:
            parent_query = """
                SELECT 
                    COALESCE(timestamp_utc, timestamp) as ts,
                    process_name,
                    process_path,
                    process_id,
                    parent_process,
                    parent_pid,
                    command_line,
                    username
                FROM events
                WHERE case_id = {case_id:UInt32}
                AND source_host = {hostname:String}
                AND process_id = {pid:UInt64}
                AND process_name != ''
                ORDER BY timestamp DESC
                LIMIT 1
            """
            
            result = client.query(parent_query, parameters={
                'case_id': case_id,
                'hostname': hostname,
                'pid': pid
            })
            
            if result.result_rows:
                row = result.result_rows[0]
                parent = {
                    'timestamp': format_for_display(row[0], case_tz) if row[0] else '',
                    'process_name': row[1] or '',
                    'process_path': row[2] or '',
                    'pid': row[3],
                    'parent_process': row[4] or '',
                    'parent_pid': row[5],
                    'command_line': row[6] or '',
                    'username': row[7] or ''
                }
        
        # Now find all children of this parent (siblings)
        siblings = []
        if parent and parent['pid']:
            siblings_query = """
                SELECT 
                    COALESCE(timestamp_utc, timestamp) as ts,
                    process_name,
                    process_path,
                    process_id,
                    parent_process,
                    parent_pid,
                    command_line,
                    username
                FROM events
                WHERE case_id = {case_id:UInt32}
                AND source_host = {hostname:String}
                AND parent_pid = {parent_pid:UInt64}
                AND process_name != ''
                ORDER BY timestamp ASC
                LIMIT 50
            """
            
            result = client.query(siblings_query, parameters={
                'case_id': case_id,
                'hostname': hostname,
                'parent_pid': parent['pid']
            })
            
            for row in result.result_rows:
                # Check if this sibling has children
                child_count_result = client.query(
                    """SELECT count() FROM events 
                       WHERE case_id = {case_id:UInt32} 
                       AND source_host = {hostname:String}
                       AND parent_pid = {pid:UInt64}
                       AND process_name != ''
                       LIMIT 1""",
                    parameters={'case_id': case_id, 'hostname': hostname, 'pid': row[3] or 0}
                )
                child_count = child_count_result.result_rows[0][0] if child_count_result.result_rows else 0
                
                siblings.append({
                    'timestamp': format_for_display(row[0], case_tz) if row[0] else '',
                    'process_name': row[1] or '',
                    'process_path': row[2] or '',
                    'pid': row[3],
                    'parent_process': row[4] or '',
                    'parent_pid': row[5],
                    'command_line': row[6] or '',
                    'username': row[7] or '',
                    'child_count': child_count
                })
        
        return jsonify({
            'success': True,
            'parent': parent,
            'siblings': siblings,
            'hostname': hostname
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================
# Known Systems API Endpoints
# ============================================

@api_bp.route('/known-systems/list/<case_uuid>')
@login_required
def get_known_systems(case_uuid):
    """Get known systems for a case"""
    try:
        from utils.known_systems_discovery import get_systems_for_case
        
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        systems = get_systems_for_case(case.id)
        
        # Aggregate all unique sources across all systems
        all_sources = set()
        for system in systems:
            sources = system.get('sources', [])
            if sources:
                all_sources.update(sources)
        
        return jsonify({
            'success': True,
            'case_uuid': case_uuid,
            'systems': systems,
            'total': len(systems),
            'aggregate_sources': sorted(list(all_sources))
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/known-systems/discover/<case_uuid>', methods=['POST'])
@login_required
def discover_systems(case_uuid):
    """Start async discovery of known systems from artifacts"""
    try:
        from tasks.celery_tasks import discover_known_systems_task
        
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Check if discovery is already running
        from utils.known_systems_discovery import get_discovery_progress
        progress = get_discovery_progress(case_uuid)
        if progress and progress.get('status') == 'running':
            return jsonify({
                'success': True,
                'status': 'already_running',
                'progress': progress
            })
        
        # Start async discovery task
        task = discover_known_systems_task.delay(
            case_id=case.id,
            case_uuid=case_uuid,
            username=current_user.username
        )
        
        return jsonify({
            'success': True,
            'status': 'started',
            'task_id': task.id
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/known-systems/discover-progress/<case_uuid>')
@login_required
def get_discovery_status(case_uuid):
    """Get discovery progress for a case"""
    try:
        from utils.known_systems_discovery import get_discovery_progress
        
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        progress = get_discovery_progress(case_uuid)
        
        return jsonify({
            'success': True,
            'progress': progress
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/known-systems/<int:system_id>')
@login_required
def get_known_system(system_id):
    """Get details for a specific known system"""
    try:
        from models.known_system import KnownSystem
        
        system = KnownSystem.query.get(system_id)
        if not system:
            return jsonify({'success': False, 'error': 'System not found'}), 404
        
        return jsonify({
            'success': True,
            'system': system.to_dict()
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/known-systems/<int:system_id>/update', methods=['POST'])
@login_required
def update_known_system(system_id):
    """Update a known system field"""
    try:
        from utils.known_systems_discovery import update_system_field
        from models.known_system import KnownSystem, OSType, SystemType
        
        data = request.get_json()
        field_name = data.get('field')
        new_value = data.get('value')
        
        if not field_name:
            return jsonify({'success': False, 'error': 'Field name required'}), 400
        
        # Validate enum values
        if field_name == 'os_type' and new_value and new_value not in OSType.all():
            return jsonify({'success': False, 'error': f'Invalid os_type: {new_value}'}), 400
        
        if field_name == 'system_type' and new_value and new_value not in SystemType.all():
            return jsonify({'success': False, 'error': f'Invalid system_type: {new_value}'}), 400
        
        # Handle boolean for compromised
        if field_name == 'compromised':
            new_value = bool(new_value)
        
        success = update_system_field(
            system_id=system_id,
            field_name=field_name,
            new_value=new_value,
            username=current_user.username
        )
        
        if success:
            system = KnownSystem.query.get(system_id)
            return jsonify({
                'success': True,
                'system': system.to_dict()
            })
        else:
            return jsonify({'success': False, 'error': 'Update failed'}), 400
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/known-systems/<int:system_id>/add-ip', methods=['POST'])
@login_required
def add_system_ip(system_id):
    """Add an IP address to a known system"""
    try:
        from utils.known_systems_discovery import add_ip_to_system
        from models.known_system import KnownSystem
        
        data = request.get_json()
        ip_address = data.get('ip_address', '').strip()
        
        if not ip_address:
            return jsonify({'success': False, 'error': 'IP address required'}), 400
        
        success = add_ip_to_system(
            system_id=system_id,
            ip_address=ip_address,
            username=current_user.username
        )
        
        system = KnownSystem.query.get(system_id)
        return jsonify({
            'success': success,
            'system': system.to_dict() if system else None
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/known-systems/<int:system_id>/add-share', methods=['POST'])
@login_required
def add_system_share(system_id):
    """Add a share to a known system"""
    try:
        from utils.known_systems_discovery import add_share_to_system
        from models.known_system import KnownSystem
        
        data = request.get_json()
        share_name = data.get('share_name', '').strip()
        share_path = data.get('share_path', '').strip()
        
        if not share_name:
            return jsonify({'success': False, 'error': 'Share name required'}), 400
        
        success = add_share_to_system(
            system_id=system_id,
            share_name=share_name,
            share_path=share_path if share_path else None,
            username=current_user.username
        )
        
        system = KnownSystem.query.get(system_id)
        return jsonify({
            'success': success,
            'system': system.to_dict() if system else None
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/known-systems/<int:system_id>/audit')
@login_required
def get_system_audit(system_id):
    """Get audit history for a known system"""
    try:
        from utils.known_systems_discovery import get_system_audit_history
        from models.known_system import KnownSystem
        
        system = KnownSystem.query.get(system_id)
        if not system:
            return jsonify({'success': False, 'error': 'System not found'}), 404
        
        history = get_system_audit_history(system_id)
        
        return jsonify({
            'success': True,
            'system_id': system_id,
            'hostname': system.hostname,
            'audit_history': history
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/known-systems/upload/<case_uuid>', methods=['POST'])
@login_required
def upload_known_systems_csv(case_uuid):
    """Upload a CSV file to import known systems"""
    import csv
    import io
    from flask_login import current_user
    from models.known_system import KnownSystem, KnownSystemAudit
    
    try:
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Check if file was uploaded
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        if not file.filename.lower().endswith('.csv'):
            return jsonify({'success': False, 'error': 'File must be a CSV'}), 400
        
        # Read and parse CSV
        content = file.read().decode('utf-8-sig')  # Handle BOM
        reader = csv.DictReader(io.StringIO(content))
        
        # Normalize header names (lowercase, strip whitespace)
        if reader.fieldnames:
            reader.fieldnames = [h.lower().strip() for h in reader.fieldnames]
        
        # Validate required columns
        if not reader.fieldnames or 'hostname' not in reader.fieldnames:
            return jsonify({'success': False, 'error': 'CSV must have a "hostname" column'}), 400
        
        created_count = 0
        updated_count = 0
        skipped_count = 0
        
        # Valid values for system_type and os_type
        valid_system_types = ['workstation', 'server', 'router', 'switch', 'printer', 'other']
        valid_os_types = ['windows', 'linux', 'mac', 'other']
        
        # Collect all rows first
        rows = list(reader)
        
        for row in rows:
            hostname = row.get('hostname', '').strip()
            if not hostname:
                continue
            
            # Extract NETBIOS name
            netbios_name, full_hostname = KnownSystem.extract_netbios_name(hostname)
            if not netbios_name:
                continue
            
            system_type = row.get('system_type', '').strip()
            os_type = row.get('os_type', '').strip()
            os_version = row.get('os_version', '').strip() or None
            notes = row.get('notes', '').strip() or None
            ip_addresses_str = row.get('ip_addresses', '').strip()
            
            # Validate and normalize system_type
            if system_type and system_type.lower() in valid_system_types:
                system_type = system_type.capitalize()
            else:
                system_type = None
            
            # Validate and normalize os_type
            if os_type and os_type.lower() in valid_os_types:
                os_type = os_type.capitalize()
            else:
                os_type = None
            
            # Parse compromised (handle various formats)
            compromised_str = row.get('compromised', '').strip().lower()
            compromised = compromised_str in ('true', 'yes', '1', 'y')
            
            # Parse IP addresses (semicolon-separated)
            ip_addresses = []
            if ip_addresses_str:
                ip_addresses = [ip.strip() for ip in ip_addresses_str.split(';') if ip.strip()]
            
            try:
                # Try to find existing system within this case
                existing_system, _ = KnownSystem.find_by_hostname_or_alias(netbios_name, case_id=case.id)
                
                if existing_system:
                    # Update existing system with new data
                    updated = False
                    
                    if system_type and existing_system.system_type != system_type:
                        existing_system.system_type = system_type
                        updated = True
                    
                    if os_type and existing_system.os_type != os_type:
                        existing_system.os_type = os_type
                        updated = True
                    
                    if os_version and existing_system.os_version != os_version:
                        existing_system.os_version = os_version
                        updated = True
                    
                    if notes and existing_system.notes != notes:
                        existing_system.notes = notes
                        updated = True
                    
                    # Only SET compromised to true - never unflag
                    if compromised and not existing_system.compromised:
                        existing_system.compromised = True
                        updated = True
                    
                    # Add IP addresses
                    for ip in ip_addresses:
                        existing_system.add_ip(ip)
                    
                    # Add full hostname as alias if different
                    if full_hostname and full_hostname != netbios_name:
                        existing_system.add_alias(full_hostname)
                    
                    # Link to case
                    existing_system.link_to_case(case.id)
                    existing_system.add_source('csv_import')
                    
                    if updated:
                        updated_count += 1
                        KnownSystemAudit.log_change(
                            existing_system.id,
                            current_user.username,
                            'csv_import',
                            'update',
                            None,
                            f'Updated from CSV upload'
                        )
                    
                    db.session.commit()
                else:
                    # Create new system with case_id
                    new_system = KnownSystem(
                        case_id=case.id,
                        hostname=netbios_name,
                        system_type=system_type,
                        os_type=os_type,
                        os_version=os_version,
                        notes=notes,
                        compromised=compromised,
                        sources=['csv_import']
                    )
                    db.session.add(new_system)
                    db.session.commit()
                    
                    # Add IP addresses
                    for ip in ip_addresses:
                        new_system.add_ip(ip)
                    
                    # Add full hostname as alias if different
                    if full_hostname and full_hostname != netbios_name:
                        new_system.add_alias(full_hostname)
                    
                    KnownSystemAudit.log_change(
                        new_system.id,
                        current_user.username,
                        'system',
                        'create',
                        None,
                        f'Created from CSV upload: {netbios_name}'
                    )
                    db.session.commit()
                    created_count += 1
                    
            except Exception as row_err:
                db.session.rollback()
                skipped_count += 1
                continue
        
        return jsonify({
            'success': True,
            'created': created_count,
            'updated': updated_count,
            'skipped': skipped_count
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/known-systems/download/<case_uuid>')
@login_required
def download_known_systems_csv(case_uuid):
    """Download all known systems for a case as CSV"""
    import csv
    import io
    from flask import Response
    from utils.known_systems_discovery import get_systems_for_case
    
    try:
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Get systems for this case
        systems = get_systems_for_case(case.id)
        
        # Create CSV in memory
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'hostname', 'system_type', 'os_type', 'os_version', 'compromised',
            'notes', 'ip_addresses', 'aliases', 'sources', 'artifacts_with_hostname', 'last_seen'
        ])
        
        # Write system rows
        for system in systems:
            ip_addresses = ';'.join(system.get('ip_addresses', []))
            aliases = ';'.join(system.get('aliases', []))
            sources = ';'.join(system.get('sources', []))
            
            writer.writerow([
                system.get('hostname', ''),
                system.get('system_type', ''),
                system.get('os_type', ''),
                system.get('os_version', ''),
                'true' if system.get('compromised') else 'false',
                system.get('notes', ''),
                ip_addresses,
                aliases,
                sources,
                system.get('artifacts_with_hostname', 0),
                system.get('last_seen', '')
            ])
        
        # Generate response
        output.seek(0)
        
        # Create filename with case name
        safe_name = ''.join(c for c in case.name if c.isalnum() or c in (' ', '-', '_')).strip()
        filename = f'known_systems_{safe_name}_{case_uuid[:8]}.csv'
        
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"'
            }
        )
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/known-systems/bulk-update', methods=['POST'])
@login_required
def bulk_update_known_systems():
    """Bulk update multiple known systems"""
    from flask_login import current_user
    from models.known_system import KnownSystem, KnownSystemAudit
    
    try:
        data = request.get_json()
        system_ids = data.get('system_ids', [])
        updates = data.get('updates', {})
        
        if not system_ids:
            return jsonify({'success': False, 'error': 'No system IDs provided'}), 400
        
        if not updates:
            return jsonify({'success': False, 'error': 'No updates provided'}), 400
        
        updated_count = 0
        
        for system_id in system_ids:
            system = KnownSystem.query.get(system_id)
            if not system:
                continue
            
            changed = False
            
            # Update system_type
            if 'system_type' in updates:
                old_value = system.system_type
                new_value = updates['system_type']
                if old_value != new_value:
                    system.system_type = new_value
                    KnownSystemAudit.log_change(
                        system_id=system.id,
                        changed_by=current_user.username,
                        field_name='system_type',
                        action='update',
                        old_value=old_value,
                        new_value=new_value
                    )
                    changed = True
            
            # Update os_type
            if 'os_type' in updates:
                old_value = system.os_type
                new_value = updates['os_type']
                if old_value != new_value:
                    system.os_type = new_value
                    KnownSystemAudit.log_change(
                        system_id=system.id,
                        changed_by=current_user.username,
                        field_name='os_type',
                        action='update',
                        old_value=old_value,
                        new_value=new_value
                    )
                    changed = True
            
            # Update compromised status
            if 'compromised' in updates:
                old_value = system.compromised
                new_value = updates['compromised']
                if old_value != new_value:
                    system.compromised = new_value
                    KnownSystemAudit.log_change(
                        system_id=system.id,
                        changed_by=current_user.username,
                        field_name='compromised',
                        action='update',
                        old_value=str(old_value),
                        new_value=str(new_value)
                    )
                    changed = True
            
            if changed:
                updated_count += 1
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'updated': updated_count
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/known-systems/bulk-delete', methods=['POST'])
@login_required
def bulk_delete_known_systems():
    """Bulk delete multiple known systems"""
    from flask_login import current_user
    from models.known_system import KnownSystem, KnownSystemAudit
    
    try:
        data = request.get_json()
        system_ids = data.get('system_ids', [])
        
        if not system_ids:
            return jsonify({'success': False, 'error': 'No system IDs provided'}), 400
        
        deleted_count = 0
        
        for system_id in system_ids:
            system = KnownSystem.query.get(system_id)
            if not system:
                continue
            
            # Log the deletion
            KnownSystemAudit.log_change(
                system_id=system.id,
                changed_by=current_user.username,
                field_name='system',
                action='delete',
                old_value=system.hostname,
                new_value=None
            )
            
            db.session.delete(system)
            deleted_count += 1
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'deleted': deleted_count
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================
# Known Users API Endpoints
# ============================================

@api_bp.route('/known-users/list/<case_uuid>')
@login_required
def get_known_users(case_uuid):
    """Get known users for a case"""
    try:
        from utils.known_users_discovery import get_users_for_case
        
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        users = get_users_for_case(case.id)
        
        # Aggregate all unique sources across all users
        all_sources = set()
        for user in users:
            sources = user.get('sources', [])
            if sources:
                all_sources.update(sources)
        
        return jsonify({
            'success': True,
            'case_uuid': case_uuid,
            'users': users,
            'total': len(users),
            'aggregate_sources': sorted(list(all_sources))
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/known-users/discover/<case_uuid>', methods=['POST'])
@login_required
def discover_users(case_uuid):
    """Start async discovery of known users from artifacts"""
    try:
        from tasks.celery_tasks import discover_known_users_task
        
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Check if discovery is already running
        from utils.known_users_discovery import get_user_discovery_progress
        progress = get_user_discovery_progress(case_uuid)
        if progress and progress.get('status') == 'running':
            return jsonify({
                'success': True,
                'status': 'already_running',
                'progress': progress
            })
        
        # Start async discovery task
        task = discover_known_users_task.delay(
            case_id=case.id,
            case_uuid=case_uuid,
            username=current_user.username
        )
        
        return jsonify({
            'success': True,
            'status': 'started',
            'task_id': task.id
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/known-users/discover-progress/<case_uuid>')
@login_required
def get_user_discovery_status(case_uuid):
    """Get discovery progress for users in a case"""
    try:
        from utils.known_users_discovery import get_user_discovery_progress
        
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        progress = get_user_discovery_progress(case_uuid)
        
        return jsonify({
            'success': True,
            'progress': progress
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/known-users/<int:user_id>')
@login_required
def get_known_user(user_id):
    """Get details for a specific known user"""
    try:
        from models.known_user import KnownUser
        
        user = KnownUser.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        return jsonify({
            'success': True,
            'user': user.to_dict()
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/known-users/<int:user_id>/update', methods=['POST'])
@login_required
def update_known_user(user_id):
    """Update a known user field"""
    try:
        from utils.known_users_discovery import update_user_field
        from models.known_user import KnownUser
        
        data = request.get_json()
        field_name = data.get('field')
        new_value = data.get('value')
        
        if not field_name:
            return jsonify({'success': False, 'error': 'Field name required'}), 400
        
        # Handle boolean for compromised
        if field_name == 'compromised':
            new_value = bool(new_value)
        
        success = update_user_field(
            user_id=user_id,
            field_name=field_name,
            new_value=new_value,
            changed_by=current_user.username
        )
        
        if success:
            user = KnownUser.query.get(user_id)
            return jsonify({
                'success': True,
                'user': user.to_dict()
            })
        else:
            return jsonify({'success': False, 'error': 'Update failed'}), 400
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/known-users/<int:user_id>/add-alias', methods=['POST'])
@login_required
def add_user_alias(user_id):
    """Add an alias to a known user"""
    try:
        from utils.known_users_discovery import add_alias_to_user
        from models.known_user import KnownUser
        
        data = request.get_json()
        alias = data.get('alias', '').strip()
        
        if not alias:
            return jsonify({'success': False, 'error': 'Alias required'}), 400
        
        success = add_alias_to_user(
            user_id=user_id,
            alias=alias,
            changed_by=current_user.username
        )
        
        user = KnownUser.query.get(user_id)
        return jsonify({
            'success': success,
            'user': user.to_dict() if user else None
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/known-users/<int:user_id>/add-email', methods=['POST'])
@login_required
def add_user_email(user_id):
    """Add an email to a known user"""
    try:
        from utils.known_users_discovery import add_email_to_user
        from models.known_user import KnownUser
        
        data = request.get_json()
        email = data.get('email', '').strip()
        
        if not email:
            return jsonify({'success': False, 'error': 'Email required'}), 400
        
        success = add_email_to_user(
            user_id=user_id,
            email=email,
            changed_by=current_user.username
        )
        
        user = KnownUser.query.get(user_id)
        return jsonify({
            'success': success,
            'user': user.to_dict() if user else None
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/known-users/<int:user_id>/audit')
@login_required
def get_user_audit(user_id):
    """Get audit history for a known user"""
    try:
        from utils.known_users_discovery import get_user_audit_history
        from models.known_user import KnownUser
        
        user = KnownUser.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        history = get_user_audit_history(user_id)
        
        return jsonify({
            'success': True,
            'user_id': user_id,
            'username': user.username,
            'audit_history': history
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/known-users/upload/<case_uuid>', methods=['POST'])
@login_required
def upload_known_users_csv(case_uuid):
    """Upload a CSV file to import known users"""
    import csv
    import io
    from flask_login import current_user
    from models.known_user import KnownUser, KnownUserAudit
    
    try:
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Check if file was uploaded
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        if not file.filename.lower().endswith('.csv'):
            return jsonify({'success': False, 'error': 'File must be a CSV'}), 400
        
        # Read and parse CSV
        content = file.read().decode('utf-8-sig')  # Handle BOM
        reader = csv.DictReader(io.StringIO(content))
        
        # Normalize header names (lowercase, strip whitespace)
        if reader.fieldnames:
            reader.fieldnames = [h.lower().strip() for h in reader.fieldnames]
        
        # Validate required columns
        if not reader.fieldnames or 'username' not in reader.fieldnames:
            return jsonify({'success': False, 'error': 'CSV must have a "username" column'}), 400
        
        created_count = 0
        updated_count = 0
        skipped_count = 0
        
        # Collect all rows first
        rows = list(reader)
        
        for row in rows:
            username = row.get('username', '').strip()
            if not username:
                continue
            
            sid = row.get('sid', '').strip() or None
            email = row.get('email', '').strip() or None
            notes = row.get('notes', '').strip() or None
            
            # Parse compromised (handle various formats)
            compromised_str = row.get('compromised', '').strip().lower()
            compromised = compromised_str in ('true', 'yes', '1', 'y')
            
            try:
                # Try to find existing user by username, sid, or email within this case
                existing_user, match_type = KnownUser.find_by_username_sid_alias_or_email(
                    username=username, sid=sid, email=email, case_id=case.id
                )
                
                if existing_user:
                    # Update existing user - always update with CSV data
                    updated = False
                    
                    # Update SID if provided and not already used by another user
                    if sid and existing_user.sid != sid:
                        sid_exists = KnownUser.query.filter(
                            KnownUser.sid == sid,
                            KnownUser.id != existing_user.id
                        ).first()
                        if not sid_exists:
                            existing_user.sid = sid
                            updated = True
                    
                    # Update email if provided
                    if email and existing_user.email != email.lower():
                        existing_user.email = email.lower()
                        updated = True
                    
                    # Update notes if provided
                    if notes and existing_user.notes != notes:
                        existing_user.notes = notes
                        updated = True
                    
                    # Only SET compromised to true - never unflag if already compromised
                    if compromised and not existing_user.compromised:
                        existing_user.compromised = True
                        updated = True
                    
                    # Link to case
                    existing_user.link_to_case(case.id)
                    existing_user.add_source('csv_import')
                    
                    if updated:
                        updated_count += 1
                        KnownUserAudit.log_change(
                            existing_user.id,
                            current_user.username,
                            'csv_import',
                            'update',
                            None,
                            f'Updated from CSV upload'
                        )
                    
                    db.session.commit()
                else:
                    # Check if SID already exists in this case before creating
                    if sid:
                        sid_exists = KnownUser.query.filter(
                            KnownUser.sid == sid,
                            KnownUser.case_id == case.id
                        ).first()
                        if sid_exists:
                            # SID exists - this is the same user with different username
                            # Add the CSV username as an alias and update other fields
                            sid_exists.add_alias(username)
                            
                            if email and sid_exists.email != email.lower():
                                sid_exists.email = email.lower()
                            if notes and sid_exists.notes != notes:
                                sid_exists.notes = notes
                            if compromised and not sid_exists.compromised:
                                sid_exists.compromised = True
                            
                            sid_exists.add_source('csv_import')
                            db.session.commit()
                            updated_count += 1
                            continue
                    
                    # Create new user with case_id
                    new_user = KnownUser(
                        case_id=case.id,
                        username=username.upper(),
                        sid=sid,
                        email=email.lower() if email else None,
                        notes=notes,
                        compromised=compromised,
                        added_by=current_user.username,
                        sources=['csv_import']
                    )
                    db.session.add(new_user)
                    db.session.commit()
                    
                    KnownUserAudit.log_change(
                        new_user.id,
                        current_user.username,
                        'user',
                        'create',
                        None,
                        f'Created from CSV upload: {username}'
                    )
                    db.session.commit()
                    created_count += 1
                    
            except Exception as row_err:
                db.session.rollback()
                skipped_count += 1
                continue
        
        return jsonify({
            'success': True,
            'created': created_count,
            'updated': updated_count,
            'skipped': skipped_count
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/known-users/download/<case_uuid>')
@login_required
def download_known_users_csv(case_uuid):
    """Download all known users for a case as CSV"""
    import csv
    import io
    from flask import Response
    from utils.known_users_discovery import get_users_for_case
    
    try:
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Get users for this case
        users = get_users_for_case(case.id)
        
        # Create CSV in memory
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'username', 'sid', 'email', 'compromised', 'notes',
            'aliases', 'sources', 'artifacts_with_user', 'last_seen'
        ])
        
        # Write user rows
        for user in users:
            aliases = ';'.join(user.get('aliases', []))
            sources = ';'.join(user.get('sources', []))
            
            writer.writerow([
                user.get('username', ''),
                user.get('sid', ''),
                user.get('email', ''),
                'true' if user.get('compromised') else 'false',
                user.get('notes', ''),
                aliases,
                sources,
                user.get('artifacts_with_user', 0),
                user.get('last_seen', '')
            ])
        
        # Generate response
        output.seek(0)
        
        # Create filename with case name
        safe_name = ''.join(c for c in case.name if c.isalnum() or c in (' ', '-', '_')).strip()
        filename = f'known_users_{safe_name}_{case_uuid[:8]}.csv'
        
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"'
            }
        )
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/known-users/bulk-update', methods=['POST'])
@login_required
def bulk_update_known_users():
    """Bulk update multiple known users"""
    from flask_login import current_user
    from models.known_user import KnownUser, KnownUserAudit
    
    try:
        data = request.get_json()
        user_ids = data.get('user_ids', [])
        updates = data.get('updates', {})
        
        if not user_ids:
            return jsonify({'success': False, 'error': 'No user IDs provided'}), 400
        
        if not updates:
            return jsonify({'success': False, 'error': 'No updates provided'}), 400
        
        updated_count = 0
        
        for user_id in user_ids:
            user = KnownUser.query.get(user_id)
            if not user:
                continue
            
            # Update compromised status
            if 'compromised' in updates:
                old_value = user.compromised
                new_value = updates['compromised']
                if old_value != new_value:
                    user.compromised = new_value
                    KnownUserAudit.log_change(
                        user_id=user.id,
                        changed_by=current_user.username,
                        field_name='compromised',
                        action='update',
                        old_value=str(old_value),
                        new_value=str(new_value)
                    )
                    updated_count += 1
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'updated': updated_count
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/known-users/bulk-delete', methods=['POST'])
@login_required
def bulk_delete_known_users():
    """Bulk delete multiple known users"""
    from flask_login import current_user
    from models.known_user import KnownUser, KnownUserAudit
    
    try:
        data = request.get_json()
        user_ids = data.get('user_ids', [])
        
        if not user_ids:
            return jsonify({'success': False, 'error': 'No user IDs provided'}), 400
        
        deleted_count = 0
        
        for user_id in user_ids:
            user = KnownUser.query.get(user_id)
            if not user:
                continue
            
            # Log the deletion
            KnownUserAudit.log_change(
                user_id=user.id,
                changed_by=current_user.username,
                field_name='user',
                action='delete',
                old_value=user.username or user.sid or f'ID:{user.id}',
                new_value=None
            )
            
            db.session.delete(user)
            deleted_count += 1
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'deleted': deleted_count
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================
# IOC Management API Endpoints
# ============================================

@api_bp.route('/iocs/types')
@login_required
def get_ioc_types():
    """Get all IOC types organized by category"""
    try:
        from models.ioc import get_ioc_types_by_category, IOCCategory
        
        types_by_category = get_ioc_types_by_category()
        icons = IOCCategory.icons()
        
        return jsonify({
            'success': True,
            'types_by_category': types_by_category,
            'category_icons': icons,
            'categories': IOCCategory.all()
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/iocs/values/<int:case_id>')
@login_required
def get_ioc_values_for_case(case_id):
    """Get just IOC values for a case (for highlighting in event modal)"""
    try:
        from models.ioc import IOC, IOCCase
        
        # Verify case exists
        case = Case.query.get(case_id)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Get all IOC values linked to this case (excluding false positives)
        ioc_links = IOCCase.query.filter_by(case_id=case_id).all()
        ioc_ids = [link.ioc_id for link in ioc_links]
        
        if not ioc_ids:
            return jsonify({'success': True, 'values': []})
        
        iocs = IOC.query.filter(
            IOC.id.in_(ioc_ids),
            IOC.false_positive == False,
            IOC.active == True
        ).all()
        
        # Extract searchable values (filenames from paths, etc.)
        from utils.ioc_artifact_tagger import extract_searchable_terms
        
        values = set()
        for ioc in iocs:
            terms = extract_searchable_terms(ioc.value, ioc.ioc_type)
            # terms is a list of (term, is_filename) tuples - extract just the term strings
            for term, _ in terms:
                if term:
                    values.add(term)
        
        return jsonify({
            'success': True,
            'values': list(values)
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/iocs/list/<case_uuid>')
@login_required
def get_iocs_for_case(case_uuid):
    """Get IOCs for a case with pagination and filtering"""
    try:
        from models.ioc import IOC, IOCCase, IOCCategory
        
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Pagination and filter parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        search = request.args.get('search', '', type=str).strip()
        category = request.args.get('category', '', type=str).strip()
        ioc_type = request.args.get('type', '', type=str).strip()
        malicious_only = request.args.get('malicious', 'false', type=str).lower() == 'true'
        
        per_page = min(max(per_page, 10), 200)
        
        # Build query - IOCs for this case (now directly associated via case_id)
        query = IOC.query.filter(IOC.case_id == case.id)
        
        # Apply filters
        if search:
            search_filter = f'%{search}%'
            query = query.filter(IOC.value.ilike(search_filter))
        
        if category:
            query = query.filter(IOC.category == category)
        
        if ioc_type:
            query = query.filter(IOC.ioc_type == ioc_type)
        
        if malicious_only:
            query = query.filter(IOC.malicious == True)
        
        # Exclude false positives by default
        query = query.filter(IOC.false_positive == False)
        
        # Order by last seen (most recent first)
        query = query.order_by(IOC.last_seen_in_artifacts.desc().nullslast(), IOC.created_at.desc())
        
        # Get total count before pagination
        total = query.count()
        
        # Apply pagination
        iocs = query.offset((page - 1) * per_page).limit(per_page).all()
        
        # Get stats
        stats = {
            'total': total,
            'by_category': {}
        }
        
        for cat in IOCCategory.all():
            cat_count = IOC.query.filter(
                IOC.case_id == case.id,
                IOC.category == cat,
                IOC.false_positive == False
            ).count()
            stats['by_category'][cat] = cat_count
        
        return jsonify({
            'success': True,
            'case_uuid': case_uuid,
            'iocs': [ioc.to_dict() for ioc in iocs],
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': (total + per_page - 1) // per_page if total > 0 else 1,
            'stats': stats
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/iocs/analyze-match-type', methods=['POST'])
@login_required
def analyze_ioc_match_type():
    """Analyze an IOC value and recommend a match type.
    
    Call this when user enters an IOC without explicitly setting type.
    Returns recommendation with explanation.
    """
    try:
        from models.ioc import get_match_type_recommendation, IOCMatchType
        
        data = request.get_json()
        value = data.get('value', '').strip()
        ioc_type = data.get('ioc_type', '').strip()
        
        if not value:
            return jsonify({'success': False, 'error': 'Value required'}), 400
        
        if not ioc_type:
            return jsonify({'success': False, 'error': 'IOC type required'}), 400
        
        recommendation = get_match_type_recommendation(value, ioc_type)
        
        return jsonify({
            'success': True,
            'recommendation': recommendation,
            'match_types': [
                {'value': IOCMatchType.TOKEN, 'label': 'Token (Whole Word)', 
                 'description': 'Best for hashes, IPs, unique identifiers - avoids partial matches'},
                {'value': IOCMatchType.SUBSTRING, 'label': 'Substring (Contains)', 
                 'description': 'Best for paths, registry, URLs - matches anywhere in event'},
                {'value': IOCMatchType.REGEX, 'label': 'Regex (Pattern)', 
                 'description': 'For complex patterns with wildcards'}
            ]
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/iocs/create/<case_uuid>', methods=['POST'])
@login_required
def create_ioc(case_uuid):
    """Create a new IOC and link to case.
    
    If match_type is not provided, auto-detection is used.
    If ioc_type is not provided, returns a prompt asking user to set it
    with a recommendation based on value analysis.
    """
    try:
        from models.ioc import IOC, IOCAudit, IOCMatchType, get_category_for_type, get_match_type_recommendation
        
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        data = request.get_json()
        ioc_type = (data.get('ioc_type') or '').strip()
        value = (data.get('value') or '').strip()
        notes = (data.get('notes') or '').strip()
        malicious = data.get('malicious', False)
        match_type = (data.get('match_type') or '').strip() or None  # Explicit match type
        
        if not value:
            return jsonify({'success': False, 'error': 'IOC value required'}), 400
        
        # If no IOC type, analyze value and recommend
        if not ioc_type:
            from models.ioc import detect_ioc_type_from_value
            suggested_type = detect_ioc_type_from_value(value)
            return jsonify({
                'success': False,
                'needs_type': True,
                'error': 'Please select an IOC type',
                'suggestion': suggested_type,
                'message': f'Based on the value, this looks like a "{suggested_type}". Please confirm or select the correct type.'
            }), 400
        
        # Get category for this type
        category = get_category_for_type(ioc_type)
        if not category:
            return jsonify({'success': False, 'error': f'Unknown IOC type: {ioc_type}'}), 400
        
        # Validate the value
        is_valid, error = IOC.validate_value(value, ioc_type)
        if not is_valid:
            return jsonify({'success': False, 'error': error}), 400
        
        # Validate match_type if provided
        if match_type and match_type not in IOCMatchType.all():
            return jsonify({'success': False, 'error': f'Invalid match type: {match_type}'}), 400
        
        # Get or create IOC for this case
        ioc, created = IOC.get_or_create(
            value=value,
            ioc_type=ioc_type,
            category=category,
            created_by=current_user.username,
            case_id=case.id,
            match_type=match_type,
            source='manual'
        )
        
        # Update fields if provided
        if notes:
            ioc.notes = notes
        if malicious:
            ioc.malicious = malicious
        
        # Log creation
        if created:
            IOCAudit.log_change(
                ioc_id=ioc.id,
                changed_by=current_user.username,
                field_name='ioc',
                action='create',
                new_value=f'{ioc_type}: {value} (match: {ioc.get_effective_match_type()})'
            )
        
        db.session.commit()
        
        # Include match type recommendation in response
        recommendation = get_match_type_recommendation(value, ioc_type)
        
        return jsonify({
            'success': True,
            'created': created,
            'ioc': ioc.to_dict(),
            'match_type_info': recommendation
        })
        
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/iocs/<int:ioc_id>')
@login_required
def get_ioc(ioc_id):
    """Get details for a specific IOC"""
    try:
        from models.ioc import IOC
        
        ioc = IOC.query.get(ioc_id)
        if not ioc:
            return jsonify({'success': False, 'error': 'IOC not found'}), 404
        
        return jsonify({
            'success': True,
            'ioc': ioc.to_dict()
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/iocs/<int:ioc_id>/update', methods=['POST'])
@login_required
def update_ioc(ioc_id):
    """Update an IOC field"""
    try:
        from models.ioc import IOC, IOCAudit
        
        ioc = IOC.query.get(ioc_id)
        if not ioc:
            return jsonify({'success': False, 'error': 'IOC not found'}), 404
        
        data = request.get_json()
        field_name = data.get('field')
        new_value = data.get('value')
        
        if not field_name:
            return jsonify({'success': False, 'error': 'Field name required'}), 400
        
        # Allowed fields to update
        allowed_fields = ['notes', 'malicious', 'false_positive', 'active', 'hidden', 'aliases', 'match_type']
        if field_name not in allowed_fields:
            return jsonify({'success': False, 'error': f'Cannot update field: {field_name}'}), 400
        
        old_value = getattr(ioc, field_name)
        
        # Handle boolean fields
        if field_name in ['malicious', 'false_positive', 'active']:
            new_value = bool(new_value)
        
        # Handle aliases field (list of strings)
        if field_name == 'aliases':
            if not isinstance(new_value, list):
                return jsonify({'success': False, 'error': 'Aliases must be a list'}), 400
            # Normalize aliases (lowercase, deduplicate)
            new_value = list(set([str(a).lower().strip() for a in new_value if a]))
        
        # Handle match_type field
        if field_name == 'match_type':
            from models.ioc import IOCMatchType
            if new_value and new_value not in IOCMatchType.all():
                return jsonify({'success': False, 'error': f'Invalid match type: {new_value}'}), 400
            # Allow None to reset to auto-detection
            if new_value == '':
                new_value = None
        
        setattr(ioc, field_name, new_value)
        
        # Log change
        IOCAudit.log_change(
            ioc_id=ioc.id,
            changed_by=current_user.username,
            field_name=field_name,
            action='update',
            old_value=old_value,
            new_value=new_value
        )
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'ioc': ioc.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/iocs/<int:ioc_id>/systems')
@login_required
def get_ioc_systems(ioc_id):
    """Get all systems where this IOC was found"""
    try:
        from models.ioc import IOC, IOCSystemSighting
        
        ioc = IOC.query.get(ioc_id)
        if not ioc:
            return jsonify({'success': False, 'error': 'IOC not found'}), 404
        
        sightings = ioc.system_sightings.all()
        
        return jsonify({
            'success': True,
            'ioc_id': ioc_id,
            'systems': [s.to_dict() for s in sightings]
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/iocs/<int:ioc_id>/audit')
@login_required
def get_ioc_audit(ioc_id):
    """Get audit history for an IOC"""
    try:
        from models.ioc import IOC, IOCAudit
        
        ioc = IOC.query.get(ioc_id)
        if not ioc:
            return jsonify({'success': False, 'error': 'IOC not found'}), 404
        
        audits = IOCAudit.query.filter_by(ioc_id=ioc_id).order_by(
            IOCAudit.changed_on.desc()
        ).all()
        
        return jsonify({
            'success': True,
            'ioc_id': ioc_id,
            'ioc_value': ioc.value,
            'audit_history': [a.to_dict() for a in audits]
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/iocs/<int:ioc_id>/delete', methods=['POST'])
@login_required
def delete_ioc_from_case(ioc_id):
    """Remove an IOC from a case (does not delete the IOC itself)"""
    try:
        from models.ioc import IOC, IOCCase, IOCAudit
        
        data = request.get_json()
        case_uuid = data.get('case_uuid')
        
        if not case_uuid:
            return jsonify({'success': False, 'error': 'Case UUID required'}), 400
        
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        ioc = IOC.query.get(ioc_id)
        if not ioc:
            return jsonify({'success': False, 'error': 'IOC not found'}), 404
        
        # Remove from case
        link = IOCCase.query.filter_by(ioc_id=ioc_id, case_id=case.id).first()
        if link:
            db.session.delete(link)
            
            IOCAudit.log_change(
                ioc_id=ioc_id,
                changed_by=current_user.username,
                field_name='case',
                action='delete',
                old_value=case.name
            )
            
            db.session.commit()
        
        return jsonify({'success': True})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/iocs/bulk-create/<case_uuid>', methods=['POST'])
@login_required
def bulk_create_iocs(case_uuid):
    """Bulk create IOCs from a list.
    
    Each IOC can include optional match_type. If not provided, auto-detection is used.
    """
    try:
        from models.ioc import IOC, IOCAudit, IOCMatchType, get_category_for_type
        
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        data = request.get_json()
        iocs_data = data.get('iocs', [])
        
        if not iocs_data:
            return jsonify({'success': False, 'error': 'No IOCs provided'}), 400
        
        created_count = 0
        linked_count = 0
        errors = []
        
        for item in iocs_data:
            ioc_type = item.get('ioc_type', '').strip()
            value = item.get('value', '').strip()
            match_type = item.get('match_type', '').strip() or None
            
            if not ioc_type or not value:
                errors.append(f'Missing type or value: {item}')
                continue
            
            category = get_category_for_type(ioc_type)
            if not category:
                errors.append(f'Unknown type: {ioc_type}')
                continue
            
            # Validate match_type if provided
            if match_type and match_type not in IOCMatchType.all():
                errors.append(f'Invalid match type for {value}: {match_type}')
                continue
            
            try:
                ioc, created = IOC.get_or_create(
                    value=value,
                    ioc_type=ioc_type,
                    category=category,
                    created_by=current_user.username,
                    case_id=case.id,
                    match_type=match_type,
                    source='bulk_import'
                )
                
                if created:
                    created_count += 1
                    linked_count += 1
                    IOCAudit.log_change(
                        ioc_id=ioc.id,
                        changed_by=current_user.username,
                        field_name='ioc',
                        action='create',
                        new_value=f'{ioc_type}: {value} (match: {ioc.get_effective_match_type()})'
                    )
                    
            except ValueError as e:
                errors.append(f'{ioc_type}: {value} - {str(e)}')
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'created': created_count,
            'linked': linked_count,
            'errors': errors
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================
# AI Settings API
# ============================================

@api_bp.route('/settings/detect-gpu', methods=['GET'])
@login_required
def detect_gpu():
    """Detect GPU(s), drivers, and Ollama installation"""
    try:
        result = {
            'success': True,
            'gpus': [],
            'recommended_gpu': None,
            'drivers': [],
            'ollama': {
                'installed': False,
                'version': None,
                'models': []
            }
        }
        
        # Detect NVIDIA GPUs using nvidia-smi
        cuda_version = None
        try:
            # First get CUDA version from nvidia-smi main output
            cuda_check = subprocess.run(['nvidia-smi'], capture_output=True, text=True, timeout=10)
            if cuda_check.returncode == 0:
                import re
                cuda_match = re.search(r'CUDA Version:\s*(\d+\.\d+)', cuda_check.stdout)
                if cuda_match:
                    cuda_version = cuda_match.group(1)
            
            # Query GPU details
            nvidia_output = subprocess.run(
                ['nvidia-smi', '--query-gpu=index,name,memory.total,memory.free,driver_version', 
                 '--format=csv,noheader,nounits'],
                capture_output=True, text=True, timeout=10
            )
            
            if nvidia_output.returncode == 0 and nvidia_output.stdout.strip():
                for line in nvidia_output.stdout.strip().split('\n'):
                    parts = [p.strip() for p in line.split(',')]
                    if len(parts) >= 5:
                        gpu = {
                            'index': int(parts[0]),
                            'name': parts[1],
                            'vram_total_mb': int(float(parts[2])),
                            'vram_free_mb': int(float(parts[3])),
                            'driver_version': parts[4],
                            'cuda_version': cuda_version,
                            'type': 'NVIDIA'
                        }
                        result['gpus'].append(gpu)
                        
                        # Add driver info
                        driver_info = f"NVIDIA Driver {parts[4]}"
                        if driver_info not in [d['name'] for d in result['drivers']]:
                            result['drivers'].append({
                                'name': driver_info,
                                'cuda': f"CUDA {cuda_version}" if cuda_version else None
                            })
        except FileNotFoundError:
            pass  # nvidia-smi not available
        except Exception as e:
            pass
        
        # Try lspci for additional GPU detection (AMD, Intel, or NVIDIA not found by nvidia-smi)
        # Skip if we already have NVIDIA GPUs from nvidia-smi (more accurate data)
        has_nvidia_from_smi = any(g['type'] == 'NVIDIA' and g['vram_total_mb'] for g in result['gpus'])
        
        try:
            lspci_output = subprocess.run(
                ['lspci', '-v'],
                capture_output=True, text=True, timeout=10
            )
            if lspci_output.returncode == 0:
                import re
                # Look for VGA/3D controllers
                vga_pattern = re.compile(r'(VGA compatible controller|3D controller):\s*(.+)', re.IGNORECASE)
                for match in vga_pattern.finditer(lspci_output.stdout):
                    gpu_name = match.group(2).strip()
                    
                    # Determine GPU type
                    if 'NVIDIA' in gpu_name.upper():
                        gpu_type = 'NVIDIA'
                        # Skip NVIDIA from lspci if we already have it from nvidia-smi
                        if has_nvidia_from_smi:
                            continue
                    elif 'AMD' in gpu_name.upper() or 'RADEON' in gpu_name.upper():
                        gpu_type = 'AMD'
                    elif 'INTEL' in gpu_name.upper():
                        gpu_type = 'Intel'
                    else:
                        gpu_type = 'Other'
                    
                    # Check if this GPU type is already in our list
                    already_found = any(g['type'] == gpu_type for g in result['gpus'])
                    
                    if not already_found:
                        result['gpus'].append({
                            'index': len(result['gpus']),
                            'name': gpu_name,
                            'vram_total_mb': None,
                            'vram_free_mb': None,
                            'driver_version': None,
                            'cuda_version': None,
                            'type': gpu_type
                        })
        except Exception:
            pass
        
        # If we have NVIDIA GPU but no driver info, try to get it separately
        has_nvidia = any(g['type'] == 'NVIDIA' for g in result['gpus'])
        if has_nvidia and not result['drivers']:
            try:
                # Get CUDA version from nvidia-smi main output
                fallback_cuda = None
                cuda_check = subprocess.run(['nvidia-smi'], capture_output=True, text=True, timeout=10)
                if cuda_check.returncode == 0:
                    import re
                    cuda_match = re.search(r'CUDA Version:\s*(\d+\.\d+)', cuda_check.stdout)
                    if cuda_match:
                        fallback_cuda = cuda_match.group(1)
                
                # Try nvidia-smi just for driver version
                driver_check = subprocess.run(
                    ['nvidia-smi', '--query-gpu=driver_version', '--format=csv,noheader,nounits'],
                    capture_output=True, text=True, timeout=10
                )
                if driver_check.returncode == 0 and driver_check.stdout.strip():
                    driver_ver = driver_check.stdout.strip().split('\n')[0].strip()
                    result['drivers'].append({
                        'name': f"NVIDIA Driver {driver_ver}",
                        'cuda': f"CUDA {fallback_cuda}" if fallback_cuda else None
                    })
                    # Update GPU records with driver info
                    for gpu in result['gpus']:
                        if gpu['type'] == 'NVIDIA':
                            gpu['driver_version'] = driver_ver
                            gpu['cuda_version'] = fallback_cuda
            except Exception:
                pass
        
        # Try to get NVIDIA VRAM info if missing
        for gpu in result['gpus']:
            if gpu['type'] == 'NVIDIA' and gpu['vram_total_mb'] is None:
                try:
                    vram_check = subprocess.run(
                        ['nvidia-smi', '--query-gpu=memory.total,memory.free', '--format=csv,noheader,nounits'],
                        capture_output=True, text=True, timeout=10
                    )
                    if vram_check.returncode == 0 and vram_check.stdout.strip():
                        parts = [p.strip() for p in vram_check.stdout.strip().split('\n')[0].split(',')]
                        if len(parts) >= 2:
                            try:
                                gpu['vram_total_mb'] = int(float(parts[0]))
                                gpu['vram_free_mb'] = int(float(parts[1]))
                            except ValueError:
                                pass
                except Exception:
                    pass
        
        # Select recommended GPU (prefer NVIDIA with most VRAM)
        if result['gpus']:
            nvidia_gpus = [g for g in result['gpus'] if g['type'] == 'NVIDIA']
            if nvidia_gpus:
                # Sort by VRAM (descending)
                nvidia_gpus.sort(key=lambda x: x['vram_total_mb'] or 0, reverse=True)
                result['recommended_gpu'] = nvidia_gpus[0]
            else:
                result['recommended_gpu'] = result['gpus'][0]
        
        # Detect Ollama
        try:
            ollama_version = subprocess.run(
                ['ollama', '--version'],
                capture_output=True, text=True, timeout=5
            )
            if ollama_version.returncode == 0:
                result['ollama']['installed'] = True
                version_text = ollama_version.stdout.strip() or ollama_version.stderr.strip()
                # Extract version number (format: "ollama version is X.X.X")
                if 'version' in version_text.lower():
                    import re
                    version_match = re.search(r'(\d+\.\d+\.\d+)', version_text)
                    if version_match:
                        result['ollama']['version'] = version_match.group(1)
                    else:
                        result['ollama']['version'] = version_text
                else:
                    result['ollama']['version'] = version_text
                
                # Get installed models
                try:
                    ollama_list = subprocess.run(
                        ['ollama', 'list'],
                        capture_output=True, text=True, timeout=10
                    )
                    if ollama_list.returncode == 0 and ollama_list.stdout.strip():
                        lines = ollama_list.stdout.strip().split('\n')
                        for line in lines[1:]:  # Skip header
                            parts = line.split()
                            if len(parts) >= 2:
                                model_name = parts[0]
                                model_size = parts[2] if len(parts) >= 3 else 'Unknown'
                                result['ollama']['models'].append({
                                    'name': model_name,
                                    'size': model_size
                                })
                except Exception:
                    pass
        except FileNotFoundError:
            result['ollama']['installed'] = False
        except Exception:
            pass
        
        # Add AI model configuration based on detected GPU
        from models.system_settings import get_ai_model_config, AI_FUNCTION_DESCRIPTIONS, SystemSettings, SettingKeys
        
        recommended_vram = None
        if result['recommended_gpu'] and result['recommended_gpu'].get('vram_total_mb'):
            recommended_vram = result['recommended_gpu']['vram_total_mb']
        
        model_config = get_ai_model_config(recommended_vram)
        if model_config:
            tier = '16gb' if recommended_vram and recommended_vram >= 14000 else '8gb'
            result['model_config'] = {
                'tier': tier,
                'functions': {}
            }
            for func_key, model_name in model_config.items():
                result['model_config']['functions'][func_key] = {
                    'model': model_name,
                    'description': AI_FUNCTION_DESCRIPTIONS.get(func_key, func_key)
                }
            
            # Store the GPU tier for use by AI functions
            SystemSettings.set(
                SettingKeys.AI_GPU_TIER,
                tier,
                value_type='string',
                updated_by='system'
            )
        else:
            result['model_config'] = None
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/settings/ai', methods=['GET'])
@login_required
def get_ai_settings():
    """Get AI settings including enabled state"""
    try:
        from models.system_settings import SystemSettings, SettingKeys
        
        ai_enabled = SystemSettings.get(SettingKeys.AI_ENABLED, False)
        ai_model = SystemSettings.get(SettingKeys.AI_DEFAULT_MODEL, None)
        
        return jsonify({
            'success': True,
            'ai_enabled': ai_enabled,
            'ai_default_model': ai_model
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/settings/ai', methods=['POST'])
@login_required
def set_ai_settings():
    """Set AI settings"""
    try:
        # Check admin permission
        if not current_user.is_administrator:
            return jsonify({'success': False, 'error': 'Administrator access required'}), 403
        
        from models.system_settings import SystemSettings, SettingKeys
        
        data = request.get_json()
        
        if 'ai_enabled' in data:
            SystemSettings.set(
                SettingKeys.AI_ENABLED, 
                data['ai_enabled'], 
                value_type='bool',
                updated_by=current_user.username
            )
        
        if 'ai_default_model' in data:
            SystemSettings.set(
                SettingKeys.AI_DEFAULT_MODEL,
                data['ai_default_model'],
                value_type='string',
                updated_by=current_user.username
            )
        
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================
# Worker Settings API
# ============================================

@api_bp.route('/settings/workers', methods=['GET'])
@login_required
def get_worker_settings():
    """Get current worker settings and system limits"""
    try:
        from models.system_settings import (
            SystemSettings, SettingKeys, 
            get_worker_limits, get_worker_concurrency, get_worker_override,
            WORKER_OPTIONS
        )
        
        limits = get_worker_limits()
        current_concurrency = get_worker_concurrency()
        override_enabled = get_worker_override()
        
        return jsonify({
            'success': True,
            'settings': {
                'concurrency': current_concurrency,
                'override_recommended': override_enabled
            },
            'limits': limits,
            'options': WORKER_OPTIONS
        })
        
    except Exception as e:
        logger.exception("Error getting worker settings")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/settings/workers', methods=['POST'])
@login_required
def set_worker_settings():
    """Set worker concurrency settings
    
    Validates against system limits and updates systemd service.
    Requires service restart to take effect.
    """
    try:
        # Check admin permission
        if not current_user.is_administrator:
            return jsonify({'success': False, 'error': 'Administrator access required'}), 403
        
        from models.system_settings import (
            SystemSettings, SettingKeys,
            get_worker_limits, WORKER_OPTIONS
        )
        
        data = request.get_json()
        concurrency = data.get('concurrency')
        override_recommended = data.get('override_recommended', False)
        
        if concurrency is None:
            return jsonify({'success': False, 'error': 'Concurrency value required'}), 400
        
        try:
            concurrency = int(concurrency)
        except (ValueError, TypeError):
            return jsonify({'success': False, 'error': 'Invalid concurrency value'}), 400
        
        # Validate against limits
        limits = get_worker_limits()
        
        # Must be a valid option
        if concurrency not in WORKER_OPTIONS:
            return jsonify({
                'success': False, 
                'error': f'Invalid concurrency value. Must be one of: {WORKER_OPTIONS}'
            }), 400
        
        # Determine effective max based on override setting
        if override_recommended:
            max_allowed = limits['absolute_max']
        else:
            max_allowed = limits['recommended_max']
        
        # Clamp to allowed maximum
        original_concurrency = concurrency
        if concurrency > max_allowed:
            concurrency = max_allowed
        
        # Save settings
        SystemSettings.set(
            SettingKeys.WORKER_OVERRIDE_RECOMMENDED,
            override_recommended,
            value_type='bool',
            updated_by=current_user.username
        )
        
        SystemSettings.set(
            SettingKeys.WORKER_CONCURRENCY,
            concurrency,
            value_type='int',
            updated_by=current_user.username
        )
        
        # Update systemd service file
        update_result = _update_worker_service_concurrency(concurrency)
        
        response = {
            'success': True,
            'concurrency': concurrency,
            'override_recommended': override_recommended,
            'service_updated': update_result['success'],
            'requires_restart': True
        }
        
        if original_concurrency != concurrency:
            response['clamped'] = True
            response['original_value'] = original_concurrency
            response['message'] = f'Concurrency clamped from {original_concurrency} to {concurrency} (max allowed: {max_allowed})'
        
        if not update_result['success']:
            response['service_error'] = update_result.get('error', 'Unknown error')
        
        return jsonify(response)
        
    except Exception as e:
        logger.exception("Error setting worker settings")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/settings/workers/restart', methods=['POST'])
@login_required
def restart_worker_service():
    """Restart the Celery worker service to apply new settings"""
    try:
        # Check admin permission
        if not current_user.is_administrator:
            return jsonify({'success': False, 'error': 'Administrator access required'}), 403
        
        import subprocess
        
        result = subprocess.run(
            ['sudo', '/usr/bin/systemctl', 'restart', 'casescope-workers'],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            return jsonify({
                'success': True,
                'message': 'Worker service restarted successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': f'Failed to restart service: {result.stderr}'
            }), 500
            
    except subprocess.TimeoutExpired:
        return jsonify({
            'success': False,
            'error': 'Service restart timed out'
        }), 500
    except Exception as e:
        logger.exception("Error restarting worker service")
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================
# Default Timezone Settings API
# ============================================

@api_bp.route('/settings/timezone', methods=['GET'])
@login_required
def get_default_timezone():
    """Get the default timezone for new cases"""
    try:
        from models.system_settings import SystemSettings, SettingKeys
        
        timezone = SystemSettings.get(SettingKeys.DEFAULT_TIMEZONE, 'America/New_York')
        
        return jsonify({
            'success': True,
            'timezone': timezone
        })
    except Exception as e:
        logger.exception("Error getting default timezone")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/settings/timezone', methods=['POST'])
@login_required
def set_default_timezone():
    """Set the default timezone for new cases"""
    try:
        # Check admin permission
        if not current_user.is_administrator:
            return jsonify({'success': False, 'error': 'Administrator access required'}), 403
        
        from models.system_settings import SystemSettings, SettingKeys
        from utils.timezone import is_valid_timezone
        
        data = request.get_json()
        timezone = data.get('timezone', 'UTC')
        
        # Validate timezone
        if not is_valid_timezone(timezone):
            return jsonify({'success': False, 'error': 'Invalid timezone'}), 400
        
        SystemSettings.set(
            SettingKeys.DEFAULT_TIMEZONE,
            timezone,
            value_type='string',
            updated_by=current_user.username
        )
        
        return jsonify({
            'success': True,
            'timezone': timezone,
            'message': 'Default timezone saved successfully'
        })
    except Exception as e:
        logger.exception("Error setting default timezone")
        return jsonify({'success': False, 'error': str(e)}), 500


def _update_worker_service_concurrency(concurrency: int) -> dict:
    """Update the systemd service file with new concurrency value
    
    Uses a privileged helper script to update the service file.
    
    Args:
        concurrency: New worker concurrency value
        
    Returns:
        dict with success status and any error message
    """
    import subprocess
    
    try:
        # Use the helper script which has sudo permissions
        result = subprocess.run(
            ['sudo', '/opt/casescope/bin/update_worker_concurrency.sh', str(concurrency)],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode != 0:
            return {'success': False, 'error': f'Failed to update service: {result.stderr or result.stdout}'}
        
        logger.info(f"Updated worker concurrency to {concurrency}")
        return {'success': True}
        
    except FileNotFoundError:
        return {'success': False, 'error': 'Helper script not found'}
    except Exception as e:
        logger.exception("Error updating worker service")
        return {'success': False, 'error': str(e)}


# ============================================
# IOC Extraction from EDR Reports API
# ============================================

@api_bp.route('/iocs/extraction/check/<case_uuid>')
@login_required
def check_edr_reports(case_uuid):
    """Check if case has EDR reports available for extraction"""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        from utils.ioc_extractor import split_edr_reports, get_report_preview
        
        has_reports = bool(case.edr_report and case.edr_report.strip())
        report_count = 0
        report_previews = []
        
        if has_reports:
            reports = split_edr_reports(case.edr_report)
            report_count = len(reports)
            report_previews = [
                {'index': i, 'preview': get_report_preview(r, 150), 'length': len(r)}
                for i, r in enumerate(reports)
            ]
        
        return jsonify({
            'success': True,
            'has_reports': has_reports,
            'report_count': report_count,
            'report_previews': report_previews
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/iocs/extraction/extract/<case_uuid>', methods=['POST'])
@login_required
def extract_iocs_from_report(case_uuid):
    """Extract IOCs from a specific EDR report"""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        if not case.edr_report or not case.edr_report.strip():
            return jsonify({'success': False, 'error': 'No EDR reports available'}), 400
        
        data = request.get_json()
        report_index = data.get('report_index', 0)
        
        from utils.ioc_extractor import (
            split_edr_reports, extract_iocs_with_ai, 
            process_extraction_for_import, get_report_preview
        )
        
        reports = split_edr_reports(case.edr_report)
        
        if report_index < 0 or report_index >= len(reports):
            return jsonify({'success': False, 'error': 'Invalid report index'}), 400
        
        report_text = reports[report_index]
        
        # Extract IOCs
        extraction, used_ai = extract_iocs_with_ai(report_text)
        
        # Process for import (deduplication, known systems/users matching)
        processed = process_extraction_for_import(
            extraction=extraction,
            case_id=case.id,
            username=current_user.username
        )
        
        return jsonify({
            'success': True,
            'report_index': report_index,
            'total_reports': len(reports),
            'report_preview': get_report_preview(report_text, 200),
            'used_ai': used_ai,
            'extraction_summary': processed.get('extraction_summary', {}),
            'iocs_to_import': processed.get('iocs_to_import', []),
            'known_systems': processed.get('known_systems_results', []),
            'known_users': processed.get('known_users_results', []),
            'mitre_indicators': processed.get('mitre_indicators', [])
        })
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/iocs/extraction/save/<case_uuid>', methods=['POST'])
@login_required
def save_extracted_iocs_api(case_uuid):
    """Save selected extracted IOCs to the database"""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        data = request.get_json()
        iocs_data = data.get('iocs', [])
        known_systems = data.get('known_systems', [])
        known_users = data.get('known_users', [])
        
        from utils.ioc_extractor import save_extracted_iocs
        
        results = save_extracted_iocs(
            iocs_data=iocs_data,
            case_id=case.id,
            username=current_user.username,
            known_systems=known_systems,
            known_users=known_users
        )
        
        return jsonify({
            'success': True,
            'results': results
        })
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================
# Find IOCs in Tagged Events
# ============================================

@api_bp.route('/iocs/find-in-events/stats/<case_uuid>')
@login_required
def get_find_iocs_stats(case_uuid):
    """Get stats for Find IOCs feature - tagged event count and IOC count"""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        from utils.clickhouse import get_fresh_client
        from models.ioc import IOC
        
        # Get count of events tagged with IOCs
        client = get_fresh_client()
        result = client.query(
            "SELECT count() FROM events WHERE case_id = {case_id:UInt32} AND length(ioc_types) > 0",
            parameters={'case_id': case.id}
        )
        tagged_count = result.result_rows[0][0] if result.result_rows else 0
        
        # Get IOC count for this case
        ioc_count = IOC.query.filter_by(case_id=case.id, active=True).count()
        
        return jsonify({
            'success': True,
            'tagged_event_count': tagged_count,
            'ioc_count': ioc_count
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/iocs/find-in-events/start/<case_uuid>', methods=['POST'])
@login_required
def start_find_iocs_in_events(case_uuid):
    """Start async task to find IOCs in tagged events"""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        from models.system_settings import SystemSettings, SettingKeys
        
        # Check if AI is enabled
        ai_enabled = SystemSettings.get(SettingKeys.AI_ENABLED, False)
        if not ai_enabled:
            return jsonify({'success': False, 'error': 'AI is not enabled'}), 400
        
        from tasks.celery_tasks import find_iocs_in_events_task
        
        # Start the Celery task
        task = find_iocs_in_events_task.delay(case.id, current_user.username)
        
        return jsonify({
            'success': True,
            'task_id': task.id
        })
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/iocs/find-in-events/progress/<case_uuid>/<task_id>')
@login_required
def get_find_iocs_progress(case_uuid, task_id):
    """Get progress of find IOCs task"""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        import redis
        import json
        from config import Config
        
        r = redis.Redis(
            host=Config.REDIS_HOST,
            port=Config.REDIS_PORT,
            db=Config.REDIS_DB,
            decode_responses=True
        )
        
        key = f"find_iocs_progress:{case.id}:{task_id}"
        data = r.get(key)
        
        if data:
            progress = json.loads(data)
            return jsonify({
                'success': True,
                'status': progress.get('status', 'processing'),
                'current': progress.get('current', 0),
                'total': progress.get('total', 0),
                'found_count': progress.get('found_count', 0),
                'current_value': progress.get('current_value', ''),
                'error': progress.get('error')
            })
        else:
            # Check Celery task status
            from celery.result import AsyncResult
            from tasks.celery_tasks import celery_app
            
            result = AsyncResult(task_id, app=celery_app)
            if result.state == 'PENDING':
                return jsonify({
                    'success': True,
                    'status': 'pending',
                    'current': 0,
                    'total': 0,
                    'found_count': 0
                })
            elif result.state == 'FAILURE':
                return jsonify({
                    'success': True,
                    'status': 'failed',
                    'error': str(result.result)
                })
            else:
                return jsonify({
                    'success': True,
                    'status': 'processing',
                    'current': 0,
                    'total': 0,
                    'found_count': 0
                })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/iocs/find-in-events/results/<case_uuid>/<task_id>')
@login_required
def get_find_iocs_results(case_uuid, task_id):
    """Get results of completed find IOCs task"""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        import redis
        import json
        from config import Config
        
        r = redis.Redis(
            host=Config.REDIS_HOST,
            port=Config.REDIS_PORT,
            db=Config.REDIS_DB,
            decode_responses=True
        )
        
        key = f"find_iocs_results:{case.id}:{task_id}"
        data = r.get(key)
        
        if data:
            results = json.loads(data)
            return jsonify({
                'success': True,
                **results
            })
        else:
            return jsonify({'success': False, 'error': 'Results not found or expired'}), 404
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/iocs/find-in-events/save/<case_uuid>', methods=['POST'])
@login_required
def save_find_iocs_results(case_uuid):
    """Save selected IOCs from find-in-events results"""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        data = request.get_json()
        iocs_data = data.get('iocs', [])
        known_systems = data.get('known_systems', [])
        known_users = data.get('known_users', [])
        
        from utils.ioc_extractor import save_extracted_iocs
        
        results = save_extracted_iocs(
            iocs_data=iocs_data,
            case_id=case.id,
            username=current_user.username,
            known_systems=known_systems,
            known_users=known_users
        )
        
        return jsonify({
            'success': True,
            'results': results
        })
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/iocs/tag-artifacts/<case_uuid>', methods=['POST'])
@login_required
def tag_artifacts_for_case(case_uuid):
    """Search all artifacts in case for IOC matches and update artifact counts.
    
    This performs case-insensitive partial matching for:
    - File paths: matches filename (e.g., "winscp.exe" matches "c:\\windows\\winscp.exe")
    - Hashes: exact match
    - IPs: exact match
    - Commands: extracts executables and matches those
    - Registry: partial match
    """
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        from utils.ioc_artifact_tagger import tag_all_iocs_globally
        
        # Search all IOCs against this case's artifacts
        results = tag_all_iocs_globally(case.id)
        
        return jsonify({
            'success': results.get('success', False),
            'total_iocs_searched': results.get('total_iocs', 0),
            'iocs_with_matches': results.get('iocs_with_matches', 0),
            'new_links_created': results.get('new_links_created', 0),
            'total_artifact_matches': results.get('total_artifact_matches', 0),
            'details': results.get('details', []),
            'error': results.get('error')
        })
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/iocs/tag-artifacts/<case_uuid>/progress', methods=['GET'])
@login_required
def get_tag_artifacts_progress(case_uuid):
    """Get progress of IOC artifact tagging for a case"""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        from utils.ioc_artifact_tagger import get_tag_progress
        
        progress = get_tag_progress(case.id)
        if progress:
            return jsonify({
                'success': True,
                'progress': progress
            })
        else:
            return jsonify({
                'success': True,
                'progress': None
            })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# Browser Downloads API
# ============================================================================

@api_bp.route('/hunting/browser/downloads/<int:case_id>')
@login_required
def get_browser_downloads(case_id):
    """Get user-initiated browser download events for a case
    
    Only returns actual user downloads from Chrome/Firefox/Edge downloads table.
    Excludes web cache entries and browsing history.
    
    Returns: timestamp, source_host (user/machine), filename, file path, source URL
    Also returns list of IOC filenames for highlighting.
    """
    try:
        from utils.clickhouse import get_client
        from utils.timezone import format_for_display
        from models.ioc import IOC
        
        case = Case.query.get(case_id)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Get case timezone for display conversion
        case_tz = case.timezone or 'UTC'
        
        # Get filename IOCs for this case to highlight malicious downloads
        ioc_filenames = set()
        filename_iocs = IOC.query.filter_by(case_id=case_id, ioc_type='File Name').all()
        for ioc in filename_iocs:
            ioc_filenames.add(ioc.value.lower())
            # Also add aliases
            if ioc.aliases:
                for alias in ioc.aliases:
                    ioc_filenames.add(alias.lower())
        
        client = get_client()
        
        # Query only browser_download artifact type (user-initiated downloads)
        # This comes from Chrome/Firefox/Edge downloads table parsing
        query = """
            SELECT 
                COALESCE(timestamp_utc, timestamp) as ts,
                source_host,
                target_path,
                username,
                raw_json,
                extra_fields,
                source_file,
                case_file_id
            FROM events 
            WHERE case_id = {case_id:UInt32}
            AND artifact_type = 'browser_download'
            ORDER BY timestamp DESC
            LIMIT 10000
        """
        
        result = client.query(query, parameters={'case_id': case_id})
        
        # Collect unique case_file_ids to batch lookup for username extraction
        case_file_ids = set()
        rows_data = []
        for row in result.result_rows:
            timestamp, source_host, target_path, username, raw_json_str, extra_fields_str, source_file, case_file_id = row
            rows_data.append(row)
            if case_file_id:
                case_file_ids.add(case_file_id)
        
        # Batch lookup CaseFile records for username extraction from path
        case_file_usernames = {}
        if case_file_ids:
            from models.case_file import CaseFile
            import re
            case_files = CaseFile.query.filter(CaseFile.id.in_(case_file_ids)).all()
            for cf in case_files:
                # Extract username from path like "C/Users/USERNAME/AppData..."
                if cf.filename:
                    match = re.search(r'[/\\]Users[/\\]([^/\\]+)[/\\]', cf.filename, re.IGNORECASE)
                    if match:
                        case_file_usernames[cf.id] = match.group(1)
        
        downloads = []
        
        for row in rows_data:
            timestamp, source_host, target_path, username, raw_json_str, extra_fields_str, source_file, case_file_id = row
            
            # Parse JSON fields
            try:
                raw_json = json.loads(raw_json_str) if raw_json_str else {}
            except:
                raw_json = {}
            
            try:
                extra_fields = json.loads(extra_fields_str) if extra_fields_str else {}
            except:
                extra_fields = {}
            
            # Extract download info from raw_json
            file_path = raw_json.get('file_path', raw_json.get('target_path', raw_json.get('current_path', target_path or '')))
            source_url = raw_json.get('url', raw_json.get('source_url', ''))
            filename = raw_json.get('filename', '')
            
            # Skip if we have no file path (invalid download record)
            if not file_path:
                continue
            
            # Extract filename from path or URL if not set
            if not filename:
                if file_path:
                    filename = file_path.split('\\')[-1].split('/')[-1]
                elif source_url:
                    # Try to extract filename from URL
                    url_path = source_url.split('?')[0]
                    filename = url_path.split('/')[-1] if '/' in url_path else ''
            
            # Get username: prefer event field, fallback to path extraction
            display_username = username or ''
            if not display_username and case_file_id:
                display_username = case_file_usernames.get(case_file_id, '')
            
            # Check if filename matches an IOC
            is_ioc_match = filename.lower() in ioc_filenames if filename else False
            
            downloads.append({
                'timestamp': format_for_display(timestamp, case_tz) if timestamp else '',
                'source_host': source_host or '',
                'username': display_username,
                'filename': filename or '(unknown)',
                'file_path': file_path or '',
                'source_url': source_url or '',
                'source_file': source_file or '',
                'is_ioc': is_ioc_match
            })
        
        return jsonify({
            'success': True,
            'case_id': case_id,
            'downloads': downloads,
            'total': len(downloads),
            'ioc_filenames': list(ioc_filenames)
        })
        
    except Exception as e:
        logger.exception(f"Error getting browser downloads: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# Noise Tagging API
# ============================================================================

@api_bp.route('/hunting/noise/stats/<int:case_id>')
@login_required
def get_noise_stats(case_id):
    """Get noise statistics for a case"""
    try:
        from utils.clickhouse import get_client
        
        client = get_client()
        
        # Count noise-tagged events
        result = client.query(
            "SELECT count() FROM events WHERE case_id = {case_id:UInt32} AND noise_matched = true",
            parameters={'case_id': case_id}
        )
        noise_count = result.result_rows[0][0] if result.result_rows else 0
        
        # Get total events
        total_result = client.query(
            "SELECT count() FROM events WHERE case_id = {case_id:UInt32}",
            parameters={'case_id': case_id}
        )
        total_count = total_result.result_rows[0][0] if total_result.result_rows else 0
        
        # Get last scan time from case metadata
        case = Case.query.get(case_id)
        last_scan = case.noise_last_scan.isoformat() if case and case.noise_last_scan else None
        
        return jsonify({
            'success': True,
            'case_id': case_id,
            'noise_count': noise_count,
            'total_count': total_count,
            'noise_percentage': round((noise_count / total_count * 100), 2) if total_count > 0 else 0,
            'last_scan': last_scan
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/hunting/noise/tag/<int:case_id>', methods=['POST'])
@login_required
def start_noise_tagging(case_id):
    """Start noise tagging task for a case"""
    try:
        from tasks.noise_tagger import tag_noise_events
        
        # Verify case exists
        case = Case.query.get(case_id)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Start async task
        task = tag_noise_events.delay(case_id, current_user.username)
        
        return jsonify({
            'success': True,
            'task_id': task.id,
            'message': 'Noise tagging started'
        })
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/hunting/noise/status/<task_id>')
@login_required
def get_noise_task_status(task_id):
    """Get status of a noise tagging task"""
    try:
        from celery.result import AsyncResult
        from tasks.celery_tasks import celery_app
        
        task = AsyncResult(task_id, app=celery_app)
        
        response = {
            'success': True,
            'task_id': task_id,
            'state': task.state,
            'progress': 0,
            'status': 'Unknown'
        }
        
        if task.state == 'PENDING':
            response['status'] = 'Waiting to start...'
            response['progress'] = 0
        elif task.state == 'PROGRESS':
            info = task.info or {}
            response['progress'] = info.get('progress', 0)
            response['status'] = info.get('status', 'Processing...')
        elif task.state == 'SUCCESS':
            response['state'] = 'completed'
            response['progress'] = 100
            response['status'] = 'Completed'
            response['result'] = task.result
        elif task.state == 'FAILURE':
            response['state'] = 'failed'
            response['error'] = str(task.result) if task.result else 'Task failed'
        
        return jsonify(response)
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================
# OpenCTI Integration API
# ============================================

@api_bp.route('/settings/opencti', methods=['GET'])
@login_required
def get_opencti_settings():
    """Get OpenCTI integration settings"""
    if not current_user.is_administrator:
        return jsonify({'success': False, 'error': 'Administrator access required'}), 403
    
    try:
        from models.system_settings import SystemSettings, SettingKeys
        
        return jsonify({
            'success': True,
            'settings': {
                'enabled': SystemSettings.get(SettingKeys.OPENCTI_ENABLED, False),
                'url': SystemSettings.get(SettingKeys.OPENCTI_URL, ''),
                'api_key': SystemSettings.get(SettingKeys.OPENCTI_API_KEY, ''),
                'ssl_verify': SystemSettings.get(SettingKeys.OPENCTI_SSL_VERIFY, False),
                'auto_enrich': SystemSettings.get(SettingKeys.OPENCTI_AUTO_ENRICH, False),
                'rag_sync': SystemSettings.get(SettingKeys.OPENCTI_RAG_SYNC, False)
            }
        })
    except Exception as e:
        logger.error(f"[OpenCTI] Error getting settings: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/settings/opencti', methods=['POST'])
@login_required
def set_opencti_settings():
    """Set OpenCTI integration settings"""
    if not current_user.is_administrator:
        return jsonify({'success': False, 'error': 'Administrator access required'}), 403
    
    try:
        from models.system_settings import SystemSettings, SettingKeys
        
        data = request.get_json()
        
        # Save settings
        if 'enabled' in data:
            SystemSettings.set(SettingKeys.OPENCTI_ENABLED, data['enabled'], 
                             value_type='bool', updated_by=current_user.username)
        
        if 'url' in data:
            url = data['url'].strip().rstrip('/')
            SystemSettings.set(SettingKeys.OPENCTI_URL, url, 
                             value_type='string', updated_by=current_user.username)
        
        if 'api_key' in data:
            SystemSettings.set(SettingKeys.OPENCTI_API_KEY, data['api_key'].strip(), 
                             value_type='string', updated_by=current_user.username)
        
        if 'ssl_verify' in data:
            SystemSettings.set(SettingKeys.OPENCTI_SSL_VERIFY, data['ssl_verify'], 
                             value_type='bool', updated_by=current_user.username)
        
        if 'auto_enrich' in data:
            SystemSettings.set(SettingKeys.OPENCTI_AUTO_ENRICH, data['auto_enrich'], 
                             value_type='bool', updated_by=current_user.username)
        
        if 'rag_sync' in data:
            SystemSettings.set(SettingKeys.OPENCTI_RAG_SYNC, data['rag_sync'], 
                             value_type='bool', updated_by=current_user.username)
        
        logger.info(f"[OpenCTI] Settings updated by {current_user.username}")
        
        return jsonify({'success': True, 'message': 'OpenCTI settings saved'})
        
    except Exception as e:
        logger.error(f"[OpenCTI] Error saving settings: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/settings/opencti/test', methods=['POST'])
@login_required
def test_opencti_connection():
    """Test OpenCTI connection with provided or saved credentials"""
    if not current_user.is_administrator:
        return jsonify({'success': False, 'error': 'Administrator access required'}), 403
    
    try:
        from utils.opencti import OpenCTIClient
        from models.system_settings import SystemSettings, SettingKeys
        
        data = request.get_json() or {}
        
        # Use provided values or fall back to saved settings
        url = data.get('url', '').strip() or SystemSettings.get(SettingKeys.OPENCTI_URL, '')
        api_key = data.get('api_key', '').strip() or SystemSettings.get(SettingKeys.OPENCTI_API_KEY, '')
        ssl_verify = data.get('ssl_verify', SystemSettings.get(SettingKeys.OPENCTI_SSL_VERIFY, False))
        
        if not url or not api_key:
            return jsonify({
                'success': False, 
                'message': 'URL and API key are required'
            })
        
        # Create client and test connection
        client = OpenCTIClient(url, api_key, ssl_verify)
        
        if client.init_error:
            return jsonify({
                'success': False,
                'message': f'Connection failed: {client.init_error}'
            })
        
        if client.ping():
            return jsonify({
                'success': True,
                'message': 'Connection successful! OpenCTI is accessible'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Connection failed - Could not reach OpenCTI or invalid credentials'
            })
            
    except Exception as e:
        logger.error(f"[OpenCTI] Connection test failed: {e}")
        return jsonify({
            'success': False,
            'message': f'Connection failed: {str(e)}'
        })


@api_bp.route('/ioc/<int:ioc_id>/enrich', methods=['POST'])
@login_required
def enrich_ioc(ioc_id):
    """Enrich a single IOC with OpenCTI threat intelligence"""
    try:
        from models.ioc import IOC
        from utils.opencti import enrich_ioc as do_enrich
        from models.system_settings import SystemSettings, SettingKeys
        
        # Check if OpenCTI is enabled
        if not SystemSettings.get(SettingKeys.OPENCTI_ENABLED, False):
            return jsonify({
                'success': False, 
                'error': 'OpenCTI integration is not enabled'
            }), 400
        
        ioc = IOC.query.get(ioc_id)
        if not ioc:
            return jsonify({'success': False, 'error': 'IOC not found'}), 404
        
        result = do_enrich(ioc)
        
        if result:
            return jsonify({
                'success': True,
                'message': f'IOC enriched successfully',
                'enrichment': json.loads(ioc.opencti_enrichment) if ioc.opencti_enrichment else None,
                'enriched_at': ioc.opencti_enriched_at.isoformat() if ioc.opencti_enriched_at else None
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Enrichment failed - check logs for details'
            }), 500
            
    except Exception as e:
        logger.error(f"[OpenCTI] Error enriching IOC {ioc_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/ioc/<int:ioc_id>/enrichment', methods=['GET'])
@login_required
def get_ioc_enrichment(ioc_id):
    """Get OpenCTI enrichment data for an IOC"""
    try:
        from models.ioc import IOC
        
        ioc = IOC.query.get(ioc_id)
        if not ioc:
            return jsonify({'success': False, 'error': 'IOC not found'}), 404
        
        if not ioc.opencti_enrichment:
            return jsonify({
                'success': False, 
                'error': 'No enrichment data available'
            }), 404
        
        enrichment = json.loads(ioc.opencti_enrichment)
        
        return jsonify({
            'success': True,
            'ioc_id': ioc_id,
            'ioc_value': ioc.value,
            'ioc_type': ioc.ioc_type,
            'enrichment': enrichment,
            'enriched_at': ioc.opencti_enriched_at.isoformat() if ioc.opencti_enriched_at else None
        })
        
    except Exception as e:
        logger.error(f"[OpenCTI] Error getting enrichment for IOC {ioc_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/iocs/bulk-enrich', methods=['POST'])
@login_required
def bulk_enrich_iocs():
    """Bulk enrich multiple IOCs with OpenCTI threat intelligence"""
    try:
        from models.ioc import IOC
        from utils.opencti import enrich_iocs_batch
        from models.system_settings import SystemSettings, SettingKeys
        
        # Check if OpenCTI is enabled
        if not SystemSettings.get(SettingKeys.OPENCTI_ENABLED, False):
            return jsonify({
                'success': False, 
                'error': 'OpenCTI integration is not enabled'
            }), 400
        
        data = request.get_json()
        ioc_ids = data.get('ioc_ids', [])
        
        if not ioc_ids or not isinstance(ioc_ids, list):
            return jsonify({
                'success': False, 
                'error': 'IOC IDs array required'
            }), 400
        
        # Get IOCs
        iocs = IOC.query.filter(IOC.id.in_(ioc_ids)).all()
        
        if not iocs:
            return jsonify({
                'success': False, 
                'error': 'No valid IOCs found'
            }), 404
        
        result = enrich_iocs_batch(iocs)
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"[OpenCTI] Error in bulk enrichment: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/iocs/bulk-update', methods=['POST'])
@login_required
def bulk_update_iocs():
    """Bulk update multiple IOCs - change active, malicious, false_positive status"""
    try:
        from models.ioc import IOC, IOCAudit
        
        data = request.get_json()
        ioc_ids = data.get('ioc_ids', [])
        updates = data.get('updates', {})
        
        if not ioc_ids or not isinstance(ioc_ids, list):
            return jsonify({'success': False, 'error': 'ioc_ids array required'}), 400
        
        if not updates or not isinstance(updates, dict):
            return jsonify({'success': False, 'error': 'updates object required'}), 400
        
        # Allowed fields for bulk update
        allowed_fields = {'active', 'malicious', 'false_positive'}
        update_fields = {k: v for k, v in updates.items() if k in allowed_fields}
        
        if not update_fields:
            return jsonify({'success': False, 'error': 'No valid update fields provided'}), 400
        
        # Get IOCs
        iocs = IOC.query.filter(IOC.id.in_(ioc_ids)).all()
        
        if not iocs:
            return jsonify({'success': False, 'error': 'No valid IOCs found'}), 404
        
        updated_count = 0
        for ioc in iocs:
            for field, value in update_fields.items():
                old_value = getattr(ioc, field)
                if old_value != value:
                    setattr(ioc, field, value)
                    IOCAudit.log_change(
                        ioc_id=ioc.id,
                        changed_by=current_user.username,
                        field_name=field,
                        action='update',
                        old_value=str(old_value),
                        new_value=str(value)
                    )
            updated_count += 1
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'updated_count': updated_count
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error in IOC bulk update: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/iocs/bulk-delete/<case_uuid>', methods=['POST'])
@login_required
def bulk_delete_iocs(case_uuid):
    """Bulk delete (remove from case) multiple IOCs"""
    try:
        from models.ioc import IOC, IOCCase, IOCAudit
        
        # Get the case
        case = Case.query.filter_by(uuid=case_uuid).first()
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        data = request.get_json()
        ioc_ids = data.get('ioc_ids', [])
        
        if not ioc_ids or not isinstance(ioc_ids, list):
            return jsonify({'success': False, 'error': 'ioc_ids array required'}), 400
        
        deleted_count = 0
        
        for ioc_id in ioc_ids:
            # Find the IOC-Case link
            ioc_case = IOCCase.query.filter_by(
                ioc_id=ioc_id,
                case_id=case.id
            ).first()
            
            if ioc_case:
                ioc = IOC.query.get(ioc_id)
                if ioc:
                    # Log the removal
                    IOCAudit.log_change(
                        ioc_id=ioc_id,
                        changed_by=current_user.username,
                        field_name='case',
                        action='delete',
                        old_value=case.uuid,
                        new_value=None
                    )
                
                db.session.delete(ioc_case)
                deleted_count += 1
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'deleted_count': deleted_count
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error in IOC bulk delete: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================
# Audit Logs API
# ============================================

@api_bp.route('/logs/audit/<category>')
@login_required
def get_audit_logs(category):
    """Get paginated audit logs by category
    
    Categories:
    - file_audit_log: FileAuditLog entries
    
    Query params:
    - page: page number (default 1)
    - per_page: items per page (default 25, max 100)
    - search: search term for filename, hash, or user
    """
    try:
        # Only administrators can view audit logs
        if not current_user.is_administrator:
            return jsonify({
                'success': False,
                'error': 'Administrator access required'
            }), 403
        
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 25, type=int), 100)
        search = request.args.get('search', '').strip()
        
        if category == 'file_audit_log':
            query = FileAuditLog.query
            
            if search:
                search_pattern = f'%{search}%'
                query = query.filter(
                    db.or_(
                        FileAuditLog.filename.ilike(search_pattern),
                        FileAuditLog.sha256_hash.ilike(search_pattern),
                        FileAuditLog.performed_by.ilike(search_pattern),
                        FileAuditLog.notes.ilike(search_pattern),
                        FileAuditLog.case_uuid.ilike(search_pattern)
                    )
                )
            
            # Order by most recent first
            query = query.order_by(FileAuditLog.performed_at.desc())
            
            # Paginate
            pagination = query.paginate(page=page, per_page=per_page, error_out=False)
            
            logs = [log.to_dict() for log in pagination.items]
            
            return jsonify({
                'success': True,
                'logs': logs,
                'total': pagination.total,
                'pages': pagination.pages,
                'page': page,
                'per_page': per_page
            })
        else:
            return jsonify({
                'success': False,
                'error': f'Unknown audit log category: {category}'
            }), 400
            
    except Exception as e:
        logger.error(f"Error fetching audit logs: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================
# Logging Settings API
# ============================================================

@api_bp.route('/settings/logging', methods=['GET'])
@login_required
def get_logging_settings():
    """Get logging configuration settings"""
    if not current_user.is_administrator:
        return jsonify({'success': False, 'error': 'Administrator access required'}), 403
    
    try:
        from models.system_settings import SystemSettings, SettingKeys
        from utils.logger import get_log_files_info, DEFAULT_LOG_PATH
        
        settings = {
            'log_level': SystemSettings.get(SettingKeys.LOG_LEVEL, 'INFO'),
            'log_path': SystemSettings.get(SettingKeys.LOG_PATH, DEFAULT_LOG_PATH),
            'log_retention_days': SystemSettings.get(SettingKeys.LOG_RETENTION_DAYS, 90),
            'log_max_size_mb': SystemSettings.get(SettingKeys.LOG_MAX_SIZE_MB, 100),
            'audit_view_permission': SystemSettings.get(SettingKeys.AUDIT_VIEW_PERMISSION, 'administrator'),
        }
        
        # Get log files info
        log_info = get_log_files_info()
        
        return jsonify({
            'success': True,
            'settings': settings,
            'log_info': log_info
        })
    except Exception as e:
        logger.error(f"Error getting logging settings: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/settings/logging', methods=['POST'])
@login_required
def set_logging_settings():
    """Set logging configuration settings"""
    if not current_user.is_administrator:
        return jsonify({'success': False, 'error': 'Administrator access required'}), 403
    
    try:
        from models.system_settings import SystemSettings, SettingKeys
        from models.audit_log import audit_setting_change
        from utils.logger import invalidate_settings_cache, ensure_log_directories
        
        data = request.get_json()
        
        # Valid log levels
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR']
        
        # Validate and save log level
        if 'log_level' in data:
            level = data['log_level'].upper()
            if level not in valid_levels:
                return jsonify({'success': False, 'error': f'Invalid log level. Must be one of: {valid_levels}'}), 400
            
            old_value = SystemSettings.get(SettingKeys.LOG_LEVEL, 'INFO')
            if old_value != level:
                SystemSettings.set(SettingKeys.LOG_LEVEL, level, 
                                 value_type='string', updated_by=current_user.username)
                audit_setting_change('log_level', old_value, level)
        
        # Validate and save log path
        if 'log_path' in data:
            path = data['log_path'].strip()
            if not path.startswith('/'):
                return jsonify({'success': False, 'error': 'Log path must be an absolute path'}), 400
            
            # Test if path is writable
            try:
                os.makedirs(path, exist_ok=True)
                test_file = os.path.join(path, '.write_test')
                with open(test_file, 'w') as f:
                    f.write('test')
                os.remove(test_file)
            except Exception as e:
                return jsonify({'success': False, 'error': f'Log path is not writable: {e}'}), 400
            
            old_value = SystemSettings.get(SettingKeys.LOG_PATH, '/opt/casescope/logs')
            if old_value != path:
                SystemSettings.set(SettingKeys.LOG_PATH, path, 
                                 value_type='string', updated_by=current_user.username)
                audit_setting_change('log_path', old_value, path)
        
        # Validate and save retention days
        if 'log_retention_days' in data:
            try:
                days = int(data['log_retention_days'])
                if days < 1 or days > 365:
                    return jsonify({'success': False, 'error': 'Retention days must be between 1 and 365'}), 400
                
                old_value = SystemSettings.get(SettingKeys.LOG_RETENTION_DAYS, 90)
                if old_value != days:
                    SystemSettings.set(SettingKeys.LOG_RETENTION_DAYS, days, 
                                     value_type='int', updated_by=current_user.username)
                    audit_setting_change('log_retention_days', old_value, days)
            except (ValueError, TypeError):
                return jsonify({'success': False, 'error': 'Invalid retention days value'}), 400
        
        # Validate and save max size
        if 'log_max_size_mb' in data:
            try:
                size = int(data['log_max_size_mb'])
                if size < 1 or size > 1000:
                    return jsonify({'success': False, 'error': 'Max size must be between 1 and 1000 MB'}), 400
                
                old_value = SystemSettings.get(SettingKeys.LOG_MAX_SIZE_MB, 100)
                if old_value != size:
                    SystemSettings.set(SettingKeys.LOG_MAX_SIZE_MB, size, 
                                     value_type='int', updated_by=current_user.username)
                    audit_setting_change('log_max_size_mb', old_value, size)
            except (ValueError, TypeError):
                return jsonify({'success': False, 'error': 'Invalid max size value'}), 400
        
        # Note: audit_view_permission removed - audit log is now always admin-only
        # for forensic chain of custody protection
        
        # Invalidate cache and ensure directories exist
        invalidate_settings_cache()
        ensure_log_directories()
        
        return jsonify({'success': True, 'message': 'Logging settings saved'})
        
    except Exception as e:
        logger.error(f"Error saving logging settings: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/settings/logging/test-path', methods=['POST'])
@login_required
def test_log_path():
    """Test if a log path is valid and writable"""
    if not current_user.is_administrator:
        return jsonify({'success': False, 'error': 'Administrator access required'}), 403
    
    try:
        data = request.get_json()
        path = data.get('path', '').strip()
        
        if not path:
            return jsonify({'success': False, 'error': 'Path is required'}), 400
        
        if not path.startswith('/'):
            return jsonify({'success': False, 'error': 'Path must be absolute'}), 400
        
        # Test directory creation
        try:
            os.makedirs(path, exist_ok=True)
        except Exception as e:
            return jsonify({'success': False, 'error': f'Cannot create directory: {e}'}), 400
        
        # Test write
        try:
            test_file = os.path.join(path, '.write_test')
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
        except Exception as e:
            return jsonify({'success': False, 'error': f'Cannot write to directory: {e}'}), 400
        
        return jsonify({'success': True, 'message': 'Path is valid and writable'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================
# FOLDER PATHS SETTINGS ENDPOINTS
# ============================================================

@api_bp.route('/settings/paths', methods=['GET'])
@login_required
def get_folder_path_settings():
    """Get folder path configuration settings"""
    if not current_user.is_administrator:
        return jsonify({'success': False, 'error': 'Administrator access required'}), 403
    
    try:
        from models.system_settings import SystemSettings, SettingKeys
        
        settings = {
            'archive_path': SystemSettings.get(SettingKeys.ARCHIVE_PATH, DEFAULT_ARCHIVE_PATH),
            'originals_path': SystemSettings.get(SettingKeys.ORIGINALS_PATH, DEFAULT_ORIGINALS_PATH),
        }
        
        return jsonify({
            'success': True,
            'settings': settings
        })
    except Exception as e:
        logger.error(f"Error getting folder path settings: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/settings/paths', methods=['POST'])
@login_required
def set_folder_path_settings():
    """Set folder path configuration settings"""
    if not current_user.is_administrator:
        return jsonify({'success': False, 'error': 'Administrator access required'}), 403
    
    try:
        from models.system_settings import SystemSettings, SettingKeys
        from models.audit_log import audit_setting_change
        
        data = request.get_json()
        
        # Validate and save archive path
        if 'archive_path' in data:
            path = data['archive_path'].strip()
            
            if not path:
                return jsonify({'success': False, 'error': 'Archive path is required'}), 400
            
            if not path.startswith('/'):
                return jsonify({'success': False, 'error': 'Archive path must be an absolute path'}), 400
            
            # Verify path exists (not creating, just checking)
            if not os.path.exists(path):
                return jsonify({'success': False, 'error': f'Path does not exist: {path}'}), 400
            
            if not os.path.isdir(path):
                return jsonify({'success': False, 'error': f'Path is not a directory: {path}'}), 400
            
            # Test if path is readable
            if not os.access(path, os.R_OK):
                return jsonify({'success': False, 'error': f'Path is not readable: {path}'}), 400
            
            old_value = SystemSettings.get(SettingKeys.ARCHIVE_PATH, DEFAULT_ARCHIVE_PATH)
            if old_value != path:
                SystemSettings.set(SettingKeys.ARCHIVE_PATH, path, 
                                 value_type='string', updated_by=current_user.username)
                audit_setting_change('archive_path', old_value, path)
        
        # Validate and save originals path
        if 'originals_path' in data:
            path = data['originals_path'].strip()
            
            if not path:
                return jsonify({'success': False, 'error': 'Originals path is required'}), 400
            
            if not path.startswith('/'):
                return jsonify({'success': False, 'error': 'Originals path must be an absolute path'}), 400
            
            # Verify path exists (not creating, just checking)
            if not os.path.exists(path):
                return jsonify({'success': False, 'error': f'Path does not exist: {path}'}), 400
            
            if not os.path.isdir(path):
                return jsonify({'success': False, 'error': f'Path is not a directory: {path}'}), 400
            
            # Test if path is readable
            if not os.access(path, os.R_OK):
                return jsonify({'success': False, 'error': f'Path is not readable: {path}'}), 400
            
            old_value = SystemSettings.get(SettingKeys.ORIGINALS_PATH, DEFAULT_ORIGINALS_PATH)
            if old_value != path:
                SystemSettings.set(SettingKeys.ORIGINALS_PATH, path, 
                                 value_type='string', updated_by=current_user.username)
                audit_setting_change('originals_path', old_value, path)
        
        return jsonify({'success': True, 'message': 'Folder path settings saved'})
        
    except Exception as e:
        logger.error(f"Error saving folder path settings: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/settings/paths/test', methods=['POST'])
@login_required
def test_folder_path():
    """Test if a folder path exists and is accessible"""
    if not current_user.is_administrator:
        return jsonify({'success': False, 'error': 'Administrator access required'}), 403
    
    try:
        data = request.get_json()
        path = data.get('path', '').strip()
        
        if not path:
            return jsonify({'success': False, 'error': 'Path is required'}), 400
        
        if not path.startswith('/'):
            return jsonify({'success': False, 'error': 'Path must be an absolute path'}), 400
        
        # Check if path exists
        if not os.path.exists(path):
            return jsonify({'success': False, 'error': f'Path does not exist: {path}'}), 400
        
        # Check if it's a directory
        if not os.path.isdir(path):
            return jsonify({'success': False, 'error': f'Path is not a directory: {path}'}), 400
        
        # Check if it's readable
        if not os.access(path, os.R_OK):
            return jsonify({'success': False, 'error': f'Path is not readable: {path}'}), 400
        
        return jsonify({'success': True, 'message': 'Path exists and is accessible'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/logs/view/<path:log_path>', methods=['GET'])
@login_required
def view_log_file(log_path):
    """View contents of a log file (tail)"""
    if not current_user.is_administrator:
        return jsonify({'success': False, 'error': 'Administrator access required'}), 403
    
    try:
        from utils.logger import get_log_path, read_log_tail
        
        lines = request.args.get('lines', 100, type=int)
        lines = min(lines, 1000)  # Cap at 1000 lines
        
        # Build full path and validate it's within log directory
        base_path = get_log_path()
        full_path = os.path.join(base_path, log_path)
        full_path = os.path.realpath(full_path)
        
        if not full_path.startswith(os.path.realpath(base_path)):
            return jsonify({'success': False, 'error': 'Invalid log path'}), 400
        
        if not os.path.exists(full_path):
            return jsonify({'success': False, 'error': 'Log file not found'}), 404
        
        log_lines = read_log_tail(full_path, lines)
        
        return jsonify({
            'success': True,
            'path': log_path,
            'lines': log_lines,
            'total_lines': len(log_lines)
        })
        
    except Exception as e:
        logger.error(f"Error viewing log file: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/logs/case/<case_uuid>', methods=['GET'])
@login_required
def get_case_logs(case_uuid):
    """Get log files for a specific case"""
    try:
        from utils.logger import get_log_files_info
        
        log_info = get_log_files_info(case_uuid)
        
        return jsonify({
            'success': True,
            'case_uuid': case_uuid,
            'log_info': log_info
        })
        
    except Exception as e:
        logger.error(f"Error getting case logs: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================
# Audit Log API
# ============================================================

@api_bp.route('/audit-log', methods=['GET'])
@login_required
def get_audit_log():
    """Get audit log entries with filtering
    
    Note: This endpoint is restricted to administrators only.
    The audit log is an immutable forensic trail that must be protected.
    """
    # Admin-only access - audit trail is sensitive forensic data
    if not current_user.is_administrator:
        return jsonify({'success': False, 'error': 'Administrator access required'}), 403
    
    try:
        from models.audit_log import AuditLog, AuditEntityType, AuditAction
        from datetime import datetime, timedelta
        
        # Parse filters
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 50, type=int), 200)
        entity_type = request.args.get('entity_type')
        action = request.args.get('action')
        username = request.args.get('username')
        case_uuid = request.args.get('case_uuid')
        search = request.args.get('search', '').strip()
        days = request.args.get('days', type=int)
        
        # Build query
        query = AuditLog.query
        
        if entity_type:
            query = query.filter(AuditLog.entity_type == entity_type)
        if action:
            query = query.filter(AuditLog.action == action)
        if username:
            query = query.filter(AuditLog.username == username)
        if case_uuid:
            query = query.filter(AuditLog.case_uuid == case_uuid)
        if days:
            cutoff = datetime.utcnow() - timedelta(days=days)
            query = query.filter(AuditLog.timestamp >= cutoff)
        if search:
            search_pattern = f'%{search}%'
            query = query.filter(
                db.or_(
                    AuditLog.entity_name.ilike(search_pattern),
                    AuditLog.old_value.ilike(search_pattern),
                    AuditLog.new_value.ilike(search_pattern),
                    AuditLog.username.ilike(search_pattern)
                )
            )
        
        # Order and paginate
        query = query.order_by(AuditLog.timestamp.desc())
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        
        return jsonify({
            'success': True,
            'entries': [e.to_dict() for e in pagination.items],
            'total': pagination.total,
            'pages': pagination.pages,
            'page': page,
            'per_page': per_page,
            'filters': {
                'entity_types': AuditEntityType.all(),
                'actions': AuditAction.all()
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting audit log: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/audit-log/entity/<entity_type>/<entity_id>', methods=['GET'])
@login_required
def get_entity_audit_log(entity_type, entity_id):
    """Get audit log entries for a specific entity"""
    try:
        from models.audit_log import AuditLog
        
        limit = request.args.get('limit', 50, type=int)
        limit = min(limit, 200)
        
        entries = AuditLog.get_by_entity(entity_type, entity_id, limit=limit)
        
        return jsonify({
            'success': True,
            'entity_type': entity_type,
            'entity_id': entity_id,
            'entries': [e.to_dict() for e in entries]
        })
        
    except Exception as e:
        logger.error(f"Error getting entity audit log: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================
# Field Enhancers API
# ============================================

@api_bp.route('/hunting/field-enhancers')
@login_required
def get_field_enhancers():
    """Get all enabled field enhancers for client-side caching
    
    Returns a lookup-optimized structure:
    {
        "artifact_type:field_path:field_value": "description",
        ...
    }
    
    Frontend caches this on page load for O(1) lookups.
    """
    try:
        from models.field_enhancer import FieldEnhancer
        
        enhancers = FieldEnhancer.query.filter_by(is_enabled=True).all()
        
        # Build lookup dict keyed by artifact_type:field_path:field_value
        lookup = {}
        for e in enhancers:
            # Create multiple keys for pattern matching
            # Exact match key
            key = f"{e.artifact_type}:{e.field_path}:{e.field_value}"
            lookup[key] = {
                'description': e.description,
                'source_pattern': e.source_pattern
            }
        
        return jsonify({
            'success': True,
            'enhancers': lookup,
            'count': len(lookup)
        })
        
    except Exception as e:
        logger.error(f"Error fetching field enhancers: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================
# Report Templates API
# ============================================

@api_bp.route('/reports/templates')
@login_required
def list_report_templates():
    """List all report templates
    
    Returns templates with metadata from database and file existence status.
    """
    try:
        from models.report_template import ReportTemplate
        
        templates = ReportTemplate.query.order_by(
            ReportTemplate.is_default.desc(),
            ReportTemplate.display_name
        ).all()
        
        return jsonify({
            'success': True,
            'templates': [t.to_dict() for t in templates]
        })
        
    except Exception as e:
        logger.error(f"Error listing report templates: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/reports/templates/active')
@login_required
def list_active_report_templates():
    """List only active templates that exist on disk
    
    Used for template selection dropdowns in report generation.
    """
    try:
        from models.report_template import ReportTemplate
        
        templates = ReportTemplate.get_active_templates()
        
        return jsonify({
            'success': True,
            'templates': [t.to_dict() for t in templates]
        })
        
    except Exception as e:
        logger.error(f"Error listing active report templates: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/reports/templates/scan', methods=['POST'])
@login_required
def scan_report_templates():
    """Scan templates folder and sync with database
    
    Admin only. Discovers new templates and marks missing ones.
    """
    if not current_user.is_administrator:
        return jsonify({'success': False, 'error': 'Administrator access required'}), 403
    
    try:
        from models.report_template import ReportTemplate
        
        result = ReportTemplate.scan_templates(updated_by=current_user.username)
        
        return jsonify({
            'success': True,
            'added': result['added'],
            'removed': result['removed'],
            'existing': result['existing'],
            'total_on_disk': result['total_on_disk']
        })
        
    except Exception as e:
        logger.error(f"Error scanning report templates: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/reports/templates/types')
@login_required
def list_report_types():
    """List available report types for templates
    
    Returns all report types with their labels and descriptions.
    """
    try:
        from models.report_template import ReportType, ReportTemplate
        
        types = []
        for rt in ReportType.all():
            types.append({
                'value': rt,
                'label': ReportType.labels().get(rt, rt),
                'description': ReportType.descriptions().get(rt, '')
            })
        
        # Also include counts of templates per type
        type_counts = ReportTemplate.get_report_types_with_templates()
        for t in types:
            t['template_count'] = type_counts.get(t['value'], 0)
        
        return jsonify({
            'success': True,
            'report_types': types
        })
        
    except Exception as e:
        logger.error(f"Error listing report types: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/reports/templates/by-type/<report_type>')
@login_required
def list_templates_by_type(report_type):
    """List active templates for a specific report type
    
    Used for template selection when generating a specific type of report.
    """
    try:
        from models.report_template import ReportTemplate, ReportType
        
        # Validate report type
        if report_type not in ReportType.all():
            return jsonify({
                'success': False, 
                'error': f'Invalid report type. Valid types: {", ".join(ReportType.all())}'
            }), 400
        
        templates = ReportTemplate.get_templates_by_type(report_type)
        
        return jsonify({
            'success': True,
            'report_type': report_type,
            'report_type_label': ReportType.labels().get(report_type, report_type),
            'templates': [t.to_dict() for t in templates]
        })
        
    except Exception as e:
        logger.error(f"Error listing templates by type: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/reports/templates/<int:template_id>', methods=['PUT'])
@login_required
def update_report_template(template_id):
    """Update report template metadata
    
    Admin only. Updates display_name, description, report_type, is_active, is_default.
    """
    if not current_user.is_administrator:
        return jsonify({'success': False, 'error': 'Administrator access required'}), 403
    
    try:
        from models.report_template import ReportTemplate, ReportType
        
        template = ReportTemplate.query.get(template_id)
        if not template:
            return jsonify({'success': False, 'error': 'Template not found'}), 404
        
        data = request.get_json() or {}
        
        # Update fields if provided
        if 'display_name' in data:
            display_name = data['display_name'].strip()
            if display_name:
                template.display_name = display_name
        
        if 'description' in data:
            template.description = data['description'].strip() or None
        
        # Update report type if provided
        if 'report_type' in data:
            report_type = data['report_type']
            if report_type and report_type in ReportType.all():
                template.report_type = report_type
            elif report_type:
                return jsonify({
                    'success': False,
                    'error': f'Invalid report type. Valid types: {", ".join(ReportType.all())}'
                }), 400
        
        if 'is_active' in data:
            template.is_active = bool(data['is_active'])
        
        if 'is_default' in data and data['is_default']:
            # Unset all other defaults first
            ReportTemplate.query.filter(ReportTemplate.id != template_id).update(
                {ReportTemplate.is_default: False}
            )
            template.is_default = True
        elif 'is_default' in data and not data['is_default']:
            template.is_default = False
        
        template.updated_by = current_user.username
        db.session.commit()
        
        return jsonify({
            'success': True,
            'template': template.to_dict()
        })
        
    except Exception as e:
        logger.error(f"Error updating report template: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/reports/templates/<int:template_id>', methods=['DELETE'])
@login_required
def delete_report_template(template_id):
    """Delete a report template
    
    Removes the template record from the database.
    Does NOT delete the actual .docx file from disk.
    """
    try:
        from models.report_template import ReportTemplate
        
        template = ReportTemplate.query.get(template_id)
        if not template:
            return jsonify({'success': False, 'error': 'Template not found'}), 404
        
        filename = template.filename
        db.session.delete(template)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Template "{filename}" removed from database'
        })
        
    except Exception as e:
        logger.error(f"Error deleting report template: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/reports/templates/<int:template_id>/placeholders')
@login_required
def get_template_placeholders(template_id):
    """Get available placeholders in a template
    
    Extracts Jinja2 variable names from the template.
    """
    try:
        from models.report_template import ReportTemplate
        from utils.report_generator import ReportGenerator
        
        template = ReportTemplate.query.get(template_id)
        if not template:
            return jsonify({'success': False, 'error': 'Template not found'}), 404
        
        if not template.file_exists:
            return jsonify({'success': False, 'error': 'Template file not found on disk'}), 404
        
        template_path = ReportTemplate.get_template_path(template.filename)
        generator = ReportGenerator(template_path)
        placeholders = generator.get_available_placeholders()
        
        return jsonify({
            'success': True,
            'placeholders': placeholders
        })
        
    except Exception as e:
        logger.error(f"Error getting template placeholders: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/reports/generate/<case_uuid>', methods=['POST'])
@login_required
def generate_report(case_uuid):
    """Generate a report for a case
    
    Request body:
    {
        "template_id": 1,
        "context": {
            "executive_summary": "...",
            "findings": "...",
            ...
        }
    }
    
    Returns:
    {
        "success": true,
        "report_path": "/storage/.../reports/CaseReport_2026-01-21_143052.docx",
        "filename": "CaseReport_2026-01-21_143052.docx"
    }
    """
    try:
        from models.report_template import ReportTemplate
        from utils.report_generator import (
            generate_case_report, 
            get_base_case_context
        )
        
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        data = request.get_json() or {}
        
        # Get template - use provided or default
        template_id = data.get('template_id')
        if template_id:
            template = ReportTemplate.query.get(template_id)
        else:
            template = ReportTemplate.get_default_template()
        
        if not template:
            return jsonify({
                'success': False, 
                'error': 'No template specified and no default template set'
            }), 400
        
        if not template.file_exists:
            return jsonify({
                'success': False, 
                'error': 'Template file not found on disk'
            }), 400
        
        # Build context - start with base case info
        context = get_base_case_context(case)
        
        # Merge in any provided context
        if 'context' in data:
            context.update(data['context'])
        
        # Generate the report
        report_path = generate_case_report(
            case_uuid=case_uuid,
            template_id=template.id,
            context=context
        )
        
        if not report_path:
            return jsonify({
                'success': False,
                'error': 'Failed to generate report'
            }), 500
        
        filename = os.path.basename(report_path)
        
        return jsonify({
            'success': True,
            'report_path': report_path,
            'filename': filename
        })
        
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/reports/list/<case_uuid>')
@login_required
def list_case_reports(case_uuid):
    """List all generated reports for a case"""
    try:
        from utils.report_generator import list_case_reports as get_reports
        
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        reports = get_reports(case_uuid)
        
        return jsonify({
            'success': True,
            'reports': reports
        })
        
    except Exception as e:
        logger.error(f"Error listing case reports: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/reports/download/<case_uuid>/<filename>')
@login_required
def download_report(case_uuid, filename):
    """Download a generated report"""
    try:
        from flask import send_file
        from utils.report_generator import get_case_reports_folder
        
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Sanitize filename to prevent path traversal
        safe_filename = os.path.basename(filename)
        if not safe_filename.lower().endswith('.docx'):
            return jsonify({'success': False, 'error': 'Invalid file type'}), 400
        
        reports_folder = get_case_reports_folder(case_uuid)
        file_path = os.path.join(reports_folder, safe_filename)
        
        if not os.path.isfile(file_path):
            return jsonify({'success': False, 'error': 'Report not found'}), 404
        
        return send_file(
            file_path,
            as_attachment=True,
            download_name=safe_filename,
            mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        )
        
    except Exception as e:
        logger.error(f"Error downloading report: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/reports/generate-ai/<case_uuid>', methods=['POST'])
@login_required
def generate_ai_report(case_uuid):
    """Generate an AI-powered report for a case based on template type
    
    Routes to the appropriate generator based on template's report_type:
    - DFIR: Uses AIReportGenerator for executive summary, IOCs, remediation
    - Timeline: Uses AITimelineGenerator for detailed event timeline
    
    Request body:
    {
        "template_id": 1  // Required - determines which generator to use
    }
    
    Returns:
    {
        "success": true,
        "filename": "DFIR_Report_20260121_143052.docx",
        "download_url": "/api/reports/download/case-uuid/filename.docx"
    }
    """
    try:
        from models.report_template import ReportTemplate, ReportType
        from utils.ai_report_generator import AIReportGenerator
        from utils.ai_timeline_generator import AITimelineGenerator
        
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        data = request.get_json() or {}
        template_id = data.get('template_id')
        
        # Get template to determine report type
        template = None
        if template_id:
            template = ReportTemplate.query.get(template_id)
        
        if not template:
            # Fall back to default DFIR template
            template = ReportTemplate.get_default_template_for_type(ReportType.DFIR)
        
        if not template:
            template = ReportTemplate.get_default_template()
        
        if not template:
            return jsonify({'success': False, 'error': 'No template found'}), 400
        
        # Route to appropriate generator based on report type
        report_type = template.report_type or ReportType.DFIR
        
        if report_type == ReportType.TIMELINE:
            # Use Timeline generator
            generator = AITimelineGenerator(case.id, template.id)
        else:
            # Use DFIR generator (default for DFIR and DETAILED_IOCS)
            generator = AIReportGenerator(case.id, template.id)
        
        result = generator.generate_report()
        
        if result.get('success'):
            response = {
                'success': True,
                'filename': result['filename'],
                'output_path': result['output_path'],
                'download_url': f"/api/reports/download/{case_uuid}/{result['filename']}",
                'sections': result.get('sections', []),
                'report_type': report_type
            }
            if 'stats' in result:
                response['stats'] = result['stats']
            return jsonify(response)
        else:
            return jsonify({
                'success': False, 
                'error': result.get('error', 'Report generation failed')
            }), 500
        
    except Exception as e:
        logger.error(f"Error generating AI report: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/reports/generate-timeline/<case_uuid>', methods=['POST'])
@login_required
def generate_timeline_report(case_uuid):
    """Generate an AI-powered Timeline report for a case
    
    This endpoint generates a detailed timeline using AI analysis of:
    - EDR report data
    - Analyst-tagged events with intelligent grouping
    - IOCs correlated to timeline entries
    
    Event Grouping Rules:
    - Groups "like" events (same signature) within time windows
    - Only groups if no unlike events intervene
    - Displays grouped events as: timestamp_start-end | description (count, hosts, users)
    
    Request body (optional):
    {
        "template_id": 1  // Optional, looks for timeline template or uses default
    }
    
    Returns:
    {
        "success": true,
        "filename": "Timeline_Report_20260121_143052.docx",
        "download_url": "/api/reports/download/case-uuid/filename.docx",
        "stats": {"total_events": 21, "event_groups": 5, "iocs": 15}
    }
    """
    try:
        from utils.ai_timeline_generator import AITimelineGenerator
        
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        data = request.get_json() or {}
        template_id = data.get('template_id')
        
        # Generate the timeline report
        generator = AITimelineGenerator(case.id, template_id)
        result = generator.generate_report()
        
        if result.get('success'):
            return jsonify({
                'success': True,
                'filename': result['filename'],
                'output_path': result['output_path'],
                'download_url': f"/api/reports/download/{case_uuid}/{result['filename']}",
                'sections': result['sections'],
                'stats': result.get('stats', {})
            })
        else:
            return jsonify({
                'success': False, 
                'error': result.get('error', 'Timeline report generation failed')
            }), 400
        
    except Exception as e:
        logger.error(f"Error generating timeline report: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================
# Case Reports Management API
# ============================================================

@api_bp.route('/reports/case/<case_uuid>')
@login_required
def list_case_reports_managed(case_uuid):
    """List all reports for a case with sync
    
    Syncs filesystem with database before returning, ensuring
    new files are added and missing files are removed.
    """
    try:
        from models.case_report import CaseReport
        from flask_login import current_user
        
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Sync filesystem with database (adds new, removes missing)
        sync_result = CaseReport.sync_reports_for_case(
            case_uuid=case_uuid,
            case_id=case.id,
            username=current_user.username if current_user.is_authenticated else 'system'
        )
        
        # Get all reports
        reports = CaseReport.get_reports_for_case(case.id)
        
        return jsonify({
            'success': True,
            'reports': [r.to_dict() for r in reports],
            'sync': sync_result
        })
        
    except Exception as e:
        logger.error(f"Error listing case reports: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/reports/<int:report_id>/notes', methods=['PUT'])
@login_required
def update_report_notes(report_id):
    """Update notes for a report
    
    Request body:
    {
        "notes": "Updated notes content"
    }
    """
    try:
        from models.case_report import CaseReport
        from flask_login import current_user
        
        report = CaseReport.get_by_id(report_id)
        if not report:
            return jsonify({'success': False, 'error': 'Report not found'}), 404
        
        # Get the case for UUID (for audit)
        case = Case.query.get(report.case_id)
        if not case:
            return jsonify({'success': False, 'error': 'Associated case not found'}), 404
        
        data = request.get_json() or {}
        notes = data.get('notes', '')
        
        # Update with audit logging
        report.update_notes(
            notes=notes,
            username=current_user.username if current_user.is_authenticated else 'system',
            case_uuid=case.uuid
        )
        
        return jsonify({
            'success': True,
            'report': report.to_dict()
        })
        
    except Exception as e:
        logger.error(f"Error updating report notes: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/reports/<int:report_id>', methods=['DELETE'])
@login_required
def delete_case_report(report_id):
    """Delete a report
    
    Deletes both the file and database record with audit logging.
    """
    try:
        from models.case_report import CaseReport
        from flask_login import current_user
        
        report = CaseReport.get_by_id(report_id)
        if not report:
            return jsonify({'success': False, 'error': 'Report not found'}), 404
        
        # Get the case for UUID (for audit)
        case = Case.query.get(report.case_id)
        if not case:
            return jsonify({'success': False, 'error': 'Associated case not found'}), 404
        
        filename = report.filename
        
        # Delete with audit logging
        report.delete_report(
            username=current_user.username if current_user.is_authenticated else 'system',
            case_uuid=case.uuid,
            delete_file=True
        )
        
        return jsonify({
            'success': True,
            'message': f'Report {filename} deleted successfully'
        })
        
    except Exception as e:
        logger.error(f"Error deleting report: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
