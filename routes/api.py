"""API routes for CaseScope"""
import os
import json
import hashlib
import logging
import platform
import subprocess
import shutil
import zipfile
from datetime import datetime
from flask import Blueprint, jsonify, request, Response, stream_with_context
from flask_login import login_required, current_user
from sqlalchemy import or_
from models.database import db
from models.user import User
from models.case import Case
from models.case_file import CaseFile, ExtractionStatus
from models.audit_log import AuditAction, AuditEntityType, AuditLog
from models.file_audit_log import FileAuditLog
from config import Config
from routes.route_helpers import (
    DEFAULT_ARCHIVE_PATH,
    DEFAULT_ORIGINALS_PATH,
    _default_upload_type_label,
    _get_parser_hints_for_case_file,
    _is_license_feature_active,
    _is_threat_intel_license_active,
    _remember_task_access,
    _task_access_allowed,
    _viewer_write_error,
)
from routes.hunting_query_helpers import _build_sigma_alert_condition
from utils.artifact_paths import (
    copy_to_directory,
    ensure_case_artifact_paths,
    ensure_case_originals_subdir,
    ensure_case_subdir,
    is_within_any_root,
    move_from_prefix,
    move_to_directory,
)

logger = logging.getLogger(__name__)

api_bp = Blueprint('api', __name__, url_prefix='/api')


def _log_case_file_audit(action: str, case_uuid: str, entity_name: str, details: dict):
    """Write a summarized case-file audit record without breaking the request."""
    try:
        AuditLog.log(
            entity_type=AuditEntityType.CASE_FILE,
            entity_id=case_uuid,
            entity_name=entity_name,
            action=action,
            case_uuid=case_uuid,
            details=details,
        )
    except Exception as e:
        logger.warning(f"Failed to write case file audit log ({action}) for {case_uuid}: {e}")

def _normalize_upload_file_info(file_info: dict) -> dict:
    """Return a file-info payload with a canonical upload type label."""
    from parsers.catalog import resolve_upload_type_selection

    normalized = resolve_upload_type_selection((file_info or {}).get('type', ''))
    normalized_file_info = dict(file_info or {})
    normalized_file_info['type'] = normalized['label']
    normalized_file_info['parser_hints'] = list(normalized.get('parser_hints', []))
    normalized_file_info['is_archive_hint'] = bool(normalized.get('is_archive'))
    return normalized_file_info
def _move_to_originals(file_path: str, case_uuid: str, filename: str) -> str:
    """Move an original uploaded file into the retained originals tree.
    
    Args:
        file_path: Current file path in uploads
        case_uuid: Case UUID for folder structure
        filename: Original filename to preserve
        
    Returns:
        New file path in originals folder, or None if move failed
    """
    if not file_path or not os.path.exists(file_path):
        return None

    originals_dir = ensure_case_originals_subdir(case_uuid)
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
        
        logger.info(f"Moved original file to originals: {file_path} -> {dest_path}")
        return dest_path
        
    except Exception as e:
        logger.error(f"Failed to move original file to originals: {file_path}: {e}")
        return None


def _copy_to_staging(source_path: str, staging_dir: str, filename: str) -> str:
    """Copy a retained original into staging for transient processing."""
    if not source_path or not os.path.exists(source_path):
        return None

    try:
        return copy_to_directory(source_path, staging_dir, filename)
    except Exception as e:
        logger.error(f"Failed to copy original into staging: {source_path}: {e}")
        return None


def _remove_file_if_present(file_path: str):
    """Best-effort removal for transient files."""
    if not file_path or not os.path.exists(file_path):
        return
    try:
        os.remove(file_path)
    except IsADirectoryError:
        shutil.rmtree(file_path, ignore_errors=True)
    except OSError:
        pass


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
        from models.system_settings import SettingKeys, SystemSettings
        live_gb = get_folder_size_gb(Config.STORAGE_FOLDER)
        originals_gb = get_folder_size_gb(SystemSettings.get(SettingKeys.ORIGINALS_PATH, DEFAULT_ORIGINALS_PATH))
        archive_gb = get_folder_size_gb(SystemSettings.get(SettingKeys.ARCHIVE_PATH, DEFAULT_ARCHIVE_PATH))
        
        # Software versions - all pulled live from system
        # CaseScope version from version.json
        casescope_version = 'Unknown'
        try:
            with open(os.path.join(Config.BASE_DIR, 'version.json'), 'r') as f:
                casescope_version = json.load(f).get('version', 'Unknown')
        except Exception as e:
            logger.debug(f"Unable to read version.json for dashboard stats: {e}")
        
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
            ch_client = clickhouse_connect.get_client(
                host=Config.CLICKHOUSE_HOST,
                port=Config.CLICKHOUSE_PORT,
                username=Config.CLICKHOUSE_USER,
                password=Config.CLICKHOUSE_PASSWORD,
                database=Config.CLICKHOUSE_DATABASE,
            )
            result = ch_client.query("SELECT version()")
            clickhouse_ver = result.result_rows[0][0]
        except Exception as e:
            logger.debug(f"Unable to query ClickHouse version for dashboard stats: {e}")
        
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
        except Exception as e:
            logger.debug(f"Unable to query PostgreSQL version for dashboard stats: {e}")
        
        # Qdrant server version via client
        qdrant_ver = 'Not available'
        try:
            from qdrant_client import QdrantClient
            qdrant = QdrantClient(host=Config.QDRANT_HOST, port=Config.QDRANT_PORT, timeout=2)
            info = qdrant.get_collections()
            # If we can connect, try to get version from server info
            try:
                import requests
                resp = requests.get(f'http://{Config.QDRANT_HOST}:{Config.QDRANT_PORT}/', timeout=2)
                if resp.ok:
                    qdrant_ver = resp.json().get('version', 'Connected')
            except Exception as e:
                logger.debug(f"Unable to fetch Qdrant version details for dashboard stats: {e}")
                qdrant_ver = 'Connected'
        except Exception as e:
            logger.debug(f"Unable to query Qdrant version for dashboard stats: {e}")
        
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
        except Exception as e:
            logger.debug(f"Unable to query ClickHouse event count for dashboard stats: {e}")
        
        # Activation status
        activation_info = {
            'status': 'not_activated',
            'status_label': 'Not Activated',
            'customer_name': None,
            'expires_at': None,
            'days_remaining': None,
            'grace_days_remaining': None,
            'features': {'ai': False, 'opencti': False}
        }
        try:
            from utils.licensing.license_manager import LicenseManager
            info = LicenseManager.get_activation_info()
            activation_info = {
                'status': info.get('status', 'not_activated'),
                'status_label': info.get('status_label', 'Unknown'),
                'customer_name': info.get('license', {}).get('customer_name'),
                'expires_at': info.get('expiry', {}).get('expires_at'),
                'days_remaining': info.get('expiry', {}).get('days_remaining'),
                'grace_days_remaining': info.get('server', {}).get('grace_days_remaining'),
                'is_expiring_soon': info.get('expiry', {}).get('is_expiring_soon', False),
                'features': info.get('features', {'ai': False, 'opencti': False})
            }
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
                    'originals_gb': originals_gb,
                    'archive_gb': archive_gb
                },
                'activation': activation_info
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
    paths = ensure_case_artifact_paths(case_uuid)
    web_path = paths['web_upload']
    sftp_path = paths['sftp_upload']
    staging_path = paths['staging']
    os.makedirs(CHUNK_TEMP_DIR, exist_ok=True)
    return web_path, sftp_path, staging_path


def _viewer_upload_error():
    return jsonify({'success': False, 'error': 'Viewers cannot modify uploaded artifacts'}), 403


def _allowed_case_upload_roots(case_uuid):
    paths = ensure_case_artifact_paths(case_uuid)
    return [paths['web_upload'], paths['sftp_upload'], paths['staging'], paths['storage']]


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
        if current_user.permission_level == 'viewer':
            return _viewer_upload_error()

        chunk = request.files.get('chunk')
        chunk_index = int(request.form.get('chunkIndex', 0))
        total_chunks = int(request.form.get('totalChunks', 1))
        upload_id = (request.form.get('uploadId') or '').strip()
        filename = os.path.basename((request.form.get('filename') or '').strip())
        case_uuid = (request.form.get('caseUuid') or '').strip()
        
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

        if current_user.permission_level == 'viewer':
            return _viewer_upload_error()
        
        web_path, sftp_path, _ = ensure_upload_dirs(case_uuid)
        allowed_roots = _allowed_case_upload_roots(case_uuid)
        
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

            if source_path and not is_within_any_root(source_path, allowed_roots):
                continue
            
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

        _log_case_file_audit(
            action=AuditAction.PREFLIGHT,
            case_uuid=case_uuid,
            entity_name='Case file preflight',
            details={
                'requested_files': len(files),
                'duplicate_count': len(duplicates),
                'duplicate_samples': [d['new_file'] for d in duplicates[:10]],
                'sources': sorted({(f.get('source') or 'web') for f in files}),
            },
        )
        
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

    if current_user.permission_level == 'viewer':
        return _viewer_upload_error()
    
    case = Case.get_by_uuid(case_uuid)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    def generate_progress():
        """Generator that yields NDJSON progress updates"""
        import time as _time
        from flask import current_app
        
        HEARTBEAT_INTERVAL = 10  # seconds between keepalive heartbeats
        
        web_path, sftp_path, staging_path = ensure_upload_dirs(case_uuid)
        allowed_roots = _allowed_case_upload_roots(case_uuid)
        
        ingested_count = 0
        extracted_count = 0
        duplicates_skipped = 0
        duplicates_deleted = 0
        archived_count = 0
        duplicate_true_count = 0
        duplicate_hash_only_count = 0
        queued_count_total = 0
        extraction_failures = []
        errors = []
        processed_files = []  # Track files for hash stage
        zip_files = []  # Track zip files for extraction stage
        zip_records = {}  # Map zip unique_key -> {'record': CaseFile, 'source_path': str, 'filename': str}
        non_zip_files = []  # Track non-zip files for move stage

        _log_case_file_audit(
            action=AuditAction.UPLOADED,
            case_uuid=case_uuid,
            entity_name='Case file ingest started',
            details={
                'requested_files': len(files),
                'skip_files': len(skip_files),
                'sources': sorted({(f.get('source') or 'web') for f in files}),
            },
        )
        
        # =============================================
        # PHASE 1: Identify files and check existence
        # =============================================
        for file_info in files:
            file_info = _normalize_upload_file_info(file_info)
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

            if source_path and not is_within_any_root(source_path, allowed_roots):
                errors.append(f'Invalid source path for {filename}')
                continue
            
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
                
                zip_hash = zf.get('hash')
                if not zip_hash:
                    try:
                        hasher = hashlib.sha256()
                        last_heartbeat = _time.monotonic()
                        with open(source_path, 'rb') as hf:
                            while True:
                                chunk = hf.read(1048576)
                                if not chunk:
                                    break
                                hasher.update(chunk)
                                now = _time.monotonic()
                                if now - last_heartbeat >= HEARTBEAT_INTERVAL:
                                    last_heartbeat = now
                                    yield json.dumps({
                                        'stage': 'extract',
                                        'current': idx + 1,
                                        'total': total_zips,
                                        'filename': zf['name'],
                                        'detail': 'Hashing archive...'
                                    }) + '\n'
                        zip_hash = hasher.hexdigest()
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
                        members = zfile.infolist()
                        if len(members) > 50000:
                            raise ValueError('Archive contains too many members')
                        total_uncompressed = sum(member.file_size for member in members)
                        if total_uncompressed > 20 * 1024 * 1024 * 1024:
                            raise ValueError('Archive exceeds uncompressed size limit')
                        real_extract_dir = os.path.realpath(extract_dir)
                        last_heartbeat = _time.monotonic()
                        for mi, member in enumerate(members):
                            target_path = os.path.realpath(os.path.join(extract_dir, member.filename))
                            if not target_path.startswith(real_extract_dir + os.sep):
                                extraction_failures.append(f'{filename}: blocked path traversal member {member.filename}')
                                continue
                            zfile.extract(member, extract_dir)
                            now = _time.monotonic()
                            if now - last_heartbeat >= HEARTBEAT_INTERVAL:
                                last_heartbeat = now
                                yield json.dumps({
                                    'stage': 'extract',
                                    'current': idx + 1,
                                    'total': total_zips,
                                    'filename': zf['name'],
                                    'detail': f'Extracting {mi + 1}/{len(members)} items'
                                }) + '\n'
                    extraction_status = ExtractionStatus.FULL
                    
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
                                'parent_zip': unique_zip_key,
                                'parent_zip_name': filename,
                                'retained_original_path': None,
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
                    source_path=source_path,
                    file_size=zip_size,
                    sha256_hash=zip_hash,
                    hostname=file_info.get('host', ''),
                    file_type=file_info.get('type', _default_upload_type_label()),
                    upload_source=file_info.get('source', 'web'),
                    is_archive=True,
                    is_extracted=False,
                    extraction_status=extraction_status,
                    status='new',
                    retention_state='archived',
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
                    source_path = nzf['source_path']
                    filename = nzf['name']
                    file_info = nzf['file_info']
                    retained_original = _move_to_originals(source_path, case_uuid, filename)
                    if not retained_original:
                        raise RuntimeError('Failed to retain original upload')

                    dest_path = _copy_to_staging(retained_original, staging_path, filename)
                    if not dest_path:
                        raise RuntimeError('Failed to create staging copy from retained original')
                    
                    processed_files.append({
                        'path': dest_path,
                        'filename': os.path.basename(dest_path),
                        'original_filename': filename,
                        'file_info': file_info,
                        'is_archive': False,
                        'is_extracted': False,
                        'parent_zip': None,
                        'parent_zip_name': None,
                        'hash': nzf.get('hash'),
                        'retained_original_path': retained_original,
                    })
                    
                    ingested_count += 1
                    
                except Exception as e:
                    errors.append(f'Error moving {nzf["name"]}: {str(e)}')
        
        # =============================================
        # PHASE 4: Calculate hashes and record metadata
        # =============================================
        total_processed = len(processed_files)
        HASH_BATCH_COMMIT_SIZE = 500
        last_progress_yield = _time.monotonic()
        
        existing_by_hash = {}
        existing_by_name = {}
        existing_records = CaseFile.query.filter_by(case_uuid=case_uuid).all()
        for er in existing_records:
            if er.sha256_hash:
                existing_by_hash[er.sha256_hash] = er
            if er.original_filename:
                existing_by_name[er.original_filename] = er
        
        for idx, pf in enumerate(processed_files):
            now = _time.monotonic()
            if idx == 0 or (now - last_progress_yield) >= 0.5 or (idx + 1) % 200 == 0 or idx == total_processed - 1:
                last_progress_yield = now
                yield json.dumps({
                    'stage': 'hash',
                    'current': idx + 1,
                    'total': total_processed,
                    'filename': pf['filename']
                }) + '\n'
            
            try:
                file_path = pf['path']
                file_size = os.path.getsize(file_path)
                
                sha256_hash = pf.get('hash')
                if not sha256_hash:
                    hasher = hashlib.sha256()
                    last_heartbeat = _time.monotonic()
                    with open(file_path, 'rb') as hf:
                        while True:
                            chunk = hf.read(1048576)  # 1MB chunks
                            if not chunk:
                                break
                            hasher.update(chunk)
                            now = _time.monotonic()
                            if now - last_heartbeat >= HEARTBEAT_INTERVAL:
                                last_heartbeat = now
                                yield json.dumps({
                                    'stage': 'hash',
                                    'current': idx + 1,
                                    'total': total_processed,
                                    'filename': pf['filename'],
                                    'detail': 'Hashing large file...'
                                }) + '\n'
                    sha256_hash = hasher.hexdigest()
                
                original_name = pf['original_filename']
                dup_type, existing = None, None
                hash_match = existing_by_hash.get(sha256_hash)
                if hash_match:
                    if hash_match.original_filename == original_name:
                        dup_type, existing = 'true', hash_match
                    else:
                        dup_type, existing = 'hash_only', hash_match
                else:
                    name_match = existing_by_name.get(original_name)
                    if name_match:
                        dup_type, existing = 'name_only', name_match
                
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
                    # Keep only the retained original (if any) and drop the staging copy.
                    duplicate_true_count += 1
                    try:
                        duplicate_record = CaseFile(
                            case_uuid=case_uuid,
                            parent_id=parent_id,
                            duplicate_of_id=existing.id,
                            filename=display_filename,
                            original_filename=original_name,
                            file_path=pf.get('retained_original_path'),
                            source_path=pf.get('retained_original_path'),
                            file_size=file_size,
                            sha256_hash=sha256_hash,
                            hostname=pf['file_info'].get('host', ''),
                            file_type=pf['file_info'].get('type', _default_upload_type_label()),
                            upload_source=pf['file_info'].get('source', 'web'),
                            is_archive=pf['is_archive'],
                            is_extracted=pf['is_extracted'],
                            extraction_status=ExtractionStatus.NA,
                            status='duplicate',
                            ingestion_status='not_done',
                            retention_state='duplicate_retained',
                            uploaded_by=uploaded_by
                        )
                        db.session.add(duplicate_record)
                        db.session.flush()
                    except Exception as e:
                        logger.warning(f"Failed to retain duplicate {display_filename}: {e}")
                        errors.append(f'Could not retain duplicate {display_filename}: {str(e)}')
                    _remove_file_if_present(file_path)
                    continue
                
                elif dup_type == 'hash_only':
                    # PARTIAL DUPLICATE: same hash, different filename
                    # Keep the retained original, drop the staging copy, create duplicate record.
                    duplicate_hash_only_count += 1
                    
                    case_file = CaseFile(
                        case_uuid=case_uuid,
                        parent_id=parent_id,
                        duplicate_of_id=existing.id,
                        filename=display_filename,
                        original_filename=original_name,
                        file_path=pf.get('retained_original_path'),
                        source_path=pf.get('retained_original_path'),
                        file_size=file_size,
                        sha256_hash=sha256_hash,
                        hostname=pf['file_info'].get('host', ''),
                        file_type=pf['file_info'].get('type', _default_upload_type_label()),
                        upload_source=pf['file_info'].get('source', 'web'),
                        is_archive=pf['is_archive'],
                        is_extracted=pf['is_extracted'],
                        extraction_status=ExtractionStatus.NA,
                        status='duplicate',  # Not parsed since content already indexed
                        ingestion_status='not_done',
                        retention_state='duplicate_retained',
                        uploaded_by=uploaded_by
                    )
                    db.session.add(case_file)
                    db.session.flush()
                    _remove_file_if_present(file_path)
                    continue
                
                # dup_type == 'name_only' or None: treat as new file
                # (name_only means same filename but different hash - different file version)
                
                case_file = CaseFile(
                    case_uuid=case_uuid,
                    parent_id=parent_id,
                    filename=display_filename,
                    original_filename=pf['original_filename'],
                    file_path=file_path,
                    source_path=pf.get('retained_original_path'),
                    file_size=file_size,
                    sha256_hash=sha256_hash,
                    hostname=pf['file_info'].get('host', ''),
                    file_type=pf['file_info'].get('type', _default_upload_type_label()),
                    upload_source=pf['file_info'].get('source', 'web'),
                    is_archive=pf['is_archive'],
                    is_extracted=pf['is_extracted'],
                    extraction_status=ExtractionStatus.NA,
                    status='new',
                    retention_state='retained',
                    uploaded_by=uploaded_by
                )
                
                db.session.add(case_file)
                db.session.flush()
                
                if sha256_hash:
                    existing_by_hash[sha256_hash] = case_file
                if original_name:
                    existing_by_name[original_name] = case_file
                
                if parent_zip_key:
                    extracted_count += 1
                
                if (idx + 1) % HASH_BATCH_COMMIT_SIZE == 0:
                    try:
                        db.session.commit()
                    except Exception as ce:
                        db.session.rollback()
                        errors.append(f'Batch commit error at file {idx + 1}: {str(ce)}')
                    
            except Exception as e:
                errors.append(f'Error hashing {pf["filename"]}: {str(e)}')
                try:
                    parent_id = None
                    parent_zip_key = pf.get('parent_zip')
                    parent_zip_name = pf.get('parent_zip_name')
                    if parent_zip_key and parent_zip_key in zip_records:
                        parent_id = zip_records[parent_zip_key]['record'].id
                    
                    display_filename = pf['filename']
                    if parent_zip_name:
                        display_filename = f"{parent_zip_name}/{pf['filename']}"
                    
                    case_file = CaseFile(
                        case_uuid=case_uuid,
                        parent_id=parent_id,
                        filename=display_filename,
                        original_filename=pf['original_filename'],
                        file_path=pf['path'],
                        source_path=pf.get('retained_original_path'),
                        file_size=0,
                        sha256_hash=None,
                        hostname=pf['file_info'].get('host', ''),
                        file_type=pf['file_info'].get('type', _default_upload_type_label()),
                        upload_source=pf['file_info'].get('source', 'web'),
                        is_archive=pf.get('is_archive', False),
                        is_extracted=pf.get('is_extracted', False),
                        extraction_status=ExtractionStatus.NA,
                        status='error',
                        ingestion_status='error',
                        retention_state='failed_retained',
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
        
        try:
            # Move zip files to originals folder and update CaseFile records
            for unique_key, zr_data in zip_records.items():
                source_path = zr_data['source_path']
                filename = zr_data['filename']
                record = zr_data['record']
                
                if source_path and os.path.exists(source_path):
                    originals_path = _move_to_originals(source_path, case_uuid, filename)
                    if originals_path:
                        # Update the CaseFile record with the new path and mark as done
                        record.file_path = originals_path
                        record.source_path = originals_path
                        record.status = 'done'
                        record.ingestion_status = 'no_parser'
                        record.retention_state = 'archived'
                        record.processed_at = datetime.utcnow()
                        CaseFile.query.filter_by(parent_id=record.id).update(
                            {'source_path': originals_path},
                            synchronize_session=False,
                        )
                        archived_count += 1
                        logger.info(f"Retained original ZIP: {filename} -> {originals_path}")
                    else:
                        # Move failed - keep file path pointing to source so it's not orphaned
                        record.file_path = source_path
                        record.source_path = source_path
                        record.status = 'error'
                        record.ingestion_status = 'error'
                        record.retention_state = 'failed_retained'
                        record.error_message = 'Failed to move to originals retention'
                        errors.append(f'Failed to retain original: {filename}')
                        logger.warning(f"ZIP file kept in uploads for recovery: {source_path}")
        except Exception as e:
            errors.append(f'Cleanup error: {str(e)}')

        # Commit all database changes
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            errors.append(f'Database error: {str(e)}')

        _log_case_file_audit(
            action=AuditAction.EXTRACTED,
            case_uuid=case_uuid,
            entity_name='Case file extraction summary',
            details={
                'archives_detected': len(zip_files),
                'archives_archived': archived_count,
                'extracted_files': extracted_count,
                'extraction_failures': len(extraction_failures),
                'extraction_failure_samples': extraction_failures[:10],
            },
        )

        if duplicate_true_count or duplicate_hash_only_count or duplicates_skipped:
            _log_case_file_audit(
                action=AuditAction.DUPLICATE_SKIPPED,
                case_uuid=case_uuid,
                entity_name='Case file duplicate summary',
                details={
                    'skipped_by_user': duplicates_skipped,
                    'true_duplicates_retained': duplicate_true_count,
                    'hash_only_duplicates_retained': duplicate_hash_only_count,
                },
            )
        
        # =============================================
        # PHASE 5b: Staging validation - catch any orphans
        # =============================================
        try:
            if os.path.isdir(staging_path):
                db_paths_check = {
                    r.file_path for r in
                    CaseFile.query.filter_by(case_uuid=case_uuid)
                    .with_entities(CaseFile.file_path).all()
                    if r.file_path
                }
                orphan_count = 0
                for root, dirs, staging_files_check in os.walk(staging_path):
                    for sf_name in staging_files_check:
                        sf_path = os.path.join(root, sf_name)
                        if sf_path not in db_paths_check:
                            try:
                                sf_size = os.path.getsize(sf_path)
                                sf_rel = os.path.relpath(sf_path, staging_path)
                                sf_hash = hashlib.sha256()
                                with open(sf_path, 'rb') as hf:
                                    while True:
                                        chunk = hf.read(1048576)
                                        if not chunk:
                                            break
                                        sf_hash.update(chunk)
                                orphan_record = CaseFile(
                                    case_uuid=case_uuid,
                                    filename=sf_rel,
                                    original_filename=sf_name,
                                    file_path=sf_path,
                                    source_path=sf_path,
                                    file_size=sf_size,
                                    sha256_hash=sf_hash.hexdigest(),
                                    hostname='',
                                    file_type=_default_upload_type_label(),
                                    upload_source='staging_import',
                                    is_extracted=True,
                                    status='new',
                                    retention_state='retained',
                                    uploaded_by=uploaded_by
                                )
                                db.session.add(orphan_record)
                                orphan_count += 1
                            except Exception as oe:
                                logger.warning(f"Failed to register staging orphan {sf_path}: {oe}")
                if orphan_count > 0:
                    db.session.commit()
                    logger.info(f"Registered {orphan_count} staging orphan files for case {case_uuid}")
        except Exception as e:
            logger.warning(f"Staging validation error: {e}")
        
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
                        parser_hints=_get_parser_hints_for_case_file(cf),
                    )
                    queued_count += 1
                queued_count_total = queued_count
                
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
                        _remove_file_if_present(cf.file_path)
                    cf.file_path = None
                    cf.status = 'done'
                    cf.ingestion_status = 'no_parser'
                    cf.processed_at = datetime.utcnow()
                    nested_archive_count += 1
                
                if nested_archive_count > 0:
                    logger.info(f"Removed {nested_archive_count} nested archive staging files for case {case_uuid}")
                
                db.session.commit()
                _log_case_file_audit(
                    action=AuditAction.QUEUED,
                    case_uuid=case_uuid,
                    entity_name='Case file ingest queued',
                    details={
                        'queued_files': queued_count_total,
                        'nested_archives_retained': nested_archive_count,
                        'ingested_records': ingested_count,
                        'errors': len(errors),
                    },
                )
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


