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
    _is_license_feature_active,
    _is_threat_intel_license_active,
    _remember_task_access,
    _task_access_allowed,
    _viewer_write_error,
)
from utils.forensic_chat_sources import get_browser_download_rows
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


def _get_parser_hints_for_case_file(case_file: CaseFile) -> list:
    """Resolve parser hints for a persisted CaseFile selection label."""
    from parsers.catalog import get_parser_hints_for_upload_type

    return get_parser_hints_for_upload_type((case_file.file_type or '').strip())


def _default_upload_type_label() -> str:
    """Return the canonical fallback upload label."""
    from parsers.catalog import AUTO_DETECT_UPLOAD_LABEL

    return AUTO_DETECT_UPLOAD_LABEL


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
    'srcipraw': ('src_ip_raw', 'blob'),
    'src_ip_raw': ('src_ip_raw', 'blob'),
    'dstipraw': ('dst_ip_raw', 'blob'),
    'dst_ip_raw': ('dst_ip_raw', 'blob'),
    'srcnatip': ('src_nat_ip', 'blob'),
    'src_nat_ip': ('src_nat_ip', 'blob'),
    'dstnatip': ('dst_nat_ip', 'blob'),
    'dst_nat_ip': ('dst_nat_ip', 'blob'),
    'natip': ('src_nat_ip', 'blob'),
    'nat_ip': ('src_nat_ip', 'blob'),
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


def _build_search_blob_field_condition(field_name: str, value: str, param_prefix: str, params: dict) -> str:
    """Build a search_blob key:value match condition."""
    param_name = f'{param_prefix}_blob'
    params[param_name] = f'%{field_name}:{value}%'
    return f"search_blob ilike {{{param_name}:String}}"


def _build_ip_field_search_condition(field_lower: str, column: str, value: str,
                                     param_prefix: str, params: dict) -> str:
    """Match IPv4 event columns and preserved searchable IP tokens."""
    if field_lower == 'ip':
        direct_src = f'{param_prefix}_src'
        direct_dst = f'{param_prefix}_dst'
        params[direct_src] = value
        params[direct_dst] = value
        conditions = [
            f"toString(src_ip) = {{{direct_src}:String}}",
            f"toString(dst_ip) = {{{direct_dst}:String}}",
        ]
        for token_field in ('src_ip', 'dst_ip', 'src_nat_ip', 'dst_nat_ip'):
            conditions.append(
                _build_search_blob_field_condition(
                    token_field,
                    value,
                    f'{param_prefix}_{token_field}',
                    params,
                )
            )
        return f"({' OR '.join(conditions)})"

    direct_param = f'{param_prefix}_fld'
    params[direct_param] = value
    token_field = 'src_ip' if column == 'src_ip' else 'dst_ip'
    token_condition = _build_search_blob_field_condition(
        token_field,
        value,
        f'{param_prefix}_{token_field}',
        params,
    )
    return f"(toString({column}) = {{{direct_param}:String}} OR {token_condition})"


def _parse_event_field_value_condition(field: str, value: str, param_prefix: str, params: dict) -> str:
    """Parse a field:value pair into a ClickHouse condition."""
    field_lower = field.lower()

    if field_lower in ('natip', 'nat_ip'):
        return (
            "("
            + _build_search_blob_field_condition('src_nat_ip', value, f'{param_prefix}_src_nat', params)
            + " OR "
            + _build_search_blob_field_condition('dst_nat_ip', value, f'{param_prefix}_dst_nat', params)
            + ")"
        )

    mapping = SEARCH_FIELD_MAP.get(field_lower)

    if mapping is None and field_lower in SEARCH_FIELD_MAP:
        return _build_search_blob_field_condition(field_lower, value, param_prefix, params)
    if mapping:
        column, match_type = mapping

        if match_type == 'blob':
            return _build_search_blob_field_condition(column, value, param_prefix, params)

        if match_type == 'eq':
            if field_lower == 'ip' or column in ('src_ip', 'dst_ip'):
                return _build_ip_field_search_condition(field_lower, column, value, param_prefix, params)

            param_name = f'{param_prefix}_fld'
            params[param_name] = value
            if column in ('logon_type', 'process_id', 'parent_pid', 'record_id',
                          'src_port', 'dst_port', 'file_size'):
                return f"{column} = {{{param_name}:String}}"
            return f"{column} = {{{param_name}:String}}"

        param_name = f'{param_prefix}_fld'
        params[param_name] = f'%{value}%'
        return f"{column} ilike {{{param_name}:String}}"

    return _build_search_blob_field_condition(field_lower, value, param_prefix, params)


SIGMA_EVENT_CONDITION = (
    "((rule_title IS NOT NULL AND rule_title != '') "
    "OR (rule_level IS NOT NULL AND rule_level != ''))"
)


def _build_sigma_alert_condition(severity_levels_param: str) -> str:
    """Build the SIGMA match condition, optionally narrowed by severity."""
    if not severity_levels_param:
        return SIGMA_EVENT_CONDITION

    if severity_levels_param == '__none__':
        return "0"

    levels_list = [level.strip().lower() for level in severity_levels_param.split(',') if level.strip()]
    if not levels_list:
        return SIGMA_EVENT_CONDITION

    normalized_buckets = set()
    for level in levels_list:
        if level in ('info', 'informational'):
            normalized_buckets.add('info')
        elif level == 'low':
            normalized_buckets.add('low')
        elif level in ('med', 'medium'):
            normalized_buckets.add('medium')
        elif level in ('high', 'crit', 'critical'):
            normalized_buckets.add('high')

    # When all severity buckets are selected, don't exclude title-only detections.
    if normalized_buckets == {'info', 'low', 'medium', 'high'}:
        return SIGMA_EVENT_CONDITION

    safe_rule_levels = []
    if 'info' in normalized_buckets:
        safe_rule_levels.extend(['informational', 'info'])
    if 'low' in normalized_buckets:
        safe_rule_levels.append('low')
    if 'medium' in normalized_buckets:
        safe_rule_levels.extend(['medium', 'med'])
    if 'high' in normalized_buckets:
        safe_rule_levels.extend(['high', 'critical', 'crit'])

    if not safe_rule_levels:
        return "0"

    quoted_levels = "', '".join(sorted(set(safe_rule_levels)))
    return f"({SIGMA_EVENT_CONDITION} AND lower(rule_level) IN ('{quoted_levels}'))"


def _build_hunting_alert_type_filter(
    sigma_filter_param: str,
    ioc_filter_param: str,
    analyst_filter_param: str,
    other_filter_param: str,
    severity_levels_param: str
) -> str:
    """Build an inclusive OR filter over the selected alert-type checkboxes."""
    selected_conditions = []

    if sigma_filter_param != 'exclude':
        selected_conditions.append(_build_sigma_alert_condition(severity_levels_param))

    if ioc_filter_param != 'exclude':
        selected_conditions.append("length(ioc_types) > 0")

    if analyst_filter_param != 'exclude':
        selected_conditions.append("analyst_tagged = true")

    if other_filter_param != 'exclude':
        selected_conditions.append(
            f"(NOT {SIGMA_EVENT_CONDITION} AND length(ioc_types) = 0 AND analyst_tagged = false)"
        )

    if not selected_conditions:
        return " AND 1=0"

    return f" AND ({' OR '.join(selected_conditions)})"


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


# ============================================
# File Management API Endpoints
# ============================================

@api_bp.route('/files/stats/<case_uuid>')
@login_required
def get_file_stats(case_uuid):
    """Get file statistics for a case"""
    try:
        from models.known_system import KnownSystem
        from models.known_user import KnownUser
        from utils.progress import get_progress

        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        stats = CaseFile.get_stats(case_uuid)
        stats['review'] = CaseFile.get_review_stats(case_uuid)

        latest_ingest = AuditLog.query.filter_by(
            case_uuid=case_uuid,
            entity_type=AuditEntityType.CASE_FILE,
            action=AuditAction.INGESTED,
        ).order_by(AuditLog.timestamp.desc()).first()
        stats['latest_ingest_summary'] = latest_ingest.to_dict()['details'] if latest_ingest else None
        stats['latest_ingest_at'] = latest_ingest.timestamp.isoformat() if latest_ingest else None

        progress = get_progress(case_uuid) or {}
        progress_status = progress.get('status', 'idle')
        known_systems = KnownSystem.query.filter_by(case_id=case.id).count()
        known_users = KnownUser.query.filter_by(case_id=case.id).count()
        all_files_finished = stats.get('total', 0) > 0 and stats.get('pending', 0) == 0
        completion_stalled = (
            all_files_finished
            and latest_ingest is None
            and progress_status in ('complete', 'waiting_for_completion')
        )
        stats['completion'] = {
            'progress_status': progress_status,
            'all_files_finished': all_files_finished,
            'has_ingest_summary': latest_ingest is not None,
            'stalled': completion_stalled,
            'repair_available': all_files_finished and latest_ingest is None,
            'known_systems': known_systems,
            'known_users': known_users,
        }

        latest_events = (((stats['latest_ingest_summary'] or {}).get('events') or {}).get('total'))
        if latest_events is not None:
            stats['events_total'] = latest_events
        else:
            try:
                from utils.clickhouse import count_events
                stats['events_total'] = count_events(case.id)
            except Exception as e:
                logger.warning(f"Could not load event count for file summary {case_uuid}: {e}")
                stats['events_total'] = 0
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
                    plugin_summary = job.plugin_summary()
                    memory_stats['total_plugins_run'] += plugin_summary.get('execution_total', 0)
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
            review_status = CaseFile.derive_review_status(
                filename=cf.filename or cf.original_filename,
                status=cf.status,
                ingestion_status=cf.ingestion_status,
                is_archive=cf.is_archive,
                retention_state=cf.retention_state,
                error_message=cf.error_message,
            )
            
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
                'error_message': cf.error_message,
                'status_detail': review_status.get('detail') or cf.error_message or '',
                'review_status': review_status,
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
            is_completing = status in (
                'waiting_for_completion',
                'flushing_buffer',
                'deduplicating',
                'discovering_systems',
                'discovering_users',
            )
            
            # Map new status to legacy completion_phase for backward compatibility
            completion_phase_map = {
                'waiting_for_completion': 'waiting_for_completion',
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
    """Queue an originals-based clean rebuild for the case."""
    try:
        from tasks.celery_tasks import reindex_case_task

        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404

        task = reindex_case_task.delay(
            case_uuid=case_uuid,
            case_id=case.id,
            username=current_user.username,
        )

        return jsonify({
            'success': True,
            'case_uuid': case_uuid,
            'task_id': task.id,
            'message': 'Originals-based case rebuild queued'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/files/repair-completion/<case_uuid>', methods=['POST'])
@login_required
def repair_case_completion(case_uuid):
    """Re-run post-ingest completion tasks for a finished case."""
    try:
        from tasks.celery_tasks import case_indexing_complete_task
        from utils.progress import clear_completion_trigger, get_progress, set_phase

        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404

        pending_count = CaseFile.query.filter(
            CaseFile.case_uuid == case_uuid,
            CaseFile.is_archive == False,
            CaseFile.status.in_(['new', 'queued', 'ingesting'])
        ).count()
        if pending_count > 0:
            return jsonify({
                'success': False,
                'error': f'{pending_count} files are still processing'
            }), 409

        progress = get_progress(case_uuid) or {}
        clear_completion_trigger(case_uuid)
        set_phase(case_uuid, 'waiting_for_completion')
        task = case_indexing_complete_task.delay(case_id=case.id, case_uuid=case_uuid)

        return jsonify({
            'success': True,
            'task_id': task.id,
            'case_uuid': case_uuid,
            'previous_progress_status': progress.get('status', 'idle'),
            'message': 'Post-ingest completion queued'
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
        JUNK_EXTENSIONS = {'.sqlite-wal', '.sqlite-shm', '.sqlite-journal'}
        orphans = []
        junk_count = 0
        unknown_count = 0
        for sf in staging_files:
            if sf['path'] not in db_paths:
                ext = os.path.splitext(sf['filename'])[1].lower()
                is_junk = ext in JUNK_EXTENSIONS
                if is_junk:
                    junk_count += 1
                else:
                    unknown_count += 1
                orphans.append({
                    'path': sf['path'],
                    'rel_path': sf['rel_path'],
                    'filename': sf['filename'],
                    'size': sf['size'],
                    'is_junk': is_junk
                })
        
        return jsonify({
            'success': True,
            'has_orphans': len(orphans) > 0,
            'orphan_count': len(orphans),
            'junk_count': junk_count,
            'unknown_count': unknown_count,
            'orphans': orphans[:100]
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
        from utils.artifact_paths import is_within_root
        
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
                        file_type=_default_upload_type_label(),
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
                    parser_hints=_get_parser_hints_for_case_file(cf),
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


@api_bp.route('/files/recover-stuck/<case_uuid>', methods=['POST'])
@login_required
def recover_stuck_files(case_uuid):
    """Recover files stuck in 'ingesting' or 'queued' status.
    
    Resets stuck files to 'new' and optionally re-queues them for parsing.
    Files are considered stuck if they've been in ingesting/queued for longer
    than the configured threshold (default 2 hours).
    """
    try:
        from tasks.celery_tasks import parse_file_task
        from utils.progress import init_progress
        
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        requeue = request.json.get('requeue', True) if request.is_json else True
        threshold_hours = request.json.get('threshold_hours', 2) if request.is_json else 2
        
        from datetime import timedelta
        cutoff = datetime.utcnow() - timedelta(hours=threshold_hours)
        
        stuck_files = CaseFile.query.filter(
            CaseFile.case_uuid == case_uuid,
            CaseFile.status.in_(['ingesting', 'queued']),
            CaseFile.uploaded_at < cutoff
        ).all()
        
        if not stuck_files:
            return jsonify({
                'success': True,
                'message': 'No stuck files found',
                'recovered': 0
            })
        
        recovered = []
        for cf in stuck_files:
            cf.status = 'new'
            cf.ingestion_status = 'not_done'
            cf.error_message = None
            cf.processed_at = None
            recovered.append({
                'id': cf.id,
                'filename': cf.filename,
                'previous_status': 'ingesting/queued',
                'file_exists': os.path.exists(cf.file_path) if cf.file_path else False
            })
        
        db.session.commit()
        
        queued_count = 0
        if requeue:
            files_to_queue = [cf for cf in stuck_files 
                             if cf.file_path and os.path.exists(cf.file_path)
                             and not cf.is_archive
                             and is_within_root(cf.file_path, os.path.join(Config.STAGING_FOLDER, case_uuid))]
            
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
                        parser_hints=_get_parser_hints_for_case_file(cf),
                    )
                    queued_count += 1
                
                db.session.commit()
        
        logger.info(f"Recovered {len(recovered)} stuck files for case {case_uuid}, re-queued {queued_count}")
        
        return jsonify({
            'success': True,
            'recovered': len(recovered),
            'requeued': queued_count,
            'requeue_note': 'Only files still present in transient staging were re-queued. Files already cleaned from staging require future reparse redesign.',
            'files': recovered
        })
        
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error recovering stuck files for case {case_uuid}")
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
        case = Case.get_by_id(case_id)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Get case timezone for display conversion
        case_tz = case.timezone or 'UTC'
        
        # Pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        search = request.args.get('search', '', type=str).strip()
        artifact_types = request.args.get('types', '', type=str).strip()
        sigma_filter_param = request.args.get('sigma_filter', '', type=str).strip()
        ioc_filter_param = request.args.get('ioc_filter', '', type=str).strip()
        analyst_filter_param = request.args.get('analyst_filter', '', type=str).strip()
        other_filter_param = request.args.get('other_filter', '', type=str).strip()
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
        if artifact_types == '__none__':
            type_filter = " AND 1=0"
        elif artifact_types:
            # Split comma-separated types and build IN clause
            types_list = [t.strip() for t in artifact_types.split(',') if t.strip()]
            if types_list:
                # Use tuple format for ClickHouse IN clause
                quoted_types = "', '".join(types_list)
                type_filter = f" AND artifact_type IN ('{quoted_types}')"
        
        # Alert type filters are inclusive: an event is shown if it matches
        # any checked alert type (SIGMA, IOC, analyst tag).
        alert_type_filter = _build_hunting_alert_type_filter(
            sigma_filter_param,
            ioc_filter_param,
            analyst_filter_param,
            other_filter_param,
            severity_levels_param
        )
        
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
                return _parse_event_field_value_condition(field, value, param_prefix, params)
            
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
                WHERE case_id = {{case_id:UInt32}}{search_clause}{type_filter}{alert_type_filter}{noise_filter}{time_filter}
            """
            data_query = f"""
                SELECT {event_columns}
                FROM events 
                WHERE case_id = {{case_id:UInt32}}{search_clause}{type_filter}{alert_type_filter}{noise_filter}{time_filter}
                ORDER BY timestamp DESC
                LIMIT {{limit:UInt32}} OFFSET {{offset:UInt32}}
            """
        else:
            count_query = f"SELECT count() FROM events WHERE case_id = {{case_id:UInt32}}{type_filter}{alert_type_filter}{noise_filter}{time_filter}"
            data_query = f"""
                SELECT {event_columns}
                FROM events 
                WHERE case_id = {{case_id:UInt32}}{type_filter}{alert_type_filter}{noise_filter}{time_filter}
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
        case = Case.get_by_id(case_id)
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
        case = Case.get_by_id(case_id)
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
        
        case = Case.get_by_id(case_id)
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
        
        case = Case.get_by_id(case_id)
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
        
        case = Case.get_by_id(case_id)
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
        
        case = Case.get_by_id(case_id)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        case_tz = case.timezone or 'UTC'
        client = get_client()
        
        # Get all filter parameters (same as get_hunting_events)
        search = request.args.get('search', '', type=str).strip()
        artifact_types = request.args.get('types', '', type=str).strip()
        sigma_filter_param = request.args.get('sigma_filter', '', type=str).strip()
        ioc_filter_param = request.args.get('ioc_filter', '', type=str).strip()
        analyst_filter_param = request.args.get('analyst_filter', '', type=str).strip()
        other_filter_param = request.args.get('other_filter', '', type=str).strip()
        severity_levels_param = request.args.get('severity_levels', '', type=str).strip()
        show_noise = request.args.get('show_noise', 'false', type=str).strip().lower() == 'true'
        time_range = request.args.get('time_range', 'none', type=str).strip()
        time_start = request.args.get('time_start', '', type=str).strip()
        time_end = request.args.get('time_end', '', type=str).strip()
        
        # Build artifact type filter
        type_filter = ""
        if artifact_types == '__none__':
            type_filter = " AND 1=0"
        elif artifact_types:
            types_list = [t.strip() for t in artifact_types.split(',') if t.strip()]
            if types_list:
                quoted_types = "', '".join(types_list)
                type_filter = f" AND artifact_type IN ('{quoted_types}')"
        
        # Match the live grid: keep events that satisfy any checked alert type.
        alert_type_filter = _build_hunting_alert_type_filter(
            sigma_filter_param,
            ioc_filter_param,
            analyst_filter_param,
            other_filter_param,
            severity_levels_param
        )
        
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
                return _parse_event_field_value_condition(field, value, param_prefix, params)
            
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
            WHERE case_id = {{case_id:UInt32}}{search_clause}{type_filter}{alert_type_filter}{noise_filter}{time_filter}
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
        
        case = Case.get_by_id(case_id)
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
        
        case = Case.get_by_id(case_id)
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
# Unified Process Hunting API Endpoints
# ============================================

@api_bp.route('/hunting/processes/list/<int:case_id>')
@login_required
def get_unified_processes(case_id):
    """Get unified process list from all sources (events, memory, EDR)
    
    Combines process data from:
    - ClickHouse events table (EVTX, EDR logs)
    - PostgreSQL memory_processes table (memory dumps)
    
    Returns deduplicated list with source attribution.
    """
    try:
        from utils.clickhouse import get_client
        from utils.timezone import format_for_display
        from models.memory_data import MemoryProcess
        from models.memory_job import MemoryJob
        
        case = Case.get_by_id(case_id)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        case_tz = case.timezone or 'UTC'
        
        # Pagination
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        per_page = min(per_page, 200)  # Cap at 200
        offset = (page - 1) * per_page
        
        # Filters
        search = request.args.get('search', '', type=str).strip()
        hostname_filter = request.args.get('hostname', '', type=str).strip()
        source_filter = request.args.get('source', '', type=str).strip()  # events, memory, or empty for all
        
        processes = []
        total_events = 0
        total_memory = 0
        
        # === EVENTS SOURCE (ClickHouse) ===
        if source_filter in ('', 'events'):
            client = get_client()
            
            # Build WHERE clause - filter for actual executable file names
            # This excludes garbage data like log messages stored in process_name field
            executable_filter = """(
                process_name LIKE '%.exe' OR 
                process_name LIKE '%.dll' OR 
                process_name LIKE '%.bat' OR 
                process_name LIKE '%.cmd' OR 
                process_name LIKE '%.ps1' OR 
                process_name LIKE '%.vbs' OR 
                process_name LIKE '%.com' OR 
                process_name LIKE '%.msi' OR
                process_name LIKE '%.js' OR
                process_name LIKE '%.wsf'
            )"""
            
            where_clauses = [
                "case_id = {case_id:UInt32}",
                "process_name != ''",
                "process_id > 0",
                executable_filter
            ]
            params = {'case_id': case_id}
            
            if hostname_filter:
                where_clauses.append("source_host = {hostname:String}")
                params['hostname'] = hostname_filter
            
            if search:
                where_clauses.append("(process_name ILIKE {search:String} OR command_line ILIKE {search:String} OR parent_process ILIKE {search:String})")
                params['search'] = f'%{search}%'
            
            where_sql = ' AND '.join(where_clauses)
            
            # Count query
            count_query = f"""
                SELECT count(DISTINCT (source_host, process_id, process_name))
                FROM events
                WHERE {where_sql}
            """
            count_result = client.query(count_query, parameters=params)
            total_events = count_result.result_rows[0][0] if count_result.result_rows else 0
            
            # Only fetch events if not filtering to memory only
            if source_filter != 'memory':
                # Main query - deduplicate by hostname + pid + process_name, take latest timestamp
                # Use unique aliases to avoid conflicts with WHERE clause column names
                query = f"""
                    SELECT 
                        source_host,
                        process_id,
                        process_name,
                        max(COALESCE(timestamp_utc, timestamp)) as latest_ts,
                        min(COALESCE(timestamp_utc, timestamp)) as first_ts,
                        argMax(parent_pid, COALESCE(timestamp_utc, timestamp)) as ppid_val,
                        argMax(parent_process, COALESCE(timestamp_utc, timestamp)) as parent_proc_val,
                        argMax(command_line, COALESCE(timestamp_utc, timestamp)) as cmdline_val,
                        argMax(username, COALESCE(timestamp_utc, timestamp)) as username_val,
                        argMax(process_path, COALESCE(timestamp_utc, timestamp)) as proc_path_val,
                        count() as event_count
                    FROM events
                    WHERE {where_sql}
                    GROUP BY source_host, process_id, process_name
                    ORDER BY latest_ts DESC
                    LIMIT {per_page} OFFSET {offset}
                """
                
                result = client.query(query, parameters=params)
                
                # Batch check for children - collect all PIDs first
                pid_list = [(row[0], row[1]) for row in result.result_rows]  # (hostname, pid)
                children_set = set()
                
                if pid_list:
                    # Check which PIDs have children in a single query
                    pids_str = ','.join([str(p[1]) for p in pid_list if p[1]])
                    if pids_str:
                        child_check_query = f"""
                            SELECT DISTINCT parent_pid
                            FROM events
                            WHERE case_id = {{case_id:UInt32}}
                            AND parent_pid IN ({pids_str})
                            AND process_name != ''
                        """
                        child_result = client.query(child_check_query, parameters={'case_id': case_id})
                        children_set = {row[0] for row in child_result.result_rows if row[0]}
                
                for row in result.result_rows:
                    hostname, pid, proc_name, latest_ts, first_ts, ppid, parent_proc, cmdline, username, proc_path, evt_count = row
                    
                    has_children = pid in children_set
                    has_parent = ppid and ppid > 0
                    
                    processes.append({
                        'id': f"evt_{hostname}_{pid}_{proc_name}",
                        'source': 'events',
                        'hostname': hostname,
                        'pid': pid,
                        'ppid': ppid,
                        'process_name': proc_name or '',
                        'parent_process': parent_proc or '',
                        'command_line': cmdline or '',
                        'username': username or '',
                        'process_path': proc_path or '',
                        'timestamp': format_for_display(latest_ts, case_tz) if latest_ts else '',
                        'first_seen': format_for_display(first_ts, case_tz) if first_ts else '',
                        'event_count': evt_count,
                        'has_children': has_children,
                        'has_parent': has_parent
                    })
        
        # === MEMORY SOURCE (PostgreSQL) ===
        if source_filter in ('', 'memory'):
            # Get completed memory jobs for this case
            jobs = MemoryJob.query.filter_by(case_id=case_id, status='completed').all()
            job_ids = [j.id for j in jobs]
            
            if job_ids:
                # Build query
                query = MemoryProcess.query.filter(
                    MemoryProcess.job_id.in_(job_ids),
                    MemoryProcess.case_id == case_id
                )
                
                if hostname_filter:
                    query = query.filter(MemoryProcess.hostname == hostname_filter)
                
                if search:
                    search_term = f'%{search}%'
                    query = query.filter(db.or_(
                        MemoryProcess.name.ilike(search_term),
                        MemoryProcess.cmdline.ilike(search_term),
                        MemoryProcess.path.ilike(search_term)
                    ))
                
                total_memory = query.count()
                
                if source_filter != 'events':
                    # Only paginate memory if not combined with events
                    if source_filter == 'memory':
                        mem_procs = query.order_by(MemoryProcess.create_time.desc()).offset(offset).limit(per_page).all()
                    else:
                        # For combined view, get all memory and we'll merge later
                        mem_procs = query.order_by(MemoryProcess.create_time.desc()).limit(500).all()
                    
                    # Get all memory processes to check parent/child relationships
                    all_pids_by_host = {}
                    all_ppids_by_host = {}
                    for mp in MemoryProcess.query.filter(MemoryProcess.job_id.in_(job_ids)).all():
                        host = mp.hostname
                        if host not in all_pids_by_host:
                            all_pids_by_host[host] = set()
                            all_ppids_by_host[host] = set()
                        all_pids_by_host[host].add(mp.pid)
                        if mp.ppid:
                            all_ppids_by_host[host].add(mp.ppid)
                    
                    for mp in mem_procs:
                        # Check if has children (any process has this PID as ppid)
                        has_children = mp.pid in all_ppids_by_host.get(mp.hostname, set())
                        # Check if has parent
                        has_parent = mp.ppid and mp.ppid in all_pids_by_host.get(mp.hostname, set())
                        
                        processes.append({
                            'id': f"mem_{mp.id}",
                            'source': 'memory',
                            'hostname': mp.hostname,
                            'pid': mp.pid,
                            'ppid': mp.ppid,
                            'process_name': mp.name or '',
                            'parent_process': '',  # Memory doesn't store parent name directly
                            'command_line': mp.cmdline or '',
                            'username': '',  # Would need SID lookup
                            'process_path': mp.path or '',
                            'timestamp': format_for_display(mp.create_time, case_tz) if mp.create_time else '',
                            'first_seen': '',
                            'event_count': 1,
                            'has_children': has_children,
                            'has_parent': has_parent,
                            'cross_memory_count': mp.cross_memory_count,
                            'cross_events_count': mp.cross_events_count
                        })
        
        # Sort combined results by timestamp
        processes.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        # If combined source, limit to per_page
        if source_filter == '':
            processes = processes[:per_page]
        
        total = total_events + total_memory
        
        return jsonify({
            'success': True,
            'processes': processes,
            'total': total,
            'total_events': total_events,
            'total_memory': total_memory,
            'page': page,
            'per_page': per_page,
            'pages': (total + per_page - 1) // per_page if total > 0 else 0
        })
        
    except Exception as e:
        logger.error(f"Error fetching unified processes: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/hunting/processes/tree/<int:case_id>')
@login_required
def get_unified_process_tree(case_id):
    """Get process tree for a specific process from all sources
    
    Returns the process, its children, and optionally its parent chain.
    Combines data from events and memory sources.
    """
    try:
        from utils.clickhouse import get_client
        from utils.timezone import format_for_display
        from models.memory_data import MemoryProcess
        from models.memory_job import MemoryJob
        
        case = Case.get_by_id(case_id)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        case_tz = case.timezone or 'UTC'
        
        hostname = request.args.get('hostname', '', type=str).strip()
        pid = request.args.get('pid', 0, type=int)
        process_name = request.args.get('process_name', '', type=str).strip()
        include_parent = request.args.get('include_parent', 'true', type=str).lower() == 'true'
        max_depth = min(request.args.get('max_depth', 5, type=int), 10)  # Cap at 10
        
        if not hostname or not pid:
            return jsonify({'success': False, 'error': 'hostname and pid are required'}), 400
        
        client = get_client()
        
        def get_process_from_events(host, p_id, p_name=None):
            """Fetch process details from events"""
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
            params = {'case_id': case_id, 'hostname': host, 'pid': p_id}
            
            if p_name:
                query += " AND process_name = {process_name:String}"
                params['process_name'] = p_name
            
            query += " GROUP BY source_host, process_id, process_name LIMIT 1"
            
            result = client.query(query, parameters=params)
            if result.result_rows:
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
                    'process_path': row[8] or ''
                }
            return None
        
        def get_children_from_events(host, parent_pid_val, parent_name=None, depth=0):
            """Fetch children from events - matching on BOTH parent_pid AND parent_process name"""
            if depth >= max_depth:
                return []
            
            # Match on both parent_pid AND parent_process to avoid PID reuse issues
            query = """
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
            """
            params = {
                'case_id': case_id, 
                'hostname': host, 
                'parent_pid': parent_pid_val,
                'parent_process': parent_name or ''
            }
            
            result = client.query(query, parameters=params)
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
                    'children': get_children_from_events(host, row[1], row[2], depth + 1)
                }
                children.append(child)
            
            return children
        
        def get_children_from_memory(host, parent_pid, depth=0):
            """Recursively fetch children from memory"""
            if depth >= max_depth:
                return []
            
            jobs = MemoryJob.query.filter_by(case_id=case_id, status='completed').all()
            job_ids = [j.id for j in jobs]
            
            if not job_ids:
                return []
            
            children_query = MemoryProcess.query.filter(
                MemoryProcess.job_id.in_(job_ids),
                MemoryProcess.hostname == host,
                MemoryProcess.ppid == parent_pid
            ).all()
            
            children = []
            for mp in children_query:
                child = {
                    'source': 'memory',
                    'hostname': mp.hostname,
                    'pid': mp.pid,
                    'process_name': mp.name or '',
                    'timestamp': format_for_display(mp.create_time, case_tz) if mp.create_time else '',
                    'ppid': mp.ppid,
                    'parent_process': '',
                    'command_line': mp.cmdline or '',
                    'username': '',
                    'children': get_children_from_memory(host, mp.pid, depth + 1)
                }
                children.append(child)
            
            return children
        
        # Get the main process
        process = get_process_from_events(hostname, pid, process_name)
        
        # If not found in events, try memory
        if not process:
            jobs = MemoryJob.query.filter_by(case_id=case_id, status='completed').all()
            job_ids = [j.id for j in jobs]
            
            if job_ids:
                mp = MemoryProcess.query.filter(
                    MemoryProcess.job_id.in_(job_ids),
                    MemoryProcess.hostname == hostname,
                    MemoryProcess.pid == pid
                ).first()
                
                if mp:
                    process = {
                        'source': 'memory',
                        'hostname': mp.hostname,
                        'pid': mp.pid,
                        'process_name': mp.name or '',
                        'timestamp': format_for_display(mp.create_time, case_tz) if mp.create_time else '',
                        'ppid': mp.ppid,
                        'parent_process': '',
                        'command_line': mp.cmdline or '',
                        'username': '',
                        'process_path': mp.path or ''
                    }
        
        if not process:
            return jsonify({'success': False, 'error': 'Process not found'}), 404
        
        # Get children from both sources
        children_events = get_children_from_events(hostname, pid, process_name)
        children_memory = get_children_from_memory(hostname, pid)
        
        # Merge children (dedupe by pid + name)
        seen = set()
        all_children = []
        for child in children_events + children_memory:
            key = (child['pid'], child['process_name'])
            if key not in seen:
                seen.add(key)
                all_children.append(child)
        
        process['children'] = all_children
        
        # Get parent chain if requested
        parent_chain = None
        if include_parent and process.get('ppid'):
            parent_chain = []
            current_ppid = process.get('ppid')
            current_parent_name = process.get('parent_process', '')
            
            for _ in range(max_depth):
                if not current_ppid or current_ppid <= 0:
                    break
                
                parent = get_process_from_events(hostname, current_ppid, current_parent_name if current_parent_name else None)
                
                if not parent:
                    # Try memory
                    jobs = MemoryJob.query.filter_by(case_id=case_id, status='completed').all()
                    job_ids = [j.id for j in jobs]
                    
                    if job_ids:
                        mp = MemoryProcess.query.filter(
                            MemoryProcess.job_id.in_(job_ids),
                            MemoryProcess.hostname == hostname,
                            MemoryProcess.pid == current_ppid
                        ).first()
                        
                        if mp:
                            parent = {
                                'source': 'memory',
                                'hostname': mp.hostname,
                                'pid': mp.pid,
                                'process_name': mp.name or '',
                                'timestamp': format_for_display(mp.create_time, case_tz) if mp.create_time else '',
                                'ppid': mp.ppid,
                                'parent_process': '',
                                'command_line': mp.cmdline or '',
                                'username': ''
                            }
                
                if parent:
                    parent_chain.append(parent)
                    current_ppid = parent.get('ppid')
                    current_parent_name = parent.get('parent_process', '')
                else:
                    # Parent not found in our data
                    parent_chain.append({
                        'source': 'unknown',
                        'hostname': hostname,
                        'pid': current_ppid,
                        'process_name': current_parent_name or f'PID {current_ppid}',
                        'timestamp': '',
                        'ppid': None,
                        'parent_process': '',
                        'command_line': '',
                        'username': '',
                        'not_found': True
                    })
                    break
        
        return jsonify({
            'success': True,
            'process': process,
            'parent_chain': parent_chain,
            'hostname': hostname
        })
        
    except Exception as e:
        logger.error(f"Error fetching process tree: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/hunting/processes/hostnames/<int:case_id>')
@login_required
def get_process_hostnames(case_id):
    """Get unique hostnames that have process data"""
    try:
        from utils.clickhouse import get_client
        from models.memory_data import MemoryProcess
        from models.memory_job import MemoryJob
        
        case = Case.get_by_id(case_id)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        hostnames = set()
        
        # From events - filter for actual executables
        client = get_client()
        query = """
            SELECT DISTINCT source_host
            FROM events
            WHERE case_id = {case_id:UInt32}
            AND process_name != ''
            AND process_id > 0
            AND (
                process_name LIKE '%.exe' OR 
                process_name LIKE '%.dll' OR 
                process_name LIKE '%.bat' OR 
                process_name LIKE '%.cmd' OR 
                process_name LIKE '%.ps1' OR 
                process_name LIKE '%.vbs' OR 
                process_name LIKE '%.com' OR 
                process_name LIKE '%.msi'
            )
        """
        result = client.query(query, parameters={'case_id': case_id})
        for row in result.result_rows:
            if row[0]:
                hostnames.add(row[0])
        
        # From memory
        jobs = MemoryJob.query.filter_by(case_id=case_id, status='completed').all()
        job_ids = [j.id for j in jobs]
        
        if job_ids:
            mem_hosts = db.session.query(MemoryProcess.hostname).filter(
                MemoryProcess.job_id.in_(job_ids)
            ).distinct().all()
            for row in mem_hosts:
                if row[0]:
                    hostnames.add(row[0])
        
        return jsonify({
            'success': True,
            'hostnames': sorted(list(hostnames))
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500



