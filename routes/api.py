"""API routes for CaseScope"""
import os
import platform
import subprocess
import shutil
from datetime import datetime
from flask import Blueprint, jsonify, request
from flask_login import login_required
from models.database import db
from models.user import User
from models.case import Case
from config import Config

api_bp = Blueprint('api', __name__, url_prefix='/api')


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
        
        # Software versions
        software = {
            'python': platform.python_version(),
            'flask': get_software_version("pip show flask | grep Version | cut -d' ' -f2"),
            'postgresql': get_software_version("psql --version | head -1"),
            'casescope': '3.1.0'
        }
        
        # Case statistics (placeholder until cases are implemented)
        total_cases = 0
        total_events = 0
        total_users = User.query.count()
        
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


def ensure_upload_dirs(case_uuid):
    """Ensure upload directories exist for a case"""
    web_path = os.path.join(WEB_UPLOAD_DIR, case_uuid)
    sftp_path = os.path.join(SFTP_UPLOAD_DIR, case_uuid)
    
    os.makedirs(web_path, exist_ok=True)
    os.makedirs(sftp_path, exist_ok=True)
    os.makedirs(CHUNK_TEMP_DIR, exist_ok=True)
    
    # Set permissions to casescope user
    try:
        shutil.chown(web_path, user='casescope', group='casescope')
        shutil.chown(sftp_path, user='casescope', group='casescope')
    except (PermissionError, LookupError):
        pass  # May not have permission to chown
    
    return web_path, sftp_path


@api_bp.route('/upload/scan/<case_uuid>')
@login_required
def scan_upload_folder(case_uuid):
    """Scan the SFTP folder for uploaded files"""
    try:
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        _, sftp_path = ensure_upload_dirs(case_uuid)
        
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
    """Handle chunked file upload"""
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
        web_path, _ = ensure_upload_dirs(case_uuid)
        
        # Create temp directory for this upload
        temp_dir = os.path.join(CHUNK_TEMP_DIR, upload_id)
        os.makedirs(temp_dir, exist_ok=True)
        
        # Save chunk
        chunk_path = os.path.join(temp_dir, f'chunk_{chunk_index:06d}')
        chunk.save(chunk_path)
        
        # Check if all chunks are uploaded
        existing_chunks = len([f for f in os.listdir(temp_dir) if f.startswith('chunk_')])
        
        if existing_chunks >= total_chunks:
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
            
            # Clean up temp directory
            shutil.rmtree(temp_dir, ignore_errors=True)
            
            # Set file ownership
            try:
                shutil.chown(final_path, user='casescope', group='casescope')
            except (PermissionError, LookupError):
                pass
            
            return jsonify({
                'success': True,
                'complete': True,
                'path': final_path
            })
        
        return jsonify({
            'success': True,
            'complete': False,
            'chunksReceived': existing_chunks
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/upload/ingest', methods=['POST'])
@login_required
def ingest_files():
    """Queue files for ingestion processing"""
    try:
        data = request.get_json()
        case_uuid = data.get('caseUuid')
        files = data.get('files', [])
        
        if not case_uuid:
            return jsonify({'success': False, 'error': 'Case UUID required'}), 400
        
        if not files:
            return jsonify({'success': False, 'error': 'No files to ingest'}), 400
        
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # For now, just log the ingestion request
        # In the future, this will queue Celery tasks for processing
        ingested_count = 0
        for file_info in files:
            # TODO: Create ingestion task for each file
            # This will be implemented when we add the parsers
            ingested_count += 1
        
        return jsonify({
            'success': True,
            'count': ingested_count,
            'message': f'Queued {ingested_count} files for ingestion'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
