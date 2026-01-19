"""Memory Forensics API routes for CaseScope"""
import os
import re
from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from datetime import datetime

from models.database import db
from models.case import Case
from models.memory_job import (
    MemoryJob, MemoryOS, MemoryType, VOLATILITY_PLUGINS, 
    get_default_plugins
)
from config import Config

memory_bp = Blueprint('memory', __name__, url_prefix='/api/memory')


def ensure_memory_dir(case_uuid):
    """Ensure the memory upload directory exists for a case
    
    Uses the same folder structure as file uploads: /opt/casescope/uploads/sftp/{case_uuid}/memory/
    """
    case_memory_path = os.path.join(Config.UPLOAD_FOLDER_SFTP, case_uuid, 'memory')
    os.makedirs(case_memory_path, exist_ok=True)
    return case_memory_path


@memory_bp.route('/folder/<case_uuid>', methods=['GET'])
@login_required
def get_memory_folder(case_uuid):
    """Get the memory upload folder path for a case"""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        folder_path = ensure_memory_dir(case_uuid)
        
        return jsonify({
            'success': True,
            'folder_path': folder_path
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@memory_bp.route('/scan/<case_uuid>', methods=['GET'])
@login_required
def scan_memory_folder(case_uuid):
    """Scan the memory upload folder for files"""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        folder_path = ensure_memory_dir(case_uuid)
        
        files = []
        if os.path.exists(folder_path):
            for root, dirs, filenames in os.walk(folder_path):
                for filename in filenames:
                    filepath = os.path.join(root, filename)
                    try:
                        stat = os.stat(filepath)
                        # Get relative path from the case folder
                        rel_path = os.path.relpath(filepath, folder_path)
                        
                        mem_type = detect_memory_type(filename)
                        files.append({
                            'name': filename,
                            'path': filepath,
                            'relative_path': rel_path,
                            'size': stat.st_size,
                            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            'type': mem_type,
                            'detected_hostname': detect_hostname_from_filename(filename),
                            'detected_os': detect_os_from_type(mem_type)
                        })
                    except (OSError, IOError) as e:
                        # Skip files we can't access
                        continue
        
        # Sort by name
        files.sort(key=lambda x: x['name'].lower())
        
        return jsonify({
            'success': True,
            'files': files,
            'folder_path': folder_path,
            'total_count': len(files)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@memory_bp.route('/clear/<case_uuid>', methods=['POST'])
@login_required
def clear_memory_folder(case_uuid):
    """Clear all files from the memory upload folder"""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        folder_path = ensure_memory_dir(case_uuid)
        
        deleted_count = 0
        errors = []
        
        if os.path.exists(folder_path):
            for root, dirs, filenames in os.walk(folder_path, topdown=False):
                for filename in filenames:
                    filepath = os.path.join(root, filename)
                    try:
                        os.remove(filepath)
                        deleted_count += 1
                    except Exception as e:
                        errors.append(f"{filename}: {str(e)}")
                
                # Remove empty directories (but not the case root)
                for dirname in dirs:
                    dirpath = os.path.join(root, dirname)
                    try:
                        os.rmdir(dirpath)
                    except:
                        pass  # Directory not empty or can't be removed
        
        return jsonify({
            'success': True,
            'deleted_count': deleted_count,
            'errors': errors
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


def detect_memory_type(filename):
    """Detect the type of memory dump from filename"""
    filename_lower = filename.lower()
    
    # Memory dump types
    if filename_lower.endswith('.dmp') or filename_lower.endswith('.dump'):
        if 'mini' in filename_lower:
            return 'Minidump'
        elif 'kernel' in filename_lower:
            return 'Kernel Dump'
        elif 'complete' in filename_lower or 'full' in filename_lower:
            return 'Complete Dump'
        return 'Memory Dump'
    
    if filename_lower.endswith('.raw') or filename_lower.endswith('.mem'):
        return 'Raw Memory'
    
    if filename_lower.endswith('.vmem'):
        return 'VMware Memory'
    
    if filename_lower.endswith('.lime'):
        return 'LiME Dump'
    
    if filename_lower.endswith('.elf') or filename_lower.endswith('.core'):
        return 'ELF Core Dump'
    
    if 'hiberfil' in filename_lower:
        return 'Hibernation File'
    
    if 'pagefile' in filename_lower:
        return 'Page File'
    
    if 'swapfile' in filename_lower:
        return 'Swap File'
    
    if filename_lower.endswith('.e01') or filename_lower.endswith('.ex01'):
        return 'EnCase Image'
    
    if filename_lower.endswith('.aff') or filename_lower.endswith('.aff4'):
        return 'AFF Image'
    
    # Common related files
    if filename_lower.endswith('.json'):
        return 'JSON Data'
    
    if filename_lower.endswith('.txt') or filename_lower.endswith('.log'):
        return 'Log/Text'
    
    if filename_lower.endswith('.csv'):
        return 'CSV Data'
    
    if filename_lower.endswith('.zip') or filename_lower.endswith('.gz') or filename_lower.endswith('.7z'):
        return 'Archive'
    
    return 'Unknown'


def detect_hostname_from_filename(filename: str) -> str:
    """Try to extract hostname from filename patterns"""
    # Common patterns: HOSTNAME_date.ext, HOSTNAME-memory.raw, etc.
    patterns = [
        r'^([A-Za-z0-9_-]+?)[-_](?:memory|memdump|dump|raw|\d{8})',
        r'^([A-Za-z0-9_-]+?)[-_]\d{4}[-_]\d{2}',
        r'^([A-Za-z0-9-]+)\.',
    ]
    
    for pattern in patterns:
        match = re.match(pattern, filename, re.IGNORECASE)
        if match:
            hostname = match.group(1).upper()
            # Filter out common non-hostname prefixes
            if hostname.lower() not in ['memory', 'memdump', 'dump', 'raw', 'full']:
                return hostname
    
    return ''


def detect_os_from_type(memory_type: str) -> str:
    """Guess OS based on memory type"""
    linux_types = ['LiME Dump', 'ELF Core Dump']
    if memory_type in linux_types:
        return 'linux'
    # Default to Windows for most forensic cases
    return 'windows'


@memory_bp.route('/plugins/<os_type>', methods=['GET'])
@login_required
def get_plugins(os_type):
    """Get available plugins for an OS type"""
    try:
        if os_type not in VOLATILITY_PLUGINS:
            return jsonify({'success': False, 'error': f'Unknown OS type: {os_type}'}), 400
        
        plugins = VOLATILITY_PLUGINS[os_type]
        
        return jsonify({
            'success': True,
            'os_type': os_type,
            'plugins': plugins
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@memory_bp.route('/submit/<case_uuid>', methods=['POST'])
@login_required
def submit_job(case_uuid):
    """Submit a memory dump for processing"""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        # Required fields
        source_file = data.get('source_file')
        hostname = data.get('hostname')
        os_type = data.get('os_type')
        memory_type = data.get('memory_type')
        selected_plugins = data.get('selected_plugins', [])
        
        if not all([source_file, hostname, os_type, memory_type]):
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400
        
        # Validate file exists
        if not os.path.exists(source_file):
            return jsonify({'success': False, 'error': 'Source file not found'}), 400
        
        # Get file info
        stat = os.stat(source_file)
        filename = os.path.basename(source_file)
        
        # Create job record
        job = MemoryJob(
            case_id=case.id,
            source_file=source_file,
            source_filename=filename,
            file_size=stat.st_size,
            hostname=hostname.upper(),
            os_type=os_type,
            memory_type=memory_type,
            selected_plugins=selected_plugins,
            status='pending',
            created_by=current_user.username
        )
        
        db.session.add(job)
        db.session.commit()
        
        # Queue the Celery task
        from tasks.memory_tasks import process_memory_dump
        task = process_memory_dump.delay(job.id)
        
        # Update job with task ID
        job.celery_task_id = task.id
        db.session.commit()
        
        return jsonify({
            'success': True,
            'job_id': job.id,
            'task_id': task.id,
            'message': f'Job queued for processing with {len(selected_plugins)} plugins'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@memory_bp.route('/jobs/<case_uuid>', methods=['GET'])
@login_required
def list_jobs(case_uuid):
    """List all memory jobs for a case"""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        jobs = MemoryJob.query.filter_by(case_id=case.id)\
            .order_by(MemoryJob.created_at.desc()).all()
        
        return jsonify({
            'success': True,
            'jobs': [job.to_dict() for job in jobs]
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@memory_bp.route('/job/<int:job_id>', methods=['GET'])
@login_required
def get_job(job_id):
    """Get details of a specific job"""
    try:
        job = MemoryJob.query.get(job_id)
        if not job:
            return jsonify({'success': False, 'error': 'Job not found'}), 404
        
        # Get real-time progress from Redis if job is running
        job_data = job.to_dict()
        if job.status == 'running':
            from tasks.memory_tasks import get_job_progress
            redis_progress = get_job_progress(job_id)
            if redis_progress:
                job_data['progress'] = int(redis_progress.get('progress', job.progress))
                job_data['current_plugin'] = redis_progress.get('current_plugin', job.current_plugin)
        
        return jsonify({
            'success': True,
            'job': job_data
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@memory_bp.route('/job/<int:job_id>/cancel', methods=['POST'])
@login_required
def cancel_job(job_id):
    """Cancel a running or pending job"""
    try:
        job = MemoryJob.query.get(job_id)
        if not job:
            return jsonify({'success': False, 'error': 'Job not found'}), 404
        
        if job.status not in ['pending', 'running']:
            return jsonify({'success': False, 'error': 'Job cannot be cancelled'}), 400
        
        # Try to revoke the Celery task
        if job.celery_task_id:
            from celery import current_app
            current_app.control.revoke(job.celery_task_id, terminate=True)
        
        job.status = 'cancelled'
        job.completed_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Job cancelled'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@memory_bp.route('/job/<int:job_id>/results', methods=['GET'])
@login_required
def get_job_results(job_id):
    """Get the output files from a completed job"""
    try:
        job = MemoryJob.query.get(job_id)
        if not job:
            return jsonify({'success': False, 'error': 'Job not found'}), 404
        
        if job.status != 'completed':
            return jsonify({'success': False, 'error': 'Job not completed'}), 400
        
        results = []
        vol3_output = os.path.join(job.output_folder, 'vol3_output')
        
        if os.path.exists(vol3_output):
            for filename in os.listdir(vol3_output):
                filepath = os.path.join(vol3_output, filename)
                if os.path.isfile(filepath):
                    stat = os.stat(filepath)
                    results.append({
                        'filename': filename,
                        'path': filepath,
                        'size': stat.st_size,
                        'plugin': filename.replace('.json', '').replace('_', '.')
                    })
        
        return jsonify({
            'success': True,
            'job_id': job_id,
            'output_folder': job.output_folder,
            'results': results,
            'plugins_completed': job.plugins_completed,
            'plugins_failed': job.plugins_failed
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@memory_bp.route('/os-types', methods=['GET'])
@login_required  
def get_os_types():
    """Get available OS types"""
    return jsonify({
        'success': True,
        'os_types': MemoryOS.choices()
    })


@memory_bp.route('/memory-types', methods=['GET'])
@login_required
def get_memory_types():
    """Get available memory dump types"""
    return jsonify({
        'success': True,
        'memory_types': MemoryType.choices()
    })
