"""Memory Forensics API routes for CaseScope"""
import os
import re
import shutil
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
from utils.artifact_paths import (
    ensure_case_artifact_paths,
    ensure_case_originals_subdir,
    ensure_case_subdir,
    is_within_any_root,
    move_to_directory,
)

memory_bp = Blueprint('memory', __name__, url_prefix='/api/memory')


def ensure_memory_dir(case_uuid):
    """Ensure the memory upload directory exists for a case
    
    Uses the same folder structure as file uploads: /opt/casescope/uploads/sftp/{case_uuid}/memory/
    """
    return ensure_case_artifact_paths(case_uuid)['memory_upload']


def ensure_memory_staging_dir(case_uuid):
    """Ensure the transient memory staging directory exists for a case."""
    return ensure_case_artifact_paths(case_uuid)['memory_staging']


def ensure_memory_originals_dir(case_uuid, *parts):
    """Ensure the retained originals directory exists for memory uploads."""
    return ensure_case_originals_subdir(case_uuid, 'memory', *parts)


def _viewer_write_error():
    return jsonify({'success': False, 'error': 'Viewers cannot modify memory artifacts'}), 403


def _get_memory_job_for_user(job_id: int):
    """Load a memory job and enforce case access."""
    job = MemoryJob.query.get(job_id)
    if not job:
        return None

    case = Case.query.get(job.case_id)
    if not case:
        return None

    if not current_user.can_access_case(case.id):
        return False

    return job


def _get_memory_no_data_reason(job_dict: dict) -> str:
    """Explain why a completed memory job has no huntable data."""
    summary = job_dict.get('plugin_summary') or {}

    if summary.get('unsupported_total') and not summary.get('ingested_total'):
        return 'Unsupported-only output'
    if summary.get('zero_row_total') and not summary.get('ingested_total'):
        return 'No matching rows'
    if summary.get('failed_total') and not summary.get('completed_total'):
        return 'Plugin failure'
    return 'No ingested data'


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
    if current_user.permission_level == 'viewer':
        return _viewer_write_error()

    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        folder_path = ensure_memory_dir(case_uuid)
        
        retained_count = 0
        errors = []
        retained_dir = ensure_memory_originals_dir(case_uuid, 'cleared_uploads')
        
        if os.path.exists(folder_path):
            for root, dirs, filenames in os.walk(folder_path, topdown=False):
                for filename in filenames:
                    filepath = os.path.join(root, filename)
                    try:
                        retained_name = f"cleared_{datetime.utcnow().strftime('%Y%m%d_%H%M%S_%f')}_{filename}"
                        if move_to_directory(filepath, retained_dir, retained_name):
                            retained_count += 1
                        else:
                            errors.append(f"{filename}: failed to retain file")
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
            'deleted_count': retained_count,
            'retained_count': retained_count,
            'errors': errors
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


def ensure_memory_web_upload_dir(case_uuid):
    """Ensure the memory web upload directory exists for a case
    
    Web uploads go to: /opt/casescope/uploads/web/{case_uuid}/memory/
    This is separate from SFTP uploads for organization.
    """
    return ensure_case_artifact_paths(case_uuid)['memory_web_upload']


@memory_bp.route('/upload/chunk', methods=['POST'])
@login_required
def upload_chunk():
    """Handle chunked file upload for memory files
    
    Memory files are large (often 4-64GB), so chunked upload is essential.
    Files are uploaded to web upload folder, then scanned for processing.
    
    Case UUID is saved to a metadata file on the first chunk so that
    subsequent chunks can recover if the browser sends incomplete form data
    (observed on the final chunk of very large files).
    """
    import fcntl
    import glob
    import json as _json
    try:
        if current_user.permission_level == 'viewer':
            return _viewer_write_error()

        chunk = request.files.get('chunk')
        chunk_index = request.form.get('chunkIndex', type=int)
        total_chunks = request.form.get('totalChunks', type=int)
        upload_id = request.form.get('uploadId', '').strip()
        filename = os.path.basename(request.form.get('filename', '').strip())
        case_uuid = request.form.get('caseUuid', '').strip()
        
        if not all([chunk, chunk_index is not None, total_chunks, upload_id]):
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400
        
        # Upload metadata is stored in a fixed location keyed by upload_id
        # so subsequent chunks can recover if the browser sends incomplete form data
        # (observed on the final chunk of very large multi-GB files)
        # Recover case_uuid/filename from saved metadata if missing from form data
        if case_uuid:
            upload_meta_dir = ensure_case_artifact_paths(case_uuid)['memory_upload_meta']
            meta_file = os.path.join(upload_meta_dir, f'{upload_id}.json')
        else:
            upload_meta_dir = None
            meta_file = None
            meta_matches = glob.glob(os.path.join(
                Config.UPLOAD_FOLDER_SFTP,
                '*',
                'memory',
                '.upload_meta',
                f'{upload_id}.json'
            ))
            if meta_matches:
                meta_file = meta_matches[0]

        if not case_uuid or not filename:
            if meta_file and os.path.exists(meta_file):
                try:
                    with open(meta_file, 'r') as f:
                        meta = _json.load(f)
                    case_uuid = case_uuid or meta.get('case_uuid', '')
                    filename = filename or os.path.basename(meta.get('filename', ''))
                except Exception:
                    pass
        
        if not all([filename, case_uuid]):
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400
        
        # Verify case exists
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404

        upload_meta_dir = ensure_case_artifact_paths(case_uuid)['memory_upload_meta']
        meta_file = os.path.join(upload_meta_dir, f'{upload_id}.json')
        
        # Create upload directory - use SFTP memory folder for consistency
        upload_path = ensure_memory_dir(case_uuid)
        temp_dir = os.path.join(upload_path, f'.temp_{upload_id}')
        os.makedirs(temp_dir, exist_ok=True)
        
        # Save upload metadata on first chunk so later chunks can recover
        if not os.path.exists(meta_file):
            try:
                with open(meta_file, 'w') as f:
                    _json.dump({'case_uuid': case_uuid, 'filename': filename}, f)
            except Exception:
                pass
        
        # Save chunk
        chunk_path = os.path.join(temp_dir, f'chunk_{chunk_index:06d}')
        chunk.save(chunk_path)
        
        # Check if all chunks received
        received_chunks = len([f for f in os.listdir(temp_dir) if f.startswith('chunk_')])
        
        if received_chunks >= total_chunks:
            lock_file_path = os.path.join(temp_dir, '.combine_lock')
            try:
                with open(lock_file_path, 'w') as lock_file:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

                    received_chunks = len([f for f in os.listdir(temp_dir) if f.startswith('chunk_')])
                    if received_chunks < total_chunks:
                        return jsonify({
                            'success': True,
                            'complete': False,
                            'received': received_chunks,
                            'total': total_chunks
                        })

                    final_path = os.path.join(upload_path, filename)
                    if os.path.exists(final_path):
                        base, ext = os.path.splitext(filename)
                        counter = 1
                        while os.path.exists(final_path):
                            final_path = os.path.join(upload_path, f'{base}_{counter}{ext}')
                            counter += 1

                    with open(final_path, 'wb') as outfile:
                        for i in range(total_chunks):
                            chunk_file = os.path.join(temp_dir, f'chunk_{i:06d}')
                            with open(chunk_file, 'rb') as infile:
                                outfile.write(infile.read())

                    try:
                        shutil.chown(final_path, user='casescope', group='casescope')
                    except (PermissionError, LookupError):
                        pass

                    shutil.rmtree(temp_dir, ignore_errors=True)
                    try:
                        os.remove(meta_file)
                    except OSError:
                        pass

                    return jsonify({
                        'success': True,
                        'complete': True,
                        'filename': os.path.basename(final_path),
                        'path': final_path
                    })
            except BlockingIOError:
                return jsonify({
                    'success': True,
                    'complete': False,
                    'received': received_chunks,
                    'total': total_chunks,
                    'combining': True
                })
        
        return jsonify({
            'success': True,
            'complete': False,
            'received': received_chunks,
            'total': total_chunks
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
        if current_user.permission_level == 'viewer':
            return _viewer_write_error()

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

        allowed_plugins = {
            plugin['name']
            for category_plugins in VOLATILITY_PLUGINS.get(os_type, {}).values()
            for plugin in category_plugins
        }
        invalid_plugins = [plugin for plugin in selected_plugins if plugin not in allowed_plugins]
        if invalid_plugins:
            return jsonify({'success': False, 'error': f'Invalid plugins selected: {", ".join(invalid_plugins)}'}), 400

        case_paths = ensure_case_artifact_paths(case_uuid)
        allowed_roots = [
            case_paths['memory_upload'],
            case_paths['memory_web_upload'],
            case_paths['sftp_upload'],
            case_paths['web_upload'],
            case_paths['originals'],
            case_paths['storage'],
        ]
        if not is_within_any_root(source_file, allowed_roots):
            return jsonify({'success': False, 'error': 'Source file must belong to this case'}), 400
        
        # Get file info
        stat = os.stat(source_file)
        filename = os.path.basename(source_file)
        retained_source = source_file
        if not is_within_any_root(source_file, [case_paths['originals'], case_paths['storage']]):
            retained_dir = ensure_memory_originals_dir(case_uuid)
            moved_path = move_to_directory(source_file, retained_dir, filename)
            if not moved_path:
                return jsonify({'success': False, 'error': 'Failed to retain source file in originals'}), 500
            retained_source = moved_path
        
        # Create job record
        job = MemoryJob(
            case_id=case.id,
            source_file=retained_source,
            original_source_file=source_file,
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
        job = _get_memory_job_for_user(job_id)
        if job is False:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
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
        job = _get_memory_job_for_user(job_id)
        if job is False:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
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
        job = _get_memory_job_for_user(job_id)
        if job is False:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
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
            'plugins_failed': job.plugins_failed,
            'plugin_results': job.plugin_results(),
            'plugin_summary': job.plugin_summary(),
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


# ============================================================================
# MEMORY HUNTING DATA ROUTES
# ============================================================================

from models.memory_data import (
    MemoryProcess, MemoryNetwork, MemoryService, MemoryMalfind,
    MemoryModule, MemoryCredential, MemorySID, MemoryInfo
)


@memory_bp.route('/job/<int:job_id>/ingest', methods=['POST'])
@login_required
def ingest_job(job_id):
    """Ingest Vol3 JSON output into database tables"""
    try:
        if current_user.permission_level == 'viewer':
            return _viewer_write_error()

        job = _get_memory_job_for_user(job_id)
        if job is False:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        if not job:
            return jsonify({'success': False, 'error': 'Job not found'}), 404

        from parsers.memory_parser import ingest_memory_job
        result = ingest_memory_job(job_id)
        
        if result['success']:
            return jsonify(result)
        else:
            return jsonify(result), 400
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@memory_bp.route('/hunting/<case_uuid>/jobs', methods=['GET'])
@login_required
def get_hunting_jobs(case_uuid):
    """Get all completed memory jobs for hunting view"""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Get completed jobs with ingested data
        jobs = MemoryJob.query.filter_by(
            case_id=case.id,
            status='completed'
        ).order_by(MemoryJob.hostname, MemoryJob.created_at.desc()).all()
        
        # Add data counts for each job
        job_list = []
        for job in jobs:
            job_dict = job.to_dict()
            job_dict['data_counts'] = {
                'processes': MemoryProcess.query.filter_by(job_id=job.id).count(),
                'network': MemoryNetwork.query.filter_by(job_id=job.id).count(),
                'services': MemoryService.query.filter_by(job_id=job.id).count(),
                'malfind': MemoryMalfind.query.filter_by(job_id=job.id).count(),
                'modules': MemoryModule.query.filter_by(job_id=job.id).count(),
                'credentials': MemoryCredential.query.filter_by(job_id=job.id).count(),
                'info': MemoryInfo.query.filter_by(job_id=job.id).count(),
            }
            job_dict['has_data'] = sum(job_dict['data_counts'].values()) > 0
            job_dict['has_artifact_data'] = sum(
                count for key, count in job_dict['data_counts'].items() if key != 'info'
            ) > 0
            
            # Get system time from memory_info if available
            info = MemoryInfo.query.filter_by(job_id=job.id).first()
            if info and info.system_time:
                job_dict['system_time'] = info.system_time.isoformat()
            else:
                job_dict['system_time'] = job.memory_timestamp.isoformat() if job.memory_timestamp else None

            if not job_dict['has_data']:
                job_dict['no_data_reason'] = _get_memory_no_data_reason(job_dict)
            else:
                job_dict['no_data_reason'] = None
            
            job_list.append(job_dict)
        
        return jsonify({
            'success': True,
            'jobs': job_list
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@memory_bp.route('/hunting/<int:job_id>/processes', methods=['GET'])
@login_required
def get_processes(job_id):
    """Get process list for a memory job"""
    try:
        job = _get_memory_job_for_user(job_id)
        if job is False:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        if not job:
            return jsonify({'success': False, 'error': 'Job not found'}), 404
        
        # Get filter params
        search = request.args.get('search', '').lower()
        
        query = MemoryProcess.query.filter_by(job_id=job_id)
        
        if search:
            query = query.filter(
                db.or_(
                    MemoryProcess.name_lower.contains(search),
                    MemoryProcess.cmdline.ilike(f'%{search}%'),
                    MemoryProcess.path.ilike(f'%{search}%')
                )
            )
        
        processes = query.order_by(MemoryProcess.pid).all()
        
        return jsonify({
            'success': True,
            'hostname': job.hostname,
            'memory_time': job.memory_timestamp.isoformat() if job.memory_timestamp else None,
            'processes': [p.to_dict() for p in processes],
            'total': len(processes)
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@memory_bp.route('/hunting/<int:job_id>/process-tree', methods=['GET'])
@login_required
def get_process_tree(job_id):
    """Get process tree structure for a memory job"""
    try:
        job = _get_memory_job_for_user(job_id)
        if job is False:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        if not job:
            return jsonify({'success': False, 'error': 'Job not found'}), 404
        
        processes = MemoryProcess.query.filter_by(job_id=job_id).all()
        
        # Build tree structure
        pid_map = {p.pid: p.to_dict() for p in processes}
        root_processes = []
        
        for proc in processes:
            proc_dict = pid_map[proc.pid]
            proc_dict['children'] = []
            
            if proc.ppid and proc.ppid in pid_map:
                # Has parent - will be added as child
                pass
            else:
                # Root process
                root_processes.append(proc_dict)
        
        # Add children to parents
        for proc in processes:
            if proc.ppid and proc.ppid in pid_map:
                pid_map[proc.ppid]['children'].append(pid_map[proc.pid])
        
        # Sort children by PID
        def sort_children(node):
            node['children'].sort(key=lambda x: x['pid'])
            for child in node['children']:
                sort_children(child)
        
        for root in root_processes:
            sort_children(root)
        
        root_processes.sort(key=lambda x: x['pid'])
        
        return jsonify({
            'success': True,
            'hostname': job.hostname,
            'tree': root_processes,
            'total': len(processes)
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@memory_bp.route('/hunting/<int:job_id>/network', methods=['GET'])
@login_required
def get_network(job_id):
    """Get network connections for a memory job"""
    try:
        job = _get_memory_job_for_user(job_id)
        if job is False:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        if not job:
            return jsonify({'success': False, 'error': 'Job not found'}), 404
        
        # Get filter params
        search = request.args.get('search', '').lower()
        state = request.args.get('state', '')
        
        query = MemoryNetwork.query.filter_by(job_id=job_id)
        
        if search:
            query = query.filter(
                db.or_(
                    MemoryNetwork.local_addr.contains(search),
                    MemoryNetwork.foreign_addr.contains(search),
                    MemoryNetwork.owner.ilike(f'%{search}%')
                )
            )
        
        if state:
            query = query.filter(MemoryNetwork.state == state)
        
        connections = query.order_by(MemoryNetwork.pid).all()
        
        # Get unique states for filter dropdown
        states = db.session.query(MemoryNetwork.state).filter_by(
            job_id=job_id
        ).distinct().all()
        
        return jsonify({
            'success': True,
            'hostname': job.hostname,
            'connections': [c.to_dict() for c in connections],
            'total': len(connections),
            'states': [s[0] for s in states if s[0]]
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@memory_bp.route('/hunting/<int:job_id>/services', methods=['GET'])
@login_required
def get_services(job_id):
    """Get services for a memory job"""
    try:
        job = _get_memory_job_for_user(job_id)
        if job is False:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        if not job:
            return jsonify({'success': False, 'error': 'Job not found'}), 404
        
        # Get filter params
        search = request.args.get('search', '').lower()
        state = request.args.get('state', '')
        
        query = MemoryService.query.filter_by(job_id=job_id)
        
        if search:
            query = query.filter(
                db.or_(
                    MemoryService.name_lower.contains(search),
                    MemoryService.display_name.ilike(f'%{search}%'),
                    MemoryService.binary_path.ilike(f'%{search}%'),
                    MemoryService.binary_path_registry.ilike(f'%{search}%')
                )
            )
        
        if state:
            query = query.filter(MemoryService.state == state)
        
        services = query.order_by(MemoryService.name).all()
        
        # Get unique states
        states = db.session.query(MemoryService.state).filter_by(
            job_id=job_id
        ).distinct().all()
        
        return jsonify({
            'success': True,
            'hostname': job.hostname,
            'services': [s.to_dict() for s in services],
            'total': len(services),
            'states': [s[0] for s in states if s[0]]
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@memory_bp.route('/hunting/<int:job_id>/malfind', methods=['GET'])
@login_required
def get_malfind(job_id):
    """Get malfind results for a memory job"""
    try:
        job = _get_memory_job_for_user(job_id)
        if job is False:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        if not job:
            return jsonify({'success': False, 'error': 'Job not found'}), 404
        
        search = request.args.get('search', '').lower()
        
        query = MemoryMalfind.query.filter_by(job_id=job_id)
        
        if search:
            query = query.filter(
                MemoryMalfind.process_name.ilike(f'%{search}%')
            )
        
        findings = query.order_by(MemoryMalfind.pid).all()
        
        return jsonify({
            'success': True,
            'hostname': job.hostname,
            'findings': [f.to_dict() for f in findings],
            'total': len(findings)
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@memory_bp.route('/hunting/<int:job_id>/modules', methods=['GET'])
@login_required
def get_modules(job_id):
    """Get loaded modules for a memory job"""
    try:
        job = _get_memory_job_for_user(job_id)
        if job is False:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        if not job:
            return jsonify({'success': False, 'error': 'Job not found'}), 404
        
        search = request.args.get('search', '').lower()
        unlinked_only = request.args.get('unlinked', 'false').lower() == 'true'
        pid = request.args.get('pid', type=int)
        
        query = MemoryModule.query.filter_by(job_id=job_id)
        
        if search:
            query = query.filter(
                db.or_(
                    MemoryModule.mapped_path.ilike(f'%{search}%'),
                    MemoryModule.process_name.ilike(f'%{search}%')
                )
            )
        
        if unlinked_only:
            query = query.filter(
                MemoryModule.in_init == False,
                MemoryModule.in_load == False,
                MemoryModule.in_mem == False
            )
        
        if pid:
            query = query.filter(MemoryModule.pid == pid)
        
        modules = query.order_by(MemoryModule.pid, MemoryModule.mapped_path).all()
        
        return jsonify({
            'success': True,
            'hostname': job.hostname,
            'modules': [m.to_dict() for m in modules],
            'total': len(modules)
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@memory_bp.route('/hunting/<int:job_id>/credentials', methods=['GET'])
@login_required
def get_credentials(job_id):
    """Get credentials for a memory job"""
    try:
        job = _get_memory_job_for_user(job_id)
        if job is False:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        if not job:
            return jsonify({'success': False, 'error': 'Job not found'}), 404
        
        source = request.args.get('source', '')  # hashdump, cachedump, lsadump
        
        query = MemoryCredential.query.filter_by(job_id=job_id)
        
        if source:
            query = query.filter(MemoryCredential.source_plugin == source)
        
        creds = query.order_by(MemoryCredential.source_plugin, MemoryCredential.username).all()
        
        return jsonify({
            'success': True,
            'hostname': job.hostname,
            'credentials': [c.to_dict(mask_secrets=True) for c in creds],
            'total': len(creds)
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@memory_bp.route('/hunting/<int:job_id>/info', methods=['GET'])
@login_required
def get_info(job_id):
    """Get system info for a memory job"""
    try:
        job = _get_memory_job_for_user(job_id)
        if job is False:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        if not job:
            return jsonify({'success': False, 'error': 'Job not found'}), 404
        
        info = MemoryInfo.query.filter_by(job_id=job_id).first()
        
        return jsonify({
            'success': True,
            'hostname': job.hostname,
            'info': info.to_dict() if info else None
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# CROSS-MEMORY SEARCH (Option 2)
# ============================================================================

@memory_bp.route('/hunting/<case_uuid>/search', methods=['GET'])
@login_required
def cross_memory_search(case_uuid):
    """Search across all memory dumps in a case"""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        search = request.args.get('q', '').strip()
        search_type = request.args.get('type', 'process')  # process, network, service, path
        
        if not search or len(search) < 2:
            return jsonify({'success': False, 'error': 'Search term too short'}), 400
        
        search_lower = search.lower()
        results = []
        
        if search_type == 'process':
            # Search processes by name
            matches = MemoryProcess.query.filter(
                MemoryProcess.case_id == case.id,
                MemoryProcess.name_lower.contains(search_lower)
            ).order_by(MemoryProcess.job_id, MemoryProcess.pid).all()
            
            # Group by job
            job_groups = {}
            for proc in matches:
                if proc.job_id not in job_groups:
                    job = MemoryJob.query.get(proc.job_id)
                    job_groups[proc.job_id] = {
                        'job_id': proc.job_id,
                        'hostname': job.hostname if job else 'Unknown',
                        'memory_time': job.memory_timestamp.isoformat() if job and job.memory_timestamp else None,
                        'matches': []
                    }
                job_groups[proc.job_id]['matches'].append(proc.to_dict())
            
            results = list(job_groups.values())
            
        elif search_type == 'network':
            # Search by IP address
            matches = MemoryNetwork.query.filter(
                MemoryNetwork.case_id == case.id,
                db.or_(
                    MemoryNetwork.foreign_addr.contains(search),
                    MemoryNetwork.local_addr.contains(search)
                )
            ).order_by(MemoryNetwork.job_id).all()
            
            job_groups = {}
            for net in matches:
                if net.job_id not in job_groups:
                    job = MemoryJob.query.get(net.job_id)
                    job_groups[net.job_id] = {
                        'job_id': net.job_id,
                        'hostname': job.hostname if job else 'Unknown',
                        'memory_time': job.memory_timestamp.isoformat() if job and job.memory_timestamp else None,
                        'matches': []
                    }
                job_groups[net.job_id]['matches'].append(net.to_dict())
            
            results = list(job_groups.values())
            
        elif search_type == 'service':
            # Search services by name
            matches = MemoryService.query.filter(
                MemoryService.case_id == case.id,
                db.or_(
                    MemoryService.name_lower.contains(search_lower),
                    MemoryService.display_name.ilike(f'%{search}%')
                )
            ).order_by(MemoryService.job_id).all()
            
            job_groups = {}
            for svc in matches:
                if svc.job_id not in job_groups:
                    job = MemoryJob.query.get(svc.job_id)
                    job_groups[svc.job_id] = {
                        'job_id': svc.job_id,
                        'hostname': job.hostname if job else 'Unknown',
                        'memory_time': job.memory_timestamp.isoformat() if job and job.memory_timestamp else None,
                        'matches': []
                    }
                job_groups[svc.job_id]['matches'].append(svc.to_dict())
            
            results = list(job_groups.values())
            
        elif search_type == 'path':
            # Search by file path (processes, modules)
            proc_matches = MemoryProcess.query.filter(
                MemoryProcess.case_id == case.id,
                db.or_(
                    MemoryProcess.path.ilike(f'%{search}%'),
                    MemoryProcess.cmdline.ilike(f'%{search}%')
                )
            ).all()
            
            mod_matches = MemoryModule.query.filter(
                MemoryModule.case_id == case.id,
                MemoryModule.mapped_path.ilike(f'%{search}%')
            ).all()
            
            job_groups = {}
            
            for proc in proc_matches:
                if proc.job_id not in job_groups:
                    job = MemoryJob.query.get(proc.job_id)
                    job_groups[proc.job_id] = {
                        'job_id': proc.job_id,
                        'hostname': job.hostname if job else 'Unknown',
                        'memory_time': job.memory_timestamp.isoformat() if job and job.memory_timestamp else None,
                        'process_matches': [],
                        'module_matches': []
                    }
                job_groups[proc.job_id]['process_matches'].append(proc.to_dict())
            
            for mod in mod_matches:
                if mod.job_id not in job_groups:
                    job = MemoryJob.query.get(mod.job_id)
                    job_groups[mod.job_id] = {
                        'job_id': mod.job_id,
                        'hostname': job.hostname if job else 'Unknown',
                        'memory_time': job.memory_timestamp.isoformat() if job and job.memory_timestamp else None,
                        'process_matches': [],
                        'module_matches': []
                    }
                job_groups[mod.job_id]['module_matches'].append(mod.to_dict())
            
            results = list(job_groups.values())
        
        # Get total job count for context
        total_jobs = MemoryJob.query.filter_by(case_id=case.id, status='completed').count()
        
        return jsonify({
            'success': True,
            'search': search,
            'search_type': search_type,
            'results': results,
            'jobs_matched': len(results),
            'total_jobs': total_jobs
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@memory_bp.route('/hunting/<case_uuid>/cross-reference/<artifact_type>/<artifact_value>', methods=['GET'])
@login_required
def get_cross_references(case_uuid, artifact_type, artifact_value):
    """Get cross-memory references for a specific artifact
    
    Used to populate the [🧠×N] badges - shows where else this artifact appears
    """
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        exclude_job = request.args.get('exclude_job', type=int)
        artifact_lower = artifact_value.lower()
        
        refs = []
        
        if artifact_type == 'process':
            # Find other jobs with this process name
            matches = db.session.query(
                MemoryProcess.job_id,
                MemoryJob.hostname,
                MemoryJob.memory_timestamp,
                db.func.count(MemoryProcess.id).label('count')
            ).join(
                MemoryJob, MemoryProcess.job_id == MemoryJob.id
            ).filter(
                MemoryProcess.case_id == case.id,
                MemoryProcess.name_lower == artifact_lower
            )
            
            if exclude_job:
                matches = matches.filter(MemoryProcess.job_id != exclude_job)
            
            matches = matches.group_by(
                MemoryProcess.job_id,
                MemoryJob.hostname,
                MemoryJob.memory_timestamp
            ).all()
            
            refs = [{
                'job_id': m[0],
                'hostname': m[1],
                'memory_time': m[2].isoformat() if m[2] else None,
                'count': m[3]
            } for m in matches]
            
        elif artifact_type == 'ip':
            # Find other jobs with this IP
            matches = db.session.query(
                MemoryNetwork.job_id,
                MemoryJob.hostname,
                MemoryJob.memory_timestamp,
                db.func.count(MemoryNetwork.id).label('count')
            ).join(
                MemoryJob, MemoryNetwork.job_id == MemoryJob.id
            ).filter(
                MemoryNetwork.case_id == case.id,
                db.or_(
                    MemoryNetwork.foreign_addr == artifact_value,
                    MemoryNetwork.local_addr == artifact_value
                )
            )
            
            if exclude_job:
                matches = matches.filter(MemoryNetwork.job_id != exclude_job)
            
            matches = matches.group_by(
                MemoryNetwork.job_id,
                MemoryJob.hostname,
                MemoryJob.memory_timestamp
            ).all()
            
            refs = [{
                'job_id': m[0],
                'hostname': m[1],
                'memory_time': m[2].isoformat() if m[2] else None,
                'count': m[3]
            } for m in matches]
            
        elif artifact_type == 'service':
            # Find other jobs with this service
            matches = db.session.query(
                MemoryService.job_id,
                MemoryJob.hostname,
                MemoryJob.memory_timestamp
            ).join(
                MemoryJob, MemoryService.job_id == MemoryJob.id
            ).filter(
                MemoryService.case_id == case.id,
                MemoryService.name_lower == artifact_lower
            )
            
            if exclude_job:
                matches = matches.filter(MemoryService.job_id != exclude_job)
            
            matches = matches.group_by(
                MemoryService.job_id,
                MemoryJob.hostname,
                MemoryJob.memory_timestamp
            ).all()
            
            refs = [{
                'job_id': m[0],
                'hostname': m[1],
                'memory_time': m[2].isoformat() if m[2] else None,
                'count': 1
            } for m in matches]
        
        return jsonify({
            'success': True,
            'artifact_type': artifact_type,
            'artifact_value': artifact_value,
            'references': refs,
            'total_refs': len(refs)
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@memory_bp.route('/job/<int:job_id>/delete', methods=['POST'])
@login_required
def delete_memory_job(job_id):
    """Delete a memory job and all associated data (admin only)
    
    This endpoint:
    - Deletes the memory job record (CASCADE deletes all memory data tables)
    - Removes the Volatility output directory
    - Optionally removes the source memory file
    """
    if current_user.permission_level != 'administrator':
        return jsonify({'success': False, 'error': 'Administrator access required'}), 403
    
    try:
        import shutil
        import os
        
        job = _get_memory_job_for_user(job_id)
        if job is False:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        if not job:
            return jsonify({'success': False, 'error': 'Memory job not found'}), 404
        
        deleted_stats = {
            'job_id': job_id,
            'hostname': job.hostname,
            'filename': job.source_filename,
            'output_deleted': False,
            'source_deleted': False
        }
        
        output_folder = job.output_folder
        
        # Delete Volatility output directory
        if output_folder and os.path.isdir(output_folder):
            try:
                shutil.rmtree(output_folder)
                deleted_stats['output_deleted'] = True
            except Exception as e:
                # Log but continue with deletion
                pass
        
        # Delete the job record
        # Due to CASCADE on foreign keys, all related data in memory_* tables is auto-deleted
        db.session.delete(job)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Memory job for "{job.hostname}" deleted successfully',
            **deleted_stats
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@memory_bp.route('/job/<int:job_id>/rebuild', methods=['POST'])
@login_required
def rebuild_memory_job(job_id):
    """Rebuild a memory job from its retained original."""
    if current_user.permission_level == 'viewer':
        return _viewer_write_error()

    try:
        job = _get_memory_job_for_user(job_id)
        if job is False:
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        if not job:
            return jsonify({'success': False, 'error': 'Job not found'}), 404

        from tasks.memory_tasks import rebuild_memory_job_from_originals

        task = rebuild_memory_job_from_originals.delay(job_id=job_id, username=current_user.username)
        return jsonify({
            'success': True,
            'job_id': job_id,
            'task_id': task.id,
            'message': 'Originals-based memory rebuild queued',
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@memory_bp.route('/rebuild/<case_uuid>', methods=['POST'])
@login_required
def rebuild_case_memory_jobs(case_uuid):
    """Rebuild all memory jobs for a case from retained originals."""
    if current_user.permission_level == 'viewer':
        return _viewer_write_error()

    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404

        from tasks.memory_tasks import rebuild_case_memory_jobs_from_originals

        task = rebuild_case_memory_jobs_from_originals.delay(case_uuid=case_uuid, username=current_user.username)
        return jsonify({
            'success': True,
            'case_uuid': case_uuid,
            'task_id': task.id,
            'message': 'Originals-based memory case rebuild queued',
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
