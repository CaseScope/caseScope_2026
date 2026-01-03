"""
Chunk-based File Upload Routes
Handles large file uploads with chunking for speed and reliability
"""

import os
import logging
from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
import hashlib
from datetime import datetime
import shutil

logger = logging.getLogger(__name__)

upload_bp = Blueprint('upload', __name__, url_prefix='/upload')

# Chunk upload configuration
CHUNK_SIZE = 5 * 1024 * 1024  # 5MB chunks
UPLOAD_TEMP_PATH = '/opt/casescope/upload_temp'
MAX_FILE_SIZE = 50 * 1024 * 1024 * 1024  # 50GB max


def get_chunk_path(case_id, upload_id):
    """Get path for storing chunks"""
    chunk_dir = os.path.join(UPLOAD_TEMP_PATH, str(case_id), upload_id)
    os.makedirs(chunk_dir, exist_ok=True)
    return chunk_dir


def get_staging_path(case_id):
    """Get staging path for case"""
    staging_path = f'/opt/casescope/staging/{case_id}'
    os.makedirs(staging_path, exist_ok=True)
    return staging_path


@upload_bp.route('/chunk/<int:case_id>', methods=['POST'])
@login_required
def upload_chunk(case_id):
    """
    Upload a single file chunk
    
    Expected form data:
    - chunk: File chunk
    - chunkIndex: Current chunk index (0-based)
    - totalChunks: Total number of chunks
    - uploadId: Unique upload session ID
    - fileName: Original filename
    - fileSize: Total file size
    """
    try:
        # Check permissions
        if current_user.role == 'read-only':
            return jsonify({'error': 'You do not have permission to upload files'}), 403
        
        # Verify case exists
        from models import Case
        case = Case.query.get_or_404(case_id)
        
        # Get form data
        chunk = request.files.get('chunk')
        chunk_index = int(request.form.get('chunkIndex'))
        total_chunks = int(request.form.get('totalChunks'))
        upload_id = request.form.get('uploadId')
        file_name = secure_filename(request.form.get('fileName'))
        file_size = int(request.form.get('fileSize'))
        
        if not chunk or not upload_id or not file_name:
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Validate file size
        if file_size > MAX_FILE_SIZE:
            return jsonify({'error': f'File too large. Max size: {MAX_FILE_SIZE / (1024**3):.1f}GB'}), 400
        
        # Save chunk
        chunk_dir = get_chunk_path(case_id, upload_id)
        chunk_path = os.path.join(chunk_dir, f'chunk_{chunk_index}')
        chunk.save(chunk_path)
        
        # Log chunk size for debugging 1-byte mismatch issue
        chunk_size_actual = os.path.getsize(chunk_path)
        logger.info(f"Saved chunk {chunk_index + 1}/{total_chunks} for {file_name} ({chunk_size_actual} bytes)")
        
        return jsonify({
            'success': True,
            'chunkIndex': chunk_index,
            'totalChunks': total_chunks,
            'chunkSize': chunk_size_actual,
            'message': f'Chunk {chunk_index + 1}/{total_chunks} uploaded'
        })
        
    except Exception as e:
        logger.error(f"Error uploading chunk: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@upload_bp.route('/complete/<int:case_id>', methods=['POST'])
@login_required
def complete_upload(case_id):
    """
    Complete chunked upload by assembling chunks
    
    Expected JSON:
    - uploadId: Unique upload session ID
    - fileName: Original filename
    - totalChunks: Total number of chunks
    - fileSize: Total file size
    """
    try:
        # Check permissions
        if current_user.role == 'read-only':
            return jsonify({'error': 'You do not have permission to upload files'}), 403
        
        # Verify case exists
        from models import Case
        case = Case.query.get_or_404(case_id)
        
        # Get request data
        data = request.get_json()
        upload_id = data.get('uploadId')
        file_name = secure_filename(data.get('fileName'))
        total_chunks = int(data.get('totalChunks'))
        file_size = int(data.get('fileSize'))
        
        if not upload_id or not file_name:
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Get chunk directory
        chunk_dir = get_chunk_path(case_id, upload_id)
        
        # Verify all chunks exist
        missing_chunks = []
        for i in range(total_chunks):
            chunk_path = os.path.join(chunk_dir, f'chunk_{i}')
            if not os.path.exists(chunk_path):
                missing_chunks.append(i)
        
        if missing_chunks:
            return jsonify({
                'error': f'Missing chunks: {missing_chunks}',
                'missing_chunks': missing_chunks
            }), 400
        
        # Assemble file
        staging_path = get_staging_path(case_id)
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S_%f')
        final_filename = f"{timestamp}_{file_name}"
        final_path = os.path.join(staging_path, final_filename)
        
        logger.info(f"Assembling {total_chunks} chunks into {final_filename}")
        
        # Combine chunks
        with open(final_path, 'wb') as outfile:
            for i in range(total_chunks):
                chunk_path = os.path.join(chunk_dir, f'chunk_{i}')
                with open(chunk_path, 'rb') as chunk_file:
                    outfile.write(chunk_file.read())
        
        # Verify file size - must be exact (corruption detection)
        actual_size = os.path.getsize(final_path)
        size_diff = abs(actual_size - file_size)
        
        if size_diff != 0:
            # Log detailed chunk information for debugging
            chunk_sizes = []
            total_chunk_bytes = 0
            for i in range(total_chunks):
                chunk_path = os.path.join(chunk_dir, f'chunk_{i}')
                if os.path.exists(chunk_path):
                    chunk_size = os.path.getsize(chunk_path)
                    chunk_sizes.append(chunk_size)
                    total_chunk_bytes += chunk_size
            
            logger.error(f"Size mismatch for {file_name}:")
            logger.error(f"  Expected: {file_size}")
            logger.error(f"  Assembled: {actual_size}")
            logger.error(f"  Difference: {size_diff}")
            logger.error(f"  Total chunks: {total_chunks}")
            logger.error(f"  Sum of chunk sizes: {total_chunk_bytes}")
            logger.error(f"  First 5 chunk sizes: {chunk_sizes[:5]}")
            logger.error(f"  Last 5 chunk sizes: {chunk_sizes[-5:]}")
            
            os.remove(final_path)
            return jsonify({
                'error': f'File size mismatch. Expected: {file_size}, Got: {actual_size} (diff: {size_diff} bytes). File may be corrupt.',
                'expected_size': file_size,
                'actual_size': actual_size,
                'chunk_analysis': {
                    'total_chunks': total_chunks,
                    'chunk_sizes': chunk_sizes
                }
            }), 500
        
        # Calculate file hash after assembly (memory-safe streaming)
        logger.info(f"Calculating SHA256 hash for {file_name}...")
        hash_obj = hashlib.sha256()
        with open(final_path, 'rb') as f:
            while chunk_data := f.read(8388608):  # 8MB chunks
                hash_obj.update(chunk_data)
        file_hash = hash_obj.hexdigest()
        logger.info(f"Calculated SHA256: {file_hash[:16]}...")
        
        # Check for duplicate file in this case (per-case deduplication)
        from models import CaseFile
        duplicate = CaseFile.query.filter_by(
            case_id=case_id,
            file_hash=file_hash
        ).first()
        
        is_duplicate = False
        duplicate_info = None
        force_reupload = data.get('forceReupload', False)
        
        if duplicate and not force_reupload:
            # Duplicate found - prepare warning info
            is_duplicate = True
            duplicate_info = {
                'id': duplicate.id,
                'filename': duplicate.original_filename,
                'uploaded_at': duplicate.uploaded_at.isoformat() if duplicate.uploaded_at else None,
                'event_count': duplicate.event_count,
                'file_size': duplicate.file_size
            }
            
            logger.info(f"Duplicate file detected: {file_name} (hash: {file_hash[:16]}...)")
            
            # Clean up uploaded file and chunks
            os.remove(final_path)
            try:
                shutil.rmtree(chunk_dir)
            except Exception as e:
                logger.warning(f"Failed to clean up chunks: {e}")
            
            return jsonify({
                'success': False,
                'isDuplicate': True,
                'duplicate': duplicate_info,
                'message': f'File already uploaded to this case on {duplicate_info["uploaded_at"]}',
                'fileHash': file_hash
            }), 409  # 409 Conflict
        
        # Clean up chunks
        try:
            shutil.rmtree(chunk_dir)
        except Exception as e:
            logger.warning(f"Failed to clean up chunks: {e}")
        
        # NEW SYSTEM (NEW_FILE_UPLOAD.ND): Move to uploads/web folder instead of auto-processing
        # Files stay in uploads/web until user clicks "Start Processing"
        web_upload_dir = f'/opt/casescope/uploads/web/{case_id}'
        os.makedirs(web_upload_dir, mode=0o770, exist_ok=True)
        
        # Move from staging to uploads/web
        final_upload_path = os.path.join(web_upload_dir, file_name)  # Use original name, not timestamped
        shutil.move(final_path, final_upload_path)
        
        # Log action
        from audit_logger import log_action
        log_action('file_upload',
                   resource_type='case',
                   resource_id=case_id,
                   resource_name=case.name,
                   details={
                       'uploaded_by': current_user.username,
                       'file_name': file_name,
                       'file_size': file_size,
                       'chunks': total_chunks,
                       'upload_path': final_upload_path,
                       'file_hash': file_hash
                   })
        
        logger.info(f"File {file_name} uploaded to web upload folder. Ready for processing.")
        
        return jsonify({
            'success': True,
            'file_name': file_name,
            'file_size': file_size,
            'file_hash': file_hash,
            'upload_path': final_upload_path,
            'message': f'File uploaded successfully. Click "Start Processing" to begin ingestion.'
        })
        
    except Exception as e:
        logger.error(f"Error completing upload: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@upload_bp.route('/cancel/<int:case_id>', methods=['POST'])
@login_required
def cancel_upload(case_id):
    """
    Cancel an in-progress upload
    
    Expected JSON:
    - uploadId: Unique upload session ID
    """
    try:
        data = request.get_json()
        upload_id = data.get('uploadId')
        
        if not upload_id:
            return jsonify({'error': 'Missing uploadId'}), 400
        
        # Clean up chunks
        chunk_dir = get_chunk_path(case_id, upload_id)
        if os.path.exists(chunk_dir):
            shutil.rmtree(chunk_dir)
            logger.info(f"Cancelled upload {upload_id} for case {case_id}")
        
        return jsonify({
            'success': True,
            'message': 'Upload cancelled and cleaned up'
        })
        
    except Exception as e:
        logger.error(f"Error cancelling upload: {e}")
        return jsonify({'error': str(e)}), 500


@upload_bp.route('/status/<int:case_id>/<upload_id>', methods=['GET'])
@login_required
def upload_status(case_id, upload_id):
    """
    Get status of an upload
    
    Returns which chunks have been uploaded
    """
    try:
        chunk_dir = get_chunk_path(case_id, upload_id)
        
        if not os.path.exists(chunk_dir):
            return jsonify({
                'exists': False,
                'uploaded_chunks': []
            })
        
        # Check which chunks exist
        uploaded_chunks = []
        for filename in os.listdir(chunk_dir):
            if filename.startswith('chunk_'):
                chunk_index = int(filename.split('_')[1])
                uploaded_chunks.append(chunk_index)
        
        return jsonify({
            'exists': True,
            'uploaded_chunks': sorted(uploaded_chunks)
        })
        
    except Exception as e:
        logger.error(f"Error checking upload status: {e}")
        return jsonify({'error': str(e)}), 500


# =============================================================================
# NEW FILE UPLOAD SYSTEM - NEW_FILE_UPLOAD.ND Implementation
# =============================================================================

@upload_bp.route('/api/list_pending/<int:case_id>', methods=['GET'])
@login_required
def list_pending_files(case_id):
    """
    List files in upload folder waiting to be processed
    
    Returns:
        JSON with list of files in web and sftp upload folders
    """
    try:
        from utils.file_ingestion import scan_upload_folder
        
        # Scan both web and sftp folders
        web_files = scan_upload_folder(case_id, 'web')
        sftp_files = scan_upload_folder(case_id, 'sftp')
        
        return jsonify({
            'success': True,
            'web_files': web_files,
            'sftp_files': sftp_files,
            'total_files': len(web_files) + len(sftp_files)
        })
        
    except Exception as e:
        logger.error(f"Error listing pending files: {e}")
        return jsonify({'error': str(e)}), 500


@upload_bp.route('/api/start_processing/<int:case_id>', methods=['POST'])
@login_required
def start_processing(case_id):
    """
    Start processing files in upload folder
    
    Triggers the new ingestion task (NEW_FILE_UPLOAD.ND)
    
    Request JSON:
        {
            'upload_type': 'web' or 'sftp',
            'resume': bool (optional, default: false)
        }
    
    Returns:
        JSON with task_id for progress tracking
    """
    try:
        from main import db
        from models import Case, IngestionProgress
        from tasks.task_ingest_files import ingest_files
        from audit_logger import log_action
        from datetime import datetime, timedelta
        
        # Verify case exists
        case = Case.query.get(case_id)
        if not case:
            return jsonify({'error': 'Case not found'}), 404
        
        # Check for recent active ingestion (prevent duplicates)
        recent_cutoff = datetime.utcnow() - timedelta(minutes=5)
        active_ingestion = IngestionProgress.query.filter(
            IngestionProgress.case_id == case_id,
            IngestionProgress.status.in_(['in_progress', 'pending']),
            IngestionProgress.started_at >= recent_cutoff
        ).first()
        
        if active_ingestion:
            logger.warning(f"Duplicate processing attempt blocked for case {case_id}")
            return jsonify({
                'success': False,
                'error': 'Processing already in progress for this case',
                'active_task_id': active_ingestion.task_id
            }), 409  # Conflict
        
        # Get parameters
        data = request.json or {}
        upload_type = data.get('upload_type', 'web')
        resume = data.get('resume', False)
        
        # Validate upload_type
        if upload_type not in ['web', 'sftp']:
            return jsonify({'error': 'Invalid upload_type. Must be "web" or "sftp"'}), 400
        
        # Queue ingestion task
        task = ingest_files.delay(
            case_id=case_id,
            user_id=current_user.id,
            upload_type=upload_type,
            resume=resume
        )
        
        # Log action
        log_action(
            action='file_ingestion_started',
            resource_type='case',
            details={
                'case_id': case_id,
                'case_name': case.name,
                'upload_type': upload_type,
                'resume': resume,
                'task_id': task.id
            },
            status='success'
        )
        
        return jsonify({
            'success': True,
            'task_id': task.id,
            'message': 'File processing started'
        })
        
    except Exception as e:
        logger.error(f"Error starting file processing: {e}")
        return jsonify({'error': str(e)}), 500


@upload_bp.route('/api/processing_status/<task_id>', methods=['GET'])
@login_required
def processing_status(task_id):
    """
    Get status of file processing task
    
    Returns:
        JSON with task status and progress
    """
    try:
        from tasks.task_ingest_files import ingest_files
        
        # Get task result
        task = ingest_files.AsyncResult(task_id)
        
        if task.state == 'PENDING':
            response = {
                'state': 'PENDING',
                'status': 'Task is waiting to start...',
                'progress': 0
            }
        elif task.state == 'PROGRESS':
            response = {
                'state': 'PROGRESS',
                'status': task.info.get('status', ''),
                'progress': task.info.get('progress', 0),
                'current_step': task.info.get('current_step', ''),
                'files_processed': task.info.get('files_processed', 0),
                'total_files': task.info.get('total_files', 0),
                'indexed': task.info.get('indexed', 0),
                'failed': task.info.get('failed', 0),
                'duplicates_skipped': task.info.get('duplicates_skipped', 0)
            }
        elif task.state == 'SUCCESS':
            result = task.result
            response = {
                'state': 'SUCCESS',
                'status': 'Processing complete',
                'progress': 100,
                'result': result
            }
        else:
            # FAILURE or other state
            response = {
                'state': task.state,
                'status': str(task.info) if task.info else 'Unknown error',
                'progress': 0
            }
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error checking processing status: {e}")
        return jsonify({'error': str(e)}), 500
