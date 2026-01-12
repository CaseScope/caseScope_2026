"""Evidence Files Blueprint - Archival storage for screenshots, exports, etc.

NOT for logs (unless they cannot be readily ingested).
These files are stored but NOT processed/indexed.
Files are stored in /opt/casescope/evidence/{case_uuid}/ which is 
separate from the parsing pipeline (uploads/staging folders).
"""
import os
import hashlib
import mimetypes
import logging
import shutil
from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, send_from_directory, session
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from sqlalchemy import func, or_

from models.database import db
from models.case import Case
from models.evidence_file import EvidenceFile
from config import Config

logger = logging.getLogger(__name__)

evidence_bp = Blueprint('evidence', __name__, url_prefix='/evidence')


def get_active_case():
    """Get the currently active case from session"""
    if 'active_case_uuid' not in session:
        return None
    return Case.get_by_uuid(session['active_case_uuid'])


def get_evidence_storage_path(case_uuid: str) -> str:
    """Get evidence storage directory for a case
    
    This path is separate from UPLOAD_FOLDER_WEB/SFTP and STAGING_FOLDER
    to ensure evidence files are NEVER parsed.
    """
    path = os.path.join(Config.EVIDENCE_FOLDER, case_uuid)
    os.makedirs(path, exist_ok=True)
    return path


def calculate_file_hash(file_path: str) -> str:
    """Calculate SHA256 hash of a file"""
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha256.update(chunk)
    return sha256.hexdigest()


def detect_file_type(filename: str) -> str:
    """Detect file type from extension"""
    ext = os.path.splitext(filename)[1].lower().lstrip('.')
    if not ext:
        return 'UNKNOWN'
    return ext.upper()


@evidence_bp.route('/upload', methods=['POST'])
@login_required
def upload_evidence():
    """Upload evidence file(s) via HTTP"""
    # Permission check
    if current_user.permission_level == 'viewer':
        return jsonify({'success': False, 'error': 'Viewers cannot upload files'}), 403
    
    case = get_active_case()
    if not case:
        return jsonify({'success': False, 'error': 'No active case selected'}), 400
    
    if 'files' not in request.files:
        return jsonify({'success': False, 'error': 'No files provided'}), 400
    
    files = request.files.getlist('files')
    if not files or files[0].filename == '':
        return jsonify({'success': False, 'error': 'No files selected'}), 400
    
    storage_path = get_evidence_storage_path(case.uuid)
    uploaded_files = []
    errors = []
    
    for file in files:
        try:
            original_filename = secure_filename(file.filename)
            if not original_filename:
                errors.append(f'Invalid filename: {file.filename}')
                continue
            
            # Generate unique filename
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S_%f')
            filename = f"{timestamp}_{original_filename}"
            file_path = os.path.join(storage_path, filename)
            
            # Save file
            file.save(file_path)
            
            # Calculate file info
            file_size = os.path.getsize(file_path)
            size_mb = round(file_size / (1024 * 1024))
            file_hash = calculate_file_hash(file_path)
            file_type = detect_file_type(original_filename)
            mime_type = mimetypes.guess_type(original_filename)[0]
            
            # Create database record
            evidence_file = EvidenceFile(
                case_uuid=case.uuid,
                filename=filename,
                original_filename=original_filename,
                file_path=file_path,
                file_size=file_size,
                size_mb=size_mb,
                file_hash=file_hash,
                file_type=file_type,
                mime_type=mime_type,
                upload_source='http',
                uploaded_by=current_user.id
            )
            db.session.add(evidence_file)
            db.session.commit()
            
            logger.info(f"Evidence file uploaded: {original_filename} for case {case.uuid}")
            uploaded_files.append(original_filename)
            
        except Exception as e:
            logger.error(f"Error uploading evidence file {file.filename}: {e}")
            errors.append(f'{file.filename}: {str(e)}')
            db.session.rollback()
    
    if uploaded_files:
        message = f'Uploaded {len(uploaded_files)} file(s)'
        if errors:
            message += f' ({len(errors)} failed)'
        return jsonify({'success': True, 'message': message, 'uploaded': uploaded_files, 'errors': errors})
    else:
        return jsonify({'success': False, 'error': 'All uploads failed', 'errors': errors}), 500


@evidence_bp.route('/bulk_import', methods=['POST'])
@login_required
def bulk_import_evidence():
    """Import evidence files from bulk upload folder"""
    # Permission check
    if current_user.permission_level == 'viewer':
        return jsonify({'success': False, 'error': 'Viewers cannot import files'}), 403
    
    case = get_active_case()
    if not case:
        return jsonify({'success': False, 'error': 'No active case selected'}), 400
    
    bulk_folder = Config.EVIDENCE_BULK_FOLDER
    if not os.path.exists(bulk_folder):
        os.makedirs(bulk_folder, exist_ok=True)
        return jsonify({'success': False, 'error': 'Bulk upload folder is empty'}), 400
    
    if not os.listdir(bulk_folder):
        return jsonify({'success': False, 'error': 'Bulk upload folder is empty'}), 400
    
    storage_path = get_evidence_storage_path(case.uuid)
    imported_files = []
    errors = []
    
    # Process all files in bulk folder
    for filename in os.listdir(bulk_folder):
        source_path = os.path.join(bulk_folder, filename)
        
        # Skip directories
        if os.path.isdir(source_path):
            continue
        
        try:
            original_filename = secure_filename(filename)
            
            # Generate unique filename
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S_%f')
            new_filename = f"{timestamp}_{original_filename}"
            dest_path = os.path.join(storage_path, new_filename)
            
            # Copy file (then delete source)
            shutil.copy2(source_path, dest_path)
            
            # Calculate file info
            file_size = os.path.getsize(dest_path)
            size_mb = round(file_size / (1024 * 1024))
            file_hash = calculate_file_hash(dest_path)
            file_type = detect_file_type(original_filename)
            mime_type = mimetypes.guess_type(original_filename)[0]
            
            # Create database record
            evidence_file = EvidenceFile(
                case_uuid=case.uuid,
                filename=new_filename,
                original_filename=original_filename,
                file_path=dest_path,
                file_size=file_size,
                size_mb=size_mb,
                file_hash=file_hash,
                file_type=file_type,
                mime_type=mime_type,
                upload_source='bulk',
                uploaded_by=current_user.id
            )
            db.session.add(evidence_file)
            db.session.commit()
            
            # Delete source file after successful import
            os.remove(source_path)
            
            imported_files.append(original_filename)
            
        except Exception as e:
            logger.error(f"Error importing evidence file {filename}: {e}")
            errors.append(f'{filename}: {str(e)}')
            db.session.rollback()
    
    if imported_files:
        logger.info(f"Bulk imported {len(imported_files)} evidence files for case {case.uuid}")
        message = f'Imported {len(imported_files)} file(s)'
        if errors:
            message += f' ({len(errors)} failed)'
        return jsonify({'success': True, 'message': message, 'imported': len(imported_files), 'errors': errors})
    else:
        return jsonify({'success': False, 'error': 'All imports failed', 'errors': errors}), 500


@evidence_bp.route('/<int:evidence_id>/download')
@login_required
def download_evidence(evidence_id):
    """Download an evidence file"""
    evidence_file = db.session.get(EvidenceFile, evidence_id)
    if not evidence_file:
        flash('Evidence file not found', 'error')
        return redirect(url_for('main.case_evidence'))
    
    directory = os.path.dirname(evidence_file.file_path)
    filename = os.path.basename(evidence_file.file_path)
    
    return send_from_directory(directory, filename, as_attachment=True, download_name=evidence_file.original_filename)


@evidence_bp.route('/<int:evidence_id>/edit', methods=['POST'])
@login_required
def edit_evidence_description(evidence_id):
    """Edit evidence file description"""
    # Permission check
    if current_user.permission_level == 'viewer':
        return jsonify({'success': False, 'error': 'Viewers cannot edit files'}), 403
    
    evidence_file = db.session.get(EvidenceFile, evidence_id)
    if not evidence_file:
        return jsonify({'success': False, 'error': 'Evidence file not found'}), 404
    
    data = request.get_json()
    new_description = data.get('description', '').strip()
    
    evidence_file.description = new_description
    db.session.commit()
    
    logger.info(f"Evidence file {evidence_id} description updated by {current_user.username}")
    
    return jsonify({'success': True, 'message': 'Description updated'})


@evidence_bp.route('/<int:evidence_id>/delete', methods=['POST'])
@login_required
def delete_evidence(evidence_id):
    """Delete an evidence file (admin only)"""
    # Permission check: Admin only
    if current_user.permission_level != 'administrator':
        return jsonify({'success': False, 'error': 'Only administrators can delete evidence files'}), 403
    
    evidence_file = db.session.get(EvidenceFile, evidence_id)
    if not evidence_file:
        return jsonify({'success': False, 'error': 'Evidence file not found'}), 404
    
    filename = evidence_file.original_filename
    file_path = evidence_file.file_path
    
    try:
        # Delete physical file
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # Delete database record
        db.session.delete(evidence_file)
        db.session.commit()
        
        logger.info(f"Evidence file {evidence_id} ({filename}) deleted by {current_user.username}")
        
        return jsonify({'success': True, 'message': 'Evidence file deleted'})
        
    except Exception as e:
        logger.error(f"Error deleting evidence file {evidence_id}: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@evidence_bp.route('/list')
@login_required
def list_evidence_api():
    """API endpoint to list evidence files for active case"""
    case = get_active_case()
    if not case:
        return jsonify({'success': False, 'error': 'No active case'}), 400
    
    page = request.args.get('page', 1, type=int)
    search_term = request.args.get('search', '', type=str).strip()
    per_page = 50
    
    # Base query
    files_query = EvidenceFile.query.filter_by(case_uuid=case.uuid)
    
    # Apply search filter
    if search_term:
        search_filter = or_(
            EvidenceFile.original_filename.ilike(f'%{search_term}%'),
            EvidenceFile.description.ilike(f'%{search_term}%'),
            EvidenceFile.file_hash.ilike(f'%{search_term}%')
        )
        files_query = files_query.filter(search_filter)
    
    files_query = files_query.order_by(EvidenceFile.uploaded_at.desc())
    pagination = files_query.paginate(page=page, per_page=per_page, error_out=False)
    
    files = []
    for ef in pagination.items:
        files.append({
            'id': ef.id,
            'original_filename': ef.original_filename,
            'file_size': ef.file_size,
            'size_display': ef.size_display,
            'file_hash': ef.file_hash,
            'file_type': ef.file_type,
            'description': ef.description,
            'uploaded_by': ef.uploader.username if ef.uploader else '—',
            'uploaded_at': ef.uploaded_at.isoformat() if ef.uploaded_at else None
        })
    
    # Get stats
    stats = EvidenceFile.get_case_stats(case.uuid)
    
    return jsonify({
        'success': True,
        'files': files,
        'page': pagination.page,
        'pages': pagination.pages,
        'total': pagination.total,
        'stats': stats
    })
