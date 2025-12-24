"""
Evidence Files Blueprint - Archival storage for screenshots, exports, etc.
NOT for logs (unless they cannot be readily ingested)
These files are stored but NOT processed/indexed
"""

from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, send_from_directory
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
import os
import hashlib
import mimetypes
import logging
from datetime import datetime
from sqlalchemy import func, or_

logger = logging.getLogger(__name__)

evidence_bp = Blueprint('evidence', __name__, url_prefix='/evidence')


def get_evidence_storage_path(case_id: int) -> str:
    """Get evidence storage directory for a case"""
    path = f"/opt/casescope/evidence/{case_id}"
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


@evidence_bp.route('/case/<int:case_id>')
@login_required
def list_evidence_files(case_id):
    """List all evidence files for a case"""
    from main import db, Case, EvidenceFile, User
    
    case = db.session.get(Case, case_id)
    if not case:
        flash('Case not found', 'error')
        return redirect(url_for('dashboard'))
    
    # Pagination and search
    page = request.args.get('page', 1, type=int)
    search_term = request.args.get('search', '', type=str).strip()
    per_page = 50
    
    # Base query
    files_query = db.session.query(EvidenceFile).filter_by(case_id=case_id)
    
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
    
    # Get files with uploader info
    files = []
    for evidence_file in pagination.items:
        uploader = db.session.get(User, evidence_file.uploaded_by) if evidence_file.uploaded_by else None
        file_data = {
            'id': evidence_file.id,
            'original_filename': evidence_file.original_filename,
            'file_size': evidence_file.file_size,
            'size_mb': evidence_file.size_mb,
            'file_hash': evidence_file.file_hash,
            'file_type': evidence_file.file_type,
            'description': evidence_file.description,
            'uploaded_by': uploader.username if uploader else '—',
            'uploaded_at': evidence_file.uploaded_at
        }
        files.append(file_data)
    
    # Statistics
    total_files = db.session.query(EvidenceFile).filter_by(case_id=case_id).count()
    total_space_bytes = db.session.query(func.sum(EvidenceFile.file_size)).filter_by(case_id=case_id).scalar() or 0
    total_space_gb = total_space_bytes / (1024**3)
    
    # File type counts
    file_types = {}
    all_files = db.session.query(EvidenceFile).filter_by(case_id=case_id).all()
    for f in all_files:
        ft = f.file_type or 'UNKNOWN'
        file_types[ft] = file_types.get(ft, 0) + 1
    
    # Sort file types by count (descending)
    file_types = dict(sorted(file_types.items(), key=lambda x: x[1], reverse=True))
    
    return render_template('evidence_files.html',
                          case=case,
                          files=files,
                          pagination=pagination,
                          search_term=search_term,
                          total_files=total_files,
                          total_space_gb=total_space_gb,
                          file_types=file_types)


@evidence_bp.route('/case/<int:case_id>/upload', methods=['POST'])
@login_required
def upload_evidence(case_id):
    """Upload evidence file(s) via HTTP"""
    from main import db, Case, EvidenceFile
    from audit_logger import log_file_action
    
    # Permission check
    if current_user.role == 'read-only':
        return jsonify({'success': False, 'error': 'Read-only users cannot upload files'}), 403
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    if 'files' not in request.files:
        return jsonify({'success': False, 'error': 'No files provided'}), 400
    
    files = request.files.getlist('files')
    if not files or files[0].filename == '':
        return jsonify({'success': False, 'error': 'No files selected'}), 400
    
    storage_path = get_evidence_storage_path(case_id)
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
                case_id=case_id,
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
            
            # Audit log
            log_file_action('upload_evidence', evidence_file.id, original_filename, details={
                'case_id': case_id,
                'file_type': file_type,
                'size_mb': size_mb
            })
            
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


@evidence_bp.route('/case/<int:case_id>/bulk_import', methods=['POST'])
@login_required
def bulk_import_evidence(case_id):
    """Import evidence files from bulk upload folder"""
    from main import db, Case, EvidenceFile
    from audit_logger import log_file_action
    import shutil
    
    # Permission check
    if current_user.role == 'read-only':
        return jsonify({'success': False, 'error': 'Read-only users cannot import files'}), 403
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    bulk_folder = '/opt/casescope/evidence_uploads'
    if not os.path.exists(bulk_folder) or not os.listdir(bulk_folder):
        return jsonify({'success': False, 'error': 'Bulk upload folder is empty'}), 400
    
    storage_path = get_evidence_storage_path(case_id)
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
            
            # Copy file
            shutil.copy2(source_path, dest_path)
            
            # Calculate file info
            file_size = os.path.getsize(dest_path)
            size_mb = round(file_size / (1024 * 1024))
            file_hash = calculate_file_hash(dest_path)
            file_type = detect_file_type(original_filename)
            mime_type = mimetypes.guess_type(original_filename)[0]
            
            # Create database record
            evidence_file = EvidenceFile(
                case_id=case_id,
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
    
    # Audit log
    if imported_files:
        log_file_action('bulk_import_evidence', case_id, f'{len(imported_files)} files', details={
            'case_id': case_id,
            'file_count': len(imported_files),
            'failed_count': len(errors)
        })
    
    if imported_files:
        message = f'Imported {len(imported_files)} file(s)'
        if errors:
            message += f' ({len(errors)} failed)'
        flash(message, 'success')
        return jsonify({'success': True, 'message': message, 'imported': len(imported_files), 'errors': errors})
    else:
        return jsonify({'success': False, 'error': 'All imports failed', 'errors': errors}), 500


@evidence_bp.route('/<int:evidence_id>/download')
@login_required
def download_evidence(evidence_id):
    """Download an evidence file"""
    from main import db, EvidenceFile
    
    evidence_file = db.session.get(EvidenceFile, evidence_id)
    if not evidence_file:
        flash('Evidence file not found', 'error')
        return redirect(url_for('dashboard'))
    
    directory = os.path.dirname(evidence_file.file_path)
    filename = os.path.basename(evidence_file.file_path)
    
    return send_from_directory(directory, filename, as_attachment=True, download_name=evidence_file.original_filename)


@evidence_bp.route('/<int:evidence_id>/edit', methods=['POST'])
@login_required
def edit_evidence_description(evidence_id):
    """Edit evidence file description"""
    from main import db, EvidenceFile
    from audit_logger import log_file_action
    
    # Permission check
    if current_user.role == 'read-only':
        return jsonify({'success': False, 'error': 'Read-only users cannot edit files'}), 403
    
    evidence_file = db.session.get(EvidenceFile, evidence_id)
    if not evidence_file:
        return jsonify({'success': False, 'error': 'Evidence file not found'}), 404
    
    data = request.get_json()
    new_description = data.get('description', '').strip()
    
    old_description = evidence_file.description
    evidence_file.description = new_description
    db.session.commit()
    
    # Audit log
    log_file_action('edit_evidence_description', evidence_id, evidence_file.original_filename, details={
        'case_id': evidence_file.case_id,
        'old_description': old_description,
        'new_description': new_description
    })
    
    return jsonify({'success': True, 'message': 'Description updated'})


@evidence_bp.route('/<int:evidence_id>/delete', methods=['POST'])
@login_required
def delete_evidence(evidence_id):
    """Delete an evidence file (admin only)"""
    from main import db, EvidenceFile
    from audit_logger import log_file_action
    
    # Permission check: Admin only
    if current_user.role != 'administrator':
        return jsonify({'success': False, 'error': 'Only administrators can delete evidence files'}), 403
    
    evidence_file = db.session.get(EvidenceFile, evidence_id)
    if not evidence_file:
        return jsonify({'success': False, 'error': 'Evidence file not found'}), 404
    
    case_id = evidence_file.case_id
    filename = evidence_file.original_filename
    file_path = evidence_file.file_path
    
    try:
        # Delete physical file
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # Delete database record
        db.session.delete(evidence_file)
        db.session.commit()
        
        # Audit log
        log_file_action('delete_evidence', evidence_id, filename, details={
            'case_id': case_id,
            'file_hash': evidence_file.file_hash,
            'admin_only': True
        })
        
        return jsonify({'success': True, 'message': 'Evidence file deleted'})
        
    except Exception as e:
        logger.error(f"Error deleting evidence file {evidence_id}: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@evidence_bp.route('/<int:evidence_id>/sync_to_dfir_iris', methods=['POST'])
@login_required
def sync_evidence_to_dfir_iris(evidence_id):
    """Sync single evidence file to DFIR-IRIS"""
    from main import db, EvidenceFile, Case, SystemSettings
    from dfir_iris import DFIRIrisClient
    from audit_logger import log_file_action
    from datetime import datetime
    
    # Permission check
    if current_user.role == 'read-only':
        return jsonify({'success': False, 'error': 'Read-only users cannot sync files'}), 403
    
    evidence_file = db.session.get(EvidenceFile, evidence_id)
    if not evidence_file:
        return jsonify({'success': False, 'error': 'Evidence file not found'}), 404
    
    case = db.session.get(Case, evidence_file.case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    # Check DFIR-IRIS configuration
    dfir_iris_url = SystemSettings.query.filter_by(setting_key='dfir_iris_url').first()
    dfir_iris_api_key = SystemSettings.query.filter_by(setting_key='dfir_iris_api_key').first()
    
    if not dfir_iris_url or not dfir_iris_api_key:
        return jsonify({
            'success': False,
            'message': '✗ DFIR-IRIS URL and API key must be configured'
        })
    
    try:
        # Initialize DFIR-IRIS client
        client = DFIRIrisClient(dfir_iris_url.setting_value, dfir_iris_api_key.setting_value)
        
        # Get or create customer and case in DFIR-IRIS
        company_name = case.company or 'Unknown Company'
        customer_id = client.get_or_create_customer(company_name)
        if not customer_id:
            return jsonify({
                'success': False,
                'message': '✗ Failed to get/create customer in DFIR-IRIS'
            })
        
        iris_case_id = client.get_or_create_case(customer_id, case.name, case.description or '', company_name)
        if not iris_case_id:
            return jsonify({
                'success': False,
                'message': '✗ Failed to get/create case in DFIR-IRIS'
            })
        
        # Upload evidence file to DFIR-IRIS
        file_id = client.upload_evidence_file(
            iris_case_id,
            evidence_file.file_path,
            evidence_file.original_filename,
            evidence_file.description or ''
        )
        
        if file_id:
            # Update evidence file record
            evidence_file.dfir_iris_synced = True
            evidence_file.dfir_iris_file_id = str(file_id)
            evidence_file.dfir_iris_sync_date = datetime.utcnow()
            db.session.commit()
            
            # Audit log
            log_file_action('sync_evidence_to_dfir_iris', evidence_id, evidence_file.original_filename, details={
                'case_id': evidence_file.case_id,
                'iris_file_id': file_id,
                'iris_case_id': iris_case_id
            })
            
            return jsonify({
                'success': True,
                'message': f'✓ Evidence file synced to DFIR-IRIS (File ID: {file_id})'
            })
        else:
            return jsonify({
                'success': False,
                'message': '✗ Failed to upload file to DFIR-IRIS'
            })
        
    except Exception as e:
        logger.error(f"Error syncing evidence file {evidence_id} to DFIR-IRIS: {e}")
        return jsonify({'success': False, 'message': f'✗ Error: {str(e)}'}), 500


@evidence_bp.route('/case/<int:case_id>/bulk_sync_to_dfir_iris', methods=['POST'])
@login_required
def bulk_sync_evidence_to_dfir_iris(case_id):
    """Bulk sync all evidence files to DFIR-IRIS"""
    from main import db, EvidenceFile, Case, SystemSettings
    from dfir_iris import DFIRIrisClient
    from audit_logger import log_file_action
    from datetime import datetime
    
    # Permission check
    if current_user.role == 'read-only':
        return jsonify({'success': False, 'error': 'Read-only users cannot sync files'}), 403
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    # Check DFIR-IRIS configuration
    dfir_iris_url = SystemSettings.query.filter_by(setting_key='dfir_iris_url').first()
    dfir_iris_api_key = SystemSettings.query.filter_by(setting_key='dfir_iris_api_key').first()
    
    if not dfir_iris_url or not dfir_iris_api_key:
        return jsonify({
            'success': False,
            'message': '✗ DFIR-IRIS URL and API key must be configured'
        })
    
    # Get all evidence files for this case
    evidence_files = EvidenceFile.query.filter_by(case_id=case_id).all()
    
    if not evidence_files:
        return jsonify({
            'success': True,
            'message': 'No evidence files to sync',
            'synced': 0,
            'failed': 0
        })
    
    synced = 0
    failed = 0
    errors = []
    
    try:
        # Initialize DFIR-IRIS client
        client = DFIRIrisClient(dfir_iris_url.setting_value, dfir_iris_api_key.setting_value)
        
        # Get or create customer and case in DFIR-IRIS
        company_name = case.company or 'Unknown Company'
        customer_id = client.get_or_create_customer(company_name)
        if not customer_id:
            return jsonify({
                'success': False,
                'message': '✗ Failed to get/create customer in DFIR-IRIS'
            })
        
        iris_case_id = client.get_or_create_case(customer_id, case.name, case.description or '', company_name)
        if not iris_case_id:
            return jsonify({
                'success': False,
                'message': '✗ Failed to get/create case in DFIR-IRIS'
            })
        
        # Sync each evidence file
        for evidence_file in evidence_files:
            try:
                # Check if file exists on disk
                if not os.path.exists(evidence_file.file_path):
                    logger.warning(f"Evidence file not found on disk: {evidence_file.file_path}")
                    failed += 1
                    errors.append(f'{evidence_file.original_filename}: File not found on disk')
                    continue
                
                # Upload to DFIR-IRIS
                file_id = client.upload_evidence_file(
                    iris_case_id,
                    evidence_file.file_path,
                    evidence_file.original_filename,
                    evidence_file.description or ''
                )
                
                if file_id:
                    # Update evidence file record
                    evidence_file.dfir_iris_synced = True
                    evidence_file.dfir_iris_file_id = str(file_id)
                    evidence_file.dfir_iris_sync_date = datetime.utcnow()
                    db.session.commit()
                    synced += 1
                else:
                    failed += 1
                    errors.append(f'{evidence_file.original_filename}: Upload failed')
                    
            except Exception as e:
                logger.error(f"Error syncing evidence file {evidence_file.id}: {e}")
                failed += 1
                errors.append(f'{evidence_file.original_filename}: {str(e)}')
                db.session.rollback()
        
        # Audit log
        log_file_action('bulk_sync_evidence_to_dfir_iris', case_id, f'{synced} evidence files', details={
            'case_id': case_id,
            'synced_count': synced,
            'failed_count': failed,
            'iris_case_id': iris_case_id
        })
        
        message = f'✓ Synced {synced} evidence file(s) to DFIR-IRIS'
        if failed > 0:
            message += f' ({failed} failed)'
        
        return jsonify({
            'success': True,
            'message': message,
            'synced': synced,
            'failed': failed,
            'errors': errors[:10]  # Limit to first 10 errors
        })
        
    except Exception as e:
        logger.error(f"Error in bulk evidence sync for case {case_id}: {e}")
        return jsonify({'success': False, 'message': f'✗ Error: {str(e)}'}), 500

