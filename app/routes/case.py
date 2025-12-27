"""
Case Routes
Handles case management, dashboard, and case-related operations
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import login_required, current_user
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

case_bp = Blueprint('case', __name__, url_prefix='/case')


@case_bp.route('/dashboard')
@case_bp.route('/dashboard/<int:case_id>')
@login_required
def case_dashboard(case_id=None):
    """
    Case dashboard - displays detailed case information
    If no case_id provided, check session or redirect to case selection
    """
    from main import db
    from models import Case, User
    
    # If no case_id, check session or user assignment
    if case_id is None:
        # Check session for selected case
        case_id = session.get('selected_case_id')
        
        # If still no case_id, check if user has assigned case (for viewers)
        if case_id is None and current_user.role == 'read-only' and current_user.case_assigned:
            case_id = current_user.case_assigned
        
        # If still no case, redirect to selection
        if case_id is None:
            flash('Please select a case to view', 'info')
            return redirect(url_for('case.select_case'))
    
    # Get case
    case = Case.query.get_or_404(case_id)
    
    # Access control for viewers
    if current_user.role == 'read-only':
        if case.id != current_user.case_assigned:
            flash('You do not have access to this case', 'error')
            return redirect(url_for('index'))
    
    # Store selected case in session
    session['selected_case_id'] = case.id
    
    # Get creator and assignee info
    creator = User.query.get(case.created_by) if case.created_by else None
    assignee = User.query.get(case.assigned_to) if case.assigned_to else None
    
    # Get all users for assignment dropdown
    all_users = User.query.filter(
        User.role.in_(['administrator', 'analyst'])
    ).order_by(User.username).all()
    
    return render_template('case/dashboard.html', 
                         case=case, 
                         creator=creator,
                         assignee=assignee,
                         all_users=all_users)


@case_bp.route('/select')
@login_required
def select_case():
    """Case selection page - list all cases user has access to"""
    from models import Case, User
    
    # Viewers can only see their assigned case
    if current_user.role == 'read-only':
        if current_user.case_assigned:
            # Redirect directly to their case
            return redirect(url_for('case.case_dashboard', case_id=current_user.case_assigned))
        else:
            flash('No case assigned to your account. Contact an administrator.', 'warning')
            return redirect(url_for('index'))
    
    # Get all cases for admins and analysts
    cases_query = Case.query
    
    # For analysts, optionally filter to only assigned cases
    # (For now, showing all cases - adjust if needed)
    
    cases = cases_query.order_by(Case.updated_at.desc()).all()
    
    # Get user info for each case
    cases_with_users = []
    for case in cases:
        creator = User.query.get(case.created_by) if case.created_by else None
        assignee = User.query.get(case.assigned_to) if case.assigned_to else None
        cases_with_users.append({
            'case': case,
            'creator': creator,
            'assignee': assignee
        })
    
    # Get all users for assignment dropdown
    all_users = User.query.filter(
        User.role.in_(['administrator', 'analyst'])
    ).order_by(User.username).all()
    
    return render_template('case/select.html', 
                         cases_data=cases_with_users,
                         all_users=all_users)


@case_bp.route('/create', methods=['POST'])
@login_required
def create_case():
    """Create a new case"""
    from main import db
    from models import Case
    from audit_logger import log_action
    
    # Only admins and analysts can create cases
    if current_user.role == 'read-only':
        return jsonify({'error': 'You do not have permission to create cases'}), 403
    
    try:
        data = request.json
        
        # Validate required fields
        if not data.get('name'):
            return jsonify({'error': 'Case name is required'}), 400
        
        # Create new case
        case = Case(
            name=data.get('name'),
            company=data.get('company'),
            description=data.get('description'),
            status=data.get('status', 'New'),
            created_by=current_user.id,
            assigned_to=int(data['assigned_to']) if data.get('assigned_to') else None,
            router_ips=data.get('router_ips'),
            vpn_ips=data.get('vpn_ips'),
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        
        # Generate OpenSearch index name
        db.session.add(case)
        db.session.flush()  # Get the ID
        case.opensearch_index = f'case_{case.id}'
        
        db.session.commit()
        
        # Audit log - comprehensive tracking
        log_action('create_case',
                   resource_type='case',
                   resource_id=case.id,
                   resource_name=case.name,
                   details={
                       'case_id': case.id,
                       'case_name': case.name,
                       'created_by': current_user.username,
                       'company': case.company or 'Not specified',
                       'status': case.status,
                       'assigned_to': case.assigned_to,
                       'opensearch_index': case.opensearch_index
                   })
        
        return jsonify({'success': True, 'case_id': case.id})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating case: {e}")
        return jsonify({'error': str(e)}), 500


@case_bp.route('/select/<int:case_id>', methods=['POST'])
@login_required
def select_case_action(case_id):
    """Set selected case in session and redirect to dashboard"""
    from models import Case
    
    case = Case.query.get_or_404(case_id)
    
    # Access control for viewers
    if current_user.role == 'read-only':
        if case.id != current_user.case_assigned:
            return jsonify({'error': 'Access denied'}), 403
    
    # Store in session
    session['selected_case_id'] = case.id
    
    return jsonify({'success': True, 'redirect': url_for('case.case_dashboard', case_id=case.id)})


@case_bp.route('/<int:case_id>/edit', methods=['POST'])
@login_required
def edit_case(case_id):
    """Update case information"""
    from main import db
    from models import Case
    from audit_logger import log_action
    
    # Only admins and analysts can edit
    if current_user.role == 'read-only':
        return jsonify({'error': 'You do not have permission to edit cases'}), 403
    
    case = Case.query.get_or_404(case_id)
    
    try:
        data = request.json
        changes = {}
        
        # Update fields
        if 'name' in data and data['name'] != case.name:
            changes['name'] = {'old': case.name, 'new': data['name']}
            case.name = data['name']
        
        if 'company' in data and data['company'] != case.company:
            changes['company'] = {'old': case.company, 'new': data['company']}
            case.company = data['company']
        
        if 'description' in data and data['description'] != case.description:
            changes['description'] = 'modified'
            case.description = data['description']
        
        if 'status' in data and data['status'] != case.status:
            changes['status'] = {'old': case.status, 'new': data['status']}
            case.status = data['status']
        
        if 'assigned_to' in data:
            new_assigned = int(data['assigned_to']) if data['assigned_to'] else None
            if new_assigned != case.assigned_to:
                changes['assigned_to'] = {'old': case.assigned_to, 'new': new_assigned}
                case.assigned_to = new_assigned
        
        if 'router_ips' in data and data['router_ips'] != case.router_ips:
            changes['router_ips'] = 'modified'
            case.router_ips = data['router_ips']
        
        if 'vpn_ips' in data and data['vpn_ips'] != case.vpn_ips:
            changes['vpn_ips'] = 'modified'
            case.vpn_ips = data['vpn_ips']
        
        # Update timestamp
        case.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        # Audit log - track all changes
        if changes:
            log_action('modify_case',
                       resource_type='case',
                       resource_id=case.id,
                       resource_name=case.name,
                       details={
                           'case_id': case.id,
                           'case_name': case.name,
                           'modified_by': current_user.username,
                           'changes': changes,
                           'timestamp': datetime.utcnow().isoformat()
                       })
        
        return jsonify({'success': True})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error editing case {case_id}: {e}")
        return jsonify({'error': str(e)}), 500


@case_bp.route('/<int:case_id>/delete', methods=['POST'])
@login_required
def delete_case(case_id):
    """
    Delete a case
    Only administrators can delete cases
    Requires deletion reason
    """
    from main import db
    from models import Case
    from audit_logger import log_action
    
    # Only administrators can delete cases
    if current_user.role != 'administrator':
        return jsonify({'error': 'Only administrators can delete cases'}), 403
    
    case = Case.query.get_or_404(case_id)
    
    # Get reason from request
    data = request.get_json() or {}
    reason = data.get('reason', '').strip()
    
    if not reason:
        return jsonify({'error': 'Deletion reason is required'}), 400
    
    try:
        # Capture case details before deletion
        case_id_copy = case.id
        case_name = case.name
        case_company = case.company
        case_status = case.status
        opensearch_index = case.opensearch_index
        
        # Import required models for cascade deletion
        from models import CaseFile, KnownSystem, KnownUser, EventIOCHit, EventSigmaHit, IOC
        
        # Delete all child records to avoid foreign key constraint violations
        # These tables have case_id as NOT NULL foreign key
        
        # Delete EventIOCHit records
        EventIOCHit.query.filter_by(case_id=case_id_copy).delete()
        
        # Delete EventSigmaHit records
        EventSigmaHit.query.filter_by(case_id=case_id_copy).delete()
        
        # Delete IOCs (nullable but should be cleaned up)
        IOC.query.filter_by(case_id=case_id_copy).delete()
        
        # Delete KnownUsers
        KnownUser.query.filter_by(case_id=case_id_copy).delete()
        
        # Delete KnownSystems
        KnownSystem.query.filter_by(case_id=case_id_copy).delete()
        
        # Delete CaseFiles
        CaseFile.query.filter_by(case_id=case_id_copy).delete()
        
        # Delete the case
        db.session.delete(case)
        db.session.commit()
        
        # Comprehensive audit log
        log_action('delete_case',
                   resource_type='case',
                   resource_id=case_id_copy,
                   resource_name=case_name,
                   details={
                       'case_id': case_id_copy,
                       'case_name': case_name,
                       'deleted_by': current_user.username,
                       'reason': reason,
                       'company': case_company,
                       'status': case_status,
                       'opensearch_index': opensearch_index,
                       'timestamp': datetime.utcnow().isoformat()
                   })
        
        return jsonify({'success': True})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting case {case_id}: {e}")
        return jsonify({'error': str(e)}), 500


@case_bp.route('/files')
@case_bp.route('/<int:case_id>/files', methods=['GET'])
@login_required
def case_files(case_id=None):
    """
    Case files page - displays uploaded files and statistics
    Shows stats for specified case or currently selected case
    """
    from main import db
    from models import Case, User, CaseFile
    import os
    
    # If no case_id provided, get from session
    if case_id is None:
        case_id = session.get('selected_case_id')
        
        # For viewers, auto-select their assigned case
        if case_id is None and current_user.role == 'read-only' and current_user.case_assigned:
            case_id = current_user.case_assigned
            session['selected_case_id'] = case_id
        
        if case_id is None:
            flash('Please select a case first', 'info')
            return redirect(url_for('case.select_case'))
    
    # Get case
    case = Case.query.get_or_404(case_id)
    
    # Access control for viewers
    if current_user.role == 'read-only':
        if case.id != current_user.case_assigned:
            flash('You do not have access to this case', 'error')
            return redirect(url_for('index'))
    
    # Store selected case in session
    session['selected_case_id'] = case.id
    
    # Check filter parameters
    show_hidden = request.args.get('show_hidden', 'false').lower() == 'true'
    only_hidden = request.args.get('only_hidden', 'false').lower() == 'true'
    
    # Calculate statistics
    storage_path = f'/opt/casescope/storage/case_{case_id}'
    staging_path = f'/opt/casescope/staging/{case_id}'
    
    # Total files in storage
    total_files = 0
    total_size = 0
    if os.path.exists(storage_path):
        for filename in os.listdir(storage_path):
            file_path = os.path.join(storage_path, filename)
            if os.path.isfile(file_path):
                total_files += 1
                total_size += os.path.getsize(file_path)
    
    # Pending files in staging
    pending_files = 0
    if os.path.exists(staging_path):
        pending_files = len([f for f in os.listdir(staging_path) if os.path.isfile(os.path.join(staging_path, f))])
    
    # Get event count from OpenSearch
    total_events = 0
    try:
        from opensearch_indexer import OpenSearchIndexer
        indexer = OpenSearchIndexer()
        index_name = f"case_{case_id}"
        total_events = indexer.get_event_count(index_name)
    except Exception as e:
        logger.error(f"Error getting event count: {e}")
    
    # Calculate indexed files (files with events)
    indexed_files = total_files - pending_files if total_events > 0 else 0
    
    # Get hidden file count
    hidden_count = CaseFile.query.filter_by(case_id=case_id, is_hidden=True).count()
    
    stats = {
        'total_files': total_files,
        'total_events': total_events,
        'indexed_files': indexed_files,
        'pending_files': pending_files,
        'hidden_files': hidden_count,
        'total_size_gb': total_size / (1024**3) if total_size > 0 else 0
    }
    
    # Get file list from database based on filter
    if only_hidden:
        files = CaseFile.query.filter_by(case_id=case_id, is_hidden=True).order_by(CaseFile.uploaded_at.desc()).all()
    elif show_hidden:
        files = CaseFile.query.filter_by(case_id=case_id).order_by(CaseFile.uploaded_at.desc()).all()
    else:
        # Default: hide hidden files
        files = CaseFile.query.filter_by(case_id=case_id, is_hidden=False).order_by(CaseFile.uploaded_at.desc()).all()
    
    return render_template('case/files.html', case=case, stats=stats, files=files, show_hidden=show_hidden, only_hidden=only_hidden)


@case_bp.route('/<int:case_id>/files/stats', methods=['GET'])
@login_required
def case_files_stats(case_id):
    """
    API endpoint for real-time stats updates
    Returns JSON with current file statistics
    """
    from models import Case, CaseFile
    import os
    
    case = Case.query.get_or_404(case_id)
    
    # Access control
    if current_user.role == 'read-only':
        if case.id != current_user.case_assigned:
            return jsonify({'error': 'Access denied'}), 403
    
    # Calculate statistics
    storage_path = f'/opt/casescope/storage/case_{case_id}'
    staging_path = f'/opt/casescope/staging/{case_id}'
    
    # Total files in storage
    total_files = 0
    total_size = 0
    if os.path.exists(storage_path):
        for filename in os.listdir(storage_path):
            file_path = os.path.join(storage_path, filename)
            if os.path.isfile(file_path):
                total_files += 1
                total_size += os.path.getsize(file_path)
    
    # Pending files in staging
    pending_files = 0
    if os.path.exists(staging_path):
        pending_files = len([f for f in os.listdir(staging_path) if os.path.isfile(os.path.join(staging_path, f))])
    
    # Get event count from OpenSearch
    total_events = 0
    try:
        from opensearch_indexer import OpenSearchIndexer
        indexer = OpenSearchIndexer()
        index_name = f"case_{case_id}"
        total_events = indexer.get_event_count(index_name)
    except Exception as e:
        logger.error(f"Error getting event count: {e}")
    
    # Get file counts by status
    processing_count = CaseFile.query.filter_by(case_id=case_id, status='processing').count()
    indexed_count = CaseFile.query.filter_by(case_id=case_id, status='indexed').count()
    failed_count = CaseFile.query.filter_by(case_id=case_id, status='failed').count()
    
    # Get recently updated files (last 10)
    recent_files = CaseFile.query.filter_by(case_id=case_id)\
        .order_by(CaseFile.uploaded_at.desc())\
        .limit(10)\
        .all()
    
    files_data = []
    for f in recent_files:
        files_data.append({
            'id': f.id,
            'filename': f.filename,
            'source_system': f.source_system,
            'event_count': f.event_count,
            'status': f.status,
            'uploaded_at': f.uploaded_at.isoformat() if f.uploaded_at else None,
            'uploader': f.uploader.username if f.uploader else 'Unknown'
        })
    
    return jsonify({
        'stats': {
            'total_files': total_files,
            'total_events': total_events,
            'indexed_files': indexed_count,
            'pending_files': pending_files,
            'processing_files': processing_count,
            'failed_files': failed_count,
            'total_size_gb': round(total_size / (1024**3), 2) if total_size > 0 else 0
        },
        'recent_files': files_data,
        'timestamp': datetime.utcnow().isoformat()
    })


@case_bp.route('/files/upload')
@case_bp.route('/<int:case_id>/files/upload')
@login_required
def files_upload(case_id=None):
    """
    File upload page
    """
    from models import Case
    
    # If no case_id provided, get from session
    if case_id is None:
        case_id = session.get('selected_case_id')
        
        if case_id is None:
            if current_user.role == 'read-only' and current_user.case_assigned:
                case_id = current_user.case_assigned
                session['selected_case_id'] = case_id
            else:
                flash('Please select a case first', 'info')
                return redirect(url_for('case.select_case'))
    
    # Get case
    case = Case.query.get_or_404(case_id)
    
    # Store selected case in session
    session['selected_case_id'] = case.id
    
    # Access control for viewers
    if current_user.role == 'read-only':
        flash('You do not have permission to upload files', 'error')
        return redirect(url_for('case.case_files', case_id=case.id))
    
    # Get worker count from config
    import config
    workers = config.CELERY_WORKERS
    
    return render_template('case/upload.html', case=case, workers=workers)


@case_bp.route('/<int:case_id>/scan-bulk-upload', methods=['POST'])
@login_required
def scan_bulk_upload(case_id):
    """
    Scan the bulk upload folder for new files and queue them for processing
    """
    import os
    from audit_logger import log_action
    from tasks.task_file_upload import process_uploaded_files
    
    # Only admins and analysts can scan
    if current_user.role == 'read-only':
        return jsonify({'error': 'You do not have permission to scan for files'}), 403
    
    # Get case
    from models import Case
    case = Case.query.get_or_404(case_id)
    
    # Define paths
    upload_path = f'/opt/casescope/bulk_upload/{case_id}/'
    
    try:
        # Check if upload folder exists
        if not os.path.exists(upload_path):
            return jsonify({
                'success': True,
                'files_found': 0,
                'message': f'Folder not found. Please create: {upload_path}'
            })
        
        # Scan for files
        files_found = []
        for filename in os.listdir(upload_path):
            file_path = os.path.join(upload_path, filename)
            if os.path.isfile(file_path):
                files_found.append(filename)
        
        if len(files_found) == 0:
            return jsonify({
                'success': True,
                'files_found': 0,
                'message': f'No files found in {upload_path}'
            })
        
        # Queue task for background processing
        task = process_uploaded_files.delay(case_id, files_found)
        
        # Audit log
        log_action('scan_bulk_upload',
                   resource_type='case',
                   resource_id=case_id,
                   resource_name=case.name,
                   details={
                       'scanned_by': current_user.username,
                       'folder': upload_path,
                       'files_found': len(files_found),
                       'files': files_found,
                       'task_id': task.id
                   })
        
        return jsonify({
            'success': True,
            'files_found': len(files_found),
            'task_id': task.id,
            'message': f'Found {len(files_found)} file(s). Processing started in background.'
        })
        
    except Exception as e:
        logger.error(f"Error scanning bulk upload folder for case {case_id}: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@case_bp.route('/<int:case_id>/edr-report')
@login_required
def get_edr_report(case_id):
    """Get EDR reports for a case (for modal display)"""
    from models import Case
    
    case = Case.query.get_or_404(case_id)
    
    # Access control for viewers
    if current_user.role == 'read-only':
        if case.id != current_user.case_assigned:
            return jsonify({'error': 'Access denied'}), 403
    
    return jsonify({
        'success': True,
        'edr_reports': case.edr_reports or 'No EDR reports available for this case.'
    })


@case_bp.route('/<int:case_id>/edr-report', methods=['POST'])
@login_required
def update_edr_report(case_id):
    """Update EDR reports for a case"""
    from main import db
    from models import Case
    from audit_logger import log_action
    
    # Only admins and analysts can edit
    if current_user.role == 'read-only':
        return jsonify({'error': 'You do not have permission to edit EDR reports'}), 403
    
    case = Case.query.get_or_404(case_id)
    
    try:
        edr_reports = request.json.get('edr_reports', '').strip()
        
        # Track change for audit
        old_value = case.edr_reports
        case.edr_reports = edr_reports
        case.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        # Audit log
        log_action('modify_case_edr', 
                   resource_type='case',
                   resource_id=case.id,
                   resource_name=case.name,
                   details={
                       'field': 'edr_reports',
                       'had_previous': bool(old_value),
                       'now_has': bool(edr_reports),
                       'report_count': len(edr_reports.split('*** NEW REPORT ***')) if edr_reports else 0
                   })
        
        return jsonify({'success': True})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating EDR report for case {case_id}: {e}")
        return jsonify({'error': str(e)}), 500
