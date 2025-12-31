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
        
        # Create upload folders for this case (NEW_FILE_UPLOAD.ND Phase 2)
        import os
        import stat
        
        case_folders = [
            f'/opt/casescope/uploads/web/{case.id}',
            f'/opt/casescope/uploads/sftp/{case.id}',
        ]
        
        for folder in case_folders:
            try:
                os.makedirs(folder, mode=0o770, exist_ok=True)
                # SFTP folder needs read/write/delete for casescope user and group
                if 'sftp' in folder:
                    os.chmod(folder, stat.S_IRWXU | stat.S_IRWXG)  # 770
            except Exception as e:
                logger.warning(f"Could not create folder {folder}: {e}")
        
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
                       'opensearch_index': case.opensearch_index,
                       'upload_folders_created': case_folders
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
    
    # Pending files - files that are being processed (query database, not filesystem)
    pending_files = CaseFile.query.filter_by(case_id=case_id).filter(
        CaseFile.status.in_(['pending', 'processing', 'parsing', 'extracting'])
    ).count()
    
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
    
    # Get file list from database (ONLY physical files, not virtual)
    # Virtual files are shown within ZIP expansion
    query = CaseFile.query.filter_by(case_id=case_id, is_virtual=False)
    
    if only_hidden:
        query = query.filter_by(is_hidden=True)
    elif not show_hidden:
        query = query.filter_by(is_hidden=False)
    
    files = query.order_by(CaseFile.uploaded_at.desc()).all()
    
    # For each container (ZIP), get child count
    for file in files:
        if file.is_container:
            file.child_count = CaseFile.query.filter_by(parent_file_id=file.id).count()
        else:
            file.child_count = 0
    
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
    
    # Pending files - files that are being processed (query database, not filesystem)
    pending_files = CaseFile.query.filter_by(case_id=case_id).filter(
        CaseFile.status.in_(['pending', 'processing', 'parsing', 'extracting'])
    ).count()
    
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
    processing_count = CaseFile.query.filter_by(case_id=case_id).filter(
        CaseFile.status.in_(['New', 'processing', 'parsing', 'extracting'])
    ).count()
    indexed_count = CaseFile.query.filter_by(case_id=case_id, status='indexed').count()
    failed_count = CaseFile.query.filter_by(case_id=case_id, status='failed').count()
    
    stats = {
        'total_files': total_files,
        'total_events': total_events,
        'indexed_files': indexed_count,
        'pending_files': pending_files,
        'processing_files': processing_count,
        'failed_files': failed_count,
        'total_size_gb': total_size / (1024**3) if total_size > 0 else 0
    }
    
    return jsonify({'stats': stats})


@case_bp.route('/<int:case_id>/files/<int:container_id>/contents', methods=['GET'])
@login_required
def get_zip_contents(case_id, container_id):
    """
    API endpoint to fetch contents of a ZIP container
    Supports pagination for large ZIPs
    
    Query params:
    - page: Page number (default 1)
    - per_page: Items per page (default 50, max 100)
    - group_by: 'system' to group by source_system
    """
    from models import Case, CaseFile
    
    case = Case.query.get_or_404(case_id)
    
    # Access control
    if current_user.role == 'read-only':
        if case.id != current_user.case_assigned:
            return jsonify({'error': 'Access denied'}), 403
    
    # Get container
    container = CaseFile.query.filter_by(id=container_id, case_id=case_id, is_container=True).first_or_404()
    
    # Pagination params
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 100)
    group_by = request.args.get('group_by', None)
    
    # Get virtual files for this container
    query = CaseFile.query.filter_by(parent_file_id=container_id, is_virtual=True)
    
    # Group by system if requested
    if group_by == 'system':
        # Get all files grouped by source_system
        all_files = query.order_by(CaseFile.source_system, CaseFile.original_filename).all()
        
        # Group files
        grouped = {}
        for file in all_files:
            system = file.source_system or 'Unknown'
            if system not in grouped:
                grouped[system] = []
            grouped[system].append({
                'id': file.id,
                'filename': file.original_filename,
                'file_type': file.file_type,
                'file_size': file.file_size,
                'event_count': file.event_count,
                'status': file.status,
                'target_index': file.target_index,
                'error_message': file.error_message
            })
        
        return jsonify({
            'container_id': container_id,
            'container_name': container.original_filename,
            'total_files': len(all_files),
            'grouped': True,
            'systems': [{
                'system': system,
                'file_count': len(files),
                'files': files
            } for system, files in grouped.items()]
        })
    
    else:
        # Paginated flat list
        pagination = query.order_by(CaseFile.original_filename).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        files_data = [{
            'id': file.id,
            'filename': file.original_filename,
            'file_type': file.file_type,
            'file_size': file.file_size,
            'event_count': file.event_count,
            'status': file.status,
            'source_system': file.source_system or '-',
            'parser_type': file.parser_type or '-',
            'target_index': file.target_index,
            'error_message': file.error_message,
            'parsing_status': file.parsing_status,
            'indexing_status': file.indexing_status
        } for file in pagination.items]
        
        return jsonify({
            'container_id': container_id,
            'container_name': container.original_filename,
            'page': page,
            'per_page': per_page,
            'total_files': pagination.total,
            'total_pages': pagination.pages,
            'has_next': pagination.has_next,
            'has_prev': pagination.has_prev,
            'files': files_data
        })


@case_bp.route('/<int:case_id>/files/active-tasks', methods=['GET'])
@login_required
def get_active_tasks(case_id):
    """
    Get list of files currently being processed by Celery workers
    Returns files actively being indexed with ZIP context
    """
    from models import Case, CaseFile
    from celery_app import celery
    
    case = Case.query.get_or_404(case_id)
    
    # Access control
    if current_user.role == 'read-only':
        if case.id != current_user.case_assigned:
            return jsonify({'error': 'Access denied'}), 403
    
    active_files = []
    
    try:
        # Inspect Celery workers for active tasks
        i = celery.control.inspect()
        active_tasks = i.active()
        
        if not active_tasks:
            return jsonify({'active_files': []})
        
        # Process each worker's tasks
        for worker_name, tasks in active_tasks.items():
            for task in tasks:
                # Only care about parse_and_index_file tasks
                if task.get('name') == 'tasks.parse_and_index_file':
                    try:
                        # Extract file_id from task args [case_id, file_id, file_path, target_index]
                        task_args = task.get('args', [])
                        if len(task_args) >= 2:
                            task_case_id = task_args[0]
                            file_id = task_args[1]
                            
                            # Only include tasks for this case
                            if task_case_id != case_id:
                                continue
                            
                            # Get file from database
                            file = CaseFile.query.get(file_id)
                            if file:
                                # Get parent ZIP name if this is a virtual file
                                parent_zip_name = None
                                if file.is_virtual and file.parent_file_id:
                                    parent = CaseFile.query.get(file.parent_file_id)
                                    if parent:
                                        parent_zip_name = parent.filename
                                
                                active_files.append({
                                    'filename': file.filename,
                                    'original_filename': file.original_filename or file.filename,
                                    'parent_zip': parent_zip_name,
                                    'is_virtual': file.is_virtual,
                                    'worker': worker_name.split('@')[0] if '@' in worker_name else worker_name
                                })
                    except Exception as e:
                        logger.error(f"Error parsing active task: {e}")
                        continue
        
        return jsonify({'active_files': active_files})
        
    except Exception as e:
        logger.error(f"Error inspecting Celery tasks: {e}")
        return jsonify({'active_files': [], 'error': str(e)})


@case_bp.route('/<int:case_id>/files/<int:container_id>/breakdown', methods=['GET'])
@login_required
def get_zip_breakdown(case_id, container_id):
    """
    API endpoint to get detailed breakdown of ZIP container files
    Shows statistics by file type, status, and events
    """
    from models import Case, CaseFile
    from sqlalchemy import func
    
    case = Case.query.get_or_404(case_id)
    
    # Access control
    if current_user.role == 'read-only':
        if case.id != current_user.case_assigned:
            return jsonify({'error': 'Access denied'}), 403
    
    # Get container
    container = CaseFile.query.filter_by(id=container_id, case_id=case_id, is_container=True).first_or_404()
    
    # Get all child files
    children = CaseFile.query.filter_by(parent_file_id=container_id, is_virtual=True).all()
    
    # Calculate statistics
    total_files = len(children)
    indexed_files = len([f for f in children if f.status == 'indexed'])
    failed_files = len([f for f in children if f.status == 'failed'])
    total_events = sum(f.event_count or 0 for f in children if f.status == 'indexed')
    
    # Breakdown by file type - Indexed
    indexed_by_type = {}
    for file in children:
        if file.status == 'indexed':
            ext = file.file_type or 'unknown'
            if ext not in indexed_by_type:
                indexed_by_type[ext] = {'count': 0, 'events': 0}
            indexed_by_type[ext]['count'] += 1
            indexed_by_type[ext]['events'] += file.event_count or 0
    
    # Breakdown by file type - Failed
    failed_by_type = {}
    for file in children:
        if file.status == 'failed':
            ext = file.file_type or 'unknown'
            if ext not in failed_by_type:
                failed_by_type[ext] = {'count': 0, 'sample_error': None}
            failed_by_type[ext]['count'] += 1
            if not failed_by_type[ext]['sample_error'] and file.error_message:
                failed_by_type[ext]['sample_error'] = file.error_message
    
    return jsonify({
        'container_id': container_id,
        'container_name': container.original_filename,
        'container_status': container.status,
        'total_files': total_files,
        'indexed_files': indexed_files,
        'failed_files': failed_files,
        'total_events': total_events,
        'indexed_by_type': indexed_by_type,
        'failed_by_type': failed_by_type
    })


@case_bp.route('/<int:case_id>/files/<int:file_id>/download', methods=['GET'])
@login_required
def download_file(case_id, file_id):
    """
    Download a file (virtual or physical)
    
    For virtual files: Extract from ZIP on-demand
    For physical files: Serve directly from storage
    
    Hybrid approach:
    - Files <100MB: Extract to memory, stream response
    - Files >100MB: Extract to temp file, send_file
    """
    from flask import send_file, Response
    from models import Case, CaseFile
    import os
    import zipfile
    import tempfile
    import io
    
    case = Case.query.get_or_404(case_id)
    
    # Access control
    if current_user.role == 'read-only':
        if case.id != current_user.case_assigned:
            return jsonify({'error': 'Access denied'}), 403
    
    # Get file record
    file_record = CaseFile.query.filter_by(id=file_id, case_id=case_id).first_or_404()
    
    # VIRTUAL FILE: Extract from parent ZIP
    if file_record.is_virtual:
        # Get parent container
        if not file_record.parent_file_id:
            return jsonify({'error': 'Virtual file has no parent container'}), 500
        
        parent = CaseFile.query.get(file_record.parent_file_id)
        if not parent or not parent.is_container:
            return jsonify({'error': 'Parent container not found'}), 500
        
        zip_path = parent.file_path
        if not os.path.exists(zip_path):
            return jsonify({'error': 'Parent ZIP file not found on disk'}), 404
        
        try:
            # Find the file in ZIP (match by original filename)
            with zipfile.ZipFile(zip_path, 'r') as zf:
                # Find matching file in ZIP
                target_file = None
                for zip_info in zf.namelist():
                    if os.path.basename(zip_info) == file_record.original_filename:
                        target_file = zip_info
                        break
                
                if not target_file:
                    return jsonify({'error': f'File not found in ZIP: {file_record.original_filename}'}), 404
                
                # Get file info
                file_info = zf.getinfo(target_file)
                file_size = file_info.file_size
                
                # Hybrid approach based on size
                if file_size < 100 * 1024 * 1024:  # <100MB: Use memory
                    logger.info(f"Extracting virtual file to memory: {file_record.original_filename} ({file_size} bytes)")
                    
                    # Extract to memory
                    file_data = zf.read(target_file)
                    
                    # Create in-memory file object
                    file_obj = io.BytesIO(file_data)
                    file_obj.seek(0)
                    
                    return send_file(
                        file_obj,
                        as_attachment=True,
                        download_name=file_record.original_filename,
                        mimetype='application/octet-stream'
                    )
                
                else:  # >100MB: Use temp file
                    logger.info(f"Extracting virtual file to temp: {file_record.original_filename} ({file_size} bytes)")
                    
                    # Extract to temporary file
                    with tempfile.NamedTemporaryFile(delete=False, suffix=f'_{file_record.original_filename}') as tmp_file:
                        tmp_path = tmp_file.name
                        with zf.open(target_file) as source:
                            import shutil
                            shutil.copyfileobj(source, tmp_file)
                    
                    # Send file and schedule cleanup
                    def cleanup_temp_file(response):
                        try:
                            os.unlink(tmp_path)
                            logger.info(f"Cleaned up temp file: {tmp_path}")
                        except Exception as e:
                            logger.error(f"Failed to cleanup temp file {tmp_path}: {e}")
                        return response
                    
                    response = send_file(
                        tmp_path,
                        as_attachment=True,
                        download_name=file_record.original_filename,
                        mimetype='application/octet-stream'
                    )
                    response.call_on_close(lambda: cleanup_temp_file(response))
                    return response
        
        except Exception as e:
            logger.error(f"Error extracting virtual file {file_id}: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'error': f'Failed to extract file: {str(e)}'}), 500
    
    # PHYSICAL FILE: Serve from storage
    else:
        file_path = file_record.file_path
        
        if not file_path or not os.path.exists(file_path):
            return jsonify({'error': 'File not found on disk'}), 404
        
        # Check if it's compressed (.gz)
        if file_path.endswith('.gz'):
            # For compressed files, decompress on the fly
            import gzip
            file_size = os.path.getsize(file_path)
            
            if file_size < 100 * 1024 * 1024:  # <100MB compressed: Decompress to memory
                logger.info(f"Decompressing to memory: {file_record.original_filename}")
                
                with gzip.open(file_path, 'rb') as gz_file:
                    file_data = gz_file.read()
                
                file_obj = io.BytesIO(file_data)
                file_obj.seek(0)
                
                return send_file(
                    file_obj,
                    as_attachment=True,
                    download_name=file_record.original_filename,
                    mimetype='application/octet-stream'
                )
            else:  # >100MB compressed: Decompress to temp
                logger.info(f"Decompressing to temp: {file_record.original_filename}")
                
                with tempfile.NamedTemporaryFile(delete=False, suffix=f'_{file_record.original_filename}') as tmp_file:
                    tmp_path = tmp_file.name
                    with gzip.open(file_path, 'rb') as gz_file:
                        import shutil
                        shutil.copyfileobj(gz_file, tmp_file)
                
                def cleanup_temp_file(response):
                    try:
                        os.unlink(tmp_path)
                    except Exception as e:
                        logger.error(f"Failed to cleanup temp file: {e}")
                    return response
                
                response = send_file(
                    tmp_path,
                    as_attachment=True,
                    download_name=file_record.original_filename,
                    mimetype='application/octet-stream'
                )
                response.call_on_close(lambda: cleanup_temp_file(response))
                return response
        
        else:
            # Uncompressed file: Serve directly
            return send_file(
                file_path,
                as_attachment=True,
                download_name=file_record.original_filename,
                mimetype='application/octet-stream'
            )


@case_bp.route('/<int:case_id>/files/<int:file_id>/retry', methods=['POST'])
@login_required
def retry_file_processing(case_id, file_id):
    """
    Retry processing of a failed file
    Resets status and re-queues for parsing
    """
    from models import Case, CaseFile
    from main import db
    from tasks.task_file_upload import parse_and_index_file
    
    case = Case.query.get_or_404(case_id)
    
    # Access control
    if current_user.role == 'read-only':
        return jsonify({'error': 'Permission denied'}), 403
    
    file_record = CaseFile.query.filter_by(id=file_id, case_id=case_id).first_or_404()
    
    # Only retry failed files
    if file_record.status not in ['failed', 'error']:
        return jsonify({'error': 'File is not in failed state'}), 400
    
    # Increment retry count
    file_record.retry_count = (file_record.retry_count or 0) + 1
    
    # Reset statuses
    file_record.status = 'parsing'
    file_record.parsing_status = 'pending'
    file_record.indexing_status = None
    file_record.error_message = None
    
    db.session.commit()
    
    logger.info(f"Retrying file {file_id}: {file_record.original_filename} (attempt #{file_record.retry_count})")
    
    # Re-queue for processing
    # For virtual files, use staging path; for physical, check file_path
    file_path = file_record.file_path
    target_index = file_record.target_index or f"case_{case_id}"
    
    if file_path and os.path.exists(file_path):
        parse_and_index_file.delay(case_id, file_id, file_path, target_index)
        return jsonify({
            'success': True,
            'message': f'File re-queued for processing (attempt #{file_record.retry_count})'
        })
    else:
        file_record.status = 'failed'
        file_record.error_message = 'File not found on disk for retry'
        db.session.commit()
        return jsonify({'error': 'File not found on disk'}), 404


@case_bp.route('/<int:case_id>/files/<int:container_id>/retry-failed', methods=['POST'])
@login_required
def retry_failed_in_container(case_id, container_id):
    """
    Retry all failed files in a ZIP container
    Batch retry for convenience
    """
    from models import Case, CaseFile
    from main import db
    from tasks.task_file_upload import parse_and_index_file
    
    case = Case.query.get_or_404(case_id)
    
    # Access control
    if current_user.role == 'read-only':
        return jsonify({'error': 'Permission denied'}), 403
    
    # Get container
    container = CaseFile.query.filter_by(id=container_id, case_id=case_id, is_container=True).first_or_404()
    
    # Get failed files in this container
    failed_files = CaseFile.query.filter_by(
        parent_file_id=container_id,
        is_virtual=True
    ).filter(CaseFile.status.in_(['failed', 'error'])).all()
    
    if not failed_files:
        return jsonify({'error': 'No failed files to retry'}), 400
    
    retried = 0
    errors = []
    
    for file_record in failed_files:
        try:
            # Increment retry count
            file_record.retry_count = (file_record.retry_count or 0) + 1
            
            # Reset statuses
            file_record.status = 'parsing'
            file_record.parsing_status = 'pending'
            file_record.indexing_status = None
            file_record.error_message = None
            
            db.session.commit()
            
            # Re-queue
            file_path = file_record.file_path
            target_index = file_record.target_index or f"case_{case_id}"
            
            if file_path and os.path.exists(file_path):
                parse_and_index_file.delay(case_id, file_record.id, file_path, target_index)
                retried += 1
            else:
                errors.append(f"{file_record.original_filename}: File not found")
        
        except Exception as e:
            errors.append(f"{file_record.original_filename}: {str(e)}")
    
    return jsonify({
        'success': True,
        'retried': retried,
        'errors': errors,
        'message': f'Retried {retried} failed files from {container.original_filename}'
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
