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
    
    # Calculate statistics
    # Total files - all files in database regardless of status
    total_files = CaseFile.query.filter_by(case_id=case_id).count()
    
    # Total size - sum from database file_size field (more accurate than filesystem)
    total_size = db.session.query(db.func.sum(CaseFile.file_size)).filter_by(case_id=case_id).scalar() or 0
    
    # Pending files - files waiting to be ingested
    # Includes: New (not started), pending, processing, parsing, extracting
    pending_files = CaseFile.query.filter_by(case_id=case_id).filter(
        CaseFile.status.in_(['New', 'pending', 'processing', 'parsing', 'extracting'])
    ).count()
    
    # Indexed files - files fully indexed (including files with 0 events)
    indexed_files = CaseFile.query.filter_by(case_id=case_id).filter(
        CaseFile.status.in_(['Indexed', 'ZeroEvents'])
    ).count()
    
    # Partial indexed files - files partially indexed but not fully
    partial_indexed_files = CaseFile.query.filter_by(case_id=case_id, status='Partial').count()
    
    # Failed parsing - files where parser exists but failed to parse
    failed_parsing = CaseFile.query.filter_by(case_id=case_id, status='ParseFail').count()
    
    # No parser - files where no parser is available
    no_parser = CaseFile.query.filter_by(case_id=case_id, status='UnableToParse').count()
    
    # Failed files - files which failed for some other reason
    failed_files = CaseFile.query.filter_by(case_id=case_id, status='Error').count()
    
    stats = {
        'total_files': total_files,
        'total_space_gb': total_size / (1024**3) if total_size > 0 else 0,
        'total_artifacts': 0,  # Will be loaded via AJAX
        'indexed_files': indexed_files,
        'partial_indexed_files': partial_indexed_files,
        'failed_parsing': failed_parsing,
        'no_parser': no_parser,
        'failed_files': failed_files,
        'pending_files': pending_files
    }
    
    # Pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    per_page = min(per_page, 100)  # Max 100 items per page
    
    # Status filter parameters (comma-separated list of statuses to show)
    # Default: Show New, Indexed, and Partial files (hide failures and zero-events by default)
    status_filter = request.args.get('statuses', 'New,Indexed,Partial')
    enabled_statuses = [s.strip() for s in status_filter.split(',') if s.strip()]
    
    # Search parameter
    search_term = request.args.get('search', '').strip()
    
    # Sorting parameters
    sort_by = request.args.get('sort_by', 'uploaded_at')
    sort_order = request.args.get('sort_order', 'desc')
    
    # Valid sortable columns
    sortable_columns = {
        'original_filename': CaseFile.original_filename,
        'filename': CaseFile.filename,
        'source_system': CaseFile.source_system,
        'uploaded_at': CaseFile.uploaded_at,
        'uploaded_by': CaseFile.uploaded_by,
        'event_count': CaseFile.event_count,
        'parser_type': CaseFile.parser_type,
        'sigma_violations': CaseFile.sigma_violations,
        'ioc_count': CaseFile.ioc_count,
        'status': CaseFile.status,
        'file_size': CaseFile.file_size
    }
    
    # Validate sort column
    if sort_by not in sortable_columns:
        sort_by = 'uploaded_at'
    
    # Validate sort order
    if sort_order not in ['asc', 'desc']:
        sort_order = 'desc'
    
    # Build query with filters
    query = CaseFile.query.filter_by(case_id=case_id)
    
    # Apply status filter
    if enabled_statuses:
        query = query.filter(CaseFile.status.in_(enabled_statuses))
    
    # Apply search filter (searches filename and file_type)
    if search_term:
        search_pattern = f'%{search_term}%'
        query = query.filter(
            db.or_(
                CaseFile.filename.ilike(search_pattern),
                CaseFile.file_type.ilike(search_pattern)
            )
        )
    
    # Apply sorting
    sort_column = sortable_columns[sort_by]
    if sort_order == 'desc':
        query = query.order_by(sort_column.desc())
    else:
        query = query.order_by(sort_column.asc())
    
    # Apply pagination to filtered and sorted query
    pagination = query.paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    files = pagination.items
    
    # NOTE: parent_file_id was removed in phase1 migration
    # Child count tracking is no longer available via database relationship
    for file in files:
        file.child_count = 0
    
    return render_template('case/files.html', case=case, stats=stats, files=files, 
                         pagination=pagination, page=page, per_page=per_page,
                         enabled_statuses=enabled_statuses, search_term=search_term,
                         sort_by=sort_by, sort_order=sort_order)


@case_bp.route('/<int:case_id>/files/stats', methods=['GET'])
@login_required
def case_files_stats(case_id):
    """
    API endpoint for real-time stats updates
    Returns JSON with current file statistics
    """
    from main import db
    from models import Case, CaseFile
    from opensearch_indexer import OpenSearchIndexer
    from opensearchpy.exceptions import NotFoundError
    import os
    
    case = Case.query.get_or_404(case_id)
    
    # Access control
    if current_user.role == 'read-only':
        if case.id != current_user.case_assigned:
            return jsonify({'error': 'Access denied'}), 403
    
    # Calculate statistics
    # Total files - all files in database regardless of status
    total_files = CaseFile.query.filter_by(case_id=case_id).count()
    
    # Total size - sum from database file_size field
    total_size = db.session.query(db.func.sum(CaseFile.file_size)).filter_by(case_id=case_id).scalar() or 0
    
    # Pending files - files waiting to be ingested
    # Includes: New (not started), pending, processing, parsing, extracting
    pending_files = CaseFile.query.filter_by(case_id=case_id).filter(
        CaseFile.status.in_(['New', 'pending', 'processing', 'parsing', 'extracting'])
    ).count()
    
    # Indexed files - files fully indexed (including files with 0 events)
    indexed_files = CaseFile.query.filter_by(case_id=case_id).filter(
        CaseFile.status.in_(['Indexed', 'ZeroEvents'])
    ).count()
    
    # Partial indexed files - files partially indexed but not fully
    partial_indexed_files = CaseFile.query.filter_by(case_id=case_id, status='Partial').count()
    
    # Failed parsing - files where parser exists but failed to parse
    failed_parsing = CaseFile.query.filter_by(case_id=case_id, status='ParseFail').count()
    
    # No parser - files where no parser is available
    no_parser = CaseFile.query.filter_by(case_id=case_id, status='UnableToParse').count()
    
    # Failed files - files which failed for some other reason
    failed_files = CaseFile.query.filter_by(case_id=case_id, status='Error').count()
    
    # Get total artifacts count from all OpenSearch indices
    total_artifacts = 0
    try:
        indexer = OpenSearchIndexer()
        client = indexer.client
        
        # Define all indices to query
        indices_to_query = [
            f'case_{case_id}',  # events
            f'case_{case_id}_browser',
            f'case_{case_id}_execution',
            f'case_{case_id}_filesystem',
            f'case_{case_id}_useractivity',
            f'case_{case_id}_comms',
            f'case_{case_id}_network',
            f'case_{case_id}_persistence',
            f'case_{case_id}_devices',
            f'case_{case_id}_cloud',
            f'case_{case_id}_remote'
        ]
        
        for index_name in indices_to_query:
            try:
                result = client.count(index=index_name, body={"query": {"match_all": {}}})
                total_artifacts += result['count']
            except NotFoundError:
                # Index doesn't exist yet, skip
                pass
            except Exception as e:
                logger.error(f"Error counting artifacts in {index_name}: {e}")
                
    except Exception as e:
        logger.error(f"Error getting total artifacts: {e}")
    
    # Get processing count for backwards compatibility
    processing_count = pending_files
    
    # ZIP containers - count of tracked ZIP files (for duplicate prevention)
    zip_containers = CaseFile.query.filter_by(case_id=case_id, parser_type='zipcontainer').count()
    
    stats = {
        'total_files': total_files,
        'total_space_gb': total_size / (1024**3) if total_size > 0 else 0,
        'total_artifacts': total_artifacts,
        'indexed_files': indexed_files,
        'partial_indexed_files': partial_indexed_files,
        'failed_parsing': failed_parsing,
        'no_parser': no_parser,
        'failed_files': failed_files,
        'pending_files': pending_files,
        'processing_files': processing_count,
        'zip_containers': zip_containers,
    }
    
    return jsonify({'stats': stats})


@case_bp.route('/<int:case_id>/files/api/list', methods=['GET'])
@login_required
def case_files_list_api(case_id):
    """API endpoint for file list (AJAX refresh without full page reload)"""
    from models import Case, CaseFile, User
    from main import db
    
    # Expire session to force fresh queries (no caching)
    db.session.expire_all()
    
    case = Case.query.get_or_404(case_id)
    
    # Access control
    if current_user.role == 'read-only' and current_user.case_assigned != case_id:
        return jsonify({'error': 'Access denied'}), 403
    
    # Get all files (filtering done client-side)
    files = CaseFile.query.filter_by(case_id=case_id).order_by(CaseFile.uploaded_at.desc()).all()
    
    # Format for JSON
    files_data = []
    for file in files:
        # Normalize status to match filter values
        status = file.status or 'New'
        
        files_data.append({
            'id': file.id,
            'filename': file.filename,
            'original_filename': file.original_filename,
            'file_size': file.file_size,
            'source_system': file.source_system or '-',
            'parser_type': file.parser_type or '-',
            'uploaded_at': file.uploaded_at.strftime('%Y-%m-%d %H:%M:%S') if file.uploaded_at else '-',
            'uploaded_by': file.uploader.username if file.uploader else 'Unknown',
            'event_count': file.event_count or 0,
            'sigma_violations': file.sigma_violations or 0,
            'ioc_count': file.ioc_count or 0,
            'status': status
        })
    
    return jsonify({'files': files_data})


@case_bp.route('/<int:case_id>/files/<int:container_id>/contents', methods=['GET'])
@login_required
def get_zip_contents(case_id, container_id):
    """
    API endpoint to fetch contents of a ZIP container
    
    NOTE: Parent-child file relationships (parent_file_id) were removed in phase1 migration.
    This endpoint now returns an empty result as ZIP content tracking is no longer available.
    """
    from models import Case, CaseFile
    
    case = Case.query.get_or_404(case_id)
    
    # Access control
    if current_user.role == 'read-only':
        if case.id != current_user.case_assigned:
            return jsonify({'error': 'Access denied'}), 403
    
    # Get container
    container = CaseFile.query.filter_by(id=container_id, case_id=case_id, is_container=True).first_or_404()
    
    # NOTE: parent_file_id was removed - ZIP content tracking is no longer available
    return jsonify({
        'container_id': container_id,
        'container_name': container.original_filename,
        'total_files': 0,
        'files': [],
        'message': 'ZIP content tracking not available in current version'
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
                # Check for NEW parallel processing: process_individual_file (V1 or V2)
                if task.get('name') in ['tasks.process_individual_file', 'tasks.process_individual_file_v2']:
                    try:
                        # Args are: [case_id, file_id, file_path]
                        task_args = task.get('args', [])
                        if len(task_args) >= 2:
                            task_case_id = task_args[0]
                            file_id = task_args[1]
                            
                            # Only include tasks for this case
                            if task_case_id != case_id:
                                continue
                            
                            file = CaseFile.query.get(file_id)
                            if file:
                                active_files.append({
                                    'filename': file.filename,
                                    'original_filename': file.original_filename or file.filename,
                                    'parent_zip': None,
                                    'is_virtual': False,
                                    'worker': worker_name.split('@')[0] if '@' in worker_name else worker_name
                                })
                    except Exception as e:
                        logger.error(f"Error parsing parallel task: {e}")
                        continue
                
                # Check for old system: parse_and_index_file tasks
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
                                active_files.append({
                                    'filename': file.filename,
                                    'original_filename': file.original_filename or file.filename,
                                    'parent_zip': None,  # parent_file_id removed in phase1
                                    'is_virtual': file.is_virtual,
                                    'worker': worker_name.split('@')[0] if '@' in worker_name else worker_name
                                })
                    except Exception as e:
                        logger.error(f"Error parsing active task: {e}")
                        continue
                
                # Check for new system: ingest_files task  
                elif task.get('name') == 'tasks.ingest_files':
                    try:
                        task_id = task.get('id')
                        if task_id:
                            from tasks.task_ingest_files import ingest_files
                            result = ingest_files.AsyncResult(task_id)
                            
                            if result.state == 'PROGRESS' and result.info:
                                current_status = result.info.get('status', '')
                                if 'Parsing' in current_status or 'Indexing' in current_status:
                                    import re
                                    match = re.search(r'(?:Parsing|Indexing)\s+(.+?)\.\.\.$', current_status)
                                    if match:
                                        filename = match.group(1)
                                        active_files.append({
                                            'filename': filename,
                                            'original_filename': filename,
                                            'parent_zip': None,
                                            'is_virtual': False,
                                            'worker': worker_name.split('@')[0] if '@' in worker_name else worker_name
                                        })
                    except Exception as e:
                        logger.error(f"Error parsing ingest task: {e}")
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
    
    NOTE: Parent-child file relationships (parent_file_id) were removed in phase1 migration.
    This endpoint returns empty results as ZIP content tracking is no longer available.
    """
    from models import Case, CaseFile
    
    case = Case.query.get_or_404(case_id)
    
    # Access control
    if current_user.role == 'read-only':
        if case.id != current_user.case_assigned:
            return jsonify({'error': 'Access denied'}), 403
    
    # Get container
    container = CaseFile.query.filter_by(id=container_id, case_id=case_id, is_container=True).first_or_404()
    
    # NOTE: parent_file_id was removed - ZIP content tracking is no longer available
    return jsonify({
        'container_id': container_id,
        'container_name': container.original_filename,
        'container_status': container.status,
        'total_files': 0,
        'indexed_files': 0,
        'failed_files': 0,
        'total_events': 0,
        'indexed_by_type': {},
        'failed_by_type': {},
        'message': 'ZIP content tracking not available in current version'
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
    # NOTE: parent_file_id was removed in phase1 migration
    # Virtual file downloads from ZIP are no longer supported
    if file_record.is_virtual:
        return jsonify({
            'error': 'Virtual file download not available',
            'message': 'Parent-child file relationships were removed. Download the original ZIP file instead.'
        }), 501
    
    # The following code is now unreachable for virtual files but kept for reference
    if False:  # Dead code - virtual file ZIP extraction
        try:
            # Find the file in ZIP (match by original filename)
            with zipfile.ZipFile('', 'r') as zf:
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
    
    NOTE: Parent-child file relationships (parent_file_id) were removed in phase1 migration.
    This endpoint is no longer functional.
    """
    from models import Case, CaseFile
    
    case = Case.query.get_or_404(case_id)
    
    # Access control
    if current_user.role == 'read-only':
        return jsonify({'error': 'Permission denied'}), 403
    
    # NOTE: parent_file_id was removed - cannot find child files in container
    return jsonify({
        'error': 'Feature not available',
        'message': 'Parent-child file relationships were removed. Use individual file retry instead.'
    }), 501
    
    # Dead code below - kept for reference
    if False:
        failed_files = []
    
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
    Scan the SFTP upload folder for new files and queue them for processing
    Uses the same modern processing pipeline as web uploads
    """
    import os
    from audit_logger import log_action
    from tasks.task_ingest_files import ingest_files
    from utils.file_ingestion import scan_upload_folder
    from datetime import datetime, timedelta
    
    # Only admins and analysts can scan
    if current_user.role == 'read-only':
        return jsonify({'error': 'You do not have permission to scan for files'}), 403
    
    # Get case
    from models import Case, IngestionProgress
    case = Case.query.get_or_404(case_id)
    
    # Use new standardized SFTP upload path
    upload_path = f'/opt/casescope/uploads/sftp/{case_id}/'
    
    try:
        # Check if upload folder exists
        if not os.path.exists(upload_path):
            return jsonify({
                'success': True,
                'files_found': 0,
                'message': f'Folder not found. Please create: {upload_path}'
            })
        
        # Use standardized scan function
        files_found = scan_upload_folder(case_id, 'sftp')
        
        if len(files_found) == 0:
            return jsonify({
                'success': True,
                'files_found': 0,
                'message': f'No files found in {upload_path}'
            })
        
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
        
        # Queue task using modern ingestion pipeline
        task = ingest_files.delay(
            case_id=case_id,
            user_id=current_user.id,
            upload_type='sftp',
            resume=False
        )
        
        # Audit log
        log_action('scan_bulk_upload',
                   resource_type='case',
                   resource_id=case_id,
                   resource_name=case.name,
                   details={
                       'scanned_by': current_user.username,
                       'folder': upload_path,
                       'files_found': len(files_found),
                       'upload_type': 'sftp',
                       'task_id': task.id
                   })
        
        return jsonify({
            'success': True,
            'files_found': len(files_found),
            'task_id': task.id,
            'message': f'Found {len(files_found)} file(s). Processing started in background.'
        })
        
    except Exception as e:
        logger.error(f"Error scanning SFTP upload folder for case {case_id}: {e}")
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


@case_bp.route('/api/artifact-stats/<int:case_id>')
@login_required
def api_artifact_stats(case_id):
    """
    Get comprehensive artifact statistics across all indices
    Returns counts for all 11 OpenSearch indices with type breakdowns
    """
    from opensearch_indexer import OpenSearchIndexer
    from opensearchpy.exceptions import NotFoundError
    from models import Case, CaseFile
    from main import db
    
    # Verify case access
    case = Case.query.get_or_404(case_id)
    if current_user.role == 'read-only' and case.id != current_user.case_assigned:
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        indexer = OpenSearchIndexer()
        client = indexer.client
        
        stats = {
            'total_artifacts': 0,
            'indices': {}
        }
        
        # Define all indices with metadata
        indices_config = {
            'events': {
                'name': f'case_{case_id}',
                'label': 'Events & Logs',
                'icon': '🔍',
                'description': 'EVTX, EDR, Firewall, Sysmon'
            },
            'browser': {
                'name': f'case_{case_id}_browser',
                'label': 'Browser Activity',
                'icon': '🌐',
                'description': 'Chrome, Edge, Firefox history'
            },
            'execution': {
                'name': f'case_{case_id}_execution',
                'label': 'Execution Artifacts',
                'icon': '⚡',
                'description': 'Prefetch, Activities, SRUM'
            },
            'filesystem': {
                'name': f'case_{case_id}_filesystem',
                'label': 'Filesystem Timeline',
                'icon': '📁',
                'description': 'MFT, Thumbcache, WinSearch'
            },
            'useractivity': {
                'name': f'case_{case_id}_useractivity',
                'label': 'User Activity',
                'icon': '👤',
                'description': 'Jump Lists, LNK shortcuts'
            },
            'comms': {
                'name': f'case_{case_id}_comms',
                'label': 'Communications',
                'icon': '💬',
                'description': 'Email, Teams/Skype, Notifications'
            },
            'network': {
                'name': f'case_{case_id}_network',
                'label': 'Network Activity',
                'icon': '🌐',
                'description': 'BITS transfers, SRUM network'
            },
            'persistence': {
                'name': f'case_{case_id}_persistence',
                'label': 'Persistence Mechanisms',
                'icon': '🔒',
                'description': 'Scheduled Tasks, WMI'
            },
            'devices': {
                'name': f'case_{case_id}_devices',
                'label': 'Device History',
                'icon': '💾',
                'description': 'USB connections, SetupAPI'
            },
            'cloud': {
                'name': f'case_{case_id}_cloud',
                'label': 'Cloud Storage',
                'icon': '☁️',
                'description': 'OneDrive operations'
            },
            'remote': {
                'name': f'case_{case_id}_remote',
                'label': 'Remote Sessions',
                'icon': '🖥️',
                'description': 'RDP bitmap cache'
            }
        }
        
        # Query each index
        for key, config in indices_config.items():
            index_name = config['name']
            
            try:
                # Get total count
                count_result = client.count(index=index_name, body={"query": {"match_all": {}}})
                total = count_result.get('count', 0)
                
                # Get breakdown by event_type
                breakdown = []
                if total > 0:
                    agg_query = {
                        "size": 0,
                        "aggs": {
                            "by_type": {
                                "terms": {
                                    "field": "event_type.keyword",
                                    "size": 20
                                }
                            }
                        }
                    }
                    
                    try:
                        agg_result = client.search(index=index_name, body=agg_query)
                        buckets = agg_result.get('aggregations', {}).get('by_type', {}).get('buckets', [])
                        
                        breakdown = [
                            {
                                'type': b['key'],
                                'count': b['doc_count']
                            }
                            for b in buckets
                        ]
                    except Exception as e:
                        logger.warning(f"Could not get breakdown for {index_name}: {e}")
                
                stats['indices'][key] = {
                    'label': config['label'],
                    'icon': config['icon'],
                    'description': config['description'],
                    'total': total,
                    'breakdown': breakdown
                }
                
                stats['total_artifacts'] += total
                
            except NotFoundError:
                stats['indices'][key] = {
                    'label': config['label'],
                    'icon': config['icon'],
                    'description': config['description'],
                    'total': 0,
                    'breakdown': []
                }
            except Exception as e:
                logger.error(f"Error querying {index_name}: {e}")
                stats['indices'][key] = {
                    'label': config['label'],
                    'icon': config['icon'],
                    'description': config['description'],
                    'total': 0,
                    'breakdown': [],
                    'error': str(e)
                }
        
        # Get file stats from database
        file_stats = db.session.query(
            db.func.count(CaseFile.id).label('total_files'),
            db.func.count(db.case((CaseFile.status == 'Indexed', CaseFile.id))).label('indexed_files'),
            db.func.count(db.case((CaseFile.status == 'New', CaseFile.id))).label('pending_files'),
            db.func.count(db.case((CaseFile.status.in_(['ParseFail', 'UnableToParse']), CaseFile.id))).label('failed_files'),
            db.func.count(db.case((CaseFile.event_count == 0, CaseFile.id))).label('zero_event_files'),
            db.func.sum(CaseFile.file_size).label('total_size')
        ).filter(
            CaseFile.case_id == case_id
        ).first()
        
        stats['files'] = {
            'total': file_stats.total_files or 0,
            'indexed': file_stats.indexed_files or 0,
            'pending': file_stats.pending_files or 0,
            'failed': file_stats.failed_files or 0,
            'zero_events': file_stats.zero_event_files or 0,
            'total_size_bytes': file_stats.total_size or 0,
            'total_size_gb': round((file_stats.total_size or 0) / (1024**3), 2)
        }
        
        return jsonify(stats)
        
    except Exception as e:
        logger.error(f"Error getting artifact stats for case {case_id}: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@case_bp.route('/<int:case_id>/review_hostnames')
@login_required
def review_hostnames(case_id):
    """
    Show files that need hostname review
    """
    from main import db
    from models import Case, CaseFile
    
    case = Case.query.get_or_404(case_id)
    
    # Access control for viewers
    if current_user.role == 'read-only':
        if case.id != current_user.case_assigned:
            flash('You do not have access to this case', 'error')
            return redirect(url_for('index'))
    
    # Get files needing review
    files_needing_review = CaseFile.query.filter_by(
        case_id=case_id,
        needs_review=True
    ).order_by(CaseFile.uploaded_at.desc()).all()
    
    return render_template('case/review_hostnames.html', 
                         case=case, 
                         files_needing_review=files_needing_review)


@case_bp.route('/<int:case_id>/update_hostname/<int:file_id>', methods=['POST'])
@login_required
def update_hostname(case_id, file_id):
    """
    Update hostname for a file and re-index with new hostname
    """
    from main import db
    from models import CaseFile
    from opensearchpy import OpenSearch
    from config import Config
    
    try:
        file_record = CaseFile.query.filter_by(
            id=file_id,
            case_id=case_id
        ).first_or_404()
        
        data = request.get_json()
        new_hostname = data.get('hostname', '').strip()
        
        if not new_hostname:
            return jsonify({'success': False, 'error': 'Hostname required'}), 400
        
        old_hostname = file_record.source_system
        
        # Update database record
        file_record.source_system = new_hostname
        file_record.source_system_confidence = 'high'
        file_record.source_system_method = 'manual'
        file_record.needs_review = False
        file_record.suggested_source_system = None
        db.session.commit()
        
        # Update OpenSearch - bulk update all events from this file
        if file_record.target_index and file_record.event_count > 0:
            try:
                client = OpenSearch(
                    hosts=[{'host': Config.OPENSEARCH_HOST, 'port': Config.OPENSEARCH_PORT}],
                    use_ssl=Config.OPENSEARCH_USE_SSL,
                    verify_certs=False,
                    ssl_show_warn=False,
                    timeout=30
                )
                
                # Update by query - update all events with this source_file
                update_query = {
                    "script": {
                        "source": "ctx._source.source_system = params.new_hostname",
                        "params": {
                            "new_hostname": new_hostname
                        }
                    },
                    "query": {
                        "term": {
                            "source_file": file_record.original_filename
                        }
                    }
                }
                
                response = client.update_by_query(
                    index=file_record.target_index,
                    body=update_query,
                    conflicts='proceed'
                )
                
                logger.info(f"Updated {response.get('updated', 0)} events with new hostname: {new_hostname}")
                
            except Exception as e:
                logger.error(f"Error updating OpenSearch events: {e}")
                # Don't fail the whole operation, database is updated
        
        return jsonify({
            'success': True,
            'old_hostname': old_hostname,
            'new_hostname': new_hostname
        })
        
    except Exception as e:
        logger.error(f"Error updating hostname: {e}", exc_info=True)
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@case_bp.route('/<int:case_id>/verify_hostname/<int:file_id>', methods=['POST'])
@login_required
def verify_hostname(case_id, file_id):
    """
    Mark current hostname as verified (no changes)
    """
    from main import db
    from models import CaseFile
    
    try:
        file_record = CaseFile.query.filter_by(
            id=file_id,
            case_id=case_id
        ).first_or_404()
        
        # Mark as verified
        file_record.needs_review = False
        file_record.source_system_confidence = 'high'
        file_record.suggested_source_system = None
        db.session.commit()
        
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"Error verifying hostname: {e}", exc_info=True)
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@case_bp.route('/<int:case_id>/verify_all_hostnames', methods=['POST'])
@login_required
def verify_all_hostnames(case_id):
    """
    Mark all current hostnames as verified for this case
    """
    from main import db
    from models import CaseFile
    
    try:
        # Update all files needing review
        updated_count = CaseFile.query.filter_by(
            case_id=case_id,
            needs_review=True
        ).update({
            'needs_review': False,
            'source_system_confidence': 'high',
            'suggested_source_system': None
        })
        
        db.session.commit()
        
        return jsonify({'success': True, 'count': updated_count})
        
    except Exception as e:
        logger.error(f"Error verifying all hostnames: {e}", exc_info=True)
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500
