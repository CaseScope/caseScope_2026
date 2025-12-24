"""
Case Management Routes Blueprint
Handles case CRUD operations and administration
"""
from flask import Blueprint, render_template, request, redirect, url_for, jsonify, flash
from flask_login import login_required, current_user
from functools import wraps
import logging

cases_bp = Blueprint('cases', __name__)
logger = logging.getLogger(__name__)


def admin_required(f):
    """Decorator to require administrator role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'administrator':
            flash('Administrator access required', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


@cases_bp.route('/admin/cases')
@login_required
@admin_required
def case_management():
    """Case Management Dashboard - List all cases with admin options"""
    from main import db, Case, User, CaseFile
    
    # Get all cases with file counts
    cases = db.session.query(Case).order_by(Case.created_at.desc()).all()
    
    # Get file counts for each case
    case_data = []
    for case in cases:
        file_count = db.session.query(CaseFile).filter_by(
            case_id=case.id, is_deleted=False
        ).count()
        
        creator_name = 'Unknown'
        if case.created_by:
            creator = db.session.get(User, case.created_by)
            creator_name = creator.full_name or creator.username if creator else 'Unknown'
        
        assignee_name = 'Unassigned'
        if case.assigned_to:
            assignee = db.session.get(User, case.assigned_to)
            assignee_name = assignee.full_name or assignee.username if assignee else 'Unassigned'
        
        case_data.append({
            'case': case,
            'file_count': file_count,
            'creator_name': creator_name,
            'assignee_name': assignee_name
        })
    
    return render_template('admin_cases.html', case_data=case_data)


@cases_bp.route('/case/<int:case_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_case(case_id):
    """Edit case details (reusable page for both admin and case owner)"""
    from main import db, Case, User
    
    case = db.session.get(Case, case_id)
    if not case:
        flash('Case not found', 'error')
        return redirect(url_for('dashboard'))
    
    # Check permissions: admin or case creator
    if current_user.role != 'administrator' and case.created_by != current_user.id:
        flash('Permission denied', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        # Track changes for audit log
        changes = {}
        old_name = case.name
        old_description = case.description
        old_edr_report = case.edr_report
        old_company = case.company
        old_vpn_ip_ranges = case.vpn_ip_ranges  # v1.43.0
        old_status = case.status
        old_assigned_to = case.assigned_to
        
        case.name = request.form.get('name', case.name)
        case.description = request.form.get('description', case.description)
        case.edr_report = request.form.get('edr_report', case.edr_report)
        case.company = request.form.get('company', case.company)
        
        # v1.43.0: VPN IP ranges
        vpn_ip_ranges = request.form.get('vpn_ip_ranges', '').strip()
        case.vpn_ip_ranges = vpn_ip_ranges if vpn_ip_ranges else None
        
        # Get requested status change
        requested_status = request.form.get('status', case.status)
        
        # Handle assignment changes (admin only)
        if current_user.role == 'administrator':
            assigned_to = request.form.get('assigned_to')
            new_assigned_to = int(assigned_to) if assigned_to and assigned_to != '' else None
            
            # Auto-status logic: When assignment changes, auto-transition to "Assigned"
            if old_assigned_to != new_assigned_to and new_assigned_to is not None:
                # User was assigned - automatically set status to "Assigned" if currently "New"
                if case.status == 'New':
                    requested_status = 'Assigned'
                    changes['status_auto'] = {'reason': 'user_assigned', 'from': 'New', 'to': 'Assigned'}
            
            case.assigned_to = new_assigned_to
            if old_assigned_to != case.assigned_to:
                changes['assigned_to'] = {'from': old_assigned_to, 'to': case.assigned_to}
        
        # Apply status change
        case.status = requested_status
        
        # Track what changed
        if old_name != case.name:
            changes['name'] = {'from': old_name, 'to': case.name}
        if old_description != case.description:
            changes['description'] = 'updated'
        if old_edr_report != case.edr_report:
            changes['edr_report'] = 'updated'
        if old_company != case.company:
            changes['company'] = {'from': old_company, 'to': case.company}
        if old_vpn_ip_ranges != case.vpn_ip_ranges:
            changes['vpn_ip_ranges'] = 'updated'  # v1.43.0
        if old_status != case.status:
            changes['status'] = {'from': old_status, 'to': case.status}
        
        db.session.commit()
        
        # Audit log
        from audit_logger import log_action
        log_action('edit_case', resource_type='case', resource_id=case_id,
                  resource_name=case.name, details=changes)
        
        flash('Case updated successfully', 'success')
        
        # Redirect back to referring page or case dashboard
        return_to = request.form.get('return_to', 'case')
        if return_to == 'admin':
            return redirect(url_for('cases.case_management'))
        else:
            return redirect(url_for('view_case', case_id=case_id))
    
    # GET: Show edit form
    users = db.session.query(User).filter_by(is_active=True).order_by(User.full_name).all()
    return render_template('case_edit.html', case=case, users=users)


@cases_bp.route('/case/<int:case_id>/toggle_status', methods=['POST'])
@login_required
@admin_required
def toggle_case_status(case_id):
    """Toggle case status between active and closed"""
    from main import db, Case
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    # Toggle status
    # v1.16.0+: Toggle between Completed and In Progress
    old_status = case.status
    if case.status == 'Completed':
        case.status = 'In Progress'
    else:
        # Any active state (New, Assigned, In Progress) -> Completed
        case.status = 'Completed'
    db.session.commit()
    
    # Audit log
    from audit_logger import log_case_action
    log_case_action('toggle_case_status', case_id, case.name, details={
        'old_status': old_status,
        'new_status': case.status
    })
    
    return jsonify({'success': True, 'status': case.status})


@cases_bp.route('/case/<int:case_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_case(case_id):
    """Delete a case and all associated data asynchronously (admin only)"""
    from main import db, Case
    from tasks import delete_case_async
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    try:
        # Audit log
        from audit_logger import log_case_action
        log_case_action('delete_case', case_id, case.name, details={
            'task_id': None,  # Will be updated after task creation
            'async': True
        })
        
        # Start async deletion task
        task = delete_case_async.delay(case_id)
        
        logger.info(f"[ADMIN] Case {case_id} deletion started by user {current_user.id}, task_id={task.id}")
        
        return jsonify({
            'success': True,
            'task_id': task.id,
            'case_id': case_id,
            'case_name': case.name,
            'message': 'Deletion started'
        })
    
    except Exception as e:
        logger.error(f"[ADMIN] Error starting case deletion {case_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@cases_bp.route('/case/<int:case_id>/delete/status/<task_id>', methods=['GET'])
@login_required
@admin_required
def delete_case_status(case_id, task_id):
    """Poll deletion progress status"""
    from celery.result import AsyncResult
    from celery_app import celery_app
    
    try:
        task = AsyncResult(task_id, app=celery_app)
        
        if task.state == 'PENDING':
            response = {
                'state': 'PENDING',
                'progress': 0,
                'message': 'Waiting to start...'
            }
        elif task.state == 'PROGRESS':
            response = {
                'state': 'PROGRESS',
                'progress': task.info.get('progress', 0),
                'step': task.info.get('step', ''),
                'message': task.info.get('message', ''),
                **{k: v for k, v in task.info.items() if k not in ['progress', 'step', 'message']}
            }
        elif task.state == 'SUCCESS':
            result = task.result
            response = {
                'state': 'SUCCESS',
                'progress': 100,
                'message': 'Deletion complete',
                'result': result
            }
        elif task.state == 'FAILURE':
            response = {
                'state': 'FAILURE',
                'progress': 0,
                'message': str(task.info)
            }
        else:
            response = {
                'state': task.state,
                'progress': 0,
                'message': 'Unknown state'
            }
        
        return jsonify(response)
    
    except Exception as e:
        logger.error(f"[ADMIN] Error checking deletion status {task_id}: {e}", exc_info=True)
        return jsonify({'state': 'ERROR', 'message': str(e)}), 500

