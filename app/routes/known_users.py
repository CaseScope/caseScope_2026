"""
Known Users Management Routes
Track user accounts involved in investigations
"""

from flask import Blueprint, render_template, jsonify, request, session, Response
from flask_login import login_required, current_user
from main import db
from models import KnownUser, Case
from audit_logger import log_action
from utils.merge_helpers import (
    is_blank, normalize_username, extract_domain_from_username,
    check_in_analyst_notes, update_analyst_notes_with_merge,
    append_original_notes, should_warn_before_combine, find_or_merge_user
)
import logging
import csv
from io import StringIO
from datetime import datetime

logger = logging.getLogger(__name__)

known_users_bp = Blueprint('known_users', __name__, url_prefix='/users')


# ============================================================================
# HELPER FUNCTIONS - Auto-Merge Logic
# ============================================================================

def _find_or_merge_user(case_id, username, domain_name=None, sid=None, user_type=None,
                        compromised=None, source='manual', description=None, analyst_notes=None,
                        created_by=None, updated_by=None):
    """
    Wrapper for centralized find_or_merge_user function
    """
    return find_or_merge_user(
        db=db, case_id=case_id, username=username, domain_name=domain_name,
        sid=sid, user_type=user_type, compromised=compromised,
        source=source, description=description, analyst_notes=analyst_notes,
        created_by=created_by, updated_by=updated_by, logger=logger
    )


@known_users_bp.route('/')
@known_users_bp.route('/manage')
@login_required
def manage():
    """
    Known Users management page
    """
    # Get selected case from session
    case_id = session.get('selected_case_id')
    case = None
    
    if case_id:
        case = Case.query.get(case_id)
        
        # Check permissions for read-only users
        if current_user.role == 'read-only':
            if not case or case.id != current_user.case_assigned:
                case = None
    
    return render_template('users/manage.html', case=case)


@known_users_bp.route('/api/list')
@login_required
def api_list():
    """
    API endpoint to list known users with pagination, search, and filtering
    
    Query Parameters:
    - page: Page number (default: 1)
    - per_page: Results per page (default: 50, max: 100)
    - search: Search query (searches username, domain_name, sid)
    - user_type: Filter by user type (domain, local, unknown)
    - compromised: Filter by compromised status
    - source: Filter by source
    - case_id: Filter by case (optional, defaults to session case)
    """
    try:
        # Get query parameters
        page = max(1, int(request.args.get('page', 1)))
        per_page = min(100, max(1, int(request.args.get('per_page', 50))))
        search_query = request.args.get('search', '').strip()
        user_type = request.args.get('user_type', '')
        compromised = request.args.get('compromised', '')
        source = request.args.get('source', '')
        
        # Get case ID from query or session
        case_id = request.args.get('case_id')
        if not case_id:
            case_id = session.get('selected_case_id')
        
        # Build query
        query = KnownUser.query
        
        # Filter by case if specified
        if case_id:
            query = query.filter(KnownUser.case_id == case_id)
        
        # Apply search filter
        if search_query:
            search_filter = db.or_(
                KnownUser.username.ilike(f'%{search_query}%'),
                KnownUser.domain_name.ilike(f'%{search_query}%'),
                KnownUser.sid.ilike(f'%{search_query}%'),
                KnownUser.description.ilike(f'%{search_query}%'),
                KnownUser.analyst_notes.ilike(f'%{search_query}%')
            )
            query = query.filter(search_filter)
        
        # Apply user type filter
        if user_type:
            query = query.filter(KnownUser.user_type == user_type)
        
        # Apply compromised filter
        if compromised:
            query = query.filter(KnownUser.compromised == compromised)
        
        # Apply source filter
        if source:
            query = query.filter(KnownUser.source == source)
        
        # Order alphabetically by username
        query = query.order_by(KnownUser.username)
        
        # Get total count
        total = query.count()
        
        # Paginate
        offset = (page - 1) * per_page
        users = query.offset(offset).limit(per_page).all()
        
        # Format results
        results = []
        for user in users:
            results.append({
                'id': user.id,
                'username': user.username,
                'domain_name': user.domain_name,
                'sid': user.sid,
                'compromised': user.compromised,
                'user_type': user.user_type,
                'source': user.source,
                'description': user.description,
                'analyst_notes': user.analyst_notes,
                'case_id': user.case_id,
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'updated_at': user.updated_at.isoformat() if user.updated_at else None
            })
        
        return jsonify({
            'success': True,
            'users': results,
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': (total + per_page - 1) // per_page
        })
        
    except Exception as e:
        logger.error(f"Error listing known users: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@known_users_bp.route('/api/get/<int:user_id>')
@login_required
def api_get(user_id):
    """
    Get details for a specific user
    """
    try:
        user = KnownUser.query.get(user_id)
        
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        # Check permissions for read-only users
        if current_user.role == 'read-only':
            if user.case_id != current_user.case_assigned:
                return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        return jsonify({
            'success': True,
            'user': {
                'id': user.id,
                'username': user.username,
                'domain_name': user.domain_name,
                'sid': user.sid,
                'compromised': user.compromised,
                'user_type': user.user_type,
                'source': user.source,
                'description': user.description,
                'analyst_notes': user.analyst_notes,
                'case_id': user.case_id,
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'updated_at': user.updated_at.isoformat() if user.updated_at else None
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting user {user_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@known_users_bp.route('/api/stats')
@login_required
def api_stats():
    """
    Get statistics for known users in the current case
    """
    try:
        case_id = session.get('selected_case_id')
        
        if not case_id:
            return jsonify({
                'success': True,
                'stats': {
                    'total': 0,
                    'domain_users': 0,
                    'local_users': 0,
                    'compromised': 0
                }
            })
        
        # Build base query
        query = KnownUser.query.filter(KnownUser.case_id == case_id)
        
        # Total count
        total = query.count()
        
        # Domain users
        domain_users = query.filter(KnownUser.user_type == 'domain').count()
        
        # Local users
        local_users = query.filter(KnownUser.user_type == 'local').count()
        
        # Compromised users
        compromised = query.filter(KnownUser.compromised == 'yes').count()
        
        return jsonify({
            'success': True,
            'stats': {
                'total': total,
                'domain_users': domain_users,
                'local_users': local_users,
                'compromised': compromised
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting user stats: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@known_users_bp.route('/api/create', methods=['POST'])
@login_required
def api_create():
    """
    Create a new known user
    
    Required fields:
    - username: Username
    
    Optional fields:
    - domain_name: Domain name or hostname for local users
    - sid: Security Identifier
    - compromised: Compromised status (default: no)
    - user_type: User type (domain, local, unknown)
    - source: Source (default: manual)
    - description: Description text
    - analyst_notes: Analyst notes
    """
    try:
        # Check if user has permission to create users
        if current_user.role == 'read-only':
            return jsonify({'success': False, 'error': 'Insufficient permissions'}), 403
        
        # Get case ID from session
        case_id = session.get('selected_case_id')
        if not case_id:
            return jsonify({'success': False, 'error': 'No case selected'}), 400
        
        # Verify case exists
        case = Case.query.get(case_id)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Get form data
        data = request.get_json()
        
        # Validate required fields
        if not data.get('username'):
            return jsonify({'success': False, 'error': 'Missing required field: username'}), 400
        
        # Use auto-merge logic to find existing or create new
        user = _find_or_merge_user(
            case_id=case_id,
            username=data['username'].strip(),
            domain_name=data.get('domain_name', '').strip() if data.get('domain_name') else None,
            sid=data.get('sid', '').strip() if data.get('sid') else None,
            user_type=data.get('user_type', 'unknown'),
            compromised=data.get('compromised', 'no'),
            source=data.get('source', 'manual'),
            description=data.get('description', '').strip() if data.get('description') else None,
            analyst_notes=data.get('analyst_notes', '').strip() if data.get('analyst_notes') else None,
            created_by=current_user.id,
            updated_by=current_user.id
        )
        
        if not user:
            return jsonify({'success': False, 'error': 'Failed to create user'}), 500
        
        db.session.commit()
        
        # Build detailed user information for audit log
        user_details = {
            'username': user.username,
            'domain_name': user.domain_name,
            'sid': user.sid,
            'user_type': user.user_type,
            'compromised': user.compromised,
            'source': user.source
        }
        
        # Log the action
        log_action(
            action='user_created',
            resource_type='case',
            resource_id=case.id,
            resource_name=case.name,
            details={
                'performed_by': current_user.username,
                'creation_method': 'manual',
                'user_id': user.id,
                'user_details': user_details
            }
        )
        
        return jsonify({
            'success': True,
            'message': 'User created successfully',
            'user': {
                'id': user.id,
                'username': user.username,
                'domain_name': user.domain_name,
                'user_type': user.user_type
            }
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating user: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@known_users_bp.route('/api/update/<int:user_id>', methods=['PUT'])
@login_required
def api_update(user_id):
    """
    Update an existing user
    
    Requires analyst or higher permissions
    Logs all changes to audit log
    """
    try:
        # Check permissions
        if current_user.role == 'read-only':
            return jsonify({'success': False, 'error': 'Insufficient permissions'}), 403
        
        # Get user
        user = KnownUser.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        # Get case for logging
        case = Case.query.get(user.case_id)
        
        # Get form data
        data = request.get_json()
        
        # Store original values for audit log
        original_values = {
            'username': user.username,
            'domain_name': user.domain_name,
            'sid': user.sid,
            'user_type': user.user_type,
            'compromised': user.compromised,
            'source': user.source,
            'description': user.description,
            'analyst_notes': user.analyst_notes
        }
        
        # Track what changed
        changes = {}
        
        # Update fields if provided
        updateable_fields = [
            'username', 'domain_name', 'sid', 'user_type',
            'compromised', 'source', 'description', 'analyst_notes'
        ]
        
        for field in updateable_fields:
            if field in data:
                new_value = data[field]
                # Strip strings
                if isinstance(new_value, str):
                    new_value = new_value.strip() if new_value else None
                
                # Check if value changed
                old_value = getattr(user, field)
                if old_value != new_value:
                    changes[field] = {
                        'old': old_value,
                        'new': new_value
                    }
                    setattr(user, field, new_value)
        
        # Update modified info
        user.updated_by = current_user.id
        
        # Check if user was marked as compromised - create IOC if needed
        ioc_created = False
        if 'compromised' in changes and changes['compromised']['new'] == 'yes':
            from utils.ioc_sync import create_ioc_from_user
            ioc = create_ioc_from_user(db, user, current_user.id)
            if ioc:
                ioc_created = True
                logger.info(f"Auto-created IOC (ID: {ioc.id}) for compromised user {user.username}")
        
        db.session.commit()
        
        # Log the action with detailed changes
        log_action(
            action='user_updated',
            resource_type='known_user',
            resource_id=user.id,
            resource_name=f"{user.domain_name}\\{user.username}" if user.domain_name else user.username,
            details={
                'performed_by': current_user.username,
                'case_name': case.name if case else 'Unknown',
                'user_id': user.id,
                'original_state': original_values,
                'changes': changes
            }
        )
        
        return jsonify({
            'success': True,
            'message': 'User updated successfully' + (' (IOC created)' if ioc_created else ''),
            'ioc_created': ioc_created,
            'user': {
                'id': user.id,
                'username': user.username,
                'domain_name': user.domain_name,
                'user_type': user.user_type
            }
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating user {user_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@known_users_bp.route('/api/delete/<int:user_id>', methods=['DELETE'])
@login_required
def api_delete(user_id):
    """
    Delete a user
    
    Requires analyst or higher permissions
    Logs deletion to audit log
    """
    try:
        # Check permissions - must be analyst or administrator
        if current_user.role not in ['analyst', 'administrator']:
            return jsonify({'success': False, 'error': 'Insufficient permissions - requires analyst or administrator role'}), 403
        
        # Get user
        user = KnownUser.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        # Get case for logging
        case = Case.query.get(user.case_id)
        
        # Store user details for audit log before deletion
        user_details = {
            'id': user.id,
            'username': user.username,
            'domain_name': user.domain_name,
            'sid': user.sid,
            'user_type': user.user_type,
            'compromised': user.compromised
        }
        
        # Delete the user
        db.session.delete(user)
        db.session.commit()
        
        # Log the action
        log_action(
            action='user_deleted',
            resource_type='known_user',
            resource_id=user_id,
            resource_name=f"{user_details.get('domain_name')}\\{user_details.get('username')}" if user_details.get('domain_name') else user_details.get('username'),
            details={
                'performed_by': current_user.username,
                'case_name': case.name if case else 'Unknown',
                'deleted_user': user_details
            }
        )
        
        return jsonify({
            'success': True,
            'message': 'User deleted successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting user {user_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@known_users_bp.route('/api/bulk_update', methods=['POST'])
@login_required
def api_bulk_update():
    """
    Bulk update multiple users
    
    Requires analyst or higher permissions
    Logs all changes to audit log
    """
    try:
        # Check permissions
        if current_user.role == 'read-only':
            return jsonify({'success': False, 'error': 'Insufficient permissions'}), 403
        
        data = request.get_json()
        user_ids = data.get('user_ids', [])
        updates = data.get('updates', {})
        
        if not user_ids:
            return jsonify({'success': False, 'error': 'No users selected'}), 400
        
        if not updates:
            return jsonify({'success': False, 'error': 'No updates specified'}), 400
        
        # Get all users
        users = KnownUser.query.filter(KnownUser.id.in_(user_ids)).all()
        
        if not users:
            return jsonify({'success': False, 'error': 'No users found'}), 404
        
        # Get case for logging (assuming all users are from same case)
        case = Case.query.get(users[0].case_id) if users else None
        
        # Track changes for each user
        all_changes = []
        
        # Update each user
        for user in users:
            user_changes = {
                'user_id': user.id,
                'user_name': f"{user.domain_name}\\{user.username}" if user.domain_name else user.username,
                'changes': {}
            }
            
            # Apply updates
            for field, new_value in updates.items():
                if hasattr(user, field):
                    old_value = getattr(user, field)
                    
                    # Strip strings
                    if isinstance(new_value, str):
                        new_value = new_value.strip() if new_value else None
                    
                    if old_value != new_value:
                        user_changes['changes'][field] = {
                            'old': old_value,
                            'new': new_value
                        }
                        setattr(user, field, new_value)
            
            user.updated_by = current_user.id
            
            if user_changes['changes']:
                all_changes.append(user_changes)
        
        db.session.commit()
        
        # Log the action
        log_action(
            action='users_bulk_updated',
            resource_type='case',
            resource_id=case.id if case else None,
            resource_name=case.name if case else 'Multiple Cases',
            details={
                'performed_by': current_user.username,
                'users_count': len(users),
                'updates_applied': updates,
                'users_changed': all_changes
            }
        )
        
        return jsonify({
            'success': True,
            'message': f'Successfully updated {len(users)} users',
            'updated_count': len(users)
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error bulk updating users: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@known_users_bp.route('/api/bulk_delete', methods=['POST'])
@login_required
def api_bulk_delete():
    """
    Bulk delete multiple users
    
    Requires analyst or higher permissions
    Logs all deletions to audit log
    """
    try:
        # Check permissions - must be analyst or administrator
        if current_user.role not in ['analyst', 'administrator']:
            return jsonify({'success': False, 'error': 'Insufficient permissions - requires analyst or administrator role'}), 403
        
        data = request.get_json()
        user_ids = data.get('user_ids', [])
        
        if not user_ids:
            return jsonify({'success': False, 'error': 'No users selected'}), 400
        
        # Get all users
        users = KnownUser.query.filter(KnownUser.id.in_(user_ids)).all()
        
        if not users:
            return jsonify({'success': False, 'error': 'No users found'}), 404
        
        # Get case for logging (assuming all users are from same case)
        case = Case.query.get(users[0].case_id) if users else None
        
        # Store user details for audit log
        deleted_users = []
        for user in users:
            deleted_users.append({
                'id': user.id,
                'username': user.username,
                'domain_name': user.domain_name,
                'sid': user.sid,
                'user_type': user.user_type
            })
            db.session.delete(user)
        
        db.session.commit()
        
        # Log the action
        log_action(
            action='users_bulk_deleted',
            resource_type='case',
            resource_id=case.id if case else None,
            resource_name=case.name if case else 'Multiple Cases',
            details={
                'performed_by': current_user.username,
                'users_count': len(users),
                'deleted_users': deleted_users
            }
        )
        
        return jsonify({
            'success': True,
            'message': f'Successfully deleted {len(users)} users',
            'deleted_count': len(users)
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error bulk deleting users: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@known_users_bp.route('/api/combine', methods=['POST'])
@login_required
def api_combine():
    """
    Combine multiple users - user selects parent, children merge in
    
    Requires analyst or higher permissions
    Logs detailed before/after states to audit log
    """
    try:
        # Check permissions
        if current_user.role not in ['analyst', 'administrator']:
            return jsonify({'success': False, 'error': 'Insufficient permissions'}), 403
        
        data = request.get_json()
        parent_id = data.get('parent_id')
        child_ids = data.get('child_ids', [])
        
        if not parent_id or not child_ids:
            return jsonify({'success': False, 'error': 'Must specify parent and children'}), 400
        
        # Get parent
        parent = KnownUser.query.get(parent_id)
        if not parent:
            return jsonify({'success': False, 'error': 'Parent not found'}), 404
        
        # Get children
        children = KnownUser.query.filter(KnownUser.id.in_(child_ids)).all()
        if not children:
            return jsonify({'success': False, 'error': 'No children found'}), 404
        
        # Verify all same case
        for child in children:
            if child.case_id != parent.case_id:
                return jsonify({'success': False, 'error': 'All users must be from same case'}), 400
        
        # Check if warning needed
        items_to_check = [{'user_type': parent.user_type, 'compromised': parent.compromised}]
        for child in children:
            items_to_check.append({'user_type': child.user_type, 'compromised': child.compromised})
        
        should_warn, warnings = should_warn_before_combine(items_to_check, 'user')
        
        # If warning and user hasn't confirmed, return warning
        if should_warn and not data.get('confirmed', False):
            return jsonify({
                'success': False,
                'warning': True,
                'warnings': warnings,
                'message': 'Please confirm you want to combine these users'
            }), 400
        
        # Track changes for summary
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        fields_merged = []
        children_deleted = []
        
        # Capture before state
        before_state = {
            'username': parent.username,
            'domain_name': parent.domain_name,
            'sid': parent.sid,
            'description': parent.description,
            'analyst_notes': parent.analyst_notes,
            'user_type': parent.user_type,
            'compromised': parent.compromised
        }
        
        for child in children:
            child_info = []
            
            # Merge each field
            for field in ['username', 'domain_name', 'sid', 'description', 'user_type', 'compromised']:
                parent_val = getattr(parent, field)
                child_val = getattr(child, field)
                
                # Skip if child has no value
                if is_blank(child_val):
                    continue
                
                # If parent blank, copy from child
                if is_blank(parent_val):
                    setattr(parent, field, child_val)
                    fields_merged.append(f"{field}: {child_val}")
                # Both have values - add to analyst notes
                elif parent_val != child_val:
                    child_info.append(f"{field}: {child_val}")
            
            # Merge analyst_notes from child
            if child.analyst_notes and not is_blank(child.analyst_notes):
                parent.analyst_notes = append_original_notes(parent.analyst_notes or "", child.analyst_notes)
            
            # Add merge note to parent
            merge_fields = {k.split(': ')[0]: k.split(': ')[1] for k in child_info if ': ' in k} if child_info else {}
            parent.analyst_notes = update_analyst_notes_with_merge(
                parent.analyst_notes or "",
                merge_type='manual',
                source_name=f"{child.domain_name}\\{child.username}" if child.domain_name else child.username,
                source_id=child.id,
                fields_merged=merge_fields if merge_fields else None
            )
            
            # Track for summary
            children_deleted.append({
                'id': child.id,
                'username': child.username,
                'domain_name': child.domain_name,
                'data_merged': child_info
            })
            
            # Delete child
            db.session.delete(child)
        
        parent.updated_by = current_user.id
        db.session.commit()
        
        # Build summary
        summary = {
            'parent': {
                'id': parent.id,
                'username': parent.username,
                'domain_name': parent.domain_name,
                'before': before_state,
                'after': {
                    'username': parent.username,
                    'domain_name': parent.domain_name,
                    'sid': parent.sid,
                    'description': parent.description,
                    'analyst_notes': parent.analyst_notes,
                    'user_type': parent.user_type,
                    'compromised': parent.compromised
                }
            },
            'children_merged': children_deleted,
            'total_merged': len(children_deleted)
        }
        
        # Audit log
        log_action('users_combined', resource_type='known_user', 
                  resource_id=parent.id, 
                  resource_name=f"{parent.domain_name}\\{parent.username}" if parent.domain_name else parent.username,
                  details=summary)
        
        return jsonify({
            'success': True,
            'summary': summary,
            'message': f'Successfully combined {len(children_deleted)} users into {parent.username}'
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error combining users: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@known_users_bp.route('/api/import_csv', methods=['POST'])
@login_required
def api_import_csv():
    """
    Import users from CSV file
    
    CSV Format (no header):
    name,domain,sid,compromised
    
    - name: Username (required, can include domain as DOMAIN\\user)
    - domain: Domain name (use , for none)
    - sid: Security Identifier (use , for none)
    - compromised: true/false
    
    Empty fields represented by ,, (consecutive commas)
    """
    try:
        # Check permissions
        if current_user.role == 'read-only':
            return jsonify({'success': False, 'error': 'Insufficient permissions'}), 403
        
        # Get case ID from session
        case_id = session.get('selected_case_id')
        if not case_id:
            return jsonify({'success': False, 'error': 'No case selected'}), 400
        
        case = Case.query.get(case_id)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        # Get uploaded file
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        if not file.filename.endswith('.csv'):
            return jsonify({'success': False, 'error': 'File must be a CSV'}), 400
        
        # Read CSV content
        content = file.read().decode('utf-8')
        csv_reader = csv.reader(StringIO(content))
        
        created_count = 0
        updated_count = 0
        error_count = 0
        errors = []
        
        line_num = 0
        for row in csv_reader:
            line_num += 1
            
            # Skip empty rows
            if not row or all(not cell.strip() for cell in row):
                continue
            
            # Validate row has correct number of fields
            if len(row) != 4:
                error_count += 1
                errors.append(f"Line {line_num}: Expected 4 fields, got {len(row)}")
                continue
            
            # Parse fields
            username_raw = row[0].strip() if row[0].strip() else None
            domain = row[1].strip() if row[1].strip() else '-'
            sid = row[2].strip() if row[2].strip() else '-'
            compromised_str = row[3].strip().lower() if row[3].strip() else 'unknown'
            
            # Validate required fields
            if not username_raw:
                error_count += 1
                errors.append(f"Line {line_num}: Username is required")
                continue
            
            # Parse username - may include domain as DOMAIN\user
            username = username_raw
            if '\\' in username_raw:
                parts = username_raw.split('\\', 1)
                if domain == '-':  # Only override if domain wasn't specified separately
                    domain = parts[0]
                username = parts[1]
            elif '@' in username_raw:
                parts = username_raw.split('@', 1)
                username = parts[0]
                if domain == '-':
                    domain = parts[1]
            
            # Determine user type
            if domain != '-' and domain.upper() not in ['LOCAL', 'WORKGROUP']:
                user_type = 'domain'
            else:
                user_type = 'local'
            
            # Parse compromised value
            if compromised_str in ['true', 'yes', '1']:
                compromised = 'yes'
            elif compromised_str in ['false', 'no', '0']:
                compromised = 'no'
            else:
                compromised = 'no'  # Default to no for imports
            
            try:
                # Track if this is new or merged
                normalized_check = normalize_username(username_raw)
                existing_check = KnownUser.query.filter(
                    KnownUser.case_id == case_id,
                    db.func.lower(KnownUser.username) == normalized_check
                ).first()
                
                # Use auto-merge logic (with SID validation)
                user = _find_or_merge_user(
                    case_id=case_id,
                    username=username_raw,  # Use raw (may include domain)
                    domain_name=domain if domain != '-' else None,
                    sid=sid if sid != '-' else None,
                    user_type=user_type,
                    compromised=compromised,
                    source='csv_import',
                    description='Imported from CSV',
                    analyst_notes='Imported from CSV file',
                    created_by=current_user.id,
                    updated_by=current_user.id
                )
                
                if user:
                    # Track whether this was new or merged
                    if existing_check:
                        updated_count += 1
                    else:
                        created_count += 1
                else:
                    error_count += 1
                    errors.append(f"Line {line_num}: Failed to create/merge user")
                
            except Exception as e:
                error_count += 1
                errors.append(f"Line {line_num}: {str(e)}")
                logger.error(f"Error importing user from line {line_num}: {e}")
        
        # Commit all changes
        db.session.commit()
        
        # Log the import
        log_action(
            action='users_imported_from_csv',
            resource_type='case',
            resource_id=case.id,
            resource_name=case.name,
            details={
                'performed_by': current_user.username,
                'created': created_count,
                'merged': updated_count,
                'errors': error_count,
                'total_lines': line_num
            }
        )
        
        result = {
            'success': True,
            'created': created_count,
            'merged': updated_count,  # Renamed for clarity
            'errors': error_count,
            'total': created_count + updated_count
        }
        
        if errors:
            result['error_details'] = errors[:10]  # Limit to first 10 errors
        
        return jsonify(result)
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error importing users from CSV: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@known_users_bp.route('/api/export_csv')
@login_required
def api_export_csv():
    """
    Export users to CSV file
    
    Query Parameters:
    - Same filters as /api/list (search, user_type, compromised, source, case_id)
    """
    try:
        # Get query parameters (same as list endpoint)
        search_query = request.args.get('search', '').strip()
        user_type = request.args.get('user_type', '')
        compromised = request.args.get('compromised', '')
        source = request.args.get('source', '')
        
        # Get case ID from query or session
        case_id = request.args.get('case_id')
        if not case_id:
            case_id = session.get('selected_case_id')
        
        # Build query
        query = KnownUser.query
        
        # Filter by case if specified
        if case_id:
            query = query.filter(KnownUser.case_id == case_id)
        
        # Apply search filter
        if search_query:
            search_filter = db.or_(
                KnownUser.username.ilike(f'%{search_query}%'),
                KnownUser.domain_name.ilike(f'%{search_query}%'),
                KnownUser.sid.ilike(f'%{search_query}%'),
                KnownUser.description.ilike(f'%{search_query}%'),
                KnownUser.analyst_notes.ilike(f'%{search_query}%')
            )
            query = query.filter(search_filter)
        
        # Apply filters
        if user_type:
            query = query.filter(KnownUser.user_type == user_type)
        if compromised:
            query = query.filter(KnownUser.compromised == compromised)
        if source:
            query = query.filter(KnownUser.source == source)
        
        # Order alphabetically by username
        query = query.order_by(KnownUser.username)
        
        # Get all users (no pagination for export)
        users = query.all()
        
        # Create CSV in memory
        output = StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'ID', 'Username', 'Domain Name', 'SID', 'User Type',
            'Compromised', 'Source', 'Description', 'Analyst Notes',
            'Case ID', 'Created At', 'Updated At'
        ])
        
        # Write data
        for user in users:
            writer.writerow([
                user.id,
                user.username or '',
                user.domain_name or '',
                user.sid or '',
                user.user_type,
                user.compromised,
                user.source,
                user.description or '',
                user.analyst_notes or '',
                user.case_id,
                user.created_at.isoformat() if user.created_at else '',
                user.updated_at.isoformat() if user.updated_at else ''
            ])
        
        # Get case name for filename
        case_name = 'all_cases'
        if case_id:
            case = Case.query.get(case_id)
            if case:
                # Sanitize case name for filename
                case_name = ''.join(c for c in case.name if c.isalnum() or c in (' ', '-', '_')).strip()
                case_name = case_name.replace(' ', '_')
        
        # Create response
        output.seek(0)
        response = Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment; filename=known_users_{case_name}.csv'
            }
        )
        
        # Log the export
        log_action(
            action='users_exported',
            resource_type='case',
            resource_id=case_id,
            resource_name=case_name,
            details=f'Exported {len(users)} users to CSV'
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Error exporting users to CSV: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@known_users_bp.route('/api/discover_from_logs', methods=['POST'])
@login_required
def api_discover_from_logs():
    """
    Trigger user discovery from OpenSearch logs
    
    Requires analyst or higher permissions
    Starts a Celery task to scan events and create user entries
    """
    try:
        # Check permissions
        if current_user.role == 'read-only':
            return jsonify({'success': False, 'error': 'Insufficient permissions'}), 403
        
        # Get case ID from session
        case_id = session.get('selected_case_id')
        if not case_id:
            return jsonify({'success': False, 'error': 'No case selected'}), 400
        
        # Verify case exists
        case = Case.query.get(case_id)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        
        if not case.opensearch_index:
            return jsonify({'success': False, 'error': 'Case has no OpenSearch index. Please upload and process files first.'}), 400
        
        # Import and start task
        from tasks.task_discover_users import discover_users_from_logs
        
        # Start Celery task
        task = discover_users_from_logs.apply_async(args=[case_id, current_user.id])
        
        # Log the action
        log_action(
            action='user_discovery_started',
            resource_type='case',
            resource_id=case.id,
            resource_name=case.name,
            details=f'Started automatic user discovery from logs. Task ID: {task.id}'
        )
        
        return jsonify({
            'success': True,
            'task_id': task.id,
            'message': 'User discovery started'
        })
        
    except Exception as e:
        logger.error(f"Error starting user discovery: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@known_users_bp.route('/api/discovery_status/<task_id>')
@login_required
def api_discovery_status(task_id):
    """
    Check status of user discovery task
    """
    try:
        from celery.result import AsyncResult
        task = AsyncResult(task_id)
        
        if task.state == 'PENDING':
            response = {
                'state': task.state,
                'status': 'Task pending...',
                'progress': 0
            }
        elif task.state == 'PROGRESS':
            response = {
                'state': task.state,
                'status': task.info.get('status', ''),
                'progress': task.info.get('progress', 0)
            }
        elif task.state == 'SUCCESS':
            result = task.result
            response = {
                'state': task.state,
                'status': 'Complete',
                'progress': 100,
                'result': result
            }
        elif task.state == 'FAILURE':
            response = {
                'state': task.state,
                'status': str(task.info),
                'progress': 0
            }
        else:
            response = {
                'state': task.state,
                'status': str(task.info),
                'progress': 0
            }
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error checking discovery status: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

