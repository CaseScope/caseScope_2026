"""Archive Routes - Case Archiving and Restoration"""
from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from functools import wraps
from main import db
from models import Case
from archive_utils import (
    archive_case,
    restore_case,
    get_case_file_size,
    get_archive_root_path,
    validate_archive_path,
    is_case_archived
)

archive_bp = Blueprint('archive', __name__, url_prefix='/archive')


def admin_required(f):
    """Decorator to require administrator role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'administrator':
            return jsonify({'success': False, 'error': 'Administrator access required'}), 403
        return f(*args, **kwargs)
    return decorated_function


@archive_bp.route('/case/<int:case_id>/archive', methods=['POST'])
@login_required
@admin_required
def archive_case_route(case_id):
    """
    Archive a case (admin only)
    
    Process:
    - Validates archive path configured
    - Creates ZIP of case files
    - Removes original files
    - Updates case status to 'Archived'
    
    Returns:
        JSON: {
            'success': bool,
            'message': str,
            'archive_path': str,
            'size_mb': float,
            'file_count': int
        }
    """
    try:
        # Check if case exists
        case = db.session.get(Case, case_id)
        if not case:
            return jsonify({
                'success': False,
                'error': f'Case {case_id} not found'
            }), 404
        
        # Check if archive path configured
        archive_root = get_archive_root_path()
        if not archive_root:
            return jsonify({
                'success': False,
                'error': 'Archive root path not configured in System Settings'
            }), 400
        
        # Validate archive path
        validation = validate_archive_path(archive_root)
        if not validation['valid']:
            return jsonify({
                'success': False,
                'error': validation['message']
            }), 400
        
        # Check if already archived
        if is_case_archived(case):
            return jsonify({
                'success': False,
                'error': 'Case is already archived'
            }), 400
        
        # Archive the case
        result = archive_case(db, case_id, current_user.id)
        
        if result['status'] == 'success':
            return jsonify({
                'success': True,
                'message': result['message'],
                'archive_path': result['archive_path'],
                'size_mb': result['size_mb'],
                'file_count': result['file_count']
            })
        else:
            return jsonify({
                'success': False,
                'error': result['message']
            }), 500
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Archive failed: {str(e)}'
        }), 500


@archive_bp.route('/case/<int:case_id>/restore', methods=['POST'])
@login_required
@admin_required
def restore_case_route(case_id):
    """
    Restore an archived case (admin only)
    
    Requires:
        JSON body: {
            'new_status': str  # New case status after restore (e.g., 'In Progress')
        }
    
    Process:
    - Validates case is archived
    - Extracts ZIP to original location
    - Sets ownership to casescope:casescope
    - Updates case status
    
    Returns:
        JSON: {
            'success': bool,
            'message': str,
            'files_restored': int
        }
    """
    try:
        # Check if case exists
        case = db.session.get(Case, case_id)
        if not case:
            return jsonify({
                'success': False,
                'error': f'Case {case_id} not found'
            }), 404
        
        # Check if case is archived
        if not is_case_archived(case):
            return jsonify({
                'success': False,
                'error': 'Case is not archived'
            }), 400
        
        # Get new status from request
        data = request.get_json() or {}
        new_status = data.get('new_status', 'In Progress')
        
        # Validate status
        valid_statuses = ['New', 'Assigned', 'In Progress', 'Completed']
        if new_status not in valid_statuses:
            return jsonify({
                'success': False,
                'error': f'Invalid status. Must be one of: {", ".join(valid_statuses)}'
            }), 400
        
        # Restore the case
        result = restore_case(db, case_id, current_user.id, new_status)
        
        if result['status'] == 'success':
            return jsonify({
                'success': True,
                'message': result['message'],
                'files_restored': result['files_restored']
            })
        else:
            return jsonify({
                'success': False,
                'error': result['message']
            }), 500
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Restore failed: {str(e)}'
        }), 500


@archive_bp.route('/case/<int:case_id>/info', methods=['GET'])
@login_required
def case_archive_info(case_id):
    """
    Get archive information for a case
    
    Returns:
        JSON: {
            'case_id': int,
            'is_archived': bool,
            'archive_path': str,
            'archived_at': str,
            'file_size': dict,
            'archive_root_configured': bool
        }
    """
    try:
        case = db.session.get(Case, case_id)
        if not case:
            return jsonify({
                'success': False,
                'error': f'Case {case_id} not found'
            }), 404
        
        # Get case file size
        size_info = get_case_file_size(case_id)
        
        # Check if archive path configured
        archive_root = get_archive_root_path()
        archive_root_configured = archive_root is not None and archive_root.strip() != ''
        
        return jsonify({
            'success': True,
            'case_id': case_id,
            'is_archived': is_case_archived(case),
            'archive_path': case.archive_path,
            'archived_at': case.archived_at.isoformat() if case.archived_at else None,
            'archived_by': case.archived_by,
            'restored_at': case.restored_at.isoformat() if case.restored_at else None,
            'file_size': size_info,
            'archive_root_configured': archive_root_configured
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Failed to get archive info: {str(e)}'
        }), 500

