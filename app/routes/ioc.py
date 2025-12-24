"""
IOC Management Routes
Manage Indicators of Compromise for threat intelligence
"""

from flask import Blueprint, render_template, jsonify, request, session, Response
from flask_login import login_required, current_user
from main import db
from models import IOC, Case
from audit_logger import log_action
import logging
import csv
from io import StringIO

logger = logging.getLogger(__name__)

ioc_bp = Blueprint('ioc', __name__, url_prefix='/ioc')


@ioc_bp.route('/')
@ioc_bp.route('/manage')
@login_required
def manage():
    """
    IOC management page - placeholder for now
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
    
    return render_template('ioc/manage.html', case=case)


@ioc_bp.route('/api/list')
@login_required
def api_list():
    """
    API endpoint to list IOCs with pagination, search, and filtering
    
    Query Parameters:
    - page: Page number (default: 1)
    - per_page: Results per page (default: 50, max: 100)
    - search: Search query (searches value, description, analyst_notes)
    - visibility: 'all', 'hidden_only', 'hide_hidden' (default: 'hide_hidden')
    - type: Filter by IOC type
    - category: Filter by category
    - threat_level: Filter by threat level
    - case_id: Filter by case (optional, defaults to session case)
    """
    try:
        # Get query parameters
        page = max(1, int(request.args.get('page', 1)))
        per_page = min(100, max(1, int(request.args.get('per_page', 50))))
        search_query = request.args.get('search', '').strip()
        visibility = request.args.get('visibility', 'hide_hidden')
        ioc_type = request.args.get('type', '')
        category = request.args.get('category', '')
        threat_level = request.args.get('threat_level', '')
        
        # Get case ID from query or session
        case_id = request.args.get('case_id')
        if not case_id:
            case_id = session.get('selected_case_id')
        
        # Build query
        query = IOC.query
        
        # Filter by case if specified
        if case_id:
            query = query.filter(IOC.case_id == case_id)
        
        # Apply visibility filter
        if visibility == 'hidden_only':
            query = query.filter(IOC.is_hidden == True)
        elif visibility == 'hide_hidden':
            query = query.filter(IOC.is_hidden == False)
        # 'all' shows everything
        
        # Apply search filter
        if search_query:
            search_filter = db.or_(
                IOC.value.ilike(f'%{search_query}%'),
                IOC.description.ilike(f'%{search_query}%'),
                IOC.analyst_notes.ilike(f'%{search_query}%')
            )
            query = query.filter(search_filter)
        
        # Apply type filter
        if ioc_type:
            query = query.filter(IOC.type == ioc_type)
        
        # Apply category filter
        if category:
            query = query.filter(IOC.category == category)
        
        # Apply threat level filter
        if threat_level:
            query = query.filter(IOC.threat_level == threat_level)
        
        # Order by most recent first
        query = query.order_by(IOC.last_seen.desc())
        
        # Get total count
        total = query.count()
        
        # Paginate
        offset = (page - 1) * per_page
        iocs = query.offset(offset).limit(per_page).all()
        
        # Format results
        results = []
        for ioc in iocs:
            results.append({
                'id': ioc.id,
                'type': ioc.type,
                'value': ioc.value,
                'category': ioc.category,
                'threat_level': ioc.threat_level,
                'confidence': ioc.confidence,
                'is_active': ioc.is_active,
                'is_whitelisted': ioc.is_whitelisted,
                'is_hidden': ioc.is_hidden,
                'first_seen': ioc.first_seen.isoformat() if ioc.first_seen else None,
                'last_seen': ioc.last_seen.isoformat() if ioc.last_seen else None,
                'times_seen': ioc.times_seen,
                'source': ioc.source,
                'description': ioc.description,
                'analyst_notes': ioc.analyst_notes,
                'case_id': ioc.case_id
            })
        
        return jsonify({
            'success': True,
            'iocs': results,
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': (total + per_page - 1) // per_page
        })
        
    except Exception as e:
        logger.error(f"Error listing IOCs: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@ioc_bp.route('/api/get/<int:ioc_id>')
@login_required
def api_get(ioc_id):
    """
    Get details for a specific IOC
    """
    try:
        ioc = IOC.query.get(ioc_id)
        
        if not ioc:
            return jsonify({'success': False, 'error': 'IOC not found'}), 404
        
        # Check permissions for read-only users
        if current_user.role == 'read-only':
            if ioc.case_id != current_user.case_assigned:
                return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        return jsonify({
            'success': True,
            'ioc': {
                'id': ioc.id,
                'type': ioc.type,
                'value': ioc.value,
                'category': ioc.category,
                'threat_level': ioc.threat_level,
                'confidence': ioc.confidence,
                'is_active': ioc.is_active,
                'is_whitelisted': ioc.is_whitelisted,
                'is_hidden': ioc.is_hidden,
                'first_seen': ioc.first_seen.isoformat() if ioc.first_seen else None,
                'last_seen': ioc.last_seen.isoformat() if ioc.last_seen else None,
                'times_seen': ioc.times_seen,
                'expires_at': ioc.expires_at.isoformat() if ioc.expires_at else None,
                'source': ioc.source,
                'source_reference': ioc.source_reference,
                'description': ioc.description,
                'analyst_notes': ioc.analyst_notes,
                'case_id': ioc.case_id,
                'created_at': ioc.created_at.isoformat() if ioc.created_at else None,
                'updated_at': ioc.updated_at.isoformat() if ioc.updated_at else None
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting IOC {ioc_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@ioc_bp.route('/api/stats')
@login_required
def api_stats():
    """
    Get IOC statistics for the current case
    """
    try:
        case_id = session.get('selected_case_id')
        
        if not case_id:
            return jsonify({
                'success': True,
                'stats': {
                    'total': 0,
                    'by_category': {},
                    'by_threat_level': {},
                    'by_type': {}
                }
            })
        
        # Build base query
        query = IOC.query.filter(IOC.case_id == case_id)
        
        # Total count (excluding hidden by default)
        total = query.filter(IOC.is_hidden == False).count()
        
        # Count by category
        by_category = {}
        categories = db.session.query(IOC.category, db.func.count(IOC.id))\
            .filter(IOC.case_id == case_id, IOC.is_hidden == False)\
            .group_by(IOC.category).all()
        for cat, count in categories:
            by_category[cat] = count
        
        # Count by threat level
        by_threat_level = {}
        threat_levels = db.session.query(IOC.threat_level, db.func.count(IOC.id))\
            .filter(IOC.case_id == case_id, IOC.is_hidden == False)\
            .group_by(IOC.threat_level).all()
        for level, count in threat_levels:
            by_threat_level[level] = count
        
        # Count by type
        by_type = {}
        types = db.session.query(IOC.type, db.func.count(IOC.id))\
            .filter(IOC.case_id == case_id, IOC.is_hidden == False)\
            .group_by(IOC.type).all()
        for ioc_type, count in types:
            by_type[ioc_type] = count
        
        return jsonify({
            'success': True,
            'stats': {
                'total': total,
                'by_category': by_category,
                'by_threat_level': by_threat_level,
                'by_type': by_type
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting IOC stats: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@ioc_bp.route('/api/check_duplicate', methods=['POST'])
@login_required
def api_check_duplicate():
    """
    Check for duplicate or overlapping IOCs
    
    Returns:
    - exact_match: True if exact value exists
    - overlaps: List of IOCs that might overlap with this value
    """
    try:
        data = request.get_json()
        value = data.get('value', '').strip()
        ioc_type = data.get('type', '')
        
        if not value:
            return jsonify({'success': False, 'error': 'Value is required'}), 400
        
        # Get case ID
        case_id = session.get('selected_case_id')
        if not case_id:
            return jsonify({'success': False, 'error': 'No case selected'}), 400
        
        # Check for exact match (case-insensitive)
        exact_match = IOC.query.filter(
            IOC.case_id == case_id,
            db.func.lower(IOC.value) == value.lower()
        ).first()
        
        # Find potential overlaps
        overlaps = []
        
        # Only check overlaps for certain types and if value is long enough
        check_overlaps = len(value) >= 3 and ioc_type in [
            'username', 'domain', 'email_address', 'email_sender', 
            'filename', 'process_name', 'registry_key', 'filepath'
        ]
        
        if check_overlaps:
            # Get all IOCs in this case
            all_iocs = IOC.query.filter(IOC.case_id == case_id).all()
            
            value_lower = value.lower()
            
            for ioc in all_iocs:
                ioc_value_lower = ioc.value.lower()
                
                # Skip exact matches (already handled)
                if ioc_value_lower == value_lower:
                    continue
                
                # Check if new value contains existing IOC value
                if len(ioc.value) >= 3 and ioc_value_lower in value_lower and len(ioc.value) < len(value):
                    # Check if it's a meaningful substring (not just common words)
                    # For commands/paths, require word boundaries or path separators
                    if ioc.type in ['command_line', 'filepath', 'process_name']:
                        # Check for word boundaries
                        if _has_word_boundary(value_lower, ioc_value_lower):
                            overlaps.append({
                                'id': ioc.id,
                                'type': ioc.type,
                                'value': ioc.value,
                                'threat_level': ioc.threat_level,
                                'relationship': 'contains',
                                'message': f'Your IOC contains existing IOC: "{ioc.value}"'
                            })
                    else:
                        overlaps.append({
                            'id': ioc.id,
                            'type': ioc.type,
                            'value': ioc.value,
                            'threat_level': ioc.threat_level,
                            'relationship': 'contains',
                            'message': f'Your IOC contains existing IOC: "{ioc.value}"'
                        })
                
                # Check if existing IOC value contains new value
                elif len(value) >= 3 and value_lower in ioc_value_lower and len(value) < len(ioc.value):
                    # Similar boundary check for commands/paths
                    if ioc.type in ['command_line', 'filepath', 'process_name']:
                        if _has_word_boundary(ioc_value_lower, value_lower):
                            overlaps.append({
                                'id': ioc.id,
                                'type': ioc.type,
                                'value': ioc.value,
                                'threat_level': ioc.threat_level,
                                'relationship': 'contained_by',
                                'message': f'Existing IOC contains your value: "{ioc.value}"'
                            })
                    else:
                        overlaps.append({
                            'id': ioc.id,
                            'type': ioc.type,
                            'value': ioc.value,
                            'threat_level': ioc.threat_level,
                            'relationship': 'contained_by',
                            'message': f'Existing IOC contains your value: "{ioc.value}"'
                        })
        
        return jsonify({
            'success': True,
            'exact_match': exact_match is not None,
            'exact_match_ioc': {
                'id': exact_match.id,
                'type': exact_match.type,
                'value': exact_match.value,
                'threat_level': exact_match.threat_level,
                'created_at': exact_match.created_at.isoformat() if exact_match.created_at else None
            } if exact_match else None,
            'overlaps': overlaps,
            'has_issues': exact_match is not None or len(overlaps) > 0
        })
        
    except Exception as e:
        logger.error(f"Error checking duplicate IOC: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


def _has_word_boundary(haystack, needle):
    """
    Check if needle exists in haystack with word boundaries or path separators
    This helps avoid false positives like 'powershell' in long commands
    """
    import re
    # Check for word boundaries, path separators, or special characters around the match
    pattern = r'(?:^|[\s\\/\-_.,;:()\[\]{}]){needle}(?:$|[\s\\/\-_.,;:()\[\]{}])'.format(
        needle=re.escape(needle)
    )
    return re.search(pattern, haystack, re.IGNORECASE) is not None


@ioc_bp.route('/api/create', methods=['POST'])
@login_required
def api_create():
    """
    Create a new IOC
    
    Required fields:
    - type: IOC type (ipv4, domain, md5, etc.)
    - value: IOC value
    - category: Category (network, file, host, etc.)
    
    Optional fields:
    - threat_level: Threat level (default: info)
    - confidence: Confidence level 0-100
    - description: Description text
    - analyst_notes: Analyst notes
    - source: Source of IOC (default: manual)
    - source_reference: Reference URL/identifier
    """
    try:
        # Check if user has permission to create IOCs
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
        required_fields = ['type', 'value', 'category']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'success': False, 'error': f'Missing required field: {field}'}), 400
        
        # Create new IOC
        ioc = IOC(
            type=data['type'],
            value=data['value'].strip(),
            category=data['category'],
            threat_level=data.get('threat_level', 'info'),
            confidence=data.get('confidence'),
            description=data.get('description', '').strip() if data.get('description') else None,
            analyst_notes=data.get('analyst_notes', '').strip() if data.get('analyst_notes') else None,
            source=data.get('source', 'manual'),
            source_reference=data.get('source_reference', '').strip() if data.get('source_reference') else None,
            case_id=case_id,
            created_by=current_user.id,
            updated_by=current_user.id
        )
        
        # Add to database
        db.session.add(ioc)
        db.session.commit()
        
        # Build detailed IOC information for audit log
        ioc_details = {
            'type': ioc.type,
            'value': ioc.value,
            'category': ioc.category,
            'threat_level': ioc.threat_level,
            'confidence': ioc.confidence,
            'source': ioc.source,
            'source_reference': ioc.source_reference,
            'description': ioc.description,
            'analyst_notes': ioc.analyst_notes
        }
        
        # Log the action with detailed information
        log_action(
            action='ioc_created_manual',
            resource_type='case',
            resource_id=case.id,
            resource_name=case.name,
            details=f'Manually created IOC: {ioc_details}'
        )
        
        return jsonify({
            'success': True,
            'message': 'IOC created successfully',
            'ioc': {
                'id': ioc.id,
                'type': ioc.type,
                'value': ioc.value,
                'category': ioc.category,
                'threat_level': ioc.threat_level
            }
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating IOC: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@ioc_bp.route('/api/update/<int:ioc_id>', methods=['PUT'])
@login_required
def api_update(ioc_id):
    """
    Update an existing IOC
    
    Requires analyst or higher permissions
    Logs all changes to audit log
    """
    try:
        # Check permissions
        if current_user.role == 'read-only':
            return jsonify({'success': False, 'error': 'Insufficient permissions'}), 403
        
        # Get IOC
        ioc = IOC.query.get(ioc_id)
        if not ioc:
            return jsonify({'success': False, 'error': 'IOC not found'}), 404
        
        # Get case for logging
        case = Case.query.get(ioc.case_id)
        
        # Get form data
        data = request.get_json()
        
        # Store original values for audit log
        original_values = {
            'type': ioc.type,
            'value': ioc.value,
            'category': ioc.category,
            'threat_level': ioc.threat_level,
            'confidence': ioc.confidence,
            'description': ioc.description,
            'analyst_notes': ioc.analyst_notes,
            'source': ioc.source,
            'source_reference': ioc.source_reference,
            'is_active': ioc.is_active,
            'is_whitelisted': ioc.is_whitelisted,
            'is_hidden': ioc.is_hidden
        }
        
        # Track what changed
        changes = {}
        
        # Update fields if provided
        updateable_fields = [
            'type', 'value', 'category', 'threat_level', 'confidence',
            'description', 'analyst_notes', 'source', 'source_reference',
            'is_active', 'is_whitelisted', 'is_hidden'
        ]
        
        for field in updateable_fields:
            if field in data:
                new_value = data[field]
                # Strip strings
                if isinstance(new_value, str):
                    new_value = new_value.strip() if new_value else None
                
                # Check if value changed
                old_value = getattr(ioc, field)
                if old_value != new_value:
                    changes[field] = {
                        'old': old_value,
                        'new': new_value
                    }
                    setattr(ioc, field, new_value)
        
        # Update modified info
        ioc.updated_by = current_user.id
        
        db.session.commit()
        
        # Log the action with detailed changes
        log_action(
            action='ioc_updated',
            resource_type='ioc',
            resource_id=ioc.id,
            resource_name=f'{ioc.type}:{ioc.value}',
            details=f'Updated IOC in case {case.name if case else "Unknown"}. Changes: {changes}'
        )
        
        return jsonify({
            'success': True,
            'message': 'IOC updated successfully',
            'ioc': {
                'id': ioc.id,
                'type': ioc.type,
                'value': ioc.value,
                'category': ioc.category,
                'threat_level': ioc.threat_level
            }
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating IOC {ioc_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@ioc_bp.route('/api/delete/<int:ioc_id>', methods=['DELETE'])
@login_required
def api_delete(ioc_id):
    """
    Delete an IOC
    
    Requires security+ permissions (analyst or administrator)
    Logs deletion to audit log
    """
    try:
        # Check permissions - must be analyst or administrator
        if current_user.role not in ['analyst', 'administrator']:
            return jsonify({'success': False, 'error': 'Insufficient permissions - requires analyst or administrator role'}), 403
        
        # Get IOC
        ioc = IOC.query.get(ioc_id)
        if not ioc:
            return jsonify({'success': False, 'error': 'IOC not found'}), 404
        
        # Get case for logging
        case = Case.query.get(ioc.case_id)
        
        # Store IOC details for audit log before deletion
        ioc_details = {
            'id': ioc.id,
            'type': ioc.type,
            'value': ioc.value,
            'category': ioc.category,
            'threat_level': ioc.threat_level,
            'confidence': ioc.confidence,
            'description': ioc.description,
            'analyst_notes': ioc.analyst_notes,
            'source': ioc.source
        }
        
        # Delete the IOC
        db.session.delete(ioc)
        db.session.commit()
        
        # Log the action
        log_action(
            action='ioc_deleted',
            resource_type='ioc',
            resource_id=ioc_id,
            resource_name=f'{ioc_details["type"]}:{ioc_details["value"]}',
            details=f'Deleted IOC from case {case.name if case else "Unknown"}. IOC details: {ioc_details}'
        )
        
        return jsonify({
            'success': True,
            'message': 'IOC deleted successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting IOC {ioc_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@ioc_bp.route('/api/bulk_update', methods=['POST'])
@login_required
def api_bulk_update():
    """
    Bulk update multiple IOCs
    
    Requires analyst or higher permissions
    Logs all changes to audit log
    """
    try:
        # Check permissions
        if current_user.role == 'read-only':
            return jsonify({'success': False, 'error': 'Insufficient permissions'}), 403
        
        data = request.get_json()
        ioc_ids = data.get('ioc_ids', [])
        updates = data.get('updates', {})
        
        if not ioc_ids:
            return jsonify({'success': False, 'error': 'No IOCs selected'}), 400
        
        if not updates:
            return jsonify({'success': False, 'error': 'No updates specified'}), 400
        
        # Get all IOCs
        iocs = IOC.query.filter(IOC.id.in_(ioc_ids)).all()
        
        if not iocs:
            return jsonify({'success': False, 'error': 'No IOCs found'}), 404
        
        # Get case for logging (assuming all IOCs are from same case)
        case = Case.query.get(iocs[0].case_id) if iocs else None
        
        # Track changes for each IOC
        all_changes = []
        
        # Update each IOC
        for ioc in iocs:
            ioc_changes = {
                'ioc_id': ioc.id,
                'ioc_value': f'{ioc.type}:{ioc.value}',
                'changes': {}
            }
            
            # Apply updates
            for field, new_value in updates.items():
                if hasattr(ioc, field):
                    old_value = getattr(ioc, field)
                    
                    # Strip strings
                    if isinstance(new_value, str):
                        new_value = new_value.strip() if new_value else None
                    
                    if old_value != new_value:
                        ioc_changes['changes'][field] = {
                            'old': old_value,
                            'new': new_value
                        }
                        setattr(ioc, field, new_value)
            
            ioc.updated_by = current_user.id
            
            if ioc_changes['changes']:
                all_changes.append(ioc_changes)
        
        db.session.commit()
        
        # Log the action
        log_action(
            action='iocs_bulk_updated',
            resource_type='case',
            resource_id=case.id if case else None,
            resource_name=case.name if case else 'Multiple Cases',
            details=f'Bulk updated {len(iocs)} IOCs. Changes: {all_changes}'
        )
        
        return jsonify({
            'success': True,
            'message': f'Successfully updated {len(iocs)} IOCs',
            'updated_count': len(iocs)
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error bulk updating IOCs: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@ioc_bp.route('/api/bulk_delete', methods=['POST'])
@login_required
def api_bulk_delete():
    """
    Bulk delete multiple IOCs
    
    Requires security+ permissions (analyst or administrator)
    Logs all deletions to audit log
    """
    try:
        # Check permissions - must be analyst or administrator
        if current_user.role not in ['analyst', 'administrator']:
            return jsonify({'success': False, 'error': 'Insufficient permissions - requires analyst or administrator role'}), 403
        
        data = request.get_json()
        ioc_ids = data.get('ioc_ids', [])
        
        if not ioc_ids:
            return jsonify({'success': False, 'error': 'No IOCs selected'}), 400
        
        # Get all IOCs
        iocs = IOC.query.filter(IOC.id.in_(ioc_ids)).all()
        
        if not iocs:
            return jsonify({'success': False, 'error': 'No IOCs found'}), 404
        
        # Get case for logging (assuming all IOCs are from same case)
        case = Case.query.get(iocs[0].case_id) if iocs else None
        
        # Store IOC details for audit log
        deleted_iocs = []
        for ioc in iocs:
            deleted_iocs.append({
                'id': ioc.id,
                'type': ioc.type,
                'value': ioc.value,
                'category': ioc.category,
                'threat_level': ioc.threat_level
            })
            db.session.delete(ioc)
        
        db.session.commit()
        
        # Log the action
        log_action(
            action='iocs_bulk_deleted',
            resource_type='case',
            resource_id=case.id if case else None,
            resource_name=case.name if case else 'Multiple Cases',
            details=f'Bulk deleted {len(iocs)} IOCs. IOCs: {deleted_iocs}'
        )
        
        return jsonify({
            'success': True,
            'message': f'Successfully deleted {len(iocs)} IOCs',
            'deleted_count': len(iocs)
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error bulk deleting IOCs: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@ioc_bp.route('/api/export_csv')
@login_required
def api_export_csv():
    """
    Export IOCs to CSV file
    
    Query Parameters:
    - Same filters as /api/list (search, visibility, type, category, threat_level, case_id)
    """
    try:
        # Get query parameters (same as list endpoint)
        search_query = request.args.get('search', '').strip()
        visibility = request.args.get('visibility', 'hide_hidden')
        ioc_type = request.args.get('type', '')
        category = request.args.get('category', '')
        threat_level = request.args.get('threat_level', '')
        
        # Get case ID from query or session
        case_id = request.args.get('case_id')
        if not case_id:
            case_id = session.get('selected_case_id')
        
        # Build query
        query = IOC.query
        
        # Filter by case if specified
        if case_id:
            query = query.filter(IOC.case_id == case_id)
        
        # Apply visibility filter
        if visibility == 'hidden_only':
            query = query.filter(IOC.is_hidden == True)
        elif visibility == 'hide_hidden':
            query = query.filter(IOC.is_hidden == False)
        
        # Apply search filter
        if search_query:
            search_filter = db.or_(
                IOC.value.ilike(f'%{search_query}%'),
                IOC.description.ilike(f'%{search_query}%'),
                IOC.analyst_notes.ilike(f'%{search_query}%')
            )
            query = query.filter(search_filter)
        
        # Apply type filter
        if ioc_type:
            query = query.filter(IOC.type == ioc_type)
        
        # Apply category filter
        if category:
            query = query.filter(IOC.category == category)
        
        # Apply threat level filter
        if threat_level:
            query = query.filter(IOC.threat_level == threat_level)
        
        # Order by most recent first
        query = query.order_by(IOC.last_seen.desc())
        
        # Get all IOCs (no pagination for export)
        iocs = query.all()
        
        # Create CSV in memory
        output = StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'ID', 'Type', 'Value', 'Category', 'Threat Level', 'Confidence',
            'Is Active', 'Is Whitelisted', 'Is Hidden', 'First Seen', 'Last Seen',
            'Times Seen', 'Source', 'Source Reference', 'Description', 'Analyst Notes',
            'Case ID', 'Created At', 'Updated At'
        ])
        
        # Write data
        for ioc in iocs:
            writer.writerow([
                ioc.id,
                ioc.type,
                ioc.value,
                ioc.category,
                ioc.threat_level,
                ioc.confidence,
                ioc.is_active,
                ioc.is_whitelisted,
                ioc.is_hidden,
                ioc.first_seen.isoformat() if ioc.first_seen else '',
                ioc.last_seen.isoformat() if ioc.last_seen else '',
                ioc.times_seen,
                ioc.source,
                ioc.source_reference or '',
                ioc.description or '',
                ioc.analyst_notes or '',
                ioc.case_id,
                ioc.created_at.isoformat() if ioc.created_at else '',
                ioc.updated_at.isoformat() if ioc.updated_at else ''
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
                'Content-Disposition': f'attachment; filename=iocs_{case_name}.csv'
            }
        )
        
        # Log the export
        log_action(
            action='iocs_exported',
            resource_type='case',
            resource_id=case_id,
            resource_name=case_name,
            details=f'Exported {len(iocs)} IOCs to CSV'
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Error exporting IOCs to CSV: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@ioc_bp.route('/api/find_duplicates')
@login_required
def api_find_duplicates():
    """
    Find duplicate IOCs that can be merged
    
    Returns groups of duplicates with root IOC and potential merges
    """
    try:
        # Get case ID from session
        case_id = session.get('selected_case_id')
        if not case_id:
            return jsonify({'success': False, 'error': 'No case selected'}), 400
        
        # Get all IOCs for this case
        iocs = IOC.query.filter(IOC.case_id == case_id, IOC.is_hidden == False).all()
        
        # Group IOCs by normalized value
        value_groups = {}
        for ioc in iocs:
            value_lower = ioc.value.lower().strip()
            
            if value_lower not in value_groups:
                value_groups[value_lower] = []
            value_groups[value_lower].append(ioc)
        
        # Find groups with duplicates
        duplicate_groups = []
        type_priority = {
            'filepath': 5,
            'command_line': 4,
            'process_name': 3,
            'filename': 2,
            'username': 1
        }
        
        for value_lower, group in value_groups.items():
            if len(group) > 1:
                # Sort by type priority (highest first), then by ID (oldest first)
                sorted_group = sorted(group, key=lambda x: (
                    -type_priority.get(x.type, 0),  # Higher priority first
                    x.id  # Older IOCs first
                ))
                
                root_ioc = sorted_group[0]
                duplicates = sorted_group[1:]
                
                duplicate_groups.append({
                    'root': {
                        'id': root_ioc.id,
                        'type': root_ioc.type,
                        'value': root_ioc.value,
                        'category': root_ioc.category,
                        'threat_level': root_ioc.threat_level,
                        'confidence': root_ioc.confidence,
                        'description': root_ioc.description,
                        'analyst_notes': root_ioc.analyst_notes,
                        'times_seen': root_ioc.times_seen,
                        'first_seen': root_ioc.first_seen.isoformat() if root_ioc.first_seen else None
                    },
                    'duplicates': [{
                        'id': dup.id,
                        'type': dup.type,
                        'value': dup.value,
                        'category': dup.category,
                        'threat_level': dup.threat_level,
                        'confidence': dup.confidence,
                        'description': dup.description,
                        'analyst_notes': dup.analyst_notes,
                        'times_seen': dup.times_seen,
                        'first_seen': dup.first_seen.isoformat() if dup.first_seen else None
                    } for dup in duplicates]
                })
        
        return jsonify({
            'success': True,
            'duplicate_groups': duplicate_groups
        })
        
    except Exception as e:
        logger.error(f"Error finding duplicate IOCs: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@ioc_bp.route('/api/merge_duplicates', methods=['POST'])
@login_required
def api_merge_duplicates():
    """
    Merge duplicate IOCs into root IOCs
    
    Requires analyst or higher permissions
    Logs detailed before/after states to audit log
    """
    try:
        # Check permissions
        if current_user.role == 'read-only':
            return jsonify({'success': False, 'error': 'Insufficient permissions'}), 403
        
        data = request.get_json()
        merges = data.get('merges', [])
        
        if not merges:
            return jsonify({'success': False, 'error': 'No merges specified'}), 400
        
        merged_count = 0
        audit_details = []
        
        for merge in merges:
            root_id = merge.get('root_id')
            duplicate_ids = merge.get('duplicate_ids', [])
            
            if not root_id or not duplicate_ids:
                continue
            
            # Get root IOC
            root_ioc = IOC.query.get(root_id)
            if not root_ioc:
                continue
            
            # Capture original state of root IOC
            original_root_state = {
                'id': root_ioc.id,
                'type': root_ioc.type,
                'value': root_ioc.value,
                'category': root_ioc.category,
                'threat_level': root_ioc.threat_level,
                'confidence': root_ioc.confidence,
                'times_seen': root_ioc.times_seen,
                'description': root_ioc.description,
                'analyst_notes': root_ioc.analyst_notes
            }
            
            merged_duplicates = []
            
            # Process each duplicate
            for dup_id in duplicate_ids:
                dup_ioc = IOC.query.get(dup_id)
                if not dup_ioc:
                    continue
                
                # Capture duplicate state before deletion
                duplicate_state = {
                    'id': dup_ioc.id,
                    'type': dup_ioc.type,
                    'value': dup_ioc.value,
                    'category': dup_ioc.category,
                    'threat_level': dup_ioc.threat_level,
                    'confidence': dup_ioc.confidence,
                    'times_seen': dup_ioc.times_seen,
                    'description': dup_ioc.description,
                    'analyst_notes': dup_ioc.analyst_notes
                }
                merged_duplicates.append(duplicate_state)
                
                # Merge information into root IOC
                merge_notes = []
                
                # Add type if different
                if dup_ioc.type != root_ioc.type:
                    merge_notes.append(f"Also seen as {dup_ioc.type}")
                
                # Add description if different and exists
                if dup_ioc.description and dup_ioc.description != root_ioc.description:
                    merge_notes.append(f"Description: {dup_ioc.description}")
                
                # Add analyst notes if exists
                if dup_ioc.analyst_notes:
                    merge_notes.append(f"Notes: {dup_ioc.analyst_notes}")
                
                # Merge into root IOC's analyst notes
                if merge_notes:
                    merge_text = f"\n[Merged from IOC #{dup_ioc.id}] " + "; ".join(merge_notes)
                    if root_ioc.analyst_notes:
                        root_ioc.analyst_notes += merge_text
                    else:
                        root_ioc.analyst_notes = merge_text.strip()
                
                # Update times seen
                if dup_ioc.times_seen:
                    root_ioc.times_seen = (root_ioc.times_seen or 0) + dup_ioc.times_seen
                
                # Update confidence (use highest)
                if dup_ioc.confidence and (not root_ioc.confidence or dup_ioc.confidence > root_ioc.confidence):
                    root_ioc.confidence = dup_ioc.confidence
                
                # Update threat level (use highest)
                threat_order = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
                if threat_order.get(dup_ioc.threat_level, 0) > threat_order.get(root_ioc.threat_level, 0):
                    root_ioc.threat_level = dup_ioc.threat_level
                
                # Delete the duplicate
                db.session.delete(dup_ioc)
                merged_count += 1
            
            root_ioc.updated_by = current_user.id
            
            # Capture adjusted state of root IOC
            adjusted_root_state = {
                'id': root_ioc.id,
                'type': root_ioc.type,
                'value': root_ioc.value,
                'category': root_ioc.category,
                'threat_level': root_ioc.threat_level,
                'confidence': root_ioc.confidence,
                'times_seen': root_ioc.times_seen,
                'description': root_ioc.description,
                'analyst_notes': root_ioc.analyst_notes
            }
            
            # Track changes for audit
            audit_details.append({
                'root_ioc': {
                    'id': root_ioc.id,
                    'value': root_ioc.value,
                    'original_state': original_root_state,
                    'adjusted_state': adjusted_root_state,
                    'changes': {
                        'threat_level': {
                            'old': original_root_state['threat_level'],
                            'new': adjusted_root_state['threat_level']
                        } if original_root_state['threat_level'] != adjusted_root_state['threat_level'] else None,
                        'confidence': {
                            'old': original_root_state['confidence'],
                            'new': adjusted_root_state['confidence']
                        } if original_root_state['confidence'] != adjusted_root_state['confidence'] else None,
                        'times_seen': {
                            'old': original_root_state['times_seen'],
                            'new': adjusted_root_state['times_seen']
                        } if original_root_state['times_seen'] != adjusted_root_state['times_seen'] else None,
                        'analyst_notes_added': len(adjusted_root_state.get('analyst_notes', '') or '') - len(original_root_state.get('analyst_notes', '') or '')
                    }
                },
                'merged_duplicates': merged_duplicates,
                'duplicates_deleted_count': len(merged_duplicates)
            })
        
        db.session.commit()
        
        # Get case for logging
        case_id = session.get('selected_case_id')
        case = Case.query.get(case_id) if case_id else None
        
        # Log detailed action
        log_action(
            action='iocs_manually_deduplicated',
            resource_type='case',
            resource_id=case.id if case else None,
            resource_name=case.name if case else 'Unknown',
            details=f'Manually deduplicated {merged_count} IOCs into {len(audit_details)} root IOCs. Details: {audit_details}'
        )
        
        return jsonify({
            'success': True,
            'merged_count': merged_count
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error merging duplicate IOCs: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500



