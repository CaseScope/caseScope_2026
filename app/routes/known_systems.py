"""
Known Systems Management Routes
Track systems/devices involved in investigations
"""

from flask import Blueprint, render_template, jsonify, request, session, Response
from flask_login import login_required, current_user
from main import db
from models import KnownSystem, Case
from audit_logger import log_action
import logging
import csv
from io import StringIO
from celery.result import AsyncResult

logger = logging.getLogger(__name__)

known_systems_bp = Blueprint('known_systems', __name__, url_prefix='/systems')


@known_systems_bp.route('/')
@known_systems_bp.route('/manage')
@login_required
def manage():
    """
    Known Systems management page
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
    
    return render_template('systems/manage.html', case=case)


@known_systems_bp.route('/api/list')
@login_required
def api_list():
    """
    API endpoint to list known systems with pagination, search, and filtering
    
    Query Parameters:
    - page: Page number (default: 1)
    - per_page: Results per page (default: 50, max: 100)
    - search: Search query (searches hostname, domain_name, ip_address)
    - system_type: Filter by system type
    - compromised: Filter by compromised status
    - source: Filter by source
    - case_id: Filter by case (optional, defaults to session case)
    """
    try:
        # Get query parameters
        page = max(1, int(request.args.get('page', 1)))
        per_page = min(100, max(1, int(request.args.get('per_page', 50))))
        search_query = request.args.get('search', '').strip()
        system_type = request.args.get('system_type', '')
        compromised = request.args.get('compromised', '')
        source = request.args.get('source', '')
        
        # Get case ID from query or session
        case_id = request.args.get('case_id')
        if not case_id:
            case_id = session.get('selected_case_id')
        
        # Build query
        query = KnownSystem.query
        
        # Filter by case if specified
        if case_id:
            query = query.filter(KnownSystem.case_id == case_id)
        
        # Apply search filter
        if search_query:
            search_filter = db.or_(
                KnownSystem.hostname.ilike(f'%{search_query}%'),
                KnownSystem.domain_name.ilike(f'%{search_query}%'),
                KnownSystem.ip_address.ilike(f'%{search_query}%'),
                KnownSystem.description.ilike(f'%{search_query}%'),
                KnownSystem.analyst_notes.ilike(f'%{search_query}%')
            )
            query = query.filter(search_filter)
        
        # Apply system type filter
        if system_type:
            query = query.filter(KnownSystem.system_type == system_type)
        
        # Apply compromised filter
        if compromised:
            query = query.filter(KnownSystem.compromised == compromised)
        
        # Apply source filter
        if source:
            query = query.filter(KnownSystem.source == source)
        
        # Order by most recent first
        query = query.order_by(KnownSystem.created_at.desc())
        
        # Get total count
        total = query.count()
        
        # Paginate
        offset = (page - 1) * per_page
        systems = query.offset(offset).limit(per_page).all()
        
        # Format results
        results = []
        for system in systems:
            results.append({
                'id': system.id,
                'hostname': system.hostname,
                'domain_name': system.domain_name,
                'ip_address': system.ip_address,
                'compromised': system.compromised,
                'source': system.source,
                'system_type': system.system_type,
                'description': system.description,
                'analyst_notes': system.analyst_notes,
                'case_id': system.case_id,
                'created_at': system.created_at.isoformat() if system.created_at else None,
                'updated_at': system.updated_at.isoformat() if system.updated_at else None
            })
        
        return jsonify({
            'success': True,
            'systems': results,
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': (total + per_page - 1) // per_page
        })
        
    except Exception as e:
        logger.error(f"Error listing known systems: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@known_systems_bp.route('/api/get/<int:system_id>')
@login_required
def api_get(system_id):
    """
    Get details for a specific system
    """
    try:
        system = KnownSystem.query.get(system_id)
        
        if not system:
            return jsonify({'success': False, 'error': 'System not found'}), 404
        
        # Check permissions for read-only users
        if current_user.role == 'read-only':
            if system.case_id != current_user.case_assigned:
                return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        return jsonify({
            'success': True,
            'system': {
                'id': system.id,
                'hostname': system.hostname,
                'domain_name': system.domain_name,
                'ip_address': system.ip_address,
                'compromised': system.compromised,
                'source': system.source,
                'system_type': system.system_type,
                'description': system.description,
                'analyst_notes': system.analyst_notes,
                'case_id': system.case_id,
                'created_at': system.created_at.isoformat() if system.created_at else None,
                'updated_at': system.updated_at.isoformat() if system.updated_at else None
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting system {system_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@known_systems_bp.route('/api/stats')
@login_required
def api_stats():
    """
    Get statistics for known systems in the current case
    """
    try:
        case_id = session.get('selected_case_id')
        
        if not case_id:
            return jsonify({
                'success': True,
                'stats': {
                    'total': 0,
                    'by_type': {},
                    'by_compromised': {},
                    'by_source': {}
                }
            })
        
        # Build base query
        query = KnownSystem.query.filter(KnownSystem.case_id == case_id)
        
        # Total count
        total = query.count()
        
        # Count by system type
        by_type = {}
        types = db.session.query(KnownSystem.system_type, db.func.count(KnownSystem.id))\
            .filter(KnownSystem.case_id == case_id)\
            .group_by(KnownSystem.system_type).all()
        for sys_type, count in types:
            by_type[sys_type] = count
        
        # Count by compromised status
        by_compromised = {}
        compromised_stats = db.session.query(KnownSystem.compromised, db.func.count(KnownSystem.id))\
            .filter(KnownSystem.case_id == case_id)\
            .group_by(KnownSystem.compromised).all()
        for status, count in compromised_stats:
            by_compromised[status] = count
        
        # Count by source
        by_source = {}
        sources = db.session.query(KnownSystem.source, db.func.count(KnownSystem.id))\
            .filter(KnownSystem.case_id == case_id)\
            .group_by(KnownSystem.source).all()
        for src, count in sources:
            by_source[src] = count
        
        return jsonify({
            'success': True,
            'stats': {
                'total': total,
                'by_type': by_type,
                'by_compromised': by_compromised,
                'by_source': by_source
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting system stats: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@known_systems_bp.route('/api/create', methods=['POST'])
@login_required
def api_create():
    """
    Create a new known system
    
    Required fields:
    - system_type: Type of system
    
    Optional fields:
    - hostname: System hostname
    - domain_name: Domain name
    - ip_address: IP address
    - compromised: Compromised status (default: unknown)
    - source: Source (default: manual)
    - description: Description text
    - analyst_notes: Analyst notes
    """
    try:
        # Check if user has permission to create systems
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
        if not data.get('system_type'):
            return jsonify({'success': False, 'error': 'Missing required field: system_type'}), 400
        
        # At least one identifier required
        if not any([data.get('hostname'), data.get('domain_name'), data.get('ip_address')]):
            return jsonify({'success': False, 'error': 'At least one identifier required: hostname, domain_name, or ip_address'}), 400
        
        # Create new system
        system = KnownSystem(
            hostname=data.get('hostname', '').strip() if data.get('hostname') else None,
            domain_name=data.get('domain_name', '').strip() if data.get('domain_name') else None,
            ip_address=data.get('ip_address', '').strip() if data.get('ip_address') else None,
            system_type=data['system_type'],
            compromised=data.get('compromised', 'unknown'),
            source=data.get('source', 'manual'),
            description=data.get('description', '').strip() if data.get('description') else None,
            analyst_notes=data.get('analyst_notes', '').strip() if data.get('analyst_notes') else None,
            case_id=case_id,
            created_by=current_user.id,
            updated_by=current_user.id
        )
        
        # Add to database
        db.session.add(system)
        db.session.commit()
        
        # Build detailed system information for audit log
        system_details = {
            'hostname': system.hostname,
            'domain_name': system.domain_name,
            'ip_address': system.ip_address,
            'system_type': system.system_type,
            'compromised': system.compromised,
            'source': system.source
        }
        
        # Log the action
        log_action(
            action='system_created',
            resource_type='case',
            resource_id=case.id,
            resource_name=case.name,
            details={
                'performed_by': current_user.username,
                'creation_method': 'manual',
                'system_id': system.id,
                'system_details': system_details
            }
        )
        
        return jsonify({
            'success': True,
            'message': 'System created successfully',
            'system': {
                'id': system.id,
                'hostname': system.hostname,
                'ip_address': system.ip_address,
                'system_type': system.system_type
            }
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating system: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@known_systems_bp.route('/api/update/<int:system_id>', methods=['PUT'])
@login_required
def api_update(system_id):
    """
    Update an existing system
    
    Requires analyst or higher permissions
    Logs all changes to audit log
    """
    try:
        # Check permissions
        if current_user.role == 'read-only':
            return jsonify({'success': False, 'error': 'Insufficient permissions'}), 403
        
        # Get system
        system = KnownSystem.query.get(system_id)
        if not system:
            return jsonify({'success': False, 'error': 'System not found'}), 404
        
        # Get case for logging
        case = Case.query.get(system.case_id)
        
        # Get form data
        data = request.get_json()
        
        # Store original values for audit log
        original_values = {
            'hostname': system.hostname,
            'domain_name': system.domain_name,
            'ip_address': system.ip_address,
            'system_type': system.system_type,
            'compromised': system.compromised,
            'source': system.source,
            'description': system.description,
            'analyst_notes': system.analyst_notes
        }
        
        # Track what changed
        changes = {}
        
        # Update fields if provided
        updateable_fields = [
            'hostname', 'domain_name', 'ip_address', 'system_type',
            'compromised', 'source', 'description', 'analyst_notes'
        ]
        
        for field in updateable_fields:
            if field in data:
                new_value = data[field]
                # Strip strings
                if isinstance(new_value, str):
                    new_value = new_value.strip() if new_value else None
                
                # Check if value changed
                old_value = getattr(system, field)
                if old_value != new_value:
                    changes[field] = {
                        'old': old_value,
                        'new': new_value
                    }
                    setattr(system, field, new_value)
        
        # Update modified info
        system.updated_by = current_user.id
        
        db.session.commit()
        
        # Log the action with detailed changes
        log_action(
            action='system_updated',
            resource_type='known_system',
            resource_id=system.id,
            resource_name=system.hostname or system.ip_address or 'Unknown',
            details={
                'performed_by': current_user.username,
                'case_name': case.name if case else 'Unknown',
                'system_id': system.id,
                'original_state': original_values,
                'changes': changes
            }
        )
        
        return jsonify({
            'success': True,
            'message': 'System updated successfully',
            'system': {
                'id': system.id,
                'hostname': system.hostname,
                'ip_address': system.ip_address,
                'system_type': system.system_type
            }
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating system {system_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@known_systems_bp.route('/api/delete/<int:system_id>', methods=['DELETE'])
@login_required
def api_delete(system_id):
    """
    Delete a system
    
    Requires analyst or higher permissions
    Logs deletion to audit log
    """
    try:
        # Check permissions - must be analyst or administrator
        if current_user.role not in ['analyst', 'administrator']:
            return jsonify({'success': False, 'error': 'Insufficient permissions - requires analyst or administrator role'}), 403
        
        # Get system
        system = KnownSystem.query.get(system_id)
        if not system:
            return jsonify({'success': False, 'error': 'System not found'}), 404
        
        # Get case for logging
        case = Case.query.get(system.case_id)
        
        # Store system details for audit log before deletion
        system_details = {
            'id': system.id,
            'hostname': system.hostname,
            'domain_name': system.domain_name,
            'ip_address': system.ip_address,
            'system_type': system.system_type,
            'compromised': system.compromised
        }
        
        # Delete the system
        db.session.delete(system)
        db.session.commit()
        
        # Log the action
        log_action(
            action='system_deleted',
            resource_type='known_system',
            resource_id=system_id,
            resource_name=system_details.get('hostname') or system_details.get('ip_address') or 'Unknown',
            details={
                'performed_by': current_user.username,
                'case_name': case.name if case else 'Unknown',
                'deleted_system': system_details
            }
        )
        
        return jsonify({
            'success': True,
            'message': 'System deleted successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting system {system_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@known_systems_bp.route('/api/bulk_update', methods=['POST'])
@login_required
def api_bulk_update():
    """
    Bulk update multiple systems
    
    Requires analyst or higher permissions
    Logs all changes to audit log
    """
    try:
        # Check permissions
        if current_user.role == 'read-only':
            return jsonify({'success': False, 'error': 'Insufficient permissions'}), 403
        
        data = request.get_json()
        system_ids = data.get('system_ids', [])
        updates = data.get('updates', {})
        
        if not system_ids:
            return jsonify({'success': False, 'error': 'No systems selected'}), 400
        
        if not updates:
            return jsonify({'success': False, 'error': 'No updates specified'}), 400
        
        # Get all systems
        systems = KnownSystem.query.filter(KnownSystem.id.in_(system_ids)).all()
        
        if not systems:
            return jsonify({'success': False, 'error': 'No systems found'}), 404
        
        # Get case for logging (assuming all systems are from same case)
        case = Case.query.get(systems[0].case_id) if systems else None
        
        # Track changes for each system
        all_changes = []
        
        # Update each system
        for system in systems:
            system_changes = {
                'system_id': system.id,
                'system_name': system.hostname or system.ip_address,
                'changes': {}
            }
            
            # Apply updates
            for field, new_value in updates.items():
                if hasattr(system, field):
                    old_value = getattr(system, field)
                    
                    # Strip strings
                    if isinstance(new_value, str):
                        new_value = new_value.strip() if new_value else None
                    
                    if old_value != new_value:
                        system_changes['changes'][field] = {
                            'old': old_value,
                            'new': new_value
                        }
                        setattr(system, field, new_value)
            
            system.updated_by = current_user.id
            
            if system_changes['changes']:
                all_changes.append(system_changes)
        
        db.session.commit()
        
        # Log the action
        log_action(
            action='systems_bulk_updated',
            resource_type='case',
            resource_id=case.id if case else None,
            resource_name=case.name if case else 'Multiple Cases',
            details={
                'performed_by': current_user.username,
                'systems_count': len(systems),
                'updates_applied': updates,
                'systems_changed': all_changes
            }
        )
        
        return jsonify({
            'success': True,
            'message': f'Successfully updated {len(systems)} systems',
            'updated_count': len(systems)
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error bulk updating systems: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@known_systems_bp.route('/api/bulk_delete', methods=['POST'])
@login_required
def api_bulk_delete():
    """
    Bulk delete multiple systems
    
    Requires analyst or higher permissions
    Logs all deletions to audit log
    """
    try:
        # Check permissions - must be analyst or administrator
        if current_user.role not in ['analyst', 'administrator']:
            return jsonify({'success': False, 'error': 'Insufficient permissions - requires analyst or administrator role'}), 403
        
        data = request.get_json()
        system_ids = data.get('system_ids', [])
        
        if not system_ids:
            return jsonify({'success': False, 'error': 'No systems selected'}), 400
        
        # Get all systems
        systems = KnownSystem.query.filter(KnownSystem.id.in_(system_ids)).all()
        
        if not systems:
            return jsonify({'success': False, 'error': 'No systems found'}), 404
        
        # Get case for logging (assuming all systems are from same case)
        case = Case.query.get(systems[0].case_id) if systems else None
        
        # Store system details for audit log
        deleted_systems = []
        for system in systems:
            deleted_systems.append({
                'id': system.id,
                'hostname': system.hostname,
                'ip_address': system.ip_address,
                'system_type': system.system_type
            })
            db.session.delete(system)
        
        db.session.commit()
        
        # Log the action
        log_action(
            action='systems_bulk_deleted',
            resource_type='case',
            resource_id=case.id if case else None,
            resource_name=case.name if case else 'Multiple Cases',
            details={
                'performed_by': current_user.username,
                'systems_count': len(systems),
                'deleted_systems': deleted_systems
            }
        )
        
        return jsonify({
            'success': True,
            'message': f'Successfully deleted {len(systems)} systems',
            'deleted_count': len(systems)
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error bulk deleting systems: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@known_systems_bp.route('/api/import_csv', methods=['POST'])
@login_required
def api_import_csv():
    """
    Import systems from CSV file
    
    CSV Format (no header):
    name,domain,ip,compromised
    
    - name: Hostname (required)
    - domain: Domain name (use , for none)
    - ip: IP address (use , for none)
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
            hostname = row[0].strip() if row[0].strip() else None
            domain = row[1].strip() if row[1].strip() else '-'
            ip_address = row[2].strip() if row[2].strip() else '-'
            compromised_str = row[3].strip().lower() if row[3].strip() else 'unknown'
            
            # Validate required fields
            if not hostname:
                error_count += 1
                errors.append(f"Line {line_num}: Hostname is required")
                continue
            
            # Parse compromised value
            if compromised_str in ['true', 'yes', '1']:
                compromised = 'yes'
            elif compromised_str in ['false', 'no', '0']:
                compromised = 'no'
            else:
                compromised = 'unknown'
            
            try:
                # Check if system already exists
                existing = KnownSystem.query.filter(
                    KnownSystem.case_id == case_id,
                    db.func.upper(KnownSystem.hostname) == hostname.upper()
                ).first()
                
                if existing:
                    # Update existing system
                    if domain != '-':
                        existing.domain_name = domain
                    if ip_address != '-':
                        existing.ip_address = ip_address
                    existing.compromised = compromised
                    existing.updated_by = current_user.id
                    
                    note = f"Updated from CSV import"
                    if existing.analyst_notes:
                        existing.analyst_notes += f"\n{note}"
                    else:
                        existing.analyst_notes = note
                    
                    updated_count += 1
                else:
                    # Create new system
                    new_system = KnownSystem(
                        hostname=hostname.upper(),
                        domain_name=domain,
                        ip_address=ip_address,
                        system_type='workstation',  # Default
                        compromised=compromised,
                        source='csv_import',
                        description='Imported from CSV',
                        analyst_notes='Imported from CSV file',
                        case_id=case_id,
                        created_by=current_user.id,
                        updated_by=current_user.id
                    )
                    db.session.add(new_system)
                    created_count += 1
                
            except Exception as e:
                error_count += 1
                errors.append(f"Line {line_num}: {str(e)}")
                logger.error(f"Error importing system from line {line_num}: {e}")
        
        # Commit all changes
        db.session.commit()
        
        # Log the import
        log_action(
            action='systems_imported_from_csv',
            resource_type='case',
            resource_id=case.id,
            resource_name=case.name,
            details={
                'performed_by': current_user.username,
                'created': created_count,
                'updated': updated_count,
                'errors': error_count,
                'total_lines': line_num
            }
        )
        
        result = {
            'success': True,
            'created': created_count,
            'updated': updated_count,
            'errors': error_count,
            'total': created_count + updated_count
        }
        
        if errors:
            result['error_details'] = errors[:10]  # Limit to first 10 errors
        
        return jsonify(result)
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error importing systems from CSV: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@known_systems_bp.route('/api/export_csv')
@login_required
def api_export_csv():
    """
    Export systems to CSV file
    
    Query Parameters:
    - Same filters as /api/list (search, system_type, compromised, source, case_id)
    """
    try:
        # Get query parameters (same as list endpoint)
        search_query = request.args.get('search', '').strip()
        system_type = request.args.get('system_type', '')
        compromised = request.args.get('compromised', '')
        source = request.args.get('source', '')
        
        # Get case ID from query or session
        case_id = request.args.get('case_id')
        if not case_id:
            case_id = session.get('selected_case_id')
        
        # Build query
        query = KnownSystem.query
        
        # Filter by case if specified
        if case_id:
            query = query.filter(KnownSystem.case_id == case_id)
        
        # Apply search filter
        if search_query:
            search_filter = db.or_(
                KnownSystem.hostname.ilike(f'%{search_query}%'),
                KnownSystem.domain_name.ilike(f'%{search_query}%'),
                KnownSystem.ip_address.ilike(f'%{search_query}%'),
                KnownSystem.description.ilike(f'%{search_query}%'),
                KnownSystem.analyst_notes.ilike(f'%{search_query}%')
            )
            query = query.filter(search_filter)
        
        # Apply filters
        if system_type:
            query = query.filter(KnownSystem.system_type == system_type)
        if compromised:
            query = query.filter(KnownSystem.compromised == compromised)
        if source:
            query = query.filter(KnownSystem.source == source)
        
        # Order by most recent first
        query = query.order_by(KnownSystem.created_at.desc())
        
        # Get all systems (no pagination for export)
        systems = query.all()
        
        # Create CSV in memory
        output = StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'ID', 'Hostname', 'Domain Name', 'IP Address', 'System Type',
            'Compromised', 'Source', 'Description', 'Analyst Notes',
            'Case ID', 'Created At', 'Updated At'
        ])
        
        # Write data
        for system in systems:
            writer.writerow([
                system.id,
                system.hostname or '',
                system.domain_name or '',
                system.ip_address or '',
                system.system_type,
                system.compromised,
                system.source,
                system.description or '',
                system.analyst_notes or '',
                system.case_id,
                system.created_at.isoformat() if system.created_at else '',
                system.updated_at.isoformat() if system.updated_at else ''
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
                'Content-Disposition': f'attachment; filename=known_systems_{case_name}.csv'
            }
        )
        
        # Log the export
        log_action(
            action='systems_exported',
            resource_type='case',
            resource_id=case_id,
            resource_name=case_name,
            details=f'Exported {len(systems)} systems to CSV'
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Error exporting systems to CSV: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@known_systems_bp.route('/api/discover_from_logs', methods=['POST'])
@login_required
def api_discover_from_logs():
    """
    Trigger system discovery from OpenSearch logs
    
    Requires analyst or higher permissions
    Starts a Celery task to scan events and create system entries
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
        
        # Import task
        from tasks.task_discover_systems import discover_systems_from_logs
        
        # Start Celery task
        task = discover_systems_from_logs.apply_async(args=[case_id, current_user.id])
        
        # Log the action
        log_action(
            action='system_discovery_started',
            resource_type='case',
            resource_id=case.id,
            resource_name=case.name,
            details=f'Started automatic system discovery from logs. Task ID: {task.id}'
        )
        
        return jsonify({
            'success': True,
            'task_id': task.id,
            'message': 'System discovery started'
        })
        
    except Exception as e:
        logger.error(f"Error starting system discovery: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@known_systems_bp.route('/api/discovery_status/<task_id>')
@login_required
def api_discovery_status(task_id):
    """
    Check status of system discovery task
    """
    try:
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
                'status': 'Task failed',
                'progress': 0,
                'error': str(task.info)
            }
        else:
            response = {
                'state': task.state,
                'status': 'Unknown state',
                'progress': 0
            }
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error checking discovery status: {e}")
        return jsonify({'error': str(e)}), 500

