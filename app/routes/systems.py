"""
System Management Routes
Handles system identification, categorization, and management
"""

from flask import Blueprint, render_template, request, redirect, url_for, jsonify, flash, Response
from flask_login import login_required, current_user
from datetime import datetime
import json
import logging
import re
import csv
import io

systems_bp = Blueprint('systems', __name__)
logger = logging.getLogger(__name__)


@systems_bp.route('/case/<int:case_id>/systems')
@login_required
def systems_management(case_id):
    """Systems Management page for a case with pagination and sorting"""
    from main import db
    from models import Case, System, SystemSettings
    from flask import request
    
    case = db.session.get(Case, case_id)
    if not case:
        flash('Case not found', 'error')
        return redirect(url_for('dashboard'))
    
    # Get pagination and sorting parameters
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 1000)  # Max 1000 per page
    sort_field = request.args.get('sort', 'system_name')
    sort_order = request.args.get('order', 'asc')
    
    # Build query
    query = System.query.filter_by(case_id=case_id)
    
    # Apply sorting
    if sort_field == 'system_name':
        if sort_order == 'asc':
            query = query.order_by(System.system_name.asc())
        else:
            query = query.order_by(System.system_name.desc())
    elif sort_field == 'system_type':
        if sort_order == 'asc':
            query = query.order_by(System.system_type.asc(), System.system_name.asc())
        else:
            query = query.order_by(System.system_type.desc(), System.system_name.asc())
    elif sort_field == 'created_at':
        if sort_order == 'asc':
            query = query.order_by(System.created_at.asc())
        else:
            query = query.order_by(System.created_at.desc())
    elif sort_field == 'added_by':
        if sort_order == 'asc':
            query = query.order_by(System.added_by.asc(), System.system_name.asc())
        else:
            query = query.order_by(System.added_by.desc(), System.system_name.asc())
    
    # Paginate
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    systems = pagination.items
    total_count = pagination.total
    total_pages = pagination.pages
    
    # Get system settings for integrations
    opencti_enabled = SystemSettings.query.filter_by(setting_key='opencti_enabled').first()
    dfir_iris_enabled = SystemSettings.query.filter_by(setting_key='dfir_iris_enabled').first()
    dfir_iris_auto_sync = SystemSettings.query.filter_by(setting_key='dfir_iris_auto_sync').first()
    
    # Get stats (all systems, not just current page)
    stats = {
        'servers': System.query.filter_by(case_id=case_id, system_type='server', hidden=False).count(),
        'workstations': System.query.filter_by(case_id=case_id, system_type='workstation', hidden=False).count(),
        'firewalls': System.query.filter_by(case_id=case_id, system_type='firewall', hidden=False).count(),
        'switches': System.query.filter_by(case_id=case_id, system_type='switch', hidden=False).count(),
        'printers': System.query.filter_by(case_id=case_id, system_type='printer', hidden=False).count(),
        'actor_systems': System.query.filter_by(case_id=case_id, system_type='actor_system', hidden=False).count(),
        'unknown': System.query.filter_by(case_id=case_id, system_type='unknown', hidden=False).count(),  # v1.43.3
        'total': System.query.filter_by(case_id=case_id, hidden=False).count(),
        'hidden': System.query.filter_by(case_id=case_id, hidden=True).count()
    }
    
    return render_template('systems_management.html',
                         case=case,
                         systems=systems,
                         stats=stats,
                         page=page,
                         per_page=per_page,
                         total_count=total_count,
                         total_pages=total_pages,
                         sort_field=sort_field,
                         sort_order=sort_order,
                         opencti_enabled=(opencti_enabled.setting_value == 'true' if opencti_enabled else False),
                         dfir_iris_enabled=(dfir_iris_enabled.setting_value == 'true' if dfir_iris_enabled else False),
                         dfir_iris_auto_sync=(dfir_iris_auto_sync.setting_value == 'true' if dfir_iris_auto_sync else False))


# System type categorization patterns
SYSTEM_TYPE_PATTERNS = {
    'server': [
        r'srv|server|dc\d+|ad\d+|sql|exchange|file|print|backup|web|app',
        r'dc-|ad-|fs-|ps-|ws-|db-|ex-|sql-'
    ],
    'firewall': [
        r'fw|firewall|fortigate|palo\s*alto|checkpoint|sonicwall|asa|juniper|vyos',
        r'fw-|ngfw-|ips-|utm-'
    ],
    'switch': [
        r'sw|switch|cisco|arista|nexus|catalyst|dell\s*switch',
        r'sw-|switch-|core-|dist-|access-'
    ],
    'printer': [
        r'print|printer|copier|mfp|hp\s*laser|ricoh|xerox|konica',
        r'pr-|print-|mfp-|copier-'
    ],
    'actor_system': [
        r'attacker|threat|actor|malicious|external|suspicious',
        r'unknown|unauth|rogue|badguy'
    ]
}


@systems_bp.route('/case/<int:case_id>/systems/list', methods=['GET'])
@login_required
def list_systems(case_id):
    """Get all systems for a case (optionally filtered by type)"""
    from main import db
    from models import Case, System
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    # Get optional type filter
    system_type = request.args.get('type', None)
    
    # Build query
    query = System.query.filter_by(case_id=case_id)
    
    # Filter by type if provided
    if system_type:
        query = query.filter_by(system_type=system_type)
    
    # Filter by visibility based on user role
    if current_user.role not in ['administrator', 'analyst']:
        query = query.filter_by(hidden=False)
    
    systems = query.order_by(System.created_at.desc()).all()
    
    systems_data = []
    for sys in systems:
        systems_data.append({
            'id': sys.id,
            'system_name': sys.system_name,
            'ip_address': sys.ip_address,
            'system_type': sys.system_type,
            'added_by': sys.added_by,
            'created_at': sys.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'hidden': sys.hidden
        })
    
    return jsonify({'success': True, 'systems': systems_data})


@systems_bp.route('/case/<int:case_id>/systems/stats', methods=['GET'])
@login_required
def get_systems_stats(case_id):
    """Get system statistics for dashboard"""
    from main import db
    from models import System
    
    # Count by type (exclude hidden)
    stats = {
        'servers': System.query.filter_by(case_id=case_id, system_type='server', hidden=False).count(),
        'workstations': System.query.filter_by(case_id=case_id, system_type='workstation', hidden=False).count(),
        'firewalls': System.query.filter_by(case_id=case_id, system_type='firewall', hidden=False).count(),
        'switches': System.query.filter_by(case_id=case_id, system_type='switch', hidden=False).count(),
        'printers': System.query.filter_by(case_id=case_id, system_type='printer', hidden=False).count(),
        'actor_systems': System.query.filter_by(case_id=case_id, system_type='actor_system', hidden=False).count(),
        'unknown': System.query.filter_by(case_id=case_id, system_type='unknown', hidden=False).count(),  # v1.43.3
        'total': System.query.filter_by(case_id=case_id, hidden=False).count()
    }
    
    return jsonify({'success': True, 'stats': stats})


@systems_bp.route('/case/<int:case_id>/systems/add', methods=['POST'])
@login_required
def add_system(case_id):
    """Manually add a system to the case"""
    if current_user.role == 'read-only':
        return jsonify({'success': False, 'error': 'Read-only users cannot add systems'}), 403
    
    from main import db
    from models import Case, System
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    try:
        system_name = request.form.get('system_name', '').strip()
        system_type = request.form.get('system_type', 'workstation')
        ip_address = request.form.get('ip_address', '').strip() or None
        
        if not system_name:
            return jsonify({'success': False, 'error': 'System name is required'}), 400
        
        # Check for duplicate
        existing = System.query.filter_by(case_id=case_id, system_name=system_name).first()
        if existing:
            return jsonify({'success': False, 'error': 'System already exists in this case'}), 400
        
        # Create system
        system = System(
            case_id=case_id,
            system_name=system_name,
            ip_address=ip_address,
            system_type=system_type,
            added_by=current_user.username,
            hidden=False
        )
        db.session.add(system)
        db.session.commit()
        
        # Audit log
        from audit_logger import log_action
        log_action('add_system', resource_type='system', resource_id=system.id,
                  resource_name=system_name,
                  details={
                      'case_id': case_id,
                      'case_name': case.name,
                      'system_type': system_type,
                      'ip_address': ip_address
                  })
        
        # Check for OpenCTI enrichment
        from models import SystemSettings
        opencti_enabled = SystemSettings.query.filter_by(setting_key='opencti_enabled').first()
        if opencti_enabled and opencti_enabled.setting_value == 'true':
            enrich_from_opencti(system)
        
        # Check for DFIR-IRIS auto sync
        dfir_iris_auto_sync = SystemSettings.query.filter_by(setting_key='dfir_iris_auto_sync').first()
        if dfir_iris_auto_sync and dfir_iris_auto_sync.setting_value == 'true':
            sync_to_dfir_iris(system)
        
        flash(f'System added: {system_name}', 'success')
        return jsonify({'success': True, 'system_id': system.id})
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"[Systems] Error adding system: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@systems_bp.route('/case/<int:case_id>/systems/<int:system_id>/get', methods=['GET'])
@login_required
def get_system(case_id, system_id):
    """Get system details for editing"""
    from main import db
    from models import System
    
    system = db.session.get(System, system_id)
    if not system or system.case_id != case_id:
        return jsonify({'success': False, 'error': 'System not found'}), 404
    
    return jsonify({
        'success': True,
        'system': {
            'id': system.id,
            'system_name': system.system_name,
            'system_type': system.system_type,
            'added_by': system.added_by,
            'hidden': system.hidden
        }
    })


@systems_bp.route('/case/<int:case_id>/systems/<int:system_id>/edit', methods=['POST'])
@login_required
def edit_system(case_id, system_id):
    """Edit system details"""
    if current_user.role == 'read-only':
        return jsonify({'success': False, 'error': 'Read-only users cannot edit systems'}), 403
    
    from main import db
    from models import System
    
    system = db.session.get(System, system_id)
    if not system or system.case_id != case_id:
        return jsonify({'success': False, 'error': 'System not found'}), 404
    
    try:
        old_name = system.system_name
        old_type = system.system_type
        old_ip = system.ip_address
        
        system.system_name = request.form.get('system_name', system.system_name).strip()
        system.ip_address = request.form.get('ip_address', '').strip() or None
        system.system_type = request.form.get('system_type', system.system_type)
        
        db.session.commit()
        
        # Audit log
        from audit_logger import log_action
        from main import Case
        case = db.session.get(Case, case_id)
        changes = {}
        if old_name != system.system_name:
            changes['system_name'] = {'old': old_name, 'new': system.system_name}
        if old_type != system.system_type:
            changes['system_type'] = {'old': old_type, 'new': system.system_type}
        if old_ip != system.ip_address:
            changes['ip_address'] = {'old': old_ip, 'new': system.ip_address}
        log_action('edit_system', resource_type='system', resource_id=system_id,
                  resource_name=system.system_name,
                  details={
                      'case_id': case_id,
                      'case_name': case.name if case else None,
                      'changes': changes
                  })
        
        flash(f'System updated: {system.system_name}', 'success')
        return jsonify({'success': True})
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"[Systems] Error editing system: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@systems_bp.route('/case/<int:case_id>/systems/<int:system_id>/delete', methods=['POST'])
@login_required
def delete_system(case_id, system_id):
    """Delete system (administrators only)"""
    if current_user.role != 'administrator':
        return jsonify({'success': False, 'error': 'Only administrators can delete systems'}), 403
    
    from main import db
    from models import System
    
    system = db.session.get(System, system_id)
    if not system or system.case_id != case_id:
        return jsonify({'success': False, 'error': 'System not found'}), 404
    
    try:
        system_name = system.system_name
        system_type = system.system_type
        from main import Case
        case = db.session.get(Case, case_id)
        
        db.session.delete(system)
        db.session.commit()
        
        # Audit log
        from audit_logger import log_action
        log_action('delete_system', resource_type='system', resource_id=system_id,
                  resource_name=system_name,
                  details={
                      'case_id': case_id,
                      'case_name': case.name if case else None,
                      'system_type': system_type
                  })
        
        flash(f'System deleted: {system_name}', 'success')
        return jsonify({'success': True})
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"[Systems] Error deleting system: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@systems_bp.route('/case/<int:case_id>/systems/<int:system_id>/toggle_hidden', methods=['POST'])
@login_required
def toggle_hidden(case_id, system_id):
    """Toggle system hidden status"""
    if current_user.role == 'read-only':
        return jsonify({'success': False, 'error': 'Read-only users cannot modify systems'}), 403
    
    from main import db
    from models import System
    
    system = db.session.get(System, system_id)
    if not system or system.case_id != case_id:
        return jsonify({'success': False, 'error': 'System not found'}), 404
    
    try:
        old_hidden = system.hidden
        system.hidden = not system.hidden
        db.session.commit()
        
        # Audit log
        from audit_logger import log_action
        from main import Case
        case = db.session.get(Case, case_id)
        log_action('toggle_system_hidden', resource_type='system', resource_id=system_id,
                  resource_name=system.system_name,
                  details={
                      'case_id': case_id,
                      'case_name': case.name if case else None,
                      'old_status': 'hidden' if old_hidden else 'visible',
                      'new_status': 'hidden' if system.hidden else 'visible'
                  })
        
        status = 'hidden' if system.hidden else 'visible'
        flash(f'System {status}: {system.system_name}', 'success')
        return jsonify({'success': True, 'hidden': system.hidden})
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"[Systems] Error toggling hidden status: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@systems_bp.route('/case/<int:case_id>/systems/<int:system_id>/event_count', methods=['GET'])
@login_required
def get_event_count(case_id, system_id):
    """Get count of events referencing this system"""
    from main import db, opensearch_client
    from models import System, CaseFile
    
    system = db.session.get(System, system_id)
    if not system or system.case_id != case_id:
        return jsonify({'success': False, 'error': 'System not found'}), 404
    
    try:
        # Get all index names for this case
        files = CaseFile.query.filter_by(case_id=case_id).all()
        index_names = [f.index_name for f in files if f.index_name]
        
        if not index_names:
            return jsonify({'success': True, 'count': 0})
        
        # Search for system name across all fields
        from opensearchpy import Search
        s = Search(using=opensearch_client, index=index_names)
        s = s.query("query_string", query=f'*{system.system_name}*', default_operator="AND")
        
        count = s.count()
        
        return jsonify({'success': True, 'count': count})
    
    except Exception as e:
        logger.error(f"[Systems] Error getting event count: {e}")
        return jsonify({'success': True, 'count': 0})


@systems_bp.route('/case/<int:case_id>/systems/scan', methods=['POST'])
@login_required
def scan_systems(case_id):
    """Scan case logs to discover systems"""
    if current_user.role == 'read-only':
        return jsonify({'success': False, 'error': 'Read-only users cannot scan systems'}), 403
    
    from main import db, opensearch_client
    from models import Case, CaseFile, System
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    try:
        # Check if there are indexed files for this case
        files = CaseFile.query.filter_by(case_id=case_id, is_indexed=True).all()
        
        if not files:
            return jsonify({'success': False, 'error': 'No indexed files found for this case'}), 400
        
        # Use consolidated index for case (v1.13.1+: 1 index per case)
        index_pattern = f"case_{case_id}"
        
        logger.info(f"[Systems] Starting system scan for case {case_id}, pattern: {index_pattern}")
        
        # Extract systems from common fields
        discovered_systems = {}
        
        # Fields to search for system names
        # v1.43.3: Added normalized_computer (primary hostname field for EVTX)
        system_fields = [
            'normalized_computer',  # Primary field - CaseScope's normalized hostname
            'Computer', 'ComputerName', 'Hostname', 'System', 'WorkstationName',
            'host.name', 'hostname', 'computer', 'computername', 'source_name',
            'SourceHostname', 'DestinationHostname', 'src_host', 'dst_host'
        ]
        
        from opensearchpy import Search
        
        for field in system_fields:
            try:
                s = Search(using=opensearch_client, index=index_pattern)
                s = s.filter('exists', field=field)
                s = s[:0]  # Don't return documents
                s.aggs.bucket('systems', 'terms', field=f'{field}.keyword', size=1000)
                
                response = s.execute()
                
                if response.aggregations and hasattr(response.aggregations, 'systems'):
                    for bucket in response.aggregations.systems.buckets:
                        system_name = bucket.key
                        doc_count = bucket.doc_count
                        
                        # Clean system name
                        system_name = system_name.strip()
                        if not system_name or system_name == '-' or len(system_name) < 2:
                            continue
                        
                        # Skip IPs, they're handled separately
                        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', system_name):
                            continue
                        
                        # v1.43.5: Strip FQDN to get just hostname (no duplicates)
                        # Examples: CM-DC01.cm.local -> CM-DC01, server.domain.com -> server
                        if '.' in system_name:
                            # Check if it looks like an FQDN (has domain suffix)
                            parts = system_name.split('.')
                            # If first part is a hostname and rest looks like domain
                            if len(parts) >= 2 and len(parts[0]) >= 2:
                                # Keep just the hostname part
                                hostname_only = parts[0].upper()
                                # Use the hostname (stripped) version
                                system_name = hostname_only
                        
                        # Normalize to uppercase for consistent matching
                        system_name = system_name.upper()
                        
                        # Track highest doc count per system
                        if system_name not in discovered_systems or doc_count > discovered_systems[system_name]['count']:
                            discovered_systems[system_name] = {
                                'name': system_name,
                                'count': doc_count,
                                'field': field
                            }
                            
                logger.debug(f"[Systems] Found {len(response.aggregations.systems.buckets)} systems in field '{field}'")
            
            except Exception as e:
                logger.warning(f"[Systems] Error scanning field '{field}': {e}")
                continue
        
        logger.info(f"[Systems] Discovered {len(discovered_systems)} unique systems")
        
        # Get IP addresses for discovered systems
        logger.info(f"[Systems] Resolving IP addresses for systems...")
        system_ips = {}
        
        # Query for IP addresses using normalized_computer and host.ip fields
        try:
            s = Search(using=opensearch_client, index=index_pattern)
            s = s.filter('exists', field='normalized_computer')
            s = s.filter('exists', field='host.ip')
            s = s[:0]  # Don't return documents
            
            # Aggregate by computer name, get most common IP (top_hits)
            s.aggs.bucket('by_computer', 'terms', field='normalized_computer.keyword', size=1000) \
                  .metric('top_ip', 'top_hits', size=1, _source=['host.ip'])
            
            response = s.execute()
            
            if response.aggregations and hasattr(response.aggregations, 'by_computer'):
                for bucket in response.aggregations.by_computer.buckets:
                    computer_name = bucket.key
                    
                    # v1.43.5: Normalize hostname (strip FQDN, uppercase)
                    if '.' in computer_name:
                        computer_name = computer_name.split('.')[0]
                    computer_name = computer_name.upper()
                    
                    if bucket.top_ip.hits.hits:
                        ip = bucket.top_ip.hits.hits[0]['_source'].get('host', {}).get('ip')
                        if ip:
                            # Only store if we don't have an IP for this host yet
                            if computer_name not in system_ips:
                                system_ips[computer_name] = ip
                                logger.debug(f"[Systems] {computer_name} -> {ip}")
            
            logger.info(f"[Systems] Resolved IPs for {len(system_ips)} systems")
        except Exception as e:
            logger.warning(f"[Systems] Could not resolve IPs: {e}")
        
        # Categorize and save systems
        new_systems = 0
        updated_systems = 0
        
        for sys_name, sys_data in discovered_systems.items():
            # Check if already exists
            existing = System.query.filter_by(case_id=case_id, system_name=sys_name).first()
            
            # Get IP address for this system
            ip_address = system_ips.get(sys_name)
            
            if not existing:
                # Categorize system type
                system_type = categorize_system(sys_name)
                
                system = System(
                    case_id=case_id,
                    system_name=sys_name,
                    ip_address=ip_address,
                    system_type=system_type,
                    added_by='CaseScope',
                    hidden=False
                )
                db.session.add(system)
                new_systems += 1
                
                logger.debug(f"[Systems] New system: {sys_name} (type: {system_type}, IP: {ip_address}, events: {sys_data['count']})")
            else:
                # Update IP address if we found one and it's not already set
                if ip_address and not existing.ip_address:
                    existing.ip_address = ip_address
                    logger.debug(f"[Systems] Updated IP for {sys_name}: {ip_address}")
                updated_systems += 1
        
        db.session.commit()
        
        # Audit log
        from audit_logger import log_action
        log_action('scan_systems', resource_type='system', resource_id=None,
                  resource_name=f'{new_systems} new, {updated_systems} updated',
                  details={
                      'case_id': case_id,
                      'case_name': case.name,
                      'new_systems': new_systems,
                      'updated_systems': updated_systems,
                      'total_discovered': len(discovered_systems)
                  })
        
        message = f"System scan complete: {new_systems} new systems found, {updated_systems} already existed"
        logger.info(f"[Systems] {message}")
        flash(message, 'success')
        
        return jsonify({
            'success': True,
            'new_systems': new_systems,
            'existing_systems': updated_systems,
            'total_discovered': len(discovered_systems)
        })
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"[Systems] Error scanning systems: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@systems_bp.route('/case/<int:case_id>/systems/<int:system_id>/enrich', methods=['POST'])
@login_required
def enrich_system(case_id, system_id):
    """Manually trigger OpenCTI enrichment for a system"""
    from main import db
    from models import System
    
    system = db.session.get(System, system_id)
    if not system or system.case_id != case_id:
        return jsonify({'success': False, 'error': 'System not found'}), 404
    
    try:
        # Audit log
        from audit_logger import log_action
        from main import Case
        case = db.session.get(Case, case_id)
        log_action('enrich_system', resource_type='system', resource_id=system_id,
                  resource_name=system.system_name,
                  details={
                      'case_id': case_id,
                      'case_name': case.name if case else None,
                      'source': 'OpenCTI'
                  })
        
        result = enrich_from_opencti(system)
        if result:
            flash(f'System enriched from OpenCTI: {system.system_name}', 'success')
            return jsonify({'success': True, 'enrichment': json.loads(system.opencti_enrichment) if system.opencti_enrichment else None})
        else:
            flash(f'OpenCTI enrichment not available', 'warning')
            return jsonify({'success': False, 'error': 'OpenCTI not configured or no data found'})
    
    except Exception as e:
        logger.error(f"[Systems] Error enriching system: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@systems_bp.route('/case/<int:case_id>/systems/<int:system_id>/sync', methods=['POST'])
@login_required
def sync_system_to_iris(case_id, system_id):
    """Manually trigger DFIR-IRIS sync for a system"""
    from main import db
    from models import System
    
    system = db.session.get(System, system_id)
    if not system or system.case_id != case_id:
        return jsonify({'success': False, 'error': 'System not found'}), 404
    
    try:
        # Audit log
        from audit_logger import log_action
        from main import Case
        case = db.session.get(Case, case_id)
        log_action('sync_system_to_iris', resource_type='system', resource_id=system_id,
                  resource_name=system.system_name,
                  details={
                      'case_id': case_id,
                      'case_name': case.name if case else None,
                      'destination': 'DFIR-IRIS'
                  })
        
        result = sync_to_dfir_iris(system)
        if result:
            flash(f'System synced to DFIR-IRIS: {system.system_name}', 'success')
            return jsonify({'success': True, 'iris_id': system.dfir_iris_asset_id})
        else:
            flash(f'DFIR-IRIS sync not available', 'warning')
            return jsonify({'success': False, 'error': 'DFIR-IRIS not configured'})
    
    except Exception as e:
        logger.error(f"[Systems] Error syncing system: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@systems_bp.route('/case/<int:case_id>/systems/sync_all', methods=['POST'])
@login_required
def bulk_sync_systems_to_iris(case_id):
    """Bulk sync all systems in a case to DFIR-IRIS"""
    from main import db
    from models import System, Case
    from flask import jsonify
    
    # Verify case exists
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    # Get all systems for this case (include hidden)
    systems = System.query.filter_by(case_id=case_id).all()
    
    if not systems:
        return jsonify({
            'success': True,
            'message': 'No systems to sync',
            'synced': 0,
            'failed': 0
        })
    
    synced = 0
    failed = 0
    errors = []
    
    for system in systems:
        try:
            result = sync_to_dfir_iris(system)
            if result:
                synced += 1
            else:
                failed += 1
                errors.append(f"Failed to sync {system.system_name}")
        except Exception as e:
            failed += 1
            errors.append(f"Error syncing {system.system_name}: {str(e)}")
            logger.error(f"[Systems] Error syncing system {system.id}: {e}")
    
    # Audit log
    from audit_logger import log_action
    log_action('bulk_sync_systems_to_iris', resource_type='case', resource_id=case_id,
              resource_name=case.name, details={
                  'total_systems': len(systems),
                  'synced': synced,
                  'failed': failed
              })
    
    if failed == 0:
        message = f'✓ Successfully synced {synced} system(s) to DFIR-IRIS'
        return jsonify({
            'success': True,
            'message': message,
            'synced': synced,
            'failed': failed
        })
    else:
        message = f'⚠️ Synced {synced} system(s), {failed} failed'
        return jsonify({
            'success': True,
            'message': message,
            'synced': synced,
            'failed': failed,
            'errors': errors[:5]  # Return first 5 errors
        })


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def categorize_system(system_name):
    """
    Categorize system based on naming patterns
    Returns: server, workstation, firewall, switch, printer, actor_system
    """
    system_name_lower = system_name.lower()
    
    # Check each type's patterns
    for sys_type, patterns in SYSTEM_TYPE_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, system_name_lower, re.IGNORECASE):
                return sys_type
    
    # Default to workstation
    return 'workstation'


def enrich_from_opencti(system):
    """
    Enrich system from OpenCTI threat intelligence
    """
    from main import db
    from models import SystemSettings
    
    # Check if OpenCTI is enabled
    opencti_enabled = SystemSettings.query.filter_by(setting_key='opencti_enabled').first()
    if not opencti_enabled or opencti_enabled.setting_value != 'true':
        logger.debug(f"[OpenCTI] Enrichment skipped - OpenCTI not enabled")
        return False
    
    # Get OpenCTI configuration
    opencti_url = SystemSettings.query.filter_by(setting_key='opencti_url').first()
    opencti_api_key = SystemSettings.query.filter_by(setting_key='opencti_api_key').first()
    
    if not opencti_url or not opencti_api_key:
        logger.warning(f"[OpenCTI] Enrichment failed - OpenCTI not configured")
        return False
    
    try:
        # Initialize OpenCTI client
        from opencti import OpenCTIClient
        client = OpenCTIClient(
            opencti_url.setting_value,
            opencti_api_key.setting_value
        )
        
        # Check system/hostname in OpenCTI
        enrichment = client.check_indicator(system.system_name, 'hostname')
        
        # Store enrichment data
        system.opencti_enrichment = json.dumps(enrichment)
        system.opencti_enriched_at = datetime.utcnow()
        db.session.commit()
        
        logger.info(f"[OpenCTI] System enriched: {system.system_name} (Found: {enrichment.get('found', False)})")
        
        return True
        
    except Exception as e:
        logger.error(f"[OpenCTI] Enrichment failed for {system.system_name}: {e}")
        return False


def sync_to_dfir_iris(system):
    """
    Sync system to DFIR-IRIS as an asset
    
    Maps CaseScope system types to DFIR-IRIS asset types:
    - firewall -> router
    - workstation -> Windows - Computer
    - server -> Windows - Server
    - switch -> switch
    - actor_system -> Windows - Computer (marked as Compromised)
    """
    from main import db
    from models import SystemSettings, Case
    from dfir_iris import DFIRIrisClient
    
    # Check if DFIR-IRIS is enabled
    dfir_iris_enabled = SystemSettings.query.filter_by(setting_key='dfir_iris_enabled').first()
    if not dfir_iris_enabled or dfir_iris_enabled.setting_value != 'true':
        logger.warning(f"[DFIR-IRIS] Cannot sync system {system.system_name}: DFIR-IRIS not enabled")
        return False
    
    # Get DFIR-IRIS configuration
    dfir_iris_url = SystemSettings.query.filter_by(setting_key='dfir_iris_url').first()
    dfir_iris_api_key = SystemSettings.query.filter_by(setting_key='dfir_iris_api_key').first()
    
    if not dfir_iris_url or not dfir_iris_api_key:
        logger.warning(f"[DFIR-IRIS] Cannot sync system {system.system_name}: Missing URL or API key")
        return False
    
    try:
        # Initialize DFIR-IRIS client
        client = DFIRIrisClient(dfir_iris_url.setting_value, dfir_iris_api_key.setting_value)
        
        # Get case information
        case = db.session.get(Case, system.case_id)
        if not case:
            logger.error(f"[DFIR-IRIS] Case {system.case_id} not found for system {system.system_name}")
            return False
        
        # Get or create customer (company)
        company_name = case.company or 'Unknown Company'
        customer_id = client.get_or_create_customer(company_name)
        if not customer_id:
            logger.error(f"[DFIR-IRIS] Failed to get/create customer for system {system.system_name}")
            return False
        
        # Get or create case in DFIR-IRIS
        iris_case_id = client.get_or_create_case(customer_id, case.name, case.description or '', company_name)
        if not iris_case_id:
            logger.error(f"[DFIR-IRIS] Failed to get/create case for system {system.system_name}")
            return False
        
        # Get available asset types from DFIR-IRIS
        asset_types = client.get_asset_types()
        if not asset_types:
            logger.error(f"[DFIR-IRIS] Failed to retrieve asset types")
            return False
        
        # Map CaseScope system type to DFIR-IRIS asset type
        asset_type_map = {
            'firewall': 'router',
            'workstation': 'windows - computer',
            'server': 'windows - server',
            'switch': 'switch',
            'actor_system': 'windows - computer',  # Actor systems are compromised computers
            'printer': 'other',
            'unknown': 'other'
        }
        
        target_asset_type = asset_type_map.get(system.system_type.lower(), 'other')
        asset_type_id = None
        
        # Find matching asset type in DFIR-IRIS
        for asset_type in asset_types:
            asset_name = asset_type.get('asset_name', '').lower()
            if target_asset_type in asset_name:
                asset_type_id = asset_type.get('asset_id')
                logger.info(f"[DFIR-IRIS] Matched system type '{system.system_type}' -> DFIR asset type '{asset_type.get('asset_name')}' (ID: {asset_type_id})")
                break
        
        if not asset_type_id:
            logger.warning(f"[DFIR-IRIS] Asset type '{target_asset_type}' not found, using first available")
            asset_type_id = asset_types[0].get('asset_id') if asset_types else 1
        
        # Check if asset already exists in DFIR-IRIS
        existing_assets = client.get_case_assets(iris_case_id)
        existing_asset = None
        
        for asset in existing_assets:
            # Match by name (case-insensitive) or by CaseScope ID in tags
            asset_name_match = asset.get('asset_name', '').lower() == system.system_name.lower()
            asset_tags = asset.get('asset_tags', '')
            casescope_id_match = f'casescope_system_id:{system.id}' in asset_tags
            
            if asset_name_match or casescope_id_match:
                existing_asset = asset
                logger.info(f"[DFIR-IRIS] Found existing asset: {system.system_name} (ID: {asset.get('asset_id')})")
                break
        
        # Prepare asset description
        asset_description = f"System from CaseScope\nType: {system.system_type}"
        if system.ip_address:
            asset_description += f"\nIP: {system.ip_address}"
        if system.added_by:
            asset_description += f"\nAdded by: {system.added_by}"
        
        # Special handling for actor_system - mark as compromised
        compromise_status_id = None
        if system.system_type.lower() == 'actor_system':
            # DFIR-IRIS uses "Compromise Status" dropdown with values like:
            # 1 = Not Applicable, 2 = Unknown, 3 = Clean, 4 = Suspected, 5 = Compromised
            # We'll use ID 5 for Compromised
            compromise_status_id = 5
            asset_description += "\n⚠️ COMPROMISED SYSTEM - Actor/attacker controlled"
        
        if existing_asset:
            # Update existing asset
            asset_id = existing_asset.get('asset_id')
            update_data = {
                'asset_name': system.system_name,
                'asset_type_id': asset_type_id,
                'asset_description': asset_description,
                'asset_tags': f'casescope,casescope_system_id:{system.id}',
                'cid': iris_case_id
            }
            
            # Add IP if available
            if system.ip_address:
                update_data['asset_ip'] = system.ip_address
            
            # Add compromise status for actor systems
            if compromise_status_id:
                update_data['compromise_status_id'] = compromise_status_id
            
            result = client._request('POST', f'/case/assets/update/{asset_id}', update_data)
            if result:
                logger.info(f"[DFIR-IRIS] Asset updated: {system.system_name} (ID: {asset_id})")
                system.dfir_iris_synced = True
                system.dfir_iris_sync_date = datetime.utcnow()
                system.dfir_iris_asset_id = str(asset_id)
                db.session.commit()
                return True
        else:
            # Create new asset
            create_data = {
                'asset_name': system.system_name,
                'asset_type_id': asset_type_id,
                'analysis_status_id': 1,  # 1 = Unspecified
                'asset_description': asset_description,
                'asset_tags': f'casescope,casescope_system_id:{system.id}',
                'cid': iris_case_id
            }
            
            # Add IP if available
            if system.ip_address:
                create_data['asset_ip'] = system.ip_address
            
            # Add compromise status for actor systems
            if compromise_status_id:
                create_data['compromise_status_id'] = compromise_status_id
            
            result = client._request('POST', '/case/assets/add', create_data)
            if result and 'data' in result:
                asset_id = result['data'].get('asset_id')
                logger.info(f"[DFIR-IRIS] Asset created: {system.system_name} (ID: {asset_id})")
                system.dfir_iris_synced = True
                system.dfir_iris_sync_date = datetime.utcnow()
                system.dfir_iris_asset_id = str(asset_id)
                db.session.commit()
                return True
        
        logger.error(f"[DFIR-IRIS] Failed to sync system {system.system_name}")
        return False
        
    except Exception as e:
        logger.error(f"[DFIR-IRIS] Error syncing system {system.system_name}: {e}", exc_info=True)
        return False


@systems_bp.route('/case/<int:case_id>/systems/export_csv')
@login_required
def export_systems_csv(case_id):
    """Export all systems for a case to CSV"""
    from main import db
    from models import Case, System
    
    # Verify case exists
    case = db.session.get(Case, case_id)
    if not case:
        flash('Case not found', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        # Get all systems for this case (exclude hidden unless admin/analyst)
        query = System.query.filter_by(case_id=case_id)
        if current_user.role not in ['administrator', 'analyst']:
            query = query.filter_by(hidden=False)
        
        systems = query.order_by(System.system_type, System.system_name).all()
        
        # Create CSV in memory
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['Name', 'Type', 'IP'])
        
        # Write data
        for system in systems:
            writer.writerow([
                system.system_name,
                system.system_type,
                system.ip_address or ''
            ])
        
        # Create response
        output.seek(0)
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename=systems_case_{case_id}_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'}
        )
    
    except Exception as e:
        flash(f'Export failed: {str(e)}', 'error')
        return redirect(url_for('systems.systems_management', case_id=case_id))


@systems_bp.route('/case/<int:case_id>/systems/bulk_edit', methods=['POST'])
@login_required
def bulk_edit_systems(case_id):
    """Bulk edit systems (v1.23.0)"""
    # Permission check: Read-only users cannot edit
    if current_user.role == 'read-only':
        return jsonify({'success': False, 'error': 'Read-only users cannot edit systems'}), 403
    
    from main import db
    from models import System, Case
    
    # Verify case exists
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    try:
        data = request.get_json()
        system_ids = data.get('system_ids', [])
        
        if not system_ids or not isinstance(system_ids, list):
            return jsonify({'success': False, 'error': 'No systems selected'}), 400
        
        # Get fields to update (only non-None values)
        updates = {}
        if 'system_type' in data:
            updates['system_type'] = data['system_type']
        if 'hidden' in data:
            updates['hidden'] = data['hidden']
        
        if not updates:
            return jsonify({'success': False, 'error': 'No fields to update'}), 400
        
        # Update systems
        updated_count = 0
        
        for system_id in system_ids:
            system = db.session.get(System, system_id)
            
            if not system:
                continue  # Skip missing systems
            
            # Verify system belongs to this case
            if system.case_id != case_id:
                continue  # Skip systems from other cases
            
            # Apply updates
            for key, value in updates.items():
                setattr(system, key, value)
            
            updated_count += 1
        
        db.session.commit()
        
        # Audit log
        from audit_logger import log_action
        log_action('bulk_edit_systems', resource_type='system', resource_id=None,
                  resource_name=f'{updated_count} systems',
                  details={
                      'case_id': case_id,
                      'case_name': case.name,
                      'system_ids': system_ids,
                      'updated_count': updated_count,
                      'updates': updates
                  })
        
        flash(f'Bulk edit complete: {updated_count} systems updated', 'success')
        return jsonify({
            'success': True,
            'updated': updated_count
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': f'Bulk edit error: {str(e)}'}), 500


@systems_bp.route('/case/<int:case_id>/systems/bulk_delete', methods=['POST'])
@login_required
def bulk_delete_systems(case_id):
    """Bulk delete systems (v1.23.0)"""
    # Permission check: Only administrators can delete
    if current_user.role != 'administrator':
        return jsonify({'success': False, 'error': 'Only administrators can delete systems'}), 403
    
    from main import db
    from models import System, Case
    
    # Verify case exists
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    try:
        data = request.get_json()
        system_ids = data.get('system_ids', [])
        
        if not system_ids or not isinstance(system_ids, list):
            return jsonify({'success': False, 'error': 'No systems selected'}), 400
        
        # Delete systems
        deleted_count = 0
        deleted_names = []
        
        for system_id in system_ids:
            system = db.session.get(System, system_id)
            
            if not system:
                continue  # Skip missing systems
            
            # Verify system belongs to this case
            if system.case_id != case_id:
                continue  # Skip systems from other cases
            
            deleted_names.append(system.system_name)
            db.session.delete(system)
            deleted_count += 1
        
        db.session.commit()
        
        # Audit log
        from audit_logger import log_action
        log_action('bulk_delete_systems', resource_type='system', resource_id=None,
                  resource_name=f'{deleted_count} systems',
                  details={
                      'case_id': case_id,
                      'case_name': case.name,
                      'system_ids': system_ids,
                      'deleted_count': deleted_count,
                      'deleted_names': deleted_names
                  })
        
        flash(f'Bulk delete complete: {deleted_count} systems deleted', 'success')
        return jsonify({
            'success': True,
            'deleted': deleted_count
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': f'Bulk delete error: {str(e)}'}), 500

