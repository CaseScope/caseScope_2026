"""
System Tools Settings Routes
Manages known-good tools and IPs to exclude from hunting/tagging.

Added in v1.38.0
"""

from flask import Blueprint, render_template, request, redirect, url_for, jsonify, flash
from flask_login import login_required, current_user
from functools import wraps
from datetime import datetime
import json
import ipaddress

system_tools_bp = Blueprint('system_tools', __name__, url_prefix='/settings/system-tools')


def admin_required(f):
    """Decorator to require administrator role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'administrator':
            flash('⛔ Administrator access required', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


# ============================================================================
# PREDEFINED TOOL CONFIGURATIONS
# ============================================================================

# Known RMM tools with their executable patterns
RMM_TOOLS = {
    'connectwise_automate': {
        'name': 'ConnectWise Automate (LabTech)',
        'executables': 'LTSVC.exe,LTSvcMon.exe,LTTray.exe,LabTech*.exe',
        'description': 'MSP Remote Monitoring & Management'
    },
    'datto_rmm': {
        'name': 'Datto RMM',
        'executables': 'AEMAgent.exe,Datto*.exe,CagService.exe',
        'description': 'MSP Remote Monitoring & Management'
    },
    'kaseya_vsa': {
        'name': 'Kaseya VSA',
        'executables': 'AgentMon.exe,Kaseya*.exe,KaseyaD.exe',
        'description': 'MSP Remote Monitoring & Management'
    },
    'ninja_rmm': {
        'name': 'NinjaRMM / NinjaOne',
        'executables': 'NinjaRMMAgent.exe,NinjaRMM*.exe',
        'description': 'MSP Remote Monitoring & Management'
    },
    'syncro': {
        'name': 'Syncro',
        'executables': 'Syncro*.exe,SyncroLive.exe',
        'description': 'MSP Remote Monitoring & Management'
    },
    'atera': {
        'name': 'Atera',
        'executables': 'AteraAgent.exe,Atera*.exe',
        'description': 'MSP Remote Monitoring & Management'
    },
    'n_able': {
        'name': 'N-able / N-central',
        'executables': 'N-central*.exe,BASupSrvc*.exe,BASupSrvcCnfg.exe',
        'description': 'MSP Remote Monitoring & Management'
    },
    'pulseway': {
        'name': 'Pulseway',
        'executables': 'PCMonitorSrv.exe,Pulseway*.exe',
        'description': 'MSP Remote Monitoring & Management'
    },
    'other': {
        'name': 'Other (Custom)',
        'executables': '',
        'description': 'User-defined RMM tool'
    }
}

# Known Remote Connectivity tools
REMOTE_TOOLS = {
    'screenconnect': {
        'name': 'ScreenConnect / ConnectWise Control',
        'executables': 'ScreenConnect*.exe,ConnectWiseControl*.exe',
        'id_field': 'Session ID',
        'description': 'Remote support - session IDs in command line'
    },
    'teamviewer': {
        'name': 'TeamViewer',
        'executables': 'TeamViewer*.exe',
        'id_field': 'Partner ID',
        'description': 'Remote support - partner IDs'
    },
    'anydesk': {
        'name': 'AnyDesk',
        'executables': 'AnyDesk*.exe',
        'id_field': 'Address',
        'description': 'Remote support - AnyDesk addresses'
    },
    'splashtop': {
        'name': 'Splashtop',
        'executables': 'Splashtop*.exe,SRManager.exe',
        'id_field': 'Session ID',
        'description': 'Remote support'
    },
    'goto_assist': {
        'name': 'GoTo Assist / GoToMyPC',
        'executables': 'g2a*.exe,GoTo*.exe',
        'id_field': 'Session ID',
        'description': 'Remote support'
    },
    'bomgar': {
        'name': 'BeyondTrust (Bomgar)',
        'executables': 'bomgar*.exe,BeyondTrust*.exe',
        'id_field': 'Session Key',
        'description': 'Remote support'
    },
    'other': {
        'name': 'Other (Custom)',
        'executables': '',
        'id_field': 'Custom ID',
        'description': 'User-defined remote tool'
    }
}


# ============================================================================
# ROUTES
# ============================================================================

@system_tools_bp.route('/')
@login_required
@admin_required
def index():
    """System Tools settings page"""
    from main import db
    from models import SystemToolsSetting
    
    # Get all settings grouped by type
    rmm_settings = SystemToolsSetting.query.filter_by(setting_type='rmm_tool').order_by(SystemToolsSetting.created_at.desc()).all()
    remote_settings = SystemToolsSetting.query.filter_by(setting_type='remote_tool').order_by(SystemToolsSetting.created_at.desc()).all()
    ip_settings = SystemToolsSetting.query.filter_by(setting_type='known_good_ip').order_by(SystemToolsSetting.created_at.desc()).all()
    
    return render_template('system_tools.html',
                         rmm_settings=rmm_settings,
                         remote_settings=remote_settings,
                         ip_settings=ip_settings,
                         rmm_tools=RMM_TOOLS,
                         remote_tools=REMOTE_TOOLS)


@system_tools_bp.route('/rmm/add', methods=['POST'])
@login_required
@admin_required
def add_rmm_tool():
    """Add RMM tool exclusion"""
    from main import db
    from models import SystemToolsSetting
    
    try:
        tool_key = request.form.get('tool_key', '').strip()
        custom_name = request.form.get('custom_name', '').strip()
        custom_executables = request.form.get('custom_executables', '').strip()
        description = request.form.get('description', '').strip()
        
        # Validate
        if tool_key == 'other':
            if not custom_name or not custom_executables:
                return jsonify({'success': False, 'error': 'Custom name and executables are required'}), 400
            tool_name = custom_name
            executables = custom_executables
        elif tool_key in RMM_TOOLS:
            tool_name = RMM_TOOLS[tool_key]['name']
            executables = RMM_TOOLS[tool_key]['executables']
            if not description:
                description = RMM_TOOLS[tool_key]['description']
        else:
            return jsonify({'success': False, 'error': 'Invalid tool selection'}), 400
        
        # Check for duplicate
        existing = SystemToolsSetting.query.filter_by(
            setting_type='rmm_tool',
            tool_name=tool_name,
            is_active=True
        ).first()
        if existing:
            return jsonify({'success': False, 'error': f'{tool_name} is already configured'}), 400
        
        # Create setting
        setting = SystemToolsSetting(
            setting_type='rmm_tool',
            tool_name=tool_name,
            executable_pattern=executables,
            description=description or f'RMM tool exclusion: {tool_name}',
            created_by=current_user.id,
            is_active=True
        )
        db.session.add(setting)
        db.session.commit()
        
        # Audit log
        from audit_logger import log_action
        log_action('add_system_tool', resource_type='system_tools_setting', resource_id=setting.id,
                  resource_name=tool_name,
                  details={'type': 'rmm_tool', 'executables': executables})
        
        flash(f'✅ RMM tool added: {tool_name}', 'success')
        return jsonify({'success': True, 'id': setting.id})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@system_tools_bp.route('/remote/add', methods=['POST'])
@login_required
@admin_required
def add_remote_tool():
    """Add Remote Connectivity tool exclusion with known-good IDs"""
    from main import db
    from models import SystemToolsSetting
    
    try:
        tool_key = request.form.get('tool_key', '').strip()
        custom_name = request.form.get('custom_name', '').strip()
        custom_executables = request.form.get('custom_executables', '').strip()
        known_good_ids = request.form.get('known_good_ids', '').strip()
        description = request.form.get('description', '').strip()
        
        # Validate
        if tool_key == 'other':
            if not custom_name or not custom_executables:
                return jsonify({'success': False, 'error': 'Custom name and executables are required'}), 400
            tool_name = custom_name
            executables = custom_executables
        elif tool_key in REMOTE_TOOLS:
            tool_name = REMOTE_TOOLS[tool_key]['name']
            executables = REMOTE_TOOLS[tool_key]['executables']
            if not description:
                description = REMOTE_TOOLS[tool_key]['description']
        else:
            return jsonify({'success': False, 'error': 'Invalid tool selection'}), 400
        
        # Parse known-good IDs (one per line)
        ids_list = [id.strip() for id in known_good_ids.split('\n') if id.strip()]
        
        # Create setting
        setting = SystemToolsSetting(
            setting_type='remote_tool',
            tool_name=tool_name,
            executable_pattern=executables,
            known_good_ids=json.dumps(ids_list) if ids_list else None,
            description=description or f'Remote tool exclusion: {tool_name}',
            created_by=current_user.id,
            is_active=True
        )
        db.session.add(setting)
        db.session.commit()
        
        # Audit log
        from audit_logger import log_action
        log_action('add_system_tool', resource_type='system_tools_setting', resource_id=setting.id,
                  resource_name=tool_name,
                  details={'type': 'remote_tool', 'executables': executables, 'known_good_ids_count': len(ids_list)})
        
        flash(f'✅ Remote tool added: {tool_name} ({len(ids_list)} known-good IDs)', 'success')
        return jsonify({'success': True, 'id': setting.id})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@system_tools_bp.route('/ip/save', methods=['POST'])
@login_required
@admin_required
def save_ip_exclusions():
    """Save known-good IP addresses/CIDR ranges"""
    from main import db
    from models import SystemToolsSetting
    
    try:
        ip_list_text = request.form.get('ip_list', '').strip()
        
        # Parse and validate IPs/CIDRs
        valid_entries = []
        errors = []
        
        for line_num, line in enumerate(ip_list_text.split('\n'), 1):
            line = line.strip()
            if not line or line.startswith('#'):  # Skip empty lines and comments
                continue
            
            try:
                # Try to parse as IP or CIDR
                if '/' in line:
                    ipaddress.ip_network(line, strict=False)
                else:
                    ipaddress.ip_address(line)
                valid_entries.append(line)
            except ValueError as e:
                errors.append(f'Line {line_num}: Invalid IP/CIDR "{line}"')
        
        if errors:
            return jsonify({'success': False, 'error': 'Validation errors:\n' + '\n'.join(errors[:5])}), 400
        
        # Clear existing IP exclusions
        SystemToolsSetting.query.filter_by(setting_type='known_good_ip').delete()
        
        # Add new entries
        for ip_entry in valid_entries:
            setting = SystemToolsSetting(
                setting_type='known_good_ip',
                ip_or_cidr=ip_entry,
                description=f'Known-good IP/network: {ip_entry}',
                created_by=current_user.id,
                is_active=True
            )
            db.session.add(setting)
        
        db.session.commit()
        
        # Audit log
        from audit_logger import log_action
        log_action('save_ip_exclusions', resource_type='system_tools_setting', resource_id=None,
                  resource_name=f'{len(valid_entries)} IP exclusions',
                  details={'count': len(valid_entries), 'entries': valid_entries[:10]})
        
        flash(f'✅ Saved {len(valid_entries)} IP/network exclusions', 'success')
        return jsonify({'success': True, 'count': len(valid_entries)})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@system_tools_bp.route('/setting/<int:setting_id>/toggle', methods=['POST'])
@login_required
@admin_required
def toggle_setting(setting_id):
    """Toggle a setting's active status"""
    from main import db
    from models import SystemToolsSetting
    
    try:
        setting = db.session.get(SystemToolsSetting, setting_id)
        if not setting:
            return jsonify({'success': False, 'error': 'Setting not found'}), 404
        
        setting.is_active = not setting.is_active
        db.session.commit()
        
        status = 'enabled' if setting.is_active else 'disabled'
        
        # Audit log
        from audit_logger import log_action
        log_action('toggle_system_tool', resource_type='system_tools_setting', resource_id=setting.id,
                  resource_name=setting.tool_name or setting.ip_or_cidr,
                  details={'new_status': status})
        
        flash(f'✅ Setting {status}: {setting.tool_name or setting.ip_or_cidr}', 'success')
        return jsonify({'success': True, 'is_active': setting.is_active})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@system_tools_bp.route('/setting/<int:setting_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_setting(setting_id):
    """Delete a setting"""
    from main import db
    from models import SystemToolsSetting
    
    try:
        setting = db.session.get(SystemToolsSetting, setting_id)
        if not setting:
            return jsonify({'success': False, 'error': 'Setting not found'}), 404
        
        name = setting.tool_name or setting.ip_or_cidr
        setting_type = setting.setting_type
        
        db.session.delete(setting)
        db.session.commit()
        
        # Audit log
        from audit_logger import log_action
        log_action('delete_system_tool', resource_type='system_tools_setting', resource_id=setting_id,
                  resource_name=name,
                  details={'type': setting_type})
        
        flash(f'🗑️ Setting deleted: {name}', 'success')
        return jsonify({'success': True})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@system_tools_bp.route('/setting/<int:setting_id>/edit', methods=['POST'])
@login_required
@admin_required
def edit_setting(setting_id):
    """Edit a setting (primarily for updating known-good IDs)"""
    from main import db
    from models import SystemToolsSetting
    
    try:
        setting = db.session.get(SystemToolsSetting, setting_id)
        if not setting:
            return jsonify({'success': False, 'error': 'Setting not found'}), 404
        
        # Update fields based on type
        if setting.setting_type == 'remote_tool':
            known_good_ids = request.form.get('known_good_ids', '').strip()
            ids_list = [id.strip() for id in known_good_ids.split('\n') if id.strip()]
            setting.known_good_ids = json.dumps(ids_list) if ids_list else None
        
        if 'description' in request.form:
            setting.description = request.form.get('description', '').strip()
        
        if 'executable_pattern' in request.form:
            setting.executable_pattern = request.form.get('executable_pattern', '').strip()
        
        setting.updated_at = datetime.utcnow()
        db.session.commit()
        
        # Audit log
        from audit_logger import log_action
        log_action('edit_system_tool', resource_type='system_tools_setting', resource_id=setting.id,
                  resource_name=setting.tool_name or setting.ip_or_cidr,
                  details={'type': setting.setting_type})
        
        flash(f'✅ Setting updated: {setting.tool_name or setting.ip_or_cidr}', 'success')
        return jsonify({'success': True})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# API ENDPOINTS FOR AI TRIAGE SEARCH
# ============================================================================

@system_tools_bp.route('/api/exclusions')
@login_required
def get_exclusions():
    """
    Get all active exclusions for use by AI Triage Search.
    Returns a structured dict for easy filtering.
    """
    from main import db
    from models import SystemToolsSetting
    
    exclusions = {
        'rmm_executables': [],
        'remote_tools': [],
        'known_good_ips': []
    }
    
    settings = SystemToolsSetting.query.filter_by(is_active=True).all()
    
    for s in settings:
        if s.setting_type == 'rmm_tool':
            if s.executable_pattern:
                # Split comma-separated patterns
                patterns = [p.strip().lower() for p in s.executable_pattern.split(',') if p.strip()]
                exclusions['rmm_executables'].extend(patterns)
        
        elif s.setting_type == 'remote_tool':
            ids = json.loads(s.known_good_ids) if s.known_good_ids else []
            exclusions['remote_tools'].append({
                'name': s.tool_name,
                'pattern': s.executable_pattern.lower() if s.executable_pattern else '',
                'known_good_ids': [id.lower() for id in ids]
            })
        
        elif s.setting_type == 'known_good_ip':
            if s.ip_or_cidr:
                exclusions['known_good_ips'].append(s.ip_or_cidr)
    
    return jsonify(exclusions)


@system_tools_bp.route('/api/has-exclusions')
@login_required
def has_exclusions():
    """Check if any exclusions are defined"""
    from main import db
    from models import SystemToolsSetting
    
    count = SystemToolsSetting.query.filter_by(is_active=True).count()
    return jsonify({'has_exclusions': count > 0, 'count': count})


# ============================================================================
# BULK HIDE KNOWN-GOOD EVENTS
# ============================================================================

@system_tools_bp.route('/case/<int:case_id>/hide-known-good', methods=['POST'])
@login_required
def hide_known_good_events(case_id):
    """
    Hide events that match known-good exclusion patterns.
    Uses streaming response to provide progress updates.
    
    Matches events where:
    - Parent process matches RMM tool patterns (LTSVC.exe, etc.)
    - Process matches remote tool with known-good session ID
    - Source IP is in known-good IP ranges
    """
    from flask import Response, stream_with_context
    from main import db, opensearch_client
    from models import Case, SystemToolsSetting
    from datetime import datetime
    import fnmatch
    
    # Permission check
    if current_user.role == 'read-only':
        return jsonify({'error': 'Read-only users cannot hide events'}), 403
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    # Load exclusions
    exclusions = _get_exclusions_dict()
    
    if not any([exclusions['rmm_executables'], exclusions['remote_tools'], exclusions['known_good_ips']]):
        return jsonify({'error': 'No exclusions defined. Please configure System Tools settings first.'}), 400
    
    def generate():
        """Generator for streaming progress updates"""
        index_name = f"case_{case_id}"
        hidden_count = 0
        processed_count = 0
        
        try:
            # First, count total events
            count_response = opensearch_client.count(index=index_name)
            total_events = count_response.get('count', 0)
            
            yield f"data: {json.dumps({'status': 'starting', 'total': total_events, 'message': f'Scanning {total_events:,} events...'})}\n\n"
            
            if total_events == 0:
                yield f"data: {json.dumps({'status': 'complete', 'hidden': 0, 'processed': 0, 'message': 'No events in case'})}\n\n"
                return
            
            # Use scroll API for large datasets
            scroll_size = 1000
            scroll_time = '5m'
            
            # Query for events that are NOT already hidden
            query = {
                "query": {
                    "bool": {
                        "must_not": [
                            {"term": {"is_hidden": True}}
                        ]
                    }
                },
                "_source": ["process", "parent", "host", "source", "@timestamp", "search_blob"]
            }
            
            response = opensearch_client.search(
                index=index_name,
                body=query,
                scroll=scroll_time,
                size=scroll_size
            )
            
            scroll_id = response.get('_scroll_id')
            hits = response['hits']['hits']
            total_to_scan = response['hits']['total']['value']
            
            yield f"data: {json.dumps({'status': 'scanning', 'total': total_to_scan, 'message': f'Found {total_to_scan:,} non-hidden events to scan'})}\n\n"
            
            events_to_hide = []
            
            while hits:
                for hit in hits:
                    processed_count += 1
                    
                    if _should_hide_event(hit, exclusions):
                        events_to_hide.append({
                            '_id': hit['_id'],
                            '_index': hit['_index']
                        })
                    
                    # Progress update every 500 events
                    if processed_count % 500 == 0:
                        pct = int((processed_count / total_to_scan) * 100)
                        yield f"data: {json.dumps({'status': 'scanning', 'processed': processed_count, 'total': total_to_scan, 'found': len(events_to_hide), 'percent': pct})}\n\n"
                
                # Get next batch
                response = opensearch_client.scroll(scroll_id=scroll_id, scroll=scroll_time)
                scroll_id = response.get('_scroll_id')
                hits = response['hits']['hits']
            
            # Clear scroll
            try:
                opensearch_client.clear_scroll(scroll_id=scroll_id)
            except:
                pass
            
            yield f"data: {json.dumps({'status': 'hiding', 'found': len(events_to_hide), 'message': f'Found {len(events_to_hide):,} events to hide. Applying...'})}\n\n"
            
            # Bulk update to hide events
            if events_to_hide:
                batch_size = 500
                for i in range(0, len(events_to_hide), batch_size):
                    batch = events_to_hide[i:i+batch_size]
                    
                    bulk_body = []
                    for evt in batch:
                        bulk_body.append({"update": {"_index": evt['_index'], "_id": evt['_id']}})
                        bulk_body.append({
                            "script": {
                                "source": "ctx._source.is_hidden = true; ctx._source.hidden_by = params.user_id; ctx._source.hidden_at = params.timestamp; ctx._source.hidden_reason = params.reason",
                                "lang": "painless",
                                "params": {
                                    "user_id": current_user.id,
                                    "timestamp": datetime.utcnow().isoformat(),
                                    "reason": "known_good_exclusion"
                                }
                            }
                        })
                    
                    try:
                        opensearch_client.bulk(body=bulk_body, refresh=False)
                        hidden_count += len(batch)
                        
                        pct = int((hidden_count / len(events_to_hide)) * 100)
                        yield f"data: {json.dumps({'status': 'hiding', 'hidden': hidden_count, 'total_to_hide': len(events_to_hide), 'percent': pct})}\n\n"
                    except Exception as e:
                        yield f"data: {json.dumps({'status': 'error', 'message': f'Bulk update error: {str(e)}'})}\n\n"
                
                # Refresh index
                opensearch_client.indices.refresh(index=index_name)
            
            # Audit log
            from audit_logger import log_action
            log_action('hide_known_good_events', resource_type='case', resource_id=case_id,
                      resource_name=case.name,
                      details={'hidden_count': hidden_count, 'processed_count': processed_count})
            
            yield f"data: {json.dumps({'status': 'complete', 'hidden': hidden_count, 'processed': processed_count, 'message': f'Hidden {hidden_count:,} known-good events'})}\n\n"
            
        except Exception as e:
            yield f"data: {json.dumps({'status': 'error', 'message': str(e)})}\n\n"
    
    return Response(stream_with_context(generate()), mimetype='text/event-stream')


def _get_exclusions_dict():
    """Get exclusions as a structured dict"""
    from models import SystemToolsSetting
    
    exclusions = {
        'rmm_executables': [],
        'remote_tools': [],
        'known_good_ips': []
    }
    
    settings = SystemToolsSetting.query.filter_by(is_active=True).all()
    
    for s in settings:
        if s.setting_type == 'rmm_tool':
            if s.executable_pattern:
                patterns = [p.strip().lower() for p in s.executable_pattern.split(',') if p.strip()]
                exclusions['rmm_executables'].extend(patterns)
        
        elif s.setting_type == 'remote_tool':
            ids = json.loads(s.known_good_ids) if s.known_good_ids else []
            exclusions['remote_tools'].append({
                'name': s.tool_name,
                'pattern': s.executable_pattern.lower() if s.executable_pattern else '',
                'known_good_ids': [id.lower() for id in ids]
            })
        
        elif s.setting_type == 'known_good_ip':
            if s.ip_or_cidr:
                exclusions['known_good_ips'].append(s.ip_or_cidr)
    
    return exclusions


def _should_hide_event(hit, exclusions):
    """
    Check if an event should be hidden based on exclusion rules.
    
    Returns True if event matches any known-good pattern.
    """
    import fnmatch
    
    src = hit.get('_source', {})
    proc = src.get('process', {})
    parent = proc.get('parent', {}) or src.get('parent', {})
    
    # Check 1: Parent process is a known RMM tool
    parent_name = (parent.get('name') or parent.get('executable') or '').lower()
    parent_name_only = parent_name.split('\\')[-1] if parent_name else ''
    
    for rmm_pattern in exclusions.get('rmm_executables', []):
        if fnmatch.fnmatch(parent_name_only, rmm_pattern):
            return True
        if fnmatch.fnmatch(parent_name, f'*{rmm_pattern}'):
            return True
    
    # Check 2: Process is a remote tool with known-good ID
    proc_name = (proc.get('name') or proc.get('executable') or '').lower()
    cmd_line = (proc.get('command_line') or '').lower()
    search_blob = (src.get('search_blob') or '').lower()
    
    for tool_config in exclusions.get('remote_tools', []):
        pattern = tool_config.get('pattern', '')
        if pattern and (pattern in proc_name or pattern in search_blob):
            # Check if session ID is in known-good list
            for known_id in tool_config.get('known_good_ids', []):
                if known_id and (known_id in cmd_line or known_id in search_blob):
                    return True
    
    # Check 3: Source IP is in known-good range
    source_ip = None
    
    # Try various IP fields
    if src.get('source', {}).get('ip'):
        source_ip = src['source']['ip']
    elif src.get('host', {}).get('ip'):
        source_ip = src['host']['ip']
    elif proc.get('user_logon', {}).get('ip'):
        source_ip = proc['user_logon']['ip']
    
    if source_ip:
        if isinstance(source_ip, list):
            source_ip = source_ip[0]
        
        for ip_range in exclusions.get('known_good_ips', []):
            if _ip_in_range(source_ip, ip_range):
                return True
    
    return False


def _ip_in_range(ip_str, cidr_or_ip):
    """Check if IP is in a CIDR range or matches exactly"""
    try:
        ip = ipaddress.ip_address(ip_str)
        
        if '/' in cidr_or_ip:
            network = ipaddress.ip_network(cidr_or_ip, strict=False)
            return ip in network
        else:
            return ip == ipaddress.ip_address(cidr_or_ip)
    except (ValueError, TypeError):
        return False

