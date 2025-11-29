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

