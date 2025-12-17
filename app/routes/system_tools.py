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

# Known EDR/Security tools - exclude routine, keep responses
EDR_TOOLS = {
    'huntress': {
        'name': 'Huntress',
        'executables': 'HuntressAgent.exe,HuntressUpdater.exe,Huntress*.exe',
        'routine_commands': 'whoami,systeminfo,ipconfig,net user,net group,hostname,tasklist',
        'response_patterns': 'isolat,quarantin,block,remediat,disable,mass isolation',
        'description': 'Huntress MDR - exclude health checks, keep isolation/response actions'
    },
    'blackpoint': {
        'name': 'Blackpoint (SNAP)',
        'executables': 'SnapAgent.exe,Blackpoint*.exe,SNAP*.exe',
        'routine_commands': 'whoami,systeminfo,ipconfig,hostname',
        'response_patterns': 'isolat,snap,block,contain,quarantin',
        'description': 'Blackpoint SNAP - exclude health checks, keep isolation/response actions'
    },
    'sentinelone': {
        'name': 'SentinelOne',
        'executables': 'SentinelAgent.exe,SentinelCtl.exe,SentinelOne*.exe',
        'routine_commands': 'whoami,systeminfo,ipconfig,hostname,tasklist',
        'response_patterns': 'isolat,quarantin,threat,mitigat,kill,terminat,remediat',
        'description': 'SentinelOne EDR - exclude health checks, keep threat response actions'
    },
    'crowdstrike': {
        'name': 'CrowdStrike Falcon',
        'executables': 'CSAgent.exe,CSFalconService.exe,CSFalcon*.exe,CrowdStrike*.exe',
        'routine_commands': 'whoami,systeminfo,ipconfig,hostname',
        'response_patterns': 'contain,isolat,block,quarantin,kill,remediat',
        'description': 'CrowdStrike Falcon - exclude health checks, keep containment actions'
    },
    'defender_atp': {
        'name': 'Microsoft Defender for Endpoint',
        'executables': 'MsSense.exe,SenseIR.exe,MpCmdRun.exe',
        'routine_commands': 'whoami,systeminfo,ipconfig',
        'response_patterns': 'isolat,quarantin,block,remediat,contain',
        'description': 'Microsoft Defender ATP - exclude health checks, keep response actions'
    },
    'sophos': {
        'name': 'Sophos Intercept X',
        'executables': 'SophosAgent.exe,Sophos*.exe,SavService.exe',
        'routine_commands': 'whoami,systeminfo,ipconfig',
        'response_patterns': 'isolat,quarantin,block,clean',
        'description': 'Sophos EDR - exclude health checks, keep response actions'
    },
    'carbon_black': {
        'name': 'VMware Carbon Black',
        'executables': 'CbDefense*.exe,RepMgr.exe,cb.exe',
        'routine_commands': 'whoami,systeminfo,ipconfig,hostname',
        'response_patterns': 'isolat,quarantin,ban,block,kill',
        'description': 'Carbon Black - exclude health checks, keep response actions'
    },
    'other': {
        'name': 'Other (Custom)',
        'executables': '',
        'routine_commands': 'whoami,systeminfo,ipconfig,hostname',
        'response_patterns': 'isolat,quarantin,block,remediat,contain,kill',
        'description': 'User-defined EDR/Security tool'
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
    edr_settings = SystemToolsSetting.query.filter_by(setting_type='edr_tool').order_by(SystemToolsSetting.created_at.desc()).all()
    ip_settings = SystemToolsSetting.query.filter_by(setting_type='known_good_ip').order_by(SystemToolsSetting.created_at.desc()).all()
    
    return render_template('system_tools.html',
                         rmm_settings=rmm_settings,
                         remote_settings=remote_settings,
                         edr_settings=edr_settings,
                         ip_settings=ip_settings,
                         rmm_tools=RMM_TOOLS,
                         remote_tools=REMOTE_TOOLS,
                         edr_tools=EDR_TOOLS)


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
        custom_path = request.form.get('custom_path', '').strip()
        description = request.form.get('description', '').strip()
        
        # Validate
        if tool_key == 'other':
            if not custom_name or not custom_executables:
                return jsonify({'success': False, 'error': 'Custom name and executables are required'}), 400
            tool_name = custom_name
            executables = custom_executables
            rmm_path = custom_path or None
        elif tool_key in RMM_TOOLS:
            tool_name = RMM_TOOLS[tool_key]['name']
            executables = RMM_TOOLS[tool_key]['executables']
            rmm_path = RMM_TOOLS[tool_key].get('path', None)  # Get default path if available
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
            rmm_path=rmm_path,
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


@system_tools_bp.route('/edr/add', methods=['POST'])
@login_required
@admin_required
def add_edr_tool():
    """Add EDR/Security tool exclusion with context-aware filtering"""
    from main import db
    from models import SystemToolsSetting
    
    try:
        tool_key = request.form.get('tool_key', '').strip()
        custom_name = request.form.get('custom_name', '').strip()
        custom_executables = request.form.get('custom_executables', '').strip()
        custom_routine = request.form.get('custom_routine', '').strip()
        custom_responses = request.form.get('custom_responses', '').strip()
        description = request.form.get('description', '').strip()
        exclude_routine = request.form.get('exclude_routine', 'true').lower() == 'true'
        keep_responses = request.form.get('keep_responses', 'true').lower() == 'true'
        
        # Validate
        if tool_key == 'other':
            if not custom_name or not custom_executables:
                return jsonify({'success': False, 'error': 'Custom name and executables are required'}), 400
            tool_name = custom_name
            executables = custom_executables
            routine_commands = custom_routine or EDR_TOOLS['other']['routine_commands']
            response_patterns = custom_responses or EDR_TOOLS['other']['response_patterns']
        elif tool_key in EDR_TOOLS:
            tool_name = EDR_TOOLS[tool_key]['name']
            executables = EDR_TOOLS[tool_key]['executables']
            routine_commands = EDR_TOOLS[tool_key]['routine_commands']
            response_patterns = EDR_TOOLS[tool_key]['response_patterns']
            if not description:
                description = EDR_TOOLS[tool_key]['description']
        else:
            return jsonify({'success': False, 'error': 'Invalid tool selection'}), 400
        
        # Check for duplicate
        existing = SystemToolsSetting.query.filter_by(
            setting_type='edr_tool',
            tool_name=tool_name,
            is_active=True
        ).first()
        if existing:
            return jsonify({'success': False, 'error': f'{tool_name} is already configured'}), 400
        
        # Parse commands/patterns into JSON lists
        routine_list = [cmd.strip().lower() for cmd in routine_commands.split(',') if cmd.strip()]
        response_list = [pat.strip().lower() for pat in response_patterns.split(',') if pat.strip()]
        
        # Create setting
        setting = SystemToolsSetting(
            setting_type='edr_tool',
            tool_name=tool_name,
            executable_pattern=executables,
            exclude_routine=exclude_routine,
            keep_responses=keep_responses,
            routine_commands=json.dumps(routine_list),
            response_patterns=json.dumps(response_list),
            description=description or f'EDR tool: {tool_name}',
            created_by=current_user.id,
            is_active=True
        )
        db.session.add(setting)
        db.session.commit()
        
        # Audit log
        from audit_logger import log_action
        log_action('add_system_tool', resource_type='system_tools_setting', resource_id=setting.id,
                  resource_name=tool_name,
                  details={'type': 'edr_tool', 'executables': executables, 
                          'exclude_routine': exclude_routine, 'keep_responses': keep_responses})
        
        flash(f'✅ EDR tool added: {tool_name}', 'success')
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
    """Edit a setting (for remote tools, EDR tools, etc.)"""
    from main import db
    from models import SystemToolsSetting
    
    try:
        setting = db.session.get(SystemToolsSetting, setting_id)
        if not setting:
            return jsonify({'success': False, 'error': 'Setting not found'}), 404
        
        # Update fields based on type
        if setting.setting_type == 'rmm_tool':
            # Update RMM-specific fields
            if 'executable_pattern' in request.form:
                setting.executable_pattern = request.form.get('executable_pattern', '').strip()
            
            if 'rmm_path' in request.form:
                setting.rmm_path = request.form.get('rmm_path', '').strip() or None
        
        elif setting.setting_type == 'remote_tool':
            known_good_ids = request.form.get('known_good_ids', '').strip()
            ids_list = [id.strip() for id in known_good_ids.split('\n') if id.strip()]
            setting.known_good_ids = json.dumps(ids_list) if ids_list else None
        
        elif setting.setting_type == 'edr_tool':
            # Update EDR-specific fields
            if 'routine_commands' in request.form:
                routine_str = request.form.get('routine_commands', '').strip()
                routine_list = [cmd.strip().lower() for cmd in routine_str.split(',') if cmd.strip()]
                setting.routine_commands = json.dumps(routine_list) if routine_list else None
            
            if 'response_patterns' in request.form:
                responses_str = request.form.get('response_patterns', '').strip()
                response_list = [pat.strip().lower() for pat in responses_str.split(',') if pat.strip()]
                setting.response_patterns = json.dumps(response_list) if response_list else None
            
            if 'exclude_routine' in request.form:
                setting.exclude_routine = request.form.get('exclude_routine', 'true').lower() == 'true'
            
            if 'keep_responses' in request.form:
                setting.keep_responses = request.form.get('keep_responses', 'true').lower() == 'true'
        
        # Common fields for all types
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
        'edr_tools': [],
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
        
        elif s.setting_type == 'edr_tool':
            routine = json.loads(s.routine_commands) if s.routine_commands else []
            responses = json.loads(s.response_patterns) if s.response_patterns else []
            executables = [p.strip().lower() for p in (s.executable_pattern or '').split(',') if p.strip()]
            exclusions['edr_tools'].append({
                'name': s.tool_name,
                'executables': executables,
                'exclude_routine': s.exclude_routine if s.exclude_routine is not None else True,
                'keep_responses': s.keep_responses if s.keep_responses is not None else True,
                'routine_commands': routine,
                'response_patterns': responses
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

@system_tools_bp.route('/case/<int:case_id>/hide-known-good/check', methods=['GET'])
@login_required
def check_hide_known_good_task(case_id):
    """
    Check if there's already a running hide-known-good task for this case.
    Returns task_id if found, otherwise returns None.
    v2.2.2: New endpoint for UX improvement - check without starting
    """
    from main import db
    from models import Case
    import celery_app
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    # Check for existing running task for this case
    inspect = celery_app.celery_app.control.inspect()
    active_tasks = inspect.active()
    
    if active_tasks:
        for worker, tasks in active_tasks.items():
            for task_info in tasks:
                if task_info['name'] == 'events_known_good.hide_known_good_all_task':
                    if task_info.get('args') and len(task_info['args']) > 0:
                        if task_info['args'][0] == case_id:
                            # Found existing task!
                            return jsonify({
                                'running': True,
                                'task_id': task_info['id'],
                                'message': 'Task already running'
                            })
    
    # No running task found
    return jsonify({
        'running': False,
        'task_id': None
    })


@system_tools_bp.route('/case/<int:case_id>/hide-known-good', methods=['POST'])
@login_required
def hide_known_good_events(case_id):
    """
    Start background task to hide events matching known-good exclusion patterns.
    Returns task_id for progress polling.
    
    v2.1.8: Uses new parallel coordinator (hide_known_good_all_task)
    v2.2.2: Checks for existing running task before creating new one
    """
    from main import db
    from models import Case
    from events_known_good import hide_known_good_all_task, has_exclusions_configured
    from celery.result import AsyncResult
    import celery_app
    
    # Permission check
    if current_user.role == 'read-only':
        return jsonify({'error': 'Read-only users cannot hide events'}), 403
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    # Validate exclusions configured
    if not has_exclusions_configured():
        return jsonify({'error': 'No exclusions defined. Please configure System Tools settings first.'}), 400
    
    # Check for existing running task for this case
    # Inspect all active tasks to see if one is already processing this case
    import logging
    logger = logging.getLogger(__name__)
    
    inspect = celery_app.celery_app.control.inspect()
    active_tasks = inspect.active()
    
    logger.info(f"[HIDE_KG] inspect.active() returned: {active_tasks}")
    
    if active_tasks:
        for worker, tasks in active_tasks.items():
            logger.info(f"[HIDE_KG] Worker '{worker}' has {len(tasks)} tasks")
            for task_info in tasks:
                logger.info(f"[HIDE_KG] Task name: '{task_info['name']}', ID: {task_info['id']}, Args: {task_info.get('args', [])}")
                if task_info['name'] == 'events_known_good.hide_known_good_all_task':
                    # Check if it's for this case_id (args[0] is case_id)
                    if task_info.get('args') and len(task_info['args']) > 0:
                        if task_info['args'][0] == case_id:
                            # Found existing task!
                            existing_task_id = task_info['id']
                            logger.info(f"[HIDE_KG] Found existing task {existing_task_id} for case {case_id}")
                            return jsonify({
                                'status': 'already_running',
                                'task_id': existing_task_id,
                                'message': 'Hide known-good task already running (reconnected to existing task)'
                            })
    else:
        logger.info(f"[HIDE_KG] No active tasks found by inspect")
    
    # No existing task found - start NEW parallel coordinator task
    task = hide_known_good_all_task.delay(case_id)
    
    return jsonify({
        'status': 'started',
        'task_id': task.id,
        'message': 'Hide known-good task started (8 parallel workers)'
    })


@system_tools_bp.route('/case/<int:case_id>/hide-known-good/status/<task_id>')
@login_required
def hide_known_good_status(case_id, task_id):
    """Poll for task status"""
    from celery.result import AsyncResult
    
    task = AsyncResult(task_id)
    
    if task.state == 'PENDING':
        return jsonify({
            'status': 'pending',
            'message': 'Task is queued...'
        })
    elif task.state == 'PROGRESS':
        # task.info contains {'status': 'scanning', 'processed': X, ...}
        # Return it directly so frontend can use the inner status
        return jsonify(task.info)
    elif task.state == 'SUCCESS':
        return jsonify({
            'status': 'complete',
            **task.result
        })
    elif task.state == 'FAILURE':
        return jsonify({
            'status': 'error',
            'message': str(task.info)
        })
    else:
        return jsonify({
            'status': task.state.lower(),
            'message': 'Processing...'
        })


# ============================================================================
# HIDE NOISE EVENTS (v1.46.0)
# ============================================================================

@system_tools_bp.route('/case/<int:case_id>/hide-noise/check', methods=['GET'])
@login_required
def check_hide_noise_task(case_id):
    """
    Check if there's already a running hide-noise task for this case.
    Returns task_id if found, otherwise returns None.
    v2.2.2: New endpoint for UX improvement - check without starting
    """
    from main import db
    from models import Case
    import celery_app
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    # Check for existing running task for this case
    inspect = celery_app.celery_app.control.inspect()
    active_tasks = inspect.active()
    
    if active_tasks:
        for worker, tasks in active_tasks.items():
            for task_info in tasks:
                if task_info['name'] == 'events_known_noise.hide_noise_all_task':
                    if task_info.get('args') and len(task_info['args']) > 0:
                        if task_info['args'][0] == case_id:
                            # Found existing task!
                            return jsonify({
                                'running': True,
                                'task_id': task_info['id'],
                                'message': 'Task already running'
                            })
    
    # No running task found
    return jsonify({
        'running': False,
        'task_id': None
    })


@system_tools_bp.route('/case/<int:case_id>/hide-noise', methods=['POST'])
@login_required
def hide_noise_events(case_id):
    """
    Start background task to hide events matching noise patterns.
    Returns task_id for progress polling.
    
    v2.1.8: Uses new parallel coordinator (hide_noise_all_task)
    v2.2.2: Checks for existing running task before creating new one
    """
    from main import db
    from models import Case
    from events_known_noise import hide_noise_all_task
    from celery.result import AsyncResult
    import celery_app
    
    # Permission check
    if current_user.role == 'read-only':
        return jsonify({'error': 'Read-only users cannot hide events'}), 403
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    # Check for existing running task for this case
    inspect = celery_app.celery_app.control.inspect()
    active_tasks = inspect.active()
    
    if active_tasks:
        for worker, tasks in active_tasks.items():
            for task_info in tasks:
                if task_info['name'] == 'events_known_noise.hide_noise_all_task':
                    # Check if it's for this case_id (args[0] is case_id)
                    if task_info.get('args') and len(task_info['args']) > 0:
                        if task_info['args'][0] == case_id:
                            # Found existing task!
                            existing_task_id = task_info['id']
                            return jsonify({
                                'status': 'already_running',
                                'task_id': existing_task_id,
                                'message': 'Hide noise task already running (reconnected to existing task)'
                            })
    
    # Start NEW parallel coordinator task (no config validation needed - uses hardcoded patterns)
    task = hide_noise_all_task.delay(case_id)
    
    return jsonify({
        'status': 'started',
        'task_id': task.id,
        'message': 'Hide noise task started (8 parallel workers)'
    })
    
    return jsonify({
        'status': 'started',
        'task_id': task.id,
        'message': 'Hide noise task started (8 parallel workers)'
    })


@system_tools_bp.route('/case/<int:case_id>/hide-noise/status/<task_id>')
@login_required
def hide_noise_status(case_id, task_id):
    """Poll for hide noise task status"""
    from celery.result import AsyncResult
    
    task = AsyncResult(task_id)
    
    if task.state == 'PENDING':
        return jsonify({
            'status': 'pending',
            'message': 'Task is queued...'
        })
    elif task.state == 'PROGRESS':
        return jsonify(task.info)
    elif task.state == 'SUCCESS':
        return jsonify({
            'status': 'complete',
            **task.result
        })
    elif task.state == 'FAILURE':
        return jsonify({
            'status': 'error',
            'message': str(task.info)
        })
    else:
        return jsonify({
            'status': task.state.lower(),
            'message': 'Processing...'
        })


def _get_exclusions_dict():
    """Get exclusions as a structured dict"""
    from models import SystemToolsSetting
    
    exclusions = {
        'rmm_executables': [],
        'remote_tools': [],
        'edr_tools': [],
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
        
        elif s.setting_type == 'edr_tool':
            routine = json.loads(s.routine_commands) if s.routine_commands else []
            responses = json.loads(s.response_patterns) if s.response_patterns else []
            executables = [p.strip().lower() for p in (s.executable_pattern or '').split(',') if p.strip()]
            exclusions['edr_tools'].append({
                'name': s.tool_name,
                'executables': executables,
                'exclude_routine': s.exclude_routine if s.exclude_routine is not None else True,
                'keep_responses': s.keep_responses if s.keep_responses is not None else True,
                'routine_commands': routine,
                'response_patterns': responses
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

