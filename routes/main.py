"""Main routes for CaseScope"""
import os
from functools import wraps
from flask import Blueprint, render_template, redirect, url_for, request, flash, session, jsonify
from flask_login import login_required, current_user
from models.database import db
from models.case import Case, CaseStatus, COMMON_TIMEZONES
from models.client import Client
from models.user import User
from models.audit_log import AuditLog, AuditAction, AuditEntityType, audit_update
from config import Config, PermissionLevel, UserSettings

main_bp = Blueprint('main', __name__)


def case_required(f):
    """Decorator to require an active case in session"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'active_case_uuid' not in session:
            flash('Please select a case first', 'warning')
            return redirect(url_for('main.select_case'))
        # Verify the case still exists
        case = Case.get_by_uuid(session['active_case_uuid'])
        if not case:
            session.pop('active_case_uuid', None)
            flash('Selected case no longer exists. Please select another case.', 'error')
            return redirect(url_for('main.select_case'))
        return f(*args, **kwargs)
    return decorated_function


def get_active_case():
    """Get the currently active case from session"""
    if 'active_case_uuid' in session:
        return Case.get_by_uuid(session['active_case_uuid'])
    return None


@main_bp.route('/')
@login_required
def index():
    """Dashboard / Home page"""
    return render_template('dashboard.html', page_title='Dashboard')


@main_bp.route('/dashboard')
@login_required
def dashboard():
    """Dashboard page"""
    return render_template('dashboard.html', page_title='Dashboard')


@main_bp.route('/cases')
@login_required
def cases():
    """Case Selection - list all cases"""
    all_cases = Case.query.order_by(Case.created_at.desc()).all()
    return render_template(
        'cases.html',
        page_title='Case Selection',
        cases=all_cases,
        CaseStatus=CaseStatus
    )


@main_bp.route('/cases/new', methods=['GET', 'POST'])
@login_required
def case_create():
    """Create new case form"""
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        company = request.form.get('company', '').strip()
        description = request.form.get('description', '').strip()
        timezone = request.form.get('timezone', 'UTC').strip()
        router_ips = request.form.get('router_ips', '').strip()
        vpn_ips = request.form.get('vpn_ips', '').strip()
        
        # Validate mandatory fields
        if not name:
            flash('Case name is required', 'error')
            return render_template('case_create.html', page_title='Create Case',
                                   timezones=COMMON_TIMEZONES, detected_tz='UTC')
        
        if not company:
            flash('Company is required', 'error')
            return render_template('case_create.html', page_title='Create Case',
                                   timezones=COMMON_TIMEZONES, detected_tz='UTC')
        
        # Validate timezone
        from utils.timezone import is_valid_timezone
        if not is_valid_timezone(timezone):
            flash('Invalid timezone selected', 'error')
            return render_template('case_create.html', page_title='Create Case',
                                   timezones=COMMON_TIMEZONES, detected_tz='UTC')
        
        # Create the case
        case = Case(
            name=name,
            company=company,
            description=description or None,
            timezone=timezone,
            router_ips=router_ips or None,
            vpn_ips=vpn_ips or None,
            created_by=current_user.username
        )
        
        db.session.add(case)
        db.session.commit()
        
        # Audit log case creation
        AuditLog.log(
            entity_type=AuditEntityType.CASE,
            entity_id=case.uuid,
            action=AuditAction.CREATED,
            entity_name=name,
            case_uuid=case.uuid,
            details={
                'company': company,
                'timezone': timezone
            }
        )
        
        # Create SFTP upload folder for this case
        sftp_case_folder = os.path.join(Config.UPLOAD_FOLDER_SFTP, case.uuid)
        os.makedirs(sftp_case_folder, exist_ok=True)
        
        flash(f'Case "{name}" created successfully', 'success')
        return redirect(url_for('main.cases'))
    
    # Get default timezone from system settings
    from models.system_settings import SystemSettings, SettingKeys
    default_tz = SystemSettings.get(SettingKeys.DEFAULT_TIMEZONE, 'America/New_York')
    
    return render_template('case_create.html', page_title='Create Case',
                           timezones=COMMON_TIMEZONES, detected_tz=default_tz)


@main_bp.route('/cases/select/<case_uuid>')
@login_required
def case_select(case_uuid):
    """Set a case as the active case in session"""
    case = Case.get_by_uuid(case_uuid)
    if not case:
        flash('Case not found', 'error')
        return redirect(url_for('main.select_case'))
    
    session['active_case_uuid'] = case_uuid
    flash(f'Case "{case.name}" selected', 'success')
    return redirect(url_for('main.case_dashboard'))


@main_bp.route('/select-case')
@login_required
def select_case():
    """Select a case - step-by-step client and case selection"""
    from models.system_settings import SystemSettings, SettingKeys
    
    clients = Client.get_active_clients()
    default_tz = SystemSettings.get(SettingKeys.DEFAULT_TIMEZONE, 'America/New_York')
    
    return render_template(
        'select_case.html',
        page_title='Select Case',
        clients=clients,
        timezones=COMMON_TIMEZONES,
        default_timezone=default_tz
    )


@main_bp.route('/api/client/<client_uuid>/cases')
@login_required
def api_client_cases(client_uuid):
    """API: Get cases for a specific client"""
    client = Client.get_by_uuid(client_uuid)
    if not client:
        return jsonify({'error': 'Client not found'}), 404
    
    cases = Case.query.filter_by(client_id=client.id).order_by(Case.created_at.desc()).all()
    
    cases_data = []
    for case in cases:
        cases_data.append({
            'uuid': case.uuid,
            'name': case.name,
            'status': case.status,
            'created_by': case.created_by,
            'created_at': case.created_at.strftime('%Y-%m-%d %H:%M') if case.created_at else None,
            'assigned_to': case.assigned_to
        })
    
    return jsonify({'cases': cases_data})


@main_bp.route('/api/case/create', methods=['POST'])
@login_required
def api_case_create():
    """API: Create a new case"""
    client_uuid = request.form.get('client_uuid', '').strip()
    name = request.form.get('name', '').strip()
    description = request.form.get('description', '').strip()
    timezone = request.form.get('timezone', 'UTC').strip()
    router_ips = request.form.get('router_ips', '').strip()
    vpn_ips = request.form.get('vpn_ips', '').strip()
    
    if not client_uuid:
        return jsonify({'success': False, 'error': 'Client is required'}), 400
    
    if not name:
        return jsonify({'success': False, 'error': 'Case name is required'}), 400
    
    client = Client.get_by_uuid(client_uuid)
    if not client:
        return jsonify({'success': False, 'error': 'Client not found'}), 404
    
    from utils.timezone import is_valid_timezone
    if not is_valid_timezone(timezone):
        timezone = client.timezone or 'UTC'
    
    case = Case(
        name=name,
        company=client.name,
        client_id=client.id,
        description=description or None,
        timezone=timezone,
        router_ips=router_ips or None,
        vpn_ips=vpn_ips or None,
        created_by=current_user.username
    )
    
    db.session.add(case)
    db.session.commit()
    
    AuditLog.log(
        entity_type=AuditEntityType.CASE,
        entity_id=case.uuid,
        action=AuditAction.CREATED,
        entity_name=name,
        case_uuid=case.uuid,
        details={
            'client': client.code,
            'company': client.name,
            'timezone': timezone
        }
    )
    
    # Create SFTP upload folder for this case
    sftp_case_folder = os.path.join(Config.UPLOAD_FOLDER_SFTP, case.uuid)
    os.makedirs(sftp_case_folder, exist_ok=True)
    
    return jsonify({'success': True, 'case_uuid': case.uuid})


@main_bp.route('/cases/info/<case_uuid>')
@login_required
def case_info(case_uuid):
    """Get case info for hover popup (JSON)"""
    case = Case.get_by_uuid(case_uuid)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    return jsonify({
        'uuid': case.uuid,
        'name': case.name,
        'company': case.company,
        'timezone': case.timezone or 'UTC',
        'status': Case.get_status_display(case.status),
        'router_ips': case.router_ips or '-',
        'vpn_ips': case.vpn_ips or '-',
        'created_by': case.created_by,
        'created_at': case.created_at.strftime('%Y-%m-%d %H:%M') if case.created_at else '-',
        'assigned_to': case.assigned_to or '-',
        'has_edr_report': bool(case.edr_report)
    })


# ============================================
# Cases Section Routes (require active case)
# ============================================

@main_bp.route('/case/dashboard')
@login_required
@case_required
def case_dashboard():
    """Case Dashboard - overview of the active case"""
    case = get_active_case()
    
    # Look up full names for created_by and assigned_to usernames
    created_by_name = case.created_by
    if case.created_by:
        creator = User.query.filter_by(username=case.created_by).first()
        if creator:
            created_by_name = creator.full_name
    
    assigned_to_name = case.assigned_to
    if case.assigned_to:
        assignee = User.query.filter_by(username=case.assigned_to).first()
        if assignee:
            assigned_to_name = assignee.full_name
    
    return render_template('case_dashboard.html', page_title='Case Dashboard', case=case,
                           created_by_name=created_by_name, assigned_to_name=assigned_to_name)


@main_bp.route('/case/<int:case_id>/analysis/<analysis_id>')
@login_required
def case_analysis_results(case_id, analysis_id):
    """Analysis Results - view results of a case analysis run"""
    from models.behavioral_profiles import CaseAnalysisRun
    from models.case import Case
    
    case = Case.query.get_or_404(case_id)
    analysis = CaseAnalysisRun.query.filter_by(
        case_id=case_id,
        analysis_id=analysis_id
    ).first_or_404()
    
    # Build summary data — prefer summary JSON, fall back to columns
    if analysis.summary and isinstance(analysis.summary, dict):
        summary = {
            'total_findings': analysis.summary.get('total_findings', 0),
            'high_confidence_count': analysis.summary.get('high_findings', 0) + analysis.summary.get('critical_findings', 0),
            'pending_actions': 0,
            'attack_chains': analysis.summary.get('attack_chains', 0),
            'patterns_analyzed': analysis.summary.get('patterns_analyzed', 0),
            'gap_findings': analysis.summary.get('gap_findings', 0),
            'users_profiled': analysis.summary.get('users_profiled', 0),
            'systems_profiled': analysis.summary.get('systems_profiled', 0),
            'census_total_events': analysis.summary.get('census_total_events', 0),
            'ioc_timeline_entries': analysis.summary.get('ioc_timeline_entries', 0),
            'ai_triage': analysis.summary.get('ai_triage'),
            'ai_synthesis': analysis.summary.get('ai_synthesis')
        }
    else:
        summary = {
            'total_findings': analysis.findings_generated or 0,
            'high_confidence_count': analysis.high_confidence_findings or 0,
            'pending_actions': 0,
            'attack_chains': analysis.attack_chains_found or 0,
            'patterns_analyzed': analysis.patterns_analyzed or 0,
            'gap_findings': analysis.gap_findings or 0,
            'users_profiled': analysis.users_profiled or 0,
            'systems_profiled': analysis.systems_profiled or 0
        }
    
    # Count pending actions
    from models.behavioral_profiles import SuggestedAction
    summary['pending_actions'] = SuggestedAction.query.filter_by(
        case_id=case_id,
        analysis_id=analysis_id,
        status='pending'
    ).count()
    
    return render_template('case_analysis_results.html', 
                           page_title='Analysis Results', 
                           case=case,
                           analysis=analysis,
                           summary=summary)


@main_bp.route('/case/upload')
@login_required
@case_required
def case_upload():
    """Upload Files - upload files for the active case"""
    case = get_active_case()
    return render_template('case_upload.html', page_title='Upload Files', case=case)


@main_bp.route('/case/files')
@login_required
@case_required
def case_files():
    """Case Files - files associated with the active case"""
    case = get_active_case()
    return render_template('case_files.html', page_title='Case Files', case=case)


@main_bp.route('/case/hunting')
@login_required
@case_required
def case_hunting():
    """Hunting - threat hunting for the active case"""
    from models.system_settings import SystemSettings, SettingKeys
    
    case = get_active_case()
    ai_enabled = SystemSettings.get(SettingKeys.AI_ENABLED, False)
    opencti_rag_enabled = (
        SystemSettings.get(SettingKeys.OPENCTI_ENABLED, False) and
        SystemSettings.get(SettingKeys.OPENCTI_RAG_SYNC, False)
    )
    
    return render_template(
        'case_hunting.html',
        page_title='Hunting',
        case=case,
        ai_enabled=ai_enabled,
        opencti_rag_enabled=opencti_rag_enabled
    )


@main_bp.route('/case/hunting/processes')
@login_required
@case_required
def case_hunting_processes():
    """Process Hunting - unified process analysis across all sources"""
    case = get_active_case()
    return render_template(
        'case_hunting_processes.html',
        page_title='Process Hunting',
        case=case
    )


@main_bp.route('/case/hunting/memory')
@login_required
@case_required
def case_hunting_memory():
    """Memory Hunting - analyze memory forensics artifacts"""
    case = get_active_case()
    return render_template(
        'case_hunting_memory.html',
        page_title='Memory Hunting',
        case=case
    )


@main_bp.route('/case/hunting/network')
@login_required
@case_required
def case_hunting_network():
    """Network Hunting - analyze PCAP/Zeek network artifacts"""
    case = get_active_case()
    return render_template(
        'case_hunting_network.html',
        page_title='Network Hunting',
        case=case
    )


@main_bp.route('/case/pcap-files')
@login_required
@case_required
def case_pcap_files():
    """PCAP Files - upload and manage network capture files"""
    case = get_active_case()
    return render_template(
        'case_pcap_files.html',
        page_title='PCAP Files',
        case=case
    )


@main_bp.route('/case/ioc-management')
@login_required
@case_required
def case_ioc_management():
    """IOC Management - manage indicators of compromise"""
    from models.system_settings import SystemSettings, SettingKeys
    case = get_active_case()
    ai_enabled = SystemSettings.get(SettingKeys.AI_ENABLED, False)
    return render_template('case_ioc_management.html', page_title='IOC Management', case=case, ai_enabled=ai_enabled)


@main_bp.route('/help/search')
@login_required
def search_help():
    """Search Help - comprehensive search syntax documentation"""
    return render_template('search_help.html', page_title='Search Help')


@main_bp.route('/case/known-systems')
@login_required
@case_required
def case_known_systems():
    """Known Systems - track known systems in the case"""
    from models.known_system import OSType, SystemType
    
    case = get_active_case()
    return render_template(
        'case_known_systems.html',
        page_title='Known Systems',
        case=case,
        OSType=OSType,
        SystemType=SystemType
    )


@main_bp.route('/case/known-users')
@login_required
@case_required
def case_known_users():
    """Known Users - track known users in the case"""
    case = get_active_case()
    return render_template(
        'case_known_users.html',
        page_title='Known Users',
        case=case
    )


@main_bp.route('/case/evidence')
@login_required
@case_required
def case_evidence():
    """Evidence - manage case evidence"""
    case = get_active_case()
    return render_template('case_evidence.html', page_title='Evidence', case=case)


@main_bp.route('/case/reports')
@login_required
@case_required
def case_reports():
    """View Reports - list and manage generated reports for the case"""
    case = get_active_case()
    return render_template('case_reports.html', page_title='Reports', case=case)


@main_bp.route('/case/memory-forensics')
@login_required
@case_required
def case_memory_forensics():
    """Memory Forensics - analyze memory dumps and artifacts"""
    case = get_active_case()
    return render_template('case_memory_forensics.html', page_title='Memory Forensics', case=case)


@main_bp.route('/case/edr-report', methods=['GET', 'POST'])
@login_required
@case_required
def case_edr_report():
    """View, add, or edit EDR report for the active case"""
    case = get_active_case()
    
    if request.method == 'POST':
        action = request.form.get('action', 'add')
        report_content = request.form.get('edr_report', '').strip()
        
        if report_content:
            if action == 'edit':
                # Replace entire report content
                case.edr_report = report_content
                db.session.commit()
                flash('EDR Report updated successfully', 'success')
            else:
                # Add new report (append with separator if existing)
                if case.edr_report:
                    case.edr_report = case.edr_report + '\n\n*** NEW REPORT ***\n\n' + report_content
                else:
                    case.edr_report = report_content
                db.session.commit()
                flash('EDR Report added successfully', 'success')
        else:
            flash('EDR Report content cannot be empty', 'error')
        return redirect(url_for('main.case_edr_report'))
    
    return render_template('case_edr_report.html', page_title='EDR Report', case=case)


@main_bp.route('/case/edit', methods=['GET', 'POST'])
@login_required
@case_required
def case_edit():
    """Edit the active case"""
    case = get_active_case()
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        company = request.form.get('company', '').strip()
        description = request.form.get('description', '').strip()
        timezone = request.form.get('timezone', 'UTC').strip()
        router_ips = request.form.get('router_ips', '').strip()
        vpn_ips = request.form.get('vpn_ips', '').strip()
        status = request.form.get('status', '').strip()
        assigned_to = request.form.get('assigned_to', '').strip()
        
        # Remediation fields
        attack_description = request.form.get('attack_description', '').strip()
        containment_actions = request.form.get('containment_actions', '').strip()
        eradication_actions = request.form.get('eradication_actions', '').strip()
        recovery_actions = request.form.get('recovery_actions', '').strip()
        lessons_learned = request.form.get('lessons_learned', '').strip()
        
        # Validate mandatory fields
        if not name:
            flash('Case name is required', 'error')
            clients = Client.get_active_clients()
            users = User.query.filter_by(is_active=True).order_by(User.username).all()
            return render_template('case_edit.html', page_title='Edit Case', case=case, 
                                   CaseStatus=CaseStatus, timezones=COMMON_TIMEZONES, clients=clients, users=users)
        
        if not company:
            flash('Company is required', 'error')
            clients = Client.get_active_clients()
            users = User.query.filter_by(is_active=True).order_by(User.username).all()
            return render_template('case_edit.html', page_title='Edit Case', case=case, 
                                   CaseStatus=CaseStatus, timezones=COMMON_TIMEZONES, clients=clients, users=users)
        
        # Validate timezone
        from utils.timezone import is_valid_timezone
        if not is_valid_timezone(timezone):
            timezone = 'UTC'
        
        # Track changes for audit log
        changes = {}
        if case.name != name:
            changes['name'] = (case.name, name)
        if case.company != company:
            changes['company'] = (case.company, company)
        if (case.description or '') != (description or ''):
            changes['description'] = (case.description, description or None)
        if case.timezone != timezone:
            changes['timezone'] = (case.timezone, timezone)
        if (case.router_ips or '') != (router_ips or ''):
            changes['router_ips'] = (case.router_ips, router_ips or None)
        if (case.vpn_ips or '') != (vpn_ips or ''):
            changes['vpn_ips'] = (case.vpn_ips, vpn_ips or None)
        if status in CaseStatus.all() and case.status != status:
            changes['status'] = (case.status, status)
        if (case.assigned_to or '') != (assigned_to or ''):
            changes['assigned_to'] = (case.assigned_to, assigned_to or None)
        if (case.attack_description or '') != (attack_description or ''):
            changes['attack_description'] = (case.attack_description, attack_description or None)
        if (case.containment_actions or '') != (containment_actions or ''):
            changes['containment_actions'] = (case.containment_actions, containment_actions or None)
        if (case.eradication_actions or '') != (eradication_actions or ''):
            changes['eradication_actions'] = (case.eradication_actions, eradication_actions or None)
        if (case.recovery_actions or '') != (recovery_actions or ''):
            changes['recovery_actions'] = (case.recovery_actions, recovery_actions or None)
        if (case.lessons_learned or '') != (lessons_learned or ''):
            changes['lessons_learned'] = (case.lessons_learned, lessons_learned or None)
        
        # Update the case
        case.name = name
        case.company = company
        case.description = description or None
        case.timezone = timezone
        case.router_ips = router_ips or None
        case.vpn_ips = vpn_ips or None
        if status in CaseStatus.all():
            case.status = status
        case.assigned_to = assigned_to or None
        case.attack_description = attack_description or None
        case.containment_actions = containment_actions or None
        case.eradication_actions = eradication_actions or None
        case.recovery_actions = recovery_actions or None
        case.lessons_learned = lessons_learned or None
        
        db.session.commit()
        
        # Audit log the changes
        if changes:
            audit_update(
                entity_type=AuditEntityType.CASE,
                entity_id=case.uuid,
                changes=changes,
                entity_name=case.name,
                case_uuid=case.uuid
            )
        
        flash('Case updated successfully', 'success')
        return redirect(url_for('main.case_dashboard'))
    
    clients = Client.get_active_clients()
    users = User.query.filter_by(is_active=True).order_by(User.username).all()
    return render_template('case_edit.html', page_title='Edit Case', case=case, 
                           CaseStatus=CaseStatus, timezones=COMMON_TIMEZONES, clients=clients, users=users)


# ============================================
# System Section Routes
# ============================================

@main_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """My Profile - view and edit current user's profile"""
    # Check if user can edit their profile (admin or analyst only)
    can_edit = current_user.is_administrator or current_user.is_analyst
    
    if request.method == 'POST':
        # Viewers cannot edit
        if not can_edit:
            flash('You do not have permission to edit your profile', 'error')
            return redirect(url_for('main.profile'))
        
        # Get form data
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()
        
        # Validate required fields
        if not full_name:
            flash('Full name is required', 'error')
            return render_template('profile.html', page_title='My Profile', can_edit=can_edit, UserSettings=UserSettings)
        
        if not email:
            flash('Email is required', 'error')
            return render_template('profile.html', page_title='My Profile', can_edit=can_edit, UserSettings=UserSettings)
        
        # Check if email is already taken by another user
        existing_user = User.query.filter(User.email == email, User.id != current_user.id).first()
        if existing_user:
            flash('Email is already in use by another user', 'error')
            return render_template('profile.html', page_title='My Profile', can_edit=can_edit, UserSettings=UserSettings)
        
        # Track changes for audit log
        changes = {}
        if current_user.full_name != full_name:
            changes['full_name'] = (current_user.full_name, full_name)
        if current_user.email != email:
            changes['email'] = (current_user.email, email)
        
        # Update user
        current_user.full_name = full_name
        current_user.email = email
        db.session.commit()
        
        # Audit log the changes
        if changes:
            audit_update(
                entity_type=AuditEntityType.SYSTEM_USER,
                entity_id=current_user.id,
                changes=changes,
                entity_name=current_user.username
            )
        
        flash('Profile updated successfully', 'success')
        return redirect(url_for('main.profile'))
    
    return render_template('profile.html', page_title='My Profile', can_edit=can_edit, UserSettings=UserSettings)


@main_bp.route('/profile/change-password', methods=['POST'])
@login_required
def change_password():
    """Change password for current user"""
    # Check if user can edit their profile
    if not (current_user.is_administrator or current_user.is_analyst):
        flash('You do not have permission to change your password', 'error')
        return redirect(url_for('main.profile'))
    
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')
    
    # Verify current password
    if not current_user.check_password(current_password):
        flash('Current password is incorrect', 'error')
        return redirect(url_for('main.profile'))
    
    # Check passwords match
    if new_password != confirm_password:
        flash('New passwords do not match', 'error')
        return redirect(url_for('main.profile'))
    
    # Validate new password
    is_valid, error_msg = User.validate_password(new_password)
    if not is_valid:
        flash(error_msg, 'error')
        return redirect(url_for('main.profile'))
    
    # Update password
    current_user.set_password(new_password)
    db.session.commit()
    
    # Audit log the password change
    AuditLog.log(
        entity_type=AuditEntityType.SYSTEM_USER,
        entity_id=current_user.id,
        action=AuditAction.PASSWORD_CHANGED,
        entity_name=current_user.username
    )
    
    flash('Password changed successfully', 'success')
    return redirect(url_for('main.profile'))


def admin_required(f):
    """Decorator to require administrator permission"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_administrator:
            flash('Administrator access required', 'error')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function


def analyst_or_admin_required(f):
    """Decorator to require analyst or administrator permission"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not (current_user.is_analyst or current_user.is_administrator):
            flash('Access denied - Analyst or Administrator access required', 'error')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function


@main_bp.route('/users')
@login_required
@admin_required
def users():
    """User Management - list all users"""
    all_users = User.query.order_by(User.created_at.desc()).all()
    return render_template(
        'users.html',
        page_title='Users',
        users=all_users,
        PermissionLevel=PermissionLevel
    )


@main_bp.route('/users/new', methods=['GET', 'POST'])
@login_required
@admin_required
def user_create():
    """Create new user"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        permission_level = request.form.get('permission_level', PermissionLevel.VIEWER)
        
        # Validate required fields
        if not username:
            flash('Username is required', 'error')
            return render_template('user_edit.html', page_title='Create User', user=None, 
                                   PermissionLevel=PermissionLevel, UserSettings=UserSettings, is_new=True)
        
        if not full_name:
            flash('Full name is required', 'error')
            return render_template('user_edit.html', page_title='Create User', user=None,
                                   PermissionLevel=PermissionLevel, UserSettings=UserSettings, is_new=True)
        
        if not email:
            flash('Email is required', 'error')
            return render_template('user_edit.html', page_title='Create User', user=None,
                                   PermissionLevel=PermissionLevel, UserSettings=UserSettings, is_new=True)
        
        if not password:
            flash('Password is required', 'error')
            return render_template('user_edit.html', page_title='Create User', user=None,
                                   PermissionLevel=PermissionLevel, UserSettings=UserSettings, is_new=True)
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('user_edit.html', page_title='Create User', user=None,
                                   PermissionLevel=PermissionLevel, UserSettings=UserSettings, is_new=True)
        
        # Validate password requirements
        is_valid, error_msg = User.validate_password(password)
        if not is_valid:
            flash(error_msg, 'error')
            return render_template('user_edit.html', page_title='Create User', user=None,
                                   PermissionLevel=PermissionLevel, UserSettings=UserSettings, is_new=True)
        
        # Check if username already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return render_template('user_edit.html', page_title='Create User', user=None,
                                   PermissionLevel=PermissionLevel, UserSettings=UserSettings, is_new=True)
        
        # Check if email already exists
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'error')
            return render_template('user_edit.html', page_title='Create User', user=None,
                                   PermissionLevel=PermissionLevel, UserSettings=UserSettings, is_new=True)
        
        # Validate permission level
        if permission_level not in PermissionLevel.all():
            permission_level = PermissionLevel.VIEWER
        
        # Create user
        user = User(
            username=username,
            full_name=full_name,
            email=email,
            permission_level=permission_level,
            created_by=current_user.username
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        # Audit log user creation
        AuditLog.log(
            entity_type=AuditEntityType.SYSTEM_USER,
            entity_id=user.id,
            action=AuditAction.CREATED,
            entity_name=username,
            details={
                'full_name': full_name,
                'email': email,
                'permission_level': permission_level
            }
        )
        
        flash(f'User "{username}" created successfully', 'success')
        return redirect(url_for('main.users'))
    
    return render_template('user_edit.html', page_title='Create User', user=None,
                           PermissionLevel=PermissionLevel, UserSettings=UserSettings, is_new=True)


@main_bp.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def user_edit(user_id):
    """Edit existing user"""
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()
        permission_level = request.form.get('permission_level', user.permission_level)
        is_active = request.form.get('is_active') == 'on'
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validate required fields
        if not full_name:
            flash('Full name is required', 'error')
            return render_template('user_edit.html', page_title='Edit User', user=user,
                                   PermissionLevel=PermissionLevel, UserSettings=UserSettings, is_new=False)
        
        if not email:
            flash('Email is required', 'error')
            return render_template('user_edit.html', page_title='Edit User', user=user,
                                   PermissionLevel=PermissionLevel, UserSettings=UserSettings, is_new=False)
        
        # Check if email is taken by another user
        existing_user = User.query.filter(User.email == email, User.id != user.id).first()
        if existing_user:
            flash('Email already in use by another user', 'error')
            return render_template('user_edit.html', page_title='Edit User', user=user,
                                   PermissionLevel=PermissionLevel, UserSettings=UserSettings, is_new=False)
        
        # Validate permission level
        if permission_level not in PermissionLevel.all():
            permission_level = user.permission_level
        
        # Track changes for audit log
        changes = {}
        if user.full_name != full_name:
            changes['full_name'] = (user.full_name, full_name)
        if user.email != email:
            changes['email'] = (user.email, email)
        if user.permission_level != permission_level:
            changes['permission_level'] = (user.permission_level, permission_level)
        if user.is_active != is_active:
            changes['is_active'] = (user.is_active, is_active)
        
        password_changed = False
        
        # Update user
        user.full_name = full_name
        user.email = email
        user.permission_level = permission_level
        user.is_active = is_active
        
        # Update password if provided
        if new_password:
            if new_password != confirm_password:
                flash('Passwords do not match', 'error')
                return render_template('user_edit.html', page_title='Edit User', user=user,
                                       PermissionLevel=PermissionLevel, UserSettings=UserSettings, is_new=False)
            
            is_valid, error_msg = User.validate_password(new_password)
            if not is_valid:
                flash(error_msg, 'error')
                return render_template('user_edit.html', page_title='Edit User', user=user,
                                       PermissionLevel=PermissionLevel, UserSettings=UserSettings, is_new=False)
            
            user.set_password(new_password)
            password_changed = True
        
        db.session.commit()
        
        # Audit log the changes
        if changes:
            audit_update(
                entity_type=AuditEntityType.SYSTEM_USER,
                entity_id=user.id,
                changes=changes,
                entity_name=user.username
            )
        
        # Separate audit entry for password reset by admin
        if password_changed:
            AuditLog.log(
                entity_type=AuditEntityType.SYSTEM_USER,
                entity_id=user.id,
                action=AuditAction.PASSWORD_CHANGED,
                entity_name=user.username,
                details={'reset_by': 'administrator'}
            )
        
        flash(f'User "{user.username}" updated successfully', 'success')
        return redirect(url_for('main.users'))
    
    return render_template('user_edit.html', page_title='Edit User', user=user,
                           PermissionLevel=PermissionLevel, UserSettings=UserSettings, is_new=False)


@main_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def user_delete(user_id):
    """Delete a user"""
    user = User.query.get_or_404(user_id)
    
    # Prevent deleting yourself
    if user.id == current_user.id:
        flash('You cannot delete your own account', 'error')
        return redirect(url_for('main.users'))
    
    username = user.username
    db.session.delete(user)
    db.session.commit()
    
    flash(f'User "{username}" deleted successfully', 'success')
    return redirect(url_for('main.users'))


@main_bp.route('/logs')
@login_required
@analyst_or_admin_required
def logs():
    """Logs page with System Logs and Audit Logs tabs
    
    Tab permissions:
    - System Logs: analyst or administrator
    - Audit Logs: administrator only
    """
    tab = request.args.get('tab', 'system')
    
    # Determine accessible tabs based on user role
    is_admin = current_user.is_administrator
    
    # Check tab permission - audit logs are admin only
    tab_denied = False
    if tab == 'audit' and not is_admin:
        tab_denied = True
    
    return render_template('logs.html',
                           page_title='Logs',
                           active_tab=tab,
                           tab_denied=tab_denied,
                           is_admin=is_admin)


@main_bp.route('/settings')
@login_required
@analyst_or_admin_required
def settings():
    """System Settings page
    
    Tab permissions:
    - General, AI, Integrations, Logging, Audit, Reports: administrators only
    - EVTX/SIGMA, Noise: analyst or administrator
    
    Note: Audit tab is admin-only to protect the immutable forensic audit trail.
    Note: Reports tab is admin-only to manage report templates.
    """
    from models.system_settings import SystemSettings, SettingKeys
    
    tab = request.args.get('tab', None)
    
    # Define tab permissions - audit is now admin-only (immutable forensic trail)
    # Reports tab is admin-only to manage report templates
    admin_only_tabs = ['general', 'ai', 'integrations', 'logging', 'audit', 'reports', 'paths']
    analyst_tabs = ['evtx', 'noise']  # Accessible by analyst or admin
    
    # Determine accessible tabs based on user role
    is_admin = current_user.is_administrator
    
    # Set default tab based on user role
    if tab is None:
        tab = 'general' if is_admin else 'evtx'
    
    # Check tab permission
    tab_denied = False
    if tab in admin_only_tabs and not is_admin:
        tab_denied = True
    
    # Get AI settings for the AI tab
    ai_enabled = SystemSettings.get(SettingKeys.AI_ENABLED, False)
    ai_default_model = SystemSettings.get(SettingKeys.AI_DEFAULT_MODEL, None)
    
    return render_template('settings.html', 
                           page_title='Settings', 
                           active_tab=tab,
                           tab_denied=tab_denied,
                           is_admin=is_admin,
                           ai_enabled=ai_enabled,
                           ai_default_model=ai_default_model)


# ============================================
# Client Routes
# ============================================

def get_active_client():
    """Get the currently active client from session"""
    if 'active_client_uuid' in session:
        from models.client import Client
        return Client.get_by_uuid(session['active_client_uuid'])
    return None


@main_bp.route('/clients')
@login_required
def clients():
    """Client Selection - list all clients"""
    from models.client import Client
    all_clients = Client.query.filter_by(is_active=True).order_by(Client.name).all()
    return render_template(
        'clients.html',
        page_title='Clients',
        clients=all_clients
    )


@main_bp.route('/client/<client_uuid>')
@login_required
def client_dashboard(client_uuid):
    """Client Dashboard - overview of a specific client"""
    from models.client import Client
    from models.agent import Agent
    
    client = Client.get_by_uuid(client_uuid)
    if not client:
        flash('Client not found', 'error')
        return redirect(url_for('main.clients'))
    
    # Store in session
    session['active_client_uuid'] = client_uuid
    
    # Get cases for this client
    cases = Case.query.filter_by(client_id=client.id).order_by(Case.created_at.desc()).all()
    
    # Count active cases (not finished or archived)
    active_cases = len([c for c in cases if c.status not in ['finished', 'archived']])
    
    # Get agents for this client
    agents = Agent.get_agents_for_client(client.id)
    online_agents = len([a for a in agents if a.status == 'online'])
    
    return render_template(
        'client_dashboard.html',
        page_title=f'{client.name}',
        client=client,
        cases=cases,
        active_cases=active_cases,
        agents=agents,
        online_agents=online_agents
    )


@main_bp.route('/client/<client_uuid>/case/new', methods=['GET', 'POST'])
@login_required
def client_case_create(client_uuid):
    """Create new case for a specific client"""
    from models.client import Client
    
    client = Client.get_by_uuid(client_uuid)
    if not client:
        flash('Client not found', 'error')
        return redirect(url_for('main.clients'))
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        timezone = request.form.get('timezone', client.timezone).strip()
        router_ips = request.form.get('router_ips', '').strip()
        vpn_ips = request.form.get('vpn_ips', '').strip()
        
        if not name:
            flash('Case name is required', 'error')
            return render_template('case_create.html', page_title='Create Case',
                                   client=client, timezones=COMMON_TIMEZONES, 
                                   detected_tz=client.timezone)
        
        from utils.timezone import is_valid_timezone
        if not is_valid_timezone(timezone):
            flash('Invalid timezone selected', 'error')
            return render_template('case_create.html', page_title='Create Case',
                                   client=client, timezones=COMMON_TIMEZONES,
                                   detected_tz=client.timezone)
        
        case = Case(
            name=name,
            company=client.name,
            client_id=client.id,
            description=description or None,
            timezone=timezone,
            router_ips=router_ips or None,
            vpn_ips=vpn_ips or None,
            created_by=current_user.username
        )
        
        db.session.add(case)
        db.session.commit()
        
        AuditLog.log(
            entity_type=AuditEntityType.CASE,
            entity_id=case.uuid,
            action=AuditAction.CREATED,
            entity_name=name,
            case_uuid=case.uuid,
            details={
                'client': client.code,
                'company': client.name,
                'timezone': timezone
            }
        )
        
        sftp_case_folder = os.path.join(Config.UPLOAD_FOLDER_SFTP, case.uuid)
        os.makedirs(sftp_case_folder, exist_ok=True)
        
        flash(f'Case "{name}" created successfully', 'success')
        return redirect(url_for('main.client_dashboard', client_uuid=client_uuid))
    
    return render_template('case_create.html', page_title='Create Case',
                           client=client, timezones=COMMON_TIMEZONES,
                           detected_tz=client.timezone)


# ============================================
# Admin Client Management Routes
# ============================================

@main_bp.route('/admin/clients')
@login_required
@admin_required
def admin_clients():
    """Admin: Manage all clients"""
    from models.client import Client
    all_clients = Client.query.order_by(Client.name).all()
    return render_template(
        'admin_clients.html',
        page_title='Manage Clients',
        clients=all_clients
    )


@main_bp.route('/admin/clients/new', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_client_create():
    """Admin: Create new client"""
    from models.client import Client
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        code = request.form.get('code', '').strip().upper()
        timezone = request.form.get('timezone', 'UTC').strip()
        contact_name = request.form.get('contact_name', '').strip()
        contact_email = request.form.get('contact_email', '').strip()
        notes = request.form.get('notes', '').strip()
        
        if not name:
            flash('Client name is required', 'error')
            return render_template('admin_client_edit.html', page_title='Create Client',
                                   client=None, is_new=True, timezones=COMMON_TIMEZONES)
        
        if not code:
            code = Client.generate_code_from_name(name)
        
        if Client.query.filter_by(code=code).first():
            flash(f'Client code "{code}" already exists', 'error')
            return render_template('admin_client_edit.html', page_title='Create Client',
                                   client=None, is_new=True, timezones=COMMON_TIMEZONES)
        
        client = Client(
            name=name,
            code=code,
            timezone=timezone,
            contact_name=contact_name or None,
            contact_email=contact_email or None,
            notes=notes or None,
            created_by=current_user.username
        )
        
        db.session.add(client)
        db.session.commit()
        
        AuditLog.log(
            entity_type=AuditEntityType.CLIENT,
            entity_id=client.uuid,
            action=AuditAction.CREATED,
            entity_name=f'Client: {name}',
            details={'code': code}
        )
        
        flash(f'Client "{name}" created successfully', 'success')
        return redirect(url_for('main.admin_clients'))
    
    return render_template('admin_client_edit.html', page_title='Create Client',
                           client=None, is_new=True, timezones=COMMON_TIMEZONES)


@main_bp.route('/admin/clients/<client_uuid>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_client_edit(client_uuid):
    """Admin: Edit existing client"""
    from models.client import Client
    
    client = Client.get_by_uuid(client_uuid)
    if not client:
        flash('Client not found', 'error')
        return redirect(url_for('main.admin_clients'))
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        timezone = request.form.get('timezone', 'UTC').strip()
        contact_name = request.form.get('contact_name', '').strip()
        contact_email = request.form.get('contact_email', '').strip()
        notes = request.form.get('notes', '').strip()
        is_active = request.form.get('is_active') == 'on'
        
        if not name:
            flash('Client name is required', 'error')
            return render_template('admin_client_edit.html', page_title='Edit Client',
                                   client=client, is_new=False, timezones=COMMON_TIMEZONES)
        
        changes = {}
        if client.name != name:
            changes['name'] = (client.name, name)
        if client.timezone != timezone:
            changes['timezone'] = (client.timezone, timezone)
        if (client.contact_name or '') != (contact_name or ''):
            changes['contact_name'] = (client.contact_name, contact_name or None)
        if (client.contact_email or '') != (contact_email or ''):
            changes['contact_email'] = (client.contact_email, contact_email or None)
        if client.is_active != is_active:
            changes['is_active'] = (client.is_active, is_active)
        
        client.name = name
        client.timezone = timezone
        client.contact_name = contact_name or None
        client.contact_email = contact_email or None
        client.notes = notes or None
        client.is_active = is_active
        
        db.session.commit()
        
        if changes:
            audit_update(
                entity_type=AuditEntityType.CLIENT,
                entity_id=client.uuid,
                changes=changes,
                entity_name=f'Client: {client.name}'
            )
        
        flash(f'Client "{name}" updated successfully', 'success')
        return redirect(url_for('main.admin_clients'))
    
    return render_template('admin_client_edit.html', page_title='Edit Client',
                           client=client, is_new=False, timezones=COMMON_TIMEZONES)


@main_bp.route('/admin/clients/<client_uuid>/delete', methods=['POST'])
@login_required
@admin_required
def admin_client_delete(client_uuid):
    """Admin: Delete a client"""
    from models.client import Client
    
    client = Client.get_by_uuid(client_uuid)
    if not client:
        flash('Client not found', 'error')
        return redirect(url_for('main.admin_clients'))
    
    if client.case_count > 0 or client.agent_count > 0:
        flash('Cannot delete client with existing cases or agents', 'error')
        return redirect(url_for('main.admin_client_edit', client_uuid=client_uuid))
    
    client_name = client.name
    db.session.delete(client)
    db.session.commit()
    
    flash(f'Client "{client_name}" deleted successfully', 'success')
    return redirect(url_for('main.admin_clients'))


# ============================================
# Admin Case Management Routes
# ============================================

@main_bp.route('/admin/cases')
@login_required
@admin_required
def admin_cases():
    """Admin: Manage all cases across all clients"""
    from models.client import Client
    
    all_cases = Case.query.order_by(Case.created_at.desc()).all()
    all_clients = Client.query.order_by(Client.code).all()
    
    return render_template(
        'admin_cases.html',
        page_title='Manage Cases',
        cases=all_cases,
        clients=all_clients
    )
