"""Main routes for CaseScope"""
import os
from functools import wraps
from flask import Blueprint, render_template, redirect, url_for, request, flash, session, jsonify
from flask_login import login_required, current_user
from models.database import db
from models.case import Case, CaseStatus, COMMON_TIMEZONES
from models.user import User
from config import Config, PermissionLevel, UserSettings

main_bp = Blueprint('main', __name__)


def case_required(f):
    """Decorator to require an active case in session"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'active_case_uuid' not in session:
            flash('Please select a case first', 'warning')
            return redirect(url_for('main.cases'))
        # Verify the case still exists
        case = Case.get_by_uuid(session['active_case_uuid'])
        if not case:
            session.pop('active_case_uuid', None)
            flash('Selected case no longer exists. Please select another case.', 'error')
            return redirect(url_for('main.cases'))
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
        return redirect(url_for('main.cases'))
    
    session['active_case_uuid'] = case_uuid
    flash(f'Case "{case.name}" selected', 'success')
    return redirect(url_for('main.case_dashboard'))


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
    return render_template('case_dashboard.html', page_title='Case Dashboard', case=case)


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
        
        # Validate mandatory fields
        if not name:
            flash('Case name is required', 'error')
            return render_template('case_edit.html', page_title='Edit Case', case=case, 
                                   CaseStatus=CaseStatus, timezones=COMMON_TIMEZONES)
        
        if not company:
            flash('Company is required', 'error')
            return render_template('case_edit.html', page_title='Edit Case', case=case, 
                                   CaseStatus=CaseStatus, timezones=COMMON_TIMEZONES)
        
        # Validate timezone
        from utils.timezone import is_valid_timezone
        if not is_valid_timezone(timezone):
            timezone = 'UTC'
        
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
        
        db.session.commit()
        flash('Case updated successfully', 'success')
        return redirect(url_for('main.case_dashboard'))
    
    return render_template('case_edit.html', page_title='Edit Case', case=case, 
                           CaseStatus=CaseStatus, timezones=COMMON_TIMEZONES)


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
        
        # Update user
        current_user.full_name = full_name
        current_user.email = email
        db.session.commit()
        
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
        
        db.session.commit()
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
    - General, AI, Integrations, Logging: administrators only
    - EVTX/SIGMA, Noise: analyst or administrator
    - Audit: based on audit_view_permission setting
    """
    from models.system_settings import SystemSettings, SettingKeys
    
    tab = request.args.get('tab', None)
    
    # Define tab permissions
    admin_only_tabs = ['general', 'ai', 'integrations', 'logging']
    analyst_tabs = ['evtx', 'noise']  # Accessible by analyst or admin
    
    # Determine accessible tabs based on user role
    is_admin = current_user.is_administrator
    
    # Check audit tab permission based on setting
    audit_permission = SystemSettings.get(SettingKeys.AUDIT_VIEW_PERMISSION, 'administrator')
    can_view_audit = is_admin or (audit_permission == 'analyst' and current_user.is_analyst)
    
    # Set default tab based on user role
    if tab is None:
        tab = 'general' if is_admin else 'evtx'
    
    # Check tab permission
    tab_denied = False
    if tab in admin_only_tabs and not is_admin:
        tab_denied = True
    elif tab == 'audit' and not can_view_audit:
        tab_denied = True
    
    # Get AI settings for the AI tab
    ai_enabled = SystemSettings.get(SettingKeys.AI_ENABLED, False)
    ai_default_model = SystemSettings.get(SettingKeys.AI_DEFAULT_MODEL, None)
    
    return render_template('settings.html', 
                           page_title='Settings', 
                           active_tab=tab,
                           tab_denied=tab_denied,
                           is_admin=is_admin,
                           can_view_audit=can_view_audit,
                           ai_enabled=ai_enabled,
                           ai_default_model=ai_default_model)
