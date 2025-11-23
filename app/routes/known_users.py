"""
Known Users Management Routes
Handles legitimate/valid users in the environment (not CaseScope app users)
"""

from flask import Blueprint, render_template, request, redirect, url_for, jsonify, flash
from flask_login import login_required, current_user
from datetime import datetime
import csv
import io

known_users_bp = Blueprint('known_users', __name__)


@known_users_bp.route('/case/<int:case_id>/known_users')
@login_required
def list_known_users(case_id):
    """Known Users management page - Case-specific"""
    from main import db
    from models import KnownUser, Case
    
    # Verify case exists
    case = db.session.get(Case, case_id)
    if not case:
        flash('Case not found', 'error')
        return redirect(url_for('dashboard'))
    
    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    search_query = request.args.get('search', '').strip()
    
    # Base query - filter by case_id
    query = KnownUser.query.filter_by(case_id=case_id)
    
    # Apply search filter
    if search_query:
        query = query.filter(KnownUser.username.ilike(f'%{search_query}%'))
    
    # Get paginated results
    pagination = query.order_by(KnownUser.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    known_users = pagination.items
    
    # Calculate stats - case-specific
    total_users = KnownUser.query.filter_by(case_id=case_id).count()
    domain_users = KnownUser.query.filter_by(case_id=case_id, user_type='domain').count()
    local_users = KnownUser.query.filter_by(case_id=case_id, user_type='local').count()
    compromised_users = KnownUser.query.filter_by(case_id=case_id, compromised=True).count()
    active_users = KnownUser.query.filter_by(case_id=case_id, active=True).count()  # v1.20.0
    inactive_users = KnownUser.query.filter_by(case_id=case_id, active=False).count()  # v1.20.0
    
    return render_template('known_users.html',
                         case=case,
                         case_id=case_id,
                         known_users=known_users,
                         pagination=pagination,
                         search_query=search_query,
                         total_users=total_users,
                         domain_users=domain_users,
                         local_users=local_users,
                         compromised_users=compromised_users,
                         active_users=active_users,
                         inactive_users=inactive_users)


@known_users_bp.route('/case/<int:case_id>/known_users/add', methods=['POST'])
@login_required
def add_known_user(case_id):
    """Add new known user manually - Case-specific"""
    # Permission check: Read-only users cannot add
    if current_user.role == 'read-only':
        return jsonify({'success': False, 'error': 'Read-only users cannot add known users'}), 403
    
    from main import db
    from models import KnownUser, Case
    from known_user_ioc_sync import sync_user_to_ioc  # v1.21.0: IOC integration
    
    # Verify case exists
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    try:
        username = request.form.get('username', '').strip()
        user_type = request.form.get('user_type', 'unknown').strip()  # v1.21.0: Default to 'unknown'
        user_sid = request.form.get('user_sid', '').strip() or None  # v1.21.0: Optional SID
        compromised = request.form.get('compromised') == 'true'
        active = request.form.get('active', 'true') == 'true'
        
        if not username:
            return jsonify({'success': False, 'error': 'Username is required'}), 400
        
        # v1.21.0: Validate user_type (domain, local, unknown, invalid)
        if user_type not in ['domain', 'local', 'unknown', 'invalid']:
            user_type = 'unknown'
        
        # Check for duplicate within this case (case-insensitive)
        existing = KnownUser.query.filter(
            KnownUser.case_id == case_id,
            db.func.lower(KnownUser.username) == username.lower()
        ).first()
        if existing:
            return jsonify({'success': False, 'error': f'User "{username}" already exists in this case'}), 400
        
        # Create known user
        known_user = KnownUser(
            case_id=case_id,
            username=username,
            user_type=user_type,
            user_sid=user_sid,  # v1.21.0
            compromised=compromised,
            active=active,
            added_method='manual',
            added_by=current_user.id
        )
        db.session.add(known_user)
        db.session.commit()
        
        # v1.21.0: If user is compromised, auto-create IOC
        ioc_created = False
        if compromised:
            success, ioc_id, msg = sync_user_to_ioc(
                case_id=case_id,
                username=username,
                user_id=known_user.id,
                current_user_id=current_user.id,
                description=f'Compromised user added manually (SID: {user_sid or "N/A"})',
                user_sid=user_sid  # v1.24.0: Pass SID to create inactive user_sid IOC
            )
            ioc_created = success and ioc_id is not None
        
        # Audit log
        from audit_logger import log_action
        log_action('add_known_user', resource_type='known_user', resource_id=known_user.id,
                  resource_name=username,
                  details={
                      'case_id': case_id,
                      'case_name': case.name,
                      'user_type': user_type,
                      'user_sid': user_sid,
                      'compromised': compromised,
                      'active': active,
                      'ioc_created': ioc_created  # v1.21.0: Track if IOC was created
                  })
        
        flash_msg = f'Known user added: {username}'
        if ioc_created:
            flash_msg += ' (IOC created automatically)'
        flash(flash_msg, 'success')
        
        return jsonify({
            'success': True,
            'user_id': known_user.id,
            'ioc_created': ioc_created  # v1.21.0: Inform frontend
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@known_users_bp.route('/case/<int:case_id>/known_users/<int:user_id>/get', methods=['GET'])
@login_required
def get_known_user(case_id, user_id):
    """Get single known user data for editing - Case-specific"""
    from main import db
    from models import KnownUser
    
    try:
        known_user = db.session.get(KnownUser, user_id)
        if not known_user:
            return jsonify({'success': False, 'error': 'Known user not found'}), 404
        
        # Verify user belongs to this case
        if known_user.case_id != case_id:
            return jsonify({'success': False, 'error': 'User does not belong to this case'}), 403
        
        return jsonify({
            'success': True,
            'user': {
                'id': known_user.id,
                'username': known_user.username,
                'user_type': known_user.user_type,
                'user_sid': known_user.user_sid,  # v1.21.0
                'compromised': known_user.compromised,
                'active': known_user.active
            }
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@known_users_bp.route('/case/<int:case_id>/known_users/<int:user_id>/update', methods=['POST'])
@login_required
def update_known_user(case_id, user_id):
    """Update known user - Case-specific"""
    # Permission check: Read-only users cannot update
    if current_user.role == 'read-only':
        return jsonify({'success': False, 'error': 'Read-only users cannot update known users'}), 403
    
    from main import db
    from models import KnownUser
    from known_user_ioc_sync import sync_user_to_ioc  # v1.21.0: IOC integration
    
    try:
        known_user = db.session.get(KnownUser, user_id)
        if not known_user:
            return jsonify({'success': False, 'error': 'Known user not found'}), 404
        
        # Verify user belongs to this case
        if known_user.case_id != case_id:
            return jsonify({'success': False, 'error': 'User does not belong to this case'}), 403
        
        # Track old values for IOC sync and audit logging
        old_username = known_user.username
        old_type = known_user.user_type
        old_compromised = known_user.compromised
        old_active = known_user.active
        old_sid = known_user.user_sid
        
        # Update fields
        if 'username' in request.form:
            new_username = request.form['username'].strip()
            if not new_username:
                return jsonify({'success': False, 'error': 'Username cannot be empty'}), 400
            
            # Check for duplicate within this case (excluding current user, case-insensitive)
            existing = KnownUser.query.filter(
                KnownUser.case_id == case_id,
                db.func.lower(KnownUser.username) == new_username.lower(),
                KnownUser.id != user_id
            ).first()
            if existing:
                return jsonify({'success': False, 'error': f'User "{new_username}" already exists in this case'}), 400
            
            known_user.username = new_username
        
        if 'user_type' in request.form:
            user_type = request.form['user_type'].strip()
            # v1.21.0: Support new types (domain, local, unknown, invalid)
            if user_type in ['domain', 'local', 'unknown', 'invalid']:
                known_user.user_type = user_type
        
        if 'user_sid' in request.form:  # v1.21.0: Optional SID
            user_sid = request.form['user_sid'].strip() or None
            known_user.user_sid = user_sid
        
        if 'compromised' in request.form:
            known_user.compromised = request.form['compromised'] == 'true'
        
        if 'active' in request.form:
            known_user.active = request.form['active'] == 'true'
        
        db.session.commit()
        
        # v1.21.0 / v1.24.0: IOC synchronization when compromised status changes
        ioc_created = False
        if not old_compromised and known_user.compromised:
            # User became compromised → Create username IOC + user_sid IOC (if SID present)
            success, ioc_id, msg = sync_user_to_ioc(
                case_id=case_id,
                username=known_user.username,
                user_id=known_user.id,
                current_user_id=current_user.id,
                description=f'User marked compromised (Type: {known_user.user_type}, SID: {known_user.user_sid or "N/A"})',
                user_sid=known_user.user_sid  # v1.24.0: Pass SID to create inactive user_sid IOC
            )
            ioc_created = success and ioc_id is not None
        
        # Audit log
        from audit_logger import log_action
        log_action('update_known_user', resource_type='known_user', resource_id=user_id,
                  resource_name=known_user.username,
                  details={
                      'case_id': case_id,
                      'username': {'old': old_username, 'new': known_user.username},
                      'user_type': {'old': old_type, 'new': known_user.user_type},
                      'user_sid': {'old': old_sid, 'new': known_user.user_sid},  # v1.21.0
                      'compromised': {'old': old_compromised, 'new': known_user.compromised},
                      'active': {'old': old_active, 'new': known_user.active},
                      'ioc_created': ioc_created  # v1.21.0
                  })
        
        flash_msg = 'Known user updated'
        if ioc_created:
            flash_msg += ' (IOC created automatically)'
        flash(flash_msg, 'success')
        
        return jsonify({
            'success': True,
            'ioc_created': ioc_created  # v1.21.0
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500
        
        db.session.commit()
        
        # Audit log
        from audit_logger import log_action
        from main import Case
        case = db.session.get(Case, case_id)
        changes = {}
        if old_username != known_user.username:
            changes['username'] = {'old': old_username, 'new': known_user.username}
        if old_type != known_user.user_type:
            changes['user_type'] = {'old': old_type, 'new': known_user.user_type}
        if old_compromised != known_user.compromised:
            changes['compromised'] = {'old': old_compromised, 'new': known_user.compromised}
        if old_active != known_user.active:
            changes['active'] = {'old': old_active, 'new': known_user.active}
        log_action('update_known_user', resource_type='known_user', resource_id=user_id,
                  resource_name=known_user.username,
                  details={
                      'case_id': case_id,
                      'case_name': case.name if case else None,
                      'changes': changes
                  })
        
        flash(f'Known user updated: {known_user.username}', 'success')
        return jsonify({'success': True})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@known_users_bp.route('/case/<int:case_id>/known_users/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_known_user(case_id, user_id):
    """Delete known user - Case-specific"""
    # Permission check: Only administrators can delete
    if current_user.role not in ['administrator']:
        return jsonify({'success': False, 'error': 'Only administrators can delete known users'}), 403
    
    from main import db
    from models import KnownUser
    
    try:
        known_user = db.session.get(KnownUser, user_id)
        if not known_user:
            return jsonify({'success': False, 'error': 'Known user not found'}), 404
        
        # Verify user belongs to this case
        if known_user.case_id != case_id:
            return jsonify({'success': False, 'error': 'User does not belong to this case'}), 403
        
        username = known_user.username
        user_type = known_user.user_type
        from main import Case
        case = db.session.get(Case, case_id)
        
        db.session.delete(known_user)
        db.session.commit()
        
        # Audit log
        from audit_logger import log_action
        log_action('delete_known_user', resource_type='known_user', resource_id=user_id,
                  resource_name=username,
                  details={
                      'case_id': case_id,
                      'case_name': case.name if case else None,
                      'user_type': user_type
                  })
        
        flash(f'Known user deleted: {username}', 'success')
        return jsonify({'success': True})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@known_users_bp.route('/case/<int:case_id>/known_users/upload_csv', methods=['POST'])
@login_required
def upload_csv(case_id):
    """Upload CSV file with known users - Case-specific"""
    # Permission check: Read-only users cannot upload
    if current_user.role == 'read-only':
        return jsonify({'success': False, 'error': 'Read-only users cannot upload CSV'}), 403
    
    from main import db
    from models import KnownUser, Case
    from known_user_ioc_sync import sync_user_to_ioc  # v1.21.0: IOC integration
    
    # Verify case exists
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    if 'csv_file' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded'}), 400
    
    file = request.files['csv_file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'}), 400
    
    if not file.filename.endswith('.csv'):
        return jsonify({'success': False, 'error': 'File must be a CSV'}), 400
    
    try:
        # Read CSV file (utf-8-sig handles BOM characters)
        stream = io.StringIO(file.stream.read().decode("utf-8-sig"), newline=None)
        csv_reader = csv.DictReader(stream)
        
        # Build case-insensitive header mapping
        if not csv_reader.fieldnames:
            return jsonify({'success': False, 'error': 'CSV file is empty or invalid'}), 400
        
        header_map = {h.lower().strip(): h for h in csv_reader.fieldnames}
        
        # Validate required headers
        if 'username' not in header_map:
            return jsonify({'success': False, 'error': f'CSV must have "Username" column. Found columns: {", ".join(csv_reader.fieldnames)}'}), 400
        
        added_count = 0
        updated_count = 0  # v1.24.0: Track updates
        skipped_count = 0
        iocs_created_count = 0  # v1.21.0: Track IOCs created
        errors = []
        
        # Pre-load existing usernames for this case (case-insensitive)
        existing_users = db.session.query(KnownUser).filter_by(case_id=case_id).all()
        existing_usernames = {user.username.lower() for user in existing_users}
        
        # Track usernames seen in this CSV to prevent duplicates within the file
        seen_usernames = set()
        
        for row_num, row in enumerate(csv_reader, start=2):  # start=2 because row 1 is headers
            try:
                # Extract data using case-insensitive mapping
                username_col = header_map.get('username')
                type_col = header_map.get('type')
                compromised_col = header_map.get('compromised')
                active_col = header_map.get('active')
                usersid_col = header_map.get('usersid')  # v1.21.0: SID field
                
                username = row.get(username_col, '').strip() if username_col else ''
                user_type = row.get(type_col, 'unknown').strip().lower() if type_col else 'unknown'  # v1.21.0: Default to 'unknown'
                compromised_str = row.get(compromised_col, 'false').strip().lower() if compromised_col else 'false'
                active_str = row.get(active_col, 'true').strip().lower() if active_col else 'true'
                user_sid = row.get(usersid_col, '').strip() if usersid_col else None  # v1.21.0
                
                if not username:
                    skipped_count += 1
                    continue
                
                # v1.21.0: Validate user_type (domain, local, unknown, invalid)
                if user_type not in ['domain', 'local', 'unknown', 'invalid']:
                    user_type = 'unknown'
                
                # Parse compromised
                compromised = compromised_str in ['true', 't', 'yes', 'y', '1']
                
                # Parse active
                active = active_str in ['true', 't', 'yes', 'y', '1']
                
                # Check for duplicate (case-insensitive) in DB or already seen in this CSV
                username_lower = username.lower()
                if username_lower in existing_usernames or username_lower in seen_usernames:
                    skipped_count += 1
                    continue
                
                # Track this username as seen
                seen_usernames.add(username_lower)
                
                # v1.26.0: Check if username IOC already exists - if so, mark as compromised
                if not compromised:  # Only check if not already marked compromised in CSV
                    from models import IOC
                    existing_username_ioc = db.session.query(IOC).filter(
                        IOC.case_id == case_id,
                        db.func.lower(IOC.ioc_value) == username_lower,
                        IOC.ioc_type == 'username'
                    ).first()
                    if existing_username_ioc:
                        compromised = True  # Auto-mark as compromised if IOC exists
                
                # Create known user
                known_user = KnownUser(
                    case_id=case_id,
                    username=username,
                    user_type=user_type,
                    user_sid=user_sid if user_sid else None,  # v1.21.0
                    compromised=compromised,
                    active=active,
                    added_method='csv',
                    added_by=current_user.id
                )
                db.session.add(known_user)
                db.session.flush()  # Get ID before IOC sync
                added_count += 1
                
                # v1.21.0 / v1.24.0: If user is compromised, create username + user_sid IOCs
                if compromised:
                    success, ioc_id, msg = sync_user_to_ioc(
                        case_id=case_id,
                        username=username,
                        user_id=known_user.id,
                        current_user_id=current_user.id,
                        description=f'Compromised user from CSV import (SID: {user_sid or "N/A"})',
                        user_sid=user_sid  # v1.24.0: Pass SID to create inactive user_sid IOC
                    )
                    if success and ioc_id:
                        iocs_created_count += 1
                
            except Exception as row_error:
                errors.append(f"Row {row_num}: {str(row_error)}")
                skipped_count += 1
        
        db.session.commit()
        
        # Audit log
        from audit_logger import log_action
        log_action('upload_known_users_csv', resource_type='known_user', resource_id=None,
                  resource_name=f'{added_count} users from CSV',
                  details={
                      'case_id': case_id,
                      'case_name': case.name,
                      'added_count': added_count,
                      'skipped_count': skipped_count,
                      'iocs_created_count': iocs_created_count,  # v1.21.0
                      'filename': file.filename,
                      'errors': errors[:5] if errors else []  # Log first 5 errors
                  })
        
        # Build result message
        message = f'CSV import complete: {added_count} users added'
        if iocs_created_count > 0:
            message += f' ({iocs_created_count} IOCs created automatically)'
        if skipped_count > 0:
            message += f', {skipped_count} skipped (duplicates or invalid)'
        
        if errors:
            message += f'. Errors: {"; ".join(errors[:5])}'  # Show first 5 errors
        
        flash(message, 'success' if added_count > 0 else 'warning')
        return jsonify({
            'success': True,
            'added': added_count,
            'skipped': skipped_count,
            'iocs_created': iocs_created_count,  # v1.21.0
            'errors': errors
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': f'CSV processing error: {str(e)}'}), 500


@known_users_bp.route('/case/<int:case_id>/known_users/export_csv')
@login_required
def export_csv(case_id):
    """Export all known users to CSV - Case-specific"""
    from main import db
    from models import KnownUser, User, Case
    
    # Verify case exists
    case = db.session.get(Case, case_id)
    if not case:
        flash('Case not found', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        # Get all known users for this case
        known_users = KnownUser.query.filter_by(case_id=case_id).order_by(KnownUser.username).all()
        
        # Audit log
        from audit_logger import log_action
        log_action('export_known_users_csv', resource_type='known_user', resource_id=None,
                  resource_name=f'{len(known_users)} users',
                  details={
                      'case_id': case_id,
                      'case_name': case.name,
                      'count': len(known_users)
                  })
        
        # Create CSV in memory
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header (v1.21.0: Added UserSID column)
        writer.writerow(['Username', 'Type', 'Compromised', 'Active', 'UserSID', 'Added Method', 'Added By', 'Date Added'])
        
        # Write data
        for ku in known_users:
            creator = db.session.get(User, ku.added_by)
            creator_name = creator.username if creator else 'Unknown'
            
            writer.writerow([
                ku.username,
                ku.user_type,
                'true' if ku.compromised else 'false',
                'true' if ku.active else 'false',
                ku.user_sid or '',  # v1.21.0: Include SID (empty if None)
                ku.added_method,
                creator_name,
                ku.created_at.strftime('%Y-%m-%d %H:%M:%S') if ku.created_at else ''
            ])
        
        # Create response
        output.seek(0)
        from flask import Response
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename=known_users_case_{case_id}_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'}
        )
    
    except Exception as e:
        flash(f'Export failed: {str(e)}', 'error')
        return redirect(url_for('known_users.list_known_users', case_id=case_id))


@known_users_bp.route('/case/<int:case_id>/known_users/bulk_edit', methods=['POST'])
@login_required
def bulk_edit_known_users(case_id):
    """Bulk edit known users (v1.22.0)"""
    # Permission check: Read-only users cannot edit
    if current_user.role == 'read-only':
        return jsonify({'success': False, 'error': 'Read-only users cannot edit known users'}), 403
    
    from main import db
    from models import KnownUser, Case
    from known_user_ioc_sync import sync_user_to_ioc  # v1.21.0: IOC integration
    
    # Verify case exists
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    try:
        data = request.get_json()
        user_ids = data.get('user_ids', [])
        
        if not user_ids or not isinstance(user_ids, list):
            return jsonify({'success': False, 'error': 'No users selected'}), 400
        
        # Get fields to update (only non-None values)
        updates = {}
        if 'user_type' in data:
            updates['user_type'] = data['user_type']
        if 'compromised' in data:
            updates['compromised'] = data['compromised']
        if 'active' in data:
            updates['active'] = data['active']
        
        if not updates:
            return jsonify({'success': False, 'error': 'No fields to update'}), 400
        
        # Update users
        updated_count = 0
        iocs_created_count = 0
        
        for user_id in user_ids:
            known_user = db.session.get(KnownUser, user_id)
            
            if not known_user:
                continue  # Skip missing users
            
            # Verify user belongs to this case
            if known_user.case_id != case_id:
                continue  # Skip users from other cases
            
            # Track if compromised status changes
            was_compromised = known_user.compromised
            
            # Apply updates
            for key, value in updates.items():
                setattr(known_user, key, value)
            
            updated_count += 1
            
            # v1.21.0 / v1.24.0: If user is NOW compromised (and wasn't before), create IOC
            if updates.get('compromised') == True and not was_compromised:
                success, ioc_id, msg = sync_user_to_ioc(
                    case_id=case_id,
                    username=known_user.username,
                    user_id=known_user.id,
                    current_user_id=current_user.id,
                    description=f'Compromised via bulk edit (SID: {known_user.user_sid or "N/A"})',
                    user_sid=known_user.user_sid  # v1.24.0: Pass SID to create inactive user_sid IOC
                )
                if success and ioc_id:
                    iocs_created_count += 1
        
        db.session.commit()
        
        # Audit log
        from audit_logger import log_action
        log_action('bulk_edit_known_users', resource_type='known_user', resource_id=None,
                  resource_name=f'{updated_count} users',
                  details={
                      'case_id': case_id,
                      'case_name': case.name,
                      'user_ids': user_ids,
                      'updated_count': updated_count,
                      'iocs_created_count': iocs_created_count,
                      'updates': updates
                  })
        
        # Build result message
        message = f'Bulk edit complete: {updated_count} users updated'
        if iocs_created_count > 0:
            message += f' ({iocs_created_count} IOCs created automatically)'
        
        flash(message, 'success')
        return jsonify({
            'success': True,
            'updated': updated_count,
            'iocs_created': iocs_created_count
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': f'Bulk edit error: {str(e)}'}), 500


@known_users_bp.route('/case/<int:case_id>/known_users/bulk_delete', methods=['POST'])
@login_required
def bulk_delete_known_users(case_id):
    """Bulk delete known users (v1.22.0)"""
    # Permission check: Only administrators can delete
    if current_user.role != 'administrator':
        return jsonify({'success': False, 'error': 'Only administrators can delete known users'}), 403
    
    from main import db
    from models import KnownUser, Case
    
    # Verify case exists
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    try:
        data = request.get_json()
        user_ids = data.get('user_ids', [])
        
        if not user_ids or not isinstance(user_ids, list):
            return jsonify({'success': False, 'error': 'No users selected'}), 400
        
        # Delete users
        deleted_count = 0
        deleted_usernames = []
        
        for user_id in user_ids:
            known_user = db.session.get(KnownUser, user_id)
            
            if not known_user:
                continue  # Skip missing users
            
            # Verify user belongs to this case
            if known_user.case_id != case_id:
                continue  # Skip users from other cases
            
            deleted_usernames.append(known_user.username)
            db.session.delete(known_user)
            deleted_count += 1
        
        db.session.commit()
        
        # Audit log
        from audit_logger import log_action
        log_action('bulk_delete_known_users', resource_type='known_user', resource_id=None,
                  resource_name=f'{deleted_count} users',
                  details={
                      'case_id': case_id,
                      'case_name': case.name,
                      'user_ids': user_ids,
                      'deleted_count': deleted_count,
                      'deleted_usernames': deleted_usernames
                  })
        
        flash(f'Bulk delete complete: {deleted_count} users deleted', 'success')
        return jsonify({
            'success': True,
            'deleted': deleted_count
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': f'Bulk delete error: {str(e)}'}), 500

