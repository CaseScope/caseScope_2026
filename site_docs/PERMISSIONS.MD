# CaseScope 2026 - User Permissions & Access Control

## Overview

CaseScope uses a **role-based access control (RBAC)** system with three distinct permission levels. Each role has specific capabilities and restrictions enforced both on the server-side (route decorators) and client-side (UI element visibility).

## Permission Decorators

### `@login_required`
- **Purpose**: Requires any authenticated user
- **Location**: `flask_login` library
- **Usage**: Applied to all protected routes
- **Redirect**: Unauthenticated users sent to login page

### `@admin_required`
- **Purpose**: Requires `administrator` role
- **Location**: `app/routes/admin.py`
- **Enforcement**: Checks `current_user.role == 'administrator'`
- **Error**: Flash message + redirect to dashboard if denied

### `@admin_or_analyst_required`
- **Purpose**: Requires `administrator` or `analyst` role (blocks viewers)
- **Location**: `app/routes/admin.py`
- **Enforcement**: Checks `current_user.role in ['administrator', 'analyst']`
- **Error**: Flash message + redirect to dashboard if denied

## Role Hierarchy

```
administrator (Full Access)
    ↓
analyst (Limited Management)
    ↓
read-only (View Only)
```

---

## Administrator Role

**Role Value**: `administrator`

### Full Permissions

#### User Management
- ✅ **View all users** - See administrators, analysts, and viewers in user list
- ✅ **Create users** - Add new users with any role (administrator, analyst, read-only)
- ✅ **Edit any user** - Modify username, email, password, role, status, case assignment
- ✅ **Change user roles** - Promote/demote users between all roles
- ✅ **Delete users** - Remove any user account (except own account)
  - Requires deletion reason for audit trail
  - Cannot delete themselves (prevents lockout)
- ✅ **Activate/deactivate users** - Enable or disable user accounts

#### Case Management
- ✅ **Full CRUD** - Create, read, update, delete all cases
- ✅ **Assign cases** - Assign cases to analysts or lock viewers to specific cases
- ✅ **View all case data** - Access all evidence, events, IOCs, reports for any case

#### Audit & Security
- ✅ **View audit log** - Full access to all audit trail entries
- ✅ **Filter/search logs** - Search by user, action, date range
- ✅ **View audit details** - See complete change history and security events

#### System Settings
- ✅ **Access settings** - Configure system-wide settings
- ✅ **Manage integrations** - Configure external tools and APIs

### Routes Accessible
- `/` - Dashboard
- `/admin/users` - User management
- `/admin/users/add` - Create user
- `/admin/users/<id>/edit` - Edit any user
- `/admin/users/<id>/delete` - Delete user
- `/admin/audit-log` - Audit log viewer
- `/admin/settings` - System settings
- All case/evidence routes

### Default Administrator Account
- **Username**: `admin`
- **Password**: `admin` (should be changed immediately)
- **Created by**: `app/init_db.py` script
- **Purpose**: Bootstrap account for initial system setup

---

## Analyst Role

**Role Value**: `analyst`

### Permissions

#### User Management (Limited)
- ✅ **View user list** - See themselves + all `read-only` (viewer) users
- ❌ **Cannot see** - Other analysts or administrators (filtered from list)
- ✅ **Edit self** - Can change own profile, email, password
- ✅ **Edit viewers** - Can modify `read-only` user profiles
- ❌ **Cannot create users** - No access to "Add User" button
- ❌ **Cannot change roles** - Cannot promote/demote any user (prevents privilege escalation)
- ❌ **Cannot delete users** - No delete functionality

**Example Access Control**:
```python
# In edit_user() route
if current_user.role == 'analyst':
    # Can only edit themselves OR viewer users
    if user.id != current_user.id and user.role != 'read-only':
        return 403  # Access denied
    
    # Cannot change roles (even for viewers)
    if role_changed:
        return 403  # Analysts cannot change user roles
```

#### Case Management
- ✅ **View assigned cases** - Full access to cases assigned to them
- ✅ **Upload evidence** - Add files, logs, artifacts to assigned cases
- ✅ **Run analysis** - IOC extraction, Sigma detection, AI analysis
- ✅ **Generate reports** - Create triage reports and investigation summaries
- ❌ **Delete cases** - Cannot remove cases from system
- ❌ **View unassigned cases** - Only see cases they're working on

#### Audit & Security
- ❌ **Cannot view audit log** - No access to `/admin/audit-log` route
- ✅ **Actions are audited** - All analyst actions logged for administrator review

### Routes Accessible
- `/` - Dashboard
- `/admin/users` - User list (filtered: self + viewers only)
- `/admin/users/<id>/edit` - Edit self or viewer users
- `/admin/users/<id>/get` - View self or viewer user details
- `/case/<id>/*` - Case routes for assigned cases
- `/files/*` - File upload/management for assigned cases
- `/ioc/*` - IOC management for assigned cases
- `/sigma/*` - Sigma detection for assigned cases

### Routes Blocked
- `/admin/users/add` - Cannot create users
- `/admin/users/<id>/delete` - Cannot delete users
- `/admin/audit-log` - Cannot view audit logs
- `/admin/settings` - Cannot access system settings

---

## Read-Only (Viewer) Role

**Role Value**: `read-only`

### Permissions

#### Case Access (Locked)
- ✅ **View single case** - Access only the case specified in `user.case_assigned` field
- ✅ **Read evidence** - View files, logs, events in assigned case
- ✅ **View reports** - Read triage reports and analysis results
- ❌ **Cannot upload** - Cannot add new files or evidence
- ❌ **Cannot modify** - No edit capabilities for any data
- ❌ **Cannot run analysis** - No IOC extraction, Sigma detection, or AI operations
- ❌ **View other cases** - Locked to single case by administrator

#### User Management
- ❌ **No access** - Cannot view `/admin/users` route
- ❌ **Cannot edit self** - Profile changes must be done by administrator or analyst

#### Audit & Security
- ❌ **No audit log access**
- ✅ **Actions are audited** - All viewer actions logged (logins, page views, file access)

### Case Assignment

Viewer users are locked to a specific case via the `case_assigned` database field:

```python
# User model
user.case_assigned = 27  # Foreign key to case.id

# Access control example
if current_user.role == 'read-only':
    if case.id != current_user.case_assigned:
        return 403  # Access denied - not your case
```

### Routes Accessible
- `/` - Dashboard (shows only assigned case)
- `/login` - Authentication
- `/case/<case_assigned>/*` - View routes for assigned case only

### Routes Blocked
- All `/admin/*` routes
- All `/case/<other_case_id>/*` routes (cases not assigned to them)
- All upload, edit, delete, analysis routes

---

## Permission Enforcement

### Server-Side Enforcement

**Route Decorators** (Primary Security):
```python
@admin_bp.route('/users')
@admin_or_analyst_required  # Blocks viewers
def users():
    # Analysts see filtered list, admins see all
    if current_user.role == 'administrator':
        users = User.query.all()
    else:
        users = User.query.filter(/* self + viewers */)
```

**Conditional Logic** (Granular Control):
```python
# Analysts can only edit self or viewers
if current_user.role == 'analyst':
    if user.id != current_user.id and user.role != 'read-only':
        return jsonify({'error': 'Access denied'}), 403
```

### Client-Side UI Control

**Conditional Rendering** (User Experience):
```jinja2
{# Show "Add User" button only to administrators #}
{% if current_user.role == 'administrator' %}
    <button onclick="showAddUserModal()">Add User</button>
{% endif %}

{# Show "Delete" button only for admins, not for own account #}
{% if current_user.role == 'administrator' and user.id != current_user.id %}
    <button onclick="deleteUser({{ user.id }})">Delete</button>
{% endif %}
```

**Button State** (Dynamic Disabling):
```javascript
// Edit button enabled/disabled based on permissions
const canEdit = currentUser.role === 'administrator' || 
                user.id === currentUser.id || 
                user.role === 'read-only';
button.disabled = !canEdit;
```

---

## Access Control Examples

### User Management Access Matrix

| Action | Administrator | Analyst | Read-Only |
|--------|--------------|---------|-----------|
| View all users | ✅ | ❌ (self + viewers) | ❌ |
| View administrators | ✅ | ❌ | ❌ |
| View analysts | ✅ | ❌ (only self) | ❌ |
| View viewers | ✅ | ✅ | ❌ |
| Create user | ✅ | ❌ | ❌ |
| Edit administrator | ✅ | ❌ | ❌ |
| Edit analyst | ✅ | ❌ (only self) | ❌ |
| Edit viewer | ✅ | ✅ | ❌ |
| Change user role | ✅ | ❌ | ❌ |
| Delete user | ✅ | ❌ | ❌ |
| View audit log | ✅ | ❌ | ❌ |

### Case Access Matrix

| Action | Administrator | Analyst | Read-Only |
|--------|--------------|---------|-----------|
| View all cases | ✅ | ❌ (assigned only) | ❌ (locked case) |
| Create case | ✅ | ✅ | ❌ |
| Upload files | ✅ | ✅ | ❌ |
| Run IOC extraction | ✅ | ✅ | ❌ |
| Run Sigma detection | ✅ | ✅ | ❌ |
| Generate reports | ✅ | ✅ | ❌ |
| Delete case | ✅ | ❌ | ❌ |
| View events | ✅ | ✅ | ✅ |
| View reports | ✅ | ✅ | ✅ |

### IOC Management Access Matrix

| Action | Administrator | Analyst | Read-Only |
|--------|--------------|---------|-----------|
| View IOCs | ✅ | ✅ | ✅ |
| Add IOC | ✅ | ✅ | ❌ |
| Edit IOC | ✅ | ✅ | ❌ |
| Delete IOC | ✅ | ✅ | ❌ |
| Bulk Edit | ✅ | ✅ | ❌ |
| Bulk Delete | ✅ | ✅ | ❌ |
| Extract IOCs from EDR | ✅ | ✅ | ❌ |
| Deduplicate IOCs | ✅ | ✅ | ❌ |
| Export IOCs (CSV) | ✅ | ✅ | ✅ |

---

## Security Best Practices

### Prevent Privilege Escalation
- ✅ Analysts cannot change any user's role (including viewers)
- ✅ Analysts cannot create administrator accounts
- ✅ Users cannot delete or disable their own accounts
- ✅ All role changes are audited with before/after values

### Session Management
- ✅ Configurable session timeout (default: 8 hours, set in `config.py`)
- ✅ "Remember me" option for persistent sessions
- ✅ Automatic logout on session expiry
- ✅ Session invalidation on logout

### Account Security
- ✅ Werkzeug password hashing (bcrypt-compatible)
- ✅ Account enable/disable without deletion
- ✅ Last login timestamp tracking
- ✅ Failed login attempts logged to audit trail

### Audit Trail
- ✅ All permission-checking actions logged
- ✅ Failed access attempts recorded with IP address
- ✅ User deletions require reason and are permanently logged
- ✅ Role changes tracked with old→new values

---

## Permission Troubleshooting

### "Access Denied" Errors

**Symptom**: User sees "Administrator access required" or 403 error

**Common Causes**:
1. **Wrong role** - Analyst trying to access admin-only route
2. **Session expired** - User logged out, needs to re-authenticate
3. **Account disabled** - `user.is_active = False`
4. **Viewer accessing wrong case** - Trying to view case they're not assigned to

**Solution**:
- Check `user.role` in database
- Verify `user.is_active = True`
- Confirm session is valid (check browser cookies)
- For viewers, verify `user.case_assigned` matches requested case ID

### Button Not Appearing

**Symptom**: Expected button (Add User, Delete, etc.) not visible

**Common Causes**:
1. **Role-based rendering** - Button hidden for non-admin users
2. **Self-protection** - Delete button hidden for own account

**Solution**: This is expected behavior! Check template conditional logic:
```jinja2
{% if current_user.role == 'administrator' %}
```

### Cannot Edit User

**Symptom**: Edit button disabled or returns error

**Analyst Restrictions**:
- Can only edit self or viewer users
- Cannot change any user's role
- Cannot edit other analysts or administrators

**Solution**: Have an administrator perform the edit, or check if user is a viewer

---

## Configuration

All permission-related settings are hardcoded in the role definitions. To modify permissions:

1. **Update route decorators** in `app/routes/*.py`
2. **Modify conditional logic** in route handlers
3. **Update UI templates** in `templates/*.html`
4. **Update this documentation** to reflect changes

**Note**: Role names (`administrator`, `analyst`, `read-only`) are stored in the database and referenced throughout the codebase. Changing role names requires database migration and code updates.
