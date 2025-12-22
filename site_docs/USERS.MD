# CaseScope 2026 - User Management & Authentication

## Overview

CaseScope uses **Flask-Login** for session-based authentication with role-based access control (RBAC). User accounts are stored in PostgreSQL with hashed passwords (Werkzeug security) and support three permission levels.

---

## User Model

### Database Table: `user`

| Column | Type | Details |
|--------|------|---------|
| `id` | Integer | Primary key (auto-increment) |
| `username` | String(80) | Unique login username, indexed, required |
| `email` | String(120) | Unique email address, required |
| `password_hash` | String(255) | Werkzeug hashed password, required |
| `full_name` | String(120) | Display name (optional) |
| `role` | String(20) | Permission level (default: 'analyst') |
| `is_active` | Boolean | Account enabled/disabled (default: True) |
| `case_assigned` | Integer | Foreign key to `case.id` (read-only users only) |
| `created_at` | DateTime | Account creation timestamp (auto) |
| `last_login` | DateTime | Last successful login timestamp |

**Constraints**:
- `username` - Unique, indexed for fast lookups
- `email` - Unique, validated format
- `case_assigned` - Foreign key relationship to `case.id`, nullable

**Relationships**:
- `assigned_case` - One-to-one to Case model (for viewers)
- `cases_created` - One-to-many backref to cases this user created
- `cases_assigned` - One-to-many backref to cases assigned to this user
- `audit_logs` - One-to-many backref to audit log entries

### Model Methods

```python
class User(UserMixin, db.Model):
    """User accounts for authentication"""
    
    def set_password(self, password):
        """Hash and set password using Werkzeug"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Verify password against stored hash"""
        return check_password_hash(self.password_hash, password)
```

**Inheritance**:
- `UserMixin` - Provides Flask-Login integration methods:
  - `is_authenticated` property
  - `is_active` property
  - `is_anonymous` property
  - `get_id()` method

---

## User Roles

### Administrator
**Role Value**: `administrator`
**Permissions**: Full access (see PERMISSIONS.MD)
**Default Account**: `admin` / `admin`

### Analyst
**Role Value**: `analyst`
**Permissions**: Case management, limited user editing (see PERMISSIONS.MD)
**Default**: New users created with this role

### Read-Only (Viewer)
**Role Value**: `read-only`
**Permissions**: View-only access to assigned case (see PERMISSIONS.MD)
**Special**: Locked to single case via `case_assigned` field

---

## Authentication System

### Login Flow

**Route**: `/login` (GET, POST)
**Blueprint**: `auth_bp` in `app/routes/auth.py`

**Process**:
1. User submits username and password
2. System queries database for `User.query.filter_by(username=username).first()`
3. Password verified via `user.check_password(password)`
4. Check if account is active (`user.is_active == True`)
5. If valid, call `login_user(user, remember=remember)`
6. Update `user.last_login = datetime.utcnow()`
7. Log audit event: `log_action('login', ...)`
8. Redirect to dashboard or `next` parameter

**Failed Login**:
- Flash error message: "Invalid username or password"
- Log warning to application log
- Audit log entry with `status='failed'`
- No indication of whether username exists (security)

**Disabled Account**:
- Flash error: "Account is disabled. Contact an administrator."
- Log warning with username
- User cannot log in even with correct password

### Session Management

**Session Storage**: Server-side sessions (Flask-Login)
**Session Timeout**: 8 hours (configurable in `config.py`)
**Remember Me**: Optional persistent login cookie

**Configuration** (`app/config.py`):
```python
SESSION_TIMEOUT_HOURS = 8  # User can adjust
SESSION_TIMEOUT = SESSION_TIMEOUT_HOURS * 3600  # Converted to seconds
PERMANENT_SESSION_LIFETIME = timedelta(seconds=SESSION_TIMEOUT)
```

**Timeout Behavior**:
- After 8 hours of inactivity, session expires
- User redirected to login page with message
- Must re-authenticate to continue

### Logout Flow

**Route**: `/logout` (GET)
**Blueprint**: `auth_bp` in `app/routes/auth.py`

**Process**:
1. Capture `username` and `user_id` from `current_user`
2. Log audit event: `log_action('logout', ...)`
3. Call `logout_user()` (invalidates session)
4. Flash info message: "You have been logged out"
5. Redirect to login page

### User Loader

**Flask-Login Integration**:
```python
@login_manager.user_loader
def load_user(user_id):
    """Load user from database by ID"""
    from models import User
    return User.query.get(int(user_id))
```

**Called By**: Flask-Login on every request
**Purpose**: Populate `current_user` object from session
**Returns**: User object or None

---

## User Management Interface

### User List Page

**Route**: `/admin/users`
**Access**: Administrators and Analysts (`@admin_or_analyst_required`)
**Template**: `templates/admin/users.html`

**Filtering**:
- **Administrators**: See all users (admins, analysts, viewers)
- **Analysts**: See themselves + all viewer users (no other analysts/admins)

**Display Columns**:
- Username
- Full Name
- Email
- Role
- Status (Active/Inactive badge)
- Assigned Case (for viewers only)
- Last Login
- Actions (Edit, Delete buttons)

**Buttons**:
- **Add User** - Visible to administrators only
- **Edit** - Enabled/disabled based on permissions
- **Delete** - Visible to administrators only (not for own account)

### Add User Modal

**Access**: Administrators only
**Form Fields**:

1. **Username** (text, required)
   - Unique identifier for login
   - Validated for uniqueness on submit

2. **Email** (email, required)
   - Unique email address
   - Validated for format and uniqueness

3. **Password** (password, required)
   - Minimum length (enforced client-side)
   - Hashed before storage (Werkzeug)

4. **Full Name** (text, optional)
   - Display name for UI

5. **Role** (dropdown, required)
   - Options: Administrator, Analyst, Read-Only
   - Default: Analyst

6. **Is Active** (dropdown, required)
   - Options: Active, Inactive
   - Default: Active

7. **Case Assigned** (dropdown, conditional)
   - Only shown if role is "Read-Only"
   - Dropdown of all cases
   - Required for viewers

**Validation**:
- Username must be unique
- Email must be unique and valid format
- Password must be provided
- Case assignment required for viewers

**Backend** (`/admin/users/add`):
```python
@admin_bp.route('/users/add', methods=['POST'])
@admin_required
def add_user():
    # Create user
    user = User(
        username=username,
        email=email,
        full_name=full_name,
        role=role,
        is_active=is_active,
        case_assigned=case_assigned if role == 'read-only' else None
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    
    # Audit log
    log_action('create_user', resource_type='user', 
               resource_id=user.id, resource_name=username,
               details={...})
```

### Edit User Modal

**Access**: 
- Administrators: Can edit any user
- Analysts: Can edit themselves or viewer users

**Form Fields**: Same as Add User, except:
- Username field disabled (cannot change username)
- Password field optional (blank = no change)
- Current values pre-populated

**Permission Checks**:
```python
# Analysts can only edit themselves or viewers
if current_user.role == 'analyst':
    if user.id != current_user.id and user.role != 'read-only':
        return 403  # Access denied
```

**Change Tracking**:
- Only modified fields sent to backend
- Backend compares old vs new values
- Changes logged to audit trail with before/after values

**Backend** (`/admin/users/<id>/edit`):
```python
@admin_bp.route('/users/<int:user_id>/edit', methods=['POST'])
@admin_or_analyst_required
def edit_user(user_id):
    # Check permissions
    # Update fields if changed
    # Track changes for audit
    # Log with detailed change history
```

### Delete User

**Access**: Administrators only
**Button**: Red "Delete" button (not shown for own account)
**Confirmation**: JavaScript prompt: "Why are you deleting this user?"

**Required**:
- Deletion reason (text input)
- Minimum length: 10 characters

**Restrictions**:
- Cannot delete own account (prevents lockout)
- Requires administrator role

**Backend** (`/admin/users/<id>/delete`):
```python
@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    # Prevent self-deletion
    if user_id == current_user.id:
        return 400
    
    # Require reason
    reason = request.json.get('reason')
    if not reason:
        return 400
    
    # Delete user
    db.session.delete(user)
    
    # Audit log with reason
    log_action('delete_user', ..., details={'reason': reason})
```

**Audit Log**:
- Captures full user details before deletion
- Includes deletion reason
- Who deleted the user
- Role and case assignment preserved

---

## User Lifecycle

### Account Creation

**Created By**: Administrators via `/admin/users/add`
**Process**:
1. Administrator fills out form
2. System validates username/email uniqueness
3. Password hashed via `user.set_password(password)`
4. User saved to database
5. Audit event logged with full details
6. Flash success message

**Default Values**:
- `role`: 'analyst'
- `is_active`: True
- `created_at`: Current timestamp
- `last_login`: NULL (until first login)

### First Login

**User Actions**:
1. Receive credentials from administrator
2. Navigate to `/login`
3. Enter username and password
4. System verifies credentials
5. `last_login` timestamp updated
6. Redirected to dashboard

**Recommended**: Users should change default password on first login (not enforced, future enhancement)

### Account Modification

**Modified By**: 
- Administrators: Any user
- Analysts: Self or viewer users

**Common Changes**:
- **Email update**: Validated for uniqueness
- **Password reset**: User enters new password (hashed)
- **Role change**: Admin-only, logged to audit trail
- **Status toggle**: Activate/deactivate account
- **Case reassignment**: For viewers, change assigned case

**All Changes Audited**: See AUDIT.MD for details

### Account Deactivation

**Alternative to Deletion**: Set `is_active = False`

**Benefits**:
- Preserves user history
- Audit logs remain intact
- Can be reactivated later
- User relationships (cases created, assigned) preserved

**Effect**:
- User cannot log in
- Sessions invalidated
- Still appears in user list (with "Inactive" badge)

### Account Deletion

**Permanent Removal**: Deletes user record from database

**When to Delete**:
- Employee terminated (required)
- Account created in error
- Compliance requirement (e.g., GDPR right to be forgotten)

**Data Impact**:
- User record deleted
- Audit logs preserved (username denormalized)
- Case relationships may be set to NULL (depending on foreign key constraints)

**Recommendation**: Prefer deactivation over deletion for audit trail integrity

---

## Password Security

### Hashing Algorithm

**Library**: Werkzeug Security
**Method**: `generate_password_hash(password)`
**Compatible With**: Bcrypt, PBKDF2, SHA256

**Default Configuration**:
```python
from werkzeug.security import generate_password_hash

# Hash password (uses pbkdf2:sha256 by default)
password_hash = generate_password_hash('user_password')

# Verify password
from werkzeug.security import check_password_hash
is_valid = check_password_hash(password_hash, 'user_input')
```

**Security Features**:
- Salted hashes (unique per user)
- Slow hashing (resistant to brute force)
- Configurable iterations (default: 260,000 for pbkdf2)

### Password Storage

**Database Column**: `password_hash` (String, 255 characters)
**Never Stored**: Plain text passwords
**Never Logged**: Passwords or hashes to audit log

**Audit Trail**:
- Password changes logged as: `"password": "changed"`
- Old password NOT logged
- New password NOT logged

### Password Reset

**Current Implementation**: Administrator manually sets new password

**Process**:
1. User contacts administrator
2. Administrator edits user account
3. Administrator enters new password
4. Password hashed and saved
5. User notified via email/phone (manual)

**Future Enhancement**: Self-service password reset via email token

---

## Case Assignment (Viewers)

### Purpose

Lock read-only users to a specific case for focused access control.

### Database Field

**Column**: `user.case_assigned`
**Type**: Integer (Foreign Key to `case.id`)
**Nullable**: Yes (NULL for administrators and analysts)
**Indexed**: No (few queries on this field)

### Usage

**Setting Assignment**:
```python
# In add/edit user form
if user.role == 'read-only':
    user.case_assigned = 27  # Case ID from dropdown
else:
    user.case_assigned = None  # Clear for non-viewers
```

**Enforcing Access**:
```python
# In case view route
if current_user.role == 'read-only':
    if case.id != current_user.case_assigned:
        flash('You do not have access to this case', 'error')
        return redirect(url_for('index'))
```

**Displaying Assignment**:
```jinja2
{# In user list table #}
{% if user.role == 'read-only' and user.case_assigned %}
    <td>{{ user.assigned_case.name }}</td>
{% else %}
    <td>-</td>
{% endif %}
```

### Relationship

**User Model**:
```python
case_assigned = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=True)
assigned_case = db.relationship('Case', foreign_keys=[case_assigned], backref='viewers')
```

**Access in Code**:
```python
user = User.query.get(5)
if user.assigned_case:
    print(f"User assigned to case: {user.assigned_case.name}")
```

---

## User Interface Components

### Sidebar Navigation

**Conditional Rendering** (based on role):

```jinja2
{% if current_user.is_authenticated %}
    <!-- All users see -->
    <a href="{{ url_for('index') }}">Dashboard</a>
    
    {% if current_user.role in ['administrator', 'analyst'] %}
        <!-- Admins and analysts see -->
        <a href="{{ url_for('cases') }}">Cases</a>
        <a href="{{ url_for('files') }}">Evidence</a>
        <a href="{{ url_for('iocs') }}">IOCs</a>
    {% endif %}
    
    {% if current_user.role == 'administrator' %}
        <!-- Admins only -->
        <div class="sidebar-section-header">Administrator</div>
        <a href="{{ url_for('admin.settings') }}">Settings</a>
        <a href="{{ url_for('admin.users') }}">Users</a>
        <a href="{{ url_for('admin.audit_log') }}">Audit Log</a>
    {% endif %}
    
    <a href="{{ url_for('auth.auth_logout') }}">Logout</a>
{% endif %}
```

### User Display

**Showing Current User**:
```jinja2
<!-- In header or topbar -->
<div class="user-info">
    <span>{{ current_user.full_name or current_user.username }}</span>
    <span class="text-muted">{{ current_user.role|title }}</span>
</div>
```

**Role Badges**:
```jinja2
{% if user.role == 'administrator' %}
    <span class="badge badge-primary">Administrator</span>
{% elif user.role == 'analyst' %}
    <span class="badge badge-success">Analyst</span>
{% else %}
    <span class="badge badge-warning">Viewer</span>
{% endif %}
```

**Status Badges**:
```jinja2
{% if user.is_active %}
    <span class="badge badge-success">Active</span>
{% else %}
    <span class="badge badge-error">Inactive</span>
{% endif %}
```

---

## Default Administrator Account

### Bootstrap Account

**Purpose**: Initial system setup and first administrator creation

**Credentials**:
- **Username**: `admin`
- **Password**: `admin`
- **Role**: `administrator`
- **Email**: `admin@example.com`
- **Active**: True

**Created By**: `app/init_db.py` script

**Setup Command**:
```bash
cd /opt/casescope
source venv/bin/activate
python3 app/init_db.py
```

**Security Warning**: 
⚠️ **CHANGE DEFAULT PASSWORD IMMEDIATELY** after first login!

**Recommended**:
1. Log in as `admin` / `admin`
2. Navigate to `/admin/users`
3. Edit `admin` user
4. Set strong password
5. Update email to real administrator email
6. Consider creating a new administrator account and deleting default

---

## User Queries (Common Operations)

### Get User by Username
```python
user = User.query.filter_by(username='john.doe').first()
```

### Get All Active Users
```python
active_users = User.query.filter_by(is_active=True).all()
```

### Get All Administrators
```python
admins = User.query.filter_by(role='administrator').all()
```

### Get All Viewers for a Case
```python
viewers = User.query.filter_by(role='read-only', case_assigned=27).all()
```

### Get User's Created Cases
```python
user = User.query.get(5)
created_cases = user.cases_created  # Relationship backref
```

### Get User's Assigned Cases
```python
user = User.query.get(5)
assigned_cases = user.cases_assigned  # Relationship backref
```

### Get User's Audit Trail
```python
user = User.query.get(5)
audit_logs = user.audit_logs.order_by(AuditLog.timestamp.desc()).all()
```

---

## Configuration

### Session Settings

**File**: `app/config.py`

```python
# Session timeout (hours)
SESSION_TIMEOUT_HOURS = 8  # User can adjust

# Calculated values (don't edit)
SESSION_TIMEOUT = SESSION_TIMEOUT_HOURS * 3600
PERMANENT_SESSION_LIFETIME = timedelta(seconds=SESSION_TIMEOUT)

# Session security
SESSION_COOKIE_SECURE = True  # HTTPS only
SESSION_COOKIE_HTTPONLY = True  # No JavaScript access
SESSION_COOKIE_SAMESITE = 'Lax'  # CSRF protection
```

### Login Manager Settings

**File**: `app/main.py`

```python
from flask_login import LoginManager

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.auth_login'  # Redirect route
login_manager.login_message = 'Please log in to access this page'
login_manager.login_message_category = 'info'
```

---

## Troubleshooting

### Cannot Log In

**Symptom**: "Invalid username or password" despite correct credentials

**Check**:
1. Username is correct (case-sensitive)
2. Password is correct (check Caps Lock)
3. Account is active: `SELECT is_active FROM user WHERE username='john.doe';`
4. Password hash exists: `SELECT password_hash FROM user WHERE username='john.doe';`

**Solution**:
- Reset password via administrator
- Check database connection
- Verify `init_db.py` was run

### Session Expires Too Quickly

**Check**: `SESSION_TIMEOUT_HOURS` in `app/config.py`

**Default**: 8 hours

**Adjust**:
```python
# config.py
SESSION_TIMEOUT_HOURS = 24  # 24 hours instead of 8
```

**Restart**: `sudo systemctl restart casescope-new.service`

### Viewer Cannot Access Assigned Case

**Check**:
1. `user.case_assigned` is set: `SELECT case_assigned FROM user WHERE id=5;`
2. Case exists: `SELECT id, name FROM case WHERE id=27;`
3. User is actually read-only role: `SELECT role FROM user WHERE id=5;`

**Solution**: Edit user and reassign case

### User List Shows Wrong Users

**Analyst seeing administrators**: This is a bug, analysts should only see themselves + viewers

**Check**: Filter logic in `/admin/users` route:
```python
if current_user.role == 'analyst':
    users_list = User.query.filter(
        db.or_(
            User.id == current_user.id,
            User.role == 'read-only'
        )
    ).all()
```

---

## Related Documentation

- **PERMISSIONS.MD** - Detailed role permissions and access control
- **AUDIT.MD** - User action logging and audit trail
- **DATABASE_STRUCTURE.MD** - User table schema and relationships
