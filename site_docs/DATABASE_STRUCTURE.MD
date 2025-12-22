# CaseScope 2026 - Database Structure

## Technology Stack
- **Database**: PostgreSQL
- **ORM**: SQLAlchemy (Flask-SQLAlchemy)
- **Authentication**: Flask-Login with Werkzeug password hashing

## User Management

### User Table (`user`)
| Column | Type | Details |
|--------|------|---------|
| `id` | Integer | Primary key |
| `username` | String(80) | Unique login username, indexed |
| `email` | String(120) | Unique email address |
| `password_hash` | String(255) | Werkzeug hashed password |
| `full_name` | String(120) | User's display name |
| `role` | String(20) | Permission level (see below) |
| `is_active` | Boolean | Account enabled/disabled (default: True) |
| `case_assigned` | Integer | Foreign key to `case.id` (read-only users only) |
| `created_at` | DateTime | Account creation timestamp |
| `last_login` | DateTime | Last successful login timestamp |

**Relationships**:
- `assigned_case` - Relationship to `Case` model (for read-only users locked to specific case)
- `cases_created` - Backref to cases this user created
- `cases_assigned` - Backref to cases assigned to this user
- `audit_logs` - Backref to audit log entries

**Methods**:
- `set_password(password)` - Hash and set password
- `check_password(password)` - Verify password against hash

### User Roles & Permissions

#### `administrator`
- **Full Access**: All functions, all cases, all users
- **User Management**: Can create, edit, delete any user of any role
- **Case Management**: Full CRUD on all cases
- **Audit Log**: Full access to view all audit logs
- **Default User**: `admin` / `admin` (created by `init_db.py`)

#### `analyst`
- **User Management**: Can edit themselves or any `read-only` (viewer) user; **cannot** create users, **cannot** change user roles
- **Case Management**: Full access to assigned cases
- **Audit Log**: View logs for their cases only
- **Restrictions**: Cannot delete users, cannot see administrators in user list

#### `read-only` (viewer)
- **Access**: View-only access to assigned case (specified in `case_assigned` field)
- **Restrictions**: Cannot edit anything, cannot access user management, cannot see audit logs
- **Case Lock**: Locked to single case specified by administrator

## Case Management

### Case Table (`case`)
| Column | Type | Details |
|--------|------|---------|
| `id` | Integer | Primary key |
| `name` | String(200) | Case name/title, indexed |
| `description` | Text | Case details/notes |
| `company` | String(200) | Client/organization name |
| `status` | String(20) | Case workflow status |
| `created_by` | Integer | Foreign key to `user.id` |
| `assigned_to` | Integer | Foreign key to `user.id` |
| `opensearch_index` | String(100) | OpenSearch index name (case-level, e.g., `case_123`) |
| `router_ips` | Text | Comma-separated router IP addresses |
| `vpn_ips` | Text | Comma-separated VPN IPs/subnets/ranges |
| `edr_reports` | Text | EDR reports (separate multiple with `*** NEW REPORT ***`) |
| `created_at` | DateTime | Creation timestamp |
| `updated_at` | DateTime | Last update timestamp (auto-updates) |

**Status Values**:
- `New` - Newly created case
- `Assigned` - Assigned to analyst
- `In Progress` - Active investigation
- `Completed` - Investigation finished
- `Archived` - Closed and archived

**Relationships**:
- `creator` - Relationship to `User` who created the case
- `assignee` - Relationship to `User` assigned to the case
- `viewers` - Backref to read-only users locked to this case

### Network Configuration Fields

#### `opensearch_index`
**Purpose**: Store the OpenSearch index name for this case  
**Format**: String (e.g., `case_123`, `case_456`)  
**Notes**: 
- Indexes are **case-level**, not file-level
- All events for this case stored in single index
- Index name typically follows pattern: `case_{id}`

#### `router_ips`
**Purpose**: Store company router IP addresses involved in the case  
**Format**: Comma-separated list of IP addresses  
**Examples**:
- Single router: `192.168.1.1`
- Multiple routers: `192.168.1.1, 10.0.0.1, 172.16.0.1`

#### `vpn_ips`
**Purpose**: Store VPN IP addresses/ranges for the case  
**Format**: Comma-separated, supports multiple formats  
**Examples**:
- Single IP: `192.168.1.100`
- Subnet: `192.168.1.0/24`
- Range: `192.168.1.50-192.168.1.60`
- Multiple entries: `192.168.1.0/24, 10.0.0.50-10.0.0.60, 172.16.5.10`

**Use Case**: Define internal/VPN IP ranges for filtering during analysis

#### `edr_reports`
**Purpose**: Store EDR (Endpoint Detection and Response) reports  
**Format**: Text field, multiple reports separated by delimiter  
**Delimiter**: `*** NEW REPORT ***`  
**Example**:
```
EDR Report #1 - Suspicious PowerShell
Detected on: 2026-01-15
Endpoint: WORKSTATION-01
Details: Base64 encoded command execution...

*** NEW REPORT ***

EDR Report #2 - Lateral Movement
Detected on: 2026-01-16  
Endpoint: SERVER-DC01
Details: Unusual RDP session from compromised account...
```

**Helper Text**: "If entering multiple EDR reports, separate each with *** NEW REPORT ***"

## Audit Logging

### AuditLog Table (`audit_log`)
| Column | Type | Details |
|--------|------|---------|
| `id` | Integer | Primary key |
| `timestamp` | DateTime | When action occurred, indexed |
| `user_id` | Integer | Foreign key to `user.id` (nullable) |
| `username` | String(80) | Denormalized username (preserved if user deleted) |
| `action` | String(100) | Action performed, indexed |
| `resource_type` | String(50) | Type of resource (user, case, file, ioc), indexed |
| `resource_id` | Integer | ID of affected resource |
| `resource_name` | String(500) | Human-readable resource name |
| `ip_address` | String(45) | Client IP (IPv4 or IPv6) |
| `user_agent` | Text | Browser/client user agent string |
| `details` | Text | JSON string with additional context |
| `status` | String(20) | Action result (success, failed, error) |

**Relationships**:
- `user` - Relationship to `User` who performed the action

**Purpose**: 
- Security compliance and forensic investigation
- Track all security-sensitive actions (login, user creation/deletion/modification, case changes)
- Immutable audit trail for compliance requirements

### Audit Logger Usage

```python
from audit_logger import log_action

# Login/logout
log_action('login', status='success')
log_action('logout')

# User management with detailed changes
log_action('create_user', 
    resource_type='user', 
    resource_id=new_user.id,
    resource_name=new_user.username,
    details={
        'role': new_user.role,
        'email': new_user.email,
        'case_assigned': case_id  # If read-only user
    }
)

log_action('modify_user',
    resource_type='user',
    resource_id=user.id,
    resource_name=user.username,
    details={
        'changes': {
            'role': {'old': 'analyst', 'new': 'administrator'},
            'email': {'old': 'old@example.com', 'new': 'new@example.com'}
        },
        'current_role': user.role
    }
)

log_action('delete_user',
    resource_type='user',
    resource_id=user.id,
    resource_name=user.username,
    details={
        'reason': 'Employee terminated',
        'deleted_by': current_user.username,
        'role': user.role,
        'case_assigned': user.case_assigned
    }
)

# Case operations
log_action('create_case',
    resource_type='case',
    resource_id=case.id,
    resource_name=case.name
)
```

## Database Initialization

**Script**: `app/init_db.py`

**Creates**:
1. All tables (user, case, audit_log)
2. Default administrator account:
   - Username: `admin`
   - Password: `admin`
   - Role: `administrator`

**Usage**:
```bash
cd /opt/casescope
source venv/bin/activate
python3 app/init_db.py
```

## Schema Changes & Migrations

Store SQL migration scripts in `/migrations` directory with descriptive names and GRANT statements for the `casescope` PostgreSQL user.
