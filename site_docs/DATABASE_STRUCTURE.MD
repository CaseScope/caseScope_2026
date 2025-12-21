# CaseScope 2026 - Database Structure

## User Management

**User Table**
- `id` - Primary key
- `username` - Unique login username (indexed)
- `email` - Unique email address
- `password_hash` - Bcrypt hashed password
- `full_name` - User's full name
- `role` - Permission level:
  - `administrator` - Full access to all functions
  - `analyst` - Cannot delete, limited user management
  - `read-only` (viewer) - View assigned cases only, no edits
- `is_active` - Account enabled/disabled
- `created_at` - Account creation timestamp
- `last_login` - Last successful login timestamp

## Case Management

**Case Table**
- `id` - Primary key
- `name` - Case name/title (indexed)
- `description` - Case details
- `company` - Client/organization name
- `status` - Case status (New, Assigned, In Progress, Completed, Archived)
- `created_by` - User ID who created the case
- `assigned_to` - User ID assigned to the case
- `created_at` - Creation timestamp
- `updated_at` - Last update timestamp

## Audit Logging

**Audit Log Table**
- `id` - Primary key
- `timestamp` - When the action occurred (indexed)
- `user_id` - Foreign key to user table (nullable - for deleted users)
- `username` - Denormalized username (preserved even if user deleted)
- `action` - Action performed (login, create_case, delete_file, etc.) (indexed)
- `resource_type` - Type of resource affected (user, case, file, ioc, etc.) (indexed)
- `resource_id` - ID of the affected resource
- `resource_name` - Human-readable resource name
- `ip_address` - IP address of request (IPv4 or IPv6)
- `user_agent` - Browser/client user agent string
- `details` - JSON string with additional action context
- `status` - Action result (success, failed, error)

**Purpose**: Security compliance, forensic investigation of user actions, audit trail for sensitive operations

**Usage**: 
```python
from audit_logger import log_action

# Simple usage
log_action('login')

# With resource
log_action('delete_case', resource_type='case', 
           resource_id=123, resource_name='Acme Investigation')

# With details
log_action('modify_user', resource_type='user', resource_id=5,
           details={'changes': {'role': 'analyst'}})
```
