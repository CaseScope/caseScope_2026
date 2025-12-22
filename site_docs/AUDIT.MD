# CaseScope 2026 - Audit Logging System

## Overview

CaseScope maintains a **comprehensive audit trail** of all security-sensitive actions for compliance, forensic investigation, and security monitoring. Every user action that modifies data or accesses sensitive resources is logged with full context.

## Purpose

- **Security Compliance**: Meet regulatory requirements (SOC 2, HIPAA, PCI-DSS, etc.)
- **Forensic Investigation**: Reconstruct who did what, when, and from where
- **Incident Response**: Identify unauthorized access or suspicious activity
- **Accountability**: Maintain clear records of user actions
- **Troubleshooting**: Debug user issues and system behavior

---

## What Gets Audited

### User Authentication & Session Management

#### Login Events
**Action**: `login`
**Logged When**: User successfully authenticates
**Details Captured**:
- Username and user ID
- User's role
- IP address
- User agent (browser/client)
- Timestamp

**Failed Login Attempts**:
- Also logged with `status='failed'`
- Includes attempted username (but not password)
- Helps detect brute force attacks

**Example**:
```json
{
  "action": "login",
  "username": "john.analyst",
  "resource_type": "user",
  "resource_id": 5,
  "details": {
    "role": "analyst"
  },
  "status": "success",
  "ip_address": "192.168.1.100",
  "timestamp": "2026-01-15T09:23:15Z"
}
```

#### Logout Events
**Action**: `logout`
**Logged When**: User explicitly logs out
**Details Captured**:
- Username and user ID
- Session duration (via timestamp comparison)
- IP address

---

### User Management

#### User Creation
**Action**: `create_user`
**Logged When**: Administrator creates a new user account
**Details Captured**:
- New username, email, role
- Who created the account (`created_by`)
- Initial active status
- **For viewers**: Case assignment (case ID and name)

**Example**:
```json
{
  "action": "create_user",
  "username": "admin",
  "resource_type": "user",
  "resource_id": 12,
  "resource_name": "jane.viewer",
  "details": {
    "created_by": "admin",
    "role": "read-only",
    "email": "jane@example.com",
    "is_active": true,
    "case_assigned": {
      "case_id": 27,
      "case_name": "Acme Corp Breach"
    }
  }
}
```

#### User Modification
**Action**: `modify_user`
**Logged When**: User profile is edited (by admin or analyst)
**Details Captured**:
- Who made the modification (`modified_by`)
- **Granular changes**: Old value → New value for each field
- Current role and case assignment after changes
- Password changes (logged as "changed", not the actual password)

**Change Tracking**:
- Only fields that actually changed are logged
- Old and new values captured for comparison
- Enables complete reconstruction of user history

**Example**:
```json
{
  "action": "modify_user",
  "username": "admin",
  "resource_type": "user",
  "resource_id": 8,
  "resource_name": "john.analyst",
  "details": {
    "modified_by": "admin",
    "changes": {
      "email": {
        "old": "john.old@example.com",
        "new": "john.new@example.com"
      },
      "role": {
        "old": "analyst",
        "new": "administrator"
      },
      "password": "changed"
    },
    "current_role": "administrator"
  }
}
```

#### User Deletion
**Action**: `delete_user`
**Logged When**: Administrator deletes a user account
**Details Captured**:
- **Deletion reason** (required, entered by admin)
- Who deleted the account (`deleted_by`)
- Deleted user's role, email, active status
- **For viewers**: Case assignment at time of deletion
- Username preserved (even though user is gone)

**Immutability**: User deletions are permanent records, username is denormalized in audit log to preserve history even after user is deleted from main table.

**Example**:
```json
{
  "action": "delete_user",
  "username": "admin",
  "resource_type": "user",
  "resource_id": 15,
  "resource_name": "terminated.user",
  "details": {
    "deleted_by": "admin",
    "reason": "Employee terminated - last day 2026-01-14",
    "role": "analyst",
    "email": "terminated@example.com",
    "was_active": true
  }
}
```

---

### Case Management (Future Implementation)

Planned audit events for case operations:

- `create_case` - New investigation case created
- `modify_case` - Case details/status updated
- `delete_case` - Case removed from system
- `assign_case` - Case assigned to analyst
- `archive_case` - Case archived

---

### Evidence & File Operations (Future Implementation)

Planned audit events for evidence handling:

- `upload_file` - Evidence file uploaded
- `delete_file` - Evidence file removed
- `reindex_file` - File re-indexed into OpenSearch
- `download_evidence` - Evidence file downloaded (data exfiltration tracking)

---

### IOC & Threat Intelligence (Future Implementation)

Planned audit events for IOC operations:

- `add_ioc` - New IOC added to threat intelligence
- `modify_ioc` - IOC details updated
- `delete_ioc` - IOC removed
- `ioc_hunt` - IOC hunting job initiated
- `ioc_match` - IOC matched in events (batch or individual)

---

### Analysis Operations (Future Implementation)

Planned audit events for analysis activities:

- `run_sigma_detection` - Sigma rule detection executed
- `extract_iocs` - IOC extraction from events
- `ai_analysis` - AI-powered analysis performed
- `generate_report` - Triage report generated

---

## Audit Log Schema

### Database Table: `audit_log`

| Column | Type | Indexed | Description |
|--------|------|---------|-------------|
| `id` | Integer | Primary | Unique audit entry ID |
| `timestamp` | DateTime | ✅ | When action occurred (UTC) |
| `user_id` | Integer | ✅ | Foreign key to user.id (nullable) |
| `username` | String(80) | - | Denormalized username (preserved if user deleted) |
| `action` | String(100) | ✅ | Action performed (e.g., 'login', 'delete_user') |
| `resource_type` | String(50) | ✅ | Type of resource (user, case, file, ioc) |
| `resource_id` | Integer | - | ID of affected resource |
| `resource_name` | String(500) | - | Human-readable resource name |
| `ip_address` | String(45) | - | Client IP address (IPv4 or IPv6) |
| `user_agent` | Text | - | Browser/client user agent |
| `details` | Text | - | JSON string with additional context |
| `status` | String(20) | - | Action result (success, failed, error) |

**Indexes**: 
- `timestamp` - For chronological queries and date range filtering
- `user_id` - For per-user audit trails
- `action` - For filtering by action type
- `resource_type` - For filtering by resource

**Relationships**:
- `user` - Relationship to User model (nullable, preserved if user deleted)

---

## Audit Logger Usage

### Python Module: `audit_logger.py`

Simple, reusable module for logging audit events from anywhere in the application.

### Basic Usage

```python
from audit_logger import log_action

# Simple action (no resource)
log_action('login')

# With resource
log_action('delete_case', 
    resource_type='case', 
    resource_id=123, 
    resource_name='Acme Investigation'
)

# With detailed context
log_action('modify_user',
    resource_type='user',
    resource_id=5,
    resource_name='john.doe',
    details={
        'modified_by': 'admin',
        'changes': {
            'role': {'old': 'analyst', 'new': 'administrator'},
            'email': {'old': 'old@ex.com', 'new': 'new@ex.com'}
        }
    }
)

# Failed action
log_action('login', 
    resource_name='invalid.user',
    status='failed'
)
```

### Function Signature

```python
def log_action(action, resource_type=None, resource_id=None, 
               resource_name=None, details=None, status='success'):
    """
    Args:
        action (str): Action performed (e.g., 'login', 'create_case')
        resource_type (str): Type of resource (e.g., 'user', 'case', 'file')
        resource_id (int): ID of the resource
        resource_name (str): Human-readable resource name
        details (dict|str): Additional context (dict will be JSON-ified)
        status (str): 'success', 'failed', or 'error'
    """
```

### Automatic Context Capture

The `log_action()` function automatically captures:

1. **User Context**: 
   - `user_id` and `username` from `current_user` (Flask-Login)
   - If no user authenticated, logs as 'system'

2. **Request Context**:
   - `ip_address` from `request.remote_addr`
   - `user_agent` from `request.headers['User-Agent']`
   - Works with Flask request context

3. **Timestamp**:
   - `datetime.utcnow()` automatically set
   - All times in UTC for consistency

4. **Details Serialization**:
   - Dicts automatically converted to JSON string
   - Strings stored as-is
   - Handles nested structures

### Error Handling

**Non-Breaking**: Audit logging failures do not crash the application.

```python
try:
    # Create audit log entry
    db.session.add(audit_entry)
    db.session.commit()
except Exception as e:
    logger.error(f"[AUDIT] Failed to log action '{action}': {e}")
    # Don't raise - audit logging failures shouldn't break the app
```

**Rationale**: A failed audit log should not prevent a user action from completing. The failure is logged to the application log for investigation, but the main operation proceeds.

---

## Viewing Audit Logs

### Web Interface: `/admin/audit-log`

**Access**: Administrator only (`@admin_required` decorator)

**Features**:
- **Pagination**: 50 entries per page
- **Filtering**: 
  - By action (e.g., "login", "delete_user")
  - By username (e.g., "admin", "john.analyst")
- **Sorting**: Most recent entries first (descending timestamp)
- **Detail Viewer**: Click "View Details" for expanded view

### Audit Details Modal

**User-Friendly Display**:
- Parsed JSON displayed in structured format
- Deletion reasons highlighted in red
- Change tracking: Old value → New value (color-coded)
- Case assignments formatted with case name
- Timestamps formatted in local timezone

**Example Modal Display**:
```
Action: modify_user
User: admin
Timestamp: 2026-01-15 09:45:32 AM
IP Address: 192.168.1.100
Status: success

Details:
━━━━━━━━━━━━━━━━━━━━━━
Modified By: admin

Changes:
  • email: old@example.com → new@example.com
  • role: analyst → administrator
  • password: changed

Current Role: administrator
```

### Query Examples

**Get all logins for a user**:
```python
logs = AuditLog.query.filter(
    AuditLog.username == 'john.analyst',
    AuditLog.action == 'login'
).order_by(AuditLog.timestamp.desc()).all()
```

**Get all user deletions**:
```python
deletions = AuditLog.query.filter(
    AuditLog.action == 'delete_user'
).order_by(AuditLog.timestamp.desc()).all()
```

**Get all failed login attempts in date range**:
```python
from datetime import datetime, timedelta

last_week = datetime.utcnow() - timedelta(days=7)
failed_logins = AuditLog.query.filter(
    AuditLog.action == 'login',
    AuditLog.status == 'failed',
    AuditLog.timestamp >= last_week
).all()
```

**Get full history for a specific user**:
```python
user_history = AuditLog.query.filter(
    db.or_(
        AuditLog.user_id == 5,  # Actions by this user
        AuditLog.resource_id == 5  # Actions on this user
    )
).order_by(AuditLog.timestamp.desc()).all()
```

---

## Audit Data Retention

### Current Implementation
- **Retention**: Indefinite (all audit logs preserved)
- **Storage**: PostgreSQL database (same as application data)
- **Immutability**: Audit logs cannot be edited or deleted via UI

### Future Considerations

**Retention Policy** (to be implemented):
- Keep all logs for minimum compliance period (e.g., 7 years)
- Archive old logs to separate storage after 1-2 years
- Export to SIEM for long-term analysis

**Performance**:
- Indexes on `timestamp`, `user_id`, `action`, `resource_type` optimize queries
- Consider partitioning by date if log table exceeds millions of rows

---

## Security & Compliance

### Data Privacy

**Sensitive Data NOT Logged**:
- ❌ Passwords (plain text)
- ❌ Password hashes
- ❌ Session tokens
- ❌ API keys or secrets

**What IS Logged**:
- ✅ Password changes (fact of change, not the new password)
- ✅ Username changes
- ✅ Email changes
- ✅ Role promotions/demotions

### Access Control

**Viewing Audit Logs**:
- Administrator only
- No self-service access for analysts or viewers
- Prevents users from covering tracks

**Immutability**:
- No edit or delete functions in UI
- Database-level constraints prevent accidental modification
- Deletions would require direct database access (logged at OS/DB level)

### Compliance Readiness

**Regulatory Frameworks Supported**:
- **SOC 2 Type II**: User access tracking, change management
- **HIPAA**: Access logs, authentication events, PHI access tracking
- **PCI-DSS**: User authentication, administrative actions, data access
- **GDPR**: User consent tracking, data access logs, deletion records

**Audit Report Features**:
- Timestamp precision (UTC, sub-second)
- IP address tracking (geo-location possible)
- User agent tracking (device/browser identification)
- Complete change history (before/after values)
- Deletion justification (required reason field)

---

## Application Logging vs. Audit Logging

### Application Logs (Flask/Celery logs)
**Purpose**: Debugging, performance monitoring, error tracking
**Location**: `/var/log/casescope/` or stdout (systemd journal)
**Format**: Plain text, structured logging
**Retention**: Days to weeks
**Example**: `INFO: User logged in: john.analyst (role: analyst)`

### Audit Logs (Database audit_log table)
**Purpose**: Security, compliance, forensics
**Location**: PostgreSQL `audit_log` table
**Format**: Structured database records with JSON details
**Retention**: Years (indefinite)
**Example**: Database record with full user context, IP, changes

**Both are complementary**: Application logs for operational monitoring, audit logs for security and compliance.

---

## Best Practices

### When to Add Audit Logging

✅ **DO audit**:
- User authentication (login, logout, failed attempts)
- User account changes (create, edit, delete, role changes)
- Data modifications (case creation, file uploads, IOC changes)
- Data deletions (evidence removal, case archival)
- Configuration changes (system settings, integrations)
- Sensitive data access (viewing case details, downloading evidence)

❌ **DON'T audit**:
- Normal page views (dashboard, search results)
- Read-only queries that don't expose sensitive data
- System health checks (e.g., `/health` endpoint)
- API calls from automated systems (unless they modify data)

### Implementation Checklist

When adding a new auditable action:

1. ✅ Import `audit_logger` at top of file
2. ✅ Call `log_action()` after successful operation
3. ✅ Include resource type and ID if applicable
4. ✅ Add detailed context in `details` dict
5. ✅ Log failures with `status='failed'` or `status='error'`
6. ✅ Use descriptive action names (e.g., 'create_case', not 'case_new')
7. ✅ Document the new audit event in this file

---

## Troubleshooting

### Audit Logs Not Appearing

**Check**:
1. Database connection working?
2. `audit_log` table exists? (Run `init_db.py`)
3. User has permission to write to table?
4. Check application logs for audit errors: `grep AUDIT /var/log/casescope/app.log`

### Timestamps in Wrong Timezone

**Solution**: All timestamps stored in UTC. Convert to local timezone in UI:
```javascript
const localTime = new Date(log.timestamp + 'Z').toLocaleString();
```

### Missing Details in Audit Log

**Check**: 
- Is `details` parameter being passed to `log_action()`?
- Is it a dict (not a string)? Dicts are JSON-ified automatically.
- Check max length of `details` column (Text type, should be large)

---

## Future Enhancements

### Planned Features

1. **Export Functionality**
   - Export audit logs to CSV/JSON for external analysis
   - SIEM integration (send logs to Splunk, ELK, etc.)

2. **Advanced Filtering**
   - Date range picker
   - Resource type filter dropdown
   - Status filter (success/failed/error)

3. **Alerting**
   - Email alerts for suspicious activity
   - Slack/Teams notifications for critical events
   - Threshold-based alerts (e.g., 5 failed logins in 10 minutes)

4. **Reporting**
   - Pre-built compliance reports (SOC 2, HIPAA, etc.)
   - User activity summaries
   - Security dashboard with metrics

5. **Data Access Tracking**
   - Log every file view/download
   - Track case access by viewers
   - Monitor IOC queries

---

## Related Documentation

- **PERMISSIONS.MD** - User roles and access control
- **USERS.MD** - User management and authentication
- **DATABASE_STRUCTURE.MD** - Database schema and audit_log table definition
