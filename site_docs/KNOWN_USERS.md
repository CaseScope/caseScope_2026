# Known Users Management

**Route**: `/users`  
**Blueprint**: `known_users_bp` (auto-loaded)  
**Database Table**: `known_users`

## Overview

Track user accounts and identities involved in investigations, including domain users, local accounts, and compromised credentials.

## Database Fields

| Field | Type | Description |
|-------|------|-------------|
| `username` | VARCHAR(255) | Username (required) |
| `domain_name` | VARCHAR(255) | Domain name (use '-' for none) |
| `sid` | VARCHAR(255) | Security Identifier (use '-' if unknown) |
| `user_type` | VARCHAR(50) | Type: domain, local, unknown (default: unknown) |
| `compromised` | VARCHAR(20) | Status: yes, no (default: no) |
| `source` | VARCHAR(50) | Source: manual, logs, ioc_extraction, csv_import (default: manual) |
| `description` | TEXT | Description (optional) |
| `analyst_notes` | TEXT | Analyst notes (optional) |
| `case_id` | INTEGER | Foreign key to case (required) |
| `created_by` | INTEGER | Foreign key to user |
| `updated_by` | INTEGER | Foreign key to user |
| `created_at` | TIMESTAMP | Creation timestamp |
| `updated_at` | TIMESTAMP | Last update timestamp |

**Note**: Username is required. Domain and SID are optional (use '-' for unknown).

## API Endpoints

### List Users
```
GET /users/api/list?page=1&per_page=50&search=query&user_type=domain&compromised=yes&source=logs
```

### Get Single User
```
GET /users/api/get/<user_id>
```

### Statistics
```
GET /users/api/stats
```
Returns breakdown by:
- Total count
- Domain users
- Local users
- Compromised count

### Create User
```
POST /users/api/create
{
    "username": "jdoe",
    "domain_name": "CORP",
    "sid": "S-1-5-21-...",
    "user_type": "domain",
    "compromised": "no",
    "source": "manual",
    "description": "Finance department user",
    "analyst_notes": "Account locked during incident response"
}
```

### Update User
```
PUT /users/api/update/<user_id>
{
    "compromised": "yes",
    "analyst_notes": "Confirmed compromised - found credential dump"
}
```

### Delete User
```
DELETE /users/api/delete/<user_id>
```
**Permissions**: Analyst or Administrator only

### Bulk Update
```
POST /users/api/bulk_update
{
    "user_ids": [1, 2, 3],
    "updates": {
        "compromised": "yes",
        "source": "logs"
    }
}
```

### Bulk Delete
```
POST /users/api/bulk_delete
{
    "user_ids": [1, 2, 3]
}
```
**Permissions**: Analyst or Administrator only

### Export CSV
```
GET /users/api/export_csv?search=query&user_type=domain
```

### Import CSV
```
POST /users/api/import_csv
Content-Type: multipart/form-data
file: [CSV file]
```

**CSV Format (no header)**:
```
name,domain,sid,compromised
jdoe,corp.local,S-1-5-21-...,true
CORP\admin,,,false
guest,,,false
```

### Discover from Logs
```
POST /users/api/discover_from_logs
```
Starts Celery task to scan OpenSearch logs for users

### Discovery Status
```
GET /users/api/discovery_status/<task_id>
```
Check status of discovery task

## Features

- **Statistics Tile**: Shows total users, domain users, local users, and compromised count
- **Search**: Search across username, domain, SID, description, and notes
- **Filters**: Filter by user type, compromised status, and source
- **Pagination**: Configurable page size (25, 50, 100)
- **Auto-Discovery**: Scan OpenSearch events to automatically discover users
- **CSV Import/Export**: Bulk import/export users via CSV
- **Bulk Operations**: 
  - Select multiple users with checkboxes
  - Bulk edit selected users
  - Bulk delete selected users (analyst+ only)
- **Modals**:
  - Add User: Create new user entry
  - Edit User: Update existing user (single or bulk)
  - Import CSV: Bulk import from CSV with format help
  - Discovery Progress: Real-time progress tracking for auto-discovery
- **Audit Logging**: All create/update/delete operations logged

## Auto-Discovery from Logs

The "Find in Logs" feature automatically discovers users by scanning both **EVTX** and **NDJSON** logs using **aggregation queries** for maximum performance.

### How It Works

1. User clicks "Find in Logs" button
2. System uses OpenSearch **terms aggregations** to extract unique usernames (fast!)
3. Scans multiple event fields for user identifiers from both EVTX and NDJSON
4. Extracts domains from `SubjectDomainName`, `TargetDomainName` (EVTX) and `user.domain` (NDJSON)
5. Extracts SIDs from `SubjectUserSid`, `TargetUserSid` (EVTX) and `user.id` (NDJSON)
6. Applies intelligent filtering to exclude system accounts and groups
7. Classifies users as domain, local, or unknown based on context
8. Performs cross-variant deduplication (e.g., `user` and `DOMAIN\user`)
9. Displays progress in real-time modal

### Fields Scanned

**EVTX Username Fields**:
- `event_data_fields.TargetUserName` - Target user (logons, account management)
- `event_data_fields.SubjectUserName` - Subject user (who performed the action)
- `event_data_fields.User` - Generic user field
- `event_data_fields.AccountName` - Account name field

**NDJSON Username Fields**:
- `user.name` - Primary user field
- `user.id` - User identifier
- `source.user.name` - Source user
- `destination.user.name` - Destination user
- `related.user` - Related users array

**Domain Fields**:
- `event_data_fields.SubjectDomainName` - EVTX subject domain
- `event_data_fields.TargetDomainName` - EVTX target domain
- `user.domain` - NDJSON user domain

**SID Fields**:
- `event_data_fields.SubjectUserSid` - EVTX subject SID
- `event_data_fields.TargetUserSid` - EVTX target SID
- `user.id` - NDJSON user ID (often SID)

### Excluded Usernames

The discovery process filters out 50+ system accounts, groups, and service accounts:

**System Accounts**:
- SYSTEM, LOCAL SERVICE, NETWORK SERVICE, NT AUTHORITY\*
- Guest, Administrator, DefaultAccount, WDAGUtilityAccount
- krbtgt, WsiAccount

**Windows Groups** (not user accounts):
- Users, Administrators, Guests, Backup Operators
- Domain Admins, Domain Users, Domain Controllers
- Power Users, Certificate Service DCOM Access
- And 30+ other built-in groups

**Service Accounts**:
- healthmailbox* (Exchange health monitoring)
- UDW, UMFD-*, DWM-* (Windows services)
- MSOL_* (Microsoft Online Services)

**Patterns Excluded**:
- Computer accounts ending with `$`
- SIDs that look like usernames (S-1-5-21-...)
- Auto-generated patterns like `name_5wofrIv`
- GUID-like patterns
- Very long random strings

### User Type Classification

- **domain**: User with domain context
  - `DOMAIN\username` format
  - `username@domain.com` format
  - Domain field is not '-', 'LOCAL', or 'WORKGROUP'
  
- **local**: Local system account
  - Domain is 'LOCAL', 'WORKGROUP', or '-'
  - `HOSTNAME\username` format
  
- **unknown**: User without clear domain association
  - No domain information available
  - Username alone without context

### Username Format Handling

The system intelligently handles multiple username formats:

```
jdoe                    → Username: jdoe, Domain: -, Type: unknown
CORP\jdoe              → Username: jdoe, Domain: CORP, Type: domain
jdoe@corp.local        → Username: jdoe, Domain: corp.local, Type: domain
HOSTNAME\localadmin    → Username: localadmin, Domain: HOSTNAME, Type: local
```

### Cross-Variant Deduplication

The system recognizes that these are the same user:
- `tabadmin`
- `SL\tabadmin`
- `tabadmin@sl.local`

**Deduplication Logic**:
1. Check for exact match (username + domain)
2. If domain version exists, update notes on it
3. If base version exists and adding domain variant, upgrade base to domain
4. Prevent duplicate entries across all variants

### Performance

- Uses OpenSearch **aggregations** instead of scrolling (MUCH faster!)
- Terms aggregation on keyword fields with bucket size of 2000
- Typical performance: Processes 200,000+ events in 2-3 seconds
- Celery task runs in background (non-blocking)
- Real-time progress updates via task state

## CSV Import/Export

### Export Format
Exported CSV includes all fields with headers for reference.

### Import Format (NO HEADER)
```csv
name,domain,sid,compromised
jdoe,corp.local,S-1-5-21-1234567890-1234567890-1234567890-1001,true
CORP\admin,,,false
guest,,,false
tabadmin,DWTEMPS,S-1-5-21-2919669050-1107293269-1234567890-500,true
local_admin,LOCAL,,false
```

**Rules**:
- No header row
- 4 fields: name, domain, sid, compromised
- Empty fields: Use consecutive commas (e.g., `user,,,false`)
- Username can include domain: `DOMAIN\user` or `user@domain.com`
- Compromised: `true`/`false`/`yes`/`no`/`1`/`0`
- Deduplication: Existing users are updated, not duplicated

### CSV Import Features
- **Smart Parsing**: Handles `DOMAIN\user`, `user@domain.com`, and plain usernames
- **Deduplication**: Updates existing users based on username + domain
- **Error Reporting**: Line-by-line error reporting for invalid entries
- **Validation**: Username is required, other fields optional
- **Audit Logging**: All imports logged with details

## IOC Extraction Integration

When usernames are extracted during EDR IOC extraction:
1. Username is processed through `_process_username_known_user()`
2. Domain and SID are extracted if available
3. User is created or existing entry is updated
4. Compromised status set to 'yes' (found in EDR report)
5. Cross-variant deduplication applied
6. Audit log created

## Permissions

| Role | View | Create | Edit | Delete |
|------|------|--------|------|--------|
| **Administrator** | ✓ | ✓ | ✓ | ✓ |
| **Analyst** | ✓ | ✓ | ✓ | ✓ |
| **Read-only** | ✓ (assigned case only) | ✗ | ✗ | ✗ |

## Audit Events

- `user_created` - User manually created
- `user_updated` - User modified
- `user_deleted` - User deleted
- `users_bulk_updated` - Bulk edit operation
- `users_bulk_deleted` - Bulk delete operation
- `users_exported` - CSV export
- `users_imported_from_csv` - CSV import
- `user_discovery_started` - Auto-discovery initiated
- `user_discovery_completed` - Auto-discovery finished

## Migration

Migration file: `/opt/casescope/migrations/add_known_users.sql`

Applied: 2025-12-24

## Files

- **Route**: `/opt/casescope/app/routes/known_users.py`
- **Model**: `/opt/casescope/app/models.py` (`KnownUser` class)
- **Template**: `/opt/casescope/templates/users/manage.html`
- **Discovery Task**: `/opt/casescope/app/tasks/task_discover_users.py`
- **Cleanup Script**: `/opt/casescope/app/scripts/cleanup_junk_users.py`
- **Navigation**: Updated in `/opt/casescope/templates/base.html`

## UI Design

Follows the same pattern as Known Systems and IOC Management:
- Central CSS used throughout (no inline styles)
- Consistent modal design with standard classes
- Responsive table layout
- Badge-based status indicators
- Bulk action toolbar
- Styled file input button for CSV import

## Cleanup Script

For removing junk users after updating exclusion filters:

```bash
cd /opt/casescope
source venv/bin/activate
python3 app/scripts/cleanup_junk_users.py          # Dry-run (shows what would be deleted)
python3 app/scripts/cleanup_junk_users.py --execute # Actually delete
```

The script uses the same exclusion logic as the discovery task.

