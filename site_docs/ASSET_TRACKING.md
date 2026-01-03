# Asset Tracking - Known Systems & Users

**Routes**: `/systems`, `/users`  
**Blueprints**: `known_systems_bp`, `known_users_bp`  
**Database Tables**: `known_systems`, `known_users`

---

## Overview

Track systems and user accounts involved in investigations. Both support:
- Manual entry
- Auto-discovery from logs
- CSV import/export
- Bulk operations
- Filtering and search

---

## Known Systems

### Purpose
Track workstations, servers, network devices, and threat actor infrastructure.

### Database Fields (`known_systems`)

| Field | Type | Description |
|-------|------|-------------|
| `hostname` | VARCHAR(255) | System hostname (optional) |
| `domain_name` | VARCHAR(255) | Domain name (optional) |
| `ip_address` | VARCHAR(45) | IP address - IPv4/IPv6 (optional) |
| `system_type` | VARCHAR(50) | Type: workstation, server, router, switch, printer, wap, other, threat_actor |
| `compromised` | VARCHAR(20) | Status: yes, no, unknown (default: unknown) |
| `source` | VARCHAR(50) | Source: manual, logs, EDR, csv_import, ioc_extraction |
| `description` | TEXT | Description (optional) |
| `analyst_notes` | TEXT | Analyst notes (optional) |
| `case_id` | INTEGER | Foreign key to case (required) |
| `created_by` | INTEGER | Foreign key to user |
| `updated_by` | INTEGER | Foreign key to user |
| `created_at` | TIMESTAMP | Creation timestamp |
| `updated_at` | TIMESTAMP | Last update timestamp (auto-updates) |

**Requirement**: At least one identifier (hostname, domain_name, or ip_address) must be provided.

### Auto-Discovery from Logs

**Trigger**: Click "🔍 Find in Logs" button

**Process**:
1. Scans OpenSearch `case_{id}` index for system fields
2. Aggregates unique hostnames with IP addresses
3. Normalizes FQDNs (strips domain, uppercases)
4. Resolves IPs from network events
5. Auto-classifies as workstation/server based on naming
6. Creates/updates `known_systems` entries

**Fields Scanned**:
```python
system_fields = [
    'normalized_computer',  # Primary normalized field
    'Computer', 'ComputerName', 'Hostname', 'System', 'WorkstationName',
    'host.name', 'hostname', 'computer', 'computername', 'source_name',
    'SourceHostname', 'DestinationHostname', 'src_host', 'dst_host'
]
```

**IP Resolution**:
```python
ip_fields = ['host.ip', 'source.ip', 'client.ip', 'server.ip']
```

**Normalization**:
- `SERVER01.CORP.LOCAL` → `SERVER01`
- `workstation.domain.com` → `WORKSTATION`
- Deduplicates by normalized hostname

### CSV Import/Export

**Import Format** (no header):
```csv
name,domain,ip,compromised
SERVER01,CORP,192.168.1.10,no
DESKTOP-ABC,,10.0.0.50,yes
```

**Export**: Downloads CSV with all fields

### API Endpoints

```http
GET  /systems/api/list?page=1&per_page=50&search=&system_type=&compromised=&source=
GET  /systems/api/get/<id>
GET  /systems/api/stats
POST /systems/api/create {hostname, ip_address, system_type, compromised, ...}
PUT  /systems/api/update/<id> {...}
DELETE /systems/api/delete/<id>
POST /systems/api/bulk_update {system_ids: [], updates: {}}
POST /systems/api/bulk_delete {system_ids: []}
POST /systems/api/discover_from_logs
GET  /systems/api/discovery_status/<task_id>
POST /systems/api/import_csv (FormData with csv_file)
GET  /systems/api/export_csv
```

**Sorting**: Alphabetically by `hostname` (A-Z)

---

## Known Users

### Purpose
Track user accounts, domain identities, and compromised credentials.

### Database Fields (`known_users`)

| Field | Type | Description |
|-------|------|-------------|
| `username` | VARCHAR(255) | Username (required) |
| `full_name` | VARCHAR(255) | Full name (optional) |
| `sid` | VARCHAR(255) | Security Identifier (optional, use '-' if unknown) |
| `user_type` | VARCHAR(50) | Type: domain, local, unknown (default: unknown) |
| `compromised` | VARCHAR(20) | Status: yes, no, unknown (default: no) |
| `source` | VARCHAR(50) | Source: manual, logs, ioc_extraction, csv_import |
| `description` | TEXT | Description (optional) |
| `analyst_notes` | TEXT | Analyst notes (optional) |
| `case_id` | INTEGER | Foreign key to case (required) |
| `created_by` | INTEGER | Foreign key to user |
| `updated_by` | INTEGER | Foreign key to user |
| `created_at` | TIMESTAMP | Creation timestamp |
| `updated_at` | TIMESTAMP | Last update timestamp (auto-updates) |

**Requirement**: Username must be provided.

### Auto-Discovery from Logs

**Trigger**: Click "🔍 Find in Logs" button

**Process**:
1. Scans OpenSearch `case_{id}` index for username fields
2. Applies 50+ exclusion rules (system accounts, computer accounts, services)
3. Normalizes variants (user, DOMAIN\user, user@domain)
4. Classifies as domain/local/unknown
5. Creates/updates `known_users` entries

**Fields Scanned**:
```python
username_fields = [
    'TargetUserName', 'SubjectUserName', 'user.name', 'UserName',
    'TargetDomainName', 'SubjectDomainName', 'user.domain'
]
```

**Exclusions** (50+ rules):

**System Accounts**:
```python
'system', 'local service', 'network service', 'nt authority\\system',
'guest', 'administrator', 'defaultaccount', 'krbtgt'
```

**Computer Accounts** (regex pattern):
```python
r'^.*\$$'  # Ends with $ (e.g., DESKTOP-ABC$, SERVER01$)
```

**Service Accounts**:
```python
'defaultapppool', 'iusr', 'localsystem', 'nsi',
'healthmailbox', 'msol_', 'umfd-', 'dwm-'
```

**Patterns**:
```python
r'^S-\d+-\d+'  # SIDs (e.g., S-1-5-18)
r'.*_\d+[a-z]{5,}$'  # Auto-generated names (e.g., user_5wofrIv)
r'^[a-z0-9]{20,}$'  # Long random strings
r'^[A-Z0-9]{8,}-[A-Z0-9]{4,}-'  # GUIDs
```

**Normalization**:
- `DOMAIN\user` → `user` (stores domain separately)
- `user@domain.com` → `user` (extracts domain)
- Case-preserving (keeps original username case)

### CSV Import/Export

**Import Format** (no header):
```csv
username,full_name,sid,compromised
jdoe,John Doe,S-1-5-21-...,no
admin,Administrator,-,yes
```

**Export**: Downloads CSV with all fields

### API Endpoints

```http
GET  /users/api/list?page=1&per_page=50&search=&user_type=&compromised=&source=
GET  /users/api/get/<id>
GET  /users/api/stats
POST /users/api/create {username, full_name, user_type, compromised, ...}
PUT  /users/api/update/<id> {...}
DELETE /users/api/delete/<id>
POST /users/api/bulk_update {user_ids: [], updates: {}}
POST /users/api/bulk_delete {user_ids: []}
POST /users/api/discover_from_logs
GET  /users/api/discovery_status/<task_id>
POST /users/api/import_csv (FormData with csv_file)
GET  /users/api/export_csv
```

**Sorting**: Alphabetically by `username` (A-Z)

---

## UI Features

### Both Systems & Users Pages

**Header Actions**:
- 🔍 Find in Logs - Auto-discover from events
- 📤 Import CSV - Bulk import from file
- ➕ Add - Manual entry

**Filters**:
- Search by name/username
- Filter by type (workstation/server/router vs domain/local)
- Filter by compromised status (yes/no/unknown)
- Filter by source (manual/logs/csv_import/ioc_extraction)

**Bulk Operations**:
- Select multiple (checkbox)
- Bulk edit (update compromised status, notes)
- Bulk delete

**Table Columns**:
- Systems: Hostname | IP | Type | Compromised | Source | Notes | Actions
- Users: Username | Full Name | Type | Compromised | Source | Notes | Actions

**Actions Per Row**:
- 👁️ View - Show detail modal
- ✏️ Edit - Edit in modal
- 🗑️ Delete - Remove (with confirmation)

---

## Discovery Modal (Both)

**Process Flow**:
1. Click "🔍 Find in Logs"
2. Confirm scan operation
3. Modal shows real-time progress:
   - Progress bar (0-100%)
   - Status text (Scanning OpenSearch...)
   - Results summary on completion
4. Auto-reloads list when complete

**Results Display**:
```
✅ Discovery Complete!

Found: 15
New Created: 8
Existing Updated: 7
Events Scanned: 1,234,567
```

**Modal Structure** (uses central CSS):
- `.modal-overlay` - Full-screen backdrop
- `.modal-container` - Dialog box
- `.modal-header` - Title and close button
- `.modal-body` - Progress and results
- `.modal-footer` - Close button (enabled after completion)

---

## Auto-Merge & Deduplication

### Auto-Merge During Discovery

**Systems Auto-Merge**:
- **Parent Selection**: NetBIOS hostname (no FQDN) becomes parent
- **Normalization**: Strip domain, convert to uppercase (SERVER01.corp.local → SERVER01)
- **Merge Rules**:
  - Blank parent fields populated from child data
  - Multiple IPs collected in `## Known IP Addresses` section of analyst notes
  - Compromised status priority: yes > no > unknown
- **Example**: SERVER01 + server01.domain.local (IP: 192.168.1.10) → SERVER01 with IP populated

**Users Auto-Merge**:
- **Parent Selection**: Username without domain prefix
- **Normalization**: Strip DOMAIN\\ prefix and @domain suffix, lowercase
- **SID Validation**: Different SIDs = different users (prevents merging different people with same username)
- **Example**: jsmith + DOMAIN\\jsmith (same SID) → Merged to jsmith

### Manual Combine (Not Yet Implemented)

Planned feature for manual consolidation of duplicates (see `/opt/casescope/app/utils/merge_helpers.py` for helper functions).

### Implementation Notes

**Systems**:
- Primary key: `(hostname, case_id)`
- Normalizes FQDN → hostname only
- Updates IP if new data has IP and existing doesn't

**Users**:
- Primary key: `(username, case_id)`
- Handles variants: `user`, `DOMAIN\user`, `user@domain`
- Normalizes to base username

### Source Tracking

All assets track where they came from:
- `manual` - Created by analyst via UI
- `logs` - Auto-discovered from events
- `csv_import` - Bulk imported from CSV
- `ioc_extraction` - Found during IOC extraction
- `edr` - Extracted from EDR reports (systems only)

### Audit Trail

All create/update/delete operations logged to `audit_log` table:
- `resource_type`: 'known_system' or 'known_user'
- `resource_id`: System/user ID
- `action_type`: 'create', 'update', 'delete', 'bulk_update', 'bulk_delete'
- `user_id`: Who performed the action
- `details`: JSON with changes

---

## Performance

**Discovery Speed**:
- Systems: ~2,000 events/sec aggregation
- Users: ~3,000 events/sec aggregation
- Typical 1M event case: 30-60 seconds

**Database Queries**:
- Indexed on: hostname, username, case_id, compromised, source
- Pagination efficient (OFFSET/LIMIT)
- Search uses ILIKE for partial matches

---

## Troubleshooting

### Discovery Not Finding Systems/Users

**Check**:
1. Events indexed? (`case_{id}` index exists?)
2. Normalized fields present? (`normalized_computer` for systems)
3. Field names match expected patterns?

**Debug**:
```bash
# Check for computer fields in events
curl -s "http://localhost:9200/case_3/_search" -H 'Content-Type: application/json' -d '{
  "size": 1,
  "_source": ["computer", "normalized_computer", "host.hostname"]
}'

# Check for username fields
curl -s "http://localhost:9200/case_3/_search" -H 'Content-Type: application/json' -d '{
  "size": 1,
  "_source": ["TargetUserName", "SubjectUserName", "user.name"]
}'
```

### Too Many Noise Users

**Solution**: Exclusion patterns are applied during discovery. Delete noise users and re-run discovery:

```sql
-- Delete computer accounts (end with $)
DELETE FROM known_users WHERE case_id = 3 AND username LIKE '%$';

-- Delete service accounts
DELETE FROM known_users WHERE case_id = 3 AND username IN (
  'LocalSystem', 'IUSR', 'DefaultAppPool', 'nsi'
);
```

Then re-run "🔍 Find in Logs" - excluded accounts won't be re-added.

### Duplicates After Discovery

**For Systems**: Should auto-deduplicate by normalized hostname  
**For Users**: Should auto-deduplicate by normalized username

If duplicates persist, check:
- FQDN vs short hostname (should normalize)
- Domain prefix variations (DOMAIN\user vs user)

---

## Related Documentation

- **Database Schema**: [DATABASE_STRUCTURE.MD](DATABASE_STRUCTURE.MD)
- **Search System**: [SEARCH_SYSTEM.md](SEARCH_SYSTEM.md)
- **Permissions**: [PERMISSIONS.MD](PERMISSIONS.MD)
- **Audit Logging**: [AUDIT.MD](AUDIT.MD)


