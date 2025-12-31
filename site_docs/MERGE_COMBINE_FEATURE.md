# Merge & Combine Feature

## Overview

The merge and combine feature provides automatic duplicate detection and manual consolidation for Known Systems, Known Users, and IOCs. This helps maintain clean, deduplicated data across the platform.

## Two Types of Operations

### 1. **Auto-Merge** (Automatic)
- Happens during discovery, CSV import, and manual creation
- Detects variants of the same item (e.g., `SERVER01` and `server01.domain.local`)
- Merges data into existing "parent" record
- Runs automatically - no user interaction required

### 2. **Manual Combine** (User-Initiated)
- User selects 2+ items and chooses which should be the parent
- All child items merge into parent and are deleted
- Shows confirmation modal with warnings if combining different types
- Provides detailed summary of what was merged

---

## Auto-Merge Logic

### Known Systems

**Parent Selection:**
- NetBIOS hostname (no FQDN) is the parent
- Example: `SERVER01` is parent, `server01.domain.local` merges into it

**Normalization:**
- Strip FQDN (everything before first `.`)
- Convert to uppercase
- `server01.corp.local` → `SERVER01`

**Merge Rules:**
- If parent field blank and child has data → copy to parent
- If both have data → add to parent's analyst notes
- All IP addresses collected in `## Known IP Addresses` section
- Compromised status priority: `yes` > `no` > `unknown`

**Example:**
```
Existing: SERVER01 (no IP, no domain)
New Discovery: server01.domain.local (IP: 192.168.1.10, domain: corp.local)

Result:
- Hostname: SERVER01 (parent)
- IP: 192.168.1.10 (copied from child)
- Domain: corp.local (copied from child)
- Analyst Notes:
  ## Auto-Merge History
  - 2024-12-30 15:30:00: Also seen as **server01.domain.local** (IP: 192.168.1.10)
```

### Known Users

**Parent Selection:**
- Username without domain prefix is the parent
- Example: `jsmith` is parent, `DOMAIN\jsmith` merges into it

**Normalization:**
- Strip domain prefix (`DOMAIN\user` → `user`)
- Strip email domain (`user@domain.com` → `user`)
- Convert to lowercase

**SID Validation (CRITICAL):**
- If SID provided and matches → merge
- If SID provided and DIFFERS → create NEW user (different person)
- If no SID → merge if username matches

**Example 1 - Same Person:**
```
Existing: jsmith (SID: S-1-5-21-XXX-1001)
New: DOMAIN\jsmith (SID: S-1-5-21-XXX-1001)

Result: MERGED (SIDs match)
```

**Example 2 - Different People:**
```
Existing: admin (SID: S-1-5-21-LOCAL-500)
New: DOMAIN\admin (SID: S-1-5-21-DOMAIN-500)

Result: TWO SEPARATE USERS (SIDs differ)
```

### IOCs

IOCs already have duplicate detection via `api_check_duplicate`, but the new combine feature provides:
- Manual consolidation of related IOCs
- Markdown-based analyst notes
- Event hit reassignment

---

## Manual Combine Workflow

### UI Flow:

1. **Select Items**: Check 2+ items of the same type
2. **Click "Combine"**: Button appears in bulk actions bar
3. **Select Parent**: Choose which item should be the parent
4. **Review Warnings**: If combining different types/statuses, warnings shown
5. **Confirm**: Click "Combine" to proceed
6. **View Summary**: Modal shows what was merged

### Warnings Shown When:

**Systems:**
- Mixing different `system_type` (e.g., server + workstation)
- Mixing different `compromised` status (yes + no)

**Users:**
- Mixing different `user_type` (domain + local)
- Mixing different `compromised` status
- **CRITICAL**: Different SIDs detected

**IOCs:**
- Mixing different IOC types (ipv4 + domain)
- Mixing different threat levels

### Field Merge Priority:

**Parent Always Wins:**
- `system_type`, `user_type`, `category`
- All structural fields in parent take precedence

**Smart Merge:**
- `compromised`: `yes` > `no` > `unknown`
- `threat_level`: `critical` > `high` > `medium` > `low` > `info`
- `confidence`: highest value wins
- `times_seen`: values summed

**Append to Notes:**
- If both have same field with different values → child value added to analyst notes
- All child analyst_notes appended to parent under `## Original Notes`

---

## Analyst Notes Format

### Markdown Structure:

```markdown
## Auto-Merge History
- 2024-12-30 15:30:00: Also seen as **SERVER01.domain.local** (IP: 192.168.1.10, domain: corp.local)
- 2024-12-30 16:00:00: Also seen as **server01** (IP: 10.0.0.5)

## Known IP Addresses
- 192.168.1.10 (current as of 2024-12-30 15:30:00)
- 10.0.0.5

## Manual Merge History
- 2024-12-30 17:00:00: Merged from **SERVER01-OLD** (ID #123)
  - `ip_address`: 172.16.0.99
  - `domain_name`: old.domain.com
  - `description`: Legacy server entry

## Original Notes
### From merged item:
Old server that was decommissioned in Q3.

[Other original analyst notes content...]
```

---

## API Endpoints

### Systems:
- `POST /systems/api/combine` - Manual combine
  - Body: `{parent_id: 1, child_ids: [2, 3], confirmed: false}`
  - Returns: Summary with before/after states

### Users:
- `POST /users/api/combine` - Manual combine
  - Body: `{parent_id: 1, child_ids: [2, 3], confirmed: false}`
  - Returns: Summary with before/after states

### IOCs:
- `POST /ioc/api/combine` - Manual combine (new)
- `POST /ioc/api/merge_duplicates` - Auto-deduplication (existing, kept for backward compatibility)

---

## Testing

### Test Files Provided:

**`examples/test_systems_merge.csv`**
- Tests FQDN normalization (SERVER01 variants)
- Tests multiple IPs for same system
- Tests case-insensitive matching

**`examples/test_users_merge.csv`**
- Tests domain prefix handling (CORP\user variants)
- Tests SID validation (different SIDs = different users)
- Tests email format (@domain.com)

### Manual Test Scenarios:

**1. Systems Auto-Merge (CSV Import)**
```bash
# Import test file
# Expected: 3 unique systems created
# - SERVER01 (3 variants merged, 2 IPs collected)
# - WORKSTATION-99 (2 variants merged)
# - DC01 (2 variants merged)
```

**2. Users SID Validation**
```bash
# Import test file
# Expected: 3 unique users created
# - jsmith (3 variants merged, same SID)
# - admin (2 SEPARATE users - different SIDs)
# - tabadmin (2 variants merged, same SID)
```

**3. Manual Combine**
```bash
# Create 2 systems manually with different data
# Select both → Combine → Choose parent
# Verify summary shows merged fields
# Verify analyst notes contain merge history
```

---

## Database Changes

No schema changes required! All functionality works with existing tables.

**Indexes Used:**
- `idx_known_systems_hostname` - fast hostname lookups
- `idx_known_users_username` - fast username lookups
- Case-insensitive comparisons via `db.func.lower()` / `db.func.upper()`

**No Unique Constraints Added:**
- Allows multiple users with same username (different SIDs)
- Allows multiple systems with same hostname (different IPs/domains)

---

## Audit Logging

All merge/combine operations logged with full detail:

**Auto-Merge:**
```json
{
  "action": "system_discovery_completed",
  "details": {
    "new_systems": 10,
    "merged_systems": 15,
    "new_systems_list": [...],
    "updated_systems_list": [...]
  }
}
```

**Manual Combine:**
```json
{
  "action": "systems_combined",
  "resource_id": 123,
  "details": {
    "parent": {
      "id": 123,
      "before": {...},
      "after": {...}
    },
    "children_merged": [
      {"id": 124, "data_merged": [...]}
    ],
    "total_merged": 2
  }
}
```

---

## Implementation Files

**Backend:**
- `app/utils/merge_helpers.py` - Core merge logic
- `app/routes/known_systems.py` - Systems auto-merge + combine
- `app/routes/known_users.py` - Users auto-merge + combine (with SID validation)
- `app/routes/ioc.py` - IOC combine endpoint
- `app/tasks/task_discover_systems.py` - Discovery auto-merge
- `app/tasks/task_discover_users.py` - User discovery auto-merge

**Frontend:**
- `templates/systems/manage.html` - UI for systems
- `templates/users/manage.html` - UI for users
- `templates/ioc/manage.html` - UI for IOCs

---

## Performance Considerations

**CSV Import (1000+ rows):**
- Loads existing items into memory dict
- Fast hash-based lookups
- Batch commits every 100 rows

**Discovery Tasks:**
- Uses OpenSearch aggregations (fast)
- Auto-merge happens in Python (not DB)
- Single commit at end

**Manual Combine:**
- Processes sequentially (1 merge = 1 transaction)
- Safe for large analyst_notes (no size limit)

---

## Future Enhancements

Possible future improvements:
1. **One-time consolidation** - Script to merge all existing duplicates
2. **Merge suggestions** - AI-powered duplicate detection
3. **Undo capability** - Soft-delete with recovery window
4. **Bulk combine** - Combine multiple groups at once
5. **Smart IP tracking** - Detect DHCP vs static IPs

