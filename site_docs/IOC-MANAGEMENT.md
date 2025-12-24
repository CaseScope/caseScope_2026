# IOC Management System

**Last Updated:** 2025-12-24  
**Status:** Active  
**Location:** `/ioc/manage`

## Overview

The IOC (Indicators of Compromise) Management System provides comprehensive functionality for tracking, analyzing, and managing threat intelligence indicators within CaseScope. It supports both manual entry and automated extraction from EDR reports.

---

## Core Components

### 1. Database Model (`/app/models.py`)

**Table:** `ioc`

**Key Fields:**
- `id` - Primary key
- `type` - IOC type (ipv4, domain, md5, filename, command_line, username, etc.)
- `value` - The actual IOC value
- `category` - Category (network, file, host, identity, vulnerability, cloud, mobile)
- `threat_level` - Severity (info, low, medium, high, critical)
- `confidence` - Confidence score (0-100)
- `is_active` - Whether IOC is currently active
- `is_whitelisted` - Whether IOC is whitelisted
- `is_hidden` - Whether IOC is hidden from default view
- `first_seen` - Timestamp of first observation
- `last_seen` - Timestamp of last observation
- `times_seen` - Count of observations
- `expires_at` - Optional expiration timestamp
- `source` - Source of IOC (manual, ai_extraction, event_extraction, threat_feed, etc.)
- `source_reference` - Reference to source (URL, ticket number, etc.)
- `description` - IOC description
- `analyst_notes` - Analyst notes and observations
- `case_id` - Associated case
- `parent_ioc_id` - Optional parent IOC for relationships
- `metadata` - JSON metadata field
- `enrichment` - JSON enrichment data
- `created_by`, `updated_by` - User tracking
- `created_at`, `updated_at` - Timestamps

---

## Features

### 1. Manual IOC Management

**Add IOC (`/ioc/api/create`)**
- Manual entry via modal form
- Duplicate detection before creation
- Overlap detection (e.g., shorter username in longer username)
- Audit logging with full IOC details
- Permission: Analyst or Administrator

**Edit IOC (`/ioc/api/update/<id>`)**
- Update any IOC fields
- Tracks original vs new values
- Detailed audit logging of all changes
- Permission: Analyst or Administrator

**Delete IOC (`/ioc/api/delete/<id>`)**
- Individual IOC deletion
- Stores IOC details before deletion
- Audit logging with complete IOC snapshot
- Permission: Analyst or Administrator (security+)

**Bulk Operations**
- Bulk Edit (`/ioc/api/bulk_update`)
  - Update multiple IOCs at once
  - Tracks changes for each IOC
  - Audit logging with all modifications
- Bulk Delete (`/ioc/api/bulk_delete`)
  - Delete multiple IOCs at once
  - Logs all deleted IOC details
  - Permission: Analyst or Administrator

### 2. Automated IOC Extraction

**From EDR Reports (`/hunting/api/extract_edr_iocs`)**

**Extraction Methods:**

1. **Primary: AI-Based Extraction (Ollama)**
   - Uses LLM to intelligently extract IOCs
   - Understands context and relationships
   - Extracts full command lines, paths, and usernames
   - Identifies MITRE ATT&CK techniques
   - Creates timeline of events
   - Prompt: `/app/ai/ai_prompts/ioc_extraction.md`

2. **Fallback: Regex-Based Extraction**
   - Activated when AI is unavailable
   - Uses comprehensive regex patterns
   - Location: `/app/utils/ioc_extractor.py`
   - Extracts:
     - Network: IPv4, IPv6, domains, URLs, emails, user-agents
     - File: MD5, SHA1, SHA256, SHA512, SSDEEP, filenames, paths
     - Host: SIDs, registry keys, command lines, processes, mutexes, pipes
     - Identity: Usernames, hostnames
     - Threat Intel: CVEs, MITRE ATT&CK IDs
     - Cryptocurrency: Bitcoin, Ethereum, Monero addresses
   - De-obfuscates indicators (hxxp, [.], [at], etc.)

**Extraction Process:**
1. User clicks "Extract IOCs from EDR" button
2. System checks for EDR reports in current case
3. Processes each report separately
4. Modal shows progress (Report X of Y)
5. Attempts AI extraction first
6. Falls back to regex if AI fails
7. Displays extracted IOCs in table format
8. User selects which IOCs to import
9. System handles duplicates intelligently
10. **Automatic Known Systems/Users Processing:**
    - Hostnames automatically added to Known Systems (compromised='yes', source='EDR')
    - Usernames automatically added to Known Users (compromised='yes', source='ioc_extraction')
    - Existing systems/users marked as compromised if not already
    - SIDs and domains extracted when available
    - Cross-variant deduplication applied for usernames

**Automatic Compromised Status:**

When IOCs are extracted from EDR reports, related systems and users are automatically marked as compromised:

- **Known Systems**: 
  - Hostnames found in reports → System created or updated
  - Compromised status set to 'yes'
  - Source set to 'EDR'
  - Note added: "Found in EDR report (IOC extraction) - marked as compromised"
  - FQDN parsing: `server.domain.com` → Hostname: `SERVER`, Domain: `domain.com`

- **Known Users**:
  - Usernames found in reports → User created or updated
  - Compromised status set to 'yes'
  - Source set to 'ioc_extraction'
  - Note added: "Found in EDR report (IOC extraction) - marked as compromised"
  - Domain and SID extracted when available
  - Cross-variant matching: `user`, `DOMAIN\user`, `user@domain` recognized as same user

**Duplicate Handling During Extraction:**

**Batch-Aware Deduplication:**
- Tracks IOCs within current extraction batch
- Prevents duplicates within same report
- Type priority: `filepath > command_line > process_name > filename > username`

**Database Deduplication:**
- Checks existing IOCs before import
- Three merge scenarios:
  1. **Exact Duplicate** - Marked as duplicate, shown but not selectable
  2. **Type Upgrade** - If new type is more specific (e.g., filepath vs filename), upgrades existing IOC
  3. **Username Overlap** - Merges `domain\user` with `user`, keeps most specific

**Merge Actions:**
- Duplicate IOCs shown in grayed-out table rows
- Checkbox disabled for duplicates
- User sees all findings but only imports new/updated IOCs
- Merges add information to existing IOC's analyst notes

### 3. Manual Deduplication (`/ioc/api/find_duplicates`, `/ioc/api/merge_duplicates`)

**Process:**
1. User clicks "Deduplicate" button
2. System analyzes all IOCs in case
3. Groups IOCs by normalized value (case-insensitive)
4. Determines "root" IOC using:
   - Type priority (filepath > command_line > process_name > filename)
   - Age (older IOCs preferred)

**Deduplication Modal:**
- Tree view showing merge plan:
  ```
  🌳 Root IOC (will be kept)
    └── IOC details
    
    Duplicates to merge (N):
    ☑ Duplicate IOC #123
      └── IOC details
    ☑ Duplicate IOC #456
      └── IOC details
  ```
- User can check/uncheck individual duplicates
- Group-level checkbox to select/deselect all in group
- Shows what will be merged before applying

**Merge Behavior:**
- Root IOC retains its ID and base properties
- Duplicate information merged into root's analyst notes:
  - Different types noted (e.g., "Also seen as process_name")
  - Different descriptions appended
  - Analyst notes combined
- Aggregated data:
  - `times_seen` summed
  - `confidence` uses highest value
  - `threat_level` uses highest severity
- Duplicates deleted after merge
- Comprehensive audit logging:
  - Original state of root IOC
  - Adjusted state of root IOC
  - Complete state of each deleted duplicate
  - All changes tracked

### 4. Search and Filtering

**Search (`/ioc/api/list`)**
- Searches: value, description, analyst_notes
- Real-time filtering
- Supports wildcards (via SQL ILIKE)

**Filters:**
- **Visibility:**
  - Hide Hidden (default)
  - All (show hidden and visible)
  - Hidden Only
- **Category:** network, file, host, identity, vulnerability, cloud, mobile
- **Threat Level:** critical, high, medium, low, info
- **Type:** All IOC types available

**Pagination:**
- Default: 50 per page
- Options: 25, 50, 100
- First/Previous/Next/Last navigation
- Page number selection

### 5. Export

**CSV Export (`/ioc/api/export_csv`)**
- Exports IOCs matching current filters
- Includes all IOC fields
- Filename: `iocs_{case_name}.csv`
- Columns:
  - ID, Type, Value, Category, Threat Level, Confidence
  - Status flags (Active, Whitelisted, Hidden)
  - Timestamps (First Seen, Last Seen, Created, Updated)
  - Times Seen, Source, Source Reference
  - Description, Analyst Notes
  - Case ID
- Audit logged

---

## IOC Types

### Network
- `ipv4` - IPv4 Address
- `ipv6` - IPv6 Address
- `domain` - Domain name
- `fqdn` - Fully Qualified Domain Name
- `url` - URL
- `email_address` - Email address
- `email_sender` - Email sender
- `user_agent` - HTTP User-Agent string

### File
- `md5` - MD5 hash
- `sha1` - SHA1 hash
- `sha256` - SHA256 hash
- `sha512` - SHA512 hash
- `ssdeep` - SSDEEP fuzzy hash
- `imphash` - Import hash
- `filename` - Filename only
- `filepath` - Full file path

### Host
- `hostname` - Hostname
- `registry_key` - Windows registry key
- `process_name` - Process name
- `command_line` - Full command line
- `service_name` - Service name
- `scheduled_task` - Scheduled task name
- `mutex` - Mutex name
- `named_pipe` - Named pipe

### Identity
- `username` - Username (with or without domain)
- `sid` - Windows Security Identifier

### Vulnerability
- `cve_id` - CVE identifier
- `malware_family` - Malware family name
- `mitre_attack_id` - MITRE ATT&CK technique ID

---

## Permissions

| Action | Read-Only | Analyst | Administrator |
|--------|-----------|---------|---------------|
| View IOCs | ✓ | ✓ | ✓ |
| Add IOC | ✗ | ✓ | ✓ |
| Edit IOC | ✗ | ✓ | ✓ |
| Delete IOC | ✗ | ✓ | ✓ |
| Bulk Edit | ✗ | ✓ | ✓ |
| Bulk Delete | ✗ | ✓ | ✓ |
| Extract IOCs | ✗ | ✓ | ✓ |
| Deduplicate | ✗ | ✓ | ✓ |
| Export CSV | ✓ | ✓ | ✓ |

---

## Audit Logging

All IOC operations are logged to the audit log with detailed information:

**Manual IOC Creation** (`ioc_created_manual`)
- User, case, timestamp
- Complete IOC details (type, value, category, threat level, confidence, source, description, notes)

**IOC Edited** (`ioc_updated`)
- User, case, timestamp
- Field-by-field changes (old value → new value)

**IOC Deleted** (`ioc_deleted`)
- User, case, timestamp
- Complete IOC snapshot before deletion

**Bulk Operations** (`iocs_bulk_updated`, `iocs_bulk_deleted`)
- User, case, timestamp
- Changes for each IOC
- Count of affected IOCs

**Automated Extraction** (`iocs_extracted_from_edr`)
- User, case, timestamp
- Count of new IOCs created
- Count of existing IOCs updated
- List of all IOCs with their details
- Whether created or updated

**Manual Deduplication** (`iocs_manually_deduplicated`)
- User, case, timestamp
- For each root IOC:
  - Original state (all fields)
  - Adjusted state (all fields)
  - Specific changes (threat_level, confidence, times_seen, analyst_notes)
- For each merged duplicate:
  - Complete state before deletion
- Total count of merges

---

## UI Components

### Main IOC Table
- Columns: Category, Type, Threat Level, Confidence, Value, Description, Last Seen, Actions
- Checkbox column for bulk selection
- Bulk actions bar appears when IOCs selected
- Color-coded badges for categories and threat levels
- Responsive design

### Statistics Cards
- Total IOCs
- Critical count
- High count  
- Network IOCs count

### Modals

**Add/Edit IOC Modal**
- Form with all IOC fields
- Required fields marked
- Duplicate warning before creation
- Status controls (Active, Whitelisted, Hidden) for editing

**Duplicate Warning Modal**
- Shows exact duplicates
- Shows overlapping IOCs
- Provides context for decision
- "Create Anyway" option

**IOC Details Modal**
- Read-only view of all IOC fields
- Formatted timestamps
- Edit button

**Deduplication Modal**
- Tree view of merge groups
- Individual and group-level checkboxes
- Shows what will be kept vs merged
- Confirmation before applying

**EDR Extraction Modal**
- Progress indicator (Report X of Y)
- Extraction summary with analysis
- Table of found IOCs with checkboxes
- Save & Next / Skip / Cancel buttons
- Duplicates shown but disabled

---

## API Endpoints

| Endpoint | Method | Purpose | Permission |
|----------|--------|---------|------------|
| `/ioc/manage` | GET | Main IOC page | User |
| `/ioc/api/list` | GET | List IOCs (paginated) | User |
| `/ioc/api/get/<id>` | GET | Get single IOC | User |
| `/ioc/api/stats` | GET | Get IOC statistics | User |
| `/ioc/api/create` | POST | Create new IOC | Analyst+ |
| `/ioc/api/update/<id>` | PUT | Update IOC | Analyst+ |
| `/ioc/api/delete/<id>` | DELETE | Delete IOC | Analyst+ |
| `/ioc/api/check_duplicate` | POST | Check for duplicates | Analyst+ |
| `/ioc/api/bulk_update` | POST | Bulk update IOCs | Analyst+ |
| `/ioc/api/bulk_delete` | POST | Bulk delete IOCs | Analyst+ |
| `/ioc/api/export_csv` | GET | Export IOCs to CSV | User |
| `/ioc/api/find_duplicates` | GET | Find duplicate IOCs | Analyst+ |
| `/ioc/api/merge_duplicates` | POST | Merge duplicates | Analyst+ |
| `/hunting/api/check_edr` | GET | Check for EDR reports | User |
| `/hunting/api/extract_edr_iocs` | POST | Extract IOCs from EDR | Analyst+ |
| `/hunting/api/save_extracted_iocs` | POST | Save extracted IOCs | Analyst+ |

---

## Integration Points

### Case Management
- IOCs are case-specific
- Session-based case selection
- Read-only users restricted to assigned case

### Audit System
- All operations logged
- Detailed before/after states
- Full traceability

### AI System  
- Primary extraction method
- Uses configured LLM model
- Structured JSON output
- Context-aware extraction

### Regex Fallback System
- Automatic fallback when AI unavailable
- Comprehensive pattern matching
- De-obfuscation support
- Returns same JSON structure as AI

---

## Best Practices

1. **Review Extractions:** Always review AI-extracted IOCs before importing
2. **Add Context:** Use description and analyst notes fields
3. **Set Confidence:** Adjust confidence levels based on source reliability
4. **Regular Deduplication:** Run deduplication periodically to keep database clean
5. **Use Filters:** Leverage filters to focus on relevant IOCs
6. **Export for Sharing:** Export IOCs as CSV for sharing with other tools
7. **Check Duplicates:** Review duplicate warnings before force-creating
8. **Audit Review:** Check audit logs for IOC changes

---

## Technical Notes

### Performance
- Pagination prevents large result sets
- Indexes on case_id, value, type for fast queries
- Batch processing for extractions
- Efficient deduplication algorithm

### Validation
- Type-specific validation for IOC values
- Required field enforcement
- Length limits on text fields
- Enum validation for categories and threat levels

### Error Handling
- Graceful AI fallback to regex
- User-friendly error messages
- Transaction rollback on failures
- Detailed error logging

---

## Future Enhancements

- [ ] Enrichment integration (VirusTotal, etc.)
- [ ] Automated expiration based on age
- [ ] IOC relationships and graph view
- [ ] Threat feed integration
- [ ] STIX/TAXII import/export
- [ ] IOC scoring system
- [ ] Automated whitelisting
- [ ] IOC templates

---

## Related Documentation

- **AI System:** `/site_docs/AI_SYSTEM.MD`
- **Audit System:** `/site_docs/AUDIT.MD`
- **Permissions:** `/site_docs/PERMISSIONS.MD`
- **Database Structure:** `/site_docs/DATABASE_STRUCTURE.MD`

