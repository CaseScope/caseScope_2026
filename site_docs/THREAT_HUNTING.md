# Threat Hunting System - IOC & SIGMA

**Last Updated**: 2025-12-26  
**Status**: ✅ Production Ready  
**Location**: `/hunting/dashboard`

---

## Overview

The Threat Hunting System provides comprehensive automated threat detection using both IOC (Indicators of Compromise) matching and SIGMA rule detection. Events matching IOCs or Sigma rules are automatically tagged and displayed with color-coded badges in search results.

---

## Core Components

### 1. IOC Hunting

**Database Table**: `event_ioc_hits`

**Purpose**: Automatically scan all events in a case for known IOCs and tag matching events.

#### Features
- Multi-strategy search based on IOC type (IPs, hashes, domains, files, URLs, emails, commands)
- Prioritizes structured fields over search_blob
- Uses OpenSearch scroll API for efficient iteration through large datasets
- Real-time progress updates (0-100%)
- Batch commits (every 100 records) to prevent memory issues
- Handles duplicate detection
- Clear/re-scan option to remove outdated detections

#### How It Works

1. User clicks **"🎯 Hunt IOCs"** button
2. Modal presents option to clear previous detections (default: checked)
3. Background task starts (`task_hunt_iocs.py`):
   - Clears old detections (if requested)
   - Gets all active IOCs for the case
   - For each IOC type, constructs optimized OpenSearch query
   - Scans events using scroll API (1000 events per batch)
   - Matches IOCs to events and determines matched field
   - Creates `EventIOCHit` records in database
   - Updates progress: `xxx,xxx events scanned (zzz%)`
4. Results displayed in modal:
   - Events scanned / Events tagged
   - Total IOC hits
   - Hits by threat level (Critical, High, Medium, Low, Info)
   - Hits by IOC table (sorted by hit count)

#### Smart Search Strategies

**By IOC Type**:
1. **IPv4**: Searches IpAddress, SourceAddress, DestAddress, ClientIPAddress (EVTX), src_ip, dst_ip, extracted_ips (firewall CSV), normalized_source_ip, normalized_dest_ip (normalized fields)
2. **File Hashes**: Searches Hashes, Hash, MD5, SHA1, SHA256 fields (case-insensitive)
3. **Domain**: Searches DestinationHostname, QueryName, TargetServerName fields
4. **File Name**: Searches TargetFilename, ImagePath, FileName fields
5. **File Path**: Searches file paths and CommandLine with phrase matching
6. **URL**: Searches Url, RequestUrl fields
7. **Email**: Searches EmailAddress, Sender, Recipient fields
8. **Command**: Searches CommandLine, ProcessCommandLine fields
9. **Generic**: Falls back to search_blob for unknown types

#### IOC Badges in Search Results

- **Column**: "IOCs" column in event search results
- **Badge Display**: Shows IOC type badges (e.g., "file", "command_line", "domain")
- **Color Coding**: Badges colored by threat level:
  - 🔴 Red (`badge-error`) - Critical
  - 🟠 Orange (`badge-warning`) - High
  - 🔵 Blue (`badge-info`) - Medium
  - Gray (`badge-secondary`) - Low/Info
- **Smart Grouping**: One badge per IOC type found in event
- **Tooltip**: Hover to see IOC details

---

### 2. SIGMA Rule Hunting

**Database Tables**: 
- `event_sigma_hits` - Detection results
- `sigma_rules` - Rule management (3,652 total rules)

**Purpose**: Scan EVTX files against enabled SIGMA detection rules using Chainsaw binary.

#### Infrastructure
- **Chainsaw Binary**: v2.13.1 at `/opt/casescope/bin/chainsaw`
- **Sigma Rules**: 3,652 rules at `/opt/casescope/rules/sigma/` (across 4 source folders)
- **Chainsaw Mappings**: `/opt/casescope/rules/mappings/`
- **Rule Management**: `/settings/sigma-rules` (Settings page)

#### Current Rule Counts
- **rules**: 3,083 core detection rules
- **rules-emerging-threats**: 436 threat-specific rules
- **rules-threat-hunting**: 131 hunting-focused rules
- **rules-compliance**: 2 compliance rules
- **Total**: 3,652 rules

#### Features
- **Enabled Rules Only**: Only uses rules enabled in database (toggle switches control hunting)
- Background processing with progress tracking
- Runs Chainsaw against each completed, non-hidden EVTX file
- Parses JSON output and matches to OpenSearch events
- Stores rule title, severity, and MITRE tags
- Supports clear/re-scan option
- Bulk toggle buttons:
  - **🎯 Threat Hunting**: Enable threat-hunting + emerging-threats only (567 rules)
  - **✓ All Rules**: Enable all 3,652 rules
- Severity-based badge colors:
  - 🔴 Critical/High = Red (`badge-error`)
  - 🟠 Medium = Orange (`badge-warning`)
  - 🔵 Low/Info = Blue (`badge-info`)

#### How It Works

1. User clicks **"🟣 Hunt SIGMA Rules"** button
2. Modal presents option to clear previous detections (default: checked)
3. Background task starts (`task_hunt_sigma.py`):
   - Clears old detections (if requested)
   - **Queries database for enabled rules only** (`is_enabled = True`)
   - Creates temporary directory with symlinks to enabled rule files
   - Gets all completed, non-hidden EVTX files where:
     - `file_type = 'evtx'`
     - `is_hidden = False`
     - `status = 'indexed'`
   - For each file:
     - Runs Chainsaw: `chainsaw hunt <file> -s <temp_dir> --mapping /mappings --json`
     - Parses JSON array output
     - Matches detections to OpenSearch events by:
       - Event Record ID (most reliable)
       - Computer name + Event ID + Timestamp (±5 sec tolerance)
     - Creates `EventSigmaHit` records in database
     - Updates progress: `xxx/yyy files checked, zzz%`
   - Cleans up temporary directory
4. Results displayed in modal:
   - Files checked / Files ignored
   - Events tagged
   - Total detections
   - Top 20 rules matched (by title)

#### Rule Management

**Settings Page**: `/settings/sigma-rules`

Features:
- View all 3,652 rules with metadata
- Toggle switches to enable/disable individual rules
- Search and filter by: title, ID, tags, source folder, level, status
- Pagination (50 rules per page)
- **Update from GitHub**: Clone/pull latest rules from SigmaHQ/sigma repository
- **Sync from Disk**: Scan filesystem and sync to database
- **Bulk Operations**:
  - **Threat Hunting Mode**: Enable 567 rules (threat-hunting + emerging-threats), disable others
  - **All Rules Mode**: Enable all 3,652 rules

**Important**: Toggle switches immediately affect next hunt - no service restart required!

#### Event Matching Strategy

Chainsaw outputs detections with:
- `timestamp`, `computer`, `event_id`, `event_record_id`
- Rule metadata: `name` (title), `level`, `tags`

Matching prioritizes:
1. **Event Record ID** (exact match) - most reliable
2. **Computer + Event ID + Timestamp** (±5 sec window)

#### SIGMA Badges in Search Results

- **Column**: "SIGMA Detections" column in event search results
- **Badge Display**: Shows count (e.g., "3 rules")
- **Color Coding**: Based on highest severity:
  - 🔴 Red (`badge-error`) - Critical/High
  - 🟠 Orange (`badge-warning`) - Medium
  - 🔵 Blue (`badge-info`) - Low/Informational
- **Tooltip**: Hover to see matched rule titles and severity levels

---

## API Endpoints

### IOC Hunting

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/hunting/api/hunt_iocs` | POST | Start IOC hunt |
| `/hunting/api/hunt_iocs/status/<task_id>` | GET | Check hunt progress |

**Start Hunt Request**:
```json
{
  "clear_previous": true
}
```

**Status Response**:
```json
{
  "state": "PROGRESS",
  "progress": 75,
  "current_ioc": "malicious.exe",
  "stats": {
    "events_scanned": 50000,
    "total_events": 100000,
    "events_with_hits": 25,
    "total_hits": 32
  }
}
```

### SIGMA Hunting

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/hunting/api/hunt_sigma` | POST | Start Sigma hunt |
| `/hunting/api/hunt_sigma/status/<task_id>` | GET | Check hunt progress |

**Start Hunt Request**:
```json
{
  "clear_previous": true
}
```

**Status Response**:
```json
{
  "state": "PROGRESS",
  "progress": 50,
  "percent": 50,
  "current_file": "Security.evtx",
  "stats": {
    "files_processed": 5,
    "total_files": 10,
    "events_tagged": 42,
    "total_hits": 64
  }
}
```

### SIGMA Rule Management

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/settings/sigma-rules` | GET | Management page |
| `/settings/sigma-rules/api/list` | GET | List rules (paginated) |
| `/settings/sigma-rules/api/toggle` | POST | Enable/disable rule |
| `/settings/sigma-rules/api/bulk-toggle` | POST | Bulk enable/disable |
| `/settings/sigma-rules/api/update` | POST | Update from GitHub |
| `/settings/sigma-rules/api/sync` | POST | Sync from disk |

---

## User Interface

### Threat Hunting Dashboard

**Location**: `/hunting/dashboard`

**Buttons**:
- **🎯 Hunt IOCs** - Launch IOC hunting
- **🟣 Hunt SIGMA Rules** - Launch Sigma hunting

Both buttons open modals with:
- Clear previous detections option (checkbox, default: checked)
- Progress view:
  - Animated progress bar (0-100%)
  - Current status message
  - Current IOC/file being processed
  - Live statistics grid
- Results view:
  - Success message
  - Summary statistics
  - Detailed results table

**Auto-refresh**: Progress checks every 2 seconds

### SIGMA Rule Management

**Location**: `/settings/sigma-rules`

**Features**:
- Statistics cards: Total rules, Enabled, Disabled, Source folders
- Source folder breakdown cards
- Bulk action buttons (top right):
  - **🎯 Threat Hunting**: Enable threat-hunting + emerging-threats only
  - **✓ All Rules**: Enable all rules
- Action buttons:
  - **Update Rules from GitHub**: Clone/pull latest from SigmaHQ/sigma
  - **Sync from Disk**: Scan filesystem and sync to database
- Search and filter:
  - Text search (title, ID, MITRE tags)
  - Source folder filter
  - Rule level filter (Critical, High, Medium, Low, Informational)
  - Status filter (Enabled, Disabled, All)
- Rules table:
  - Toggle switches for enable/disable
  - Rule title and path
  - Level badge (color-coded)
  - Category
  - Source folder
  - MITRE ATT&CK tags with technique numbers
  - Pagination (50 per page)

---

## Performance

### IOC Hunting
- **OpenSearch Scroll API**: Bypasses 10k result limit
- **Batch Processing**: Processes 1000 events at a time
- **Batch Commits**: Commits to DB every 100 records
- **Duplicate Prevention**: Database constraint + query check
- **5-minute scroll timeout**: Balances performance and resource usage
- **Typical Performance**: Handles 30M+ events gracefully

### SIGMA Hunting
- **Enabled rules only**: Performance scales with enabled rule count
- **Threat Hunting mode**: 567 rules (faster)
- **All Rules mode**: 3,652 rules (comprehensive)
- **Chainsaw execution**: 30-180 seconds per EVTX file (depends on file size and rule count)
- **Large cases** (1,000 files): 30+ minutes total (depends on enabled rules)
- **Database inserts**: Batch size 100 for efficiency
- **Temporary directory**: Symlinks created/cleaned up per hunt

---

## Security & Audit

### Permissions
- **Read-only users**: Cannot hunt (view results only)
- **Analysts**: Can hunt and manage rules
- **Administrators**: Can hunt and manage rules

### Audit Logging
- Hunt start events:
  - `ioc_hunt_started` - IOC hunt initiated
  - `sigma_hunt_started` - Sigma hunt initiated
- Rule management events:
  - `toggle_sigma_rule` - Individual rule enabled/disabled
  - `bulk_toggle_sigma_rules` - Bulk rule changes
  - `update_sigma_rules` - GitHub update triggered
  - `sync_sigma_rules` - Disk sync triggered
- Includes task_id, user, and operation details

---

## Files Modified/Created

### IOC Hunting
1. `/opt/casescope/migrations/add_event_ioc_hits.sql` - Database schema
2. `/opt/casescope/app/models.py` - Added `EventIOCHit` model
3. `/opt/casescope/app/tasks/task_hunt_iocs.py` - Celery task
4. `/opt/casescope/app/routes/hunting.py` - Added IOC hunt API routes
5. `/opt/casescope/app/routes/search.py` - Added IOC badge integration
6. `/opt/casescope/templates/hunting/dashboard.html` - Added button, modal, JavaScript
7. `/opt/casescope/templates/search/events.html` - Added IOCs column and badge display
8. `/opt/casescope/app/celery_app.py` - Registered task

### SIGMA Hunting
1. `/opt/casescope/bin/chainsaw` - Binary (9.9MB)
2. `/opt/casescope/rules/sigma/` - 3,652 rules (42MB)
3. `/opt/casescope/rules/mappings/` - Chainsaw mappings
4. `/opt/casescope/migrations/add_event_sigma_hits.sql` - Detection results table
5. `/opt/casescope/migrations/add_sigma_rules.sql` - Rule management table
6. `/opt/casescope/app/models.py` - Added `EventSigmaHit` and `SigmaRule` models
7. `/opt/casescope/app/tasks/task_hunt_sigma.py` - Celery task (enabled rules only)
8. `/opt/casescope/app/tasks/task_sigma_management.py` - GitHub update and sync tasks
9. `/opt/casescope/app/utils/sigma_utils.py` - Rule parsing and management utilities
10. `/opt/casescope/app/routes/hunting.py` - Added Sigma hunt API routes
11. `/opt/casescope/app/routes/settings.py` - Added SIGMA management API routes
12. `/opt/casescope/app/routes/search.py` - Added Sigma hit counts to event search
13. `/opt/casescope/templates/hunting/dashboard.html` - Button + modal
14. `/opt/casescope/templates/admin/settings.html` - Added SIGMA Rules tile
15. `/opt/casescope/templates/admin/sigma_rules.html` - Management page
16. `/opt/casescope/templates/search/events.html` - Added SIGMA Detections column
17. `/opt/casescope/app/celery_app.py` - Registered Sigma tasks
18. `/opt/casescope/scripts/sync_sigma_rules.py` - Command-line sync utility

---

## Event Tag Filters

Both IOC and Sigma hunts integrate with the event tagging system:

**Four Filter Types** (in Event Search):
1. **📄 Other Events** - Events without tags, IOCs, or Sigma hits
2. **⭐ Tagged Events** - Analyst-tagged events
3. **🔴 IOC Events** - Events with IOC hits
4. **🟣 SIGMA Events** - Events matching Sigma rules

See [EVENT_TAGGING_SYSTEM.md](EVENT_TAGGING_SYSTEM.md) for details.

---

## Troubleshooting

### IOC Hunt Issues

**No hits found:**
- Verify IOCs are active and not whitelisted
- Check IOC types are supported
- Review search strategy for IOC type
- Check OpenSearch connectivity

**Slow performance:**
- Reduce batch size in config
- Check OpenSearch cluster health
- Monitor network latency

**Task fails:**
- Check Celery workers are running
- Review logs: `/opt/casescope/logs/celery_worker.log`
- Verify sufficient disk space

### SIGMA Hunt Issues

**No detections found:**
- Check EVTX files are present and not hidden
- Verify enabled rules: Navigate to Settings → SIGMA Rules
- Verify Chainsaw has execute permissions: `ls -lh /opt/casescope/bin/chainsaw`
- Test Chainsaw manually: `/opt/casescope/bin/chainsaw hunt <file> -s /opt/casescope/rules/sigma/rules`

**Wrong rules being used:**
- Check enabled rules in Settings → SIGMA Rules
- Verify toggle switches match your intent
- Use bulk buttons for quick mode switching

**Events not matching:**
- Check OpenSearch index exists for case
- Verify timestamps in events are correct
- Look at Celery worker logs

**Task fails:**
- Check Celery workers are running: `systemctl status casescope-workers`
- Review logs for errors
- Ensure sufficient disk space for temp files

### SIGMA Rule Management Issues

**No rules showing:**
- Rules need to be synced from disk first
- Click "Sync from Disk" button or run `/opt/casescope/scripts/sync_sigma_rules.py`

**Update from GitHub fails:**
- Check network connectivity: `curl -I https://github.com`
- Check git installed: `which git`
- Check permissions: `ls -la /opt/casescope/rules/sigma`

**Database permission errors:**
- Run migration script: `/opt/casescope/migrations/add_sigma_rules.sql`
- Verify permissions: `sudo -u postgres psql casescope -c "\dp sigma_rules"`

---

## Maintenance

### Update Sigma Rules (monthly recommended)
**Via Web Interface**:
1. Navigate to Settings → SIGMA Rules
2. Click "Update Rules from GitHub"
3. Wait for completion (2-5 minutes)
4. Click "Sync from Disk" if needed

**Via Command Line**:
```bash
cd /opt/casescope/rules/sigma
sudo -u casescope git pull
cd /opt/casescope
source venv/bin/activate
python3 scripts/sync_sigma_rules.py
```

### Clear Old Detections
```sql
-- Clear IOC detections older than 90 days
DELETE FROM event_ioc_hits WHERE detected_at < NOW() - INTERVAL '90 days';

-- Clear Sigma detections older than 90 days  
DELETE FROM event_sigma_hits WHERE detected_at < NOW() - INTERVAL '90 days';
```

### Verify Rule Counts
```bash
sudo -u postgres psql casescope -c "SELECT source_folder, COUNT(*), SUM(CASE WHEN is_enabled THEN 1 ELSE 0 END) as enabled FROM sigma_rules GROUP BY source_folder;"
```

---

## Best Practices

1. **Regular Hunts**: Run IOC and Sigma hunts after adding new evidence
2. **Clear Old Data**: Use clear/re-scan option to remove outdated detections
3. **Review Results**: Check hunt results for false positives
4. **Update Rules**: Keep Sigma rules up-to-date monthly
5. **Monitor Performance**: Watch Celery logs during large hunts
6. **Tag Key Events**: Manually tag important findings for easy reference
7. **Optimize Rule Sets**: Use "Threat Hunting" mode for faster hunts when appropriate
8. **Rule Management**: Disable noisy or irrelevant rules to improve signal-to-noise ratio

---

## Related Documentation

- [IOC-MANAGEMENT.md](IOC-MANAGEMENT.md) - IOC database and management
- [EVENT_TAGGING_SYSTEM.md](EVENT_TAGGING_SYSTEM.md) - Event filtering
- [SEARCH_SYSTEM.md](SEARCH_SYSTEM.md) - Event search interface
- [AUDIT.MD](AUDIT.MD) - Audit logging
- [CELERY_SYSTEM.md](CELERY_SYSTEM.md) - Background task system

---

**Status**: Both IOC and SIGMA hunting systems are production-ready and actively in use. SIGMA rule management system provides full control over detection rules. 🚀

