# Case Cleanup Procedure - Reset Case to Clean State

## Overview
This document outlines all locations where case data is stored and what must be cleaned/reset to return a case to a pristine state (as if no files or events were uploaded).

**Use Cases:**
- Testing ingestion pipeline
- Clearing corrupted data
- Reprocessing all files from scratch
- Decommissioning a case

---

## Case Files Statistics - Data Sources

The case files page shows the following statistics and their data sources:

| Statistic | Value Example | Data Source |
|-----------|---------------|-------------|
| **Total Files** | 1067 | Filesystem: Count of files in `/opt/casescope/storage/case_{case_id}/` |
| **Total Events** | 619,474 | OpenSearch: `curl http://localhost:9200/case_{case_id}/_count` |
| **Indexed Files** | 745 | PostgreSQL: `SELECT COUNT(*) FROM case_file WHERE case_id = X AND status = 'indexed'` |
| **Pending Files** | 107 | Filesystem: Count of files in `/opt/casescope/staging/{case_id}/` |
| **Total Size** | 2.52 GB | Filesystem: Sum of file sizes in `/opt/casescope/storage/case_{case_id}/` |

**Code Reference:** `/opt/casescope/app/routes/case.py` → `case_files_stats()` (lines 431-510)

---

## Data Storage Locations

### 1. PostgreSQL Database (`casescope` database)

#### `case_file` Table
**Purpose:** Tracks metadata for all uploaded files

**Columns:**
```sql
id                 -- Primary key
case_id            -- Foreign key to case.id
filename           -- File name
original_filename  -- Original upload name
file_type          -- evtx, json, csv, etc.
file_size          -- Size in bytes
file_path          -- Full storage path
source_system      -- Computer/hostname extracted from events
event_count        -- Number of events in this file
sigma_violations   -- SIGMA rule match count
ioc_count          -- IOC match count
uploaded_by        -- Foreign key to user.id
uploaded_at        -- Timestamp
status             -- pending, processing, indexed, failed
error_message      -- Error details if failed
indexed_at         -- When indexing completed
is_hidden          -- True for files with 0 events
```

**To Clean:**
```sql
DELETE FROM case_file WHERE case_id = {CASE_ID};
```

**Effects:**
- Removes all file tracking records
- Resets "Indexed Files" count to 0
- Clears upload history for the case

---

### 2. Filesystem Storage

#### A. `/opt/casescope/storage/case_{case_id}/`
**Purpose:** Permanent storage for processed files

**Contains:**
- Original uploaded files (EVTX, JSON, CSV, etc.)
- Files that have been indexed into OpenSearch
- Files remain here even after indexing

**To Clean:**
```bash
rm -rf /opt/casescope/storage/case_{CASE_ID}/
# Or to preserve directory:
rm -f /opt/casescope/storage/case_{CASE_ID}/*
```

**Effects:**
- Removes all stored files
- Resets "Total Files" count to 0
- Resets "Total Size" to 0 GB
- Files CANNOT be re-indexed without re-uploading

#### B. `/opt/casescope/staging/{case_id}/`
**Purpose:** Temporary staging area for validated files waiting to be processed

**Contains:**
- Files that passed validation but haven't been ingested yet
- Files waiting for Celery workers to process them

**To Clean:**
```bash
rm -rf /opt/casescope/staging/{CASE_ID}/
# Or to preserve directory:
rm -f /opt/casescope/staging/{CASE_ID}/*
```

**Effects:**
- Removes pending files
- Resets "Pending Files" count to 0
- Files will NOT be processed by Celery workers

#### C. `/opt/casescope/upload_temp/{case_id}/`
**Purpose:** Temporary storage during chunked uploads (Method 1 & 2)

**Contains:**
- Incomplete upload chunks
- Temporary files being assembled
- Automatically cleaned after upload completes or fails

**To Clean:**
```bash
rm -rf /opt/casescope/upload_temp/{CASE_ID}/
```

**Effects:**
- Clears incomplete/abandoned uploads
- Minimal impact on stats (these don't count toward totals)

#### D. `/opt/casescope/bulk_upload/`
**Purpose:** Shared directory for bulk file uploads

**Contains:**
- Files uploaded via bulk upload feature
- Shared across all cases

**To Clean:**
```bash
# Check for case-specific files first
ls -lh /opt/casescope/bulk_upload/
# Remove case-specific files only
rm -f /opt/casescope/bulk_upload/{case_specific_files}
```

**Effects:**
- Clears bulk upload queue
- Should only be cleaned if files are case-specific

---

### 3. OpenSearch Index

#### Index Name: `case_{case_id}`
**Purpose:** Stores all event data for the case

**Contains:**
- Individual events parsed from EVTX/JSON/CSV files
- Event metadata (timestamps, event IDs, source systems)
- Full event content for search/analysis
- SIGMA rule match flags
- IOC match flags

**To View:**
```bash
# Check if index exists
curl http://localhost:9200/case_{CASE_ID}

# Count events
curl http://localhost:9200/case_{CASE_ID}/_count

# View sample events
curl http://localhost:9200/case_{CASE_ID}/_search?size=5
```

**To Clean:**
```bash
# Delete entire index
curl -X DELETE http://localhost:9200/case_{CASE_ID}
```

**Effects:**
- Removes ALL event data
- Resets "Total Events" count to 0
- Search functionality will return no results
- SIGMA/IOC analysis results are lost
- Index will be automatically recreated when new files are uploaded

---

### 4. Celery Task Queue (Redis)

#### Redis Keys
**Purpose:** Stores task state for background processing

**Contains:**
- `celery-task-meta-*` - Task results/status
- Task queue data for pending file processing jobs

**To View:**
```bash
# Connect to Redis
redis-cli

# List Celery keys
KEYS celery-task-meta-*

# Count pending tasks
LLEN celery

# Check task status
GET celery-task-meta-{TASK_ID}
```

**To Clean:**
```bash
# Purge all Celery tasks (affects ALL cases!)
celery -A celery_worker purge

# Or selectively delete task metadata
redis-cli KEYS "celery-task-meta-*" | xargs redis-cli DEL
```

**Effects:**
- Clears pending processing tasks
- Stops active file processing for the case
- Task results/status are lost
- **WARNING:** This affects ALL cases, not just one

---

## Complete Cleanup Procedure

### Option 1: Full Case Reset (Recommended)

This procedure completely resets a case to clean state while preserving the case record itself.

```bash
#!/bin/bash
# Case Cleanup Script
# Replace {CASE_ID} with actual case ID

CASE_ID=2  # Change this

echo "=== Cleaning Case ${CASE_ID} ==="

# 1. Stop Celery workers (prevent processing during cleanup)
echo "[1/6] Stopping Celery workers..."
sudo systemctl stop casescope-workers

# 2. Delete database records
echo "[2/6] Deleting database records..."
sudo -u postgres psql -d casescope <<EOF
DELETE FROM case_file WHERE case_id = ${CASE_ID};
EOF

# 3. Delete OpenSearch index
echo "[3/6] Deleting OpenSearch index..."
curl -X DELETE http://localhost:9200/case_${CASE_ID}

# 4. Delete filesystem storage
echo "[4/6] Deleting storage files..."
rm -rf /opt/casescope/storage/case_${CASE_ID}
rm -rf /opt/casescope/staging/${CASE_ID}
rm -rf /opt/casescope/upload_temp/${CASE_ID}

# 5. Purge Celery tasks (optional - affects all cases)
echo "[5/6] Purging Celery tasks..."
# Uncomment if you want to clear ALL pending tasks
# celery -A celery_worker purge -f

# 6. Restart services
echo "[6/6] Restarting services..."
sudo systemctl start casescope-workers

echo "=== Case ${CASE_ID} Cleanup Complete ==="
echo "Current Stats:"
echo "  Database records: $(sudo -u postgres psql -d casescope -t -c "SELECT COUNT(*) FROM case_file WHERE case_id = ${CASE_ID};")"
echo "  OpenSearch events: $(curl -s http://localhost:9200/case_${CASE_ID}/_count 2>/dev/null | grep -oP '(?<="count":)\d+' || echo 0)"
echo "  Storage files: $(ls /opt/casescope/storage/case_${CASE_ID}/ 2>/dev/null | wc -l)"
echo "  Staging files: $(ls /opt/casescope/staging/${CASE_ID}/ 2>/dev/null | wc -l)"
```

**Save as:** `/opt/casescope/scripts/cleanup_case.sh`

**Usage:**
```bash
chmod +x /opt/casescope/scripts/cleanup_case.sh
sudo /opt/casescope/scripts/cleanup_case.sh
```

---

### Option 2: Selective Cleanup

Clean only specific components:

#### A. Database Only (preserve files)
```sql
DELETE FROM case_file WHERE case_id = {CASE_ID};
```

#### B. OpenSearch Only (preserve files)
```bash
curl -X DELETE http://localhost:9200/case_{CASE_ID}
```

#### C. Files Only (preserve database/opensearch)
```bash
rm -rf /opt/casescope/storage/case_{CASE_ID}/
rm -rf /opt/casescope/staging/{CASE_ID}/
```

#### D. Staging Only (preserve indexed files)
```bash
rm -rf /opt/casescope/staging/{CASE_ID}/
```

---

## Verification Steps

After cleanup, verify the case is in clean state:

### 1. Database Check
```sql
SELECT COUNT(*) FROM case_file WHERE case_id = {CASE_ID};
-- Expected: 0
```

### 2. OpenSearch Check
```bash
curl http://localhost:9200/case_{CASE_ID}/_count
# Expected: {"error": ... "index_not_found_exception"} OR {"count": 0}
```

### 3. Filesystem Check
```bash
ls /opt/casescope/storage/case_{CASE_ID}/ 2>/dev/null | wc -l
# Expected: 0 (or directory doesn't exist)

ls /opt/casescope/staging/{CASE_ID}/ 2>/dev/null | wc -l
# Expected: 0 (or directory doesn't exist)
```

### 4. Web UI Check
Navigate to: `https://your-server/case/{CASE_ID}/files`

**Expected Stats:**
- Total Files: **0**
- Total Events: **0**
- Indexed Files: **0**
- Pending Files: **0**
- Total Size: **0 GB**

---

## Common Issues

### Issue 1: Stats Don't Reset After Cleanup
**Symptoms:** Web UI still shows old counts

**Cause:** Browser cache or API not refreshing

**Solution:**
```bash
# Hard refresh browser (Ctrl+Shift+R)
# Or clear browser cache
# Or check API directly:
curl -k https://localhost:443/api/case/{CASE_ID}/files/stats
```

### Issue 2: Files Re-appear After Cleanup
**Symptoms:** Files come back after deletion

**Cause:** Celery workers still processing staged files

**Solution:**
```bash
# Stop workers BEFORE cleanup
sudo systemctl stop casescope-workers
# Perform cleanup
# Restart workers
sudo systemctl start casescope-workers
```

### Issue 3: OpenSearch Index Won't Delete
**Symptoms:** Index still exists after DELETE

**Cause:** OpenSearch not responding or index locked

**Solution:**
```bash
# Check OpenSearch status
curl http://localhost:9200/_cluster/health

# Force delete with ignore_unavailable
curl -X DELETE "http://localhost:9200/case_{CASE_ID}?ignore_unavailable=true"

# Restart OpenSearch if necessary
sudo systemctl restart opensearch
```

### Issue 4: Permission Denied on File Deletion
**Symptoms:** Cannot delete files in storage/staging

**Cause:** Files owned by casescope user

**Solution:**
```bash
# Use sudo or switch to casescope user
sudo rm -rf /opt/casescope/storage/case_{CASE_ID}/

# Or as casescope user
sudo -u casescope rm -rf /opt/casescope/storage/case_{CASE_ID}/
```

---

## Case Metadata (NOT Cleaned)

The following case data is **preserved** during cleanup and is NOT part of file/event data:

### `case` Table (PostgreSQL)
- Case name, description, company
- Status (New, In Progress, etc.)
- Created by, assigned to
- Router IPs, VPN IPs
- EDR reports
- Created/updated timestamps

**To Clean Case Metadata (Destructive!):**
```sql
-- WARNING: This deletes the entire case
DELETE FROM case WHERE id = {CASE_ID};
```

---

## Audit Considerations

### Audit Logging
The cleanup process does NOT automatically log to the audit trail. Consider adding manual audit entries:

```sql
INSERT INTO audit_log (timestamp, user_id, username, action, resource_type, resource_id, resource_name, details, status)
VALUES (
    NOW(),
    {USER_ID},
    '{USERNAME}',
    'case_cleanup',
    'case',
    {CASE_ID},
    '{CASE_NAME}',
    '{"files_deleted": 1067, "events_deleted": 619474, "reason": "Testing reprocessing"}',
    'success'
);
```

---

## Reprocessing After Cleanup

After cleanup, to reprocess files:

1. **Re-upload files** via web UI or bulk upload
2. **Files will be automatically:**
   - Validated
   - Moved to staging
   - Processed by Celery workers
   - Indexed into new OpenSearch index
   - Database records recreated

3. **Verify reprocessing:**
   - Check `/opt/casescope/staging/{CASE_ID}/` - should populate with new files
   - Monitor Celery logs: `tail -f /opt/casescope/logs/celery.log`
   - Watch stats update in web UI

---

## Quick Reference

| Component | Location | Clean Command |
|-----------|----------|---------------|
| Database | PostgreSQL `case_file` | `DELETE FROM case_file WHERE case_id = X;` |
| Events | OpenSearch `case_{id}` | `curl -X DELETE http://localhost:9200/case_X` |
| Storage | `/opt/casescope/storage/case_{id}/` | `rm -rf /opt/casescope/storage/case_X/` |
| Staging | `/opt/casescope/staging/{id}/` | `rm -rf /opt/casescope/staging/X/` |
| Temp | `/opt/casescope/upload_temp/{id}/` | `rm -rf /opt/casescope/upload_temp/X/` |

---

## Version
- **Document Version:** 1.0.0
- **Last Updated:** 2025-12-23
- **CaseScope Version:** 2026

