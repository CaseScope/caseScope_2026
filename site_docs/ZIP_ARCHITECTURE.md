# ZIP-Centric File Processing Architecture

**Version**: 2.0 (December 2025)  
**Status**: Production Ready  
**Target Performance**: <5 minutes for 3GB ZIP with ~1000 files

---

## Overview

CaseScope 2.0 implements a revolutionary **ZIP-centric** file processing architecture that fundamentally changes how forensic evidence is stored, indexed, and accessed.

### Key Principles

1. **Zero Deletion**: Nothing is permanently deleted. Everything is compressed and kept.
2. **ZIP as Source of Truth**: ZIP files remain in storage; extracted files are virtual references.
3. **Multi-Index Strategy**: Different artifact types route to specialized OpenSearch indexes.
4. **Intelligent Compression**: GZIP compression applied immediately after indexing.
5. **On-Demand Extraction**: Virtual files extracted from ZIP only when downloaded.

---

## Architecture Components

### 1. Database Schema

**New Fields in `case_file` Table**:

```sql
-- Container/Virtual Tracking
is_container BOOLEAN DEFAULT false          -- True for ZIP files
is_virtual BOOLEAN DEFAULT false            -- True for files extracted from ZIP
parent_file_id INTEGER                      -- References parent ZIP (if virtual)
target_index VARCHAR(100)                   -- OpenSearch index (case_X, case_X_browser, etc.)

-- Processing State Tracking
extraction_status VARCHAR(50)               -- pending, in_progress, completed, failed
parsing_status VARCHAR(50)                  -- pending, in_progress, completed, failed
indexing_status VARCHAR(50)                 -- pending, in_progress, completed, failed

-- Error Handling
error_details TEXT                          -- Detailed error messages
files_failed INTEGER DEFAULT 0              -- Count of failed files in container
retry_count INTEGER DEFAULT 0               -- Number of retry attempts
```

**Foreign Key**:
```sql
ALTER TABLE case_file ADD CONSTRAINT fk_parent_file 
  FOREIGN KEY (parent_file_id) REFERENCES case_file(id) ON DELETE CASCADE;
```

### 2. File Processing Flow

#### For ZIP Files:

```
1. UPLOAD → Move to storage/case_X/
2. CREATE container record (is_container=True, is_virtual=False, status='extracting')
3. EXTRACT → staging/case_X/extract_{container_id}/ (temporary)
4. For each extracted file:
   a. CREATE virtual file record (is_virtual=True, parent_file_id=container.id, status='parsing')
   b. QUEUE for parsing (parallel processing across workers)
5. UPDATE container to status='parsing' when extraction complete
6. As each child file completes:
   a. PARSE artifact (EVTX/NDJSON/CSV/Browser)
   b. NORMALIZE fields (computer, timestamp, event_id)
   c. INDEX to appropriate OpenSearch index
   d. COMPRESS (GZIP) and delete from staging
   e. UPDATE child status to 'indexed'
   f. CALL update_container_status() - accumulates event_count, updates container status
7. When all children complete:
   - Container status → 'indexed' (all succeeded) or 'partial' (some failed)
   - Container event_count = SUM(child event_counts)
```

#### For Standalone Files:

```
1. UPLOAD → Move to staging/case_X/
2. CREATE standalone record (is_container=False, is_virtual=False)
3. PARSE artifact → NDJSON
4. INDEX to OpenSearch
5. COMPRESS with GZIP
6. MOVE compressed to storage/case_X/
7. UPDATE status to "indexed"
```

### 3. Multi-Index Routing

**Automatic routing based on file type/name**:

| Artifact Type | OpenSearch Index | Source Files |
|--------------|------------------|--------------|
| Windows Event Logs | `case_X` | `.evtx`, `.ndjson` |
| Browser History | `case_X_browser` | `History`, `places.sqlite`, `WebCache*.dat` |
| Program Execution | `case_X_execution` | `.pf` (Prefetch) |
| Network Activity | `case_X_network` | `SRUDB.dat` (SRUM) |
| Device Connections | `case_X_devices` | `setupapi.dev.log` |

**Benefits**:
- Faster, more targeted searches
- Better performance on large datasets
- Easier to manage retention/cleanup per artifact type
- Clear separation of concerns

---

## Parsers (Phase 1-3)

### Phase 1: Core Events (Existing)

**EVTX Parser** (`parsers/evtx_parser.py`)
- Windows Event Logs → `case_X`
- Chunked processing (5000 events)
- Uses comprehensive normalization module (`event_normalization.py`)
- Handles nested structures (`Event.System.Computer` for ZIP exports)
- Memory-safe for 16-32GB systems

**NDJSON Parser** (`parsers/ndjson_parser.py`)
- Pre-parsed JSON events → `case_X`
- Supports EDR formats (CrowdStrike, SentinelOne, Huntress, CyLR)
- Uses comprehensive normalization module
- Extracts from nested fields (`host.hostname`, `event.code`)

**CSV Parser** (`parsers/firewall_csv_parser.py`)
- Firewall logs (SonicWall, generic) → `case_X`
- Auto-detects format from headers
- Uses comprehensive normalization module
- Extracts all IPs for IOC hunting

### Phase 2: Browser Artifacts (NEW)

**Chrome/Firefox History Parser** (`parsers/browser_history_parser.py`)
- Chrome History SQLite → `case_X_browser`
- Firefox places.sqlite → `case_X_browser`
- Extracts: URLs, visits, downloads
- Timestamp conversion: Chrome (1601 epoch), Firefox (Unix microseconds)
- Tables: `urls`, `visits`, `downloads`, `moz_places`

**WebCache ESE Parser** (`parsers/webcache_parser.py`)
- Windows WebCache (IE/Edge) → `case_X_browser`
- ESE database parsing via `pyesedb`
- Extracts: Container_X tables (cache, history, cookies)
- FILETIME conversion (100-nanosecond intervals)

### Phase 3: System Artifacts (NEW)

**Prefetch Parser** (`parsers/prefetch_parser.py`)
- Windows Prefetch (.pf) → `case_X_execution`
- Parsing via `pyscca` library
- Extracts: Executable name, run count, last 8 run times, file references
- Tracks program execution history

**SRUM Parser** (`parsers/srum_parser.py`)
- Windows SRUM (SRUDB.dat) → `case_X_network`
- Network data usage per application
- ESE database parsing
- Extracts: AppId, UserId, BytesSent, BytesRecvd, timestamps

**setupapi Parser** (`parsers/setupapi_parser.py`)
- Windows device installation log → `case_X_devices`
- UTF-16LE encoding
- Extracts: USB VID/PID/Serial, device connection timestamps
- Tracks device history

---

## UI Features

### 1. Expandable ZIP Viewer

**Location**: `/case/<id>/files` (files.html)

**Features**:
- 📦 ZIP files shown with icon + file count
- Click ZIP to expand/collapse contents
- Two view modes:
  - **Flat List**: Paginated (50 items/page, up to 100)
  - **Grouped by System**: Collapsible sections per computer

**Pagination**:
```javascript
GET /case/<id>/files/<container_id>/contents?page=1&per_page=50
GET /case/<id>/files/<container_id>/contents?group_by=system
```

### 2. Download Virtual Files

**Route**: `GET /case/<id>/files/<file_id>/download`

**Hybrid Approach**:
- Files <100MB: Extract to memory (io.BytesIO)
- Files >100MB: Extract to temp file, cleanup after send
- Works for both virtual (from ZIP) and physical (from storage) files
- Auto-decompresses .gz files

### 3. Error Handling & Retry

**Individual Retry**:
```javascript
POST /case/<id>/files/<file_id>/retry
```
- Resets status: failed → parsing
- Increments retry_count
- Re-queues for processing

**Batch Retry**:
```javascript
POST /case/<id>/files/<container_id>/retry-failed
```
- Retries all failed files in ZIP
- Returns count + error list

**UI**:
- 🔄 retry button for failed files
- Confirmation dialog
- Auto-refresh after retry

### 4. Status Badges

| Status | Badge | Meaning |
|--------|-------|---------|
| indexed | ✓ Indexed (green) | Successfully indexed to OpenSearch |
| processing | Processing... (blue) | Currently being processed |
| parsing | Parsing... (blue) | Being parsed to NDJSON |
| pending | Pending (gray) | Queued for processing |
| failed | Failed (red) | Processing failed (can retry) |
| extracting | Extracting... (blue) | ZIP extraction in progress |

---

## Performance Tuning

### Auto-Tune Script

**Location**: `/opt/casescope/autotune_workers.py`

**Formula**:
```python
optimal_workers = min(16, max(4, int(CPU_cores * 0.75)))

# RAM constraint check
ram_based_max = int((memory_gb - 4.0) / 0.75)  # 750MB per worker
optimal_workers = min(optimal_workers, ram_based_max)
```

**Current System** (16 cores, 62.9GB RAM):
- Optimal Workers: **12**
- Estimated Throughput: **~72 files/minute**
- Target: <5 minutes for 3GB ZIP

**Run**:
```bash
cd /opt/casescope
python3 autotune_workers.py
sudo systemctl restart casescope-workers
```

### Celery Configuration

**config.py**:
```python
CELERY_WORKERS = 12  # Auto-tuned
CELERY_MAX_TASKS_PER_CHILD = 1000  # Prevent memory leaks
CELERY_WORKER_PREFETCH_MULTIPLIER = 2  # Prefetch 2 tasks per worker
CELERY_TASK_ACKS_LATE = True  # Prevent task loss on crash
```

### Chunk Sizes

| Operation | Chunk Size | Reason |
|-----------|------------|--------|
| EVTX parsing | 5000 events | Balance memory vs speed |
| NDJSON parsing | 5000 events | Same as EVTX |
| Browser history | 5000 events | Consistent with other parsers |
| WebCache ESE | 5000 events | ESE records can be large |
| SRUM | 1000 events per table | Multiple tables, limit total |
| setupapi | 1000 events | Line-by-line parsing |
| OpenSearch bulk | Per config | Set in OPENSEARCH_BULK_CHUNK_SIZE |

---

## Storage Management

### Zero-Deletion Policy

**Principle**: Never permanently delete data. Compress instead.

**GZIP Compression**:
- Applied immediately after indexing
- Compression level: 6 (balance speed vs ratio)
- Typical ratio: 60-80% size reduction
- Decompressed on-the-fly when downloaded

**Storage Paths**:
```
/opt/casescope/
├── storage/
│   └── case_X/
│       ├── evidence.zip                    # Container (kept)
│       ├── standalone_file.evtx.gz        # Compressed standalone
│       └── cert.pem                       # Uncompressed (small files)
├── staging/
│   └── case_X/
│       └── (temporary extraction area, cleared after indexing)
└── bulk_upload/
    └── case_X/
        └── (user upload area, moved to storage)
```

### File Lifecycle

**Virtual File** (from ZIP):
1. Exists in parent ZIP in `storage/case_X/`
2. Temporarily extracted to `staging/case_X/` during processing
3. After indexing, deleted from staging
4. Database record tracks original location in ZIP
5. On download: Re-extracted on-demand

**Standalone File**:
1. Uploaded to `bulk_upload/case_X/` or web upload
2. Moved to `staging/case_X/`
3. Parsed and indexed
4. Compressed with GZIP
5. Moved to `storage/case_X/filename.gz`
6. On download: Decompressed on-the-fly

---

## Migration from v1.x

### Automatic Migration

**Script**: `migrate_existing_cases.py`

**What it does**:
1. Finds all existing `case_file` records where `is_container` and `is_virtual` are NULL/FALSE
2. Sets `target_index = 'case_' || case_id` for all files
3. Marks existing ZIPs as containers (`is_container = TRUE`)
4. All files remain in storage, fully backward compatible

**Run**:
```bash
cd /opt/casescope
python3 migrate_existing_cases.py
```

**Results** (Case 3):
- 352 EVTX files marked as standalone
- All files now have `target_index` set
- No data loss, no file movement

---

## Container Status & Event Tracking (v1.5.7)

### Automatic Container Updates

**Function**: `update_container_status(container_id)` in `task_file_upload.py`

**Triggered**: Automatically after each child file completes (success or failure)

**Logic**:
```python
# Get all children
children = CaseFile.query.filter_by(parent_file_id=container_id).all()

# Check completion status
all_indexed = all(child.status == 'indexed' for child in children)
any_failed = any(child.status == 'failed' for child in children)

# Calculate cumulative events
total_events = sum(child.event_count or 0 for child in children)

# Update container
if all_indexed:
    container.status = 'indexed'  # All succeeded
    container.event_count = total_events
elif any_failed:
    container.status = 'partial'  # Some failed
    container.event_count = total_events  # Still counts successful files
else:
    container.event_count = total_events  # Running total during processing
```

**Status Progression**:
```
extracting → parsing → indexed/partial
```

**Event Count**:
- Updates in real-time as children complete
- Shows cumulative total from all successfully indexed child files
- Displayed in file list and ZIP breakdown modal

### ZIP Breakdown Modal

**Trigger**: Click file count badge (e.g., "954 files") on any ZIP container

**Endpoint**: `/case/<id>/files/<container_id>/breakdown`

**Shows**:
- Total files extracted
- Successfully indexed count
- Failed files count
- Total events indexed
- Container status
- **Indexed files by type** (with descriptions):
  - File type (evtx, ndjson, dat, db, etc.)
  - Description (e.g., "Windows Event Log files - System, Security, Application logs")
  - Count of files
  - Event count per type
- **Failed files by type** (with sample errors):
  - File type
  - Description
  - Count
  - Common error message

**File Type Descriptions**:
```javascript
'evtx': 'Windows Event Log files - System, Security, Application logs'
'ndjson': 'Newline Delimited JSON - Typically EDR/SIEM logs (CrowdStrike, SentinelOne, etc.)'
'dat': 'Data files - Often WebCache (browser cache), ESE databases'
'db': 'SQLite databases - Thumbnails, application data, browser artifacts'
'' (empty): 'Browser artifacts - History, Cookies, Download records (SQLite)'
```

---

## API Reference

### Get ZIP Contents

```http
GET /case/<case_id>/files/<container_id>/contents?page=1&per_page=50
```

**Response** (Paginated):
```json
{
  "container_id": 123,
  "container_name": "evidence.zip",
  "page": 1,
  "per_page": 50,
  "total_files": 352,
  "total_pages": 8,
  "has_next": true,
  "has_prev": false,
  "files": [
    {
      "id": 456,
      "filename": "System.evtx",
      "file_type": "evtx",
      "file_size": 10485760,
      "event_count": 15234,
      "status": "indexed",
      "source_system": "DESKTOP-ABC123",
      "target_index": "case_3",
      "parsing_status": "completed",
      "indexing_status": "completed"
    }
  ]
}
```

**Response** (Grouped by System):
```json
{
  "container_id": 123,
  "container_name": "evidence.zip",
  "total_files": 352,
  "grouped": true,
  "systems": [
    {
      "system": "DESKTOP-ABC123",
      "file_count": 120,
      "files": [...]
    },
    {
      "system": "LAPTOP-XYZ789",
      "file_count": 232,
      "files": [...]
    }
  ]
}
```

### Download File

```http
GET /case/<case_id>/files/<file_id>/download
```

**Behavior**:
- Virtual files: Extracted from parent ZIP on-demand
- Physical files: Served directly (or decompressed if .gz)
- <100MB: Memory-based
- >100MB: Temp file + cleanup

### Retry Failed File

```http
POST /case/<case_id>/files/<file_id>/retry
```

**Response**:
```json
{
  "success": true,
  "message": "File re-queued for processing (attempt #2)"
}
```

### Batch Retry Failed Files

```http
POST /case/<case_id>/files/<container_id>/retry-failed
```

**Response**:
```json
{
  "success": true,
  "retried": 5,
  "errors": [],
  "message": "Retried 5 failed files from evidence.zip"
}
```

---

## Troubleshooting

### Files Stuck in Staging

**Symptom**: `pending_files` count remains non-zero, no progress

**Diagnosis**:
```bash
ls -lah /opt/casescope/staging/<case_id>/
```

**Common Causes**:
1. No parser available for file type
2. Celery workers crashed mid-processing
3. File permissions issue

**Solution**:
```bash
# Check Celery logs
tail -100 /opt/casescope/logs/celery_worker.log

# Restart workers
sudo systemctl restart casescope-workers

# Manually retry files via UI
```

### Low Performance (<72 files/min)

**Check**:
1. Worker count: `ps aux | grep celery | wc -l` (should be 13 = 12 workers + 1 master)
2. CPU usage: `htop` (should be ~75% utilized)
3. OpenSearch health: Check if indexing is bottleneck

**Optimize**:
```bash
# Re-run autotune
python3 autotune_workers.py
sudo systemctl restart casescope-workers

# Check OpenSearch performance
curl -X GET "localhost:9200/_cat/indices?v"
```

### Download Fails for Virtual Files

**Symptom**: 404 or "File not found in ZIP"

**Diagnosis**:
1. Check parent ZIP exists: `ls -lah /opt/casescope/storage/case_X/`
2. Check database `parent_file_id` is set correctly
3. Verify filename matching (case-sensitive)

**Solution**:
```sql
SELECT id, original_filename, parent_file_id, file_path 
FROM case_file 
WHERE id = <file_id>;

-- Check parent
SELECT id, original_filename, file_path 
FROM case_file 
WHERE id = <parent_file_id>;
```

---

## Future Enhancements

### Planned Features

1. **Duplicate ZIP Dialog**: User choice (Replace/Keep Both/Cancel) when uploading duplicate
2. **Compression Statistics**: Show compression ratio, original size vs compressed
3. **Artifact-Specific Views**: Dedicated UI for browser history, Prefetch timeline
4. **Smart Caching**: Cache frequently accessed virtual files in staging
5. **Incremental ZIP Updates**: Add files to existing ZIP without re-processing all

### Performance Targets

- **Current**: ~14 minutes baseline for 3GB/1000 files
- **Target**: <5 minutes with parallel processing
- **Future**: <2 minutes with SSD caching + async extraction

---

## Summary

CaseScope 2.0's ZIP-centric architecture provides:

✅ **Zero data loss** - Everything compressed, nothing deleted  
✅ **Efficient storage** - ZIPs kept, extracted files virtual  
✅ **Fast retrieval** - On-demand extraction only when needed  
✅ **Multi-index routing** - Specialized indexes for artifact types  
✅ **Comprehensive parsers** - Phase 1-3 all implemented  
✅ **Error resilience** - Retry failed files, track all errors  
✅ **Auto-tuned performance** - 12 workers, ~72 files/minute  
✅ **User-friendly UI** - Expandable ZIPs, download buttons, status badges  

**Production ready** for forensic investigations with datasets up to 100GB.

