# File Indexing Pipeline (v1.46.0)

## Overview

The file indexing pipeline has been completely refactored in v1.46.0 to use a **4-Phase Sequential Architecture** for better modularity, progress tracking, and data consistency.

**Breaking Change**: The old single-task `process_file()` approach has been replaced with a coordinator-based phased pipeline.

---

## Architecture

### High-Level Flow

```
User clicks "Re-Index All Files"
  ↓
Create ReindexProgress record
  ↓
Start reindex_coordinator_task
  ↓
Pre-Phase: Clear Old Data
  ↓
Phase 1: Index + SIGMA (per file, parallel workers)
  ↓
Phase 2: Known Good Hunting (bulk, parallel workers)
  ↓
Phase 3: Known Noise Hunting (bulk, parallel workers)
  ↓
Phase 4: IOC Hunting (per file, excludes noise, parallel workers)
  ↓
Mark ReindexProgress as completed
  ↓
Frontend polls /reindex-status and shows live progress
```

---

## Phase Details

### Pre-Phase: Clear Old Data

**Purpose**: Ensure a clean slate for reindex by removing all previous detection/classification data.

**Operations**:
1. Delete all `EventStatus` records for the case (or specific files)
2. Delete all `SigmaViolation` records
3. Delete all `IOCMatch` records (if applicable)
4. Delete OpenSearch index entirely (rebuild from scratch)
5. Reset CaseFile metadata (`is_indexed=False`, `indexing_status='Pending'`, etc.)

**Module**: `bulk_operations.py::clear_case_data_for_reindex()`

**Important**: This phase treats all files as brand new. No incremental updates.

**Progress Tracking**:
- `statuses_deleted`: Count of EventStatus records deleted
- `violations_deleted`: Count of SigmaViolation records deleted

---

### Phase 1: Index + SIGMA

**Purpose**: Index EVTX files to OpenSearch and run SIGMA detection.

**Operations**:
1. **Per File (Parallel)**:
   - Convert EVTX → JSONL using `evtx_dump`
   - Parse and normalize events
   - Add case metadata (`case_id`, `file_id`, `case_name`, `source_file`)
   - **Set `event_status='new'` for ALL events** (no auto-hide)
   - Bulk index to OpenSearch
   - Run Chainsaw SIGMA detection
   - Store SIGMA violations in database
   - Mark events with SIGMA hits: `has_sigma=True`

**Modules**:
- `index_evtx.py::index_file_simple()` - Index only
- `sigma_evtx.py::sigma_file_simple()` - SIGMA only

**Celery Task**: `phase1_index_and_sigma_task(file_id, case_id, progress_id)`

**Progress Tracking**:
- `phase1_total_files`: Total files to index
- `phase1_completed_files`: Files completed
- `phase1_events_indexed`: Total events indexed
- `phase1_sigma_violations`: Total SIGMA violations found

**Key Design Decision**: NO auto-hide during indexing. All events start as `'new'`. Noise detection happens in Phases 2 & 3.

---

### Phase 2: Known Good Hunting

**Purpose**: Identify benign/expected events using Known Good rules and mark them as `'noise'`.

**Operations**:
1. **8 Parallel Workers** (each processes subset of rules):
   - Query OpenSearch for events matching Known Good patterns
   - Examples: Windows Defender scans, Office activation, CrowdStrike telemetry
   - Update `event_status='noise'` in OpenSearch
   - Create/Update `EventStatus` records in database with `status='noise'`

**Module**: `events_known_good.py::hunt_known_good(case_id, worker_id)`

**Rules Source**: `site_documentation/EVENTS_KNOWN_GOOD.md`

**Celery Task**: `phase2_known_good_worker_task(case_id, worker_id, progress_id)`

**Progress Tracking**:
- `phase2_total_workers`: 8 (fixed)
- `phase2_completed_workers`: Workers finished
- `phase2_events_marked`: Total events marked as noise

**Important**: Uses `bulk_set_status(db_session, ...)` with the **correct db.session** from Celery worker context to ensure commits persist.

---

### Phase 3: Known Noise Hunting

**Purpose**: Identify known noisy/repetitive events and mark them as `'noise'`.

**Operations**:
1. **8 Parallel Workers** (each processes subset of rules):
   - Query OpenSearch for events matching Known Noise patterns
   - Examples: Sysmon DNS queries to CDNs, Repeated registry reads, WMI Provider events
   - Update `event_status='noise'` in OpenSearch
   - Create/Update `EventStatus` records in database with `status='noise'`

**Module**: `events_known_noise.py::hunt_known_noise(case_id, worker_id)`

**Rules Source**: `site_documentation/EVENTS_KNOWN_NOISE.md`

**Celery Task**: `phase3_known_noise_worker_task(case_id, worker_id, progress_id)`

**Progress Tracking**:
- `phase3_total_workers`: 8 (fixed)
- `phase3_completed_workers`: Workers finished
- `phase3_events_marked`: Total events marked as noise

---

### Phase 4: IOC Hunting

**Purpose**: Hunt for Indicators of Compromise (IOCs) in events, **excluding noise events**.

**Operations**:
1. **Per File (Parallel)**:
   - Query OpenSearch for events: `WHERE event_status != 'noise'`
   - Run IOC detection (IP addresses, domains, file hashes, etc.)
   - Store IOC matches in database
   - Update CaseFile with IOC counts

**Module**: `ioc_utils.py::hunt_iocs_in_file(case_id, file_id, exclude_noise=True)`

**Celery Task**: `phase4_ioc_hunt_task(file_id, case_id, progress_id)`

**Progress Tracking**:
- `phase4_total_files`: Total files to process
- `phase4_completed_files`: Files completed
- `phase4_iocs_found`: Total IOC matches found

**Key Design Decision**: By excluding noise events, we dramatically reduce false positives and processing time.

---

## Database Schema

### ReindexProgress Table

Stores progress tracking for each reindex operation.

```sql
CREATE TABLE reindex_progress (
    id SERIAL PRIMARY KEY,
    case_id INTEGER NOT NULL REFERENCES "case"(id),
    user_id INTEGER NOT NULL REFERENCES "user"(id),
    status VARCHAR(20) DEFAULT 'pending',  -- pending, running, completed, failed
    celery_task_id VARCHAR(255),
    current_phase INTEGER DEFAULT 0,  -- 0-4
    current_phase_name VARCHAR(100),
    
    -- Phase 1: Index + SIGMA
    phase1_status VARCHAR(20) DEFAULT 'pending',
    phase1_total_files INTEGER DEFAULT 0,
    phase1_completed_files INTEGER DEFAULT 0,
    phase1_events_indexed INTEGER DEFAULT 0,
    phase1_sigma_violations INTEGER DEFAULT 0,
    
    -- Phase 2: Known Good
    phase2_status VARCHAR(20) DEFAULT 'pending',
    phase2_total_workers INTEGER DEFAULT 0,
    phase2_completed_workers INTEGER DEFAULT 0,
    phase2_events_marked INTEGER DEFAULT 0,
    
    -- Phase 3: Known Noise
    phase3_status VARCHAR(20) DEFAULT 'pending',
    phase3_total_workers INTEGER DEFAULT 0,
    phase3_completed_workers INTEGER DEFAULT 0,
    phase3_events_marked INTEGER DEFAULT 0,
    
    -- Phase 4: IOC Hunting
    phase4_status VARCHAR(20) DEFAULT 'pending',
    phase4_total_files INTEGER DEFAULT 0,
    phase4_completed_files INTEGER DEFAULT 0,
    phase4_iocs_found INTEGER DEFAULT 0,
    
    -- Pre-phase data clearing
    statuses_deleted INTEGER DEFAULT 0,
    violations_deleted INTEGER DEFAULT 0,
    
    -- Timing
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    error_message TEXT
);
```

**Indexes**:
- `case_id` - Fast lookup for case progress
- `status` - Filter active/completed reindexes
- `celery_task_id` - Track Celery task
- `started_at` - Recent first ordering

---

## API Endpoints

### POST /case/<case_id>/bulk_reindex

**Purpose**: Start the 4-phase reindex pipeline.

**Request**: `POST` with `Accept: application/json`

**Response**:
```json
{
    "success": true,
    "message": "Re-indexing started: 156 files",
    "progress_id": 42,
    "file_count": 156
}
```

**Process**:
1. Validate case exists and not archived
2. Check Celery workers available
3. Get all non-deleted, non-hidden files
4. Create `ReindexProgress` record
5. Start `reindex_coordinator_task` in Celery
6. Return progress_id to frontend for polling

---

### GET /case/<case_id>/reindex-status

**Purpose**: Get real-time progress of the reindex pipeline.

**Request**: `GET`

**Response**:
```json
{
    "status": "running",
    "current_phase": 2,
    "current_phase_name": "Hunting for Known Good Events",
    "statuses_deleted": 0,
    "violations_deleted": 15234,
    "phase1": {
        "status": "completed",
        "total_files": 156,
        "completed_files": 156,
        "events_indexed": 2789543,
        "sigma_violations": 15234
    },
    "phase2": {
        "status": "running",
        "total_workers": 8,
        "completed_workers": 5,
        "events_marked": 820350
    },
    "phase3": {
        "status": "pending",
        "total_workers": 8,
        "completed_workers": 0,
        "events_marked": 0
    },
    "phase4": {
        "status": "pending",
        "total_files": 156,
        "completed_files": 0,
        "iocs_found": 0
    },
    "started_at": "2025-12-03T10:30:15",
    "completed_at": null,
    "error_message": null
}
```

**Frontend Polling**: Frontend polls this endpoint every 2 seconds to update the modal.

---

## Frontend Progress Modal

### Modal UI

The modal displays all 4 phases with real-time progress:

```
┌─────────────────────────────────────────────────┐
│  4-Phase Re-Index Pipeline                      │
├─────────────────────────────────────────────────┤
│                                                  │
│  ✓ Clearing Old Data                            │
│    Deleted 0 event statuses, 15,234 violations  │
│                                                  │
│  ✓ Phase 1: Index + SIGMA                       │
│    156/156 files                                 │
│    2,789,543 events indexed, 15,234 violations  │
│                                                  │
│  ◐ Phase 2: Hunting for Known Good Events       │
│    5/8 workers                                   │
│    820,350 events marked as noise                │
│                                                  │
│  ○ Phase 3: Hunting for Known Noise Events      │
│    0/8 workers                                   │
│    0 events marked as noise                      │
│                                                  │
│  ○ Phase 4: Hunting for IOCs                    │
│    0/156 files                                   │
│    0 IOCs found                                  │
│                                                  │
└─────────────────────────────────────────────────┘
```

**Status Icons**:
- `✓` - Completed (green)
- `◐` - Running (spinner animation, blue)
- `✗` - Failed (red)
- `○` - Pending (gray)

**Implementation**: `app/templates/case_files.html::updateReindexPhaseProgress()`

---

## Code Modules

### Coordinator

**File**: `app/reindex_coordinator.py`

**Functions**:
- `start_reindex_pipeline()` - Main orchestrator, runs phases sequentially
- `run_phase1_index_sigma()` - Phase 1 coordinator
- `run_phase2_known_good()` - Phase 2 coordinator
- `run_phase3_known_noise()` - Phase 3 coordinator
- `run_phase4_ioc_hunt()` - Phase 4 coordinator

### Phase 1 Modules

**File**: `app/index_evtx.py`
- `index_file_simple(db, opensearch_client, file_id, case_id)` - Index EVTX to OpenSearch only

**File**: `app/sigma_evtx.py`
- `sigma_file_simple(db, opensearch_client, file_id, case_id)` - SIGMA detection only

### Phase 2 & 3 Modules

**File**: `app/events_known_good.py`
- `hunt_known_good(db, opensearch_client, case_id, worker_id)` - Known Good detection

**File**: `app/events_known_noise.py`
- `hunt_known_noise(db, opensearch_client, case_id, worker_id)` - Known Noise detection

### Phase 4 Module

**File**: `app/ioc_utils.py`
- `hunt_iocs_in_file(db, opensearch_client, case_id, file_id, exclude_noise=True)` - IOC detection

### Celery Tasks

**File**: `app/tasks.py`

**Tasks**:
- `reindex_coordinator_task(case_id, user_id, file_ids, progress_id)` - Main coordinator
- `phase1_index_and_sigma_task(file_id, case_id, progress_id)` - Phase 1 worker
- `phase2_known_good_worker_task(case_id, worker_id, progress_id)` - Phase 2 worker
- `phase3_known_noise_worker_task(case_id, worker_id, progress_id)` - Phase 3 worker
- `phase4_ioc_hunt_task(file_id, case_id, progress_id)` - Phase 4 worker

---

## Critical Design Patterns

### 1. Database Session Context

**Problem**: Celery workers use a different `db.session` than the one imported from `main.py`.

**Solution**: Pass `db.session` as a parameter to all functions that commit data.

```python
# ❌ BAD - imports disconnected session
from models import db

def bulk_set_status(...):
    db.session.add(record)
    db.session.commit()  # Commit might not persist!

# ✅ GOOD - accepts session from caller
def bulk_set_status(db_session, ...):
    db_session.add(record)
    db_session.commit()  # Persists correctly

# Call from Celery task
with app.app_context():
    bulk_set_status(db.session, ...)  # Pass the correct session
```

### 2. Batch Processing for Large Datasets

**Problem**: Processing 820K+ records at once causes memory issues and slow commits.

**Solution**: Batch processing with configurable `BATCH_SIZE`.

```python
BATCH_SIZE = 10000

for i in range(0, len(event_ids), BATCH_SIZE):
    batch = event_ids[i:i + BATCH_SIZE]
    
    # Process batch
    existing = EventStatus.query.filter(EventStatus.event_id.in_(batch)).all()
    
    for event_id in batch:
        # Create or update
        ...
    
    db.session.commit()  # Commit per batch
```

### 3. Dual Storage (OpenSearch + PostgreSQL)

**Pattern**: Store event status in BOTH OpenSearch (for fast filtering) and PostgreSQL (for audit trail).

**OpenSearch**:
- `event_status` field (`'new'`, `'noise'`, `'hunted'`, `'confirmed'`)
- Used for search filtering: `WHERE event_status != 'noise'`
- Fast term queries, no joins needed

**PostgreSQL**:
- `EventStatus` table with `event_id`, `status`, `user_id`, `updated_at`, `notes`
- Source of truth for counts and audit history
- Used for statistics on Case Files page

**Synchronization**: Both are updated in the same transaction when status changes.

---

## Performance Considerations

### Parallel Workers

- **Phase 1**: Processes files in parallel (limited by Celery worker count)
- **Phase 2 & 3**: 8 parallel workers per phase (rule-based partitioning)
- **Phase 4**: Processes files in parallel (limited by Celery worker count)

### OpenSearch Batch Indexing

- Bulk index in batches of 1000 events
- Prevents memory bloat and improves throughput

### Database Batch Commits

- Commit `EventStatus` records in batches of 10,000
- Prevents PostgreSQL `IN` clause limits and lock contention

---

## Monitoring and Debugging

### Check Reindex Progress

```bash
# Query current progress
sudo -u postgres psql casescope -c "
SELECT current_phase_name, phase1_completed_files, phase2_completed_workers, 
       phase3_completed_workers, phase4_completed_files, status
FROM reindex_progress 
WHERE case_id = 15 
ORDER BY started_at DESC 
LIMIT 1;
"
```

### Check Celery Workers

```bash
# List active tasks
cd /opt/casescope && source venv/bin/activate
celery -A celery_app inspect active

# Check worker status
celery -A celery_app inspect stats
```

### Check OpenSearch Event Status Distribution

```bash
# Count events by status
curl -X GET "localhost:9200/case_15/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "size": 0,
  "aggs": {
    "status_distribution": {
      "terms": {
        "field": "event_status",
        "size": 10
      }
    }
  }
}
'
```

---

## Migration from v1.45.x

### Breaking Changes

1. **Old `process_file()` task is replaced**
   - Previously handled indexing, SIGMA, auto-hide, and IOC hunting in one task
   - Now split into 4 separate phases with dedicated tasks

2. **New ReindexProgress table required**
   - Run database migration to create table (see above SQL)

3. **Frontend modal polling required**
   - Old modal showed "steps" from synchronous response
   - New modal polls `/reindex-status` every 2 seconds

### Compatibility

- Old single-file index (`/case/<id>/file/<fid>/index`) still works for individual files
- Bulk reindex uses new phased approach

---

## Troubleshooting

### Issue: Noise count doesn't match between OpenSearch and DB

**Symptom**: OpenSearch shows 820K noise events, DB shows 59K.

**Cause**: `bulk_set_status()` was using wrong `db.session` or not batching commits.

**Fix**: Ensure `bulk_set_status(db.session, ...)` receives session from Celery worker context and uses batching.

### Issue: Phase stuck at "running" forever

**Symptom**: Phase 2 shows `phase2_status='running'` but never completes.

**Cause**: Worker tasks failed silently or Celery workers crashed.

**Fix**:
1. Check Celery worker logs: `tail -f /opt/casescope/logs/workers.log`
2. Check task status: `celery -A celery_app inspect active`
3. Restart workers: `sudo systemctl restart casescope-celery`

### Issue: Progress modal shows old data

**Symptom**: Modal shows completed reindex from yesterday.

**Cause**: API returns most recent `ReindexProgress` record, not necessarily current one.

**Fix**: Clear old progress records or filter by `status='running'`.

---

## Version History

- **v1.46.0**: Complete rewrite to 4-phase architecture with progress tracking
- **v1.45.x**: Single-task `process_file()` with inline auto-hide
- **v1.19.8**: Added full index deletion for clean rebuilds

---

## See Also

- `site_documentation/EVENTS_KNOWN_GOOD.md` - Known Good rules
- `site_documentation/EVENTS_KNOWN_NOISE.md` - Known Noise rules
- `site_documentation/EVENTS_TRIAGE.md` - Phase 3 triage workflow
- `site_documentation/FIX_REPEATING_ISSUES.md` - Common pitfalls
