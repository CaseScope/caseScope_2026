# File Processing Pipeline (v2.1.x)

## Overview

The file processing pipeline uses a **Modular Phased Architecture** introduced in v2.0.0. Each processing phase is a separate module with its own coordinator, and files progress through phases sequentially with real-time progress tracking.

---

## Architecture

### High-Level Flow

```
User clicks "Re-Index All Files"
  ↓
main.py → bulk_reindex_route (Background Thread)
  ↓
coordinator_reindex.py → reindex_files()
  ↓
PHASE 1: Clear Metadata (processing_clear_metadata.py)
  ↓
coordinator_index.py → index_new_files()
  ├─→ PHASE 2: Index Files (processing_index.py)
  ├─→ PHASE 3: SIGMA Detection (processing_sigma.py)
  ├─→ PHASE 4: Known-Good Filter (events_known_good.py) [8 parallel workers]
  ├─→ PHASE 5: Known-Noise Filter (events_known_noise.py) [8 parallel workers]
  └─→ PHASE 6: IOC Matching (processing_ioc.py)
  ↓
Frontend polls /case/<id>/progress/reindex (Redis-backed)
Progress bar auto-resumes on page reload
```

---

## Phase Details

### PHASE 1: Clear Metadata

**Purpose**: Delete all existing event data to ensure clean reindex.

**Module**: `app/processing_clear_metadata.py`

**Operations**:
1. Delete OpenSearch events for queued files OR entire case index
2. Delete SigmaViolation records
3. Delete IOCMatch records
4. Delete TimelineTag records
5. Delete EventStatus records
6. Reset CaseFile metadata:
   - `event_count = 0`
   - `violation_count = 0`
   - `ioc_event_count = 0`
   - `is_indexed = False`
   - `is_hidden = False` (reset for fresh 0-event detection)
   - `indexing_status = 'Queued'`
   - `error_message = None`
   - `celery_task_id = None`

**Celery Tasks**:
- `clear_file_task(file_id, clear_type='all')` - Worker task (8 parallel)
- `bulk_clear_case(case_id)` - Fast bulk clear (deletes entire index)

**Progress Tracking**: Redis-backed via `progress_tracker.py`

---

### PHASE 2: Index Files

**Purpose**: Convert EVTX/CSV/JSON files to normalized events in OpenSearch.

**Module**: `app/processing_index.py`

**Operations**:
1. Queue files with `indexing_status = 'Queued'`
2. Parallel Celery workers process files:
   - `file_processing.index_one_file()`
   - Converts EVTX → JSON via evtx_dump
   - Normalizes events
   - Auto-hides files with 0 events (`is_hidden=True`)
   - Bulk index to OpenSearch
   - Updates `indexing_status = 'Indexed'`

**Database Polling**:
- Coordinator polls `CaseFile.indexing_status IN ('Queued', 'Indexing')`
- Phase completes when count = 0
- NO `result.get()` blocking calls (prevents deadlocks)

**Celery Tasks**:
- `index_file_task(file_id, case_id)` - Worker task

**Progress Tracking**:
- `current_count`: Files still in queue
- `total_count`: Total files to index

---

### PHASE 3: SIGMA Detection

**Purpose**: Run SIGMA rules against indexed events.

**Module**: `app/processing_sigma.py`

**Operations**:
1. Queue files with `indexing_status = 'Indexed'`
2. Parallel Celery workers process files:
   - `sigma_detection.detect_sigma_violations()`
   - Runs Chainsaw with SIGMA rules
   - Creates SigmaViolation records
   - Updates event documents with `has_sigma=True`
   - Updates `CaseFile.violation_count`
   - Updates `indexing_status = 'SIGMA Complete'`

**Database Polling**:
- Coordinator polls `CaseFile.indexing_status = 'SIGMA Testing'`
- Phase completes when count = 0

**Celery Tasks**:
- `detect_sigma_file_task(file_id, case_id)` - Worker task

**Progress Tracking**:
- `current_count`: Files still processing SIGMA
- `total_count`: Total files for SIGMA

---

### PHASE 4: Known-Good Filter (Parallel)

**Purpose**: Mark events from trusted tools (RMM, EDR) as noise.

**Module**: `app/events_known_good.py`

**Operations**:
1. Coordinator dispatches 8 parallel slice tasks
2. Each worker processes 1/8 of events using OpenSearch sliced scroll:
   - Loads exclusion patterns from `SystemToolsSetting` table
   - Matches events using `is_known_good_event()`:
     - **Rule 1 (RMM):** EXE pattern OR path in search_blob → noise
     - **Rule 2 (Remote):** Tool EXE AND session ID in blob → noise
     - **Rule 3 (EDR):** EDR EXE AND routine command (unless response pattern) → noise
   - Updates OpenSearch: `event_status='noise'`
   - Updates database: `EventStatus` table with `status='noise'`

**Celery Tasks**:
- `hide_known_good_all_task(case_id)` - Coordinator (v2.1.0)
- `hide_known_good_slice_task(case_id, slice_id, max_slices)` - Worker (8 parallel)

**Progress Tracking**:
- Task-based polling via `progress_tracker.py`
- `current_count`: Events hidden
- `total_count`: Events scanned

**Performance**: Processes ~800K events in 2-3 minutes (8 workers)

---

### PHASE 5: Known-Noise Filter (Parallel)

**Purpose**: Mark routine Windows system noise as noise.

**Module**: `app/events_known_noise.py`

**Operations**:
1. Coordinator dispatches 8 parallel slice tasks
2. Each worker processes 1/8 of events using OpenSearch sliced scroll:
   - Checks hardcoded noise patterns from `noise_filters.py`:
     - 109 NOISE_PROCESSES (conhost.exe, auditpol.exe, etc.)
     - Noise commands with generic parents
     - Firewall keywords
   - Updates OpenSearch: `event_status='noise'`
   - Updates database: `EventStatus` table with `status='noise'`

**Celery Tasks**:
- `hide_noise_all_task(case_id)` - Coordinator (v2.1.0)
- `hide_noise_slice_task(case_id, slice_id, max_slices)` - Worker (8 parallel)

**Progress Tracking**:
- Task-based polling via `progress_tracker.py`
- `current_count`: Events hidden
- `total_count`: Events scanned

**Performance**: Processes ~800K events in 2-3 minutes (8 workers)

---

### PHASE 6: IOC Matching

**Purpose**: Hunt for Indicators of Compromise in events.

**Module**: `app/processing_ioc.py`

**Operations**:
1. Queue files with active IOCs
2. Parallel Celery workers process files:
   - `file_processing.hunt_iocs()`
   - Searches for IP, hostname, username, process, hash, command IOCs
   - Excludes events with `event_status='noise'`
   - Creates IOCMatch records
   - Updates `CaseFile.ioc_event_count`
   - Updates `indexing_status = 'IOC Complete'`

**Database Polling**:
- Coordinator polls `CaseFile.indexing_status = 'IOC Hunting'`
- Phase completes when count = 0

**Celery Tasks**:
- `hunt_iocs_file_task(file_id, case_id)` - Worker task

**Progress Tracking**:
- `current_count`: Files still hunting IOCs
- `total_count`: Total files for IOC matching

---

### FINALIZE: Mark Files Complete

**Operations**:
1. Query files with `is_indexed=True` AND `indexing_status != 'Completed'`
2. Set `indexing_status = 'Completed'`
3. Clear `celery_task_id`
4. Call `complete_progress(case_id, 'reindex', success=True)` to clear Redis progress

**Module**: `app/coordinator_index.py` (end of `index_new_files()`)

---

## Progress Tracking (v2.0.1)

### Redis-Backed Storage

**Module**: `app/progress_tracker.py`

**Functions**:
- `start_progress(case_id, operation_type, phases)` - Initialize
- `update_phase(case_id, operation_type, phase_num, phase_name, status, message, current_count, total_count)` - Update phase
- `complete_progress(case_id, operation_type, success)` - Finalize
- `get_progress(case_id, operation_type)` - Retrieve

**Redis Keys**:
- `casescope:progress:<case_id>:<operation_type>` - Main progress data
- `casescope:operation:<case_id>` - Operation lock
- `casescope:phase:<case_id>:<phase_num>` - Individual phase data

**Auto-Resume (v2.0.2)**:
- Frontend JavaScript checks for ongoing operations on page load
- Automatically resumes progress monitoring if status='running'

---

## Frontend Progress Display

### Real-Time Progress Bar (v2.0.1)

**Location**: `app/templates/case_files.html`

**Features**:
- Banner-style progress bar with gradient background
- Shows: "Phase Name - X/Y (Z%)"
- Polls `/case/<id>/progress/reindex` every 2 seconds
- Automatically hides when complete

**Modal Display**:
- Detailed phase breakdown
- Per-phase progress bars
- Status indicators: ✓ (complete), ⏳ (running), ⚠️ (failed), ⏸️ (pending)

---

## Database Models

### CaseFile Fields (v2.1.4)

```python
class CaseFile(db.Model):
    # Processing Status
    indexing_status = db.Column(db.String(50))  # 'Queued', 'Indexing', 'Indexed', 
                                                 # 'SIGMA Testing', 'SIGMA Complete',
                                                 # 'IOC Hunting', 'IOC Complete', 
                                                 # 'Completed', 'Failed - ...'
    is_indexed = db.Column(db.Boolean, default=False)
    is_hidden = db.Column(db.Boolean, default=False)  # Auto-hide 0-event files
    is_deleted = db.Column(db.Boolean, default=False)
    
    # Counts
    event_count = db.Column(db.Integer, default=0)
    violation_count = db.Column(db.Integer, default=0)
    ioc_event_count = db.Column(db.Integer, default=0)
    
    # Task Tracking
    celery_task_id = db.Column(db.String(255))
    error_message = db.Column(db.Text)
```

### EventStatus Table

```python
class EventStatus(db.Model):
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'))
    event_id = db.Column(db.String(255))
    status = db.Column(db.String(20))  # 'new', 'noise', 'hunted', 'confirmed'
    notes = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
```

---

## API Endpoints

### POST /case/<case_id>/bulk-reindex

**Purpose**: Start the reindex pipeline.

**Handler**: `app/main.py` → `bulk_reindex_route()`

**Process**:
1. Runs `reindex_files()` in background daemon thread
2. Returns immediately with success message
3. Frontend starts polling for progress

**Response**:
```json
{
    "status": "success",
    "message": "Reindexing started for 156 files"
}
```

---

### GET /case/<case_id>/progress/reindex

**Purpose**: Get real-time progress of reindex.

**Handler**: `app/routes/progress.py` → `get_reindex_progress()`

**Response**:
```json
{
    "status": "running",
    "description": "Reindexing files...",
    "phases": [
        {
            "number": 1,
            "name": "Clear Data",
        "status": "completed",
            "message": "Cleared old data",
            "current_count": 675,
            "total_count": 675
    },
        {
            "number": 4,
            "name": "Known-Good Filter",
        "status": "running",
            "message": "Filtering known-good events...",
            "current_count": 523401,
            "total_count": 1200000
        }
    ],
    "started_at": "2025-12-05T10:30:15",
    "completed_at": null
}
```

---

## Code Modules

### Coordinators

- `app/coordinator_reindex.py` - Main reindex orchestrator
- `app/coordinator_index.py` - Indexing workflow orchestrator
- `app/coordinator_resigma.py` - Re-SIGMA orchestrator
- `app/coordinator_ioc.py` - Re-IOC orchestrator

### Processing Modules

- `app/processing_clear_metadata.py` - Phase 1: Clear data
- `app/processing_index.py` - Phase 2: Index files
- `app/processing_sigma.py` - Phase 3: SIGMA detection
- `app/events_known_good.py` - Phase 4: Known-good filtering (parallel)
- `app/events_known_noise.py` - Phase 5: Known-noise filtering (parallel)
- `app/processing_ioc.py` - Phase 6: IOC matching

### Core Processing

- `app/file_processing.py` - File indexing logic (`index_one_file`, `hunt_iocs`)
- `app/sigma_detection.py` - SIGMA detection engine
- `app/event_descriptions.py` - Event description enrichment

### Utilities

- `app/progress_tracker.py` - Redis-backed progress tracking
- `app/tasks.py` - Celery task helpers
- `app/utils.py` - General utilities

---

## Critical Design Patterns

### 1. Database Polling (v2.0.0)

**Problem**: Celery `result.get()` causes deadlocks in Gunicorn workers.

**Solution**: Coordinators poll database instead of blocking on task results.

```python
# Poll for files still in queue
while True:
    in_queue = db.session.query(CaseFile).filter(
        CaseFile.case_id == case_id,
        CaseFile.indexing_status.in_(['Queued', 'Indexing'])
    ).count()
    
    if in_queue == 0:
        break  # Phase complete
    
    time.sleep(5)  # Poll every 5 seconds
```

### 2. Background Thread Coordinator (v2.0.0)

**Pattern**: Long-running coordinators run in daemon threads, not Celery tasks.

```python
# main.py → bulk_reindex_route
def bulk_reindex_route(case_id):
    # Run in background thread
    import threading
    thread = threading.Thread(
        target=reindex_files,
        args=(case_id,),
        daemon=True
    )
    thread.start()
    
    return jsonify({'status': 'success'})
```

### 3. Parallel Slice Processing (v2.1.0)

**Pattern**: Split large datasets into 8 slices, process in parallel.

```python
# Dispatch 8 parallel workers
from celery import group

slice_tasks = group([
    hide_known_good_slice_task.s(case_id, i, 8)
    for i in range(8)
])
group_result = slice_tasks.apply_async()

# Poll for completion
while not group_result.ready():
    time.sleep(5)

# Get results
for res in group_result.get():
    total_hidden += res['hidden']
```

### 4. Dual Storage (OpenSearch + PostgreSQL)

**Pattern**: Store event status in BOTH systems for performance and reliability.

**OpenSearch** (fast filtering):
```json
{
    "event_status": "noise",
    "status_reason": "auto_known_good"
}
```

**PostgreSQL** (reliable counts):
```sql
INSERT INTO event_status (case_id, event_id, status, notes)
VALUES (15, 'abc123', 'noise', 'Auto-marked');
```

---

## Performance Considerations

### Parallelization

- **Phase 2 (Index)**: Limited by Celery worker count (files processed in parallel)
- **Phase 3 (SIGMA)**: Limited by Celery worker count (files processed in parallel)
- **Phase 4 (Known-Good)**: 8 parallel slices (fixed)
- **Phase 5 (Known-Noise)**: 8 parallel slices (fixed)
- **Phase 6 (IOC)**: Limited by Celery worker count (files processed in parallel)

### Database Connection Pooling (v2.1.0)

```python
# main.py
app.config['SQLALCHEMY_POOL_SIZE'] = 20
app.config['SQLALCHEMY_MAX_OVERFLOW'] = 10
app.config['SQLALCHEMY_POOL_TIMEOUT'] = 30
app.config['SQLALCHEMY_POOL_RECYCLE'] = 1800
app.config['SQLALCHEMY_POOL_PRE_PING'] = True
```

### Batch Processing

- OpenSearch bulk index: 1000 events per batch
- Database commits: 10,000 records per batch
- Prevents memory bloat and improves throughput

---

## Monitoring and Debugging

### Check Progress via Redis

```bash
redis-cli GET "casescope:progress:15:reindex"
```

### Check Celery Workers

```bash
# Active tasks
celery -A celery_app inspect active

# Worker stats
celery -A celery_app inspect stats
```

### Check File Status Distribution

```bash
sudo -u postgres psql casescope -c "
SELECT indexing_status, COUNT(*)
FROM case_file
WHERE case_id = 15 AND is_deleted = false
GROUP BY indexing_status;
"
```

---

## Version History

- **v2.1.4** - Dynamic "Files with Events" counter
- **v2.1.3** - Button brightness reduction
- **v2.1.2** - Centralized CSS button styles
- **v2.1.1** - Progress bar auto-clear fix, task registration
- **v2.1.0** - Parallel Known-Good/Noise processing (8 workers)
- **v2.0.2** - Auto-resume progress monitoring on page reload
- **v2.0.1** - Real-time progress bars with percentages
- **v2.0.0** - Modular processing system with database polling

---

## See Also

- `site_documentation/EVENTS_KNOWN_GOOD.md` - Known-good detection rules
- `site_documentation/EVENTS_KNOWN_NOISE.md` - Known-noise detection rules
- `site_maps/CASE_FILES.md` - Complete dependency map
