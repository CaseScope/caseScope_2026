# CaseScope Modular Processing System v2.0

**Status**: Implementation Complete - Ready for Integration Testing  
**Date**: 2025-12-03  
**Purpose**: Redesigned file processing system with phased, modular architecture

---

## 📋 Overview

The new modular processing system separates file processing into distinct, sequential phases with parallel execution within each phase.

### Old System Problems
- Monolithic `process_file` task did everything: index → SIGMA → IOC
- Workers could start SIGMA before all files were indexed
- IOC matching ran per-file (inefficient)
- No clear separation of concerns
- Hard to debug and maintain

### New System Benefits
✅ **Modular** - Each phase in its own file with clear responsibility  
✅ **Sequential** - Phase 2 doesn't start until Phase 1 is 100% complete  
✅ **Parallel** - 8 workers can run within each phase  
✅ **Efficient** - IOC matching runs once across all events (not per-file)  
✅ **Maintainable** - Clear code organization and logging  
✅ **Testable** - Each phase can be tested independently  

---

## 🏗️ Architecture

### New Files Created

```
/opt/casescope/app/
├── processing_index.py      - Phase 1: File indexing (8 workers)
├── processing_sigma.py       - Phase 2: SIGMA detection (8 workers)
├── processing_ioc.py         - Phase 3: IOC matching (8 workers)
└── phase_coordinator.py      - Orchestrates all phases sequentially
```

### Processing Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    PHASE COORDINATOR                        │
│                 (phase_coordinator.py)                      │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ PHASE 1: FILE INDEXING (processing_index.py)               │
│ • Process all files in queue                                │
│ • 8 workers run in parallel                                 │
│ • Convert EVTX/NDJSON/CSV/IIS to searchable format         │
│ • Index events to OpenSearch                                │
│ • Update database metadata                                  │
│ ✓ Wait for ALL files to complete                           │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ PHASE 2: SIGMA DETECTION (processing_sigma.py)             │
│ • Process all indexed EVTX files                            │
│ • 8 workers run in parallel                                 │
│ • Run Chainsaw with SIGMA rules                             │
│ • Create SigmaViolation records                             │
│ • Flag events in OpenSearch                                 │
│ ✓ Wait for ALL files to complete                           │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ PHASE 3: HIDE KNOWN-GOOD EVENTS (events_known_good.py)     │
│ • Single-threaded operation                                 │
│ • Filter events from trusted tools (RMM, EDR)               │
│ • Based on SystemToolsSettings                              │
│ ✓ Wait for completion                                       │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ PHASE 4: HIDE KNOWN-NOISE EVENTS (events_known_noise.py)   │
│ • Single-threaded operation                                 │
│ • Filter routine system noise                               │
│ • Firewall denies, monitoring loops, etc.                   │
│ ✓ Wait for completion                                       │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ PHASE 5: IOC MATCHING (processing_ioc.py)                  │
│ • Match ALL IOCs across ALL events in case                  │
│ • 8 workers run in parallel (one per IOC)                   │
│ • Create IOCMatch records                                   │
│ • Flag events in OpenSearch                                 │
│ ✓ Wait for ALL IOCs to complete                            │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
                        [ COMPLETED ]
```

---

## 📁 File Details

### 1. `processing_index.py` - File Indexing

**Purpose**: Convert files to searchable format and index to OpenSearch

**Main Functions**:
```python
@celery_app.task
def index_file_task(file_id: int) -> Dict:
    """Worker task: Index a single file"""
    
def index_all_files_in_queue(case_id: int) -> Dict:
    """Coordinator: Index all queued files in parallel"""
    
def is_indexing_complete(case_id: int) -> bool:
    """Check if all files are indexed"""
```

**Worker Behavior**:
- Gets file from database
- Checks if already indexed (skip if yes)
- Calls `file_processing.index_file()` to do the work
- Updates status to 'Indexed'
- Returns event count

**Parallelism**: Up to 8 files can be indexed simultaneously

**Wait Condition**: All files must reach status 'Indexed' before moving to Phase 2

---

### 2. `processing_sigma.py` - SIGMA Detection

**Purpose**: Run SIGMA rules against EVTX files using Chainsaw

**Main Functions**:
```python
@celery_app.task
def sigma_detect_task(file_id: int) -> Dict:
    """Worker task: Run SIGMA on a single EVTX file"""
    
def sigma_detect_all_files(case_id: int) -> Dict:
    """Coordinator: Run SIGMA on all EVTX files in parallel"""
    
def is_sigma_complete(case_id: int) -> bool:
    """Check if SIGMA has run on all EVTX files"""
```

**Worker Behavior**:
- Checks if file is EVTX (skip others)
- Checks if file has events (skip if 0)
- Calls `file_processing.chainsaw_file()` to do the work
- Updates status to 'SIGMA Complete'
- Returns violation count

**Parallelism**: Up to 8 EVTX files can be processed simultaneously

**Wait Condition**: All EVTX files must complete SIGMA before moving to Phase 3

---

### 3. `processing_ioc.py` - IOC Matching

**Purpose**: Match IOCs against ALL events in case (not per-file)

**Main Functions**:
```python
@celery_app.task
def match_ioc_task(case_id: int, ioc_id: int) -> Dict:
    """Worker task: Match a single IOC across all case events"""
    
def match_all_iocs(case_id: int) -> Dict:
    """Coordinator: Match all IOCs in parallel"""
    
def is_ioc_matching_complete(case_id: int) -> bool:
    """Check if IOC matching is complete (always True)"""
```

**Worker Behavior**:
- Gets IOC from database
- Searches OpenSearch for matches (across ALL files in case)
- Creates IOCMatch records
- Flags matching events with `has_ioc`
- Updates file IOC counts
- Returns match count

**Key Difference from Old System**:
- ❌ Old: IOC matching ran per-file during indexing
- ✅ New: IOC matching runs ONCE across all events after everything is indexed

**Parallelism**: Up to 8 IOCs can be matched simultaneously

**Wait Condition**: All active IOCs must complete matching before finalizing

---

### 4. `phase_coordinator.py` - Orchestrator

**Purpose**: Run all phases in sequence and handle phase transitions

**Main Functions**:
```python
def run_phased_processing(case_id: int, progress_callback=None) -> Dict:
    """Run all 5 phases in sequence"""
    
@celery_app.task
def run_phased_processing_task(case_id: int) -> Dict:
    """Async wrapper for run_phased_processing"""
    
def get_processing_status(case_id: int) -> Dict:
    """Get current processing status for a case"""
```

**Execution Logic**:
1. Run Phase 1 → wait for completion
2. If Phase 1 fails → STOP (don't continue)
3. Run Phase 2 → wait for completion
4. If Phase 2 fails → log warning but CONTINUE
5. Run Phase 3 → wait for completion
6. Run Phase 4 → wait for completion
7. Run Phase 5 → wait for completion
8. Mark all files as 'Completed'

**Critical vs Non-Critical Phases**:
- **Critical**: Phase 1 (indexing) - MUST succeed to continue
- **Non-Critical**: Phases 2-5 - Failures are logged but processing continues

**Progress Callbacks**:
- Optional callback function for UI updates
- Called at phase start/end with status messages

---

## 🔄 Integration Points

### Where Old System Called `process_file()`

The old system had these entry points that need updating:

**1. File Upload (`upload_integration.py`)**:
```python
# OLD:
celery_app.send_task('tasks.process_file', args=[file_id, 'full'])

# NEW:
from phase_coordinator import run_phased_processing_task
run_phased_processing_task.delay(case_id)  # Process entire case
```

**2. Bulk Operations (`tasks.py`)**:
```python
# OLD:
@celery_app.task
def bulk_reindex(case_id):
    # Clear data
    # Queue files with operation='reindex'
    
# NEW:
@celery_app.task
def bulk_reindex(case_id):
    # Clear data
    from phase_coordinator import run_phased_processing
    return run_phased_processing(case_id)
```

**3. Manual File Processing (`routes/files.py`)**:
```python
# OLD:
process_file.delay(file_id, operation='full')

# NEW:
# For single file: still use old system OR
# Better: trigger phased processing for entire case
```

---

## 📊 Database Status Fields

### CaseFile.indexing_status Values

**Old System**:
```
Queued → Indexing → SIGMA Testing → IOC Hunting → Completed
```

**New System**:
```
Queued → Indexing → Indexed → SIGMA Testing → SIGMA Complete → IOC Hunting → Completed
```

**New Status Values**:
- `Indexed` - File indexed but SIGMA not yet run
- `SIGMA Complete` - SIGMA finished but IOC not yet run
- `Completed` - All phases finished

**Why Add Intermediate Statuses?**
- Clear visibility into which phase is running
- Easier debugging when things fail
- Can resume from specific phase

---

## 🧪 Testing Plan

### Phase 1: Unit Testing (Per Module)

Test each processing module independently:

```bash
# Test indexing phase
cd /opt/casescope/app
python3 -c "
from processing_index import index_file_task, index_all_files_in_queue
from main import app

with app.app_context():
    # Test single file
    result = index_file_task(file_id=12345)
    print(f'Single file: {result}')
    
    # Test all files
    result = index_all_files_in_queue(case_id=25)
    print(f'All files: {result}')
"
```

```bash
# Test SIGMA phase
python3 -c "
from processing_sigma import sigma_detect_task, sigma_detect_all_files
from main import app

with app.app_context():
    result = sigma_detect_all_files(case_id=25)
    print(f'SIGMA: {result}')
"
```

```bash
# Test IOC phase
python3 -c "
from processing_ioc import match_ioc_task, match_all_iocs
from main import app

with app.app_context():
    result = match_all_iocs(case_id=25)
    print(f'IOC: {result}')
"
```

### Phase 2: Integration Testing (Full Flow)

Test complete phased processing:

```bash
# Test full processing flow
python3 -c "
from phase_coordinator import run_phased_processing
from main import app

with app.app_context():
    result = run_phased_processing(case_id=25)
    print(f'Status: {result[\"status\"]}')
    print(f'Phases completed: {result[\"phases_completed\"]}')
    print(f'Stats: {result[\"stats\"]}')
"
```

### Phase 3: Live Testing (With Real Files)

1. Create new test case
2. Upload 5-10 small EVTX files
3. Trigger phased processing
4. Monitor logs: `/var/log/casescope/casescope.log`
5. Check database: File statuses, event counts, SIGMA violations, IOC matches
6. Verify OpenSearch: Events indexed, has_sigma flags, has_ioc flags

---

## 🔧 Integration Steps

### Step 1: Backup Current System

```bash
# Backup tasks.py (main processing file)
cp /opt/casescope/app/tasks.py /opt/casescope/app/tasks.py.backup.$(date +%Y%m%d)

# Backup upload_integration.py
cp /opt/casescope/app/upload_integration.py /opt/casescope/app/upload_integration.py.backup.$(date +%Y%m%d)
```

### Step 2: Update Upload Integration

Modify `upload_integration.py` to use phased processing:

**File**: `/opt/casescope/app/upload_integration.py`
**Function**: `handle_http_upload_v96()` and `handle_bulk_upload_v96()`

```python
# OLD (line ~83):
celery_app.send_task('tasks.process_file', args=[file_id, 'full'])

# NEW:
# After all files are queued, trigger phased processing ONCE for the case
from phase_coordinator import run_phased_processing_task
run_phased_processing_task.delay(case_id)
```

### Step 3: Update Bulk Reindex

Modify `tasks.py` bulk operations to use phased processing:

**File**: `/opt/casescope/app/tasks.py`
**Function**: `bulk_reindex()`

```python
@celery_app.task(bind=True, name='tasks.bulk_reindex')
def bulk_reindex(self, case_id):
    """Re-index all files in a case using phased processing"""
    # ... existing cleanup code ...
    
    # NEW: Use phased processing instead of queueing individual files
    from phase_coordinator import run_phased_processing
    result = run_phased_processing(case_id)
    
    return result
```

### Step 4: Register New Celery Tasks

Add new tasks to Celery configuration (if needed):

**File**: `/opt/casescope/app/celery_app.py`

The tasks are automatically discovered since they use `@celery_app.task` decorator.

### Step 5: Restart Services

```bash
# Restart Celery workers to load new code
sudo systemctl restart casescope-worker

# Restart Flask app
sudo systemctl restart casescope
```

### Step 6: Test with Sample Case

```bash
# Monitor logs in real-time
tail -f /var/log/casescope/casescope.log | grep -E '\[PHASE|INDEX_TASK|SIGMA_TASK|IOC_TASK\]'

# In another terminal, trigger processing
python3 /opt/casescope/app/test_phased_processing.py
```

---

## 🐛 Troubleshooting

### Issue: Phase 1 never completes

**Symptoms**: Files stuck in 'Indexing' status

**Checks**:
1. Check Celery workers are running: `sudo systemctl status casescope-worker`
2. Check worker logs: `tail -f /var/log/casescope/celery_worker.log`
3. Check for stuck tasks: Look for files with `celery_task_id` set but task is FAILURE/SUCCESS

**Fix**:
```python
# Clear stuck task IDs
from main import app, db
from models import CaseFile

with app.app_context():
    stuck = CaseFile.query.filter(
        CaseFile.celery_task_id.isnot(None),
        CaseFile.indexing_status == 'Indexing'
    ).all()
    
    for f in stuck:
        f.celery_task_id = None
        f.indexing_status = 'Queued'
    
    db.session.commit()
    print(f'Cleared {len(stuck)} stuck files')
```

### Issue: SIGMA phase fails on all files

**Symptoms**: Phase 2 shows 100% failure rate

**Checks**:
1. Check Chainsaw binary exists: `ls -lh /opt/casescope/bin/chainsaw`
2. Check SIGMA rules exist: `ls /opt/casescope/sigma_rules_repo/rules/windows/ | head`
3. Check EVTX files exist on disk

**Fix**: Chainsaw or SIGMA rules missing - re-install per INSTALL.md

### Issue: IOC matching finds 0 matches

**Symptoms**: Phase 5 completes but total_matches=0

**Checks**:
1. Verify IOCs exist: `SELECT COUNT(*) FROM ioc WHERE case_id=25 AND is_active=TRUE;`
2. Verify events indexed: Check OpenSearch for case_25 index
3. Check IOC values are searchable (not empty, not too complex)

**Fix**: Add test IOC and verify match

---

## 📈 Performance Expectations

### Indexing Phase (Phase 1)
- **Speed**: ~1-5 files/second (depends on file size)
- **Example**: 100 files @ 50MB each = ~5-10 minutes with 8 workers

### SIGMA Phase (Phase 2)
- **Speed**: ~1-2 EVTX files/second (Chainsaw is CPU-intensive)
- **Example**: 50 EVTX files = ~5-10 minutes with 8 workers

### Known-Good Phase (Phase 3)
- **Speed**: ~10,000-50,000 events/second (single-threaded)
- **Example**: 1M events = ~30-60 seconds

### Known-Noise Phase (Phase 4)
- **Speed**: ~10,000-50,000 events/second (single-threaded)
- **Example**: 1M events = ~30-60 seconds

### IOC Matching Phase (Phase 5)
- **Speed**: ~100-1,000 IOCs/minute (depends on matches found)
- **Example**: 50 IOCs against 1M events = ~5-10 minutes

### Total Time Estimate
- **Small case** (10 files, 10K events): ~2-5 minutes
- **Medium case** (100 files, 500K events): ~20-30 minutes
- **Large case** (1000 files, 10M events): ~2-4 hours

---

## 🎯 Success Criteria

Phased processing is working correctly if:

✅ **Phase 1**: All files show `is_indexed=True` and `event_count > 0`  
✅ **Phase 2**: EVTX files show `violation_count >= 0` (may be 0 if no violations)  
✅ **Phase 3**: Events with known-good indicators have `event_status='noise'`  
✅ **Phase 4**: Events with known-noise patterns have `event_status='noise'`  
✅ **Phase 5**: IOCMatch records exist and events have `has_ioc=True`  
✅ **Final**: All files show `indexing_status='Completed'` and `celery_task_id=NULL`  

---

## 📝 Next Steps

1. ✅ **Module Creation** - DONE (processing_index.py, processing_sigma.py, processing_ioc.py, phase_coordinator.py)
2. ⏳ **Integration** - Update tasks.py and upload_integration.py to use new system
3. ⏳ **Testing** - Run unit tests on each module
4. ⏳ **Live Testing** - Test with real case files
5. ⏳ **Monitoring** - Add progress tracking UI
6. ⏳ **Documentation** - Update user-facing docs

---

## 🔗 Related Files

**New Modules**:
- `/opt/casescope/app/processing_index.py`
- `/opt/casescope/app/processing_sigma.py`
- `/opt/casescope/app/processing_ioc.py`
- `/opt/casescope/app/phase_coordinator.py`

**Files to Update**:
- `/opt/casescope/app/tasks.py` - Update bulk operations
- `/opt/casescope/app/upload_integration.py` - Use phased processing
- `/opt/casescope/app/routes/files.py` - Update single file processing

**Dependencies (Existing)**:
- `/opt/casescope/app/file_processing.py` - index_file(), chainsaw_file(), hunt_iocs()
- `/opt/casescope/app/events_known_good.py` - hide_known_good_events()
- `/opt/casescope/app/events_known_noise.py` - hide_noise_events()

---

**Implementation Status**: ✅ Modules Created, ⏳ Integration Pending, ⏳ Testing Pending

