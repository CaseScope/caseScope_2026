# File State Tracking System

**Version:** 2.2.0  
**Date:** December 18, 2025  
**Status:** ✅ Active - Fully Operational

## Recent Updates

**December 18, 2025 - Coordinator Finalization Fix:**
- **Issue**: Noise filtering flags (`known_good`, `known_noise`) were never being set
- **Root Cause**: Noise filtering modules operate on OpenSearch events, not CaseFile records
- **Fix**: Coordinators now set these flags in finalization phase after all phases complete
- **Files Updated**: `app/coordinator_index.py`, `app/coordinator_reindex.py`
- **Impact**: Files now properly reach `Completed` state after all phases done

## Overview

The File State Tracking System replaces fragile status string parsing with explicit boolean flags and state management. This system provides reliable file processing tracking, accurate statistics, and consistent state transitions across all operations.

## Problem Solved

### Before v2.2.0 (Status String Parsing)

- **Failed files count mismatch**: Failed files page showed 2,937 files, but case statistics showed 1 file
- **Root cause**: Two different methods of counting failed files:
  - Failed files page: `NOT IN ['Completed', 'Indexing', 'SIGMA Testing', 'IOC Hunting', 'Queued']`
  - Statistics: `LIKE 'Failed%'`
- **Additional issues**:
  - Ambiguous statuses: "IOC Complete" looks complete but isn't
  - No phase tracking: Can't tell if SIGMA/IOC/Noise have run
  - Re-operations are blind: Don't know original completion state
  - Statistics are fragile: Break when status strings change

### After v2.2.0 (Flag-Based Tracking)

- ✅ **Consistent statistics**: All queries use same boolean flags
- ✅ **Explicit phase tracking**: Each phase has dedicated flag
- ✅ **State persistence**: Save/restore state for partial re-operations
- ✅ **Completion logic**: Computed property based on file type and flags
- ✅ **Atomic operations**: Flags updated as phases complete

---

## Database Schema

### New Fields in `case_file` Table

```sql
-- Processing flags (boolean)
is_new BOOLEAN DEFAULT TRUE        -- Newly uploaded, not indexed yet
is_indexed BOOLEAN DEFAULT FALSE   -- Indexing complete
sigma_hunted BOOLEAN DEFAULT FALSE -- SIGMA detection complete (EVTX only)
ioc_hunted BOOLEAN DEFAULT FALSE   -- IOC hunting complete
known_good BOOLEAN DEFAULT FALSE   -- Known-good filtering complete
known_noise BOOLEAN DEFAULT FALSE  -- Known-noise filtering complete
is_hidden BOOLEAN DEFAULT FALSE    -- Hidden (0-events or filtered)
failed BOOLEAN DEFAULT FALSE       -- Failed at any step

-- State tracking
file_state VARCHAR(50) DEFAULT 'New'      -- Current state for UI display
previous_state VARCHAR(50) DEFAULT NULL   -- State before re-operation

-- Queue tracking (existing field, new usage)
celery_task_id VARCHAR(255) DEFAULT NULL  -- NULL = not queued, NOT NULL = queued
```

### Indexes

```sql
CREATE INDEX idx_case_file_is_new ON case_file(is_new);
CREATE INDEX idx_case_file_sigma_hunted ON case_file(sigma_hunted);
CREATE INDEX idx_case_file_ioc_hunted ON case_file(ioc_hunted);
CREATE INDEX idx_case_file_known_good ON case_file(known_good);
CREATE INDEX idx_case_file_known_noise ON case_file(known_noise);
CREATE INDEX idx_case_file_failed ON case_file(failed);
CREATE INDEX idx_case_file_file_state ON case_file(file_state);
```

---

## File States

### State Flow Diagram

```
INITIAL UPLOAD/REINDEX:
  New → Indexing → Indexed → SIGMA Hunting → SIGMA Checked → 
  IOC Hunting → IOC Checked → Noise Checking → Noise Checked → Completed

RE-OPERATIONS (from Completed):
  Completed → Reindexing → [full pipeline] → Completed
  Completed → SIGMA Hunting → SIGMA Checked → Completed (restore)
  Completed → IOC Hunting → IOC Checked → Completed (restore)
  Completed → Noise Checking → Noise Checked → Completed (restore)

SPECIAL:
  Any state → Failed (on error)
  Indexed → Hidden (if 0 events)
  Noise Checked → Hidden (if known-good or known-noise matched)
```

### State Definitions

| State | Description | Flags Set |
|-------|-------------|-----------|
| `New` | File just uploaded, not processed | `is_new=True` |
| `Indexing` | Currently indexing to OpenSearch | `is_new=False` |
| `Indexed` | Indexing complete, ready for hunting | `is_indexed=True` |
| `SIGMA Hunting` | Running SIGMA detection (EVTX only) | - |
| `SIGMA Checked` | SIGMA detection complete | `sigma_hunted=True` |
| `IOC Hunting` | Running IOC hunting | - |
| `IOC Checked` | IOC hunting complete | `ioc_hunted=True` |
| `Noise Checking` | Running known-good/noise filtering | - |
| `Noise Checked` | Noise filtering complete | `known_good=True, known_noise=True` |
| `Completed` | All phases complete | Computed via `is_completed` |
| `Failed` | Error at any step | `failed=True` |
| `Hidden` | 0 events or filtered as noise | `is_hidden=True` |

---

## Completion Logic

### `is_completed` Property

A file is considered **completed** when:

1. ✅ It has been **indexed** (`is_indexed=True`)
2. ✅ **IOC hunting** is complete (`ioc_hunted=True`)
3. ✅ **Noise checking** is complete (`known_good=True` AND `known_noise=True`)
4. ✅ For **EVTX files**: SIGMA detection is complete (`sigma_hunted=True`)
5. ✅ For **non-EVTX files**: SIGMA is skipped (ignored)
6. ❌ NOT hidden (`is_hidden=False`)
7. ❌ NOT failed (`failed=False`)
8. ❌ NOT 0 events (`event_count > 0`)

### Python Implementation

```python
@property
def is_completed(self):
    """Determines if file processing is fully completed"""
    # Files with 0 events, hidden, or failed are never "completed"
    if self.is_hidden or self.failed or self.event_count == 0:
        return False
    
    # Check if file is EVTX (needs SIGMA)
    is_evtx = self.original_filename.lower().endswith('.evtx')
    
    # All files need: indexed, IOC hunted, noise checked
    base_complete = (
        self.is_indexed and
        self.ioc_hunted and
        self.known_good and
        self.known_noise
    )
    
    # EVTX files additionally need SIGMA
    if is_evtx:
        return base_complete and self.sigma_hunted
    else:
        return base_complete
```

### SQL Query for Completed Files

```sql
SELECT COUNT(*) 
FROM case_file
WHERE is_deleted = FALSE
  AND is_hidden = FALSE
  AND failed = FALSE
  AND event_count > 0
  AND is_indexed = TRUE
  AND ioc_hunted = TRUE
  AND known_good = TRUE
  AND known_noise = TRUE
  AND (
      -- Non-EVTX files don't need SIGMA
      original_filename NOT ILIKE '%.evtx'
      OR 
      -- EVTX files need SIGMA
      sigma_hunted = TRUE
  );
```

---

## File State Manager (`file_state_manager.py`)

### Purpose

Manages file state transitions and flag updates with validation.

### Key Functions

#### State Transitions

```python
# Start operations
fsm.start_indexing(case_file)           # New → Indexing
fsm.start_sigma_hunting(case_file)      # Indexed → SIGMA Hunting
fsm.start_ioc_hunting(case_file)        # SIGMA Checked → IOC Hunting
fsm.start_noise_checking(case_file)     # IOC Checked → Noise Checking

# Complete operations
fsm.complete_indexing(case_file, event_count)    # Sets is_indexed=True or is_hidden=True
fsm.complete_sigma_hunting(case_file)            # Sets sigma_hunted=True
fsm.complete_ioc_hunting(case_file)              # Sets ioc_hunted=True
fsm.complete_noise_checking(case_file, marked_as_noise)  # Sets flags or hides

# Finalization
fsm.finalize_processing(case_file)      # Checks is_completed and sets state='Completed'
fsm.mark_failed(case_file, error_msg)   # Sets failed=True, state='Failed'
```

#### Re-Operations

```python
# Full reindex - resets all flags
fsm.start_reindex(case_file)
# ... run full pipeline ...
fsm.finalize_processing(case_file)

# Partial re-operation (sigma, ioc, or noise)
fsm.start_partial_operation(case_file, 'sigma')  # Saves previous_state
# ... run SIGMA only ...
fsm.complete_partial_operation(case_file, 'sigma')  # Restores previous_state
```

### State Transition Validation

The manager enforces valid transitions:

```python
VALID_TRANSITIONS = {
    'New': ['Indexing', 'Failed'],
    'Indexing': ['Indexed', 'Hidden', 'Failed'],
    'Indexed': ['SIGMA Hunting', 'IOC Hunting', 'Hidden', 'Failed'],
    'SIGMA Hunting': ['SIGMA Checked', 'Failed'],
    # ... etc
}

def validate_transition(from_state, to_state):
    """Returns True if transition is allowed"""
    if from_state not in VALID_TRANSITIONS:
        return True  # Allow unknown (backward compat)
    return to_state in VALID_TRANSITIONS[from_state]
```

---

## File Statistics (`file_statistics.py`)

### Purpose

Provides consistent file statistics queries using flag-based tracking.

### Statistics Functions

```python
import file_statistics as fstats

# Get comprehensive statistics
stats = fstats.get_file_statistics(db.session, CaseFile, case_id=123)
# Returns:
# {
#   'total_files': int,
#   'files_with_events': int,
#   'hidden_files': int,
#   'completed_files': int,     # Uses is_completed logic
#   'failed_files': int,         # Uses failed flag
#   'indexed_files': int,
#   'sigma_checked': int,
#   'ioc_checked': int,
#   'noise_checked': int,
#   'queued_files': int,
#   'new_files': int,
#   'total_space_gb': float
# }

# Get files by state
state_counts = fstats.get_files_by_state(db.session, CaseFile, case_id=123)
# Returns: {'Completed': 289, 'Failed': 3, 'Indexing': 5, ...}

# Get failed files count
failed_count = fstats.get_failed_files_count(db.session, CaseFile, case_id=123)

# Get failed files paginated
pagination = fstats.get_failed_files_paginated(
    db.session, CaseFile, Case,
    case_id=123, page=1, per_page=50, search_term='error'
)

# Get files currently processing (have celery_task_id)
processing = fstats.get_processing_files(db.session, CaseFile, case_id=123, limit=100)

# Get files needing a specific phase
files_needing_sigma = fstats.get_files_needing_phase(
    db.session, CaseFile, 'sigma', case_id=123
)

# Get incomplete files (indexed but not completed)
incomplete = fstats.get_incomplete_files(db.session, CaseFile, case_id=123)

# Get human-readable summary
summary = fstats.get_statistics_summary(db.session, CaseFile, case_id=123)
print(summary)
```

---

## Processing Flow

### Initial Upload (tasks.py `process_file()`)

**Note**: Individual file processing sets most flags, but `known_good` and `known_noise` are set by the coordinator after bulk noise filtering completes.

```python
# Step 1: Duplicate check
dup_result = duplicate_check(...)
if dup_result['status'] == 'skip':
    fsm.finalize_processing(case_file)  # Mark completed (duplicate)
    return {'status': 'success'}

# Step 2: Index file
fsm.start_indexing(case_file)  # State='Indexing', is_new=False
db.session.commit()

index_result = index_file(...)

if index_result['status'] == 'error':
    fsm.mark_failed(case_file, error_msg)  # State='Failed', failed=True
    return index_result

fsm.complete_indexing(case_file, event_count)  # State='Indexed', is_indexed=True
db.session.commit()

if event_count == 0:
    return {'status': 'success'}  # Hidden

# Step 3: SIGMA (EVTX only)
if case_file.original_filename.lower().endswith('.evtx'):
    fsm.start_sigma_hunting(case_file)  # State='SIGMA Hunting'
    db.session.commit()
    
    chainsaw_result = chainsaw_file(...)
    
    fsm.complete_sigma_hunting(case_file)  # State='SIGMA Checked', sigma_hunted=True
    db.session.commit()

# Step 4: IOC Hunting
fsm.start_ioc_hunting(case_file)  # State='IOC Hunting'
db.session.commit()

ioc_result = hunt_iocs(...)

fsm.complete_ioc_hunting(case_file)  # State='IOC Checked', ioc_hunted=True
db.session.commit()

# Note: known_good/known_noise flags are NOT set here
# They are set by the coordinator after bulk noise filtering
```

### Coordinator Finalization (coordinator_index.py, coordinator_reindex.py)

**This is where `known_good` and `known_noise` flags are finally set:**

```python
# After all 5 phases complete (Index, SIGMA, Known-Good, Known-Noise, IOC):

# Phase 6: Finalization
files = db.session.query(CaseFile).filter(
    CaseFile.case_id == case_id,
    CaseFile.is_indexed == True,
    CaseFile.celery_task_id.isnot(None)
).all()

for f in files:
    # Clear celery_task_id
    f.celery_task_id = None
    
    # Update noise checking flags (NOW SET!)
    if not f.known_good:
        f.known_good = True   # Noise filtering completed
    if not f.known_noise:
        f.known_noise = True  # Noise filtering completed
    
    # Update file_state based on completion
    if f.is_completed:  # This property checks all flags
        f.file_state = 'Completed'
    elif f.failed:
        f.file_state = 'Failed'
    elif f.is_hidden:
        f.file_state = 'Hidden'

db.session.commit()
```

### Re-Index Operation

```python
# Save state and reset all flags
fsm.start_reindex(case_file)
# previous_state = 'Completed' (saved)
# State = 'Reindexing'
# All flags reset to False
db.session.commit()

# Run full pipeline (same as initial upload)
# ...

# Finalize
fsm.finalize_processing(case_file)
case_file.previous_state = None
db.session.commit()
```

### Partial Re-Operation (Re-SIGMA Example)

```python
# Save current state
fsm.start_partial_operation(case_file, 'sigma')
# previous_state = 'Completed' (saved)
# State = 'SIGMA Hunting'
# sigma_hunted = False (only this flag reset)
db.session.commit()

# Run SIGMA only
chainsaw_result = chainsaw_file(...)

# Mark SIGMA complete
fsm.complete_sigma_hunting(case_file)
# State = 'SIGMA Checked'
# sigma_hunted = True

# Restore previous state
fsm.complete_partial_operation(case_file, 'sigma')
# State = 'Completed' (restored from previous_state)
# previous_state = None
db.session.commit()
```

---

## Statistics Queries

### Files with Events

```python
# Count (not hidden, not deleted)
SELECT COUNT(*) FROM case_file
WHERE is_deleted = FALSE AND is_hidden = FALSE;
```

### Completed Files

```python
# Count (uses completion logic)
SELECT COUNT(*) FROM case_file
WHERE is_deleted = FALSE
  AND is_hidden = FALSE
  AND failed = FALSE
  AND event_count > 0
  AND is_indexed = TRUE
  AND ioc_hunted = TRUE
  AND known_good = TRUE
  AND known_noise = TRUE
  AND (original_filename NOT ILIKE '%.evtx' OR sigma_hunted = TRUE);
```

### Failed Files

```python
# Count
SELECT COUNT(*) FROM case_file
WHERE failed = TRUE AND is_deleted = FALSE;
```

### SIGMA Checked

```python
# Count
SELECT COUNT(*) FROM case_file
WHERE sigma_hunted = TRUE AND is_deleted = FALSE;
```

### IOC Checked

```python
# Count
SELECT COUNT(*) FROM case_file
WHERE ioc_hunted = TRUE AND is_deleted = FALSE;
```

### Noise Checked

```python
# Count (both flags must be True)
SELECT COUNT(*) FROM case_file
WHERE known_good = TRUE AND known_noise = TRUE AND is_deleted = FALSE;
```

### Queued Files

```python
# Count (has celery_task_id)
SELECT COUNT(*) FROM case_file
WHERE celery_task_id IS NOT NULL AND is_deleted = FALSE;
```

### Hidden Files

```python
# Count
SELECT COUNT(*) FROM case_file
WHERE is_hidden = TRUE AND is_deleted = FALSE;
```

---

## Migration from v2.1.x to v2.2.0

### Database Migration

Run the migration script:

```bash
cd /opt/casescope
sudo -u postgres psql casescope < migrations/add_file_state_tracking.sql
```

### Migration Logic

The SQL migration attempts to map existing `indexing_status` values to new flags:

1. **Completed files**: Set all flags to `True`, `file_state='Completed'`
2. **Failed files**: Set `failed=True`, `file_state='Failed'`
3. **Indexed files**: Set `is_indexed=True`, `file_state='Indexed'`
4. **Processing files**: Map to appropriate states ('Indexing', 'SIGMA Testing', etc.)
5. **Hidden files**: Set `file_state='Hidden'`
6. **EVTX files**: Set `sigma_hunted=True` if status indicates SIGMA complete

### Backward Compatibility

- `indexing_status` field **remains** for now (deprecated)
- New code uses flags and `file_state`
- Old code continues to work (reads `indexing_status`)
- **No** dual-write needed (no production deployment)

---

## Usage Examples

### Route Example (Failed Files)

```python
@files_bp.route('/case/<int:case_id>/failed_files')
@login_required
def view_failed_files(case_id):
    """View failed files (v2.2.0)"""
    import file_statistics as fstats
    
    # Get failed files using new module
    pagination = fstats.get_failed_files_paginated(
        db.session, CaseFile, 
        case_id=case_id,
        page=page, 
        per_page=50, 
        search_term=search_term
    )
    
    failed_count = fstats.get_failed_files_count(
        db.session, CaseFile, case_id=case_id
    )
    
    return render_template('failed_files.html', ...)
```

### Processing Example (Coordinator)

```python
def process_batch(file_ids):
    """Process a batch of files"""
    import file_state_manager as fsm
    
    for file_id in file_ids:
        case_file = db.session.get(CaseFile, file_id)
        
        # Start operation
        fsm.start_sigma_hunting(case_file)
        db.session.commit()
        
        try:
            # Run processing
            result = chainsaw_file(...)
            
            # Mark complete
            fsm.complete_sigma_hunting(case_file)
            
        except Exception as e:
            # Mark failed
            fsm.mark_failed(case_file, str(e))
        
        db.session.commit()
```

### Statistics Dashboard

```python
def get_dashboard_stats(case_id):
    """Get statistics for dashboard"""
    import file_statistics as fstats
    
    # Get comprehensive stats
    stats = fstats.get_file_statistics(db.session, CaseFile, case_id)
    
    # Get state breakdown
    states = fstats.get_files_by_state(db.session, CaseFile, case_id)
    
    # Get incomplete files
    incomplete = fstats.get_incomplete_files(db.session, CaseFile, case_id)
    
    return {
        'stats': stats,
        'states': states,
        'incomplete_count': len(incomplete),
        'incomplete_files': [f.original_filename for f in incomplete[:10]]
    }
```

---

## Testing

### Manual Testing Checklist

1. **Initial Upload**
   - [ ] Upload new file
   - [ ] Verify `is_new=True`, `file_state='New'`
   - [ ] Wait for indexing
   - [ ] Verify `is_indexed=True`, `file_state='Indexed'`
   - [ ] Wait for SIGMA (EVTX)
   - [ ] Verify `sigma_hunted=True`, `file_state='SIGMA Checked'`
   - [ ] Wait for IOC
   - [ ] Verify `ioc_hunted=True`, `file_state='IOC Checked'`
   - [ ] Verify final state is `Completed` with `is_completed=True`

2. **0 Event Files**
   - [ ] Upload file with 0 events
   - [ ] Verify `is_hidden=True`, `file_state='Hidden'`
   - [ ] Verify NOT counted in completed files

3. **Failed Files**
   - [ ] Cause indexing to fail
   - [ ] Verify `failed=True`, `file_state='Failed'`
   - [ ] Verify shows on failed files page
   - [ ] Verify failed count matches

4. **Re-Operations**
   - [ ] Re-index completed file
   - [ ] Verify all flags reset during reindex
   - [ ] Verify final state is `Completed` again
   - [ ] Re-SIGMA completed file
   - [ ] Verify only `sigma_hunted` flag reset
   - [ ] Verify state restored to `Completed` after

5. **Statistics**
   - [ ] Verify files with events count
   - [ ] Verify completed count uses completion logic
   - [ ] Verify failed count uses `failed` flag
   - [ ] Verify SIGMA/IOC/Noise counts match flags
   - [ ] Verify queued count uses `celery_task_id`

### Debugging

```python
# Get file state summary
import file_state_manager as fsm

case_file = db.session.get(CaseFile, file_id)
summary = fsm.get_state_summary(case_file)
print(summary)

# Output:
# {
#   'file_id': 123,
#   'filename': 'Security.evtx',
#   'file_state': 'Completed',
#   'previous_state': None,
#   'flags': {
#     'is_new': False,
#     'is_indexed': True,
#     'sigma_hunted': True,
#     'ioc_hunted': True,
#     'known_good': True,
#     'known_noise': True,
#     'is_hidden': False,
#     'failed': False
#   },
#   'is_completed': True,
#   'is_queued': False,
#   'event_count': 42536
# }
```

---

## Benefits

### Accuracy
- ✅ Consistent failed file counts across all pages
- ✅ Accurate completion tracking based on file type
- ✅ No ambiguous states

### Reliability
- ✅ Explicit phase tracking with boolean flags
- ✅ State transition validation
- ✅ State persistence for partial operations

### Performance
- ✅ Indexed boolean columns for fast queries
- ✅ No complex string parsing
- ✅ Efficient statistics calculations

### Maintainability
- ✅ Centralized state management (`file_state_manager.py`)
- ✅ Centralized statistics (`file_statistics.py`)
- ✅ Clear separation of concerns
- ✅ Easy to add new phases or states

### Debugging
- ✅ `get_state_summary()` shows all flags at once
- ✅ `previous_state` field for re-operation tracking
- ✅ Clear state names in logs

---

## Future Enhancements

1. **State Machine Visualization**: Add UI to show file processing pipeline
2. **Retry Logic**: Auto-retry failed files with exponential backoff
3. **Phase Dependencies**: Enforce phase order (can't IOC hunt before indexing)
4. **Bulk State Operations**: Change state for multiple files at once
5. **State History**: Track state change history in separate table
6. **Performance Metrics**: Track time spent in each state

---

## Files Modified

### New Files
- `migrations/add_file_state_tracking.sql` - Database migration
- `app/file_state_manager.py` - State transition management
- `app/file_statistics.py` - Statistics queries
- `!important_info/FILE_STATS.MD` - This documentation

### Modified Files
- `app/models.py` - Added new fields and `is_completed` property
- `app/tasks.py` - Updated `process_file()` to use state manager
- `app/routes/files.py` - Updated routes to use new statistics module

### Deprecated (Not Removed Yet)
- `app/hidden_files.py::get_failed_files_count()` - Use `file_statistics.get_failed_files_count()`
- `app/hidden_files.py::get_failed_files()` - Use `file_statistics.get_failed_files_paginated()`
- `CaseFile.indexing_status` - Use `CaseFile.file_state` and flags instead

---

## Support

For questions or issues:
1. Check logs for state transitions: `grep "\[STATE\]" /opt/casescope/logs/app.log`
2. Use `get_state_summary()` to inspect file state
3. Verify database flags match expected values
4. Check `VALID_TRANSITIONS` dict if transition is blocked

---

**End of Documentation**

