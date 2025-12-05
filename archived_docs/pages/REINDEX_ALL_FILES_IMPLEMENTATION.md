# Re-Index All Files - Implementation Complete

**Version**: 2.0.0  
**Date**: December 4, 2025  
**Status**: ✅ **READY FOR TESTING**

---

## Overview

Completely rewired the "Re-Index All Files" button to use the new modular processing system with live phase updates in the Processing Status tile.

## User Flow

### 1. User Clicks "Re-Index All Files" Button
- Confirmation dialog appears
- User confirms they want to proceed with full rebuild

### 2. Preparation Modal Shows (During Clearing)
- Modal displays: "Clearing metadata and preparing files..."
- This modal stays visible while:
  - Backend queues files
  - Backend clears metadata (OpenSearch + database)
- **Modal auto-closes** ONLY when files actually start processing (not just queued)

### 3. Processing Status Tile Updates
The "Processing Status" section in the File Statistics tile shows live updates:

```
┌─────────────────────────────────────────┐
│ Processing Status                       │
├─────────────────────────────────────────┤
│ 🗑️ Clearing metadata                    │ ← Live phase indicator
├─────────────────────────────────────────┤
│ ✅ Completed: 42      ❌ Failed: 0      │
│ ⏳ Queued: 0          📇 Indexing: 8    │
│ 🛡️ SIGMA: 0           🎯 IOC: 0         │
└─────────────────────────────────────────┘
```

Phase indicators that appear during processing:
- 🗑️ **Clearing metadata** (during phase 1)
- 📇 **Indexing files** (during phase 2)
- 🛡️ **Running SIGMA detection** (during phase 3)
- ✅ **Marking known-good events** (during phase 4)
- 🔇 **Marking known-noise patterns** (during phase 5)
- 🎯 **Running IOC detection** (during phase 6)

### 4. Files Are Reindexed
- All phases run automatically
- User can monitor progress via:
  - Live phase indicator
  - File status counters (updating every 10 seconds)
  - Queue display (updating every 10 seconds)

### 5. Completion
- Phase indicator disappears
- Page refreshes automatically
- All stats updated

---

## Technical Implementation

### Backend Changes

#### 1. `/app/main.py` - Route Handler
**Function**: `bulk_reindex_route(case_id)`

```python
@app.route('/case/<int:case_id>/bulk_reindex', methods=['POST'])
@login_required
def bulk_reindex_route(case_id):
    # Starts coordinator_reindex.reindex_files_task() as Celery task
    # Returns JSON: {'success': True, 'task_id': '...', 'case_id': 123}
```

**Changes**:
- Replaced OLD phased system (ReindexProgress model, manual phase tracking)
- NOW uses `coordinator_reindex.reindex_files_task()` Celery wrapper
- Coordinator handles all phases automatically
- Progress tracking via `progress_tracker.py`

#### 2. `/app/routes/progress.py` - Progress API
**Endpoint**: `GET /case/<case_id>/progress/reindex`

```python
@progress_bp.route('/case/<int:case_id>/progress/<operation>', methods=['GET'])
@login_required
def get_operation_progress(case_id, operation):
    # Returns current phase info from progress_tracker
```

**Returns**:
```json
{
    "status": "running",
    "current_phase": 2,
    "total_phases": 7,
    "phases": [
        {
            "phase_num": 1,
            "name": "Clearing Metadata",
            "status": "completed",
            "message": "Cleared 42 files",
            "stats": {"cleared": 42, "events_deleted": 150000}
        },
        {
            "phase_num": 2,
            "name": "Indexing Files",
            "status": "running",
            "message": "Indexed 20/42 files",
            "stats": {"completed": 20, "total": 42}
        }
    ],
    "elapsed_time": 45.3
}
```

#### 3. Blueprint Registration
Added to `/app/main.py`:
```python
from routes.progress import progress_bp
app.register_blueprint(progress_bp)
```

---

### Frontend Changes

#### 1. Processing Status Tile - Added Phase Indicator
**File**: `/app/templates/case_files.html` (lines 63-67)

```html
<!-- Current Operation Phase (hidden by default) -->
<div id="current-operation-phase" style="display: none; ...">
    <span id="operation-phase-icon">⚙️</span>
    <span id="operation-phase-text">Processing...</span>
</div>
```

#### 2. Re-Index Button Handler
**Function**: `confirmReindex()`

**Flow**:
1. Show confirmation dialog
2. Start backend reindex via POST `/case/{id}/bulk_reindex`
3. Show preparation modal
4. Monitor queue status until files start processing
5. Close preparation modal
6. Start phase monitoring
7. Update Processing Status tile with current phase
8. Auto-refresh page when complete

#### 3. Supporting Functions

**`monitorReindexStart()`**
- Polls `/case/{id}/queue/status` every second
- Detects when files actually start processing (not just queued)
- Closes preparation modal when processing begins
- Max timeout: 2 minutes

**`startPhaseMonitoring()`**
- Polls `/case/{id}/progress/reindex` every 3 seconds
- Updates Processing Status tile with current phase
- Detects completion/failure
- Auto-refreshes page when done

**`updateProcessingStatusPhase(phase)`**
- Maps phase names to icons and text
- Updates the phase indicator banner
- Changes color based on status (running=blue, success=green, error=red)

**`showProcessingStatusPhase(icon, text, status)`**
- Shows the phase indicator banner
- Updates icon and text
- Sets background color

**`hideProcessingStatusPhase()`**
- Hides the phase indicator when operation completes

---

## Phase Mapping

| Phase Name | Icon | Display Text |
|------------|------|--------------|
| Queuing Files | 📋 | Queuing files for reindex |
| Clearing Metadata | 🗑️ | Clearing metadata |
| Indexing Files | 📇 | Indexing files |
| SIGMA Detection | 🛡️ | Running SIGMA detection |
| Known-Good Events | ✅ | Marking known-good events |
| Known-Noise Events | 🔇 | Marking known-noise patterns |
| IOC Detection | 🎯 | Running IOC detection |

---

## Existing Features Preserved

### 1. Live Statistics (Every 10 seconds)
- File status counts (Completed, Failed, Queued, Indexing, SIGMA, IOC)
- Event statistics (Total, SIGMA, IOC)
- Event status breakdown (New, Hunted, Confirmed, Noise)

### 2. Queue Display (Every 10 seconds)
- Shows files currently processing
- Shows files queued (first 30 + count)
- Updates automatically

### 3. Per-File Status Updates
- Smart polling (3s when processing, 10s when idle)
- Updates individual file rows with latest counts

---

## Coordinator Integration

The route calls `coordinator_reindex.reindex_files_task()` which:

1. **Queues all files** (marks as `indexing_status='Queued'`)
2. **Clears metadata** via `processing_clear_metadata.py` (clear_type='all')
3. **Runs full pipeline** via `coordinator_index.py`:
   - Phase 2: Index files (`processing_index.py`)
   - Phase 3: SIGMA detection (`processing_sigma.py`)
   - Phase 4: Known-good events (`events_known_good.py`)
   - Phase 5: Known-noise events (`events_known_noise.py`)
   - Phase 6: IOC detection (`processing_ioc.py`)

All phases update `progress_tracker` which frontend polls via `/case/{id}/progress/reindex`.

---

## Files Modified

### Backend
1. `/app/main.py` - Rewired `bulk_reindex_route()` to use coordinator
2. `/app/main.py` - Registered `progress_bp` blueprint
3. `/app/routes/progress.py` - Created (already existed)
4. `/app/coordinator_reindex.py` - Already existed with proper task wrapper

### Frontend
5. `/app/templates/case_files.html` - Added phase indicator to Processing Status tile
6. `/app/templates/case_files.html` - Rewrote `confirmReindex()` function
7. `/app/templates/case_files.html` - Added `monitorReindexStart()`
8. `/app/templates/case_files.html` - Added `startPhaseMonitoring()`
9. `/app/templates/case_files.html` - Added `updateProcessingStatusPhase()`
10. `/app/templates/case_files.html` - Added `showProcessingStatusPhase()`
11. `/app/templates/case_files.html` - Added `hideProcessingStatusPhase()`

---

## Testing Checklist

### Pre-Test Setup
- [ ] Ensure Celery workers running (`systemctl status casescope-worker`)
- [ ] Ensure OpenSearch running (`systemctl status opensearch`)
- [ ] Ensure PostgreSQL running (`systemctl status postgresql`)
- [ ] Create test case with 5-10 small EVTX files

### Test Flow
1. [ ] Click "Re-Index All Files" button
2. [ ] Verify confirmation dialog appears
3. [ ] Confirm operation
4. [ ] Verify preparation modal appears with "Clearing metadata..." message
5. [ ] Wait 30-60 seconds (metadata clearing)
6. [ ] Verify preparation modal closes automatically when files start processing
7. [ ] Verify Processing Status tile shows phase indicator:
   - [ ] 🗑️ Clearing metadata
   - [ ] 📇 Indexing files
   - [ ] 🛡️ Running SIGMA detection
   - [ ] ✅ Marking known-good events
   - [ ] 🔇 Marking known-noise patterns
   - [ ] 🎯 Running IOC detection
8. [ ] Verify file status counters update every 10 seconds
9. [ ] Verify queue display updates every 10 seconds
10. [ ] Verify phase indicator disappears when complete
11. [ ] Verify page auto-refreshes
12. [ ] Verify all files show "Indexed" status
13. [ ] Verify events searchable
14. [ ] Verify SIGMA violations detected
15. [ ] Verify IOCs matched

### Error Scenarios
- [ ] Test with no files (should show "No files to reindex")
- [ ] Test with archived case (should show error)
- [ ] Test with no Celery workers (should show error)
- [ ] Test canceling confirmation dialog (should do nothing)

---

## Known Limitations

1. **No Cancel Button**: Once started, reindex cannot be cancelled (future enhancement)
2. **No ETA**: Phase indicator doesn't show estimated completion time (future enhancement)
3. **No Progress Bars**: Shows phase but not % complete within phase (future enhancement)

---

## Future Enhancements

1. **Add Cancel Button** - Allow user to abort reindex mid-process
2. **Add Progress Bars** - Show % complete for each phase
3. **Add ETA** - Calculate and display estimated time remaining
4. **Add Notifications** - Browser notification when complete
5. **Add History** - Track reindex history with start/end times
6. **Add Retry Logic** - Auto-retry failed files

---

## Backward Compatibility

- ✅ Old route still exists at same URL
- ✅ Non-JSON requests still redirect (backward compatible)
- ✅ Audit logging preserved
- ✅ Archive guard preserved
- ✅ Worker availability check preserved

---

## Next Steps

1. **Wire up other reindex buttons**:
   - Re-Index Selected Files
   - Re-Index Single File
2. **Wire up re-SIGMA buttons**
3. **Wire up re-IOC buttons**
4. **Test with real data**

---

## Conclusion

The "Re-Index All Files" button is now fully integrated with the new modular processing system. Users get:
- Real-time feedback during clearing phase (preparation modal)
- Live phase updates in the Processing Status tile
- Automatic page refresh on completion
- Seamless experience with existing statistics and queue displays

**Status**: ✅ Ready for testing!

