# Progress Tracking System for Modular Processing

## Overview

The CaseScope Progress Tracking System provides real-time progress monitoring for long-running operations like reindexing, SIGMA detection, and IOC hunting.

## Architecture

### Components

1. **`progress_tracker.py`** - Core progress tracking module (in-memory storage)
2. **`routes/progress.py`** - Flask API endpoints for progress retrieval
3. **`case_files.html`** - JavaScript modal for displaying progress
4. **Coordinators** - Each coordinator (reindex, resigma, reioc) uses progress tracking

## Backend Usage

### Starting Progress

```python
from progress_tracker import start_progress, update_phase, complete_progress

# Start tracking an operation
start_progress(
    case_id=123, 
    operation='reindex',  # or 'resigma', 'reioc', 'clear_metadata', 'index'
    total_phases=5,
    description='Reindexing all files'
)
```

### Updating Phases

```python
# Update progress for a specific phase
update_phase(
    case_id=123,
    operation='reindex',
    phase_num=1,  # 1-based phase number
    phase_name='Clearing Metadata',
    status='running',  # 'running', 'completed', 'failed', 'skipped'
    message='Clearing 10 files...',
    stats={  # Optional statistics dict
        'cleared': 5,
        'total': 10,
        'events_deleted': 1500
    }
)
```

### Completing Operations

```python
# Mark operation as complete
complete_progress(
    case_id=123,
    operation='reindex',
    success=True,
    error_message=None  # Optional error message if failed
)
```

### Retrieving Progress

```python
from progress_tracker import get_progress

progress = get_progress(case_id=123, operation='reindex')
# Returns dict with: status, current_phase, total_phases, phases[], elapsed_time, error_message
```

## Frontend Usage

### JavaScript Functions

#### Show Progress Modal

```javascript
showProgressModal(
    'reindex',  // operation type
    'Re-Indexing Files',  // modal title
    'Starting reindex...'  // initial message
);
```

#### Poll for Progress

```javascript
pollOperationProgress(
    caseId,  // case ID
    'reindex',  // operation type
    function(success) {  // callback when complete
        if (success) {
            location.reload();
        }
    }
);
```

#### Close Modal

```javascript
closeProgressModal();
```

### Complete Example

```javascript
function startReindex(caseId) {
    // Show modal
    showProgressModal('reindex', 'Re-Indexing Files', 'Starting reindex process...');
    
    // Start backend operation
    fetch(`/case/${caseId}/reindex`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'}
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Start polling for progress
            pollOperationProgress(caseId, 'reindex', function(success) {
                if (success) {
                    location.reload();
                } else {
                    alert('Reindex failed');
                }
            });
        } else {
            closeProgressModal();
            alert('Failed to start reindex');
        }
    });
}
```

## API Endpoint

### GET `/case/<case_id>/progress/<operation>`

Returns current progress for an operation.

**Response:**
```json
{
    "status": "running",  // 'running', 'completed', 'failed', 'not_found'
    "current_phase": 2,
    "total_phases": 5,
    "description": "Reindexing all files",
    "phases": [
        {
            "phase_num": 1,
            "name": "Clearing Metadata",
            "status": "completed",
            "message": "Cleared 10 files",
            "stats": {
                "cleared": 10,
                "events_deleted": 1500
            },
            "start_time": 1234567890.123,
            "end_time": 1234567895.456
        },
        {
            "phase_num": 2,
            "name": "Indexing Files",
            "status": "running",
            "message": "Indexing 5/10 files",
            "stats": {
                "completed": 5,
                "total": 10
            },
            "start_time": 1234567895.500,
            "end_time": null
        }
    ],
    "elapsed_time": 45.3,
    "error_message": null
}
```

## Operation Types

- **`reindex`** - Full reindex of files
- **`resigma`** - Re-run SIGMA detection only
- **`reioc`** - Re-run IOC hunting only
- **`clear_metadata`** - Clear metadata operation
- **`index`** - Initial index of new files

## Phase Status Values

- **`running`** - Phase is currently executing
- **`completed`** - Phase finished successfully
- **`failed`** - Phase encountered an error
- **`skipped`** - Phase was skipped

## Modal UI Features

### Visual Elements

- **Spinner** - Animated spinner for running phases
- **Icons** - Status icons (✅ completed, ❌ failed, ⏳ running, ⏭️ skipped)
- **Progress Bars** - Visual progress indicators
- **Statistics** - Real-time stats (files processed, events indexed, etc.)
- **Elapsed Time** - Live counter showing operation duration

### Statistics Display

The modal automatically formats and displays various statistics:

- `cleared` - Files cleared
- `indexed` - Files indexed
- `processed` - Items processed
- `violations` - SIGMA violations found
- `total_matches` - IOC matches found
- `events_deleted` - Events deleted
- `violations_deleted` - Violations deleted
- `ioc_matches_deleted` - IOC matches deleted
- `completed/total` - Progress fraction

## Implementation in Coordinators

### Example: Reindex Coordinator

```python
from progress_tracker import start_progress, update_phase, complete_progress

def reindex_files(case_id: int, file_ids: Optional[List[int]] = None):
    # Start tracking
    start_progress(case_id, 'reindex', 7, 'Reindexing files')
    
    try:
        # Phase 1: Queue files
        update_phase(case_id, 'reindex', 1, 'Queuing Files', 'running', 'Preparing files...')
        # ... queue logic ...
        update_phase(case_id, 'reindex', 1, 'Queuing Files', 'completed', 
                    f'Queued {total} files', {'files_queued': total})
        
        # Phase 2: Clear metadata
        update_phase(case_id, 'reindex', 2, 'Clearing Metadata', 'running', 'Clearing data...')
        result = clear_all_queued_files(case_id, clear_type='all')
        update_phase(case_id, 'reindex', 2, 'Clearing Metadata', 'completed',
                    f'Cleared {result["cleared"]} files', result)
        
        # ... more phases ...
        
        # Complete successfully
        complete_progress(case_id, 'reindex', success=True)
        
    except Exception as e:
        # Complete with error
        complete_progress(case_id, 'reindex', success=False, error_message=str(e))
        raise
```

## Cleanup

The progress tracker includes automatic cleanup of old entries:

```python
from progress_tracker import clear_old_progress

# Clear entries older than 1 hour (default)
clear_old_progress(max_age_seconds=3600)
```

Consider running this periodically (e.g., via a scheduled task or cron job).

## Notes

- Progress data is stored **in-memory** and will be lost on application restart
- For production, consider using Redis or a database for persistent storage
- The polling interval is 2 seconds by default (configurable in JavaScript)
- Progress entries older than 1 hour are automatically cleaned up
- Multiple operations can be tracked simultaneously for different cases

## Future Enhancements

1. **Persistent Storage** - Move from in-memory to Redis/database
2. **WebSocket Support** - Real-time push updates instead of polling
3. **Progress Estimation** - Add ETA calculations based on historical data
4. **Cancellation Support** - Allow users to cancel long-running operations
5. **Progress History** - Store completed operations for audit trail

