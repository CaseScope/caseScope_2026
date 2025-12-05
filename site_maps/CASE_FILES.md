# Case Files Page - Site Map & Dependency Documentation

**Page:** `/case/<case_id>/files` (Case Files Dashboard)  
**Version:** 2.1.4  
**Last Updated:** 2025-12-05

---

## Overview

The Case Files page is the central hub for managing file processing, monitoring queue status, and viewing file/event statistics. This document maps all files, dependencies, and call chains required for each feature on this page.

---

## Table of Contents

1. [Main Page Files](#main-page-files)
2. [Button Actions & Dependencies](#button-actions--dependencies)
3. [Auto-Refresh & Stats](#auto-refresh--stats)
4. [Database Models](#database-models)
5. [Shared Utilities](#shared-utilities)
6. [Complete File Dependency Tree](#complete-file-dependency-tree)

---

## Main Page Files

### Primary Template
- **File:** `app/templates/case_files.html`
- **Purpose:** Main dashboard UI with buttons, stats tiles, file table, and modals
- **Extends:** `app/templates/base.html`
- **JavaScript:** Embedded (handles button clicks, auto-refresh, progress monitoring)
- **CSS:** Uses `app/static/css/theme.css` for centralized button styles

### Backend Route Handler
- **File:** `app/routes/files.py`
- **Route:** `@files_bp.route('/case/<int:case_id>/files')`
- **Function:** `case_files_route(case_id)`
- **Purpose:** Renders template with initial stats and file list
- **Returns:** Rendered `case_files.html` with context data

---

## Button Actions & Dependencies

### 1. 🧹 Queue Cleanup Button

**Flow:**
```
case_files.html (showQueueCleanupWarning)
  ↓ [Modal Confirmation]
  ↓ (executeQueueCleanup)
  ↓ [POST /case/<case_id>/queue/cleanup]
  ↓
routes/files.py (queue_cleanup_case)
  ↓
diagnostics_queue_cleanup.py (cleanup_all_queues)
  ├─→ models.py (CaseFile)
  ├─→ progress_tracker.py (get_progress_key, get_operation_key, get_phase_key)
  ├─→ main.py (db, opensearch_client)
  └─→ celery.task.control (revoke)
```

**Files Required:**
- `app/templates/case_files.html` (UI + JavaScript)
- `app/routes/files.py` (endpoint)
- `app/diagnostics_queue_cleanup.py` (cleanup logic)
- `app/models.py` (CaseFile model)
- `app/progress_tracker.py` (Redis keys)
- `app/main.py` (db, OpenSearch client)
- `app/celery_app.py` (Celery task control)

---

### 2. 🔄 Re-queue Failed Button

**Flow:**
```
case_files.html (requeueFailedFiles)
  ↓ [POST /case/<case_id>/requeue-failed]
  ↓
routes/files.py (requeue_failed_files)
  ├─→ models.py (CaseFile)
  └─→ tasks.py (commit_with_retry)
```

**Files Required:**
- `app/templates/case_files.html`
- `app/routes/files.py`
- `app/models.py`
- `app/tasks.py`

---

### 3. 🔄 Re-Index All Files Button

**Flow:**
```
case_files.html (confirmReindex)
  ↓ [Confirmation Dialog]
  ↓ [POST /case/<case_id>/bulk-reindex]
  ↓
main.py (bulk_reindex_route)
  ↓ [Background Thread]
  ↓
coordinator_reindex.py (reindex_files)
  ├─→ PHASE 1: Clear Metadata
  │   ├─→ processing_clear_metadata.py (bulk_clear_case OR clear_queued_files)
  │   │   ├─→ celery_app.py (clear_file_task workers)
  │   │   ├─→ models.py (CaseFile, SigmaViolation, IOCMatch, TimelineTag, EventStatus)
  │   │   ├─→ main.py (opensearch_client, db)
  │   │   ├─→ utils.py (make_index_name)
  │   │   └─→ tasks.py (commit_with_retry)
  │   └─→ progress_tracker.py (update_phase)
  │
  ├─→ PHASE 2-6: Run Standard Indexing Workflow
  │   └─→ coordinator_index.py (index_new_files)
  │       │
  │       ├─→ PHASE 1: Index Files
  │       │   ├─→ processing_index.py (index_queued_files)
  │       │   │   ├─→ celery_app.py (index_file_task workers)
  │       │   │   ├─→ file_processing.py (index_one_file)
  │       │   │   │   ├─→ file_processing.py (index_evtx_json, index_edr_csv, etc.)
  │       │   │   │   ├─→ event_descriptions.py (get_event_description)
  │       │   │   │   ├─→ main.py (opensearch_client)
  │       │   │   │   ├─→ models.py (CaseFile, Case)
  │       │   │   │   ├─→ utils.py (make_index_name)
  │       │   │   │   └─→ tasks.py (commit_with_retry)
  │       │   │   └─→ Database polling (checks indexing_status)
  │       │   └─→ progress_tracker.py (update_phase)
  │       │
  │       ├─→ PHASE 2: SIGMA Detection
  │       │   ├─→ processing_sigma.py (detect_sigma_all_files)
  │       │   │   ├─→ celery_app.py (detect_sigma_file_task workers)
  │       │   │   ├─→ sigma_detection.py (detect_sigma_violations)
  │       │   │   │   ├─→ main.py (opensearch_client)
  │       │   │   │   ├─→ models.py (SigmaViolation, SigmaRule, CaseFile)
  │       │   │   │   ├─→ sigma.collection.Collection (sigma library)
  │       │   │   │   └─→ tasks.py (commit_with_retry)
  │       │   │   └─→ Database polling (checks indexing_status)
  │       │   └─→ progress_tracker.py (update_phase)
  │       │
  │       ├─→ PHASE 3: Known-Good Filter (Parallel)
  │       │   ├─→ events_known_good.py (hide_known_good_all_task)
  │       │   │   ├─→ celery_app.py (hide_known_good_slice_task workers - 8 parallel)
  │       │   │   │   ├─→ events_known_good.py (process_slice)
  │       │   │   │   │   ├─→ main.py (opensearch_client)
  │       │   │   │   │   ├─→ events_known_good.py (get_cached_exclusions, match_exclusion)
  │       │   │   │   │   └─→ models.py (ExclusionPattern)
  │       │   │   │   ├─→ events_known_good.py (bulk_hide_events)
  │       │   │   │   │   ├─→ main.py (opensearch_client)
  │       │   │   │   │   ├─→ models.py (CaseFile)
  │       │   │   │   │   └─→ tasks.py (commit_with_retry)
  │       │   │   │   └─→ progress_tracker.py (update_task_progress)
  │       │   │   └─→ Celery group polling (waits for all 8 slices)
  │       │   └─→ progress_tracker.py (update_phase_progress_from_task)
  │       │
  │       ├─→ PHASE 4: Known-Noise Filter (Parallel)
  │       │   ├─→ events_known_noise.py (hide_noise_all_task)
  │       │   │   ├─→ celery_app.py (hide_noise_slice_task workers - 8 parallel)
  │       │   │   │   ├─→ events_known_noise.py (process_slice)
  │       │   │   │   │   ├─→ main.py (opensearch_client)
  │       │   │   │   │   └─→ events_known_noise.py (is_firewall_noise, is_noise_process, is_noise_command)
  │       │   │   │   ├─→ events_known_noise.py (bulk_hide_events)
  │       │   │   │   │   ├─→ main.py (opensearch_client)
  │       │   │   │   │   ├─→ models.py (CaseFile)
  │       │   │   │   │   └─→ tasks.py (commit_with_retry)
  │       │   │   │   └─→ progress_tracker.py (update_task_progress)
  │       │   │   └─→ Celery group polling (waits for all 8 slices)
  │       │   └─→ progress_tracker.py (update_phase_progress_from_task)
  │       │
  │       ├─→ PHASE 5: IOC Matching
  │       │   ├─→ processing_ioc.py (hunt_iocs_all_files)
  │       │   │   ├─→ celery_app.py (hunt_iocs_file_task workers)
  │       │   │   ├─→ file_processing.py (hunt_iocs)
  │       │   │   │   ├─→ main.py (opensearch_client)
  │       │   │   │   ├─→ models.py (IOC, IOCMatch, CaseFile)
  │       │   │   │   ├─→ utils.py (make_index_name)
  │       │   │   │   └─→ tasks.py (commit_with_retry)
  │       │   │   └─→ Database polling (checks indexing_status)
  │       │   └─→ progress_tracker.py (update_phase)
  │       │
  │       └─→ FINALIZE: Mark files as completed
  │           ├─→ models.py (CaseFile)
  │           ├─→ tasks.py (commit_with_retry)
  │           └─→ progress_tracker.py (complete_progress)
  │
  └─→ progress_tracker.py (start_progress, update_phase, complete_progress)
```

**Files Required:**
- `app/templates/case_files.html`
- `app/main.py` (bulk_reindex_route, opensearch_client, db)
- `app/coordinator_reindex.py`
- `app/coordinator_index.py`
- `app/processing_clear_metadata.py`
- `app/processing_index.py`
- `app/processing_sigma.py`
- `app/processing_ioc.py`
- `app/events_known_good.py`
- `app/events_known_noise.py`
- `app/file_processing.py` (index_one_file, hunt_iocs)
- `app/sigma_detection.py`
- `app/event_descriptions.py`
- `app/models.py` (CaseFile, Case, SigmaViolation, SigmaRule, IOCMatch, IOC, TimelineTag, EventStatus, ExclusionPattern)
- `app/progress_tracker.py`
- `app/celery_app.py`
- `app/tasks.py` (commit_with_retry)
- `app/utils.py` (make_index_name)

---

### 4. 🛡️ Re-SIGMA All Files Button

**Flow:**
```
case_files.html (confirmReSigma)
  ↓ [Confirmation Dialog]
  ↓ [POST /case/<case_id>/bulk-resigma]
  ↓
main.py (bulk_resigma_route)
  ↓ [Background Thread]
  ↓
coordinator_resigma.py (resigma_files)
  ├─→ processing_clear_metadata.py (clear_queued_files with clear_type='sigma')
  │   └─→ [Same dependencies as Phase 1 above]
  ├─→ processing_sigma.py (detect_sigma_all_files)
  │   └─→ [Same dependencies as SIGMA phase above]
  └─→ progress_tracker.py (start_progress, update_phase, complete_progress)
```

**Files Required:**
- `app/templates/case_files.html`
- `app/main.py`
- `app/coordinator_resigma.py`
- `app/processing_clear_metadata.py`
- `app/processing_sigma.py`
- `app/sigma_detection.py`
- `app/models.py`
- `app/progress_tracker.py`
- `app/celery_app.py`
- `app/tasks.py`
- `app/utils.py`

---

### 5. 🎯 Re-Hunt IOCs Button

**Flow:**
```
case_files.html (confirmReHunt)
  ↓ [Confirmation Dialog]
  ↓ [POST /case/<case_id>/bulk-rehunt]
  ↓
tasks.py (bulk_rehunt - Celery task)
  ├─→ processing_clear_metadata.py (clear_queued_files with clear_type='ioc')
  │   └─→ [Same dependencies as Phase 1 above]
  ├─→ processing_ioc.py (hunt_iocs_all_files)
  │   └─→ [Same dependencies as IOC phase above]
  └─→ progress_tracker.py (start_progress, update_phase, complete_progress)
```

**Files Required:**
- `app/templates/case_files.html`
- `app/tasks.py` (bulk_rehunt task)
- `app/processing_clear_metadata.py`
- `app/processing_ioc.py`
- `app/file_processing.py` (hunt_iocs)
- `app/models.py`
- `app/progress_tracker.py`
- `app/celery_app.py`
- `app/utils.py`

---

### 6. 🔁 Refresh Event Descriptions Button

**Flow:**
```
case_files.html (confirmRefreshDescriptions)
  ↓ [Confirmation Dialog]
  ↓ [POST /case/<case_id>/refresh-descriptions]
  ↓
routes/files.py (refresh_descriptions_route)
  ↓
tasks.py (refresh_event_descriptions_task - Celery task)
  ├─→ main.py (opensearch_client)
  ├─→ event_descriptions.py (get_event_description)
  ├─→ models.py (CaseFile)
  └─→ utils.py (make_index_name)
```

**Files Required:**
- `app/templates/case_files.html`
- `app/routes/files.py`
- `app/tasks.py` (refresh_event_descriptions_task)
- `app/event_descriptions.py`
- `app/main.py`
- `app/models.py`
- `app/utils.py`
- `app/celery_app.py`

---

### 7. 🗑️ Delete Case Files Button (Admin Only)

**Flow:**
```
case_files.html (confirmDeleteAll)
  ↓ [Confirmation Dialog]
  ↓ [POST /case/<case_id>/delete-all-files]
  ↓
routes/files.py (delete_all_files_route)
  ├─→ main.py (opensearch_client)
  ├─→ models.py (CaseFile, SigmaViolation, IOCMatch, TimelineTag, EventStatus, Case)
  ├─→ utils.py (make_index_name)
  └─→ tasks.py (commit_with_retry)
```

**Files Required:**
- `app/templates/case_files.html`
- `app/routes/files.py`
- `app/main.py`
- `app/models.py`
- `app/utils.py`
- `app/tasks.py`

---

### 8. 🛡️ Hide Known Good Button

**Flow:**
```
case_files.html (showHideKnownGoodModal)
  ↓ [Modal with options]
  ↓ (executeHideKnownGood)
  ↓ [POST /case/<case_id>/hide-known-good]
  ↓
routes/files.py (hide_known_good_route)
  ↓
events_known_good.py (hide_known_good_events)
  ├─→ events_known_good.py (get_cached_exclusions, process_events_batch)
  │   ├─→ models.py (ExclusionPattern)
  │   └─→ events_known_good.py (match_exclusion)
  ├─→ events_known_good.py (bulk_hide_events)
  │   ├─→ main.py (opensearch_client)
  │   ├─→ models.py (CaseFile)
  │   └─→ tasks.py (commit_with_retry)
  └─→ main.py (opensearch_client)
```

**Files Required:**
- `app/templates/case_files.html`
- `app/routes/files.py`
- `app/events_known_good.py`
- `app/main.py`
- `app/models.py`
- `app/tasks.py`

---

### 9. 🔇 Hide Known Noise Button

**Flow:**
```
case_files.html (showHideNoiseModal)
  ↓ [Modal confirmation]
  ↓ (executeHideNoise)
  ↓ [POST /case/<case_id>/hide-noise]
  ↓
routes/files.py (hide_noise_route)
  ↓
events_known_noise.py (hide_noise_events)
  ├─→ events_known_noise.py (is_firewall_noise, is_noise_process, is_noise_command)
  ├─→ events_known_noise.py (bulk_hide_events)
  │   ├─→ main.py (opensearch_client)
  │   ├─→ models.py (CaseFile)
  │   └─→ tasks.py (commit_with_retry)
  └─→ main.py (opensearch_client)
```

**Files Required:**
- `app/templates/case_files.html`
- `app/routes/files.py`
- `app/events_known_noise.py`
- `app/main.py`
- `app/models.py`
- `app/tasks.py`

---

## Auto-Refresh & Stats

### File Stats Auto-Refresh (Every 10 seconds)

**Flow:**
```
case_files.html (refreshFileStats - JavaScript)
  ↓ [GET /case/<case_id>/file-stats]
  ↓
routes/files.py (file_stats_case)
  ├─→ models.py (CaseFile, Case)
  ├─→ event_status.py (get_status_counts)
  └─→ Returns JSON with stats
```

**Files Required:**
- `app/templates/case_files.html` (JavaScript)
- `app/routes/files.py`
- `app/models.py`
- `app/event_status.py`
- `app/main.py` (db)

**Stats Returned:**
- `completed` - Files with status 'SIGMA Complete', 'IOC Complete', or 'Completed'
- `failed` - Files with status like 'Failed%'
- `indexed` - Files with status 'Indexed'
- `sigma_checked` - Files with status 'SIGMA Complete'
- `ioc_checked` - Files with status 'IOC Complete'
- `queued` - Files with status in 'Queued', 'Indexing', 'SIGMA Testing', 'IOC Hunting'
- `total_events` - Sum of event_count from visible files
- `sigma_events` - Sum of violation_count from visible files
- `ioc_events` - Sum of ioc_event_count from visible files
- `status_counts` - Breakdown by event status (new, hunted, confirmed, noise)
- `files_with_events` - Total files - Hidden files (v2.1.4)
- `hidden_files` - Count of files with is_hidden=True (v2.1.4)
- `total_files_all` - All files including hidden (v2.1.4)

---

### Progress Monitoring (Real-time)

**Flow:**
```
case_files.html (startPhaseMonitoring - JavaScript)
  ↓ [Polls every 2 seconds]
  ↓ [GET /case/<case_id>/progress/reindex]
  ↓
routes/progress.py (get_reindex_progress)
  ├─→ progress_tracker.py (get_progress)
  └─→ Redis (casescope:progress:<case_id>:reindex)
```

**Files Required:**
- `app/templates/case_files.html` (JavaScript)
- `app/routes/progress.py`
- `app/progress_tracker.py`
- Redis (data store)

---

### Auto-Resume Progress on Page Load (v2.0.2)

**Flow:**
```
case_files.html (checkForOngoingOperations - JavaScript)
  ↓ [DOMContentLoaded event]
  ↓ [GET /case/<case_id>/progress/reindex]
  ↓
routes/progress.py (get_reindex_progress)
  ├─→ progress_tracker.py (get_progress)
  └─→ If status='running', calls startPhaseMonitoring()
```

**Files Required:**
- `app/templates/case_files.html` (JavaScript)
- `app/routes/progress.py`
- `app/progress_tracker.py`

---

## Database Models

All models are defined in `app/models.py`:

### Core Models
- **Case** - Case metadata
- **CaseFile** - File records with processing status
  - `indexing_status` - Current processing state
  - `is_indexed` - Boolean flag
  - `is_hidden` - Boolean flag (auto-hide 0-event files)
  - `is_deleted` - Soft delete flag
  - `event_count` - Total events in file
  - `violation_count` - SIGMA violations count
  - `ioc_event_count` - IOC matches count
  - `celery_task_id` - Associated Celery task

### Detection Models
- **SigmaRule** - SIGMA detection rules
- **SigmaViolation** - SIGMA detection results
- **IOC** - Indicators of Compromise
- **IOCMatch** - IOC detection results

### Event Models
- **EventStatus** - Event classification (hunted, confirmed, noise)
- **TimelineTag** - Timeline event tags
- **ExclusionPattern** - Known-good exclusion rules

---

## Shared Utilities

### Core Utilities (`app/utils.py`)
- `make_index_name(case_id)` - Generate OpenSearch index name

### Database Utilities (`app/tasks.py`)
- `commit_with_retry()` - Retry-safe database commits

### Progress Tracking (`app/progress_tracker.py`)
- `start_progress(case_id, operation_type, phases)` - Initialize Redis tracking
- `update_phase(case_id, operation_type, phase_num, phase_name, status, message, current_count, total_count)` - Update phase status
- `complete_progress(case_id, operation_type, success)` - Finalize progress tracking
- `get_progress(case_id, operation_type)` - Retrieve current progress from Redis

### Event Status (`app/event_status.py`)
- `get_status_counts(case_id)` - Get event status breakdown from database

### Event Descriptions (`app/event_descriptions.py`)
- `get_event_description(event_id, channel, provider)` - Get human-readable event description

---

## Complete File Dependency Tree

### Minimum Required Files for Page Load
```
app/templates/case_files.html
  ├─→ app/templates/base.html
  ├─→ app/static/css/theme.css
  └─→ app/routes/files.py (case_files_route)
      ├─→ app/models.py (Case, CaseFile)
      ├─→ app/main.py (db)
      └─→ app/utils.py (make_index_name)
```

### Full Runtime Dependencies (All Features)
```
Frontend:
  - app/templates/case_files.html
  - app/templates/base.html
  - app/static/css/theme.css

Backend Routes:
  - app/routes/files.py (main file operations)
  - app/routes/progress.py (progress monitoring)
  - app/main.py (app initialization, bulk operations)

Coordinators (Orchestration):
  - app/coordinator_reindex.py
  - app/coordinator_index.py
  - app/coordinator_resigma.py
  - app/coordinator_ioc.py (if used)

Processing Modules:
  - app/processing_clear_metadata.py
  - app/processing_index.py
  - app/processing_sigma.py
  - app/processing_ioc.py

Event Filtering:
  - app/events_known_good.py
  - app/events_known_noise.py

Core Processing:
  - app/file_processing.py (index_one_file, hunt_iocs)
  - app/sigma_detection.py
  - app/event_descriptions.py
  - app/event_status.py

Diagnostics:
  - app/diagnostics_queue_cleanup.py

Database:
  - app/models.py (all models)
  - app/tasks.py (commit_with_retry)

Utilities:
  - app/utils.py (make_index_name, etc.)
  - app/progress_tracker.py (Redis tracking)

Celery:
  - app/celery_app.py (task registration)
  - app/config.py (configuration)

External Dependencies:
  - Redis (progress tracking)
  - OpenSearch (event storage)
  - PostgreSQL (metadata storage)
  - Celery Workers (background processing)
```

---

## Key Design Patterns

### 1. **Modular Processing Architecture (v2.0.0)**
- Each phase (Clear, Index, SIGMA, Known-Good, Known-Noise, IOC) is a separate module
- Coordinators orchestrate phase sequencing
- Celery tasks handle parallelization within phases

### 2. **Database Polling (v2.0.0)**
- Coordinators poll `CaseFile.indexing_status` instead of blocking on `result.get()`
- Prevents Celery deadlocks in Gunicorn workers
- Allows for graceful failure recovery

### 3. **Real-time Progress Tracking (v2.0.1)**
- Redis stores progress data with phase-level granularity
- Frontend JavaScript polls every 2 seconds
- Auto-resume on page reload (v2.0.2)

### 4. **Centralized CSS Button Styles (v2.1.2)**
- All buttons use `btn-primary`, `btn-success`, `btn-warning`, `btn-danger` classes
- Defined in `app/static/css/theme.css`
- No inline styles for easy maintenance

### 5. **Dynamic File Counters (v2.1.4)**
- "Files with Events" = Total Files - Hidden Files
- Updates in real-time during processing
- Hidden files (0 events) auto-filtered via `is_hidden` flag

---

## Version History

- **v2.1.4** - Dynamic "Files with Events" counter, renamed from "Total Files"
- **v2.1.3** - Button brightness reduction (30% darker backgrounds)
- **v2.1.2** - Centralized CSS button styles
- **v2.1.1** - Fixed progress bar not clearing after completion, registered events_known_* tasks
- **v2.1.0** - Parallel Known-Good/Noise processing (8 workers)
- **v2.0.7** - Emergency Queue Cleanup diagnostics module
- **v2.0.6** - Processing Status note (Stats do not include hidden files)
- **v2.0.5** - New Processing Status tile layout (distinct counts)
- **v2.0.4** - Fixed Known-Good/Noise import errors
- **v2.0.3** - Reverted IOC to per-file processing
- **v2.0.2** - Auto-resume progress monitoring on page reload
- **v2.0.1** - Real-time progress bars with percentages
- **v2.0.0** - Modular processing system with database polling

---

## Notes for Developers

1. **Adding New Buttons:**
   - Add HTML in `case_files.html`
   - Use CSS classes from `theme.css` (btn-primary, btn-success, btn-warning, btn-danger)
   - Create endpoint in `routes/files.py` or `main.py`
   - Add confirmation dialog if destructive

2. **Modifying Processing Workflow:**
   - Edit coordinator files for phase sequencing
   - Edit processing modules for phase logic
   - Update `progress_tracker.py` calls for UI feedback
   - Test database polling behavior

3. **Adding New Stats:**
   - Add query in `routes/files.py` → `file_stats_case()`
   - Add field to JSON response
   - Add HTML element in `case_files.html` with unique ID
   - Add JavaScript refresh in `refreshFileStats()`

4. **Testing:**
   - Test with small datasets first
   - Monitor Redis keys: `redis-cli KEYS "casescope:*"`
   - Check Celery worker logs: `sudo journalctl -u casescope-worker -f`
   - Check Gunicorn logs: `sudo journalctl -u casescope -f`

---

**End of Case Files Site Map**

