# Archived Old Processing Files

This directory contains old/deprecated files from the pre-v2.2.x processing system.

## Date Archived
December 5, 2025

## Reason for Archival
These files were replaced by the new modular coordinator system (v2.1.0+):
- `coordinator_index.py` - New file indexing coordinator
- `coordinator_reindex.py` - New reindex coordinator
- `coordinator_resigma.py` - New Re-SIGMA coordinator
- `coordinator_ioc.py` - New Re-IOC coordinator
- `processing_*.py` - Modular processing modules
- `progress_tracker.py` - Redis-backed progress tracking

## Archived Files

### Python Modules

#### `reindex_coordinator.py` (v1.46.0)
- **Original Purpose:** Orchestrated 4-phase reindex pipeline
- **Replaced By:** `coordinator_reindex.py` (v2.1.0+)
- **Issues:** 
  - Used custom progress tracking (not Redis-based)
  - Tightly coupled phases
  - No parallel Known-Good/Noise processing

#### `phase_coordinator.py` (v2.0.0)
- **Original Purpose:** Sequential phase execution for all processing
- **Replaced By:** Modular coordinators (`coordinator_*.py`)
- **Issues:**
  - Monolithic design
  - Single-threaded Known-Good/Noise
  - No progress bar integration

#### `test_modular_processing.py`
- **Original Purpose:** Test suite for old phase_coordinator
- **Replaced By:** N/A (testing now done via live operations)
- **Status:** Depends on archived `phase_coordinator.py`

### Documentation Files

#### `REINDEX_ALL_FILES_IMPLEMENTATION.md`
- Implementation plan for old reindex system

#### `Reindex_Bug_Analysis_and_Fix.md`
- Bug fixes for v1.46.0 reindex system

#### `REINDEX_CODE_REVIEW_AND_FIXES.md`
- Code review of old reindex system

#### `REINDEX_MODAL_FIX_DOCUMENTATION (1).md`
- UI modal fixes for old reindex

#### `REINDEX_MODAL_IMPROVEMENT_v1.19.6.md`
- UI improvements for old reindex system

#### `MODULAR_PROCESSING_SYSTEM_V2.md`
- Design doc for v2.0.0 processing (before v2.1.0 coordinators)

#### `COORDINATOR_PROCESSING_FIX.md`
- Comprehensive fix documentation for coordinator system bugs

## Tasks Still in `tasks.py` (Not Removed Yet)

The following old Celery tasks remain in `app/tasks.py` but are **NO LONGER CALLED**:

### Lines 547-582: `tasks.bulk_rechainsaw`
- **Status:** DEPRECATED - replaced by `coordinator_resigma.resigma_files_task`
- **Last Used:** v2.1.6
- **Can Be Removed:** Yes (no active references)

### Lines 585-623: `tasks.bulk_rehunt`
- **Status:** DEPRECATED - replaced by `coordinator_ioc.reioc_files_task`
- **Last Used:** v2.1.6
- **Can Be Removed:** Yes (no active references)

### Lines 4727-4891: `reindex_phase_monitor_task`
- **Status:** DEPRECATED - replaced by `progress_tracker.py` Redis polling
- **Last Used:** v1.46.0
- **Can Be Removed:** Yes (no active references)

### Lines 5098-5118: `reindex_coordinator_task_OLD`
- **Status:** DEPRECATED - replaced by `coordinator_reindex.reindex_files_task`
- **Last Used:** v1.46.0
- **Can Be Removed:** Yes (no active references)

### Lines 5121-5301: `phase1_index_and_sigma_task`, `phase2_sigma_only_task`, etc.
- **Status:** DEPRECATED - replaced by modular `processing_*.py` tasks
- **Last Used:** v1.46.0
- **Can Be Removed:** Yes (no active references)

## Current Active System (v2.2.x)

### Active Coordinators
- `coordinator_index.py` - New file indexing (5 phases)
- `coordinator_reindex.py` - Full reindex (7 phases including clear)
- `coordinator_resigma.py` - Re-SIGMA detection (3 phases)
- `coordinator_ioc.py` - Re-IOC matching (3 phases)

### Active Processing Modules
- `processing_index.py` - EVTX indexing to OpenSearch
- `processing_sigma.py` - SIGMA rule detection
- `processing_clear_metadata.py` - Clear old data before re-processing
- `processing_ioc.py` - IOC matching
- `events_known_good.py` - Known-good event filtering (parallel)
- `events_known_noise.py` - Known-noise event filtering (parallel)

### Active Progress System
- `progress_tracker.py` - Redis-backed real-time progress tracking
- UI: `case_files.html` - Progress bar with phase detection

## Migration Path

If you need to reference old behavior:
1. Check this archive for the original implementations
2. Current system documentation is in `/opt/casescope/site_documentation/`
3. Key docs:
   - `FILE_INDEXING_PIPELINE.MD` - Current v2.1.x pipeline
   - `EVENTS_KNOWN_GOOD.md` - Parallel Known-Good system
   - `EVENTS_KNOWN_NOISE.md` - Parallel Known-Noise system
   - `FIX_REPEATING_ISSUES.md` - Common bugs and solutions

## Next Cleanup Steps

1. **Remove old tasks from `tasks.py`:**
   - Delete lines 547-623 (bulk_rechainsaw, bulk_rehunt)
   - Delete lines 4723-5301 (all v1.46.0 reindex tasks)
   
2. **Remove old bulk_operations functions:**
   - Review `bulk_operations.py` for any LEGACY sections (line 831+)
   - Extract and archive if no longer used

3. **Update version.json:**
   - Document removal of legacy code in release notes

## Historical Context

### Version Timeline
- **v1.15.0:** Unified bulk operations introduced
- **v1.46.0:** Phased reindex pipeline with monitor tasks
- **v2.0.0:** Modular processing system (phase_coordinator)
- **v2.1.0:** Parallel Known-Good/Noise coordinators
- **v2.1.6:** Re-SIGMA/Re-IOC wired to new coordinators
- **v2.2.x:** Progress bar fixes, all coordinators stabilized

### Key Issues Resolved
- Circular import deadlocks (v2.2.2)
- Celery `.get()` deadlocks (v2.2.4)
- Progress bar phase matching (v2.2.x)
- Stale object finalization bugs (v2.1.9)

