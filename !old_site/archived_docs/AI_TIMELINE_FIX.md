# AI Timeline Fix - November 18, 2025

## Problem
The AI Timeline feature was not working because the required database table `case_timeline` was missing from the database.

## Root Cause
The migration script `migrations/add_case_timeline.py` had not been run to create the `case_timeline` table, which is required for the AI Timeline feature introduced in v1.16.3.

## Solution Applied

### 1. Created Database Table
Created a standalone migration script that doesn't require loading the full Flask application (to avoid permission issues with log files):
- File: `/opt/casescope/app/migrations/run_case_timeline_migration.py`
- Successfully created the `case_timeline` table with all required columns:
  - id, case_id, generated_by, status, model_name
  - celery_task_id, timeline_title, timeline_content, timeline_json
  - prompt_sent, raw_response, generation_time_seconds, version
  - event_count, ioc_count, system_count
  - progress_percent, progress_message, error_message
  - created_at, updated_at
- Created necessary indices for performance

### 2. Restarted Services
Restarted both services to load the new database table:
```bash
sudo systemctl restart casescope.service
sudo systemctl restart casescope-worker.service
```

### 3. Verified Fix
- ✅ Table `case_timeline` exists in database
- ✅ CaseScope application service running
- ✅ Celery worker service running
- ✅ Task `tasks.generate_case_timeline` registered in Celery
- ✅ Timeline routes accessible (`/case/<id>/timeline/status`, etc.)

## How to Use AI Timeline

1. Navigate to a case in CaseScope
2. Click the "📅 AI Case Timeline" button
3. Confirm the generation (takes 3-5 minutes)
4. The timeline will analyze:
   - All events in the case
   - Active IOCs (Indicators of Compromise)
   - All systems involved
   - SIGMA rule violations
5. Once complete, view the chronological timeline with:
   - Timeline summary (first/last events, time span)
   - Chronological event timeline
   - Attack progression analysis
   - IOC timeline matrix
   - System activity timeline

## Technical Details

### Model Used
- Default: `dfir-qwen:latest` (Qwen model optimized for DFIR timeline analysis)
- Configurable via system settings: `ai_timeline_model`

### Requirements
- AI features enabled in System Settings
- Ollama service running
- Timeline model pulled in Ollama
- Sufficient events/IOCs in case for meaningful analysis

### Celery Task
- Task name: `tasks.generate_case_timeline`
- Concurrency: 8 workers
- Status tracking: Real-time progress updates via database
- Cancellable: Can be cancelled during generation

## Files Modified/Created
1. `/opt/casescope/app/migrations/run_case_timeline_migration.py` (NEW)

## Files Already Present (Working)
- `/opt/casescope/app/routes/timeline.py` - Timeline routes
- `/opt/casescope/app/tasks.py` - Contains `generate_case_timeline` task
- `/opt/casescope/app/ai_report.py` - Contains `generate_timeline_prompt` function
- `/opt/casescope/app/models.py` - Contains `CaseTimeline` model
- `/opt/casescope/app/templates/view_timeline.html` - Timeline viewer template
- Frontend JavaScript in case view templates

## Status
✅ **FIXED** - AI Timeline feature is now fully operational

