# Archive: 2025-12-17

This directory contains temporary and diagnostic files that were archived on December 17, 2025.

## Archived Files

### Test/Dry Run Scripts
- `dry_run_case25.py` - Test script for AI Triage search on Case 25
- `dry_run_case25_full.py` - Extended test script for Case 25
- `dry_run_case25_complete.py` - Complete test script for Case 25

### One-Time Migration Scripts
- `sync_noise_to_db.py` - One-time script to sync noise events from OpenSearch to PostgreSQL (fixed missing EventStatus records)

### Diagnostic/Analysis Documents
- `DIAGNOSTIC_RESULTS.md` - Re-SIGMA diagnostic results from troubleshooting
- `DOCUMENT_ANALYSIS.md` - Analysis of coordinator processing fix documentation
- `MODULAR_SYSTEM_ANALYSIS.md` - Complete analysis of modular processing system
- `RE_SIGMA_CELERY_ISSUE.md` - Documentation of Re-SIGMA Celery deadlock investigation

### Obsolete Template Files
- `dashboard.html` - Old simple dashboard template (replaced by dashboard_enhanced.html)
  - Was never used in production (Flask route always used dashboard_enhanced.html)
  - Had basic 2-tile layout vs enhanced 4-tile layout with system stats

## Reason for Archival

These files were temporary diagnostic, test, and troubleshooting files created during development and debugging sessions. They served their purpose and are no longer needed in the main codebase, but are preserved here for historical reference.

## Safe to Delete?

Yes, these files can be safely deleted if disk space is needed. The functionality they tested or fixed is now integrated into the main application code.

---
*Archived by: AI Assistant*  
*Date: December 17, 2025*

