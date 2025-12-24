# App Directory File Analysis
**Date:** December 17, 2025  
**Total .py files:** 68

## Executive Summary

**Good News:** The app directory is well-maintained! Out of 68 Python files, only **2 files** are candidates for archival:
1. `auto_hide.py` - Unused module (dead code)
2. `cleanup_stale_locks.py` - Standalone cron script (should be moved to scripts folder)

All other files are actively used and imported by the application.

## Detailed Analysis

### ✅ ALL FILES ARE ACTIVELY USED

Every module in the app directory (except 2) is imported and used:
- **Core application:** main.py, wsgi.py, config.py, models.py, celery_app.py, logging_config.py
- **Processing pipelines:** file_processing.py, processing_*.py, coordinator_*.py
- **Event management:** event_status.py, events_known_good.py, events_known_noise.py
- **Search & Triage:** search_utils.py, ai_triage_*.py, triage_patterns.py
- **EVTX tools:** evtx_descriptions.py, evtx_scraper.py, evtx_scrapers_enhanced.py, evtx_enrichment.py
- **Utilities:** utils.py, validation.py, export_utils.py, audit_logger.py
- **Integrations:** dfir_iris.py, opencti.py
- **Diagnostics:** diagnostics_*.py, queue_cleanup.py, celery_health.py
- **Hardware:** hardware_setup.py, hardware_utils.py (used by routes/settings.py)

### 🗑️ Files to Archive/Relocate

#### 1. `auto_hide.py` - DEAD CODE
- **Status:** Not imported anywhere
- **Original Purpose:** "Modular functions to check if events should be auto-hidden during indexing"
- **Comment says:** "Used by file_processing.py" but this is FALSE
- **Reality:** Never actually integrated into file_processing.py
- **Recommendation:** Archive (move to 2025-12-17_archive/)

#### 2. `cleanup_stale_locks.py` - STANDALONE SCRIPT
- **Status:** Standalone cron script, not imported
- **Purpose:** Clean up stale case locks (meant to run via cron)
- **Reality:** Should live in a /scripts/ or /bin/ directory, not /app/
- **Recommendation:** Move to /opt/casescope/scripts/ (create if needed)

### 📋 Shell Scripts

#### 1. `fresh_install.sh`
- **Status:** Complete fresh installation script
- **Usage:** `sudo bash fresh_install.sh`
- **Recommendation:** Keep (useful for new deployments)

#### 2. `safe_shutdown.sh`
- **Status:** Safe Celery worker shutdown script
- **Usage:** Pauses queue and waits for tasks to finish
- **Recommendation:** Keep (useful for maintenance)

## Recommendations

### Immediate Actions

1. **Archive dead code:**
   ```bash
   mv /opt/casescope/app/auto_hide.py /opt/casescope/2025-12-17_archive/
   ```

2. **Create scripts directory and move standalone scripts:**
   ```bash
   mkdir -p /opt/casescope/scripts
   mv /opt/casescope/app/cleanup_stale_locks.py /opt/casescope/scripts/
   ```

3. **Update cron jobs (if cleanup_stale_locks is in crontab):**
   ```bash
   # Old path: /opt/casescope/app/cleanup_stale_locks.py
   # New path: /opt/casescope/scripts/cleanup_stale_locks.py
   ```

### Optional: Better Organization

Consider creating these subdirectories for better organization:
- `/opt/casescope/scripts/` - Standalone utility scripts (cron jobs, maintenance)
- `/opt/casescope/docs/` - Move INSTALL.md, README.md here
- `/opt/casescope/tools/` - Command-line tools (if any)

## Files That Look Duplicated But Aren't

### EVTX Scrapers
- ❌ `evtx_scraper.py` - NOT a duplicate
  - **Used by:** evtx_descriptions.py
  - **Purpose:** Main scraper for Ultimate Windows Security
  
- ❌ `evtx_scrapers_enhanced.py` - NOT a duplicate
  - **Used by:** evtx_descriptions.py
  - **Purpose:** Additional scrapers (MyEventLog.com, Microsoft Learn)

Both are needed and actively used.

### Hardware Files
- ❌ `hardware_setup.py` - NOT unused
  - **Used by:** routes/settings.py
  - **Purpose:** NVIDIA driver & CUDA setup
  
- ❌ `hardware_utils.py` - NOT unused
  - **Used by:** routes/settings.py
  - **Purpose:** GPU detection & VRAM info

Both are needed for hardware detection and setup.

## Conclusion

The app directory is **well-maintained and lean**. Only 2 files need attention:
- 1 dead code module (auto_hide.py)
- 1 misplaced script (cleanup_stale_locks.py)

All 66 other Python files are actively used by the application. No major cleanup needed!

---
*Analysis performed by AI Assistant*  
*Date: December 17, 2025*

