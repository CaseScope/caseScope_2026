# 🗑️ CaseScope Unused Files Report

**Generated**: November 17, 2025  
**Review Type**: Comprehensive codebase analysis  
**Purpose**: Identify files that can be safely removed

---

## 📊 Summary

**Total Files Identified for Removal**: 15 files (~20 MB)

### Categories:
1. **Backup Files**: 4 files
2. **One-Time Migration Scripts**: 8 files  
3. **Development/Testing Files**: 2 files
4. **Old Documentation**: 1 file

---

## 🔴 HIGH PRIORITY - Backup Files (Safe to Remove)

### 1. `celery_app.py.backup`
- **Type**: Backup file
- **Size**: Unknown
- **Reason**: Backup of celery_app.py, no longer needed
- **Risk**: None - backup only

### 2. `bulk_operations_global.py.backup_v1.14.3`
- **Type**: Backup file  
- **Size**: ~20KB (estimated)
- **Reason**: Archived after v1.15.0 refactoring merged this into bulk_operations.py
- **Risk**: None - replaced by unified bulk_operations.py

### 3. `ai_training.py.backup_v1.11.20`
- **Type**: Backup file
- **Size**: Unknown
- **Reason**: Backup from version 1.11.20
- **Risk**: None - backup only

### 4. `tasks.py.broken`
- **Type**: Broken/old version
- **Size**: Unknown
- **Reason**: Marked as broken, current tasks.py is working
- **Risk**: None - broken version not in use

---

## 🟡 MEDIUM PRIORITY - One-Time Migration Scripts

These scripts were used for database migrations and are no longer needed after successful migration:

### 5. `add_known_users_table.py`
- **Type**: One-time migration script
- **Purpose**: Added case_id to KnownUser table (v1.12.22)
- **Status**: Migration complete
- **Risk**: Low - can be kept for reference or removed

### 6. `migrate_audit_log.py`
- **Type**: One-time migration script
- **Purpose**: Migrated audit log structure
- **Status**: Migration complete
- **Risk**: Low - historical migration

### 7. `migrate_to_consolidated_indices.py`
- **Type**: One-time migration script
- **Purpose**: Migrated from per-file to per-case OpenSearch indices (v1.13.1)
- **Status**: Migration complete, architecture changed
- **Risk**: Low - may want to keep for reference

### 8. `migrate_user_created_by.py`
- **Type**: One-time migration script
- **Purpose**: Added created_by field to users
- **Status**: Migration complete
- **Risk**: Low - historical migration

### 9. `backfill_source_file_type.py`
- **Type**: One-time data backfill script
- **Purpose**: Backfilled source_file_type for existing events
- **Status**: Backfill complete
- **Risk**: Low - historical script

### 10. `recover_limbo_files.py`
- **Type**: One-time recovery script
- **Purpose**: Recovered files stuck in limbo state
- **Status**: Issue resolved in code
- **Risk**: Low - may be useful for future recovery

### 11. `seed_ai_models.py`
- **Type**: One-time seeding script
- **Purpose**: Initial seeding of AI model list
- **Status**: Models can be managed via UI
- **Risk**: Low - may be useful for fresh installs

### 12. `migrations/add_*.py` (7 files)
- **Files**:
  - `migrations/add_ai_gpu_vram.py`
  - `migrations/add_ai_hardware_mode.py`
  - `migrations/add_ai_report_prompt_response.py`
  - `migrations/add_ai_report_stage_tracking.py`
  - `migrations/add_case_id_to_known_users.py`
  - `migrations/add_systems_table.py`
  - `migrations/add_validation_results.py`
- **Type**: Database migration scripts
- **Purpose**: Added various database fields/tables
- **Status**: All migrations complete
- **Risk**: Low - can be kept for documentation or removed

---

## 🟠 LOW PRIORITY - Development Files

### 13. `main_NEW.py`
- **Type**: Development/testing file
- **Size**: ~5KB
- **Purpose**: Appears to be refactored version or test file
- **Status**: main.py is the active file
- **Risk**: Medium - verify this isn't used for testing before removing

### 14. `PUSH_TO_GITHUB.sh`
- **Type**: Developer helper script
- **Size**: ~9KB
- **Purpose**: Helper script for pushing to GitHub
- **Status**: git commands can be used directly
- **Risk**: Low - convenience script only

---

## 📄 DOCUMENTATION FILES

### 15. `SUMMARY.txt`
- **Type**: Old documentation
- **Size**: ~13KB
- **Purpose**: Summary from v1.0.0 release (October 2025)
- **Status**: Historical, info now in APP_MAP.md and version.json
- **Risk**: Low - can be removed if APP_MAP.md is comprehensive

---

## 🔵 LOG FILES (Should NOT be in Git)

### 16. `u_ex250112.log`
- **Type**: IIS log file
- **Size**: **19 MB** ⚠️
- **Purpose**: Appears to be test/sample IIS log
- **Status**: Should not be in repository
- **Risk**: None - but taking up significant space
- **Action**: Remove from git and add *.log to .gitignore

---

## ✅ VERIFIED IN-USE FILES (DO NOT REMOVE)

The following files are actively used and should NOT be removed:

### Core Application Files:
- ✅ `main.py` - Active Flask application
- ✅ `tasks.py` - Active Celery tasks
- ✅ `models.py` - Database models
- ✅ `config.py` - Configuration
- ✅ `celery_app.py` - Celery setup
- ✅ `wsgi.py` - WSGI entry point
- ✅ `requirements.txt` - Dependencies

### Processing Modules:
- ✅ `file_processing.py` - File processing pipeline
- ✅ `upload_pipeline.py` - Upload pipeline
- ✅ `upload_integration.py` - Upload route handlers
- ✅ `bulk_operations.py` - Bulk operations (v1.15.0 unified)

### Feature Modules:
- ✅ `ai_report.py` - Used by routes/settings.py
- ✅ `ai_training.py` - AI LoRA training
- ✅ `ai_resource_lock.py` - AI resource locking
- ✅ `audit_logger.py` - Used throughout application
- ✅ `dfir_iris.py` - Used by routes/settings.py
- ✅ `opencti.py` - Used by routes/ioc.py, routes/systems.py, routes/settings.py
- ✅ `event_deduplication.py` - Used by file_processing.py
- ✅ `event_normalization.py` - Used by file_processing.py
- ✅ `evtx_descriptions.py` - EVTX event description system
- ✅ `evtx_enrichment.py` - Event description refresh
- ✅ `evtx_scraper.py` - Used by evtx_descriptions.py
- ✅ `evtx_scrapers_enhanced.py` - Used by evtx_descriptions.py
- ✅ `export_utils.py` - CSV export functionality
- ✅ `hardware_setup.py` - Used by routes/settings.py
- ✅ `hardware_utils.py` - Used by routes/settings.py
- ✅ `hidden_files.py` - Hidden file management
- ✅ `known_user_utils.py` - Known user utilities
- ✅ `login_analysis.py` - Login analysis features
- ✅ `logging_config.py` - Logging configuration
- ✅ `search_utils.py` - Search utilities
- ✅ `sigma_utils.py` - SIGMA rule management
- ✅ `system_stats.py` - System statistics
- ✅ `utils.py` - General utilities
- ✅ `validation.py` - Validation functions
- ✅ `bulk_import.py` - Bulk import functionality
- ✅ `queue_cleanup.py` - Queue maintenance

### Utility Scripts (Keep):
- ✅ `fresh_install.sh` - Installation automation
- ✅ `safe_shutdown.sh` - Safe shutdown utility

### Documentation (Keep):
- ✅ `README.md` - Main documentation
- ✅ `INSTALL.md` - Installation guide
- ✅ `APP_MAP.md` - Technical documentation
- ✅ `QUICK_REFERENCE.md` - Command reference
- ✅ `UI_SYSTEM.md` - UI documentation
- ✅ `EVTX_DESCRIPTIONS_README.md` - EVTX docs
- ✅ `version.json` - Version history

### Routes (All Active):
- ✅ `routes/__init__.py`
- ✅ `routes/admin.py`
- ✅ `routes/api.py`
- ✅ `routes/api_stats.py`
- ✅ `routes/auth.py`
- ✅ `routes/cases.py`
- ✅ `routes/files.py`
- ✅ `routes/ioc.py`
- ✅ `routes/known_users.py`
- ✅ `routes/settings.py`
- ✅ `routes/systems.py`
- ✅ `routes/users.py`

---

## 📝 Recommended Actions

### Immediate Actions (Safe):
```bash
# Remove backup files
rm celery_app.py.backup
rm bulk_operations_global.py.backup_v1.14.3
rm ai_training.py.backup_v1.11.20
rm tasks.py.broken

# Remove large log file from repository
rm u_ex250112.log
echo "*.log" >> .gitignore
```

### Optional Actions (After Verification):
```bash
# Remove migration scripts (keep for reference if unsure)
rm add_known_users_table.py
rm migrate_audit_log.py
rm migrate_to_consolidated_indices.py
rm migrate_user_created_by.py
rm backfill_source_file_type.py

# Remove recovery/seeding scripts
rm recover_limbo_files.py
rm seed_ai_models.py

# Remove database migration scripts
rm migrations/add_ai_gpu_vram.py
rm migrations/add_ai_hardware_mode.py
rm migrations/add_ai_report_prompt_response.py
rm migrations/add_ai_report_stage_tracking.py
rm migrations/add_case_id_to_known_users.py
rm migrations/add_systems_table.py
rm migrations/add_validation_results.py

# Remove old documentation
rm SUMMARY.txt

# Remove development files (verify first!)
rm main_NEW.py
rm PUSH_TO_GITHUB.sh
```

---

## 💾 Space Savings

**Estimated Total**: ~20 MB
- Large log file: ~19 MB
- Backup/migration files: ~1 MB

---

## ⚠️ Important Notes

1. **Backup First**: Consider backing up the entire directory before removal
2. **Migration Scripts**: These can be removed safely but you may want to keep them for documentation
3. **main_NEW.py**: Verify this is not used for testing before removing
4. **Git Commit**: After removal, commit with clear message about what was cleaned up
5. **.gitignore**: Update .gitignore to prevent log files from being committed

---

## 🔍 Verification Commands

Before removing, you can verify files aren't imported:
```bash
cd /opt/casescope/app

# Check if a file is imported anywhere
grep -r "import filename\|from filename" . --include="*.py"

# Example for main_NEW:
grep -r "import main_NEW\|from main_NEW" . --include="*.py"
```

---

**Report End**

