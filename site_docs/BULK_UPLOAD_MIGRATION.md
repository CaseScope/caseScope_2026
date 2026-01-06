# Bulk Upload Path Migration

**Date:** January 6, 2026  
**Status:** Migration Required

---

## Summary

The bulk upload (SFTP) processing has been **unified** with the web upload processing to use the same modern, parallel ingestion pipeline. This improves performance, consistency, and maintainability.

### What Changed

| Aspect | Old (Legacy) | New (Current) |
|--------|-------------|---------------|
| **Upload Path** | `/opt/casescope/bulk_upload/{case_id}/` | `/opt/casescope/uploads/sftp/{case_id}/` |
| **Processing Task** | `process_uploaded_files` (task_file_upload.py) | `ingest_files` (task_ingest_files.py) |
| **Architecture** | ZIP-centric sequential | NEW_FILE_UPLOAD.ND parallel |
| **Workers** | Single worker | 8 parallel workers |
| **Duplicate Detection** | File-level only | SHA256 hash with storage verification |
| **Progress Tracking** | Limited | Full ingestion progress table |

---

## Migration Steps

### For Administrators

#### 1. Move Existing Files (if any)

If you have files waiting in the old bulk_upload directory:

```bash
# Check for files in old location
ls -la /opt/casescope/bulk_upload/*/

# For each case with pending files, move to new location
for case_id in $(ls /opt/casescope/bulk_upload/ 2>/dev/null); do
    if [ -d "/opt/casescope/bulk_upload/$case_id" ]; then
        # Create new SFTP upload directory
        mkdir -p "/opt/casescope/uploads/sftp/$case_id"
        
        # Move files
        mv /opt/casescope/bulk_upload/$case_id/* /opt/casescope/uploads/sftp/$case_id/ 2>/dev/null
        
        # Set correct permissions
        chown -R casescope:casescope "/opt/casescope/uploads/sftp/$case_id/"
        chmod 770 "/opt/casescope/uploads/sftp/$case_id/"
        
        echo "Migrated case $case_id"
    fi
done

# Remove old bulk_upload directory (after verifying migration)
# rm -rf /opt/casescope/bulk_upload/
```

#### 2. Update User Documentation

Update any internal SFTP upload instructions to use:
```
/opt/casescope/uploads/sftp/{case_id}/
```

Instead of:
```
/opt/casescope/bulk_upload/{case_id}/  # OLD - DO NOT USE
```

#### 3. Update SFTP/SCP Scripts

If you have automated upload scripts, update the target path:

**Old:**
```bash
scp evidence.zip casescope@server:/opt/casescope/bulk_upload/123/
```

**New:**
```bash
scp evidence.zip casescope@server:/opt/casescope/uploads/sftp/123/
```

---

## Benefits of New System

### 1. **Parallel Processing**
- Files now process across 8 workers simultaneously
- Dramatically faster for bulk uploads

### 2. **Unified Pipeline**
- Web and SFTP uploads use identical processing
- Consistent behavior and error handling
- Single codebase to maintain

### 3. **Better Duplicate Detection**
- SHA256 hash verification
- Storage-level duplicate checking
- Prevents re-processing same files

### 4. **Progress Tracking**
- Real-time status updates
- Resumable operations
- Better error reporting

### 5. **Modern Architecture**
- Uses NEW_FILE_UPLOAD.ND specification
- Follows current best practices
- Future-proof design

---

## User Experience

### What Stays the Same
- SFTP/SCP access still works
- "Scan for New Files" button still works
- File types supported are unchanged
- Processing steps are identical

### What's Different
- **New upload path**: `/opt/casescope/uploads/sftp/{case_id}/`
- **Faster processing**: Parallel workers
- **Better feedback**: Real-time progress updates
- **Duplicate detection**: Automatic hash checking

---

## Troubleshooting

### Files Not Appearing After Upload

**Check upload path:**
```bash
# New path (correct)
ls -la /opt/casescope/uploads/sftp/{case_id}/

# Old path (will not be scanned)
ls -la /opt/casescope/bulk_upload/{case_id}/
```

**Solution:** Move files to new location (see migration steps above)

### "Processing Already in Progress" Error

This is a new safety feature. Only one ingestion can run per case at a time.

**Wait:** Let current processing complete (check case files page)  
**Or:** Cancel stuck processing via database if truly stuck

---

## Technical Details

### Code Changes

**File:** `/opt/casescope/app/routes/case.py`
- Route: `scan_bulk_upload` (line 1311)
- Changed from: `process_uploaded_files.delay()` 
- Changed to: `ingest_files.delay()` with `upload_type='sftp'`

**File:** `/opt/casescope/templates/case/upload.html`
- Updated UI to display: `/opt/casescope/uploads/sftp/{case_id}/`

**Documentation Updated:**
- `README.MD`
- `ZIP_ARCHITECTURE.md`
- `CELERY_SYSTEM.md`
- `CASE_CLEANUP_PROCEDURE.md`

### Directory Permissions

New SFTP upload directories should have:
```bash
drwxrwx--- casescope casescope /opt/casescope/uploads/sftp/{case_id}/
```

### Service Restart

Changes applied after restart:
```bash
sudo systemctl restart casescope-new
```

---

## Rollback (Not Recommended)

If you need to temporarily rollback (not recommended):

1. Revert `/opt/casescope/app/routes/case.py` line 1311-1382
2. Revert `/opt/casescope/templates/case/upload.html` line 833
3. Restart Flask: `sudo systemctl restart casescope-new`

**Note:** The new system is superior in every way. Rollback should only be for emergency debugging.

---

## Questions?

Contact: System Administrator  
Migration Date: January 6, 2026  
Migration Status: ✅ Complete

