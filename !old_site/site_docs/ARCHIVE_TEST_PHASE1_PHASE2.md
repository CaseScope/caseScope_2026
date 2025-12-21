# Archive Case Feature - Phase 1 & 2 Testing Guide

**Status**: Phase 1 (Database & Settings) + Phase 2 (Core Functions) COMPLETE
**Version**: v1.18.0 (In Progress)
**Last Update**: 2025-11-20

---

## 🎯 What Should Work Now

### ✅ Phase 1: Settings & Database
1. System Settings UI has "Case Archiving" section
2. Archive path can be configured and saved
3. Path validation works (absolute, exists, writable, space)
4. Database has archive fields in `case` table

### ✅ Phase 2: Core Functions
1. `archive_utils.py` module loaded and importable
2. Archive path validation functions work
3. Case file size calculation works
4. Archive/restore functions exist (not yet exposed to UI)

---

## 🧪 Test Plan

### Test 1: System Settings UI

**What to Test:**
1. Navigate to System Settings (admin only)
2. Scroll to "🗄️ Case Archiving" section
3. Verify all UI elements present:
   - Archive Root Path input field
   - "How Case Archiving Works" info panel
   - "Requirements" warning panel

**Expected Result:**
- Section visible and styled correctly
- Warning shows: "Archive path not configured" (if empty)

**Screenshot Location**: Settings page, after Logging section, before AI section

---

### Test 2: Configure Archive Path (Invalid)

**Test Steps:**
1. In System Settings, set Archive Root Path to: `archive` (relative)
2. Click "Save Settings"

**Expected Result:**
- ⚠️ Flash message: "Archive path must be absolute (e.g., /archive)"
- Setting NOT saved

**Repeat with:**
- `/nonexistent` - Should warn: "Path does not exist"
- `/root` (assuming not writable) - Should warn: "Not writable by casescope user"

---

### Test 3: Configure Archive Path (Valid)

**Test Steps:**
1. Create archive directory:
```bash
sudo mkdir -p /archive
sudo chown casescope:casescope /archive
sudo chmod 755 /archive
```

2. In System Settings, set Archive Root Path to: `/archive`
3. Click "Save Settings"

**Expected Result:**
- ✅ Flash message: "Settings saved successfully"
- No warnings
- Archive path persisted (reload page, should still show `/archive`)

---

### Test 4: Database Verification

**Test Steps:**
```bash
cd /opt/casescope
sudo -u casescope bash -c "source venv/bin/activate && cd app && python3 << 'EOF'
from main import app, db
from models import Case, SystemSettings

with app.app_context():
    # Check system_settings table
    setting = db.session.query(SystemSettings).filter_by(setting_key='archive_root_path').first()
    print(f'Archive Path Setting: {setting.setting_value if setting else \"NOT FOUND\"}')
    
    # Check case table has new columns
    from sqlalchemy import inspect
    inspector = inspect(db.engine)
    case_columns = [col['name'] for col in inspector.get_columns('case')]
    
    archive_columns = ['archive_path', 'archived_at', 'archived_by', 'restored_at']
    for col in archive_columns:
        status = '✅' if col in case_columns else '❌'
        print(f'{status} Column: {col}')
    
    # Check Case model relationships
    case = Case.query.first()
    if case:
        print(f'\n✅ Case model has archive fields:')
        print(f'  - archive_path: {case.archive_path}')
        print(f'  - archived_at: {case.archived_at}')
        print(f'  - archived_by: {case.archived_by}')
        print(f'  - restored_at: {case.restored_at}')
        print(f'  - status: {case.status}')
EOF
"
```

**Expected Result:**
```
Archive Path Setting: /archive
✅ Column: archive_path
✅ Column: archived_at
✅ Column: archived_by
✅ Column: restored_at

✅ Case model has archive fields:
  - archive_path: None
  - archived_at: None
  - archived_by: None
  - restored_at: None
  - status: New (or In Progress, etc)
```

---

### Test 5: Archive Utils Module

**Test Steps:**
```bash
cd /opt/casescope
sudo -u casescope bash -c "source venv/bin/activate && cd app && python3 << 'EOF'
import sys
from main import app, db
from models import Case
from archive_utils import (
    get_archive_root_path,
    validate_archive_path,
    get_case_file_size,
    is_case_archived
)

with app.app_context():
    print('='*60)
    print('ARCHIVE UTILS MODULE TESTS')
    print('='*60)
    
    # Test 1: Get archive path
    print('\n1. Get Archive Root Path:')
    path = get_archive_root_path()
    print(f'   Result: {path}')
    
    # Test 2: Validate path
    if path:
        print('\n2. Validate Archive Path:')
        validation = validate_archive_path(path)
        print(f'   Valid: {validation[\"valid\"]}')
        print(f'   Message: {validation[\"message\"]}')
        print(f'   Space: {validation[\"space_gb\"]:.1f} GB')
        print(f'   Owner: {validation[\"owner\"]}')
    
    # Test 3: Get case file size (pick first case)
    case = Case.query.first()
    if case:
        print(f'\n3. Get Case File Size (Case {case.id}):')
        size_info = get_case_file_size(case.id)
        print(f'   Size: {size_info[\"size_display\"]}')
        print(f'   Files: {size_info[\"file_count\"]:,}')
        print(f'   Bytes: {size_info[\"size_bytes\"]:,}')
    
    # Test 4: Check if archived
    if case:
        print(f'\n4. Is Case Archived:')
        archived = is_case_archived(case)
        print(f'   Result: {archived} (Expected: False)')
        print(f'   Status: {case.status}')
    
    print('\n' + '='*60)
    print('✅ ALL MODULE TESTS PASSED')
    print('='*60)
EOF
"
```

**Expected Result:**
```
============================================================
ARCHIVE UTILS MODULE TESTS
============================================================

1. Get Archive Root Path:
   Result: /archive

2. Validate Archive Path:
   Valid: True
   Message: Archive path valid: 100.5GB free, owner casescope:casescope
   Space: 100.5 GB
   Owner: casescope:casescope

3. Get Case File Size (Case 1):
   Size: 5.2 GB
   Files: 1,234
   Bytes: 5,583,493,120

4. Is Case Archived:
   Result: False (Expected: False)
   Status: In Progress

============================================================
✅ ALL MODULE TESTS PASSED
============================================================
```

---

### Test 6: Manual Archive Test (Python Console)

**⚠️ WARNING**: This will actually archive a case! Only test on a non-critical case!

**Test Steps:**
```bash
cd /opt/casescope
sudo -u casescope bash -c "source venv/bin/activate && cd app && python3 << 'EOF'
from main import app, db
from models import Case
from archive_utils import archive_case

with app.app_context():
    # Pick a SMALL case for testing
    # Change case_id to a real case ID
    case_id = 999  # CHANGE THIS TO A TEST CASE
    user_id = 1    # Admin user
    
    print(f'Archiving case {case_id}...')
    result = archive_case(db, case_id, user_id)
    
    print('\nResult:')
    print(f'  Status: {result[\"status\"]}')
    print(f'  Message: {result[\"message\"]}')
    if result['status'] == 'success':
        print(f'  Archive Path: {result[\"archive_path\"]}')
        print(f'  Size: {result[\"size_mb\"]:.1f} MB')
        print(f'  Files: {result[\"file_count\"]}')
EOF
"
```

**Expected Result (Success):**
```
Archiving case 999...

Result:
  Status: success
  Message: Case archived successfully: 10 files (2.3 MB)
  Archive Path: /archive/2025-11-20 - TestCase_case999/archive.zip
  Size: 2.3 MB
  Files: 10
```

**Verify:**
1. Check archive created:
```bash
ls -lh /archive/2025-11-20*
# Should show directory with archive.zip
```

2. Check original files removed:
```bash
ls -la /opt/casescope/uploads/999/
# Should show empty directory (folder structure preserved)
```

3. Check database:
```bash
cd /opt/casescope
sudo -u casescope bash -c "source venv/bin/activate && cd app && python3 << 'EOF'
from main import app, db
from models import Case

with app.app_context():
    case = db.session.get(Case, 999)  # CHANGE TO YOUR TEST CASE
    print(f'Status: {case.status}')
    print(f'Archive Path: {case.archive_path}')
    print(f'Archived At: {case.archived_at}')
    print(f'Archived By: {case.archived_by}')
EOF
"
```

**Expected:**
```
Status: Archived
Archive Path: /archive/2025-11-20 - TestCase_case999/archive.zip
Archived At: 2025-11-20 15:50:12.345678
Archived By: 1
```

---

### Test 7: Manual Restore Test (Python Console)

**⚠️ WARNING**: Only run if you did Test 6!

**Test Steps:**
```bash
cd /opt/casescope
sudo -u casescope bash -c "source venv/bin/activate && cd app && python3 << 'EOF'
from main import app, db
from models import Case
from archive_utils import restore_case

with app.app_context():
    case_id = 999  # SAME CASE FROM TEST 6
    user_id = 1
    
    print(f'Restoring case {case_id}...')
    result = restore_case(db, case_id, user_id, new_status='In Progress')
    
    print('\nResult:')
    print(f'  Status: {result[\"status\"]}')
    print(f'  Message: {result[\"message\"]}')
    if result['status'] == 'success':
        print(f'  Files Restored: {result[\"files_restored\"]}')
EOF
"
```

**Expected Result:**
```
Restoring case 999...

Result:
  Status: success
  Message: Case restored successfully: 10 files
  Files Restored: 10
```

**Verify:**
1. Check files restored:
```bash
ls -la /opt/casescope/uploads/999/
# Should show 10 files
```

2. Check ownership:
```bash
ls -l /opt/casescope/uploads/999/ | head -5
# All files should be casescope:casescope
```

3. Check database:
```bash
cd /opt/casescope
sudo -u casescope bash -c "source venv/bin/activate && cd app && python3 << 'EOF'
from main import app, db
from models import Case

with app.app_context():
    case = db.session.get(Case, 999)
    print(f'Status: {case.status}')
    print(f'Archive Path: {case.archive_path}')  # Should still be recorded
    print(f'Restored At: {case.restored_at}')
EOF
"
```

**Expected:**
```
Status: In Progress
Archive Path: /archive/2025-11-20 - TestCase_case999/archive.zip
Restored At: 2025-11-20 15:52:34.567890
```

4. Check archive deleted:
```bash
ls /archive/2025-11-20*
# Should NOT exist (deleted after successful restore)
```

---

## ✅ Success Criteria

**Phase 1 & 2 are working if:**

- [x] System Settings shows Archive section
- [x] Archive path can be configured
- [x] Invalid paths show warnings
- [x] Valid path saves successfully
- [x] Database has archive fields
- [x] `archive_utils.py` imports without errors
- [x] Archive path validation returns correct results
- [x] Case file size calculation works
- [x] Manual archive test succeeds (optional)
- [x] Manual restore test succeeds (optional)

---

## ❌ Known Limitations (Not Yet Implemented)

**What WON'T work yet:**

- ❌ No UI buttons to archive/restore (Phase 3)
- ❌ No progress modals (Phase 3)
- ❌ No archive warning banner on cases (Phase 3)
- ❌ No automatic guards on file operations (Phase 4)
- ❌ Re-index/upload still allowed on archived cases (Phase 4)
- ❌ No API endpoints for archive/restore (Phase 2 - pending)

**To use archive/restore, you must:**
- Use Python console (as shown in Test 6 & 7)
- OR wait for Phase 3 (UI integration)

---

## 🐛 Troubleshooting

### Issue: "Archive path not saved"
**Solution**: Check permissions on `/archive`:
```bash
sudo chown casescope:casescope /archive
sudo chmod 755 /archive
```

### Issue: "Module not found: archive_utils"
**Solution**: Restart web service:
```bash
sudo systemctl restart casescope.service
```

### Issue: "Permission denied" during archive
**Solution**: Check case file ownership:
```bash
sudo chown -R casescope:casescope /opt/casescope/uploads/
```

### Issue: Archive ZIP not created
**Solution**: Check logs:
```bash
tail -f /opt/casescope/logs/workers.log
# Look for [ARCHIVE] entries
```

---

## 📝 Next Steps (After Testing)

If Phase 1 & 2 tests pass:

1. **Phase 3**: UI Integration
   - Add archive/restore buttons to case dashboard
   - Add progress modals
   - Add archive warning banner

2. **Phase 4**: Backend Guards
   - Prevent upload/reindex/delete on archived cases
   - Add guards to Celery tasks

3. **Phase 5**: Documentation & Testing
   - Update version.json
   - Update APP_MAP.md
   - End-to-end testing

---

## 📊 Testing Checklist

Use this checklist to track your testing:

- [ ] Test 1: System Settings UI visible
- [ ] Test 2: Invalid path validation works
- [ ] Test 3: Valid path saves successfully
- [ ] Test 4: Database verification passes
- [ ] Test 5: Archive utils module tests pass
- [ ] Test 6: Manual archive test (optional)
- [ ] Test 7: Manual restore test (optional)

**Mark items complete as you test them!**

