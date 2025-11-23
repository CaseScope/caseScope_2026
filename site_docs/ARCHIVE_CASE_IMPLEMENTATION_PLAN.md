# Archive Case Feature - Implementation Plan

## Executive Summary

This document outlines a comprehensive plan to implement an **Archive Case** feature that allows users to move case files to cold storage while retaining all indexed data for search and analysis. The feature maintains full data integrity and provides seamless archive/restore workflows.

---

## Table of Contents

1. [Feature Overview](#feature-overview)
2. [Technical Analysis](#technical-analysis)
3. [Database Schema Changes](#database-schema-changes)
4. [Implementation Phases](#implementation-phases)
5. [Breaking Changes Prevention](#breaking-changes-prevention)
6. [Testing Strategy](#testing-strategy)
7. [Rollback Plan](#rollback-plan)

---

## Feature Overview

### Purpose
- Move case files to external storage (e.g., spinning disk drives) to free up SSD space
- Retain all indexed data in OpenSearch for continued search/analysis
- Prevent operations that require source files
- Enable seamless restoration when needed

### User Workflow
1. Admin configures archive path in System Settings
2. User changes case status to "Archived"
3. System creates ZIP of all case files, stores in archive location
4. Source files removed from working set
5. UI displays archive warning and disables file-dependent operations
6. User can restore case by changing status back to active

---

## Technical Analysis

### What Works WITHOUT Source Files ✅
Based on code analysis (`hunt_iocs` in `file_processing.py`, line 1500+):

| Operation | Requires Source Files? | Notes |
|-----------|----------------------|--------|
| **IOC Hunting** | ❌ NO | Uses OpenSearch only |
| **Search Events** | ❌ NO | Uses OpenSearch only |
| **View Events** | ❌ NO | Uses OpenSearch only |
| **Export CSV** | ❌ NO | Uses OpenSearch only |
| **AI Reports** | ❌ NO | Uses OpenSearch data |
| **AI Timelines** | ❌ NO | Uses OpenSearch data |
| **View Systems** | ❌ NO | Uses database only |
| **View IOCs** | ❌ NO | Uses database only |
| **Login Analysis** | ❌ NO | Uses OpenSearch only |

### What REQUIRES Source Files ❌
Based on code analysis (`process_file` in `tasks.py`, `index_file` in `file_processing.py`):

| Operation | Requires Source Files? | Notes |
|-----------|----------------------|--------|
| **Re-Index Files** | ✅ YES | Reads EVTX/NDJSON/CSV/IIS files directly |
| **Re-SIGMA** | ✅ YES | Chainsaw reads EVTX files directly |
| **Upload New Files** | ✅ YES | Adds files to case directory |
| **Bulk Upload** | ✅ YES | Adds files to case directory |
| **File Export (raw)** | ✅ YES | Downloads original file |

### User's Question Answered
> "I assume re-hunt IOCs would work since I dont think that requires the sources files but please correct me if I am wrong"

**✅ CORRECT!** IOC re-hunting will work perfectly on archived cases. The `hunt_iocs` function (line 1500-1857 in `file_processing.py`) only queries OpenSearch data and never accesses source files.

---

## Database Schema Changes

### 1. Case Model (`models.py`, line 33+)

```python
class Case(db.Model):
    """Investigation cases"""
    __tablename__ = 'case'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False, index=True)
    description = db.Column(db.Text)
    company = db.Column(db.String(200))
    
    # EXISTING: status values are: New, Assigned, In Progress, Completed
    # CHANGE: Add 'Archived' to allowed values
    status = db.Column(db.String(20), default='New')
    
    # NEW FIELDS FOR ARCHIVING
    archive_path = db.Column(db.String(1000))  # Full path to archive ZIP
    archived_at = db.Column(db.DateTime)        # When archived
    archived_by = db.Column(db.Integer, db.ForeignKey('user.id'))  # Who archived
    restored_at = db.Column(db.DateTime)        # When last restored (for audit)
    
    # Existing fields...
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    files = db.relationship('CaseFile', back_populates='case', lazy='dynamic')
    creator = db.relationship('User', foreign_keys=[created_by], backref='cases_created')
    assignee = db.relationship('User', foreign_keys=[assigned_to], backref='cases_assigned')
    archiver = db.relationship('User', foreign_keys=[archived_by], backref='cases_archived')
```

### 2. Settings Model (NEW)

Create a new `AppSettings` model or add to existing settings table:

```python
class AppSettings(db.Model):
    """Application-wide settings"""
    __tablename__ = 'app_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    setting_key = db.Column(db.String(100), unique=True, nullable=False)
    setting_value = db.Column(db.Text)
    description = db.Column(db.Text)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey('user.id'))
```

Setting key: `archive_root_path`
Example value: `/archive` or `/mnt/archive_drive`

### 3. Migration Script

```python
# app/migrations/add_archive_fields.py

import sqlite3
import os

def run_migration():
    db_path = '/opt/casescope/app/casescope.db'
    
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        
        # Add archive fields to case table
        try:
            cursor.execute('ALTER TABLE "case" ADD COLUMN archive_path VARCHAR(1000);')
            cursor.execute('ALTER TABLE "case" ADD COLUMN archived_at TIMESTAMP;')
            cursor.execute('ALTER TABLE "case" ADD COLUMN archived_by INTEGER REFERENCES "user"(id);')
            cursor.execute('ALTER TABLE "case" ADD COLUMN restored_at TIMESTAMP;')
            print("✅ Added archive fields to case table")
        except sqlite3.OperationalError as e:
            if 'duplicate column name' in str(e):
                print("⚠️  Archive fields already exist")
            else:
                raise
        
        # Create app_settings table if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS app_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                setting_key VARCHAR(100) UNIQUE NOT NULL,
                setting_value TEXT,
                description TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_by INTEGER REFERENCES "user"(id)
            );
        ''')
        print("✅ Created app_settings table")
        
        # Insert default archive path setting
        cursor.execute('''
            INSERT OR IGNORE INTO app_settings (setting_key, setting_value, description)
            VALUES ('archive_root_path', NULL, 'Root path for archived case files (e.g., /archive)');
        ''')
        print("✅ Added archive_root_path setting")
        
        conn.commit()

if __name__ == '__main__':
    run_migration()
```

---

## Implementation Phases

### Phase 1: Foundation (Settings & Database)

**Files to Create:**
- `app/migrations/add_archive_fields.py` - Database migration
- `app/archive_utils.py` - Core archive functions

**Files to Modify:**
- `app/models.py` - Add archive fields and AppSettings model
- `app/settings.py` or `app/main.py` - Add archive path setting to system settings page

**Tasks:**
1. Create migration script
2. Add AppSettings model to `models.py`
3. Update Case model with archive fields
4. Add archive path input to System Settings page
5. Add validation: path must exist, be writable, owned by casescope:casescope

**Testing:**
- Run migration on test database
- Verify fields added correctly
- Test setting archive path in UI
- Verify path validation

---

### Phase 2: Archive Process

**Files to Create:**
- `app/archive_utils.py` - Archive/restore functions
- `app/routes/archive.py` - Archive routes (Flask blueprint)
- `app/tasks_archive.py` - Celery tasks for async archive/restore

**Core Functions (`app/archive_utils.py`):**

```python
def archive_case(db, case_id: int, current_user_id: int) -> dict:
    """
    Archive a case by creating ZIP of files and removing originals
    
    Process:
    1. Validate archive path is configured
    2. Get all case files from database
    3. Create archive directory: {archive_root}/{date} - {case_name}_case{id}/
    4. Create ZIP of /opt/casescope/uploads/{case_id}/
    5. Verify ZIP integrity (test extract)
    6. Record archive path in database
    7. Delete original files (keep directory structure)
    8. Update case status to 'Archived'
    9. Audit log
    
    Returns:
        {'status': 'success'/'error', 'message': str, 'archive_path': str}
    """
    pass

def restore_case(db, case_id: int, current_user_id: int) -> dict:
    """
    Restore an archived case by extracting ZIP back to original location
    
    Process:
    1. Validate case is archived
    2. Validate archive ZIP exists
    3. Extract ZIP to /opt/casescope/uploads/{case_id}/
    4. Verify all files restored (compare counts)
    5. Set ownership to casescope:casescope
    6. Update case status (user's choice)
    7. Update restored_at timestamp
    8. Delete archive ZIP
    9. Audit log
    
    Returns:
        {'status': 'success'/'error', 'message': str, 'files_restored': int}
    """
    pass

def validate_archive_path(path: str) -> dict:
    """
    Validate archive path is usable
    
    Checks:
    - Path exists
    - Path is absolute
    - Path is writable
    - Path owned by casescope:casescope
    - Sufficient disk space (>100GB recommended)
    
    Returns:
        {'valid': bool, 'message': str, 'space_gb': float}
    """
    pass

def get_case_file_size(case_id: int) -> int:
    """Calculate total size of case files in bytes"""
    pass
```

**Celery Tasks (`app/tasks_archive.py`):**

```python
@celery_app.task(bind=True, name='tasks.archive_case_async')
def archive_case_async(self, case_id: int, user_id: int):
    """
    Async archive task with progress updates
    
    Progress updates:
    - 10%: Preparing archive
    - 30%: Creating ZIP (with file count progress)
    - 60%: Verifying ZIP
    - 80%: Removing original files
    - 100%: Complete
    """
    pass

@celery_app.task(bind=True, name='tasks.restore_case_async')
def restore_case_async(self, case_id: int, user_id: int):
    """
    Async restore task with progress updates
    
    Progress updates:
    - 10%: Validating archive
    - 30%: Extracting files (with file count progress)
    - 60%: Setting permissions
    - 80%: Verifying restore
    - 100%: Complete
    """
    pass
```

**Routes (`app/routes/archive.py`):**

```python
@archive_bp.route('/case/<int:case_id>/archive', methods=['POST'])
@login_required
def archive_case_route(case_id):
    """
    Archive a case (admin only)
    
    Returns:
        JSON: {'success': bool, 'task_id': str, 'message': str}
    """
    pass

@archive_bp.route('/case/<int:case_id>/archive/status', methods=['GET'])
@login_required
def archive_status_route(case_id):
    """
    Get archive progress
    
    Returns:
        JSON: {'status': str, 'progress': int, 'message': str}
    """
    pass

@archive_bp.route('/case/<int:case_id>/restore', methods=['POST'])
@login_required
def restore_case_route(case_id):
    """
    Restore an archived case (admin only)
    
    Requires:
        - new_status: str (New, In Progress, etc.)
    
    Returns:
        JSON: {'success': bool, 'task_id': str, 'message': str}
    """
    pass

@archive_bp.route('/case/<int:case_id>/restore/status', methods=['GET'])
@login_required
def restore_status_route(case_id):
    """
    Get restore progress
    
    Returns:
        JSON: {'status': str, 'progress': int, 'message': str}
    """
    pass
```

**Testing:**
- Archive small test case (10 files, <100MB)
- Verify ZIP created in correct location
- Verify original files removed
- Verify folder structure preserved
- Verify database updated correctly
- Test restore process
- Verify all files restored
- Verify permissions set correctly

---

### Phase 3: UI Integration

**Files to Modify:**
- `app/templates/view_case.html` - Add archive warning banner
- `app/templates/view_case_enhanced.html` - Add archive warning banner
- `app/templates/case_list.html` - Add archive status column
- `app/main.py` - Add status change validation

**Archive Warning Banner:**

```html
<!-- At top of case dashboard, immediately under header -->
{% if case.status == 'Archived' %}
<div style="
    background: linear-gradient(135deg, #ff6b6b 0%, #ff8e8e 100%);
    border: 2px solid #ff4444;
    border-radius: 8px;
    padding: var(--spacing-lg);
    margin: var(--spacing-lg) 0;
    text-align: center;
    box-shadow: 0 4px 12px rgba(255, 68, 68, 0.3);
">
    <div style="font-size: 1.5em; font-weight: bold; color: white; margin-bottom: var(--spacing-sm);">
        ⚠️ ARCHIVED CASE
    </div>
    <div style="color: white; font-size: 1em; line-height: 1.6;">
        <strong>Source files are archived and unavailable.</strong><br>
        Search, IOC hunting, and reporting remain fully functional.<br>
        Disabled functions: Re-Index, Re-SIGMA, Upload Files, Delete Files<br>
        <button onclick="showRestoreModal()" class="btn btn-success" style="margin-top: var(--spacing-md);">
            🔄 Restore Case
        </button>
    </div>
</div>
{% endif %}
```

**Disabled Functions:**

Wrap file operation buttons with archive check:

```html
{% if case.status != 'Archived' %}
    <button onclick="reindexFile({{ file.id }})">Re-Index</button>
    <button onclick="uploadFiles()">Upload Files</button>
    <!-- etc -->
{% else %}
    <button disabled title="Cannot re-index archived cases">Re-Index</button>
    <button disabled title="Cannot upload to archived cases">Upload Files</button>
    <!-- etc -->
{% endif %}
```

**Status Change Modal:**

Add confirmation when changing to/from Archived status:

```html
<div id="archiveConfirmModal" class="modal">
    <div class="modal-content">
        <h3>Archive Case?</h3>
        <p>This will:</p>
        <ul>
            <li>Create a ZIP archive of all case files</li>
            <li>Store archive at: <span id="archivePath"></span></li>
            <li>Remove original files from working set</li>
            <li>Disable re-indexing and file uploads</li>
            <li>Keep all indexed data searchable</li>
        </ul>
        <p><strong>Estimated archive size: <span id="archiveSize"></span></strong></p>
        <div class="modal-actions">
            <button onclick="confirmArchive()" class="btn btn-danger">Archive</button>
            <button onclick="closeModal()" class="btn btn-secondary">Cancel</button>
        </div>
    </div>
</div>

<div id="restoreConfirmModal" class="modal">
    <div class="modal-content">
        <h3>Restore Archived Case?</h3>
        <p>This will:</p>
        <ul>
            <li>Extract all files from archive</li>
            <li>Restore files to original locations</li>
            <li>Delete archive ZIP after successful restore</li>
            <li>Re-enable all file operations</li>
        </ul>
        <label for="newStatus">New Status:</label>
        <select id="newStatus" class="form-input">
            <option value="New">New</option>
            <option value="In Progress">In Progress</option>
            <option value="Assigned">Assigned</option>
            <option value="Completed">Completed</option>
        </select>
        <div class="modal-actions">
            <button onclick="confirmRestore()" class="btn btn-success">Restore</button>
            <button onclick="closeModal()" class="btn btn-secondary">Cancel</button>
        </div>
    </div>
</div>
```

**Progress Modals:**

Reuse existing progress modal pattern from AI Reports/Timelines:

```html
<div id="archiveProgressModal" class="modal">
    <div class="modal-content">
        <h3 id="archiveProgressTitle">Archiving Case...</h3>
        <div class="progress-bar">
            <div id="archiveProgressBar" style="width: 0%;"></div>
        </div>
        <p id="archiveProgressMessage">Preparing...</p>
        <p id="archiveProgressDetails"></p>
    </div>
</div>
```

**JavaScript Functions:**

```javascript
function showArchiveConfirm() {
    // Get estimated size
    fetch(`/case/${caseId}/files/size`)
        .then(r => r.json())
        .then(data => {
            document.getElementById('archiveSize').textContent = data.size_display;
            document.getElementById('archivePath').textContent = data.archive_path;
            showModal('archiveConfirmModal');
        });
}

function confirmArchive() {
    closeModal();
    showModal('archiveProgressModal');
    
    fetch(`/case/${caseId}/archive`, {
        method: 'POST',
        credentials: 'same-origin'
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            pollArchiveProgress(data.task_id);
        } else {
            alert('Archive failed: ' + data.message);
            closeModal();
        }
    });
}

function pollArchiveProgress(taskId) {
    const interval = setInterval(() => {
        fetch(`/case/${caseId}/archive/status?task_id=${taskId}`)
            .then(r => r.json())
            .then(data => {
                updateProgressBar('archiveProgressBar', data.progress);
                document.getElementById('archiveProgressMessage').textContent = data.message;
                
                if (data.status === 'complete') {
                    clearInterval(interval);
                    setTimeout(() => {
                        location.reload();
                    }, 2000);
                } else if (data.status === 'error') {
                    clearInterval(interval);
                    alert('Archive failed: ' + data.message);
                    closeModal();
                }
            });
    }, 2000);
}

// Similar functions for restore process
```

**Testing:**
- Test archive button appears correctly
- Test disabled state on archived cases
- Test progress modal during archive
- Test warning banner display
- Test restore modal and process
- Test status change validation

---

### Phase 4: Backend Validation & Guards

**Files to Modify:**
- `app/routes/files.py` - Add archive checks to file operations
- `app/tasks.py` - Add archive checks to process_file task
- `app/main.py` - Add archive validation to status changes

**Validation Function (`app/archive_utils.py`):**

```python
def is_case_archived(case) -> bool:
    """Check if case is archived"""
    return case.status == 'Archived'

def require_unarchived_case(case) -> tuple:
    """
    Decorator helper to block operations on archived cases
    
    Returns:
        (is_archived, error_response)
    """
    if is_case_archived(case):
        return True, jsonify({
            'success': False,
            'error': 'Cannot perform this operation on an archived case. Please restore the case first.'
        }), 403
    return False, None
```

**Add Guards to File Operations:**

```python
# In routes/files.py

@files_bp.route('/case/<int:case_id>/files/upload', methods=['POST'])
@login_required
def upload_files_route(case_id):
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    # GUARD: Block uploads to archived cases
    archived, error_response = require_unarchived_case(case)
    if archived:
        return error_response
    
    # Continue with normal upload logic...

@files_bp.route('/files/<int:file_id>/reindex', methods=['POST'])
@login_required
def reindex_single_file(file_id):
    case_file = db.session.get(CaseFile, file_id)
    if not case_file:
        return jsonify({'success': False, 'error': 'File not found'}), 404
    
    case = case_file.case
    
    # GUARD: Block re-index on archived cases
    archived, error_response = require_unarchived_case(case)
    if archived:
        return error_response
    
    # Continue with normal re-index logic...

# Add similar guards to:
# - bulk_reindex_selected()
# - bulk_rechainsaw()
# - delete_file()
# - bulk_delete_files()
# - All other file mutation operations
```

**Add Guard to Celery Tasks:**

```python
# In tasks.py

@celery_app.task(bind=True, name='tasks.process_file')
def process_file(self, file_id, operation='full'):
    # ... existing code ...
    
    # GUARD: Block file processing on archived cases
    if case.status == 'Archived' and operation in ['full', 'reindex', 'chainsaw_only']:
        error_msg = f'Cannot process files in archived case (operation={operation})'
        logger.error(f"[TASK] {error_msg}")
        case_file.indexing_status = 'Failed'
        case_file.error_message = error_msg
        case_file.celery_task_id = None
        db.session.commit()
        return {'status': 'error', 'message': error_msg}
    
    # Allow ioc_only operation (doesn't need source files)
    if case.status == 'Archived' and operation != 'ioc_only':
        error_msg = f'Cannot re-index/re-sigma archived case (operation={operation}). Re-hunt IOCs is allowed.'
        logger.error(f"[TASK] {error_msg}")
        case_file.indexing_status = 'Failed'
        case_file.error_message = error_msg
        case_file.celery_task_id = None
        db.session.commit()
        return {'status': 'error', 'message': error_msg}
    
    # Continue with normal processing...
```

**Testing:**
- Test each guarded endpoint with archived case
- Verify 403 error returned
- Verify error messages are clear
- Test that ioc_only still works
- Test all bulk operations blocked

---

### Phase 5: Audit Logging & Documentation

**Files to Modify:**
- `app/audit_logger.py` - Add archive events
- `app/version.json` - Add feature entry
- `app/APP_MAP.md` - Document archive feature

**Audit Events:**

```python
# Archive events
log_action(db, 'case_archive_initiated', case_id, user_id)
log_action(db, 'case_archive_completed', case_id, user_id, details={'archive_path': path, 'size_mb': size})
log_action(db, 'case_archive_failed', case_id, user_id, details={'error': error})

log_action(db, 'case_restore_initiated', case_id, user_id)
log_action(db, 'case_restore_completed', case_id, user_id, details={'files_restored': count})
log_action(db, 'case_restore_failed', case_id, user_id, details={'error': error})

log_action(db, 'archive_path_configured', None, user_id, details={'path': path})
```

**Version Entry:**

```json
{
  "version": "1.18.0",
  "release_date": "2025-11-21",
  "changes": [
    "🗄️ NEW FEATURE: Case Archiving - Archive case files to cold storage while retaining all indexed data. Archive path configurable in System Settings. Files stored as ZIP with original directory structure preserved. Archived cases show warning banner, disable re-index/upload operations, but retain full search/analysis capabilities. IOC re-hunting fully supported on archived cases. Seamless restore process with progress tracking. Perfect for freeing SSD space while maintaining long-term case accessibility."
  ]
}
```

**Testing:**
- Verify all audit events logged
- Check audit log entries are detailed
- Verify version.json updated
- Verify APP_MAP.md updated

---

## Breaking Changes Prevention

### Strategy: Additive-Only Changes

**Principle:** Only ADD new functionality, never REMOVE or CHANGE existing behavior.

### 1. Database Changes are Additive
- ✅ New columns added to `case` table (archive_path, archived_at, etc.)
- ✅ New `app_settings` table created
- ✅ Existing columns unchanged
- ✅ Existing data unaffected

### 2. New Status Value is Optional
- ✅ "Archived" is a new status value
- ✅ Existing statuses (New, In Progress, etc.) unchanged
- ✅ Existing cases remain functional
- ✅ No forced status migrations

### 3. Guards are Defensive
- ✅ Archive checks only trigger if `status == 'Archived'`
- ✅ Non-archived cases behave exactly as before
- ✅ No performance impact on existing workflows

### 4. UI Changes are Conditional
- ✅ Archive warning only shows if `status == 'Archived'`
- ✅ Disabled buttons only affect archived cases
- ✅ Non-archived cases see no UI changes

### 5. Backward Compatibility
- ✅ Feature is opt-in (user must configure archive path)
- ✅ Feature is user-initiated (admin archives case)
- ✅ Feature can be disabled (don't set archive path)
- ✅ Existing cases continue working identically

### 6. Rollback Safety
- ✅ Migration can be reversed (drop columns)
- ✅ No data loss risk (original files deleted AFTER zip verified)
- ✅ Archive path stored in DB (can restore if needed)
- ✅ Audit log tracks all archive/restore operations

---

## Testing Strategy

### Unit Tests

```python
# tests/test_archive.py

def test_validate_archive_path_exists():
    """Test archive path validation"""
    pass

def test_validate_archive_path_writable():
    """Test write permission check"""
    pass

def test_get_case_file_size():
    """Test size calculation"""
    pass

def test_archive_case_creates_zip():
    """Test ZIP creation"""
    pass

def test_archive_case_preserves_structure():
    """Test directory structure in ZIP"""
    pass

def test_archive_case_verifies_integrity():
    """Test ZIP integrity check"""
    pass

def test_archive_case_removes_originals():
    """Test original files deleted"""
    pass

def test_restore_case_extracts_files():
    """Test ZIP extraction"""
    pass

def test_restore_case_sets_permissions():
    """Test casescope:casescope ownership"""
    pass

def test_restore_case_verifies_count():
    """Test all files restored"""
    pass

def test_archived_case_blocks_reindex():
    """Test re-index blocked"""
    pass

def test_archived_case_blocks_upload():
    """Test upload blocked"""
    pass

def test_archived_case_allows_ioc_hunt():
    """Test IOC hunting still works"""
    pass

def test_archived_case_allows_search():
    """Test search still works"""
    pass
```

### Integration Tests

1. **Small Case Test (10 files, 100MB)**
   - Archive → Verify ZIP → Delete originals → Search events → Re-hunt IOCs → Restore

2. **Medium Case Test (1000 files, 5GB)**
   - Archive → Verify no data loss → Test all disabled functions → Restore

3. **Large Case Test (5000 files, 50GB)**
   - Archive → Verify progress tracking → Test performance → Restore

4. **Multi-Case Test**
   - Archive Case A → Archive Case B → Search both → Restore Case A → Verify Case B still archived

5. **Failure Scenarios**
   - Disk full during archive
   - Network disconnect during restore
   - ZIP corruption
   - Permission errors
   - Concurrent archive attempts

### Manual Testing Checklist

- [ ] Configure archive path in settings
- [ ] Archive small test case
- [ ] Verify ZIP created
- [ ] Verify original files deleted
- [ ] Verify folder structure preserved
- [ ] Verify archive warning displays
- [ ] Verify re-index button disabled
- [ ] Verify upload button disabled
- [ ] Verify search still works
- [ ] Verify IOC re-hunt still works
- [ ] Verify AI reports still work
- [ ] Restore case
- [ ] Verify all files restored
- [ ] Verify permissions correct
- [ ] Verify all functions re-enabled
- [ ] Archive large case (5000+ files)
- [ ] Test progress modal during archive
- [ ] Test progress modal during restore
- [ ] Test error handling (disk full)
- [ ] Test concurrent archive attempts
- [ ] Test audit log entries

---

## Rollback Plan

### If Critical Issues Found

**Step 1: Disable Feature in UI**

```python
# In settings page or main.py
ARCHIVE_FEATURE_ENABLED = False

# Wrap all archive UI elements
{% if ARCHIVE_FEATURE_ENABLED %}
    <!-- archive buttons -->
{% endif %}
```

**Step 2: Block Archive Routes**

```python
# In routes/archive.py
@archive_bp.before_request
def check_feature_flag():
    if not ARCHIVE_FEATURE_ENABLED:
        abort(404)
```

**Step 3: Restore Any Archived Cases**

```bash
# Emergency restore script
sudo -u casescope python3 -c "
from app import create_app, db
from app.models import Case
from app.archive_utils import restore_case

app = create_app()
with app.app_context():
    archived_cases = Case.query.filter_by(status='Archived').all()
    for case in archived_cases:
        print(f'Restoring case {case.id}...')
        result = restore_case(db, case.id, user_id=1)
        print(result)
"
```

**Step 4: Revert Database (if needed)**

```python
# app/migrations/remove_archive_fields.py

import sqlite3

def rollback_migration():
    db_path = '/opt/casescope/app/casescope.db'
    
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        
        # Remove archive fields (note: SQLite doesn't support DROP COLUMN before 3.35.0)
        # Instead, update any archived cases back to 'In Progress'
        cursor.execute('UPDATE "case" SET status = "In Progress" WHERE status = "Archived";')
        
        # Drop app_settings table
        cursor.execute('DROP TABLE IF EXISTS app_settings;')
        
        conn.commit()
```

**Step 5: Remove Archive Files**

```python
# Delete archive blueprints
rm /opt/casescope/app/routes/archive.py
rm /opt/casescope/app/archive_utils.py
rm /opt/casescope/app/tasks_archive.py

# Revert modified files from git
cd /opt/casescope
git checkout app/models.py
git checkout app/templates/view_case.html
# ... etc
```

---

## Summary

### Implementation Estimate

| Phase | Effort | Risk | Priority |
|-------|--------|------|----------|
| Phase 1: Foundation | 4 hours | Low | High |
| Phase 2: Archive Process | 8 hours | Medium | High |
| Phase 3: UI Integration | 6 hours | Low | High |
| Phase 4: Backend Guards | 4 hours | Low | High |
| Phase 5: Audit & Docs | 2 hours | Low | Medium |
| **Total** | **24 hours** | **Low-Medium** | **High** |

### Key Benefits

1. **Space Savings** - Free up SSD space by moving old cases to spinning disks
2. **Cost Efficiency** - Retain searchable data without expensive fast storage
3. **Data Retention** - Keep cases indefinitely without performance impact
4. **User Experience** - Seamless archive/restore with progress tracking
5. **Safety** - Multiple verification steps, audit logging, rollback plan

### Risk Mitigation

- **Data Loss** - ZIP verified before originals deleted
- **Corruption** - Integrity checks at multiple stages
- **Performance** - Async tasks prevent UI blocking
- **Permissions** - Explicit ownership checks and corrections
- **Breaking Changes** - Additive-only implementation strategy
- **Rollback** - Clear procedure to revert if needed

### Recommendation

**PROCEED WITH IMPLEMENTATION** ✅

This feature is:
- Well-scoped and clearly defined
- Low risk to existing functionality
- High value for long-term case management
- Properly architected with safety guards
- Fully reversible if issues arise

The implementation follows CaseScope best practices:
- Modular code organization
- Async tasks for long operations
- Progress tracking for user feedback
- Comprehensive audit logging
- Backward compatibility maintained

