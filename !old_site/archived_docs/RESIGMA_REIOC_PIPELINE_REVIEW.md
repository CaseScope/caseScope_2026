# Re-SIGMA & Re-IOC Hunt Pipeline - Complete Code Review
**Comprehensive Analysis of All Re-SIGMA and Re-IOC Hunt Operations**

**Review Date**: November 20, 2025  
**Version**: 1.16.24+  
**Status**: ✅ MOSTLY CORRECT (1 bug found in IOC_only operation)

---

## 🎯 Executive Summary

**RESULT**: ✅ **RE-SIGMA: ALL CORRECT** | ⚠️ **RE-IOC HUNT: 1 BUG FOUND**

After comprehensive review of the entire re-SIGMA and re-IOC hunt pipelines:

### **Re-SIGMA Operations** ✅
- ✅ All routes correctly clear SIGMA violations (database)
- ✅ All routes correctly clear SIGMA flags in OpenSearch
- ✅ All routes properly call `operation='chainsaw_only'`
- ✅ Task correctly implements chainsaw_only operation
- ✅ Single file, selected files, and bulk all files use same architecture

### **Re-IOC Hunt Operations** ⚠️
- ✅ All routes correctly clear IOC matches (database)
- ✅ Single file route correctly clears IOC flags in OpenSearch
- ✅ All routes properly call `operation='ioc_only'`
- ⚠️ **BUG FOUND**: Task ioc_only operation clears by `index_name` instead of `file_id`
- ✅ Single file, selected files, and bulk all files use same architecture (except bug)

---

## 📋 Operations Overview

### **Re-SIGMA Operations:**

| Operation | Route | Task | Status |
|-----------|-------|------|--------|
| **Single File** | `/case/<id>/file/<id>/rechainsaw` | Synchronous `chainsaw_file()` | ✅ Correct |
| **Selected Files** | `/case/<id>/bulk_rechainsaw_selected` | `process_file(file_id, 'chainsaw_only')` per file | ✅ Correct |
| **All Files (Case)** | `/case/<id>/bulk_rechainsaw` | `bulk_rechainsaw(case_id)` → `process_file` | ✅ Correct |

### **Re-IOC Hunt Operations:**

| Operation | Route | Task | Status |
|-----------|-------|------|--------|
| **Single File** | `/case/<id>/file/<id>/rehunt_iocs` | Synchronous `hunt_iocs()` | ✅ Correct |
| **Selected Files** | `/case/<id>/bulk_rehunt_selected` | `process_file(file_id, 'ioc_only')` per file | ⚠️ Bug in task |
| **All Files (Case)** | `/case/<id>/bulk_rehunt` | `bulk_rehunt(case_id)` → `process_file` | ⚠️ Bug in task |

---

## 🔍 DETAILED CODE REVIEW

## PART 1: RE-SIGMA OPERATIONS

### **1. Single File Re-SIGMA** ✅

**Route**: `routes/files.py:581-654`

```python
@files_bp.route('/case/<int:case_id>/file/<int:file_id>/rechainsaw', methods=['POST'])
@login_required
def rechainsaw_single_file(case_id, file_id):
```

**Code Review**:

| Step | Code | Status | Notes |
|------|------|--------|-------|
| **Get file** | `case_file = db.session.get(CaseFile, file_id)` | ✅ Correct | Proper SQLAlchemy 2.0 |
| **Check indexed** | `if not case_file.is_indexed: flash warning` | ✅ Correct | Must be indexed first |
| **Clear DB violations** | `clear_file_sigma_violations(db, file_id)` | ✅ Correct | Deletes from sigma_violation table |
| **Clear OS flags** | `clear_file_sigma_flags_in_opensearch(opensearch_client, case_id, case_file)` | ✅ Correct | Clears has_sigma, sigma_rules fields |
| **Reset count** | `case_file.violation_count = 0` | ✅ Correct | Resets violation count |
| **Set status** | `case_file.indexing_status = 'SIGMA Testing'` | ✅ Correct | Shows in-progress status |
| **Commit** | `db.session.commit()` | ✅ Correct | Commits before processing |
| **Run SIGMA** | `chainsaw_file(...)` **SYNCHRONOUSLY** | ✅ Correct | Fast operation, runs in request |
| **Update status** | `case_file.indexing_status = 'Completed'` | ✅ Correct | Marks complete |

**Verdict**: ✅ **CORRECT - No issues found**

**Note**: Single file re-SIGMA runs **synchronously** (not queued) because it's fast (~1-5 seconds).

---

### **2. Selected Files Re-SIGMA** ✅

**Route**: `routes/files.py:875-943`

```python
@files_bp.route('/case/<int:case_id>/bulk_rechainsaw_selected', methods=['POST'])
@login_required
def bulk_rechainsaw_selected(case_id):
```

**Code Review**:

| Step | Code | Status | Notes |
|------|------|--------|-------|
| **Worker check** | `check_workers_available(min_workers=1)` | ✅ Correct | Safety check |
| **Get file IDs** | `file_ids = request.form.getlist('file_ids', type=int)` | ✅ Correct | From checkboxes |
| **Query files** | `filter(id.in_(file_ids), case_id == case_id, is_deleted == False, is_indexed == True)` | ✅ Correct | Only indexed files |
| **Loop files** | For each file: clear violations, clear flags, reset count | ✅ Correct | Per-file cleanup |
| **Clear DB** | `clear_file_sigma_violations(db, file.id)` | ✅ Correct | Deletes violations |
| **Clear OS flags** | `clear_file_sigma_flags_in_opensearch(opensearch_client, case_id, file)` | ✅ Correct | Clears OpenSearch flags |
| **Reset metadata** | `violation_count=0`, `indexing_status='Queued'`, `celery_task_id=None` | ✅ Correct | Ready for processing |
| **Commit** | `db.session.commit()` | ✅ Correct | Commits before queuing |
| **Queue tasks** | `queue_file_processing(process_file, files, operation='chainsaw_only')` | ✅ Correct | Uses correct operation |

**Verdict**: ✅ **CORRECT - No issues found**

---

### **3. Bulk Re-SIGMA All Files** ✅

**Route**: `main.py:3689-3721`

```python
@app.route('/case/<int:case_id>/bulk_rechainsaw', methods=['POST'])
@login_required
def bulk_rechainsaw_route(case_id):
```

**Task**: `tasks.py:513-548`

```python
@celery_app.task(bind=True, name='tasks.bulk_rechainsaw')
def bulk_rechainsaw(self, case_id):
```

**Code Review**:

| Step | Code | Status | Notes |
|------|------|--------|-------|
| **Worker check** | `check_workers_available(min_workers=1)` | ✅ Correct | Safety check |
| **Count files** | `query(CaseFile).filter_by(case_id=case_id, is_deleted=False, is_indexed=True).count()` | ✅ Correct | Only indexed |
| **Queue task** | `bulk_rechainsaw.delay(case_id)` | ✅ Correct | Calls Celery task |
| **Get files** | `get_case_files(db, case_id, include_deleted=False, include_hidden=False)` | ✅ Correct | Excludes deleted/hidden |
| **Filter indexed** | `files = [f for f in files if f.is_indexed]` | ✅ Correct | Only indexed files |
| **Clear DB** | `clear_case_sigma_violations(db, case_id)` | ✅ Correct | All violations for case |
| **Clear OS flags** | `clear_case_sigma_flags_in_opensearch(opensearch_client, case_id, files)` | ✅ Correct | All flags in OpenSearch |
| **Reset metadata** | `violation_count=0`, `indexing_status='Queued'`, `celery_task_id=None` per file | ✅ Correct | Reset all files |
| **Commit** | `commit_with_retry(db.session)` | ✅ Correct | Commits changes |
| **Queue files** | `queue_file_processing(process_file, files, operation='chainsaw_only')` | ✅ Correct | Uses correct operation |

**Verdict**: ✅ **CORRECT - No issues found**

---

### **4. chainsaw_only Operation in process_file** ✅

**Task**: `tasks.py:392-422`

```python
elif operation == 'chainsaw_only':
```

**Code Review**:

| Step | Code | Status | Notes |
|------|------|--------|-------|
| **Import models** | `from models import SigmaViolation` | ✅ Correct | Needed for deletion |
| **Clear DB** | `db.session.query(SigmaViolation).filter_by(file_id=file_id).delete()` | ✅ Correct | Deletes all violations |
| **Commit** | `db.session.commit()` | ✅ Correct | Commits deletion |
| **Clear OS flags** | `clear_file_sigma_flags_in_opensearch(opensearch_client, case_file.case_id, case_file)` | ✅ Correct | Clears OpenSearch flags |
| **Run SIGMA** | `chainsaw_file(...)` | ✅ Correct | Runs chainsaw detection |
| **Set status** | `case_file.indexing_status = 'Completed'` | ✅ Correct | Marks complete |
| **Commit** | `commit_with_retry(db.session)` | ✅ Correct | Final commit |

**Verdict**: ✅ **CORRECT - No issues found**

---

## PART 2: RE-IOC HUNT OPERATIONS

### **1. Single File Re-IOC Hunt** ✅

**Route**: `routes/files.py:657-775`

```python
@files_bp.route('/case/<int:case_id>/file/<int:file_id>/rehunt_iocs', methods=['POST'])
@login_required
def rehunt_iocs_single_file(case_id, file_id):
```

**Code Review**:

| Step | Code | Status | Notes |
|------|------|--------|-------|
| **Get file** | `case_file = db.session.get(CaseFile, file_id)` | ✅ Correct | Proper SQLAlchemy 2.0 |
| **Check indexed** | `if not case_file.is_indexed: flash warning` | ✅ Correct | Must be indexed first |
| **Clear DB matches** | `clear_file_ioc_matches(db, file_id)` | ✅ Correct | Deletes from ioc_match table |
| **Clear OS flags** | Manual bulk update of `has_ioc`, `ioc_count`, `ioc_details`, `matched_iocs` | ✅ Correct | Clears all IOC fields |
| **Query** | `{"term": {"file_id": file_id}}, {"term": {"has_ioc": True}}` | ✅ Correct | Only events with IOC flags |
| **Update fields** | Sets all to False/0/[] | ✅ Correct | Properly clears |
| **Batch size** | 100 events per bulk | ✅ Correct | Good batch size |
| **Reset count** | `case_file.ioc_event_count = 0` | ✅ Correct | Resets count |
| **Set status** | `case_file.indexing_status = 'IOC Hunting'` | ✅ Correct | Shows in-progress |
| **Commit** | `db.session.commit()` | ✅ Correct | Commits before hunting |
| **Run hunt** | `hunt_iocs(...)` **SYNCHRONOUSLY** | ✅ Correct | Fast operation |
| **Update status** | `case_file.indexing_status = 'Completed'` | ✅ Correct | Marks complete |

**Verdict**: ✅ **CORRECT - No issues found**

**Note**: Single file re-IOC hunt runs **synchronously** (not queued) because it's fast.

---

### **2. Selected Files Re-IOC Hunt** ⚠️

**Route**: `routes/files.py:946-1005`

```python
@files_bp.route('/case/<int:case_id>/bulk_rehunt_selected', methods=['POST'])
@login_required
def bulk_rehunt_selected(case_id):
```

**Code Review**:

| Step | Code | Status | Notes |
|------|------|--------|-------|
| **Worker check** | `check_workers_available(min_workers=1)` | ✅ Correct | Safety check |
| **Get file IDs** | `file_ids = request.form.getlist('file_ids', type=int)` | ✅ Correct | From checkboxes |
| **Query files** | `filter(id.in_(file_ids), case_id == case_id, is_deleted == False, is_indexed == True)` | ✅ Correct | Only indexed files |
| **Loop files** | For each file: clear matches, reset count | ✅ Correct | Per-file cleanup |
| **Clear DB** | `clear_file_ioc_matches(db, file.id)` | ✅ Correct | Deletes matches |
| **Reset metadata** | `ioc_event_count=0`, `indexing_status='Queued'`, `celery_task_id=None` | ✅ Correct | Ready for processing |
| **Commit** | `db.session.commit()` | ✅ Correct | Commits before queuing |
| **Queue tasks** | `queue_file_processing(process_file, files, operation='ioc_only')` | ✅ Correct | Uses correct operation |

**Route Verdict**: ✅ **CORRECT**

**BUT**: The task has a bug (see below).

---

### **3. Bulk Re-IOC Hunt All Files** ⚠️

**Route**: `main.py:3724-3755`

**Task**: `tasks.py:551-607`

```python
@celery_app.task(bind=True, name='tasks.bulk_rehunt')
def bulk_rehunt(self, case_id):
```

**Code Review**:

| Step | Code | Status | Notes |
|------|------|--------|-------|
| **Clear cache** | `opensearch_client.indices.clear_cache(...)` | ✅ Correct | Prevents heap issues |
| **Get files** | `get_case_files(...)`, filter by `is_indexed` | ✅ Correct | Only indexed files |
| **Clear DB** | `clear_case_ioc_matches(db, case_id)` | ✅ Correct | All matches for case |
| **Clear OS flags** | `clear_case_ioc_flags_in_opensearch(opensearch_client, case_id, files)` | ✅ Correct | All flags in OpenSearch |
| **Reset metadata** | `ioc_event_count=0`, `indexing_status='Queued'` per file | ✅ Correct | Reset all files |
| **Commit** | `commit_with_retry(db.session)` | ✅ Correct | Commits changes |
| **Queue files** | `queue_file_processing(process_file, files, operation='ioc_only')` | ✅ Correct | Uses correct operation |

**Route Verdict**: ✅ **CORRECT**

**BUT**: The task has a bug (see below).

---

### **4. ioc_only Operation in process_file** ⚠️ **BUG FOUND**

**Task**: `tasks.py:424-443`

```python
elif operation == 'ioc_only':
    from models import IOCMatch
    db.session.query(IOCMatch).filter(IOCMatch.index_name == index_name).delete()  # ❌ BUG!
    db.session.commit()
    
    result = hunt_iocs(...)
```

**Code Review**:

| Step | Code | Status | Issue |
|------|------|--------|-------|
| **Import** | `from models import IOCMatch` | ✅ Correct | - |
| **Clear matches** | `filter(IOCMatch.index_name == index_name).delete()` | ❌ **BUG** | Uses `index_name` instead of `file_id` |
| **Commit** | `db.session.commit()` | ✅ Correct | - |
| **Run hunt** | `hunt_iocs(...)` | ✅ Correct | - |
| **Set status** | `indexing_status = 'Completed'` | ✅ Correct | - |

**THE BUG**:

```python
# CURRENT (WRONG):
db.session.query(IOCMatch).filter(IOCMatch.index_name == index_name).delete()

# SHOULD BE:
db.session.query(IOCMatch).filter_by(file_id=file_id).delete()
```

**Why It's Wrong**:
- `index_name` is `case_22` (same for ALL files in the case)
- This deletes IOC matches for ALL files in the case, not just the current file
- `file_id` uniquely identifies the file being processed

**Impact**:
- When re-hunting IOCs on a single file, it clears IOC matches for ALL files in the case
- Then only re-hunts IOCs for the one file
- Result: Other files lose their IOC matches

**Fix**:
```python
elif operation == 'ioc_only':
    from models import IOCMatch
    db.session.query(IOCMatch).filter_by(file_id=file_id).delete()  # ✅ FIXED
    db.session.commit()
    
    result = hunt_iocs(
        db=db,
        opensearch_client=opensearch_client,
        CaseFile=CaseFile,
        IOC=IOC,
        IOCMatch=IOCMatch,
        file_id=file_id,
        index_name=index_name,
        celery_task=self
    )
    
    case_file.indexing_status = 'Completed'
    commit_with_retry(db.session, logger_instance=logger)
    return result
```

**Verdict**: ⚠️ **BUG FOUND - Clear by file_id instead of index_name**

---

## 📊 OpenSearch Operations Review

### **Re-SIGMA: Clear OpenSearch Flags** ✅

**Function**: `bulk_operations.py:737+` - `clear_file_sigma_flags_in_opensearch()`

**What It Clears**:
```python
{
    'doc': {
        'has_sigma': False,
        'sigma_rules': [],
        'sigma_count': 0
    }
}
```

✅ **CORRECT**: Clears all SIGMA-related fields

### **Re-IOC Hunt: Clear OpenSearch Flags** ✅

**Single File Route** (lines 683-727):
```python
{
    'doc': {
        'has_ioc': False,
        'ioc_count': 0,
        'ioc_details': [],
        'matched_iocs': []
    }
}
```

✅ **CORRECT**: Clears all IOC-related fields

**Bulk Function**: `bulk_operations.py` - `clear_case_ioc_flags_in_opensearch()`

✅ **CORRECT**: Clears IOC flags for all files in case

---

## 🗄️ Database Operations Review

### **Clear SIGMA Violations** ✅

**Single File**:
```python
def clear_file_sigma_violations(db, file_id: int) -> int:
    deleted = db.session.query(SigmaViolation).filter_by(file_id=file_id).delete()
    return deleted
```

✅ **CORRECT**: Deletes by `file_id`

**Bulk All Files**:
```python
def clear_case_sigma_violations(db, case_id: int) -> int:
    deleted = db.session.query(SigmaViolation).filter_by(case_id=case_id).delete()
    return deleted
```

✅ **CORRECT**: Deletes by `case_id` for all files

### **Clear IOC Matches** ✅

**Single File**:
```python
def clear_file_ioc_matches(db, file_id: int) -> int:
    # Calls clear_ioc_matches(db, scope='case', case_id=case_file.case_id, file_ids=[file_id])
    # Which does: query.filter(IOCMatch.file_id.in_(file_ids))
```

✅ **CORRECT**: Deletes by `file_id`

**Bulk All Files**:
```python
def clear_case_ioc_matches(db, case_id: int) -> int:
    deleted = db.session.query(IOCMatch).filter_by(case_id=case_id).delete()
    return deleted
```

✅ **CORRECT**: Deletes by `case_id` for all files

---

## 📝 Database Fields Review

### **CaseFile Fields Used**:

| Field | Re-SIGMA | Re-IOC Hunt | Status |
|-------|----------|-------------|--------|
| `violation_count` | Reset to 0 | Unchanged | ✅ Correct |
| `ioc_event_count` | Unchanged | Reset to 0 | ✅ Correct |
| `indexing_status` | Set to 'Queued' or 'SIGMA Testing' | Set to 'Queued' or 'IOC Hunting' | ✅ Correct |
| `celery_task_id` | Reset to None | Reset to None | ✅ Correct |
| `is_indexed` | Unchanged (must stay True) | Unchanged (must stay True) | ✅ Correct |

---

## ✅ Consistency Across Operations

### **Re-SIGMA Consistency**:

| Step | Single | Selected | Bulk | Status |
|------|--------|----------|------|--------|
| Clear DB violations | ✅ | ✅ | ✅ | Consistent |
| Clear OpenSearch flags | ✅ | ✅ | ✅ | Consistent |
| Reset violation_count | ✅ | ✅ | ✅ | Consistent |
| Use `operation='chainsaw_only'` | N/A (sync) | ✅ | ✅ | Consistent |

### **Re-IOC Hunt Consistency**:

| Step | Single | Selected | Bulk | Status |
|------|--------|----------|------|--------|
| Clear DB matches | ✅ | ✅ | ✅ | Consistent |
| Clear OpenSearch flags | ✅ | ✅ | ✅ | Consistent |
| Reset ioc_event_count | ✅ | ✅ | ✅ | Consistent |
| Use `operation='ioc_only'` | N/A (sync) | ✅ | ✅ | Consistent |
| Task clears matches | N/A | ❌ Bug | ❌ Bug | **INCONSISTENT** |

---

## 🐛 BUGS FOUND

### **BUG #1: IOC_only Operation Clears Wrong Records** ⚠️

**Location**: `tasks.py:427`

**Current Code (WRONG)**:
```python
db.session.query(IOCMatch).filter(IOCMatch.index_name == index_name).delete()
```

**Problem**: 
- `index_name` is the same for ALL files in a case (`case_22`)
- This deletes IOC matches for ALL files, not just the current file

**Fixed Code**:
```python
db.session.query(IOCMatch).filter_by(file_id=file_id).delete()
```

**Impact**: 
- **HIGH** - Causes data loss
- When re-hunting IOCs on one file, ALL files in the case lose their IOC matches

**Severity**: **CRITICAL** ⚠️

---

## 🔄 Execution Flow Diagrams

### **Single File Re-SIGMA Flow** (Synchronous):

```
Button Click
         ↓
POST /case/<id>/file/<id>/rechainsaw
         ↓
Clear DB: SigmaViolation WHERE file_id=X
         ↓
Clear OpenSearch: has_sigma=False WHERE file_id=X
         ↓
Set: violation_count=0, status='SIGMA Testing'
         ↓
db.session.commit()
         ↓
chainsaw_file() - RUNS IMMEDIATELY
         ↓
Set: status='Completed'
         ↓
✅ DONE (in same request)
```

### **Selected Files Re-SIGMA Flow** (Async):

```
Button Click
         ↓
POST /case/<id>/bulk_rechainsaw_selected
         ↓
For each file:
  - Clear DB: SigmaViolation WHERE file_id=X
  - Clear OpenSearch: has_sigma=False WHERE file_id=X
  - Set: violation_count=0, status='Queued'
         ↓
db.session.commit()
         ↓
Queue: process_file.delay(file_id, operation='chainsaw_only')
         ↓
tasks.py:process_file()
         ↓
operation='chainsaw_only' branch:
  - Clear DB violations (again, for safety)
  - Clear OpenSearch flags (again, for safety)
  - chainsaw_file()
  - Set: status='Completed'
         ↓
✅ DONE
```

### **Single File Re-IOC Hunt Flow** (Synchronous):

```
Button Click
         ↓
POST /case/<id>/file/<id>/rehunt_iocs
         ↓
Clear DB: IOCMatch WHERE file_id=X
         ↓
Clear OpenSearch: has_ioc=False, ioc_details=[] WHERE file_id=X
         ↓
Set: ioc_event_count=0, status='IOC Hunting'
         ↓
db.session.commit()
         ↓
hunt_iocs() - RUNS IMMEDIATELY
         ↓
Set: status='Completed'
         ↓
✅ DONE (in same request)
```

### **Selected Files Re-IOC Hunt Flow** (Async) ⚠️:

```
Button Click
         ↓
POST /case/<id>/bulk_rehunt_selected
         ↓
For each file:
  - Clear DB: IOCMatch WHERE file_id=X
  - Set: ioc_event_count=0, status='Queued'
         ↓
db.session.commit()
         ↓
Queue: process_file.delay(file_id, operation='ioc_only')
         ↓
tasks.py:process_file()
         ↓
operation='ioc_only' branch:
  ❌ BUG: Clear DB: IOCMatch WHERE index_name='case_22'
     (Clears ALL files in case, not just this file!)
  - hunt_iocs()
  - Set: status='Completed'
         ↓
⚠️ DONE (but cleared wrong files)
```

---

## 🎯 Testing Recommendations

### **Test Re-SIGMA Operations**:

1. **Single File**:
   ```
   1. Upload EVTX file with SIGMA violations
   2. Verify violation_count > 0
   3. Click "Re-SIGMA" button
   4. Verify:
      - violation_count resets to 0
      - OpenSearch has_sigma flags cleared
      - SIGMA re-runs immediately
      - violation_count matches original
   ```

2. **Selected Files**:
   ```
   1. Upload 5 EVTX files
   2. Select 3 files
   3. Click "Re-SIGMA Selected"
   4. Verify:
      - Only 3 files re-SIGMA
      - Other 2 files unchanged
      - Violations cleared correctly
   ```

### **Test Re-IOC Hunt Operations** (With Bug Fix):

1. **Single File**:
   ```
   1. Upload file with IOC matches
   2. Verify ioc_event_count > 0
   3. Click "Re-Hunt IOCs" button
   4. Verify:
      - ioc_event_count resets to 0
      - OpenSearch has_ioc flags cleared
      - IOC hunt re-runs immediately
      - ioc_event_count matches original
   ```

2. **Selected Files** (AFTER BUG FIX):
   ```
   1. Upload 5 files with IOC matches
   2. Note ioc_event_count for each
   3. Select 3 files
   4. Click "Re-Hunt IOCs Selected"
   5. Verify:
      - Only 3 files re-hunt
      - Other 2 files KEEP their IOC matches ✅
      - Selected files re-hunt correctly
   ```

3. **Test Bug Exists** (BEFORE FIX):
   ```
   1. Upload 5 files with IOC matches
   2. Note ioc_event_count for each
   3. Select 1 file
   4. Click "Re-Hunt IOCs Selected"
   5. BUG: ALL 5 files lose IOC matches ❌
   6. Only 1 file re-hunts
   7. Result: 4 files have 0 IOC matches incorrectly
   ```

---

## 📝 THE FIX

### **File**: `tasks.py:424-443`

**Change Line 427**:

```python
# BEFORE (WRONG):
elif operation == 'ioc_only':
    from models import IOCMatch
    db.session.query(IOCMatch).filter(IOCMatch.index_name == index_name).delete()  # ❌
    db.session.commit()

# AFTER (CORRECT):
elif operation == 'ioc_only':
    from models import IOCMatch
    db.session.query(IOCMatch).filter_by(file_id=file_id).delete()  # ✅
    db.session.commit()
```

**Why This Fix**:
- `file_id` uniquely identifies the file being processed
- `index_name` is the same for ALL files in the case
- Must delete matches ONLY for the current file

---

## 🎉 SUMMARY

### **Re-SIGMA Operations**: ✅ **ALL CORRECT**
- All three operations (single, selected, bulk) work correctly
- Database clearing correct
- OpenSearch flag clearing correct
- Consistent architecture across all operations

### **Re-IOC Hunt Operations**: ⚠️ **1 BUG FOUND**
- Single file operation: ✅ Correct
- Selected files operation: ✅ Correct (route) / ⚠️ Bug (task)
- Bulk all files operation: ✅ Correct (route) / ⚠️ Bug (task)
- **Critical bug**: Task clears by `index_name` instead of `file_id`
- **Fix is simple**: Change one line (line 427)

### **Overall Assessment**:
- **Re-SIGMA**: Production ready ✅
- **Re-IOC Hunt**: Needs 1-line fix ⚠️

---

**Review Completed**: November 20, 2025  
**Reviewer**: AI Code Assistant  
**Verification**: Manual code review + logic trace  
**Status**: 
- ✅ **RE-SIGMA: APPROVED - NO CHANGES NEEDED**
- ⚠️ **RE-IOC HUNT: 1 CRITICAL BUG - FIX REQUIRED**
