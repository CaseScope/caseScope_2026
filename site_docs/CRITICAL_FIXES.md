# Critical Bug Fixes - Ready to Apply

**Date**: November 20, 2025  
**Version**: 1.18.0  
**Priority**: Apply These First

---

## 🔴 FIX 1: Add Request Timeouts (30 minutes)

### opencti.py

**Find all requests calls and add timeout:**

```python
# BEFORE:
response = requests.get(url, headers=headers)
response = requests.post(url, json=data, headers=headers)

# AFTER:
response = requests.get(url, headers=headers, timeout=30)
response = requests.post(url, json=data, headers=headers, timeout=30)
```

**Locations to fix:**
```bash
cd /opt/casescope/app
grep -n "requests.get\|requests.post" opencti.py dfir_iris.py
```

### opencti.py - All Functions
```python
def enrich_ioc(ioc_value, ioc_type):
    try:
        response = requests.post(
            f"{OPENCTI_URL}/graphql",
            headers=headers,
            json=query,
            timeout=30  # ADD THIS
        )
        # ...
```

### dfir_iris.py - All Functions
```python
def create_case(case):
    try:
        response = requests.post(
            f"{IRIS_URL}/api/v2/cases",
            headers=headers,
            json=data,
            timeout=30  # ADD THIS
        )
        # ...
```

**Test**: Kill OpenCTI/DFIR-IRIS service, verify requests fail after 30 seconds

---

## 🔴 FIX 2: Add Pagination Validation (2 hours)

### Step 1: Add to validation.py

```python
# validation.py - ADD THIS FUNCTION

from functools import wraps
from flask import request, abort

def validate_pagination(max_per_page=1000):
    """
    Decorator to validate pagination parameters
    
    Usage:
        @app.route('/search')
        @validate_pagination(max_per_page=500)
        def search():
            ...
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # Get pagination params
            page = request.args.get('page', 1, type=int)
            per_page = request.args.get('per_page', 50, type=int)
            
            # Validate page
            if page < 1:
                abort(400, description="Page number must be >= 1")
            
            # Validate per_page
            if per_page < 1:
                abort(400, description="Per page must be >= 1")
            if per_page > max_per_page:
                abort(400, description=f"Per page must be <= {max_per_page}")
            
            # Call original function
            return f(*args, **kwargs)
        return wrapper
    return decorator


def validate_case_exists(f):
    """
    Decorator to validate case exists and user has access
    
    Usage:
        @app.route('/case/<int:case_id>')
        @validate_case_exists
        def view_case(case_id, case=None):
            # case object available as kwarg
    """
    @wraps(f)
    def wrapper(case_id, *args, **kwargs):
        from main import db
        from models import Case
        
        case = db.session.get(Case, case_id)
        if not case:
            abort(404, description=f"Case {case_id} not found")
        
        # Add case to kwargs so route can use it
        kwargs['case'] = case
        return f(case_id, *args, **kwargs)
    return wrapper
```

### Step 2: Apply to Routes

**main.py - search_events**
```python
# BEFORE:
@app.route('/case/<int:case_id>/search')
@login_required
def search_events(case_id):
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    # ...

# AFTER:
from validation import validate_pagination, validate_case_exists

@app.route('/case/<int:case_id>/search')
@login_required
@validate_case_exists
@validate_pagination(max_per_page=1000)
def search_events(case_id, case=None):  # case now in kwargs
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    # No validation needed - decorator handles it
    # ...
```

**Apply to these routes:**
- `search_events` (main.py)
- `export_search_results` (main.py)
- `list_sigma_rules` (main.py)
- All routes in `routes/files.py` with pagination
- All routes in `routes/ioc.py` with pagination

**Pattern:**
```python
@login_required
@validate_case_exists  # If route has case_id
@validate_pagination(max_per_page=1000)  # Adjust limit per route
def my_route(case_id, case=None):
    # case validated, pagination validated
```

---

## 🔴 FIX 3: Add Database Locking (1 hour)

### tasks.py - process_file function

**Location**: Line ~250

```python
# BEFORE:
case_file = db.session.get(CaseFile, file_id)
if not case_file:
    return {'status': 'error', 'message': 'File not found'}

# AFTER:
# Use SELECT FOR UPDATE to lock row
case_file = db.session.query(CaseFile).with_for_update().filter_by(id=file_id).first()
if not case_file:
    return {'status': 'error', 'message': 'File not found'}

# Row is now locked until commit - prevents race conditions
```

**Why This Works**:
- `with_for_update()` adds `FOR UPDATE` to SQL query
- PostgreSQL locks the row
- Other transactions must wait
- Lock released on commit/rollback
- Prevents duplicate processing

**Test**:
1. Upload 2 files simultaneously
2. Both should process without duplicates
3. Check OpenSearch for duplicate events

---

## 🔴 FIX 4: Add Task Cleanup (1 hour)

### tasks.py - All Task Functions

**Pattern to apply:**

```python
# BEFORE:
@celery_app.task(bind=True, name='tasks.process_file')
def process_file(self, file_id, operation='full'):
    case_file.celery_task_id = self.request.id
    db.session.commit()
    
    # ... processing ...
    
    case_file.celery_task_id = None  # Only on success
    db.session.commit()

# AFTER:
@celery_app.task(bind=True, name='tasks.process_file')
def process_file(self, file_id, operation='full'):
    try:
        case_file.celery_task_id = self.request.id
        db.session.commit()
        
        # ... processing ...
        
        case_file.celery_task_id = None
        db.session.commit()
        
    finally:
        # ALWAYS clear task ID, even on crash
        try:
            with app.app_context():
                case_file = db.session.get(CaseFile, file_id)
                if case_file and case_file.celery_task_id == self.request.id:
                    case_file.celery_task_id = None
                    db.session.commit()
        except Exception as e:
            logger.error(f"Failed to clear task ID: {e}")
            # Don't raise - cleanup failure shouldn't fail task
```

**Apply to:**
- `process_file` (tasks.py)
- `generate_ai_report` (tasks.py)
- `generate_case_timeline` (tasks.py)
- Any task that sets a tracking ID

**Test**:
1. Start processing file
2. Kill worker (kill -9)
3. Check database - celery_task_id should be cleared
4. File can be requeued

---

## 🔴 FIX 5: Add AI Report Event Limit (1 hour)

### ai_report.py - generate_ai_report function

**Location**: Around line 517

```python
# BEFORE:
tagged_events = []
for file_id in file_ids:
    events = get_tagged_events(...)
    tagged_events.extend(events)  # Unbounded!

# AFTER:
MAX_EVENTS_FOR_AI = 50000

tagged_events = []
for file_id in file_ids:
    events = get_tagged_events(...)
    
    # Check limit before extending
    if len(tagged_events) + len(events) > MAX_EVENTS_FOR_AI:
        remaining = MAX_EVENTS_FOR_AI - len(tagged_events)
        if remaining > 0:
            tagged_events.extend(events[:remaining])
        
        # Set error and stop
        report.status = 'failed'
        report.error_message = (
            f'Too many tagged events ({len(tagged_events) + len(events):,}). '
            f'Maximum: {MAX_EVENTS_FOR_AI:,}. '
            f'Please tag only the most important events.'
        )
        db.session.commit()
        
        # Release AI lock
        from ai_resource_lock import release_ai_lock
        release_ai_lock()
        
        return {
            'status': 'error',
            'message': report.error_message
        }
    
    tagged_events.extend(events)

# Continue if under limit
logger.info(f"[AI REPORT] Loaded {len(tagged_events):,} tagged events")
```

**Alternative: Set Limit in UI**

Add warning in template:
```html
<!-- templates/view_case_enhanced.html -->
<div class="info-box">
    <h4>AI Report Limits</h4>
    <p>Maximum tagged events: 50,000</p>
    <p>Tag only the most important events for analysis.</p>
</div>
```

**Test**:
1. Tag 60,000 events
2. Generate AI report
3. Should fail with clear error message
4. No OOM crash

---

## 🔴 FIX 6: Test Archive Feature (2 hours)

### Follow Test Suite

**Use existing test document:**
```bash
cat /opt/casescope/app/ARCHIVE_TEST_PHASE1_PHASE2.md
```

### Quick Test Checklist

**Test 1: Settings UI**
- [ ] Navigate to System Settings
- [ ] See "Case Archiving" section
- [ ] Configure path: `/archive`
- [ ] Validation works for invalid paths

**Test 2: Small Case Archive**
```bash
# Pick smallest case
psql -d casescope -c "SELECT id, name, total_files FROM case ORDER BY total_files LIMIT 5;"

# Use Python console to archive
cd /opt/casescope/app
sudo -u casescope bash -c "source ../venv/bin/activate && python3 << 'EOF'
from main import app, db
from models import Case
from archive_utils import archive_case

with app.app_context():
    result = archive_case(db, case_id=<SMALL_CASE_ID>, user_id=1)
    print(result)
EOF
"
```

**Expected**:
- ZIP created in `/archive/`
- Original files removed
- Database updated
- Case status = 'Archived'

**Test 3: Restore**
```bash
# Restore the case
sudo -u casescope bash -c "source ../venv/bin/activate && python3 << 'EOF'
from main import app, db
from archive_utils import restore_case

with app.app_context():
    result = restore_case(db, case_id=<CASE_ID>, user_id=1, new_status='In Progress')
    print(result)
EOF
"
```

**Expected**:
- Files restored to original location
- Ownership correct (casescope:casescope)
- ZIP deleted
- Case status updated

**Test 4: Guards Work**
- [ ] Try to upload to archived case → Blocked
- [ ] Try to re-index archived case → Blocked
- [ ] Try to clear files in archived case → Blocked
- [ ] IOC hunting still works → Allowed

---

## 📋 APPLY ALL FIXES CHECKLIST

### Preparation
- [ ] Backup database
- [ ] Backup code
- [ ] Git commit current state
- [ ] Test in dev environment first

### Apply Fixes
- [ ] Fix 1: Request timeouts (30 min)
- [ ] Fix 2: Pagination validation (2 hours)
- [ ] Fix 3: Database locking (1 hour)
- [ ] Fix 4: Task cleanup (1 hour)
- [ ] Fix 5: AI event limit (1 hour)
- [ ] Fix 6: Test archive (2 hours)

### Testing
- [ ] Test timeouts (kill service, verify failure)
- [ ] Test validation (try per_page=999999)
- [ ] Test locking (upload 2 files simultaneously)
- [ ] Test cleanup (kill worker, check task ID)
- [ ] Test AI limit (tag >50K events)
- [ ] Test archive (small case end-to-end)

### Deployment
- [ ] Restart services
- [ ] Monitor logs for errors
- [ ] Test critical paths
- [ ] Announce maintenance window if needed

---

## 🎯 EXPECTED RESULTS

After applying all fixes:

✅ **No hung requests** (30s timeout)  
✅ **No memory exhaustion** (pagination validated)  
✅ **No duplicate processing** (database locking)  
✅ **No stuck files** (task cleanup)  
✅ **No AI OOM crashes** (event limit)  
✅ **Archive feature tested** (production-ready)

---

## 🚨 ROLLBACK PLAN

If issues arise:

```bash
cd /opt/casescope/app
git log --oneline -5  # Find commit before changes
git reset --hard <COMMIT_HASH>
sudo systemctl restart casescope.service casescope-worker.service
```

---

## 📞 SUPPORT

Issues with fixes?
1. Check logs: `tail -f /opt/casescope/logs/workers.log`
2. Check services: `systemctl status casescope casescope-worker`
3. Rollback if needed (see above)
4. Contact support with error details

---

**Total Time**: 8 hours  
**Risk Level**: LOW (all fixes are defensive)  
**Impact**: HIGH (prevents crashes and data issues)  
**Priority**: CRITICAL (do this week)
