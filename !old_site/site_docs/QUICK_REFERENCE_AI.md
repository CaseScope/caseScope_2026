# CaseScope 2026 - Quick Reference for AI Code Assistants
**Common Patterns, Functions, and Code Examples**

**Last Updated**: November 21, 2025  
**Purpose**: Fast lookup for AI assistants working with the codebase

---

## 🚀 Quick Start for AI

###

 **System Purpose**
Digital forensics platform that processes EVTX/JSON/CSV logs, detects threats with SIGMA rules, hunts IOCs, and generates AI reports.

### **Key Files to Know**
```
main.py (4,532 lines) - Flask app + 72 routes (NEEDS REFACTORING)
models.py (25K lines) - Database schema
tasks.py (2,077 lines) - Celery background tasks
file_processing.py (1,856 lines) - Core processing logic
routes/*.py - Route blueprints (13 files)
```

### **Tech Stack**
- Flask + SQLAlchemy + PostgreSQL 16
- OpenSearch 2.11 (event search)
- Celery + Redis (background tasks)
- Ollama (AI)

---

## 🗄️ Database Quick Reference

### **Import Models**
```python
from models import (
    db, User, Case, CaseFile, IOC, IOCMatch,
    SigmaRule, SigmaViolation, System, TimelineTag,
    AIReport, CaseTimeline, EvidenceFile, KnownUser
)
```

### **Common Queries**

#### Get Case
```python
case = db.session.get(Case, case_id)
if not case:
    return jsonify({'error': 'Case not found'}), 404
```

#### Get Files for Case
```python
files = db.session.query(CaseFile).filter(
    CaseFile.case_id == case_id,
    CaseFile.is_deleted == False,
    CaseFile.is_hidden == False
).all()
```

#### Get File Statistics
```python
from bulk_operations import get_files

# Get completed files
completed = db.session.query(CaseFile).filter(
    CaseFile.case_id == case_id,
    CaseFile.indexing_status == 'Completed',
    CaseFile.is_deleted == False,
    CaseFile.is_hidden == False
).count()

# Or use helper (if available)
stats = CaseFileQueries.get_stats(case_id)  # After refactoring
```

#### Get Active IOCs
```python
iocs = db.session.query(IOC).filter(
    IOC.case_id == case_id,
    IOC.is_active == True
).all()
```

#### Create Audit Log
```python
from audit_logger import log_action

log_action(
    action='delete_file',
    resource_type='file',
    resource_id=file_id,
    resource_name=filename,
    status='success',
    details={'case_id': case_id}
)
```

---

## 🔍 OpenSearch Quick Reference

### **Import Client**
```python
from main import opensearch_client
```

### **Common Patterns**

#### Search Events
```python
response = opensearch_client.search(
    index=f"case_{case_id}",
    body={
        "query": {
            "bool": {
                "must": [
                    {"term": {"file_id": file_id}},
                    {"term": {"has_ioc": True}}
                ],
                "must_not": [
                    {"term": {"is_hidden": True}}
                ]
            }
        },
        "size": 10000
    }
)

events = [hit['_source'] for hit in response['hits']['hits']]
```

#### Count Events
```python
count = opensearch_client.count(
    index=f"case_{case_id}",
    body={
        "query": {
            "term": {"file_id": file_id}
        }
    }
)['count']
```

#### Delete Events
```python
opensearch_client.delete_by_query(
    index=f"case_{case_id}",
    body={
        "query": {
            "term": {"file_id": file_id}
        }
    },
    conflicts='proceed',
    ignore=[404]
)
```

#### Update Event Flags
```python
from opensearchpy import helpers

def update_ioc_flags(opensearch_client, case_id, event_ids):
    actions = [
        {
            "_op_type": "update",
            "_index": f"case_{case_id}",
            "_id": event_id,
            "doc": {
                "has_ioc": True,
                "ioc_matches": ["192.168.1.100"]
            }
        }
        for event_id in event_ids
    ]
    
    helpers.bulk(opensearch_client, actions)
```

#### Search Forensic Fields (v1.19.3+)
```python
# v1.19.3+: All EventData/UserData fields extracted as forensic_* fields
# Examples: forensic_TargetUserName, forensic_IpAddress, forensic_ProcessName

# Search for specific username
response = opensearch_client.search(
    index=f"case_{case_id}",
    body={
        "query": {
            "term": {"forensic_TargetUserName.keyword": "administrator"}
        }
    }
)

# Search for IP address
response = opensearch_client.search(
    index=f"case_{case_id}",
    body={
        "query": {
            "term": {"forensic_IpAddress": "192.168.1.100"}
        }
    }
)

# Search for logon type
response = opensearch_client.search(
    index=f"case_{case_id}",
    body={
        "query": {
            "term": {"forensic_LogonType": "3"}
        }
    }
)

# NOTE: Original EventData/UserData still exist as JSON strings
# forensic_* fields are for filtering/searching specific fields
# EventData/UserData strings are for full-text search
```

---

## ⚙️ Celery Tasks Quick Reference

### **Queue a Task**
```python
from tasks import process_file

# Async (recommended)
process_file.delay(file_id, operation='full')

# Sync (testing only)
result = process_file.apply(args=[file_id, 'full'])
```

### **Create a New Task**
```python
from celery_app import celery_app

@celery_app.task(bind=True, name='tasks.my_task')
def my_task(self, param1, param2):
    from main import app, db
    
    with app.app_context():
        # Database operations here
        case = db.session.get(Case, param1)
        # ... do work ...
        db.session.commit()
    
    return {'status': 'success', 'data': result}
```

### **Update Task Progress**
```python
self.update_state(
    state='PROGRESS',
    meta={
        'current': 5,
        'total': 10,
        'percent': 50,
        'message': 'Processing file 5 of 10'
    }
)
```

---

## 🎨 Frontend Quick Reference

### **Flash Messages**
```python
from flask import flash

flash('Operation successful!', 'success')
flash('Warning: File already exists', 'warning')
flash('Error: Operation failed', 'error')
```

### **Render Template**
```python
from flask import render_template

return render_template(
    'case_files.html',
    case=case,
    files=files,
    page=page,
    total_pages=total_pages
)
```

### **JSON Response**
```python
from flask import jsonify

return jsonify({
    'success': True,
    'data': {'count': 100},
    'message': 'Operation completed'
}), 200

# Error response
return jsonify({
    'success': False,
    'error': 'File not found'
}), 404
```

### **Redirect**
```python
from flask import redirect, url_for

return redirect(url_for('files.case_files', case_id=case_id))
```

---

## 🔐 Authentication & Authorization

### **Require Login**
```python
from flask_login import login_required, current_user

@app.route('/protected')
@login_required
def protected_route():
    return f'Hello {current_user.username}'
```

### **Check Role**
```python
if current_user.role not in ['administrator', 'analyst']:
    flash('Unauthorized', 'error')
    return redirect(url_for('dashboard'))
```

### **Check Admin**
```python
if current_user.role != 'administrator':
    return jsonify({'error': 'Admin only'}), 403
```

---

## 📁 File Processing Quick Reference

### **Process File Pipeline**
```python
from file_processing import (
    duplicate_check, index_file, 
    chainsaw_file, hunt_iocs
)

# 1. Check for duplicates
dup_result = duplicate_check(
    db=db,
    CaseFile=CaseFile,
    SkippedFile=SkippedFile,
    case_id=case_id,
    filename=filename,
    file_path=file_path,
    upload_type='http'
)

if dup_result['status'] == 'skip':
    # File is duplicate
    pass

# 2. Index events to OpenSearch
index_result = index_file(
    db=db,
    opensearch_client=opensearch_client,
    CaseFile=CaseFile,
    Case=Case,
    case_id=case_id,
    filename=filename,
    file_path=file_path,
    file_hash=dup_result['file_hash'],
    file_size=dup_result['file_size'],
    uploader_id=current_user.id,
    upload_type='http'
)

# 3. Run SIGMA detection
chainsaw_result = chainsaw_file(
    db=db,
    opensearch_client=opensearch_client,
    CaseFile=CaseFile,
    SigmaRule=SigmaRule,
    SigmaViolation=SigmaViolation,
    file_id=file_id,
    index_name=f"case_{case_id}"
)

# 4. Hunt IOCs
ioc_result = hunt_iocs(
    db=db,
    opensearch_client=opensearch_client,
    CaseFile=CaseFile,
    IOC=IOC,
    IOCMatch=IOCMatch,
    file_id=file_id,
    index_name=f"case_{case_id}"
)
```

---

## 🎯 Common Operations

### **Upload File**
```python
from werkzeug.utils import secure_filename
import os

file = request.files['file']
filename = secure_filename(file.filename)
filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
file.save(filepath)

# Create CaseFile record
case_file = CaseFile(
    case_id=case_id,
    filename=filename,
    original_filename=file.filename,
    file_path=filepath,
    file_size=os.path.getsize(filepath),
    uploaded_by=current_user.id,
    indexing_status='Queued'
)
db.session.add(case_file)
db.session.commit()

# Queue for processing
from tasks import process_file
process_file.delay(case_file.id)
```

### **Delete File**
```python
import os

# Delete from database
case_file = db.session.get(CaseFile, file_id)
case_file.is_deleted = True
db.session.commit()

# Delete from filesystem (optional)
if os.path.exists(case_file.file_path):
    os.remove(case_file.file_path)

# Delete from OpenSearch
opensearch_client.delete_by_query(
    index=f"case_{case_id}",
    body={"query": {"term": {"file_id": file_id}}},
    conflicts='proceed',
    ignore=[404]
)
```

### **Search Events**
```python
from search_utils import construct_search_query

query_body = construct_search_query(
    query="EventID:4624 AND LogonType:10",
    filters={
        'file_id': file_id,
        'has_ioc': True,
        'date_range': {
            'start': '2025-01-01T00:00:00Z',
            'end': '2025-01-31T23:59:59Z'
        }
    },
    case_id=case_id,
    page=1,
    per_page=50
)

response = opensearch_client.search(
    index=f"case_{case_id}",
    body=query_body
)

events = [hit['_source'] for hit in response['hits']['hits']]
total = response['hits']['total']['value']
```

---

## 🤖 AI Operations

### **Generate AI Report**
```python
from tasks import generate_ai_report
from models import AIReport

# Create report record
report = AIReport(
    case_id=case_id,
    generated_by=current_user.id,
    model_name='phi3:mini',
    status='pending'
)
db.session.add(report)
db.session.commit()

# Queue generation task
generate_ai_report.delay(report.id)

return jsonify({
    'report_id': report.id,
    'status': 'generating'
})
```

### **Check AI Status**
```python
import requests

try:
    response = requests.get('http://localhost:11434/api/tags', timeout=2)
    models = response.json().get('models', [])
    status = 'available' if models else 'no_models'
except:
    status = 'unavailable'

return jsonify({
    'status': status,
    'models': models
})
```

---

## 🔧 Utility Functions

### **Calculate File Hash**
```python
import hashlib

def calculate_sha256(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()
```

### **Format File Size**
```python
def format_size(bytes):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes < 1024.0:
            return f"{bytes:.1f} {unit}"
        bytes /= 1024.0
    return f"{bytes:.1f} TB"
```

### **Get Index Name**
```python
from utils import make_index_name

# Consolidated index (v1.13.1+)
index_name = make_index_name(case_id)  # Returns: case_22

# Legacy per-file index (deprecated)
index_name = make_index_name(case_id, filename)  # Returns: case_22_Security_evtx
```

---

## 🐛 Known Issues & Fixes

### **CRITICAL: Re-Index Broken** ⚠️

**Problem**: All re-index operations fail to reprocess files.

**Temporary Workaround**:
```python
# Instead of:
process_file.delay(file_id, operation='full')  # Gets skipped

# Use:
# 1. Manually set is_indexed = False
case_file.is_indexed = False
case_file.indexing_status = 'Queued'
db.session.commit()

# 2. Then queue
process_file.delay(file_id, operation='full')
```

**Permanent Fix**: See `Reindex_Bug_Analysis_and_Fix.md`

---

## 📝 Code Style Guidelines

### **Route Function Pattern**
```python
@app.route('/case/<int:case_id>/action', methods=['POST'])
@login_required
def action_name(case_id):
    """
    Brief description
    
    Args:
        case_id: Case ID
        
    Returns:
        Redirect or JSON response
    """
    # 1. Get resources
    case = db.session.get(Case, case_id)
    if not case:
        flash('Case not found', 'error')
        return redirect(url_for('dashboard'))
    
    # 2. Check permissions
    if current_user.role != 'administrator':
        flash('Unauthorized', 'error')
        return redirect(url_for('dashboard'))
    
    # 3. Perform action
    try:
        # ... do work ...
        db.session.commit()
        
        # 4. Audit log
        from audit_logger import log_action
        log_action('action_name', 'resource_type', resource_id)
        
        # 5. Response
        flash('Operation successful', 'success')
        return redirect(url_for('view_case', case_id=case_id))
        
    except Exception as e:
        logger.error(f'Error: {e}', exc_info=True)
        flash('Operation failed', 'error')
        return redirect(url_for('view_case', case_id=case_id))
```

### **Task Pattern**
```python
@celery_app.task(bind=True, name='tasks.task_name')
def task_name(self, param1, param2):
    """Task description"""
    from main import app, db
    from models import Model
    
    logger.info(f"[TASK] Starting task_name with {param1}")
    
    with app.app_context():
        try:
            # Update progress
            self.update_state(
                state='PROGRESS',
                meta={'percent': 50, 'message': 'Processing...'}
            )
            
            # Do work
            result = do_work(param1, param2)
            
            # Commit
            db.session.commit()
            
            return {
                'status': 'success',
                'data': result
            }
            
        except Exception as e:
            logger.error(f"[TASK] Error: {e}", exc_info=True)
            return {
                'status': 'error',
                'message': str(e)
            }
```

---

## 🎯 Quick Answers to Common Questions

**Q: How do I add a new route?**  
A: Add to appropriate blueprint in `routes/*.py`, not main.py

**Q: How do I query events?**  
A: Use opensearch_client.search() with case index: `case_{case_id}`

**Q: How do I queue a background task?**  
A: Import from tasks.py and use `.delay()` method

**Q: How do I log user actions?**  
A: Use `from audit_logger import log_action`

**Q: Where are file uploads stored?**  
A: `/opt/casescope/uploads/` (configurable)

**Q: How do I check if user is admin?**  
A: `if current_user.role == 'administrator'`

**Q: How do I get case statistics?**  
A: Query CaseFile table with filters, or use bulk_operations helpers

**Q: How do IOC matches work?**  
A: hunt_iocs() searches OpenSearch for IOC values, creates IOCMatch records

**Q: How does SIGMA detection work?**  
A: chainsaw_file() exports events to JSON, runs chainsaw CLI, parses results

**Q: Where is the AI code?**  
A: ai_report.py (report generation), ai_training.py (LoRA training)

---

## 📚 Files to Read First

1. **ARCHITECTURE_OVERVIEW.md** - System understanding
2. **This file** - Common patterns
3. **ROUTES_COMPLETE.md** - All endpoints
4. **DATABASE_SCHEMA.md** - Data structures
5. **models.py** - Actual model definitions

---

## ⚠️ Important Gotchas

1. **Always use `case_{case_id}` for index name** (consolidated indices since v1.13.1)
2. **Filter out deleted files**: `is_deleted == False`
3. **Filter out hidden files**: `is_hidden == False` (unless specifically needed)
4. **Use app context in Celery tasks**: `with app.app_context():`
5. **Commit after database changes**: `db.session.commit()`
6. **Log audit actions**: Use audit_logger for all mutations
7. **Check permissions**: Verify user.role before allowing actions
8. **Handle exceptions**: Wrap operations in try/except
9. **Re-index is broken**: Known issue with documented fix

---

**✅ VERIFIED**: All patterns extracted from actual codebase (Nov 20, 2025)  
**📖 FOR**: AI code assistants (Cursor, Copilot, etc.)  
**🎯 PURPOSE**: Fast reference for common operations
