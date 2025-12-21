# CaseScope 2026 - Architecture Overview
**For AI Code Assistants - Complete System Understanding**

**Version**: 1.16.24  
**Last Updated**: November 20, 2025  
**Purpose**: Digital Forensics & Incident Response (DFIR) Platform

---

## 🎯 System Purpose

CaseScope 2026 analyzes security events from multiple log sources:
- Windows Event Logs (EVTX)
- JSON event logs
- CSV logs
- IIS web server logs

**Core Workflow**: Upload → Process → Index → Detect Threats → Search → Generate AI Reports

---

## 🏗️ Architecture Diagram

```
┌─────────────┐
│   Browser   │
│  (User UI)  │
└──────┬──────┘
       │ HTTP/WebSocket
       ▼
┌─────────────────────────────────────────────────┐
│              Flask Web Application               │
│  (main.py + routes/*.py)                        │
│  - Handles HTTP requests                         │
│  - Renders templates                             │
│  - Manages user sessions                         │
└──┬──────────┬───────────┬──────────┬────────────┘
   │          │           │          │
   │          │           │          │
   ▼          ▼           ▼          ▼
┌──────┐  ┌──────┐  ┌──────────┐  ┌──────┐
│PostgreSQL  │OpenSearch │   Redis   │Ollama│
│(metadata)│(events)  │  (queue)  │ (AI) │
└──────┘  └──────┘  └──────────┘  └──────┘
   ▲          ▲           │
   │          │           │
   │          │           ▼
   │          │     ┌────────────┐
   │          │     │   Celery   │
   │          │     │  Workers   │
   │          │     │ (4 concurrent)│
   │          └─────┤            │
   └────────────────│  Process   │
                    │   Files    │
                    └────────────┘
```

---

## 📦 Technology Stack

### **Backend**
| Component | Version | Purpose |
|-----------|---------|---------|
| **Flask** | 3.x | Web framework |
| **SQLAlchemy** | 2.x | ORM for PostgreSQL |
| **Celery** | 5.x | Background task queue |
| **Gunicorn** | 21.x | Production WSGI server (4 workers) |

### **Databases**
| Component | Version | Purpose | Size |
|-----------|---------|---------|------|
| **PostgreSQL** | 16.10 | Case metadata, users, IOCs | ~100MB typical |
| **OpenSearch** | 2.11.0 | Event search engine | ~50GB typical |
| **Redis** | 7.0.15 | Celery message queue | <100MB |

### **Processing Engines**
| Component | Version | Purpose |
|-----------|---------|---------|
| **Chainsaw** | v2.13.1 | SIGMA rule detection engine |
| **evtx_dump** | Latest | EVTX to JSON converter |
| **Ollama** | Latest | Local AI inference (phi3:mini, qwen) |

### **External Integrations** (Optional)
| Component | Purpose |
|-----------|---------|
| **OpenCTI** | Threat intelligence enrichment |
| **DFIR-IRIS** | Case management sync |

---

## 📁 Project Structure

```
/opt/casescope/
├── app/                          # Main application code
│   ├── main.py                   # Flask app + routes (4,532 lines - NEEDS REFACTORING)
│   ├── config.py                 # Configuration
│   ├── models.py                 # SQLAlchemy models (25K lines)
│   ├── tasks.py                  # Celery tasks (2,077 lines)
│   │
│   ├── routes/                   # Route blueprints
│   │   ├── __init__.py
│   │   ├── auth.py               # Login/logout
│   │   ├── cases.py              # Case management
│   │   ├── files.py              # File operations (2,050 lines)
│   │   ├── ioc.py                # IOC management
│   │   ├── systems.py            # System discovery
│   │   ├── known_users.py        # User tracking
│   │   ├── evidence.py           # Evidence files
│   │   ├── settings.py           # Application settings
│   │   ├── users.py              # User management
│   │   ├── admin.py              # Admin functions
│   │   ├── timeline.py           # Timeline operations
│   │   ├── api.py                # API endpoints
│   │   └── api_stats.py          # Statistics API
│   │
│   ├── templates/                # Jinja2 HTML templates (38 files)
│   │   ├── base.html             # Base template with nav
│   │   ├── components/           # Reusable components
│   │   │   ├── pagination.html   # Pagination (not used everywhere yet)
│   │   │   └── stats_card.html   # Statistics cards
│   │   └── [38 template files]
│   │
│   ├── static/                   # CSS, JavaScript, images
│   │   ├── css/
│   │   │   └── theme.css         # Main stylesheet
│   │   ├── js/
│   │   │   └── app.js            # Main JavaScript
│   │   └── favicon.svg
│   │
│   ├── migrations/               # Database migrations
│   │   ├── add_case_timeline.py
│   │   ├── add_case_status_workflow.py
│   │   ├── add_evidence_file.py
│   │   └── add_evidence_dfir_iris_sync.py
│   │
│   │ # Processing & Analysis
│   ├── file_processing.py        # Core file processing (1,856 lines)
│   ├── event_normalization.py    # Event structure normalization
│   ├── event_deduplication.py    # Duplicate event detection
│   ├── evtx_scraper.py           # EVTX parsing
│   ├── evtx_enrichment.py        # Event description updates
│   ├── evtx_descriptions.py      # Event ID descriptions
│   ├── sigma_utils.py            # SIGMA rule management
│   ├── search_utils.py           # Search query construction (1,017 lines)
│   │
│   │ # IOC & Analysis
│   ├── login_analysis.py         # Login event analysis (1,211 lines)
│   ├── known_user_utils.py       # Known user tracking
│   ├── opencti.py                # OpenCTI integration
│   ├── dfir_iris.py              # DFIR-IRIS integration
│   │
│   │ # AI Features
│   ├── ai_report.py              # AI report generation (1,150 lines)
│   ├── ai_training.py            # LoRA training (17K lines)
│   ├── ai_resource_lock.py       # AI resource locking
│   │
│   │ # Bulk Operations
│   ├── bulk_operations.py        # Bulk file operations (793 lines)
│   ├── bulk_import.py            # Bulk import from folders
│   ├── upload_pipeline.py        # Upload handling (876 lines)
│   ├── upload_integration.py     # Upload integration
│   │
│   │ # Utilities
│   ├── utils.py                  # Helper functions
│   ├── validation.py             # Input validation
│   ├── audit_logger.py           # Audit logging
│   ├── logging_config.py         # Logging setup
│   ├── celery_app.py             # Celery configuration
│   ├── celery_health.py          # Celery health checks
│   ├── queue_cleanup.py          # Queue maintenance
│   ├── system_stats.py           # System statistics
│   ├── hardware_setup.py         # Hardware detection
│   ├── hardware_utils.py         # Hardware utilities
│   ├── hidden_files.py           # Hidden file management
│   ├── export_utils.py           # Export utilities
│   │
│   └── wsgi.py                   # WSGI entry point
│
├── uploads/                      # Uploaded files staging
├── local_uploads/                # Local folder uploads
└── venv/                         # Python virtual environment
```

---

## 🔄 Core Data Flow

### 1. **File Upload & Processing**

```
User uploads EVTX/JSON/CSV file
         ↓
HTTP POST to /case/<id>/upload_files
         ↓
File saved to staging area (/opt/casescope/uploads/)
         ↓
CaseFile record created in PostgreSQL
         ↓
Celery task queued (tasks.process_file)
         ↓
┌────────────────────────────────────┐
│   Celery Worker Processing         │
├────────────────────────────────────┤
│ 1. duplicate_check()               │  # Check SHA256 + filename
│ 2. index_file()                    │  # Parse events → OpenSearch
│ 3. chainsaw_file()                 │  # SIGMA detection
│ 4. hunt_iocs()                     │  # IOC matching
└────────────────────────────────────┘
         ↓
File marked "Completed" in PostgreSQL
Events indexed in OpenSearch case_<id> index
```

### 2. **Event Search Flow**

```
User enters search query
         ↓
GET /case/<id>/search?q=...
         ↓
search_utils.py constructs OpenSearch query
         ↓
Query OpenSearch index: case_<id>
         ↓
Results returned with highlighting
         ↓
Template renders results with:
- Event details
- IOC badges (if matched)
- SIGMA badges (if violated)
- Timeline tag options
```

### 3. **IOC Hunting Flow**

```
User adds IOC (IP, hash, filename, etc.)
         ↓
POST /case/<id>/ioc/add
         ↓
IOC saved to PostgreSQL
         ↓
Background task: hunt_iocs() for all files
         ↓
OpenSearch query with IOC value
         ↓
Matching events:
- has_ioc flag set to True
- ioc_matches field populated
- IOCMatch records created in PostgreSQL
         ↓
CaseFile.ioc_event_count updated
```

### 4. **AI Report Generation Flow**

```
User clicks "Generate AI Report"
         ↓
POST /case/<id>/ai/generate
         ↓
Celery task: generate_ai_report()
         ↓
ai_report.py:
1. Gathers case data (IOCs, events, systems)
2. Constructs prompt (up to 100K tokens)
3. Calls Ollama API (streaming)
4. Saves to AIReport table
         ↓
WebSocket updates UI with live preview
         ↓
Report completed and stored
```

---

## 💾 Database Schema Overview

### **PostgreSQL Tables** (25K lines in models.py)

#### **Core Tables**
| Table | Purpose | Key Fields |
|-------|---------|------------|
| **user** | User accounts | username, email, password_hash, role |
| **case** | Investigation cases | name, status, created_by, assigned_to |
| **case_file** | Uploaded files | filename, file_hash, indexing_status, event_count |

#### **Detection Tables**
| Table | Purpose | Key Fields |
|-------|---------|------------|
| **ioc** | Indicators of Compromise | ioc_type, ioc_value, case_id |
| **ioc_match** | IOC detections | ioc_id, file_id, event_id |
| **sigma_rule** | SIGMA detection rules | title, rule_yaml, is_enabled |
| **sigma_violation** | SIGMA detections | rule_id, file_id, event_id |

#### **Analysis Tables**
| Table | Purpose | Key Fields |
|-------|---------|------------|
| **system** | Discovered systems | hostname, ip_address, system_type, case_id |
| **known_user** | Known user accounts | username, display_name, case_id |
| **timeline_tag** | Tagged events | event_id, index_name, case_id, tag_type |

#### **AI Tables**
| Table | Purpose | Key Fields |
|-------|---------|------------|
| **ai_report** | Generated reports | status, model_name, report_content |
| **ai_report_chat** | Report refinements | report_id, role, message |
| **case_timeline** | AI timelines | timeline_content, timeline_json, status |
| **ai_model** | AI model metadata | model_name, trained, trainable |
| **ai_training_session** | Training sessions | task_id, status, progress |

#### **Evidence Tables**
| Table | Purpose | Key Fields |
|-------|---------|------------|
| **evidence_file** | Non-processed files | filename, file_hash, description |

#### **System Tables**
| Table | Purpose | Key Fields |
|-------|---------|------------|
| **audit_log** | User actions | user_id, action, resource_type, ip_address |
| **evtx_description** | Event descriptions | event_id, description, source |
| **skipped_file** | Duplicate files | file_hash, reason |
| **search_history** | Search queries | case_id, query, results_count |
| **system_settings** | App settings | key, value, category |

### **OpenSearch Indices**

#### **Event Indices**
- **Format**: `case_<case_id>` (one index per case)
- **Document Structure**:
```json
{
  "_id": "case_22_evt_4624_DESKTOP-ABC_2025-01-15T10:30:45_abc123",
  "_source": {
    "file_id": 12345,
    "opensearch_key": "case_22_file_12345",
    "source_file": "Security.evtx",
    "source_file_type": "EVTX",
    
    "System": {
      "Provider": {"Name": "Microsoft-Windows-Security-Auditing"},
      "EventID": 4624,
      "Computer": "DESKTOP-ABC",
      "TimeCreated": {"SystemTime": "2025-01-15T10:30:45.123Z"}
    },
    
    "EventData": {
      "SubjectUserName": "john.doe",
      "TargetUserName": "admin",
      "LogonType": "10",
      "IpAddress": "192.168.1.100"
    },
    
    "has_ioc": true,
    "ioc_matches": ["192.168.1.100"],
    "has_sigma": true,
    "sigma_rules": ["Suspicious RDP Login"],
    "is_hidden": false,
    
    "normalized_timestamp": "2025-01-15T10:30:45.123Z",
    "normalized_computer": "DESKTOP-ABC",
    "normalized_event_id": "4624",
    "search_blob": "Successful login john.doe admin RDP 192.168.1.100"
  }
}
```

---

## 🔧 Key Components

### **1. File Processing Pipeline** (`file_processing.py`)

#### **Main Functions**:

```python
def duplicate_check(db, CaseFile, SkippedFile, case_id, filename, 
                   file_path, upload_type, exclude_file_id=None) -> dict:
    """
    Check if file already processed
    - Calculates SHA256 hash
    - Checks against existing files
    - Returns: skip/continue + file metadata
    """

def index_file(db, opensearch_client, CaseFile, Case, case_id, filename,
               file_path, file_hash, file_size, uploader_id, upload_type,
               file_id=None, celery_task=None, use_event_descriptions=True,
               force_reindex=False) -> dict:
    """
    Main indexing function
    - Detects file type (EVTX, JSON, CSV, IIS)
    - Parses events
    - Normalizes structure
    - Indexes to OpenSearch
    - Updates CaseFile record
    """

def chainsaw_file(db, opensearch_client, CaseFile, SigmaRule, 
                 SigmaViolation, file_id, index_name, celery_task=None) -> dict:
    """
    SIGMA detection
    - Exports events to temp JSON
    - Runs chainsaw with enabled rules
    - Parses CSV output
    - Updates OpenSearch events
    - Creates SigmaViolation records
    """

def hunt_iocs(db, opensearch_client, CaseFile, IOC, IOCMatch, file_id,
              index_name, celery_task=None) -> dict:
    """
    IOC hunting
    - Gets all active IOCs for case
    - Searches OpenSearch for matches
    - Updates has_ioc flags
    - Creates IOCMatch records
    """
```

#### **Supported File Types**:
- **EVTX**: Windows Event Logs (via evtx_dump)
- **JSON**: Standard JSON arrays or NDJSON
- **CSV**: CSV with headers
- **IIS**: W3C Extended Log Format

### **2. Search System** (`search_utils.py`)

```python
def construct_search_query(query, filters, case_id, page=1, 
                          per_page=50, sort_field=None, 
                          sort_order='desc') -> dict:
    """
    Builds OpenSearch query from user input
    
    Filters:
    - file_id: Specific file
    - event_type: EVTX, JSON, CSV, IIS
    - has_ioc: IOC matches only
    - has_sigma: SIGMA violations only
    - date_range: Time window
    - event_id: Windows Event ID
    - computer: Computer name
    """
```

**Query Types**:
- **Simple text**: `simple_query_string` with field boosting
- **Phrase matching**: Quotes for exact matches
- **Boolean operators**: AND, OR, NOT
- **Wildcard**: `*` and `?` supported
- **Field-specific**: `EventID:4624 Computer:SERVER01`

### **3. Celery Tasks** (`tasks.py`)

```python
@celery_app.task(bind=True, name='tasks.process_file')
def process_file(self, file_id, operation='full'):
    """
    Main worker task
    Operations:
    - 'full': All steps (duplicate check → index → SIGMA → IOC)
    - 'reindex': Force complete reprocessing (⚠️ CURRENTLY BROKEN)
    - 'chainsaw_only': SIGMA detection only
    - 'ioc_only': IOC hunting only
    """

@celery_app.task(bind=True, name='tasks.bulk_reindex')
def bulk_reindex(self, case_id):
    """Reindex all files in case (clear + reprocess)"""

@celery_app.task(bind=True, name='tasks.bulk_rechainsaw')
def bulk_rechainsaw(self, case_id):
    """Re-run SIGMA on all files"""

@celery_app.task(bind=True, name='tasks.bulk_rehunt')
def bulk_rehunt(self, case_id):
    """Re-hunt IOCs on all files"""

@celery_app.task(bind=True, name='tasks.generate_ai_report')
def generate_ai_report(self, report_id):
    """Generate AI analysis report"""

@celery_app.task(bind=True, name='tasks.generate_case_timeline')
def generate_case_timeline(self, timeline_id):
    """Generate AI timeline"""
```

### **4. AI System** (`ai_report.py`, `ai_training.py`)

#### **Report Generation**:
```python
def generate_report(case_id, model_name='phi3:mini', hardware_mode='cpu') -> int:
    """
    1. Gather case data (IOCs, systems, events summary)
    2. Construct prompt (up to 100K tokens)
    3. Stream response from Ollama
    4. Parse and validate
    5. Save to database
    """
```

**Models Supported**:
- **phi3:mini** - Fast, 4.9GB (default)
- **dfir-qwen:latest** - Forensics-optimized, 7GB
- **Custom LoRA** - Trained on your reports

#### **LoRA Training**:
```python
def train_model(model_name, report_ids, user_id) -> str:
    """
    Fine-tune AI model on existing reports
    1. Export reports as training data
    2. Use Unsloth for LoRA training
    3. Deploy to Ollama
    4. Mark model as trained
    """
```

---

## 🎨 Frontend Architecture

### **Template System** (Jinja2)

**Base Template** (`base.html`):
```html
<!DOCTYPE html>
<html>
<head>
    <title>{% block title %}CaseScope{% endblock %}</title>
    <link rel="stylesheet" href="/static/css/theme.css?v={{ cache_bust }}">
</head>
<body>
    <nav><!-- Global navigation --></nav>
    
    <div class="container">
        {% with messages = get_flashed_messages(with_categories=true) %}
            <!-- Flash messages -->
        {% endwith %}
        
        {% block content %}{% endblock %}
    </div>
    
    <script src="/static/js/app.js?v={{ cache_bust }}"></script>
    {% block scripts %}{% endblock %}
</body>
</html>
```

### **CSS Architecture** (`theme.css`)

**CSS Variables**:
```css
:root {
  /* Colors */
  --color-primary: #2563eb;
  --color-success: #10b981;
  --color-warning: #f59e0b;
  --color-danger: #ef4444;
  --color-bg: #ffffff;
  --color-bg-secondary: #f3f4f6;
  --color-text: #1f2937;
  --color-border: #e5e7eb;
  
  /* Spacing */
  --spacing-xs: 0.25rem;
  --spacing-sm: 0.5rem;
  --spacing-md: 1rem;
  --spacing-lg: 1.5rem;
  --spacing-xl: 2rem;
}
```

### **JavaScript Patterns**

**Common Pattern - API Calls**:
```javascript
async function performAction(url, method = 'POST', data = null) {
    try {
        const options = {
            method: method,
            headers: {'Content-Type': 'application/json'}
        };
        if (data) options.body = JSON.stringify(data);
        
        const response = await fetch(url, options);
        if (!response.ok) throw new Error('Request failed');
        
        const result = await response.json();
        return result;
    } catch (error) {
        console.error('Error:', error);
        alert('Operation failed: ' + error.message);
    }
}
```

**Common Pattern - Modals**:
```javascript
function showModal(modalId) {
    document.getElementById(modalId).style.display = 'block';
}

function hideModal(modalId) {
    document.getElementById(modalId).style.display = 'none';
}

// Close on overlay click
document.querySelectorAll('.modal').forEach(modal => {
    modal.addEventListener('click', (e) => {
        if (e.target === modal) hideModal(modal.id);
    });
});
```

---

## 🔐 Security Architecture

### **Authentication** (`routes/auth.py`)
- **Session-based**: Flask-Login manages sessions
- **Password hashing**: Werkzeug security (bcrypt)
- **Remember me**: Optional persistent login

### **Authorization**
**Roles**:
- **administrator**: Full access, user management
- **analyst**: Case access, file operations
- **read-only**: View-only access

**Permission Checks**:
```python
@login_required  # Must be logged in
def protected_route():
    if current_user.role != 'administrator':
        return jsonify({'error': 'Unauthorized'}), 403
```

### **Audit Logging** (`audit_logger.py`)
```python
def log_action(action, resource_type, resource_id=None, 
               resource_name=None, status='success', 
               details=None, ip_address=None):
    """
    Logs all user actions to audit_log table
    - Who did what
    - When
    - From which IP
    - Success/failure
    """
```

---

## ⚙️ Configuration

### **Environment Variables** (`.env` or system env)
```bash
# Database
DATABASE_URL=postgresql://user:pass@localhost/casescope

# OpenSearch
OPENSEARCH_HOST=localhost
OPENSEARCH_PORT=9200

# Redis
REDIS_URL=redis://localhost:6379/0

# Security
SECRET_KEY=your-secret-key-here
SESSION_TYPE=filesystem

# Uploads
UPLOAD_FOLDER=/opt/casescope/uploads
MAX_UPLOAD_SIZE=10737418240  # 10GB

# Celery
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0

# AI
OLLAMA_BASE_URL=http://localhost:11434
DEFAULT_AI_MODEL=phi3:mini

# Integrations (optional)
OPENCTI_URL=http://localhost:8080
OPENCTI_TOKEN=your-token
DFIR_IRIS_URL=http://localhost:8000
DFIR_IRIS_TOKEN=your-token
```

### **Configuration Class** (`config.py`)
```python
class Config:
    # Flask
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key'
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Connection pooling
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 10,
        'max_overflow': 20,
        'pool_pre_ping': True,
        'pool_recycle': 3600
    }
    
    # OpenSearch
    OPENSEARCH_HOST = os.environ.get('OPENSEARCH_HOST', 'localhost')
    OPENSEARCH_PORT = int(os.environ.get('OPENSEARCH_PORT', 9200))
    
    # Upload limits
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024 * 1024  # 10GB
```

---

## 🐛 Known Issues & Bugs

### **CRITICAL - Re-Index Broken** ⚠️
**Status**: Documented fix available  
**Issue**: All re-index operations (single, selected, bulk) fail to reprocess files  
**Root Cause**: `operation='reindex'` documented but never implemented in `tasks.process_file()`  
**Fix**: See `Reindex_Bug_Analysis_and_Fix.md`

### **Refactoring Needed**
- **main.py too large**: 4,532 lines, should be ~600 lines (81+ routes belong in blueprints)
- **Duplicate queries**: OpenSearch and database queries repeated 100+ times
- **Template redundancy**: Pagination, modals, tables duplicated across 38 templates

### **Optimization Opportunities**
- OpenSearch query builder class (eliminate 2,000 lines)
- Database query helpers (eliminate 1,500 lines)
- JavaScript consolidation (eliminate 2,200 lines)

---

## 📊 Performance Characteristics

### **Tested Scale**
- **40+ million events** indexed
- **9,400+ files** processed
- **331,000+ SIGMA violations** detected
- **41,000+ IOC events** flagged
- **3,074 active SIGMA rules**

### **Hardware Requirements**
- **Minimum**: 4 CPU cores, 16GB RAM, 100GB SSD
- **Recommended**: 8+ CPU cores, 32GB RAM, 500GB NVMe SSD
- **Large datasets**: 16+ CPU cores, 64GB RAM, 1TB+ NVMe SSD

### **Processing Speed**
- **EVTX parsing**: ~50,000 events/minute (single worker)
- **OpenSearch indexing**: ~100,000 events/minute (bulk operations)
- **SIGMA detection**: ~10,000 events/second (Chainsaw)
- **IOC hunting**: ~50,000 events/second (OpenSearch query)

---

## 🔄 Deployment Architecture

### **Production Setup**
```
┌──────────────┐
│ Nginx/Apache │  (Reverse proxy, SSL termination)
└──────┬───────┘
       │
┌──────▼───────┐
│  Gunicorn    │  (4 workers, port 5000)
│  (main.py)   │
└──────┬───────┘
       │
┌──────▼───────┐
│ PostgreSQL   │  (localhost:5432)
└──────────────┘

┌──────────────┐
│ OpenSearch   │  (localhost:9200, 8GB heap)
└──────────────┘

┌──────────────┐
│    Redis     │  (localhost:6379)
└──────┬───────┘
       │
┌──────▼───────┐
│ Celery (4x)  │  (Background workers)
└──────────────┘

┌──────────────┐
│   Ollama     │  (localhost:11434, AI inference)
└──────────────┘
```

### **Systemd Services**
```bash
# Web application
/etc/systemd/system/casescope.service

# Celery workers
/etc/systemd/system/casescope-worker.service

# Check status
systemctl status casescope casescope-worker
```

---

## 📝 For Cursor AI: Quick Tips

### **To Add a New Route**:
1. Create function in appropriate blueprint (`routes/*.py`)
2. Use decorator: `@blueprint_name.route('/path')`
3. Add to navigation in `base.html` if needed
4. Test with browser or curl

### **To Query Database**:
```python
from models import db, CaseFile
from sqlalchemy import and_

# Simple query
file = db.session.get(CaseFile, file_id)

# Complex query
files = db.session.query(CaseFile).filter(
    and_(
        CaseFile.case_id == case_id,
        CaseFile.is_deleted == False,
        CaseFile.indexing_status == 'Completed'
    )
).all()
```

### **To Query OpenSearch**:
```python
from main import opensearch_client

# Search
response = opensearch_client.search(
    index=f"case_{case_id}",
    body={
        "query": {
            "bool": {
                "must": [{"term": {"file_id": file_id}}]
            }
        },
        "size": 10000
    }
)

events = [hit['_source'] for hit in response['hits']['hits']]
```

### **To Add a Celery Task**:
```python
# In tasks.py
@celery_app.task(bind=True, name='tasks.my_task')
def my_task(self, param1, param2):
    from main import app, db
    with app.app_context():
        # Do work with database access
        pass

# To call it
from tasks import my_task
my_task.delay(value1, value2)  # Async
result = my_task.apply(args=[value1, value2])  # Sync (testing)
```

---

## 📚 Related Documentation

See these files for detailed information:
- **ROUTES_COMPLETE.md** - All routes explained
- **DATABASE_SCHEMA.md** - Database models and relationships
- **FRONTEND_GUIDE.md** - Templates, CSS, JavaScript
- **PROCESSING_PIPELINE.md** - File processing workflow
- **API_REFERENCE.md** - API endpoints
- **QUICK_REFERENCE.md** - Common patterns

---

**✅ VERIFIED**: All information extracted from actual codebase (Nov 20, 2025)
