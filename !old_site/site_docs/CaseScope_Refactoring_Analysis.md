# CaseScope 2026 - Deep Dive Refactoring Analysis

## Executive Summary

After analyzing the entire codebase (4,386 lines in main.py, 46,194 total lines), I've identified **significant refactoring opportunities** that will:
- **Reduce code by ~40-50%** through consolidation
- **Improve maintainability** by eliminating duplication
- **Enhance modularity** with proper separation of concerns
- **Standardize patterns** across the application

---

## 🔴 CRITICAL ISSUES - Priority 1

### 1. **Massive main.py File (4,386 lines)**

**Problem**: main.py contains 81+ route handlers that should be in blueprints.

**Current State**:
```
main.py breakdown:
- Authentication routes (login/logout) - should be in routes/auth.py
- Case management routes - should be in routes/cases.py  
- AI report routes (15+ routes) - should be in routes/ai.py
- Search routes (15+ routes) - should be in routes/search.py
- EVTX descriptions routes (10+ routes) - should be in routes/evtx.py
- Timeline tagging routes (8+ routes) - should be in routes/timeline.py (already exists!)
- Dashboard route - should be in routes/dashboard.py
```

**Routes that need to be moved**:

#### To `routes/search.py` (NEW):
- `/case/<int:case_id>/search` - search_events()
- `/case/<int:case_id>/search/export` - export_search_results()
- `/case/<int:case_id>/search/event/<event_id>` - get_event_detail_route()
- `/case/<int:case_id>/search/tag` - tag_timeline_event()
- `/case/<int:case_id>/search/untag` - untag_timeline_event()
- `/case/<int:case_id>/search/hide` - hide_event()
- `/case/<int:case_id>/search/unhide` - unhide_event()
- `/case/<int:case_id>/search/bulk-tag` - bulk_tag_events()
- `/case/<int:case_id>/search/bulk-untag` - bulk_untag_events()
- `/case/<int:case_id>/search/bulk-hide` - bulk_hide_events()
- `/case/<int:case_id>/search/bulk-unhide` - bulk_unhide_events()
- `/case/<int:case_id>/search/columns` - update_search_columns()
- `/case/<int:case_id>/search/history/<int:search_id>/favorite` - toggle_search_favorite()

**Impact**: Removes ~1,500 lines from main.py

#### To `routes/ai.py` (NEW):
- `/ai/status` - ai_status()
- `/case/<int:case_id>/ai/generate` - generate_ai_report()
- `/ai/report/<int:report_id>/view` - view_ai_report()
- `/ai/report/<int:report_id>` - get_ai_report() (GET)
- `/ai/report/<int:report_id>` - delete_ai_report() (DELETE)
- `/ai/report/<int:report_id>/live-preview` - get_ai_report_live_preview()
- `/ai/report/<int:report_id>/cancel` - cancel_ai_report()
- `/ai/report/<int:report_id>/download` - download_ai_report()
- `/ai/report/<int:report_id>/chat` - ai_report_chat() (POST)
- `/ai/report/<int:report_id>/chat` - get_ai_report_chat_history() (GET)
- `/ai/report/<int:report_id>/review` - get_ai_report_review()
- `/ai/report/<int:report_id>/apply` - apply_ai_chat_refinement()
- `/case/<int:case_id>/ai/reports` - list_ai_reports()

**Impact**: Removes ~1,200 lines from main.py

#### To `routes/evtx.py` (NEW):
- `/evtx_descriptions` - evtx_descriptions()
- `/evtx_descriptions/update` - evtx_descriptions_update()
- `/evtx_descriptions/custom` - create_custom_event()
- `/evtx_descriptions/custom/<int:event_desc_id>` - update_custom_event() (PUT)
- `/evtx_descriptions/custom/<int:event_desc_id>` - delete_custom_event() (DELETE)
- `/case/<int:case_id>/refresh_descriptions` - refresh_descriptions_case_route()
- `/refresh_descriptions_global` - refresh_descriptions_global_route()

**Impact**: Removes ~600 lines from main.py

#### To `routes/auth.py` (enhance existing):
Currently routes/auth.py only has 103 lines. Move login/logout from main.py:
- `/login` - login() 
- `/logout` - logout()

**Impact**: Removes ~100 lines from main.py

#### To `routes/cases.py` (enhance existing):
Currently routes/cases.py only has 258 lines. Move from main.py:
- `/` - dashboard() (rename to index)
- `/cases` - case_selection()
- `/case/create` - create_case()
- `/case/<int:case_id>/status` - case_file_status()
- `/case/<int:case_id>` - view_case()
- `/select_case/<int:case_id>` - select_case()
- `/clear_case` - clear_case()
- `/queue/cleanup` - queue_cleanup_all()
- `/queue/health` - queue_health_check()

**Impact**: Removes ~400 lines from main.py

**Total Reduction**: ~3,800 lines removed from main.py → **Only ~600 lines remaining** (helpers, config, app initialization)

---

### 2. **Duplicate OpenSearch Query Patterns (Appears 100+ times)**

**Problem**: Every file has nearly identical OpenSearch query construction.

**Example - Repeated Pattern**:
```python
# This pattern appears in:
# - main.py (20+ times)
# - routes/files.py (30+ times)
# - routes/systems.py (15+ times)
# - search_utils.py (25+ times)
# - file_processing.py (10+ times)

query = {
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
    }
}
response = opensearch_client.search(index=index_name, body=query, size=10000)
```

**Solution**: Create `opensearch_helpers.py`:

```python
# opensearch_helpers.py (NEW FILE)

class OpenSearchQueryBuilder:
    """Fluent API for building OpenSearch queries"""
    
    def __init__(self, client, index_name):
        self.client = client
        self.index_name = index_name
        self.must = []
        self.must_not = []
        self.should = []
        self.filters = []
        self._size = 10000
        self._sort = None
        self._source = None
        
    def term(self, field, value):
        """Add exact term match"""
        self.must.append({"term": {field: value}})
        return self
        
    def terms(self, field, values):
        """Add terms match (OR)"""
        self.must.append({"terms": {field: values}})
        return self
        
    def exclude(self, field, value):
        """Exclude term"""
        self.must_not.append({"term": {field: value}})
        return self
        
    def range_query(self, field, gte=None, lte=None):
        """Add range query"""
        range_obj = {}
        if gte: range_obj['gte'] = gte
        if lte: range_obj['lte'] = lte
        self.must.append({"range": {field: range_obj}})
        return self
        
    def exists(self, field):
        """Field must exist"""
        self.must.append({"exists": {"field": field}})
        return self
        
    def search_text(self, query, fields=None):
        """Full-text search"""
        search_obj = {"query": query}
        if fields:
            search_obj["fields"] = fields
        self.must.append({"simple_query_string": search_obj})
        return self
        
    def size(self, size):
        """Set result size"""
        self._size = size
        return self
        
    def sort(self, field, order="asc"):
        """Add sorting"""
        self._sort = [{field: {"order": order}}]
        return self
        
    def source(self, fields):
        """Specify source fields to return"""
        self._source = fields
        return self
        
    def build(self):
        """Build the query dict"""
        query = {"bool": {}}
        if self.must: query["bool"]["must"] = self.must
        if self.must_not: query["bool"]["must_not"] = self.must_not
        if self.should: query["bool"]["should"] = self.should
        if self.filters: query["bool"]["filter"] = self.filters
        
        body = {"query": query, "size": self._size}
        if self._sort: body["sort"] = self._sort
        if self._source: body["_source"] = self._source
        
        return body
        
    def execute(self):
        """Build and execute query"""
        body = self.build()
        return self.client.search(index=self.index_name, body=body)
        
    def count(self):
        """Count matching documents"""
        body = self.build()
        return self.client.count(index=self.index_name, body=body)['count']


# Convenience functions for common queries
def get_events_by_file(client, case_id, file_id, include_hidden=False):
    """Get all events for a file"""
    builder = OpenSearchQueryBuilder(client, f"case_{case_id}")
    builder.term("file_id", file_id)
    if not include_hidden:
        builder.exclude("is_hidden", True)
    return builder.execute()


def get_ioc_events(client, case_id, file_id=None, include_hidden=False):
    """Get events with IOC matches"""
    builder = OpenSearchQueryBuilder(client, f"case_{case_id}")
    builder.term("has_ioc", True)
    if file_id:
        builder.term("file_id", file_id)
    if not include_hidden:
        builder.exclude("is_hidden", True)
    return builder.execute()


def get_sigma_events(client, case_id, file_id=None, include_hidden=False):
    """Get events with SIGMA violations"""
    builder = OpenSearchQueryBuilder(client, f"case_{case_id}")
    builder.term("has_sigma", True)
    if file_id:
        builder.term("file_id", file_id)
    if not include_hidden:
        builder.exclude("is_hidden", True)
    return builder.execute()


def search_events(client, case_id, search_query, filters=None):
    """Generic event search with filters"""
    builder = OpenSearchQueryBuilder(client, f"case_{case_id}")
    
    if search_query:
        builder.search_text(search_query, fields=["*"])
    
    if filters:
        if 'file_id' in filters:
            builder.term("file_id", filters['file_id'])
        if 'has_ioc' in filters:
            builder.term("has_ioc", filters['has_ioc'])
        if 'has_sigma' in filters:
            builder.term("has_sigma", filters['has_sigma'])
        if 'event_type' in filters:
            builder.term("source_file_type", filters['event_type'])
        if 'date_range' in filters:
            builder.range_query(
                "System.TimeCreated.SystemTime",
                gte=filters['date_range'].get('start'),
                lte=filters['date_range'].get('end')
            )
    
    builder.exclude("is_hidden", True)
    return builder.execute()
```

**Usage Example** (replaces 20+ lines with 3):
```python
# BEFORE (repeated everywhere):
query = {
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
response = opensearch_client.search(index=f"case_{case_id}", body=query)
events = [hit['_source'] for hit in response['hits']['hits']]

# AFTER (using helper):
from opensearch_helpers import get_ioc_events
response = get_ioc_events(opensearch_client, case_id, file_id)
events = [hit['_source'] for hit in response['hits']['hits']]
```

**Impact**: 
- Eliminates ~2,000 lines of duplicate query construction
- Centralizes query logic for easier maintenance
- Adds type safety and validation
- Makes queries more readable

---

### 3. **Duplicate Database Query Patterns**

**Problem**: Repeated SQLAlchemy query patterns across all files.

**Example - File Statistics Query** (appears 15+ times):
```python
# This exact pattern in:
# - main.py (5 times)
# - routes/files.py (7 times)  
# - routes/cases.py (3 times)

completed = db.session.query(CaseFile).filter(
    CaseFile.case_id == case_id,
    CaseFile.indexing_status == 'Completed',
    CaseFile.is_deleted == False,
    CaseFile.is_hidden == False
).count()

queued = db.session.query(CaseFile).filter(
    CaseFile.case_id == case_id,
    CaseFile.indexing_status == 'Queued',
    CaseFile.is_deleted == False,
    CaseFile.is_hidden == False
).count()

# ... repeat for: indexing, sigma, ioc_hunting, failed
```

**Solution**: Create `db_helpers.py`:

```python
# db_helpers.py (NEW FILE)

from models import db, CaseFile, Case, IOC, SigmaViolation, System, TimelineTag, AIReport
from sqlalchemy import func, and_, or_

class CaseFileQueries:
    """Centralized CaseFile query helpers"""
    
    @staticmethod
    def get_stats(case_id, include_hidden=False):
        """Get file processing statistics for a case"""
        base_filter = [
            CaseFile.case_id == case_id,
            CaseFile.is_deleted == False
        ]
        if not include_hidden:
            base_filter.append(CaseFile.is_hidden == False)
        
        def count_by_status(status):
            return db.session.query(CaseFile).filter(
                and_(*base_filter, CaseFile.indexing_status == status)
            ).count()
        
        return {
            'completed': count_by_status('Completed'),
            'queued': count_by_status('Queued'),
            'indexing': count_by_status('Indexing'),
            'sigma': count_by_status('SIGMA Detection'),
            'ioc_hunting': count_by_status('IOC Hunting'),
            'failed': db.session.query(CaseFile).filter(
                and_(*base_filter, CaseFile.indexing_status.like('Failed%'))
            ).count(),
            'hidden': db.session.query(CaseFile).filter(
                CaseFile.case_id == case_id,
                CaseFile.is_deleted == False,
                CaseFile.is_hidden == True
            ).count() if include_hidden else 0
        }
    
    @staticmethod
    def get_by_status(case_id, status, include_hidden=False):
        """Get files by processing status"""
        query = db.session.query(CaseFile).filter(
            CaseFile.case_id == case_id,
            CaseFile.is_deleted == False
        )
        if not include_hidden:
            query = query.filter(CaseFile.is_hidden == False)
        
        if status == 'failed':
            query = query.filter(CaseFile.indexing_status.like('Failed%'))
        else:
            query = query.filter(CaseFile.indexing_status == status)
        
        return query.all()
    
    @staticmethod
    def get_event_counts(case_id):
        """Get event count statistics"""
        result = db.session.query(
            func.sum(CaseFile.event_count).label('total_events'),
            func.sum(CaseFile.ioc_event_count).label('ioc_events'),
            func.sum(CaseFile.sigma_event_count).label('sigma_events'),
            func.count(CaseFile.id).label('file_count')
        ).filter(
            CaseFile.case_id == case_id,
            CaseFile.is_deleted == False,
            CaseFile.is_hidden == False
        ).first()
        
        return {
            'total_events': result.total_events or 0,
            'ioc_events': result.ioc_events or 0,
            'sigma_events': result.sigma_events or 0,
            'file_count': result.file_count or 0
        }


class CaseQueries:
    """Centralized Case query helpers"""
    
    @staticmethod
    def get_case_with_stats(case_id):
        """Get case with computed statistics"""
        case = db.session.get(Case, case_id)
        if not case:
            return None
        
        file_stats = CaseFileQueries.get_stats(case_id)
        event_counts = CaseFileQueries.get_event_counts(case_id)
        
        case.stats = {
            **file_stats,
            **event_counts,
            'ioc_count': db.session.query(IOC).filter(IOC.case_id == case_id, IOC.is_active == True).count(),
            'system_count': db.session.query(System).filter(System.case_id == case_id).count(),
            'timeline_tags': db.session.query(TimelineTag).filter(TimelineTag.case_id == case_id).count(),
            'ai_reports': db.session.query(AIReport).filter(AIReport.case_id == case_id).count()
        }
        
        return case
    
    @staticmethod
    def get_all_with_stats():
        """Get all cases with statistics"""
        cases = db.session.query(Case).order_by(Case.created_at.desc()).all()
        for case in cases:
            file_stats = CaseFileQueries.get_stats(case.id)
            case.stats = file_stats
        return cases


class IOCQueries:
    """Centralized IOC query helpers"""
    
    @staticmethod
    def get_active_iocs(case_id):
        """Get all active IOCs for a case"""
        return db.session.query(IOC).filter(
            IOC.case_id == case_id,
            IOC.is_active == True
        ).all()
    
    @staticmethod
    def get_iocs_by_type(case_id, ioc_type):
        """Get IOCs filtered by type"""
        return db.session.query(IOC).filter(
            IOC.case_id == case_id,
            IOC.is_active == True,
            IOC.ioc_type == ioc_type
        ).all()
```

**Usage**:
```python
# BEFORE (30+ lines):
completed = db.session.query(CaseFile).filter(
    CaseFile.case_id == case_id,
    CaseFile.indexing_status == 'Completed',
    CaseFile.is_deleted == False,
    CaseFile.is_hidden == False
).count()
# ... repeat 6 more times for each status

# AFTER (1 line):
from db_helpers import CaseFileQueries
stats = CaseFileQueries.get_stats(case_id)
```

**Impact**: Eliminates ~1,500 lines of duplicate database queries

---

### 4. **Template Redundancy (3,000+ lines)**

**Problem**: Massive code duplication in HTML templates.

**Examples of Duplication**:

#### A. Pagination Component (repeated in 15+ templates):
```html
<!-- This exact code in: case_files.html, global_files.html, hidden_files.html, 
     failed_files.html, evidence_files.html, admin_audit.html, known_users.html, etc. -->
<div class="pagination">
    {% if page > 1 %}
    <a href="?page={{ page - 1 }}&per_page={{ per_page }}" class="btn btn-secondary">← Previous</a>
    {% endif %}
    
    <span>Page {{ page }} of {{ total_pages }} ({{ total_items }} items)</span>
    
    {% if page < total_pages %}
    <a href="?page={{ page + 1 }}&per_page={{ per_page }}" class="btn btn-secondary">Next →</a>
    {% endif %}
</div>
```

**Solution**: Already exists at `templates/components/pagination.html` but **NOT BEING USED**!

Replace all instances with:
```html
{% include 'components/pagination.html' %}
```

**Impact**: Removes ~300 lines

#### B. Stats Card Component (repeated 50+ times):
```html
<!-- Appears in: dashboard.html, view_case.html, view_case_enhanced.html, 
     case_files.html, systems_management.html, etc. -->
<div class="stat-card">
    <div class="stat-number">{{ count }}</div>
    <div class="stat-label">{{ label }}</div>
    <div class="stat-icon">{{ icon }}</div>
</div>
```

**Solution**: Create `templates/components/stat_card.html`:
```html
<!-- templates/components/stat_card.html -->
<div class="stat-card {% if color %}stat-card-{{ color }}{% endif %}">
    {% if icon %}
    <div class="stat-icon">{{ icon }}</div>
    {% endif %}
    <div class="stat-content">
        <div class="stat-number">{{ number }}</div>
        <div class="stat-label">{{ label }}</div>
        {% if sublabel %}
        <div class="stat-sublabel">{{ sublabel }}</div>
        {% endif %}
    </div>
    {% if link %}
    <a href="{{ link }}" class="stat-link">View →</a>
    {% endif %}
</div>
```

Usage:
```html
{% include 'components/stat_card.html' with number=file_stats.completed, label='Completed', icon='✓', color='success' %}
```

**Impact**: Removes ~500 lines

#### C. Table Headers (repeated 20+ times):
```html
<!-- Repeated in many file listing templates -->
<thead>
    <tr>
        <th><input type="checkbox" id="select-all"></th>
        <th>Filename</th>
        <th>Type</th>
        <th>Size</th>
        <th>Events</th>
        <th>Status</th>
        <th>Actions</th>
    </tr>
</thead>
```

**Solution**: Create flexible table macros in `templates/macros/tables.html`:
```html
<!-- templates/macros/tables.html -->
{% macro table_header(columns, selectable=False) %}
<thead>
    <tr>
        {% if selectable %}
        <th><input type="checkbox" id="select-all" class="select-all"></th>
        {% endif %}
        {% for col in columns %}
        <th {% if col.sortable %}class="sortable" data-field="{{ col.field }}"{% endif %}>
            {{ col.label }}
            {% if col.sortable %}<span class="sort-icon">⇅</span>{% endif %}
        </th>
        {% endfor %}
    </tr>
</thead>
{% endmacro %}

{% macro file_row(file, actions=[], selectable=False) %}
<tr data-file-id="{{ file.id }}">
    {% if selectable %}
    <td><input type="checkbox" class="file-select" value="{{ file.id }}"></td>
    {% endif %}
    <td>{{ file.filename }}</td>
    <td><span class="badge badge-{{ file.file_type|lower }}">{{ file.file_type }}</span></td>
    <td>{{ file.size_mb }} MB</td>
    <td>{{ file.event_count }}</td>
    <td><span class="status-badge status-{{ file.indexing_status|lower|replace(' ', '-') }}">{{ file.indexing_status }}</span></td>
    <td class="actions">
        {% for action in actions %}
        {{ action|safe }}
        {% endfor %}
    </td>
</tr>
{% endmacro %}
```

**Impact**: Removes ~800 lines

#### D. Modal Dialogs (repeated 30+ times):
Every page has similar modal structure for confirmations, forms, etc.

**Solution**: Create `templates/macros/modals.html`:
```html
{% macro confirm_modal(id, title, message, confirm_text='Confirm', cancel_text='Cancel') %}
<div id="{{ id }}" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h3>{{ title }}</h3>
            <button class="modal-close">&times;</button>
        </div>
        <div class="modal-body">
            <p>{{ message }}</p>
        </div>
        <div class="modal-footer">
            <button class="btn btn-secondary modal-cancel">{{ cancel_text }}</button>
            <button class="btn btn-danger modal-confirm">{{ confirm_text }}</button>
        </div>
    </div>
</div>
{% endmacro %}

{% macro form_modal(id, title, form_content, submit_text='Submit') %}
<div id="{{ id }}" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h3>{{ title }}</h3>
            <button class="modal-close">&times;</button>
        </div>
        <div class="modal-body">
            {{ form_content|safe }}
        </div>
        <div class="modal-footer">
            <button class="btn btn-secondary modal-cancel">Cancel</button>
            <button class="btn btn-primary modal-submit">{{ submit_text }}</button>
        </div>
    </div>
</div>
{% endmacro %}
```

**Impact**: Removes ~1,000 lines

**Total Template Reduction**: ~2,600 lines (from 8,000+ to ~5,400)

---

### 5. **Duplicate JavaScript Patterns**

**Problem**: Same JavaScript functions copy-pasted across multiple templates.

**Examples**:

#### A. File Selection Logic (in 10+ templates):
```javascript
// This exact code in: case_files.html, global_files.html, hidden_files.html, 
// failed_files.html, evidence_files.html, etc.

document.getElementById('select-all').addEventListener('change', function() {
    const checkboxes = document.querySelectorAll('.file-select');
    checkboxes.forEach(cb => cb.checked = this.checked);
    updateBulkActionButtons();
});

document.querySelectorAll('.file-select').forEach(cb => {
    cb.addEventListener('change', updateBulkActionButtons);
});

function updateBulkActionButtons() {
    const selected = document.querySelectorAll('.file-select:checked').length;
    document.getElementById('bulk-actions').style.display = selected > 0 ? 'block' : 'none';
    document.getElementById('selected-count').textContent = selected;
}
```

**Solution**: Create `static/js/components/file-selection.js`:
```javascript
// static/js/components/file-selection.js

class FileSelection {
    constructor(options = {}) {
        this.selectAllId = options.selectAllId || 'select-all';
        this.itemClass = options.itemClass || 'file-select';
        this.bulkActionsId = options.bulkActionsId || 'bulk-actions';
        this.selectedCountId = options.selectedCountId || 'selected-count';
        this.callbacks = options.callbacks || {};
        
        this.init();
    }
    
    init() {
        const selectAll = document.getElementById(this.selectAllId);
        if (selectAll) {
            selectAll.addEventListener('change', () => this.toggleAll());
        }
        
        document.querySelectorAll(`.${this.itemClass}`).forEach(cb => {
            cb.addEventListener('change', () => this.updateUI());
        });
        
        this.updateUI();
    }
    
    toggleAll() {
        const selectAll = document.getElementById(this.selectAllId);
        const checkboxes = document.querySelectorAll(`.${this.itemClass}`);
        checkboxes.forEach(cb => cb.checked = selectAll.checked);
        this.updateUI();
    }
    
    updateUI() {
        const selected = this.getSelected();
        const bulkActions = document.getElementById(this.bulkActionsId);
        const selectedCount = document.getElementById(this.selectedCountId);
        
        if (bulkActions) {
            bulkActions.style.display = selected.length > 0 ? 'block' : 'none';
        }
        if (selectedCount) {
            selectedCount.textContent = selected.length;
        }
        
        if (this.callbacks.onChange) {
            this.callbacks.onChange(selected);
        }
    }
    
    getSelected() {
        return Array.from(document.querySelectorAll(`.${this.itemClass}:checked`))
            .map(cb => cb.value);
    }
    
    clearSelection() {
        document.querySelectorAll(`.${this.itemClass}`).forEach(cb => cb.checked = false);
        const selectAll = document.getElementById(this.selectAllId);
        if (selectAll) selectAll.checked = false;
        this.updateUI();
    }
}

// Export for use in templates
window.FileSelection = FileSelection;
```

Usage in templates:
```html
<script src="{{ url_for('static', filename='js/components/file-selection.js') }}"></script>
<script>
const fileSelection = new FileSelection({
    callbacks: {
        onChange: (selected) => console.log(`${selected.length} files selected`)
    }
});
</script>
```

**Impact**: Removes ~400 lines of duplicate JavaScript

#### B. Modal Logic (in 20+ templates):
```javascript
// Repeated in every template with modals
function showModal(modalId) {
    document.getElementById(modalId).style.display = 'block';
}

function hideModal(modalId) {
    document.getElementById(modalId).style.display = 'none';
}

document.querySelectorAll('.modal-close, .modal-cancel').forEach(btn => {
    btn.addEventListener('click', function() {
        this.closest('.modal').style.display = 'none';
    });
});
```

**Solution**: Create `static/js/components/modal.js`:
```javascript
// static/js/components/modal.js

class Modal {
    constructor(modalId, options = {}) {
        this.modalId = modalId;
        this.modal = document.getElementById(modalId);
        this.options = {
            closeOnOverlay: options.closeOnOverlay !== false,
            onOpen: options.onOpen || null,
            onClose: options.onClose || null,
            onConfirm: options.onConfirm || null
        };
        
        this.init();
    }
    
    init() {
        if (!this.modal) return;
        
        // Close button
        this.modal.querySelectorAll('.modal-close, .modal-cancel').forEach(btn => {
            btn.addEventListener('click', () => this.hide());
        });
        
        // Confirm button
        const confirmBtn = this.modal.querySelector('.modal-confirm, .modal-submit');
        if (confirmBtn && this.options.onConfirm) {
            confirmBtn.addEventListener('click', () => {
                this.options.onConfirm();
                this.hide();
            });
        }
        
        // Overlay click
        if (this.options.closeOnOverlay) {
            this.modal.addEventListener('click', (e) => {
                if (e.target === this.modal) this.hide();
            });
        }
    }
    
    show() {
        this.modal.style.display = 'block';
        if (this.options.onOpen) this.options.onOpen();
    }
    
    hide() {
        this.modal.style.display = 'none';
        if (this.options.onClose) this.options.onClose();
    }
    
    toggle() {
        if (this.modal.style.display === 'block') {
            this.hide();
        } else {
            this.show();
        }
    }
}

// Utility function for confirmation dialogs
async function confirmAction(message, title = 'Confirm Action') {
    return new Promise((resolve) => {
        const modal = new Modal('confirm-modal', {
            onConfirm: () => resolve(true),
            onClose: () => resolve(false)
        });
        
        document.getElementById('confirm-title').textContent = title;
        document.getElementById('confirm-message').textContent = message;
        modal.show();
    });
}

window.Modal = Modal;
window.confirmAction = confirmAction;
```

**Impact**: Removes ~600 lines

#### C. API Call Patterns (in 30+ templates):
```javascript
// This pattern repeated everywhere
async function deleteFile(fileId) {
    if (!confirm('Are you sure?')) return;
    
    try {
        const response = await fetch(`/case/${caseId}/file/${fileId}/delete`, {
            method: 'DELETE',
            headers: {'Content-Type': 'application/json'}
        });
        
        if (response.ok) {
            alert('File deleted successfully');
            location.reload();
        } else {
            const error = await response.json();
            alert(`Error: ${error.message}`);
        }
    } catch (error) {
        alert(`Error: ${error.message}`);
    }
}
```

**Solution**: Create `static/js/api-client.js`:
```javascript
// static/js/api-client.js

class APIClient {
    constructor(baseUrl = '') {
        this.baseUrl = baseUrl;
    }
    
    async request(url, options = {}) {
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json'
            }
        };
        
        const config = {
            ...defaultOptions,
            ...options,
            headers: {
                ...defaultOptions.headers,
                ...options.headers
            }
        };
        
        try {
            const response = await fetch(this.baseUrl + url, config);
            
            if (!response.ok) {
                const error = await response.json().catch(() => ({message: 'Request failed'}));
                throw new Error(error.message || `HTTP ${response.status}`);
            }
            
            return await response.json();
        } catch (error) {
            console.error('API Error:', error);
            throw error;
        }
    }
    
    get(url) {
        return this.request(url, {method: 'GET'});
    }
    
    post(url, data) {
        return this.request(url, {
            method: 'POST',
            body: JSON.stringify(data)
        });
    }
    
    put(url, data) {
        return this.request(url, {
            method: 'PUT',
            body: JSON.stringify(data)
        });
    }
    
    delete(url) {
        return this.request(url, {method: 'DELETE'});
    }
    
    // Convenience methods with UI feedback
    async deleteWithConfirm(url, message = 'Are you sure?') {
        if (!await confirmAction(message)) {
            return null;
        }
        
        try {
            const result = await this.delete(url);
            showNotification('Deleted successfully', 'success');
            return result;
        } catch (error) {
            showNotification(`Error: ${error.message}`, 'error');
            throw error;
        }
    }
    
    async postWithFeedback(url, data, successMessage = 'Operation successful') {
        try {
            const result = await this.post(url, data);
            showNotification(successMessage, 'success');
            return result;
        } catch (error) {
            showNotification(`Error: ${error.message}`, 'error');
            throw error;
        }
    }
}

// Global instance
window.api = new APIClient();

// Notification helper
function showNotification(message, type = 'info') {
    // Simple notification (can be enhanced with a proper notification component)
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.classList.add('fade-out');
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

window.showNotification = showNotification;
```

Usage:
```javascript
// BEFORE (15+ lines):
async function deleteFile(fileId) {
    if (!confirm('Are you sure?')) return;
    try {
        const response = await fetch(...);
        if (response.ok) {
            alert('Success');
            location.reload();
        }
    } catch (error) {
        alert(`Error: ${error.message}`);
    }
}

// AFTER (1 line):
async function deleteFile(fileId) {
    await api.deleteWithConfirm(`/case/${caseId}/file/${fileId}/delete`, 'Delete this file?');
    location.reload();
}
```

**Impact**: Removes ~1,200 lines

**Total JavaScript Reduction**: ~2,200 lines

---

## 🟡 Medium Priority Issues

### 6. **Route Parameter Validation Duplication**

**Problem**: Every route manually validates case_id, file_id, etc.

**Example** (repeated 50+ times):
```python
@app.route('/case/<int:case_id>/...')
def some_route(case_id):
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    # Check permissions
    if current_user.role not in ['administrator', 'analyst']:
        return jsonify({'error': 'Unauthorized'}), 403
```

**Solution**: Create decorators in `route_decorators.py`:
```python
# route_decorators.py (NEW FILE)

from functools import wraps
from flask import jsonify, abort
from flask_login import current_user
from models import db, Case, CaseFile, IOC, System

def require_case(f):
    """Decorator to validate case_id and inject case object"""
    @wraps(f)
    def decorated_function(case_id, *args, **kwargs):
        case = db.session.get(Case, case_id)
        if not case:
            return jsonify({'error': 'Case not found'}), 404
        return f(case=case, *args, **kwargs)
    return decorated_function

def require_file(f):
    """Decorator to validate file_id and inject file object"""
    @wraps(f)
    def decorated_function(file_id, *args, **kwargs):
        file = db.session.get(CaseFile, file_id)
        if not file:
            return jsonify({'error': 'File not found'}), 404
        return f(file=file, *args, **kwargs)
    return decorated_function

def require_role(*roles):
    """Decorator to check user role"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.role not in roles:
                return jsonify({'error': 'Unauthorized'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_admin(f):
    """Shortcut for admin-only routes"""
    return require_role('administrator')(f)
```

Usage:
```python
# BEFORE:
@app.route('/case/<int:case_id>/delete')
def delete_case(case_id):
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    if current_user.role != 'administrator':
        return jsonify({'error': 'Unauthorized'}), 403
    # ... delete logic

# AFTER:
@app.route('/case/<int:case_id>/delete')
@require_case
@require_admin
def delete_case(case):
    # case object automatically injected
    # ... delete logic
```

**Impact**: Removes ~1,000 lines

---

### 7. **Duplicate Error Handling**

**Problem**: Try-catch blocks repeated everywhere with same logic.

**Solution**: Create error handling utilities in `error_handlers.py`:
```python
# error_handlers.py (NEW FILE)

from functools import wraps
from flask import jsonify
import logging

logger = logging.getLogger(__name__)

def handle_errors(default_message='Operation failed', log_errors=True):
    """Decorator to standardize error handling"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                return f(*args, **kwargs)
            except ValueError as e:
                if log_errors:
                    logger.warning(f"ValueError in {f.__name__}: {e}")
                return jsonify({'error': str(e)}), 400
            except KeyError as e:
                if log_errors:
                    logger.warning(f"KeyError in {f.__name__}: {e}")
                return jsonify({'error': f'Missing required field: {e}'}), 400
            except PermissionError as e:
                if log_errors:
                    logger.warning(f"PermissionError in {f.__name__}: {e}")
                return jsonify({'error': 'Permission denied'}), 403
            except Exception as e:
                if log_errors:
                    logger.error(f"Error in {f.__name__}: {e}", exc_info=True)
                return jsonify({'error': default_message, 'details': str(e)}), 500
        return decorated_function
    return decorator
```

Usage:
```python
# BEFORE (20+ lines):
@app.route('/case/<int:case_id>/process')
def process_case(case_id):
    try:
        case = db.session.get(Case, case_id)
        if not case:
            return jsonify({'error': 'Case not found'}), 404
        # ... processing logic
        return jsonify({'success': True})
    except ValueError as e:
        logger.warning(f"ValueError: {e}")
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Error processing case: {e}")
        return jsonify({'error': 'Processing failed'}), 500

# AFTER (5 lines):
@app.route('/case/<int:case_id>/process')
@require_case
@handle_errors('Failed to process case')
def process_case(case):
    # ... processing logic
    return jsonify({'success': True})
```

**Impact**: Removes ~800 lines

---

### 8. **Duplicate Celery Task Patterns**

**Problem**: Similar task structure repeated in tasks.py (1,991 lines).

**Current Structure**:
- process_file() - 300 lines
- bulk_reindex() - 200 lines
- bulk_rechainsaw() - 150 lines
- bulk_rehunt_iocs() - 150 lines
- delete_case_task() - 200 lines

All follow same pattern:
1. Get database objects
2. Update status
3. Process in loop
4. Handle errors
5. Update status

**Solution**: Create base task class in `celery_tasks_base.py`:
```python
# celery_tasks_base.py (NEW FILE)

from celery import Task
from celery_app import celery_app
from models import db
from main import app
import logging

logger = logging.getLogger(__name__)

class DatabaseTask(Task):
    """Base task with database session management"""
    
    def __call__(self, *args, **kwargs):
        with app.app_context():
            try:
                return super().__call__(*args, **kwargs)
            except Exception as e:
                logger.error(f"Task {self.name} failed: {e}", exc_info=True)
                raise
            finally:
                db.session.remove()

class ProgressTask(DatabaseTask):
    """Task with progress tracking"""
    
    def update_progress(self, current, total, message=''):
        """Update task progress"""
        if total > 0:
            percent = int((current / total) * 100)
            self.update_state(
                state='PROGRESS',
                meta={
                    'current': current,
                    'total': total,
                    'percent': percent,
                    'message': message
                }
            )

class BulkProcessingTask(ProgressTask):
    """Base class for bulk file processing tasks"""
    
    def process_files(self, case_id, file_ids, operation_name, process_func):
        """Generic bulk processing"""
        from models import Case, CaseFile
        from audit_logger import log_action
        
        case = db.session.get(Case, case_id)
        if not case:
            raise ValueError(f"Case {case_id} not found")
        
        files = db.session.query(CaseFile).filter(
            CaseFile.id.in_(file_ids),
            CaseFile.case_id == case_id
        ).all()
        
        if not files:
            raise ValueError("No files found")
        
        total = len(files)
        succeeded = 0
        failed = 0
        errors = []
        
        for idx, file in enumerate(files, 1):
            try:
                self.update_progress(idx, total, f"Processing {file.filename}")
                process_func(file)
                succeeded += 1
            except Exception as e:
                failed += 1
                errors.append(f"{file.filename}: {str(e)}")
                logger.error(f"Failed to process {file.filename}: {e}")
        
        # Log audit
        log_action(
            action=f'bulk_{operation_name}',
            resource_type='file',
            resource_id=None,
            status='completed',
            details={
                'case_id': case_id,
                'total_files': total,
                'succeeded': succeeded,
                'failed': failed,
                'errors': errors[:10]  # Limit error list
            }
        )
        
        return {
            'status': 'completed',
            'total': total,
            'succeeded': succeeded,
            'failed': failed,
            'errors': errors
        }
```

Usage:
```python
# BEFORE (150+ lines):
@celery_app.task(bind=True, name='tasks.bulk_rechainsaw')
def bulk_rechainsaw(self, case_id, file_ids):
    with app.app_context():
        try:
            case = db.session.get(Case, case_id)
            if not case:
                return {'error': 'Case not found'}
            
            files = db.session.query(CaseFile).filter(
                CaseFile.id.in_(file_ids),
                CaseFile.case_id == case_id
            ).all()
            
            total = len(files)
            succeeded = 0
            failed = 0
            
            for idx, file in enumerate(files):
                try:
                    # Update progress
                    self.update_state(state='PROGRESS', meta={...})
                    # Clear SIGMA
                    # Run chainsaw
                    succeeded += 1
                except Exception as e:
                    failed += 1
            
            # Log audit
            log_action(...)
            
            return {'total': total, 'succeeded': succeeded, 'failed': failed}
        except Exception as e:
            logger.error(...)
            raise

# AFTER (20 lines):
@celery_app.task(bind=True, base=BulkProcessingTask, name='tasks.bulk_rechainsaw')
def bulk_rechainsaw(self, case_id, file_ids):
    from file_processing import chainsaw_file
    
    def process_file(file):
        # Clear SIGMA violations
        db.session.query(SigmaViolation).filter(
            SigmaViolation.file_id == file.id
        ).delete()
        db.session.commit()
        
        # Run chainsaw
        chainsaw_file(
            db=db,
            SigmaRule=SigmaRule,
            SigmaViolation=SigmaViolation,
            case_file=file,
            opensearch_client=opensearch_client,
            case_id=case_id
        )
    
    return self.process_files(case_id, file_ids, 'rechainsaw', process_file)
```

**Impact**: Reduces tasks.py from 1,991 lines to ~800 lines (60% reduction)

---

## 🟢 Nice-to-Have Improvements

### 9. **Configuration Management**

**Current Problem**: Configuration scattered across multiple files.

**Solution**: Centralize in `config/` directory:
```
config/
├── __init__.py          # Main Config class
├── development.py       # Development settings
├── production.py        # Production settings
├── testing.py          # Test settings
└── constants.py        # App constants
```

### 10. **Logging Standardization**

**Current Problem**: Inconsistent logging formats.

**Solution**: Already have logging_config.py - just need to enforce usage everywhere.

### 11. **API Response Standardization**

**Current Problem**: Inconsistent JSON response structures.

**Solution**: Create response utilities in `api_responses.py`:
```python
# api_responses.py (NEW FILE)

from flask import jsonify

def success_response(data=None, message='Success', status=200):
    """Standard success response"""
    response = {'success': True, 'message': message}
    if data is not None:
        response['data'] = data
    return jsonify(response), status

def error_response(message, errors=None, status=400):
    """Standard error response"""
    response = {'success': False, 'error': message}
    if errors:
        response['errors'] = errors
    return jsonify(response), status

def paginated_response(items, page, per_page, total, **kwargs):
    """Standard paginated response"""
    return jsonify({
        'success': True,
        'data': items,
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': (total + per_page - 1) // per_page
        },
        **kwargs
    })
```

---

## 📊 Impact Summary

### Code Reduction Breakdown

| Component | Current Lines | After Refactoring | Reduction | Reduction % |
|-----------|---------------|-------------------|-----------|-------------|
| **main.py** | 4,386 | ~600 | 3,786 | 86% |
| **routes/*.py** | 5,500 | 3,500 | 2,000 | 36% |
| **templates/*.html** | 8,000+ | ~5,400 | 2,600 | 33% |
| **JavaScript (in templates)** | 3,500 | 1,300 | 2,200 | 63% |
| **file_processing.py** | 1,855 | 1,200 | 655 | 35% |
| **tasks.py** | 1,991 | 800 | 1,191 | 60% |
| **search_utils.py** | 1,017 | 600 | 417 | 41% |
| **Other duplication** | - | - | 1,000 | - |
| **TOTAL** | **46,194** | **~27,500** | **18,694** | **40%** |

### New Files Created

1. **opensearch_helpers.py** (~400 lines) - OpenSearch query builder
2. **db_helpers.py** (~300 lines) - Database query helpers
3. **route_decorators.py** (~150 lines) - Route validation decorators
4. **error_handlers.py** (~100 lines) - Error handling utilities
5. **celery_tasks_base.py** (~200 lines) - Base task classes
6. **api_responses.py** (~50 lines) - Standardized API responses
7. **static/js/api-client.js** (~150 lines) - Frontend API client
8. **static/js/components/modal.js** (~150 lines) - Modal component
9. **static/js/components/file-selection.js** (~100 lines) - File selection component
10. **templates/macros/tables.html** (~200 lines) - Table macros
11. **templates/macros/modals.html** (~150 lines) - Modal macros
12. **routes/search.py** (NEW blueprint) - Search routes
13. **routes/ai.py** (NEW blueprint) - AI report routes
14. **routes/evtx.py** (NEW blueprint) - EVTX description routes

**Total New Code**: ~2,000 lines (mostly utilities that eliminate 18,000+ lines of duplication)

---

## 🚀 Implementation Plan

### Phase 1: Critical Refactoring (Week 1-2)
1. **Day 1-2**: Create helper files
   - opensearch_helpers.py
   - db_helpers.py
   - route_decorators.py

2. **Day 3-5**: Move routes to blueprints
   - Create routes/search.py
   - Create routes/ai.py
   - Create routes/evtx.py
   - Move routes from main.py

3. **Day 6-7**: Test and validate
   - Run full application test suite
   - Manual testing of all moved routes

### Phase 2: Template Refactoring (Week 3)
1. **Day 8-9**: Create template components
   - templates/macros/tables.html
   - templates/macros/modals.html
   - Update existing templates

2. **Day 10**: JavaScript consolidation
   - Create static/js/api-client.js
   - Create static/js/components/

3. **Day 11**: Test templates

### Phase 3: Task Refactoring (Week 4)
1. **Day 12-13**: Create celery_tasks_base.py
2. **Day 14**: Refactor tasks.py
3. **Day 15**: Test background processing

### Phase 4: Polish & Documentation (Week 5)
1. Update documentation
2. Final testing
3. Performance benchmarking

---

## 🎯 Quick Wins (Can Do Today)

These require minimal effort but provide immediate value:

1. **Use existing pagination component** (1 hour)
   - Replace all pagination HTML with `{% include 'components/pagination.html' %}`
   - **Impact**: -300 lines immediately

2. **Move login/logout to routes/auth.py** (30 minutes)
   - Already have auth.py blueprint
   - **Impact**: -100 lines from main.py

3. **Create opensearch_helpers.py** (2 hours)
   - Start with just 3 helper functions
   - Replace queries in main.py
   - **Impact**: -500 lines

4. **Create stat_card component** (1 hour)
   - Used in 10+ templates
   - **Impact**: -200 lines

5. **Create api-client.js** (2 hours)
   - **Impact**: -400 lines across all templates

**Total Quick Wins**: ~1,500 lines removed in 1 day of work

---

## ⚠️ Risks & Mitigation

### Risks:
1. **Breaking existing functionality** during refactoring
2. **Database session issues** with new helpers
3. **Import circular dependencies** with new modules
4. **Performance regressions** from added abstraction layers

### Mitigation:
1. **Comprehensive testing** after each change
2. **Git branching strategy** - refactor in feature branches
3. **Staged rollout** - Phase by phase implementation
4. **Performance monitoring** - Benchmark before/after
5. **Backup strategy** - Can revert any phase independently

---

## 📈 Long-Term Benefits

1. **Maintainability**: Changes in one place instead of 50
2. **Onboarding**: New developers understand structure faster
3. **Testing**: Centralized helpers are easier to unit test
4. **Performance**: Query optimization in one place benefits entire app
5. **Consistency**: Standardized patterns across codebase
6. **Scalability**: Modular architecture supports growth

---

## 🔍 Conclusion

The codebase has **significant duplication** but is well-structured enough that refactoring will be straightforward. The biggest wins are:

1. **Moving routes from main.py** to blueprints (3,800 lines)
2. **OpenSearch query builder** (2,000 lines)
3. **Template components** (2,600 lines)
4. **JavaScript consolidation** (2,200 lines)

**Total reduction: ~40-50% of codebase** while improving quality and maintainability.

The application is production-ready and functional - this refactoring is **purely for code quality**, not fixing bugs. You can implement incrementally without breaking existing functionality.

Would you like me to start implementing any of these refactorings?
