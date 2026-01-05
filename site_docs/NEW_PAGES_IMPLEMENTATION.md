# New Pages Implementation Guide
## Based on layout.MD Structure

This document tracks the implementation of new forensic artifact pages in CaseScope.

---

## ✅ Completed

### Parser Routing (Updated)
**File:** `app/utils/parser_routing.py`

All parsers now route to correct indices per layout.MD:
- ✅ `case_X_useractivity` - jumplist, lnk
- ✅ `case_X_comms` - pst, teams_skype, notifications  
- ✅ `case_X_network` - bits
- ✅ `case_X_persistence` - schtasks, wmi
- ✅ `case_X_devices` - usb, setupapi
- ✅ `case_X_cloud` - onedrive
- ✅ `case_X_remote` - rdp_cache

### Pages Created
1. ✅ **User Activity** (`templates/useractivity/shortcuts.html`)
   - Jump Lists and LNK shortcuts
   - Search/filter by type and user
   - Statistics dashboard
   - Event details modal

---

## 📋 TODO: Remaining Pages

### 1. Communications Page
**Template:** `templates/communications/messages.html`  
**Route:** `/communications/<case_id>`  
**Icon:** 💬  
**Index:** `case_X_comms`

**Parsers:**
- PST/OST emails (pst_parser)
- Teams/Skype messages (teams_skype_parser)
- Windows notifications (notifications_parser)

**Features to Include:**
- Email count, message count, notification count
- Search by sender, recipient, subject, content
- Filter by communication type (email/teams/notifications)
- Timeline view of communications
- Attachment indicators for emails
- Suspicious attachment detection

---

### 2. Network Activity Page  
**Template:** `templates/network/activity.html`  
**Route:** `/network/<case_id>`  
**Icon:** 🌐  
**Index:** `case_X_network`

**Parsers:**
- BITS transfers (bits_parser)
- SRUM network data (srum_parser - network portion)

**Features to Include:**
- Total downloads, bytes transferred
- Active/completed/failed transfers
- Search by URL, file path
- Filter by transfer state
- Suspicious download indicators (C2 domains, known bad URLs)
- Timeline of network activity

---

### 3. Persistence Page
**Template:** `templates/persistence/mechanisms.html`  
**Route:** `/persistence/<case_id>`  
**Icon:** 🔒  
**Index:** `case_X_persistence`

**Parsers:**
- Scheduled Tasks (schtasks_parser)
- WMI persistence (wmi_parser)

**Features to Include:**
- Total persistence mechanisms found
- Risk level indicators (high/medium/low)
- Suspicious command detection (PowerShell, encoded, hidden)
- Search by task name, command, author
- Filter by risk level
- WMI event subscriptions and consumers
- Timeline of task creation

---

### 4. Devices Page
**Template:** `templates/devices/history.html`  
**Route:** `/devices/<case_id>`  
**Icon:** 💾  
**Index:** `case_X_devices`

**Parsers:**
- USB history (usb_history_parser)
- SetupAPI logs (setupapi_parser)

**Features to Include:**
- Total devices connected
- Unique device count
- Search by vendor, serial number, device name
- Filter by device type (disk, phone, etc.)
- Timeline of connections/disconnections
- Unknown/suspicious device indicators

---

### 5. Cloud Storage Page
**Template:** `templates/cloud/sync.html`  
**Route:** `/cloud/<case_id>`  
**Icon:** ☁️  
**Index:** `case_X_cloud`

**Parsers:**
- OneDrive (onedrive_parser)

**Features to Include:**
- Total files synced
- Upload/download counts
- Search by file path, operation type
- Filter by operation (upload/download/delete)
- Account information
- Sync folder locations
- Timeline of cloud activity

---

### 6. Remote Sessions Page
**Template:** `templates/remote/sessions.html`  
**Route:** `/remote/<case_id>`  
**Icon:** 🖥️  
**Index:** `case_X_remote`

**Parsers:**
- RDP Cache (rdp_cache_parser)

**Features to Include:**
- Total RDP cache entries
- Bitmap tile count
- Search by timestamp
- Visual indicators (if bitmap reconstruction available)
- Session timeline
- Cache size statistics

---

## Implementation Template

Each page should follow this structure:

```html
{% extends "base.html" %}

{% block title %}[Page Name] - CaseScope 2026{% endblock %}
{% block header_title %}[Page Name]{% endblock %}

{% block content %}
<div class="content-header">
    <h1 class="content-title">[Icon] [Page Name]</h1>
    <p class="content-subtitle">{{ case.name }}</p>
</div>

<!-- Statistics Card -->
<div class="card mb-4">
    <div class="card-header">
        <h3 class="card-title mb-0">Summary</h3>
    </div>
    <div class="card-body">
        <div class="grid grid-4">
            <!-- Stats here -->
        </div>
    </div>
</div>

<!-- Search and Filters -->
<div class="card mb-4">
    <div class="card-header">
        <h3 class="card-title mb-0">Search & Filter</h3>
    </div>
    <div class="card-body">
        <!-- Search inputs and filters -->
    </div>
</div>

<!-- Results -->
<div class="card mb-4">
    <div class="card-header">
        <h3 class="card-title mb-0">📋 Results</h3>
    </div>
    <div class="card-body">
        <div id="resultsContainer"></div>
        <!-- Pagination -->
    </div>
</div>

<!-- Details Modal -->
<div id="eventDetailsModal" class="modal-overlay" style="display: none;">
    <!-- Modal content -->
</div>

<script>
// Page-specific JavaScript
</script>
{% endblock %}
```

---

## Route Handlers Needed

Create route handlers in `app/routes/`:

```python
# app/routes/useractivity.py
from flask import Blueprint, render_template, jsonify, request
from opensearch_indexer import OpenSearchIndexer

useractivity_bp = Blueprint('useractivity', __name__, url_prefix='/useractivity')

@useractivity_bp.route('/<int:case_id>')
def shortcuts(case_id):
    # Render page
    pass

@useractivity_bp.route('/api/stats/<int:case_id>')
def api_stats(case_id):
    # Return statistics
    pass

@useractivity_bp.route('/api/events/<int:case_id>')
def api_events(case_id):
    # Return paginated events
    pass

@useractivity_bp.route('/api/users/<int:case_id>')
def api_users(case_id):
    # Return list of users
    pass
```

Register in `main.py`:
```python
from routes.useractivity import useractivity_bp
app.register_blueprint(useractivity_bp)
```

---

## Sidebar Navigation Update

Update `templates/base.html` sidebar to include new pages:

```html
<!-- Existing pages -->
<a href="/search/{{ session.get('current_case_id') }}">🔍 Search</a>
<a href="/browser/{{ session.get('current_case_id') }}">🌐 Browser History</a>
<a href="/execution/{{ session.get('current_case_id') }}">⚡ Execution</a>
<a href="/filesystem/{{ session.get('current_case_id') }}">📁 Filesystem</a>

<!-- NEW pages -->
<a href="/useractivity/{{ session.get('current_case_id') }}">👤 User Activity</a>
<a href="/communications/{{ session.get('current_case_id') }}">💬 Communications</a>
<a href="/network/{{ session.get('current_case_id') }}">🌐 Network</a>
<a href="/persistence/{{ session.get('current_case_id') }}">🔒 Persistence</a>
<a href="/devices/{{ session.get('current_case_id') }}">💾 Devices</a>
<a href="/cloud/{{ session.get('current_case_id') }}">☁️ Cloud</a>
<a href="/remote/{{ session.get('current_case_id') }}">🖥️ Remote Sessions</a>
```

---

## Priority Order

Implement in this order for maximum impact:

1. **Persistence** - Critical for threat hunting
2. **Communications** - High-value evidence
3. **Network Activity** - C2/exfiltration detection
4. **Devices** - Data theft detection
5. **Cloud Storage** - Exfiltration tracking
6. **Remote Sessions** - Lateral movement evidence

---

## Testing Checklist

For each page:
- [ ] Page loads without errors
- [ ] Statistics display correctly
- [ ] Search functionality works
- [ ] Filters apply properly
- [ ] Pagination works
- [ ] Event details modal displays
- [ ] API endpoints return valid JSON
- [ ] No console errors
- [ ] Responsive on mobile
- [ ] Matches existing page styling

---

## Notes

- All pages use the same OpenSearch query pattern
- Reuse JavaScript functions from existing pages where possible
- Follow existing naming conventions
- Use the parser_routing.py module for index names
- Add appropriate error handling
- Log API errors for debugging

