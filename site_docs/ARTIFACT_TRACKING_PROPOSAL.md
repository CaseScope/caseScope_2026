# Artifact Tracking Proposal
## Comprehensive Evidence Metrics Dashboard

---

## Current State (Files-Only Tracking)

**Current Metrics on Case Files Page:**
- ✅ Total Files - Keep
- ✅ Total Events - **EXPAND to Total Artifacts**
- ✅ Indexed Files - Keep
- ✅ Pending Files - Keep
- ✅ Files Not Indexed - Keep
- ✅ Files with 0 Events - Keep
- ✅ Total Size - Keep

**Problem:** Only tracks files and "events" count, doesn't distinguish between different artifact types across 11 indices.

---

## Proposed Solution: Multi-Index Artifact Dashboard

### Option 1: Expand Case Dashboard (Recommended)
**Location:** `/case/dashboard/<case_id>`  
**Template:** `templates/case/dashboard.html`

Add new section below Case Information with comprehensive artifact metrics:

```
📊 Evidence Artifacts Summary
┌─────────────────────────────────────────────────────────────┐
│  TOTAL ARTIFACTS: 1,234,567                                 │
│  ACROSS 11 INDICES                                          │
└─────────────────────────────────────────────────────────────┘

Events & Logs (case_X)
├─ 🔍 Event Logs (EVTX): 485,392 events
├─ 📊 EDR/NDJSON: 234,156 events  
├─ 🔥 Firewall Logs: 89,432 events
└─ Total: 809,980 events

Browser Activity (case_X_browser)
├─ 🌐 Browser Visits: 15,234 visits
├─ ⬇️ Downloads: 342 files
└─ Total: 15,576 artifacts

Execution Artifacts (case_X_execution)
├─ ⚡ Prefetch: 1,234 files
├─ 🔗 LNK Shortcuts: 456 shortcuts (MOVED to useractivity)
├─ 📋 Jump Lists: 123 lists (MOVED to useractivity)
├─ 📊 Activities Cache: 5,678 entries
└─ Total: 7,491 artifacts

Filesystem Timeline (case_X_filesystem)
├─ 📁 MFT Entries: 2,456,789 entries
├─ 🖼️ Thumbcache: 1,234 thumbnails
├─ 🔍 Windows Search: 45,678 indexed items
└─ Total: 2,503,701 artifacts

User Activity (case_X_useractivity) ⭐ NEW
├─ 📋 Jump Lists: 123 lists
├─ 🔗 LNK Shortcuts: 456 shortcuts
└─ Total: 579 artifacts

Communications (case_X_comms) ⭐ NEW
├─ 📧 Email (PST/OST): 12,345 messages
├─ 💬 Teams/Skype: 567 messages
├─ 🔔 Notifications: 890 notifications
└─ Total: 13,802 artifacts

Network Activity (case_X_network) ⭐ NEW
├─ ⬇️ BITS Transfers: 234 jobs
├─ 🌐 SRUM Network: 1,234 connections
└─ Total: 1,468 artifacts

Persistence (case_X_persistence) ⭐ NEW
├─ ⏰ Scheduled Tasks: 89 tasks
│  └─ 🚨 High Risk: 12 tasks
├─ 🔮 WMI Subscriptions: 23 subscriptions
│  └─ 🚨 Suspicious: 5 subscriptions
└─ Total: 112 artifacts

Devices (case_X_devices) ⭐ NEW
├─ 💾 USB Devices: 45 devices
│  └─ 🔌 Connections: 234 events
├─ 📝 SetupAPI Logs: 567 entries
└─ Total: 801 artifacts

Cloud Storage (case_X_cloud) ⭐ NEW
├─ ☁️ OneDrive Syncs: 1,234 operations
│  ├─ ⬆️ Uploads: 456
│  ├─ ⬇️ Downloads: 678
│  └─ 🗑️ Deletions: 100
└─ Total: 1,234 artifacts

Remote Sessions (case_X_remote) ⭐ NEW
├─ 🖥️ RDP Cache: 234 bitmap tiles
├─ 📸 Cache Files: 12 cache files
└─ Total: 246 artifacts
```

---

## Implementation Details

### Database Schema (No Changes Needed!)
The `case_file` table already has everything we need:
```sql
- id, case_id, filename, file_size  -- File tracking
- status, event_count               -- Processing status
- parser_type                        -- NEW: Use this!
- target_index                       -- Which OpenSearch index
```

### Metrics to Track

#### Keep from Current System:
✅ **File-Level Metrics:**
- Total Files
- Indexed Files  
- Pending Files (status='New')
- Files Not Indexed (status='ParseFail', 'UnableToParse')
- Files with 0 Events (event_count=0)
- Total Size (GB)

#### Add NEW Artifact Metrics:
⭐ **Per-Index Artifact Counts:**

Query each OpenSearch index:
```python
def get_artifact_counts(case_id):
    indices = {
        'events': f'case_{case_id}',
        'browser': f'case_{case_id}_browser',
        'execution': f'case_{case_id}_execution',
        'filesystem': f'case_{case_id}_filesystem',
        'useractivity': f'case_{case_id}_useractivity',
        'comms': f'case_{case_id}_comms',
        'network': f'case_{case_id}_network',
        'persistence': f'case_{case_id}_persistence',
        'devices': f'case_{case_id}_devices',
        'cloud': f'case_{case_id}_cloud',
        'remote': f'case_{case_id}_remote',
    }
    
    counts = {}
    for key, index_name in indices.items():
        try:
            count = opensearch.count(index=index_name)
            counts[key] = count.get('count', 0)
        except NotFoundError:
            counts[key] = 0
    
    return counts
```

#### Breakdown by Artifact Type (using aggregations):

For each index, aggregate by `event_type.keyword`:
```python
{
    "size": 0,
    "aggs": {
        "by_type": {
            "terms": {"field": "event_type.keyword", "size": 50}
        }
    }
}
```

Returns:
- case_X: evtx_event, edr_event, firewall_event
- case_X_browser: browser_visit, browser_download, webcache_entry
- case_X_execution: prefetch_run, activities_entry
- case_X_useractivity: jumplist_entry, lnk_shortcut
- case_X_comms: email_message, teams_message, notification
- case_X_persistence: scheduled_task, wmi_subscription
- case_X_devices: usb_connection, setupapi_event
- case_X_cloud: onedrive_upload, onedrive_download, onedrive_delete
- case_X_remote: rdp_cache_tile

---

## Proposed Dashboard Layout

### Collapsible Sections (Accordion Style)

```
┌─ 📄 FILE SUMMARY (always visible)
│  Total: 7,323 | Indexed: 7,155 | Pending: 168 | Size: 2.24 GB
└─────────────────────────────────────────────────────────────

┌─ 📊 ARTIFACT SUMMARY (expandable) ⭐ CLICK TO EXPAND
│  └─ Total Artifacts Across All Indices: 3,245,678
│
│  ┌─ 🔍 Events & Logs (809,980)
│  │  ├─ Event Logs (EVTX): 485,392
│  │  ├─ EDR/Sysmon: 234,156
│  │  └─ Firewall: 89,432
│  │
│  ┌─ 🌐 Browser Activity (15,576)  
│  │  ├─ Visits: 14,234
│  │  ├─ Downloads: 342
│  │  └─ WebCache: 1,000
│  │
│  ┌─ ⚡ Execution Artifacts (7,491)
│  │  ├─ Prefetch: 1,234
│  │  ├─ Activities: 5,678
│  │  └─ SRUM: 579
│  │
│  ┌─ 📁 Filesystem Timeline (2,503,701)
│  │  ├─ MFT Entries: 2,456,789
│  │  ├─ Thumbcache: 1,234
│  │  └─ WinSearch: 45,678
│  │
│  ┌─ 👤 User Activity (579) ⭐ NEW
│  │  ├─ Jump Lists: 123
│  │  └─ LNK Shortcuts: 456
│  │
│  ┌─ 💬 Communications (13,802) ⭐ NEW
│  │  ├─ Emails: 12,345
│  │  ├─ Teams/Skype: 567
│  │  └─ Notifications: 890
│  │
│  ┌─ 🌐 Network Activity (1,468) ⭐ NEW
│  │  └─ BITS Transfers: 1,468
│  │
│  ┌─ 🔒 Persistence (112) ⭐ NEW
│  │  ├─ Scheduled Tasks: 89 (🚨 12 high risk)
│  │  └─ WMI: 23 (🚨 5 suspicious)
│  │
│  ┌─ 💾 Devices (801) ⭐ NEW
│  │  └─ USB Connections: 801
│  │
│  ┌─ ☁️ Cloud Storage (1,234) ⭐ NEW
│  │  └─ OneDrive Operations: 1,234
│  │
│  └─ 🖥️ Remote Sessions (246) ⭐ NEW
│     └─ RDP Cache: 246 tiles
└─────────────────────────────────────────────────────────────

┌─ ⚠️ PROCESSING STATUS (if active)
│  └─ 168 files currently being processed
│     Worker 1: System.evtx (45,234 events so far)
│     Worker 2: $MFT (parsing...)
└─────────────────────────────────────────────────────────────
```

---

## Implementation Plan

### Step 1: Create Artifact Stats API
**File:** `app/routes/case.py`

```python
@case_bp.route('/api/artifact-stats/<int:case_id>')
@login_required
def api_artifact_stats(case_id):
    """
    Get comprehensive artifact statistics across all indices
    """
    from opensearch_indexer import OpenSearchIndexer
    from opensearchpy.exceptions import NotFoundError
    
    indexer = OpenSearchIndexer()
    client = indexer.client
    
    stats = {
        'total_artifacts': 0,
        'indices': {}
    }
    
    # Define all indices
    indices_config = {
        'events': {
            'name': f'case_{case_id}',
            'label': 'Events & Logs',
            'icon': '🔍'
        },
        'browser': {
            'name': f'case_{case_id}_browser',
            'label': 'Browser Activity',
            'icon': '🌐'
        },
        'execution': {
            'name': f'case_{case_id}_execution',
            'label': 'Execution Artifacts',
            'icon': '⚡'
        },
        'filesystem': {
            'name': f'case_{case_id}_filesystem',
            'label': 'Filesystem Timeline',
            'icon': '📁'
        },
        'useractivity': {
            'name': f'case_{case_id}_useractivity',
            'label': 'User Activity',
            'icon': '👤'
        },
        'comms': {
            'name': f'case_{case_id}_comms',
            'label': 'Communications',
            'icon': '💬'
        },
        'network': {
            'name': f'case_{case_id}_network',
            'label': 'Network Activity',
            'icon': '🌐'
        },
        'persistence': {
            'name': f'case_{case_id}_persistence',
            'label': 'Persistence',
            'icon': '🔒'
        },
        'devices': {
            'name': f'case_{case_id}_devices',
            'label': 'Devices',
            'icon': '💾'
        },
        'cloud': {
            'name': f'case_{case_id}_cloud',
            'label': 'Cloud Storage',
            'icon': '☁️'
        },
        'remote': {
            'name': f'case_{case_id}_remote',
            'label': 'Remote Sessions',
            'icon': '🖥️'
        }
    }
    
    # Query each index
    for key, config in indices_config.items():
        index_name = config['name']
        
        try:
            # Get total count
            count_result = client.count(index=index_name)
            total = count_result.get('count', 0)
            
            # Get breakdown by event_type
            agg_query = {
                "size": 0,
                "aggs": {
                    "by_type": {
                        "terms": {
                            "field": "event_type.keyword",
                            "size": 20
                        }
                    }
                }
            }
            
            agg_result = client.search(index=index_name, body=agg_query)
            buckets = agg_result.get('aggregations', {}).get('by_type', {}).get('buckets', [])
            
            breakdown = [
                {
                    'type': b['key'],
                    'count': b['doc_count']
                }
                for b in buckets
            ]
            
            stats['indices'][key] = {
                'label': config['label'],
                'icon': config['icon'],
                'total': total,
                'breakdown': breakdown
            }
            
            stats['total_artifacts'] += total
            
        except NotFoundError:
            stats['indices'][key] = {
                'label': config['label'],
                'icon': config['icon'],
                'total': 0,
                'breakdown': []
            }
    
    return jsonify(stats)
```

### Step 2: Update Dashboard Template

Add collapsible artifact section to `templates/case/dashboard.html`:

```html
<!-- After Case Description, before existing content -->

<!-- Artifact Statistics Section -->
<div class="card mb-4">
    <div class="card-header" style="cursor: pointer;" onclick="toggleArtifactStats()">
        <div class="d-flex justify-content-between align-items-center">
            <h2 class="card-title mb-0">📊 Evidence Artifacts</h2>
            <div class="d-flex align-items-center gap-3">
                <span id="artifactTotalBadge" class="badge badge-primary">
                    Loading...
                </span>
                <span id="artifactToggleIcon">▼</span>
            </div>
        </div>
    </div>
    
    <!-- File Summary (Always Visible) -->
    <div class="card-body border-bottom">
        <div class="grid grid-6">
            <div class="stat-card-compact">
                <div class="stat-label">Files</div>
                <div class="stat-value" id="stat-files">-</div>
            </div>
            <div class="stat-card-compact">
                <div class="stat-label">Indexed</div>
                <div class="stat-value text-success" id="stat-indexed">-</div>
            </div>
            <div class="stat-card-compact">
                <div class="stat-label">Pending</div>
                <div class="stat-value text-warning" id="stat-pending">-</div>
            </div>
            <div class="stat-card-compact">
                <div class="stat-label">Failed</div>
                <div class="stat-value text-error" id="stat-failed">-</div>
            </div>
            <div class="stat-card-compact">
                <div class="stat-label">Zero Events</div>
                <div class="stat-value text-muted" id="stat-zero">-</div>
            </div>
            <div class="stat-card-compact">
                <div class="stat-label">Total Size</div>
                <div class="stat-value" id="stat-size">-</div>
            </div>
        </div>
    </div>
    
    <!-- Detailed Artifact Breakdown (Collapsible) -->
    <div id="artifactDetailsSection" class="card-body" style="display: none;">
        <div id="artifactBreakdown">
            <!-- Populated by JavaScript -->
        </div>
    </div>
</div>
```

### Step 3: JavaScript for Dynamic Loading

```javascript
async function loadArtifactStats() {
    try {
        const response = await fetch(`/case/api/artifact-stats/{{ case.id }}`);
        const data = await response.json();
        
        // Update total badge
        document.getElementById('artifactTotalBadge').textContent = 
            formatNumber(data.total_artifacts) + ' Total Artifacts';
        
        // Build breakdown HTML
        let html = '';
        
        for (const [key, index] of Object.entries(data.indices)) {
            if (index.total > 0) {
                html += `
                    <div class="artifact-index-section mb-3">
                        <div class="d-flex justify-content-between align-items-center mb-2">
                            <h4>${index.icon} ${index.label}</h4>
                            <span class="badge badge-info">${formatNumber(index.total)}</span>
                        </div>
                        <div class="artifact-breakdown">
                `;
                
                // Show breakdown by type
                index.breakdown.forEach(item => {
                    html += `
                        <div class="d-flex justify-content-between text-small mb-1">
                            <span>${item.type}</span>
                            <span class="text-muted">${formatNumber(item.count)}</span>
                        </div>
                    `;
                });
                
                html += `
                        </div>
                    </div>
                `;
            }
        }
        
        document.getElementById('artifactBreakdown').innerHTML = html || 
            '<p class="text-muted">No artifacts indexed yet</p>';
        
    } catch (error) {
        console.error('Error loading artifact stats:', error);
    }
}

function toggleArtifactStats() {
    const section = document.getElementById('artifactDetailsSection');
    const icon = document.getElementById('artifactToggleIcon');
    
    if (section.style.display === 'none') {
        section.style.display = 'block';
        icon.textContent = '▲';
        loadArtifactStats(); // Load on first expand
    } else {
        section.style.display = 'none';
        icon.textContent = '▼';
    }
}
```

---

## Option 2: Dedicated Artifacts Overview Page (Alternative)

Create new page: `/case/artifacts/<case_id>`

**Advantages:**
- Doesn't clutter dashboard
- Can have more detailed visualizations
- Separate navigation item

**Disadvantages:**
- One more click to see artifact overview
- Less visible to users

---

## Recommendation: Hybrid Approach

1. **Case Dashboard:** Keep file metrics + collapsible artifact summary
2. **Case Files Page:** Keep current file table (useful for file management)
3. **New "Evidence Overview" Page:** Deep-dive artifact analytics with:
   - Timeline view across all indices
   - Heat map of artifact types
   - System/user correlation
   - Suspicious artifact highlighting

---

## Metrics Summary

### KEEP (Existing File Metrics):
- ✅ Total Files
- ✅ Indexed Files
- ✅ Pending Files
- ✅ Files Not Indexed
- ✅ Files with 0 Events
- ✅ Total Size (GB)

### ADD (New Artifact Metrics):
- ⭐ Total Artifacts (sum across all 11 indices)
- ⭐ Per-Index Counts (11 indices)
- ⭐ Per-Type Breakdown (event_type aggregations)
- ⭐ Risk Indicators (high-risk persistence, suspicious WMI)
- ⭐ Timeline Distribution (artifacts over time)
- ⭐ Source System Breakdown (artifacts per computer)

### REMOVE/CONSOLIDATE:
- ❌ "Total Events" → Replace with "Total Artifacts" (more accurate)
- ❌ Separate per-page stats → Consolidate into single overview

---

## Priority Implementation

1. **Add API endpoint** - `/case/api/artifact-stats/<case_id>` (1 hour)
2. **Update dashboard template** - Add collapsible section (30 min)
3. **Add JavaScript** - Load and display breakdown (30 min)
4. **Testing** - Verify counts match across indices (30 min)

**Total Effort:** ~2.5 hours for complete implementation

---

## Next Steps

Choose approach:
- **Option A:** Expand Case Dashboard with collapsible artifact section (recommended)
- **Option B:** Create dedicated "Evidence Overview" page
- **Option C:** Hybrid (both)

I recommend **Option A** as it provides immediate visibility without adding navigation complexity.

