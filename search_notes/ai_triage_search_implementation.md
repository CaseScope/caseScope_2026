# AI Triage Search - Implementation Plan

**Created**: 2025-11-29  
**Purpose**: Blueprint for implementing the fully automated AI Triage Search feature by reusing existing code.

---

## Overview

The AI Triage Search combines:
1. **Triage IOC Discovery** (exists in `triage_report.py`)
2. **MITRE Pattern Matching** (exists in `ai_search.py`)
3. **Time Window Analysis** (NEW - ~10 lines)
4. **Process Tree Building** (NEW - ~10 lines)
5. **Orchestration** (NEW - ties it together)

**Goal**: User clicks "AI Search" button → enters date → system automatically finds IOCs, hunts related activity, builds process trees, identifies MITRE techniques, and generates attack narrative.

---

## Existing Code to Reuse

### From `app/ai_search.py`

```python
from app.ai_search import (
    # Attack Detection
    identify_attack_techniques,      # Returns {technique_id: [matching_events]}
    generate_attack_analysis,        # Returns formatted attack analysis string
    MITRE_ATTACK_PATTERNS,           # Dict of technique indicators
    
    # Kill Chain Analysis
    determine_kill_chain_phase,      # Maps techniques → kill chain phase
    get_kill_chain_context,          # Context string for LLM
    get_gap_analysis,                # What to look for if not found
    KILL_CHAIN_PHASES,               # Full kill chain definition
    GAP_ANALYSIS,                    # Gap analysis templates
    
    # User Investigation
    get_user_timeline,               # Timeline for specific user
    analyze_user_compromise,         # Compromise analysis
    
    # Query Expansion
    expand_query_for_dfir,           # "malware" → 30+ search terms
    DFIR_QUERY_EXPANSION,            # Expansion dictionary
    
    # Pattern Detection
    IntelligentSampler,              # Class with detection methods:
                                     #   ._detect_suspicious_processes()
                                     #   ._detect_lateral_movement()
                                     #   ._detect_password_spray()
    
    # Exclusions
    COMMON_EXCLUSIONS,               # Known-good processes
)
```

### From `app/routes/triage_report.py`

```python
from app.routes.triage_report import (
    # IOC Extraction
    extract_iocs_with_llm,           # LLM-based IOC extraction
    extract_iocs_with_regex,         # Regex fallback
    
    # Search Functions
    search_ioc,                      # Search OpenSearch for IOC term
    extract_from_search_results,     # Extract IPs/hostnames/users from results
    extract_recon_from_results,      # Extract commands/executables from results
    extract_defender_threats,        # Get Defender threat names
    
    # Validation
    is_valid_hostname,               # Filter invalid hostnames
    is_machine_account,              # Filter machine accounts (ending in $)
    
    # Constants
    RECON_SEARCH_TERMS,              # ['nltest', 'whoami', 'ipconfig', ...]
    NOT_HOSTNAMES,                   # Blocklist for hostname validation
    NOT_USERNAMES,                   # Blocklist for username validation
)
```

### From `app/search_utils.py`

```python
from app.search_utils import (
    build_search_query,              # Build OpenSearch query with filters
    execute_search,                  # Execute query and return results
)
```

---

## New Code to Add (~50 lines total)

### 1. Time Window Search Function

```python
from datetime import datetime, timedelta

def search_time_window(opensearch_client, case_id: int, hostname: str, 
                       anchor_time: datetime, minutes: int = 5) -> List[Dict]:
    """
    Search for all events ±N minutes around an anchor timestamp.
    
    Args:
        opensearch_client: OpenSearch client
        case_id: Case ID
        hostname: Computer name to filter by
        anchor_time: Center timestamp
        minutes: Window size (default ±5 minutes)
    
    Returns:
        List of events sorted by timestamp
    """
    start = (anchor_time - timedelta(minutes=minutes)).isoformat()
    end = (anchor_time + timedelta(minutes=minutes)).isoformat()
    
    query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"normalized_computer.keyword": hostname}},
                    {"range": {"@timestamp": {"gte": start, "lte": end}}}
                ]
            }
        },
        "sort": [{"@timestamp": "asc"}],
        "size": 500,
        "_source": ["@timestamp", "process.name", "process.command_line", 
                   "process.parent.name", "process.parent.pid", "process.pid",
                   "process.user.name", "process.user.domain", "process.hash.sha256",
                   "has_ioc", "matched_iocs", "has_sigma", "sigma_rules", "search_blob"]
    }
    
    result = opensearch_client.search(index=f"case_{case_id}", body=query)
    return [hit['_source'] for hit in result['hits']['hits']]
```

### 2. Process Tree Builder Function

```python
def build_process_tree(opensearch_client, case_id: int, parent_pid: str, 
                       hostname: str, time_window_hours: int = 24) -> List[Dict]:
    """
    Find all child processes spawned by a parent PID.
    
    Args:
        opensearch_client: OpenSearch client
        case_id: Case ID
        parent_pid: Parent process ID to find children of
        hostname: Computer name to filter by
        time_window_hours: How far back to search
    
    Returns:
        List of child process events sorted by timestamp
    """
    query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"process.parent.pid": str(parent_pid)}},
                    {"term": {"normalized_computer.keyword": hostname}}
                ]
            }
        },
        "sort": [{"@timestamp": "asc"}],
        "size": 100,
        "_source": ["@timestamp", "process.name", "process.command_line",
                   "process.pid", "process.parent.pid", "process.parent.name",
                   "process.user.name", "process.user.domain"]
    }
    
    result = opensearch_client.search(index=f"case_{case_id}", body=query)
    return [hit['_source'] for hit in result['hits']['hits']]


def get_process_siblings(opensearch_client, case_id: int, parent_pid: str,
                         hostname: str) -> List[Dict]:
    """Find all processes with the same parent (siblings)."""
    return build_process_tree(opensearch_client, case_id, parent_pid, hostname)
```

### 3. Anchor Event Finder

```python
def find_anchor_events(opensearch_client, case_id: int, iocs: Dict,
                       start_date: str, end_date: str) -> List[Dict]:
    """
    Find events that match extracted IOCs - these are our anchor points.
    
    Args:
        opensearch_client: OpenSearch client
        case_id: Case ID
        iocs: Dict with keys: ips, hostnames, usernames, file_paths, hashes
        start_date: Search window start
        end_date: Search window end
    
    Returns:
        List of anchor events with timestamps and matched IOC info
    """
    anchors = []
    
    # Search each IOC type
    for ioc_type, ioc_list in iocs.items():
        for ioc_value in ioc_list:
            results, total = search_ioc(opensearch_client, case_id, ioc_value)
            for event in results:
                anchors.append({
                    'event': event,
                    'matched_ioc': ioc_value,
                    'ioc_type': ioc_type,
                    'timestamp': event.get('@timestamp')
                })
    
    # Deduplicate by event ID and sort by timestamp
    seen = set()
    unique_anchors = []
    for a in sorted(anchors, key=lambda x: x['timestamp'] or ''):
        event_id = a['event'].get('_id')
        if event_id not in seen:
            seen.add(event_id)
            unique_anchors.append(a)
    
    return unique_anchors
```

### 4. Main Orchestrator Function

```python
def ai_triage_search(case_id: int, report_text: str, search_date: datetime,
                     window_hours: int = 24) -> Dict:
    """
    Full automated AI Triage Search.
    
    Phases:
    1. Extract IOCs from report (reuse triage_report.py)
    2. Hunt IOCs to discover new ones (reuse triage_report.py)
    3. Hunt malware/recon indicators (reuse triage_report.py)
    4. Find anchor events (NEW)
    5. Search time windows around anchors (NEW)
    6. Build process trees (NEW)
    7. Apply MITRE pattern matching (reuse ai_search.py)
    8. Generate attack narrative (reuse ai_search.py)
    
    Returns:
        Dict with iocs, timeline, process_trees, mitre_techniques, narrative
    """
    from app.ai_search import (
        identify_attack_techniques,
        determine_kill_chain_phase,
        generate_attack_analysis,
        get_gap_analysis
    )
    from app.routes.triage_report import (
        extract_iocs_with_llm,
        extract_iocs_with_regex,
        search_ioc,
        extract_from_search_results,
        extract_recon_from_results,
        RECON_SEARCH_TERMS
    )
    
    results = {
        'iocs': {},
        'anchors': [],
        'time_windows': [],
        'process_trees': [],
        'mitre_techniques': {},
        'kill_chain_phase': None,
        'narrative': '',
        'timeline': []
    }
    
    # =========================================================================
    # PHASE 1-3: IOC Extraction & Hunting (REUSE EXISTING)
    # =========================================================================
    
    # Extract IOCs from report
    iocs = extract_iocs_with_llm(report_text)
    if not iocs or not any(iocs.values()):
        iocs = extract_iocs_with_regex(report_text)
    
    results['iocs']['from_report'] = iocs
    
    # Calculate search window
    start_date = (search_date - timedelta(hours=window_hours)).isoformat()
    end_date = (search_date + timedelta(hours=window_hours)).isoformat()
    
    # Hunt IOCs (snowball discovery)
    discovered_ips = set()
    discovered_hostnames = set()
    discovered_usernames = set()
    
    for ip in iocs.get('ips', []):
        search_results, _ = search_ioc(opensearch_client, case_id, ip)
        new_ips, new_hosts, new_users = extract_from_search_results(search_results)
        discovered_ips.update(new_ips)
        discovered_hostnames.update(new_hosts)
        discovered_usernames.update(new_users)
    
    # ... (repeat for hostnames, usernames - same as triage_report.py)
    
    results['iocs']['discovered'] = {
        'ips': list(discovered_ips),
        'hostnames': list(discovered_hostnames),
        'usernames': list(discovered_usernames)
    }
    
    # =========================================================================
    # PHASE 4: Find Anchor Events (NEW)
    # =========================================================================
    
    all_iocs = {
        'ips': list(set(iocs.get('ips', []) + list(discovered_ips))),
        'hostnames': list(set(iocs.get('hostnames', []) + list(discovered_hostnames))),
        'usernames': list(set(iocs.get('usernames', []) + list(discovered_usernames))),
        'file_paths': iocs.get('file_paths', []),
        'hashes': iocs.get('hashes', [])
    }
    
    anchors = find_anchor_events(opensearch_client, case_id, all_iocs, 
                                  start_date, end_date)
    results['anchors'] = anchors
    
    # =========================================================================
    # PHASE 5: Time Window Analysis (NEW)
    # =========================================================================
    
    all_window_events = []
    for anchor in anchors[:20]:  # Limit to top 20 anchors
        hostname = anchor['event'].get('normalized_computer') or \
                   anchor['event'].get('host', {}).get('hostname')
        if not hostname:
            continue
            
        anchor_time = datetime.fromisoformat(anchor['timestamp'].replace('Z', '+00:00'))
        window_events = search_time_window(opensearch_client, case_id, 
                                           hostname, anchor_time, minutes=5)
        all_window_events.extend(window_events)
        
        results['time_windows'].append({
            'anchor': anchor,
            'events': window_events
        })
    
    # =========================================================================
    # PHASE 6: Process Tree Building (NEW)
    # =========================================================================
    
    # Find suspicious parent PIDs to investigate
    suspicious_parents = set()
    for event in all_window_events:
        proc = event.get('process', {})
        parent = proc.get('parent', {})
        parent_name = (parent.get('name') or '').lower()
        proc_name = (proc.get('name') or '').lower()
        
        # Browser spawning executable = suspicious
        if parent_name in ['firefox.exe', 'chrome.exe', 'msedge.exe', 'iexplore.exe']:
            if proc_name.endswith('.exe') and proc_name not in [parent_name]:
                suspicious_parents.add((parent.get('pid'), event.get('normalized_computer')))
        
        # cmd.exe or powershell spawning recon tools
        if parent_name in ['cmd.exe', 'powershell.exe']:
            if proc_name in ['nltest.exe', 'whoami.exe', 'net.exe', 'ipconfig.exe']:
                suspicious_parents.add((parent.get('pid'), event.get('normalized_computer')))
    
    for parent_pid, hostname in suspicious_parents:
        if parent_pid and hostname:
            tree = build_process_tree(opensearch_client, case_id, parent_pid, hostname)
            if tree:
                results['process_trees'].append({
                    'parent_pid': parent_pid,
                    'hostname': hostname,
                    'children': tree
                })
    
    # =========================================================================
    # PHASE 7: MITRE Pattern Matching (REUSE EXISTING)
    # =========================================================================
    
    # Convert events to format expected by identify_attack_techniques
    formatted_events = []
    for event in all_window_events:
        formatted_events.append({
            '_source': event,
            '_id': event.get('_id', str(hash(str(event))))
        })
    
    techniques = identify_attack_techniques(formatted_events)
    results['mitre_techniques'] = techniques
    
    kill_chain = determine_kill_chain_phase(techniques)
    results['kill_chain_phase'] = kill_chain
    
    # =========================================================================
    # PHASE 8: Generate Narrative (REUSE EXISTING)
    # =========================================================================
    
    narrative = generate_attack_analysis(formatted_events)
    results['narrative'] = narrative
    
    # Build timeline
    timeline = []
    for event in sorted(all_window_events, key=lambda x: x.get('@timestamp', '')):
        proc = event.get('process', {})
        timeline.append({
            'timestamp': event.get('@timestamp'),
            'process': proc.get('name'),
            'command': proc.get('command_line'),
            'user': f"{proc.get('user', {}).get('domain', '')}\\{proc.get('user', {}).get('name', '')}",
            'parent': proc.get('parent', {}).get('name'),
            'techniques': [t for t, evts in techniques.items() 
                          if any(e.get('_id') == event.get('_id') for e in evts)]
        })
    results['timeline'] = timeline
    
    return results
```

---

## File Structure

```
app/
├── ai_search.py              # Existing - MITRE patterns, attack analysis
├── routes/
│   ├── triage_report.py      # Existing - IOC extraction, hunting
│   └── ai_triage_search.py   # NEW - Orchestrator + time window + process tree
├── templates/
│   └── search_events.html    # Add "AI Search" button to existing modal
```

---

## Frontend Changes

### Add to `search_events.html`

1. **New Button** (next to existing Triage Report button):
```html
<button onclick="showAITriageSearchModal()" class="btn btn-primary">
    🔍 AI Search
</button>
```

2. **Modal** (similar to existing triage modal):
```html
<div id="aiTriageSearchModal" class="modal-overlay" style="display: none;">
    <div class="modal-container">
        <div class="modal-header">
            <h3>🔍 AI Triage Search</h3>
            <button onclick="closeAITriageSearchModal()" class="modal-close">×</button>
        </div>
        <div class="modal-body">
            <!-- Phase 1: Date Input -->
            <div id="aiSearchDatePhase">
                <label>Enter investigation date:</label>
                <input type="datetime-local" id="aiSearchDate">
                <button onclick="startAITriageSearch()">Start Analysis</button>
            </div>
            
            <!-- Phase 2: Progress -->
            <div id="aiSearchProgressPhase" style="display: none;">
                <div class="progress-log" id="aiSearchProgressLog"></div>
            </div>
            
            <!-- Phase 3: Results -->
            <div id="aiSearchResultsPhase" style="display: none;">
                <div id="aiSearchResults"></div>
            </div>
        </div>
    </div>
</div>
```

3. **JavaScript**:
```javascript
async function startAITriageSearch() {
    const date = document.getElementById('aiSearchDate').value;
    const caseId = {{ case_id }};
    
    // Show progress phase
    document.getElementById('aiSearchDatePhase').style.display = 'none';
    document.getElementById('aiSearchProgressPhase').style.display = 'block';
    
    // Stream results via SSE
    const eventSource = new EventSource(`/case/${caseId}/ai-triage-search/stream?date=${date}`);
    
    eventSource.onmessage = function(event) {
        const data = JSON.parse(event.data);
        if (data.type === 'progress') {
            appendProgress(data.message);
        } else if (data.type === 'complete') {
            showResults(data.results);
            eventSource.close();
        }
    };
}
```

---

## API Endpoints

### New Route: `/case/<case_id>/ai-triage-search/stream`

```python
@ai_triage_search_bp.route('/case/<int:case_id>/ai-triage-search/stream')
@login_required
def ai_triage_search_stream(case_id):
    """Stream AI Triage Search results via SSE."""
    date_str = request.args.get('date')
    search_date = datetime.fromisoformat(date_str)
    
    def generate():
        # Get case description as report
        case = Case.query.get(case_id)
        report_text = case.description or ''
        
        yield f"data: {json.dumps({'type': 'progress', 'message': 'Starting analysis...'})}\n\n"
        
        # Run the analysis
        results = ai_triage_search(case_id, report_text, search_date)
        
        yield f"data: {json.dumps({'type': 'complete', 'results': results})}\n\n"
    
    return Response(generate(), mimetype='text/event-stream')
```

---

## Testing Checklist

1. [ ] Test on Case 17 (JELLY) - RDP compromise + recon
2. [ ] Test on Case 18 (JHD) - Phishing + malicious RMM
3. [ ] Test on Case 22 (SERVU) - Phishing + ScreenConnect
4. [ ] Test on Case 11 (DEPCO) - Lateral movement + Cobalt Strike
5. [ ] Test on Case 8 (CM) - VPN compromise + domain enum

---

## Summary

| Component | Lines of Code | Source |
|-----------|---------------|--------|
| MITRE Pattern Matching | 0 | Reuse `ai_search.py` |
| Kill Chain Analysis | 0 | Reuse `ai_search.py` |
| Attack Narrative | 0 | Reuse `ai_search.py` |
| IOC Extraction | 0 | Reuse `triage_report.py` |
| Snowball Hunting | 0 | Reuse `triage_report.py` |
| Recon Detection | 0 | Reuse `triage_report.py` |
| Time Window Search | ~20 | NEW |
| Process Tree Builder | ~20 | NEW |
| Anchor Event Finder | ~30 | NEW |
| Orchestrator | ~100 | NEW |
| Frontend Modal | ~50 | NEW |
| API Endpoint | ~30 | NEW |
| **TOTAL NEW CODE** | **~250 lines** | |

**90% reuse of existing code. Only ~250 lines of new code needed.**

