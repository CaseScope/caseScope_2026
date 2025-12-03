# Events Triage - Technical Reference

Complete documentation for the Triage system, including the prerequisites page and modular IOC extraction. This document provides enough detail to reconstruct the entire system.

---

## Overview

The Triage system provides a guided workflow for AI-powered attack chain analysis. Instead of a monolithic "run everything" approach, it breaks triage into individual phases that can be run manually as prerequisites are met. Each phase is a standalone module that can be triggered independently.

### Key Concepts

| Term | Description |
|------|-------------|
| **Triage** | Automated analysis to identify attack chains from event data |
| **Prerequisites** | Required configuration before running triage phases |
| **Phase** | An individual triage step (e.g., IOC Extraction, Snowball Hunting) |
| **EDR Report** | Analyst-pasted security report from EDR/MDR vendor |
| **IOC** | Indicator of Compromise (IP, hash, hostname, username, etc.) |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         PREREQUISITES LAYER                              │
│  Triage Page (triage.html)                                              │
│  ├── System Scan Check: Are systems defined?                            │
│  ├── EDR Report Check: Is there an EDR report?                         │
│  ├── IOCs Defined Check: Are there active IOCs?                        │
│  ├── Tagged Events Check: Are there timeline tags?                     │
│  └── Triage Date Check: Is a focus date set?                           │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         MODULE LAYER                                     │
│  app/ai_triage_edr_ioc.py (Phase 1 - IOC Extraction)                   │
│  ├── is_ai_enabled() - Check AI system setting                         │
│  ├── extract_iocs_with_llm() - AI extraction (QWEN)                    │
│  ├── extract_iocs_with_regex() - Regex fallback                        │
│  └── extract_iocs_from_report() - Main entry point                     │
│                                                                         │
│  Future modules:                                                        │
│  ├── ai_triage_snowball.py (Phase 2 - Snowball Hunting)                │
│  ├── ai_triage_patterns.py (Phase 3 - Attack Pattern Detection)        │
│  └── ai_triage_timeline.py (Phase 4 - Timeline Generation)             │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         ROUTES LAYER                                     │
│  app/main.py                                                            │
│  ├── GET  /case/<id>/triage - Triage page                              │
│  ├── POST /case/<id>/triage/extract-iocs - Run IOC extraction          │
│  └── POST /case/<id>/triage/add-extracted-iocs - Save IOCs to DB       │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         STORAGE LAYER                                    │
│  PostgreSQL: IOC table (extracted IOCs)                                 │
│  PostgreSQL: AITriageSearch table (triage history)                      │
│  OpenSearch: case_{id} index (event data for hunting)                   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Triage Page Template

### File: `app/templates/triage.html`

The triage page displays prerequisites status and provides action buttons for each phase.

### Template Variables

| Variable | Type | Description |
|----------|------|-------------|
| `case` | Case | The current case object |
| `systems_configured` | bool | True if systems are defined |
| `system_count` | int | Number of systems |
| `has_edr_report` | bool | True if EDR report exists |
| `has_iocs` | bool | True if active IOCs exist |
| `ioc_count` | int | Number of active IOCs |
| `has_tagged_events` | bool | True if timeline tags exist |
| `tag_count` | int | Number of tagged events |
| `has_triage_date` | bool | True if triage date is set |
| `triage_date` | datetime | The configured triage date |
| `previous_triages` | list | Recent AITriageSearch records |
| `ai_enabled` | bool | True if AI is enabled in settings |

### Prerequisite Cards

Each prerequisite is displayed as a card with:
- **Status icon**: ✅ (complete), ⚠️ (warning), ❌ (missing), 💡 (optional)
- **Status badge**: Pill badge showing count or status (uses `.badge-pill` CSS class)
- **Action button**: Link to configure or view the prerequisite
- **Conditional styling**: Border color indicates status (success/warning/error/muted)

```html
<div class="prereq-card" style="
    background: var(--color-background-secondary);
    border-radius: var(--border-radius);
    padding: var(--spacing-lg);
    border-left: 4px solid {% if condition %}var(--color-success){% else %}var(--color-warning){% endif %};
">
    <!-- Header with title and badge -->
    <div style="display: flex; justify-content: space-between; ...">
        <h4>{% if condition %}✅{% else %}⚠️{% endif %} 1. System Scan</h4>
        <span class="badge-pill {% if condition %}badge-pill-success{% else %}badge-pill-warning{% endif %}">
            {{ count }} Systems
        </span>
    </div>
    
    <!-- Status message and action button -->
    {% if condition %}
        <p style="color: var(--color-success);">✓ Systems configured</p>
        <a href="..." class="btn btn-secondary btn-sm" style="opacity: 0.7;">View Systems</a>
    {% else %}
        <p style="color: var(--color-warning);">⚠️ No systems defined</p>
        <a href="..." class="btn btn-primary btn-sm">Configure Systems</a>
    {% endif %}
</div>
```

### Triage Actions Section

Individual phase buttons that can be run manually:

```html
<div class="card">
    <div class="card-header">
        <h2 class="card-title">🎯 Triage Actions</h2>
    </div>
    <div class="card-body">
        <!-- Phase 1: IOC Extraction -->
        <div style="display: flex; align-items: center; gap: var(--spacing-md); ...">
            <div style="flex: 1;">
                <h4>Phase 1: IOC Extraction</h4>
                <p>Extract IOCs using {% if ai_enabled %}AI{% else %}regex{% endif %}</p>
            </div>
            <div>
                {% if has_edr_report %}
                    <button onclick="extractIOCs()" class="btn btn-sm btn-primary">
                        📋 Extract IOCs from EDR Report
                    </button>
                {% else %}
                    <button disabled class="btn btn-sm" style="opacity: 0.5;">
                        📋 Extract IOCs from EDR Report
                    </button>
                {% endif %}
            </div>
        </div>
    </div>
</div>
```

---

## IOC Extraction Module

### File: `app/ai_triage_edr_ioc.py`

Standalone module for extracting IOCs from EDR/MDR reports. Supports AI extraction (QWEN) with regex fallback.

### Module Functions

| Function | Purpose |
|----------|---------|
| `is_ai_enabled()` | Check if AI is enabled in system settings |
| `get_ollama_host()` | Get configured Ollama host from settings |
| `is_valid_hostname(hostname, ip_set)` | Validate hostname format |
| `extract_iocs_with_llm(report_text)` | AI extraction using QWEN model |
| `extract_iocs_with_regex(report_text)` | Regex-based extraction (fallback) |
| `extract_iocs_from_report(report_text, force_regex)` | **Main entry point** |
| `get_ioc_summary(iocs)` | Generate summary for UI display |

### Flow Logic

```python
def extract_iocs_from_report(report_text: str, force_regex: bool = False) -> Dict:
    """
    Flow:
    1. If force_regex=True → skip AI, use regex
    2. Check is_ai_enabled() from system settings
    3. If AI enabled → try LLM, fall back to regex on failure
    4. If AI disabled → use regex directly
    """
    if force_regex:
        iocs = extract_iocs_with_regex(report_text)
        iocs['extraction_method'] = 'regex'
        return iocs
    
    if is_ai_enabled():
        iocs = extract_iocs_with_llm(report_text)
        if iocs:
            iocs['extraction_method'] = 'llm'
            return iocs
        else:
            # LLM failed, fall back
            iocs = extract_iocs_with_regex(report_text)
            iocs['extraction_method'] = 'regex_fallback'
            return iocs
    else:
        iocs = extract_iocs_with_regex(report_text)
        iocs['extraction_method'] = 'regex'
        return iocs
```

### LLM Extraction

**Model:** `dfir-qwen:latest` (hardcoded for best IOC extraction accuracy)

**Prompt Structure:**
```
Extract IOCs from the following EDR/security report. Return ONLY valid JSON.

SCHEMA (use empty arrays [] if none found):
{
  "usernames": ["exact usernames only"],
  "sids": ["S-1-5-21-... format only"],
  "ips": ["IP addresses - defang: 91.236.230[.]136 becomes 91.236.230.136"],
  "hostnames": ["computer names like SERVER01, DC1"],
  "domains": ["domain names like evil.com"],
  "processes": ["executable names like nltest.exe"],
  "paths": ["file/folder paths like C:\\Users\\..."],
  "commands": ["full command lines executed"],
  "hashes": ["SHA256, SHA1, or MD5 hashes"],
  "timestamps": ["ISO 8601 format"],
  "registry_keys": ["HKLM\\..., HKCU\\..."],
  "tools": ["tool names: WinSCP, Mimikatz, BlueVPS"],
  "services": ["network services: RDP, SMB, WinRM"],
  "threat_types": ["enumeration", "lateral_movement", etc.],
  "malware_indicated": true or false
}

Report:
{report_text}
```

### Regex Extraction

Patterns extracted:

| Type | Pattern | Example |
|------|---------|---------|
| `ips` | `\b(?:(?:25[0-5]|...)\.\){3}(?:...)\b` | `192.168.1.50` |
| `hashes` | SHA256 (64 hex), SHA1 (40 hex), MD5 (32 hex) | `a1b2c3...` |
| `sids` | `S-1-5-21-[\d-]+` | `S-1-5-21-123456-789` |
| `usernames` | Context patterns: `user "..."`, `account "..."` | `BButler` |
| `hostnames` | Context patterns: `host "..."`, `machine "..."` | `SERVER01` |
| `paths` | `[A-Za-z]:\\(?:[^\s\\/:*?"<>|']+\\)+` | `C:\Users\Admin\` |
| `processes` | `(?:executed|ran|...) "([a-zA-Z0-9_\-]+\.exe)"` | `nltest.exe` |
| `commands` | PowerShell, nltest, net commands | `nltest /dclist` |
| `tools` | Known tool list (WinSCP, Mimikatz, etc.) | `WinSCP` |
| `timestamps` | `\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}` | `2025-01-15T10:30:00` |

### Output Structure

```python
{
    'usernames': ['BButler', 'Admin'],
    'ips': ['192.168.1.50', '10.0.0.100'],
    'hostnames': ['SERVER01', 'DC1'],
    'processes': ['nltest.exe', 'WinSCP.exe'],
    'paths': ['C:\\Users\\Admin\\Documents\\'],
    'hashes': ['a1b2c3d4e5f6...'],
    'commands': ['nltest /dclist:domain.local'],
    'tools': ['WinSCP', 'Advanced IP Scanner'],
    'timestamps': ['2025-01-15T10:30:00Z'],
    'sids': ['S-1-5-21-123456789-987654321'],
    'domains': ['evil.com'],
    'registry_keys': [],
    'services': [],
    'threat_types': ['enumeration', 'lateral_movement'],
    'malware_indicated': True,
    'extraction_method': 'llm'  # or 'regex', 'regex_fallback'
}
```

---

## Routes

### File: `app/main.py`

### GET `/case/<int:case_id>/triage`

**Function:** `triage_page(case_id)`

Renders the triage prerequisites page.

**Data Fetched:**
```python
# 1. System Scan Check
system_count = db.session.query(System).filter_by(case_id=case_id, hidden=False).count()
systems_configured = system_count > 0

# 2. EDR Report Check
has_edr_report = bool(case.edr_report and case.edr_report.strip())

# 3. IOC Check
ioc_count = db.session.query(IOC).filter_by(case_id=case_id, is_active=True).count()
has_iocs = ioc_count > 0

# 4. Tagged Events Check
tag_count = db.session.query(TimelineTag).filter_by(case_id=case_id).count()
has_tagged_events = tag_count > 0

# 5. Triage Date Check
last_triage = db.session.query(AITriageSearch).filter_by(case_id=case_id).order_by(...).first()
has_triage_date = bool(last_triage and last_triage.search_date)

# 6. AI Setting
ai_enabled = get_setting('ai_enabled', 'false') == 'true'
```

### POST `/case/<int:case_id>/triage/extract-iocs`

**Function:** `triage_extract_iocs(case_id)`

Extracts IOCs from the case's EDR report.

**Request:** None (uses case.edr_report)

**Response:**
```json
{
    "success": true,
    "iocs": {
        "usernames": [...],
        "ips": [...],
        ...
    },
    "summary": {
        "total_count": 25,
        "by_type": {"ips": 5, "usernames": 3, ...},
        "malware_indicated": true,
        "extraction_method": "llm"
    }
}
```

### POST `/case/<int:case_id>/triage/add-extracted-iocs`

**Function:** `triage_add_extracted_iocs(case_id)`

Adds extracted IOCs to the case's IOC database.

**Request:**
```json
{
    "iocs": {
        "usernames": ["BButler"],
        "ips": ["192.168.1.50"],
        ...
    }
}
```

**Response:**
```json
{
    "success": true,
    "added_count": 15
}
```

**Type Mapping:**
```python
type_mapping = {
    'ips': 'ip',
    'hostnames': 'hostname',
    'usernames': 'username',
    'sids': 'user_sid',
    'paths': 'filepath',
    'processes': 'filename',
    'hashes': 'hash',
    'commands': 'command',
    'tools': 'tool',
    'domains': 'domain'
}
```

**IOC Creation:**
```python
new_ioc = IOC(
    case_id=case_id,
    ioc_type=ioc_type_db,
    ioc_value=value[:500],
    description='Extracted from EDR Report',  # Use 'description', NOT 'ioc_source'
    is_active=True,
    created_by=current_user.id
)
```

---

## JavaScript Functions

### File: `app/templates/triage.html` (script block)

| Function | Purpose |
|----------|---------|
| `extractIOCs()` | Calls `/triage/extract-iocs`, shows modal with results |
| `showIOCResults(data)` | Renders extraction results in modal |
| `closeIocModal()` | Closes the IOC extraction modal |
| `addExtractedIOCs()` | Calls `/triage/add-extracted-iocs` to save IOCs |
| `escapeHtml(text)` | Escapes HTML for safe display |

### IOC Extraction Flow

```javascript
function extractIOCs() {
    // 1. Show modal with progress spinner
    document.getElementById('iocExtractionModal').style.display = 'flex';
    document.getElementById('iocExtractionProgress').style.display = 'block';
    
    // 2. Call API
    fetch(`/case/${CASE_ID}/triage/extract-iocs`, { method: 'POST' })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                extractedIOCs = data.iocs;  // Store for adding later
                showIOCResults(data);
            } else {
                // Show error
            }
        });
}

function addExtractedIOCs() {
    fetch(`/case/${CASE_ID}/triage/add-extracted-iocs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ iocs: extractedIOCs })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert(`Added ${data.added_count} IOCs`);
            location.reload();
        }
    });
}
```

---

## CSS Classes Used

### Badge Pills (from `theme.css`)

```css
.badge-pill {
    display: inline-flex;
    align-items: center;
    padding: var(--spacing-xs) var(--spacing-md);
    border-radius: 999px;
    font-size: 0.8rem;
    font-weight: 600;
    white-space: nowrap;
}

.badge-pill-success { background: var(--color-success); color: white; }
.badge-pill-warning { background: var(--color-warning); color: white; }
.badge-pill-error   { background: var(--color-error); color: white; }
.badge-pill-muted   { background: var(--color-text-muted); color: white; }
.badge-pill-info    { background: var(--color-info); color: white; }
```

### Button Styles

```css
.btn-sm {
    padding: 6px var(--spacing-md);
    font-size: 0.875rem;
}

/* Disabled state */
button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
}
```

---

## Database Models

### IOC Table (for storing extracted IOCs)

**File:** `app/models.py` (line 170)

```python
class IOC(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False, index=True)
    ioc_type = db.Column(db.String(50), nullable=False)  # 'ip', 'username', 'user_sid', 'hostname', 'fqdn', 'command', 'filename', 'hash', etc.
    ioc_value = db.Column(db.String(500), nullable=False, index=True)
    description = db.Column(db.Text)  # 'Extracted from EDR Report'
    threat_level = db.Column(db.String(20), default='medium')
    is_active = db.Column(db.Boolean, default=True)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # OpenCTI integration
    opencti_enrichment = db.Column(db.Text)
    opencti_enriched_at = db.Column(db.DateTime)
    
    # DFIR-IRIS integration
    dfir_iris_synced = db.Column(db.Boolean, default=False)
    dfir_iris_sync_date = db.Column(db.DateTime)
    dfir_iris_ioc_id = db.Column(db.String(100))
```

**Note:** When adding IOCs from EDR extraction, use `description='Extracted from EDR Report'` (NOT `ioc_source`).

### AITriageSearch Table (triage history)

**File:** `app/models.py`

```python
class AITriageSearch(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'))
    status = db.Column(db.String(50))  # 'running', 'completed', 'failed'
    search_date = db.Column(db.DateTime)
    iocs_extracted_count = db.Column(db.Integer, default=0)
    iocs_extracted_json = db.Column(db.Text)
    iocs_discovered_count = db.Column(db.Integer, default=0)
    auto_tagged_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
```

---

## System Settings

### AI Enabled Setting

| Key | Default | Description |
|-----|---------|-------------|
| `ai_enabled` | `'false'` | Enable/disable AI features |
| `ollama_host` | `'http://localhost:11434'` | Ollama API endpoint |

**Checking AI Status:**
```python
from routes.settings import get_setting
ai_enabled = get_setting('ai_enabled', 'false') == 'true'
```

---

## Usage Examples

### Extract IOCs from Report (Python)

```python
from ai_triage_edr_ioc import extract_iocs_from_report, get_ioc_summary

report = """
On 2025-01-15, the threat actor BButler accessed SERVER01 from 192.168.1.50.
They executed nltest.exe /dclist:domain.local and exfiltrated data using WinSCP.
"""

iocs = extract_iocs_from_report(report)
summary = get_ioc_summary(iocs)

print(f"Extracted {summary['total_count']} IOCs via {summary['extraction_method']}")
print(f"Malware indicated: {summary['malware_indicated']}")
```

### Force Regex Mode

```python
# Skip AI entirely, use regex only
iocs = extract_iocs_from_report(report, force_regex=True)
```

### Check AI Setting Before Calling

```python
from ai_triage_edr_ioc import is_ai_enabled

if is_ai_enabled():
    print("AI extraction will be used")
else:
    print("Regex extraction will be used")
```

---

## Future Phases (Planned Modules)

| Phase | Module | Description |
|-------|--------|-------------|
| 1 | `ai_triage_edr_ioc.py` | ✅ IOC Extraction from EDR Report |
| 2 | `ai_triage_snowball.py` | Snowball hunting - discover related IOCs |
| 3 | `ai_triage_patterns.py` | Attack pattern detection (uses `events_attack_patterns.py`) |
| 4 | `ai_triage_malware.py` | AV/EDR malware log analysis |
| 5 | `ai_triage_timeline.py` | Timeline generation and tagging |
| 6 | `ai_triage_report.py` | LLM-generated analysis report |

Each module will follow the same pattern:
- Standalone file in `/app/`
- Main entry function that can be called directly
- Route in `main.py` for manual trigger
- Button in triage page with enable/disable logic

---

## Reconstruction Checklist

To rebuild this system:

1. **Triage Page** (`templates/triage.html`)
   - Create prerequisite cards with conditional styling
   - Add badge pills for status indicators
   - Add triage actions section with phase buttons
   - Add modals for progress and results

2. **IOC Extraction Module** (`ai_triage_edr_ioc.py`)
   - Implement `is_ai_enabled()` to check system settings
   - Implement `extract_iocs_with_llm()` with QWEN prompt
   - Implement `extract_iocs_with_regex()` with pattern matching
   - Implement `extract_iocs_from_report()` with flow logic

3. **Routes** (`main.py`)
   - Add `triage_page()` route to render prerequisites
   - Add `triage_extract_iocs()` route for extraction
   - Add `triage_add_extracted_iocs()` route to save IOCs
   - **Important:** Use `description` field for IOC source, NOT `ioc_source`

4. **CSS** (`theme.css`)
   - Add `.badge-pill` classes for status indicators
   - Ensure `.btn-sm` is defined for small buttons

5. **JavaScript**
   - Implement `extractIOCs()` for API call and modal
   - Implement `addExtractedIOCs()` to save to database
   - Handle progress states and error display

---

## Version History

| Version | Changes |
|---------|---------|
| v1.46.0 | Initial triage page with prerequisites |
| v1.46.0 | Created `ai_triage_edr_ioc.py` module |
| v1.46.0 | Added IOC extraction routes and UI |
| v1.46.0 | Added `.badge-pill` CSS classes to `theme.css` |
| v1.46.2 | Fixed IOC creation bug: changed `ioc_source` to `description` field |

