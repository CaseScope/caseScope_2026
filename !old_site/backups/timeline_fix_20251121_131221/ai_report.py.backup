#!/usr/bin/env python3
"""
CaseScope AI Report Generation Module
Uses Ollama + Phi-3 Medium 14B for local LLM inference
"""

import requests
import json
from datetime import datetime
from logging_config import get_logger

logger = get_logger('app')


# Model descriptions and metadata
# UPDATED 2025-11-07: Complete DFIR-optimized overhaul - 4 specialized models
# All models fit in 7.5GB VRAM (Tesla P4). Total: ~24 GB disk space (was ~317 GB)
# Model names verified against actual Ollama registry (2025-11-07)
MODEL_INFO = {
    # ===== DFIR-OPTIMIZED MODELS WITH FORENSIC ANALYST PROFILES =====
    
    # DFIR-Llama: General reasoning + summarization (DEFAULT/RECOMMENDED)
    'dfir-llama:latest': {
        'name': 'DFIR-Llama 3.1 8B (Forensic Profile)',
        'speed': 'Fast',
        'quality': 'Excellent',
        'size': '4.9 GB',
        'description': 'DFIR-trained forensic analyst profile. Strong evidence discipline, timeline construction, MITRE mapping. No hallucinations. Excellent for general incident response. Runs fully on 7.5GB VRAM.',
        'speed_estimate': '~25-35 tok/s GPU (100% on-device), ~10-15 tok/s CPU',
        'time_estimate': '3-5 minutes (GPU), 10-15 minutes (CPU)',
        'recommended': True,
        'trainable': False,  # Llama 3.1 not supported in current Unsloth version
        'cpu_optimal': {'num_ctx': 16384, 'num_thread': 16, 'temperature': 0.3},
        'gpu_optimal': {'num_ctx': 16384, 'num_thread': 8, 'temperature': 0.3, 'num_gpu_layers': -1}
    },
    
    # DFIR-Mistral: Short-to-mid context formatting
    'dfir-mistral:latest': {
        'name': 'DFIR-Mistral 7B (Forensic Profile)',
        'speed': 'Fast',
        'quality': 'Excellent',
        'size': '4.4 GB',
        'description': 'DFIR-trained forensic analyst profile. Efficient chronological reconstruction. Reliable formatting (tables, timelines). Sharp on short-to-mid contexts. Runs fully on 7.5GB VRAM.',
        'speed_estimate': '~25-35 tok/s GPU (100% on-device), ~10-15 tok/s CPU',
        'time_estimate': '3-5 minutes (GPU), 10-15 minutes (CPU)',
        'recommended': True,
        'trainable': True,  # Mistral 7B fully supported by Unsloth
        'cpu_optimal': {'num_ctx': 16384, 'num_thread': 16, 'temperature': 0.3},
        'gpu_optimal': {'num_ctx': 16384, 'num_thread': 8, 'temperature': 0.3, 'num_gpu_layers': -1}
    },
    
    # DFIR-DeepSeek: Code/log/PowerShell expert
    'dfir-deepseek:latest': {
        'name': 'DFIR-DeepSeek-Coder 16B (Forensic Profile)',
        'speed': 'Moderate',
        'quality': 'Excellent',
        'size': '10 GB',
        'description': 'DFIR-trained forensic analyst profile specialized in script analysis. PowerShell decoding, obfuscation detection, command-line parsing. Excellent for script-heavy attacks. May use minor CPU offloading (~15%) on 7.5GB VRAM.',
        'speed_estimate': '~15-25 tok/s GPU (85% on-device, 15% CPU offload), ~8-12 tok/s CPU',
        'time_estimate': '5-8 minutes (GPU), 12-18 minutes (CPU)',
        'recommended': True,
        'trainable': False,  # DeepSeek models not yet supported by Unsloth
        'cpu_optimal': {'num_ctx': 16384, 'num_thread': 16, 'temperature': 0.3},
        'gpu_optimal': {'num_ctx': 16384, 'num_thread': 16, 'temperature': 0.3, 'num_gpu_layers': -1}  # 16 threads for CPU offloading
    },
    
    # DFIR-Qwen: Long lists and low hallucination
    'dfir-qwen:latest': {
        'name': 'DFIR-Qwen 2.5 7B (Forensic Profile)',
        'speed': 'Fast',
        'quality': 'Excellent',
        'size': '4.7 GB',
        'description': 'DFIR-trained forensic analyst profile. Strong structured reasoning. Excellent with long IOC lists (100+) and large event datasets (300+). Constrained reasoning = LOW HALLUCINATION. Runs fully on 7.5GB VRAM.',
        'speed_estimate': '~22-32 tok/s GPU (100% on-device), ~9-14 tok/s CPU',
        'time_estimate': '3-5 minutes (GPU), 9-13 minutes (CPU)',
        'recommended': True,
        'cpu_optimal': {'num_ctx': 16384, 'num_thread': 16, 'temperature': 0.3},
        'gpu_optimal': {'num_ctx': 16384, 'num_thread': 8, 'temperature': 0.3, 'num_gpu_layers': -1}
    }
}


def calculate_cpu_offload_percent(model_size_gb, vram_gb):
    """
    Calculate estimated CPU offload percentage
    Returns 0-100% estimate of work offloaded to CPU
    """
    if vram_gb <= 0:
        return 100  # No GPU, all CPU
    
    # Account for VRAM overhead (context, activations, etc.)
    # Reserve ~1.5GB for overhead
    available_vram = max(vram_gb - 1.5, 0)
    
    if model_size_gb <= available_vram:
        return 0  # Fits entirely in VRAM
    elif model_size_gb <= available_vram + 2:
        # Minor offloading (just a few layers)
        overage = model_size_gb - available_vram
        return min(int((overage / 2) * 25), 25)  # 0-25%
    elif model_size_gb <= vram_gb * 2:
        # Moderate offloading (significant layers)
        overage_ratio = (model_size_gb - available_vram) / model_size_gb
        return min(int(overage_ratio * 60) + 20, 60)  # 20-60%
    else:
        # Heavy offloading (most layers on CPU)
        overage_ratio = (model_size_gb - available_vram) / model_size_gb
        return min(int(overage_ratio * 100), 95)  # 60-95%


def parse_model_size(size_str):
    """Parse model size string to GB float (e.g., '19 GB' -> 19.0)"""
    import re
    match = re.search(r'(\d+\.?\d*)', str(size_str))
    if match:
        return float(match.group(1))
    return 0.0


def get_model_info(model_name):
    """Get metadata for a specific model"""
    return MODEL_INFO.get(model_name, {
        'name': model_name,
        'speed': 'Unknown',
        'quality': 'Unknown',
        'size': 'Unknown',
        'description': 'Custom model',
        'speed_estimate': 'Unknown',
        'time_estimate': 'Unknown',
        'recommended': False
    })


def check_ollama_status():
    """
    Check if Ollama is running and Phi-3 model is available
    
    Returns:
        dict: Status information
            {
                'installed': bool,
                'running': bool,
                'model_available': bool,
                'models': list,
                'error': str (if any)
            }
    """
    try:
        response = requests.get('http://localhost:11434/api/tags', timeout=2)
        if response.status_code == 200:
            data = response.json()
            models = data.get('models', [])
            model_names = [m.get('name', '') for m in models]
            
            # Enrich models with metadata
            enriched_models = []
            for model in models:
                model_name = model.get('name', '')
                info = get_model_info(model_name)
                enriched_models.append({
                    'name': model_name,
                    'display_name': info['name'],
                    'speed': info['speed'],
                    'quality': info['quality'],
                    'size': info['size'],
                    'description': info['description'],
                    'speed_estimate': info['speed_estimate'],
                    'time_estimate': info['time_estimate'],
                    'recommended': info['recommended'],
                    'size_bytes': model.get('size', 0),
                    'modified_at': model.get('modified_at', '')
                })
            
            # Check for any AI model
            model_available = len(models) > 0
            
            return {
                'installed': True,
                'running': True,
                'model_available': model_available,
                'models': enriched_models,
                'model_names': model_names,
                'error': None
            }
        else:
            return {
                'installed': False,
                'running': False,
                'model_available': False,
                'models': [],
                'model_names': [],
                'error': f'Ollama returned status code {response.status_code}'
            }
    except requests.exceptions.ConnectionError:
        return {
            'installed': False,
            'running': False,
            'model_available': False,
            'models': [],
            'model_names': [],
            'error': 'Cannot connect to Ollama (not installed or not running)'
        }
    except Exception as e:
        logger.error(f"[AI] Error checking Ollama status: {e}")
        return {
            'installed': False,
            'running': False,
            'model_available': False,
            'models': [],
            'model_names': [],
            'error': str(e)
        }


def generate_timeline_prompt(case, iocs, systems, events_data, event_count):
    """
    Build the prompt for AI timeline generation (v1.18.6)
    
    Focus: Chronological timeline from ANALYST-TAGGED events with intelligent consolidation.
    
    Args:
        case: Case object
        iocs: List of IOC objects
        systems: List of System objects
        events_data: List of TAGGED event dicts from OpenSearch (sorted by timestamp)
        event_count: Total number of events in case (before tagging)
        
    Returns:
        str: Formatted timeline prompt for analyst-tagged event consolidation
    """
    
    tagged_count = len(events_data)
    
    # Token limit safety check
    MAX_TAGGED_EVENTS = 1000
    token_warning = ""
    if tagged_count > MAX_TAGGED_EVENTS:
        token_warning = f"⚠️ WARNING: {tagged_count} events tagged, showing first {MAX_TAGGED_EVENTS} due to AI context limits.\n"
        token_warning += "Consider tagging fewer events or generating timeline in phases.\n\n"
        events_data = events_data[:MAX_TAGGED_EVENTS]
        tagged_count = MAX_TAGGED_EVENTS
    
    prompt = f"""You are a DFIR Timeline Analysis Engine.

═══════════════════════════════════════════════════════════════════════════════
MISSION: CHRONOLOGICAL TIMELINE FROM ANALYST-TAGGED EVENTS
═══════════════════════════════════════════════════════════════════════════════

Create a precise chronological timeline from events the analyst has tagged as significant.

IMPORTANT: The analyst has pre-filtered {event_count:,} events down to {tagged_count} timeline-relevant events.
Every event below was explicitly tagged by the analyst as important for understanding this case.
Your job is to organize these tagged events into a coherent timeline narrative.

═══════════════════════════════════════════════════════════════════════════════
CASE INFORMATION
═══════════════════════════════════════════════════════════════════════════════

Case Name: {case.name}
Company: {case.company or 'Unknown'}
Description: {case.description or 'No description'}

EVENT SCOPE:
- Total Events in Case: {event_count:,}
- Events Tagged for Timeline: {tagged_count}
- Active IOCs: {len(iocs)}
- Systems in Scope: {len(systems)}

═══════════════════════════════════════════════════════════════════════════════
TIMELINE REQUIREMENTS
═══════════════════════════════════════════════════════════════════════════════

Your timeline MUST include these sections:

## 1. Timeline Summary

- First tagged event timestamp (UTC)
- Last tagged event timestamp (UTC)
- Total time span covered
- Events analyzed: {tagged_count}
- Timeline organization:
  • Individual entries: [N events shown separately]
  • Consolidated groups: [M groups representing X events]
  • Total timeline entries: [N + M]

## 2. Event Consolidation Summary

Show which event types were consolidated:

| Event Type | Individual | Consolidated | Total Events |
|------------|-----------|--------------|-------------|
| Example: 4624 Logons | 5 | 3 groups (45 events) | 50 |

## 3. Chronological Timeline

Format each event or consolidated group:

### For Individual Events:
```
YYYY-MM-DD HH:MM:SS UTC | [SYSTEM-NAME] | Event Description
├─ IOC: [if IOC detected]
├─ SIGMA: [if SIGMA violation]
└─ Context: [why this event matters]
```

### For Consolidated Groups:
```
YYYY-MM-DD HH:MM:SS to HH:MM:SS UTC | [PRIMARY-SYSTEM or "Multiple Systems"]
├─ Activity Type: [Brief description]
├─ Event Details: EventID [ID] - [N] occurrences
├─ Key Data:
│  ├─ User(s): [username(s)]
│  ├─ Systems: [system1, system2, ... (N total)]
│  ├─ Source: [IP/hostname if relevant]
│  └─ Timespan: [duration]
├─ IOC: [if any events had IOC hits]
├─ SIGMA: [if any events had SIGMA violations]
└─ Context: [Why this matters - lateral movement, persistence, etc.]
```

## 4. Attack Progression (MITRE ATT&CK Kill Chain)

Map the tagged events to attack phases:
- **Reconnaissance** (scanning, discovery)
- **Initial Access** (first successful login, exploit)
- **Execution** (command execution, script running)
- **Persistence** (scheduled tasks, registry modifications)
- **Privilege Escalation** (elevation attempts)
- **Lateral Movement** (RDP, SMB, network activity)
- **Exfiltration** (large data transfers, external connections)

## 5. IOC Timeline Matrix

Show when each IOC appears in the tagged events:

| IOC Type | IOC Value | First Seen (UTC) | Last Seen (UTC) | Tagged Events | Systems |

## 6. System Activity Summary

Per-system activity based on tagged events

═══════════════════════════════════════════════════════════════════════════════
INDICATORS OF COMPROMISE (IOCs)
═══════════════════════════════════════════════════════════════════════════════

"""
    
    if iocs:
        prompt += "Active IOCs to track in timeline:\n\n"
        for ioc in iocs:
            prompt += f"- **{ioc.ioc_type}**: `{ioc.ioc_value}`"
            if ioc.description:
                prompt += f" ({ioc.description})"
            if ioc.threat_level:
                prompt += f" [Threat: {ioc.threat_level}]"
            prompt += "\n"
    else:
        prompt += "No IOCs defined for this case.\n"
    
    prompt += "\n═══════════════════════════════════════════════════════════════════════════════\n"
    prompt += "SYSTEMS IN SCOPE\n"
    prompt += "═══════════════════════════════════════════════════════════════════════════════\n\n"
    
    if systems:
        for system in systems:
            prompt += f"- **{system.system_name}** ({system.system_type})"
            if system.ip_address:
                prompt += f" - IP: {system.ip_address}"
            prompt += "\n"
    else:
        prompt += "No systems explicitly defined. Extract system names from events.\n"
    
    prompt += "\n═══════════════════════════════════════════════════════════════════════════════\n"
    prompt += f"ANALYST-TAGGED EVENTS (ALL {tagged_count} EVENTS BELOW)\n"
    prompt += "═══════════════════════════════════════════════════════════════════════════════\n\n"
    
    if tagged_count == 0:
        prompt += "⚠️ WARNING: No events have been tagged for timeline analysis.\n"
        prompt += "The analyst should tag key events using the search interface before generating a timeline.\n\n"
    else:
        prompt += f"{token_warning}"
        prompt += f"The analyst has tagged these {tagged_count} events as timeline-relevant.\n"
        prompt += "Each event below is significant and should be included in your timeline.\n\n"
    
    if events_data:
        for idx, event_wrapper in enumerate(events_data, 1):  # NO CAP - show ALL tagged events
            event = event_wrapper.get('_source', {})
            
            # v1.18.3 FIX: Use normalized fields (exist at top level)
            # Original code looked for System.* but actual structure is Event.System.*
            timestamp = event.get('normalized_timestamp', 'Unknown')
            computer = event.get('normalized_computer', 'Unknown')
            event_id = event.get('normalized_event_id', 'N/A')
            source_type = event.get('source_file_type', 'Unknown')
            has_ioc = event.get('has_ioc', False)
            has_sigma = event.get('has_sigma', False)
            
            prompt += f"[{idx}] {timestamp} | {computer} | EventID:{event_id} ({source_type})"
            
            if has_ioc:
                prompt += " 🎯IOC"
            if has_sigma:
                sigma_rules = event.get('sigma_rule', '')
                prompt += f" ⚠️SIGMA:{sigma_rules[:50]}"
            
            # Add some event data context
            # EventData is stored as JSON string, need to parse it
            event_obj = event.get('Event', {})
            event_data_str = event_obj.get('EventData', '')
            if event_data_str and isinstance(event_data_str, str):
                try:
                    import json
                    event_data = json.loads(event_data_str)
                except:
                    event_data = {}
            else:
                event_data = event_data_str if isinstance(event_data_str, dict) else {}
            
            if event_data:
                key_fields = ['TargetUserName', 'SubjectUserName', 'IpAddress', 'WorkstationName', 
                             'CommandLine', 'Image', 'TargetFilename', 'SourceAddress', 'TargetAddress']
                data_str = []
                for field in key_fields:
                    if field in event_data and event_data[field]:
                        value = str(event_data[field])[:100]  # Truncate long values
                        data_str.append(f"{field}={value}")
                if data_str:
                    prompt += f" | {', '.join(data_str[:3])}"  # Show first 3 fields
            
            # Add timeline tag note if present
            tag_note = event.get('timeline_tag_note', '')
            if tag_note:
                prompt += f" | 📝 Analyst Note: {tag_note}"
            
            prompt += "\n"
    else:
        prompt += "No events available for timeline analysis.\n"
    
    prompt += "\n═══════════════════════════════════════════════════════════════════════════════\n"
    prompt += "ANALYSIS INSTRUCTIONS\n"
    prompt += "═══════════════════════════════════════════════════════════════════════════════\n\n"
    prompt += f"""
**CRITICAL CONTEXT**: You are analyzing {tagged_count} events that were MANUALLY TAGGED by the analyst.
Every event above is significant - the analyst has already filtered out noise.

Your task is to organize these events into a readable timeline narrative.

═══════════════════════════════════════════════════════════════════════════════
EVENT GROUPING AND CONSOLIDATION RULES
═══════════════════════════════════════════════════════════════════════════════

**You MUST consolidate repetitive events** to create readable narrative flow.

### When to Group Events:

**Group these patterns** when they occur within a 10-minute window:

1. **Multiple Successful Logins (Event 4624)**
   - Same user logging into multiple systems
   - Same logon type (especially Type 3 - Network, Type 10 - RDP)
   - Consolidate into: "Lateral movement: User X authenticated to N systems"

2. **Failed Login Attempts (Event 4625)**
   - Multiple failures against same system
   - Same or different usernames
   - Consolidate into: "Brute force: N failed login attempts"

3. **Process Execution (Events 4688, Sysmon 1)**
   - Same command/process on multiple systems
   - Same user executing multiple similar commands
   - Consolidate into: "Command execution: User X ran [command] on N systems"

4. **File Access (Events 4663, 5145)**
   - Multiple file accesses by same user
   - Same share or directory
   - Consolidate into: "File access: User X accessed N files in [share]"

5. **Network Connections (Sysmon 3, Firewall logs)**
   - Multiple connections to same destination
   - Same protocol/port
   - Consolidate into: "Network activity: N connections to [destination]"

6. **Registry Modifications (Sysmon 12, 13)**
   - Multiple registry changes
   - Same key path pattern
   - Consolidate into: "Registry modification: N changes to [key path]"

### Consolidation Examples:

**Example 1: Lateral Movement**
```
2025-09-05 11:00:15 to 11:05:43 UTC | Multiple Systems
├─ Lateral Movement: User 'DOMAIN\\admin' authenticated to 15 systems
├─ Event Details: 4624 Type 3 (Network Logon) - 50 occurrences
├─ Key Data:
│  ├─ User: DOMAIN\\admin
│  ├─ Systems: SRV01, SRV02, SRV03, WKS01-WKS12 (15 total)
│  ├─ Source: 192.168.1.100 (admin workstation)
│  └─ Timespan: 5 minutes 28 seconds
└─ Context: Rapid authentication across multiple servers suggests lateral movement
   or legitimate administrative sweep. Investigate admin's intended activity.
```

**Example 2: Brute Force Attack**
```
2025-09-05 14:22:11 to 14:24:33 UTC | DC01
├─ Brute Force Attack: Failed login attempts for multiple accounts
├─ Event Details: 4625 (Failed Logon) - 127 occurrences
├─ Key Data:
│  ├─ Target Accounts: administrator (50), admin (40), root (37)
│  ├─ Source IPs: 192.168.1.50, 192.168.1.51
│  ├─ Failure Reason: Bad password (0xC000006A)
│  └─ Timespan: 2 minutes 22 seconds (54 attempts/minute)
├─ SIGMA: Brute Force Detection Rule
└─ Context: High-frequency failed logins indicate password spray or brute force
   attack. Source IPs should be investigated and blocked.
```

**Example 3: Reconnaissance**
```
2025-09-05 09:15:00 to 09:16:30 UTC | Multiple Systems
├─ Network Scanning: Port scan detected across infrastructure
├─ Event Details: Firewall Deny - 234 occurrences
├─ Key Data:
│  ├─ Source: 192.168.1.99 (compromised workstation)
│  ├─ Targets: 192.168.1.1-192.168.1.254 (entire subnet)
│  ├─ Ports: 445 (SMB), 3389 (RDP), 22 (SSH)
│  └─ Timespan: 1 minute 30 seconds
├─ IOC: 192.168.1.99 marked as compromised host
└─ Context: Automated scanning suggests attacker reconnaissance phase.
   Host 192.168.1.99 likely compromised and being used for discovery.
```

═══════════════════════════════════════════════════════════════════════════════
WHEN NOT TO GROUP EVENTS
═══════════════════════════════════════════════════════════════════════════════

**Keep separate** (do NOT consolidate):

1. **Events with different IOC hits** - Each IOC detection is unique
2. **Events with different SIGMA violations** - Each rule match is significant
3. **Events with analyst notes** - Analyst tagged each for a reason
4. **Events separated by > 10 minutes** - Different activity phases
5. **Events on different attack phases** - Initial access vs. lateral movement
6. **Privilege escalation events** - Each escalation attempt is critical
7. **Command execution with different commands** - Show what was run
8. **Unique or rare events** - Don't group one-off events

═══════════════════════════════════════════════════════════════════════════════
DATA PRESERVATION GUARANTEE
═══════════════════════════════════════════════════════════════════════════════

**All {tagged_count} events MUST be accounted for** in your timeline.

When you consolidate:
✅ Count total occurrences: "50 occurrences"
✅ Show time range: "11:00:15 to 11:05:43 UTC"
✅ List affected systems: "15 systems" with sample names
✅ Preserve IOC/SIGMA flags
✅ Include key data (users, IPs, commands)

When you don't consolidate:
✅ Show individual event with full context
✅ Explain why this specific event matters

**Verification**: Your timeline should explain what happened with all {tagged_count} tagged events,
either individually or as part of consolidated groups.

═══════════════════════════════════════════════════════════════════════════════
OUTPUT REQUIREMENTS
═══════════════════════════════════════════════════════════════════════════════

**Timeline Summary** must include:
- Total events analyzed: {tagged_count}
- Events shown individually: [count]
- Events shown in consolidated groups: [count]
- Time span: [first to last]

**Formatting**:
- Use UTC timestamps exclusively
- Use tree structure (├─ └─) for details
- Bold system names and IOC values
- Use Markdown tables for IOC matrix
- Number timeline entries sequentially

**DO NOT**:
- ❌ Skip events without showing them somewhere (individual or grouped)
- ❌ Invent events not in the tagged list
- ❌ Make assumptions about activity between events
- ❌ Group events across different attack phases

**Remember**: Consolidation makes the timeline READABLE, not shorter.
All {tagged_count} events must be accounted for, just organized intelligently.

**Output**: A complete Markdown timeline ready for display.
"""
    
    return prompt


def generate_case_report_prompt(case, iocs, tagged_events, systems=None, existing_timeline=None):
    """
    Build the prompt for AI report generation using simplified ChatGPT-style structure (v1.11.27)
    Enhanced with MITRE knowledge block and system-level instructions (v1.11.32)
    Updated v1.16.3: Added existing_timeline parameter for timeline-aware report generation
    
    Simplified, concise prompt matching ChatGPT's approach with collapsed timelines and clear structure.
    
    Args:
        case: Case object
        iocs: List of IOC objects
        tagged_events: List of tagged event dicts from OpenSearch
        systems: List of System objects (optional, for improved context)
        existing_timeline: CaseTimeline object (optional, uses pre-generated timeline if available)
        
    Returns:
        str: Formatted DFIR prompt with collapsed timeline, IOC table, MITRE mapping, and recommendations
    """
    
    if systems is None:
        systems = []
    
    # Build the prompt with EXTRACTION-FIRST workflow (v1.11.36) - Forces EXTRACT → VALIDATE → RENDER
    prompt = f"""You are a DFIR / Threat-Intel reporting engine.

═══════════════════════════════════════════════════════════════════════════════
MANDATORY CONTRACT
═══════════════════════════════════════════════════════════════════════════════

Return a complete Markdown report in exactly this order and with these section titles:

1) Executive Summary
2) Timeline (UTC)
3) Indicators of Compromise (IOCs)
4) Event-to-MITRE Map
5) What / Why / How to Stop

═══════════════════════════════════════════════════════════════════════════════
WORKFLOW (follow step-by-step):
═══════════════════════════════════════════════════════════════════════════════

A) EXTRACT → Build a structured extraction from the input. Do not summarize yet.
   - Pull EVERY event with timestamp, host, event name/ID, account, and any detail fields.
   - Collapse repeated events (e.g., 4625) per host into ranges with counts.
   - Harvest ALL IOCs: IPs, hostnames, usernames, file paths, processes, commands, URLs/domains, hashes.
   - Collect ATT&CK techniques (prefer IDs like T1059.001). If unmapped, leave blank.

B) VALIDATE → Check you have at least:
   - ≥1 timeline line per distinct host or event group
   - An IOC table row for each distinct observable found
   - ATT&CK IDs formatted as `T\\d{{4}}(\\.\\d{{3}})?`
   If any check fails, FIX the extraction and re-run VALIDATE. Do not skip.

C) RENDER → Only after VALIDATE passes, render the final report with the exact five sections.

═══════════════════════════════════════════════════════════════════════════════
RENDERING RULES
═══════════════════════════════════════════════════════════════════════════════

Timeline format: "<start> to <end> — <Event name> on <host> (<count> events) [Key users: ...]"

IOC table columns (exact): | Type | Value/Name | Notes | Source |

Event-to-MITRE: list each event type seen → ATT&CK IDs.

Never invent data. If unknown, write "Not observed."

Use UTC. Be concise and factual.

═══════════════════════════════════════════════════════════════════════════════
MITRE QUICK MAP (use when relevant; do not force):
═══════════════════════════════════════════════════════════════════════════════

- Event 4625 (failed logon) → T1110 (Brute Force) / attempt toward T1078
- Event 4624 (suspicious success) → T1078 Valid Accounts
- RDP / rdpclip.exe → T1021.001 Remote Services: RDP
- PowerShell / powershell.exe → T1059.001 PowerShell
- cmd.exe / command prompt → T1059.003 Windows Command Shell
- Network shares / Event 5140 / enumeration → T1135 Network Share Discovery / T1087.002 Account Discovery
- nltest /domain_trusts → T1482 Domain Trust Discovery
- net.exe (user/group commands) → T1087.002 / T1069.002 Permission Groups Discovery
- Advanced IP Scanner, network scans → T1046 Network Service Scanning / T1018 Remote System Discovery
- VPN / external remote services → T1133 External Remote Services
- NOTEPAD.EXE opening enumeration files → T1005 Data from Local System / T1074.001 Local Data Staging
- Suspicious file execution from %TEMP% → T1204.002 User Execution: Malicious File

═══════════════════════════════════════════════════════════════════════════════
CONSTRAINTS
═══════════════════════════════════════════════════════════════════════════════

- Collapse repeated events per host into time ranges with counts.
- Extract IOCs even if repeated in different events (dedupe rows by value, keep best Notes/Source).
- Do not omit sections. If no data, include section with "Not observed."

═══════════════════════════════════════════════════════════════════════════════
<<<DATA>>>
═══════════════════════════════════════════════════════════════════════════════

TASK: Analyze the data below and produce the report per the CONTRACT.

CASE INFORMATION:
Case Name: {case.name}
Company: {case.company or 'N/A'}
Investigation Date: {case.created_at.strftime('%Y-%m-%d') if case.created_at else 'N/A'}
"""
    
    # v1.16.3: Add existing timeline if available
    if existing_timeline and existing_timeline.timeline_content:
        prompt += f"""
═══════════════════════════════════════════════════════════════════════════════
EXISTING TIMELINE (use this as the chronological backbone for your report)
═══════════════════════════════════════════════════════════════════════════════

A timeline has already been generated for this case (v{existing_timeline.version}).
USE THIS TIMELINE for section 2) Timeline (UTC) in your report.
You may enhance it with additional context or formatting, but preserve the chronological events.

TIMELINE CONTENT:
{existing_timeline.timeline_content}

═══════════════════════════════════════════════════════════════════════════════
END OF EXISTING TIMELINE
═══════════════════════════════════════════════════════════════════════════════

**IMPORTANT**: Use the above timeline as your section 2) Timeline (UTC).
Do NOT create a new timeline from scratch. Use this existing one.
"""
        logger.info(f"[AI REPORT] Including existing timeline v{existing_timeline.version} in prompt ({len(existing_timeline.timeline_content)} chars)")
    else:
        logger.info(f"[AI REPORT] No existing timeline - will generate from tagged events")
    
    prompt += """
INPUT.KNOWN_IOCS:
"""
    
    # Add IOCs with enhanced context: events, descriptions, and usage analysis (v1.11.36)
    if iocs:
        prompt += f"({len(iocs)} total observables)\n\n"
        
        # DEBUG: Log first event structure to help diagnose issues
        if tagged_events and len(tagged_events) > 0:
            logger.info(f"[AI REPORT DEBUG] First event structure: {json.dumps(tagged_events[0], indent=2)[:500]}")
        
        for ioc_obj in iocs:
            ioc_value = ioc_obj.ioc_value
            ioc_type = ioc_obj.ioc_type or 'unknown'
            
            prompt += f"IOC: {ioc_value}\n"
            prompt += f"  Type: {ioc_type}\n"
            
            if ioc_obj.threat_level:
                prompt += f"  Threat Level: {ioc_obj.threat_level}\n"
            
            # Add description (explains what this IOC was used for)
            if ioc_obj.description:
                prompt += f"  Purpose/Description: {ioc_obj.description}\n"
            
            # Find events that contain this IOC
            # Strategy: Normalize backslashes to forward slashes for reliable matching
            matching_events = []
            for idx, event in enumerate(tagged_events, 1):
                source = event.get('_source', {})
                
                # Convert entire source to JSON string and normalize backslashes
                import json as json_lib
                event_json = json_lib.dumps(source).lower()
                # Normalize: Replace all backslashes (single or double) with forward slashes
                event_json_normalized = event_json.replace('\\\\', '/').replace('\\', '/')
                
                # Also normalize the IOC for comparison
                ioc_normalized = ioc_value.lower().replace('\\', '/')
                
                # Match IOC (case-insensitive, backslash-agnostic)
                if ioc_normalized in event_json_normalized:
                    # Extract metadata using the same logic as search_utils.py (handles all event structures)
                    from search_utils import extract_event_fields
                    fields = extract_event_fields(source)
                    
                    timestamp = fields.get('timestamp', 'Unknown')
                    computer_name = fields.get('computer_name', 'N/A')  # FIXED: use 'computer_name' not 'computer'
                    event_id = fields.get('event_id', 'N/A')
                    description = fields.get('description', '')
                    desc_preview = description[:80] + '...' if len(description) > 80 else description
                    
                    matching_events.append(f"Event {idx} (Time: {timestamp}, System: {computer_name}, EventID: {event_id}, Desc: {desc_preview})")
            
            if matching_events:
                prompt += f"  Events Containing This IOC ({len(matching_events)} total):\n"
                for event_ref in matching_events[:10]:  # Limit to first 10 to avoid prompt bloat
                    prompt += f"    - {event_ref}\n"
            else:
                prompt += f"  Events Containing This IOC: None found in tagged events\n"
            
            prompt += "\n"
        
        prompt += "\n"
    else:
        prompt += "None defined\n\n"
    
    # Add systems in simple format (for AI context)
    if systems:
        prompt += f"SYSTEMS IDENTIFIED ({len(systems)} total):\n"
        for system in systems:
            system_type_label = {
                'server': '🖥️ Server',
                'workstation': '💻 Workstation',
                'firewall': '🔥 Firewall',
                'switch': '🔀 Switch',
                'printer': '🖨️ Printer',
                'actor_system': '⚠️ Actor System'
            }.get(system.system_type, system.system_type)
            
            # Include IP address if available
            ip_info = f" | IP: {system.ip_address}" if system.ip_address else ""
            prompt += f"- System: {system.system_name} | Type: {system_type_label}{ip_info} | Added By: {system.added_by}\n"
        prompt += "\n"
    else:
        prompt += "SYSTEMS IDENTIFIED: None found (run 'Find Systems' to auto-discover)\n\n"
    
    # Add tagged events in simple format (CSV-like)
    if tagged_events:
        prompt += f"\nINPUT.EVENTS ({len(tagged_events)} events, CSV/JSON normalized):\n\n"
        
        from search_utils import extract_event_fields
        
        for i, event in enumerate(tagged_events, 1):
            source = event.get('_source', {})
            
            # Extract fields using the same logic as search results (handles EVTX/JSON/EDR structures)
            fields = extract_event_fields(source)
            
            prompt += f"Event {i}:\n"
            prompt += f"  Timestamp: {fields.get('timestamp', 'Unknown')}\n"
            prompt += f"  Event ID: {fields.get('event_id', 'N/A')}\n"
            prompt += f"  Computer: {fields.get('computer_name', 'N/A')}\n"  # FIXED: use 'computer_name' not 'computer'
            prompt += f"  Description: {fields.get('description', 'No description')}\n"
            
            # Add ALL other fields from source (don't filter - give AI all data)
            exclude_fields = {'timestamp', '@timestamp', 'event_id', 'EventID', 'computer_name', 'computer', 
                            'Computer', 'description', 'source_type', 'source_file', 'has_sigma', 'has_ioc',
                            '@version', '_index', '_type', '_score', 'tags', 'opensearch_key', 'normalized_timestamp',
                            'normalized_computer', 'normalized_event_id', 'ioc_count', 'is_hidden', 'hidden_by', 
                            'hidden_at', 'source_file_type'}
            
            for key, value in source.items():
                if key not in exclude_fields and value and str(value).strip():
                    # For nested dicts, show as JSON
                    if isinstance(value, dict):
                        prompt += f"  {key}: {json.dumps(value)}\n"
                    else:
                        prompt += f"  {key}: {value}\n"
            
            prompt += "\n"
    else:
        prompt += "\nINPUT.EVENTS: None available\n\n"
    
    # Close the data section
    prompt += """
<<<END DATA>>>

Generate a professional DFIR incident report following the 5-section structure above. Use Markdown formatting. Make it clear and suitable for both executives and technical readers.
"""
    
    return prompt


def generate_report_with_ollama(prompt, model='deepseek-r1:32b', hardware_mode='cpu', num_ctx=None, num_thread=None, temperature=None, report_obj=None, db_session=None):
    """
    Generate report using Ollama API with real-time streaming
    
    Args:
        prompt: The prompt to send to the model
        model: Model name (default: deepseek-r1:32b)
        hardware_mode: 'cpu' or 'gpu' - automatically applies optimal settings (default: 'cpu')
        num_ctx: Context window size (optional, auto-set based on hardware_mode)
        num_thread: Number of CPU threads to use (optional, auto-set based on hardware_mode)
        temperature: Sampling temperature (optional, auto-set based on hardware_mode)
        report_obj: AIReport database object for real-time updates (optional)
        db_session: Database session for committing updates (optional)
        
    Returns:
        tuple: (success: bool, response: str/dict)
    """
    import time
    
    try:
        # Get optimal settings for this model and hardware mode
        model_info = MODEL_INFO.get(model, {})
        optimal_settings = model_info.get(f'{hardware_mode}_optimal', {})
        
        # Use provided values or fall back to optimal settings or defaults
        num_ctx = num_ctx if num_ctx is not None else optimal_settings.get('num_ctx', 8192)
        num_thread = num_thread if num_thread is not None else optimal_settings.get('num_thread', 16)
        temperature = temperature if temperature is not None else optimal_settings.get('temperature', 0.3)
        num_gpu_layers = optimal_settings.get('num_gpu_layers', 0)  # GPU only
        
        options = {
            'num_ctx': num_ctx,
            'num_thread': num_thread,
            'num_predict': 16384 if hardware_mode == 'gpu' else 8192,  # Higher output for GPU
            'temperature': temperature,
            'top_p': 0.9,
            'top_k': 40,
            'stop': []  # CRITICAL: Remove ALL stop sequences that might be terminating early
        }
        
        # Add GPU layers if in GPU mode
        if hardware_mode == 'gpu' and num_gpu_layers != 0:
            options['num_gpu'] = num_gpu_layers
        
        payload = {
            'model': model,
            'prompt': prompt,
            'stream': True,  # Enable streaming for real-time updates
            'options': options
        }
        
        logger.info(f"[AI] Generating report with {model} (mode={hardware_mode.upper()}, ctx={num_ctx}, threads={num_thread}, gpu_layers={num_gpu_layers}, STREAMING=ON)")
        
        response = requests.post(
            'http://localhost:11434/api/generate',
            json=payload,
            stream=True  # Enable response streaming, no timeout (user can cancel)
        )
        
        if response.status_code == 200:
            report_text = ''
            tokens_generated = 0
            start_time = time.time()
            last_update_time = start_time
            last_update_tokens = 0
            prompt_eval_count = 0
            total_duration = 0
            
            # Process streaming response
            for line in response.iter_lines():
                if line:
                    try:
                        chunk = json.loads(line)
                        
                        # Append response text
                        if 'response' in chunk:
                            report_text += chunk['response']
                            tokens_generated += 1
                        
                        # Get prompt eval count (only in first chunk)
                        if 'prompt_eval_count' in chunk and prompt_eval_count == 0:
                            prompt_eval_count = chunk.get('prompt_eval_count', 0)
                        
                        # CRITICAL: Check for cancellation every 10 tokens during streaming
                        if tokens_generated % 10 == 0 and report_obj and db_session:
                            try:
                                db_session.refresh(report_obj)
                                if report_obj.status == 'cancelled':
                                    logger.info(f"[AI] Report {report_obj.id} cancelled during streaming (at {tokens_generated} tokens)")
                                    response.close()  # Close the streaming connection
                                    return False, {'error': 'Report generation was cancelled by user'}
                            except Exception as e:
                                logger.warning(f"[AI] Failed to check cancellation status: {e}")
                        
                        # Update database every 50 tokens (real-time feedback)
                        current_time = time.time()
                        if report_obj and db_session and tokens_generated > 0:
                            if tokens_generated % 50 == 0 or (current_time - last_update_time) >= 5:
                                elapsed = current_time - start_time
                                if elapsed > 0:
                                    current_tps = tokens_generated / elapsed
                                    
                                    # Update report with real-time metrics AND content for live preview
                                    report_obj.total_tokens = tokens_generated
                                    report_obj.tokens_per_second = current_tps
                                    report_obj.progress_message = f'Generating report... {tokens_generated} tokens at {current_tps:.1f} tok/s'
                                    report_obj.raw_response = report_text  # ← ADD THIS: Update raw_response for live preview!
                                    
                                    try:
                                        db_session.commit()
                                        logger.info(f"[AI] Progress: {tokens_generated} tokens, {current_tps:.2f} tok/s")
                                    except Exception as e:
                                        logger.warning(f"[AI] Failed to update progress: {e}")
                                        db_session.rollback()
                                    
                                    last_update_time = current_time
                                    last_update_tokens = tokens_generated
                        
                        # Check if this is the final chunk
                        if chunk.get('done', False):
                            total_duration = chunk.get('total_duration', 0) / 1_000_000_000
                            eval_count = chunk.get('eval_count', tokens_generated)
                            break
                            
                    except json.JSONDecodeError as e:
                        logger.warning(f"[AI] Failed to parse chunk: {e}")
                        continue
            
            # Final calculations
            generation_time = time.time() - start_time
            
            if not report_text:
                return False, {'error': 'Empty response from model'}
            
            # Calculate final tokens/second
            if generation_time > 0 and tokens_generated > 0:
                final_tps = tokens_generated / generation_time
                logger.info(f"[AI] Report generated in {generation_time:.1f}s | {tokens_generated} tokens | {final_tps:.2f} tok/s")
            else:
                final_tps = 0
                logger.info(f"[AI] Report generated in {generation_time:.1f} seconds")
            
            return True, {
                'report': report_text,
                'duration_seconds': generation_time,
                'model': model,
                'eval_count': tokens_generated,
                'prompt_eval_count': prompt_eval_count
            }
        else:
            error_msg = f'Ollama API returned status {response.status_code}'
            logger.error(f"[AI] {error_msg}")
            return False, {'error': error_msg, 'response': response.text}
            
    except requests.exceptions.Timeout:
        error_msg = 'Request timed out after 20 minutes (may need GPU acceleration or host CPU optimization)'
        logger.error(f"[AI] {error_msg}")
        return False, {'error': error_msg}
    except Exception as e:
        error_msg = f'Error generating report: {str(e)}'
        logger.error(f"[AI] {error_msg}")
        return False, {'error': error_msg}


def format_report_title(case_name):
    """Generate a title for the AI report"""
    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
    return f"DFIR Investigation Report: {case_name} - {timestamp}"


def markdown_to_html(markdown_text, case_name, company_name=""):
    """
    Convert markdown report to professional HTML suitable for Microsoft Word
    
    Args:
        markdown_text: The markdown-formatted report
        case_name: Name of the case
        company_name: Company name (optional)
        
    Returns:
        str: HTML document with professional formatting
    """
    import re
    from datetime import datetime
    
    # Process line by line to preserve structure
    html = markdown_text
    
    # Headers (### to h3, ## to h2, # to h1) - do first before other conversions
    html = re.sub(r'^### (.*?)$', r'<h3>\1</h3>', html, flags=re.MULTILINE)
    html = re.sub(r'^## (.*?)$', r'<h2>\1</h2>', html, flags=re.MULTILINE)
    html = re.sub(r'^# (.*?)$', r'<h1>\1</h1>', html, flags=re.MULTILINE)
    
    # Bold and code formatting
    html = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', html)
    html = re.sub(r'`(.*?)`', r'<code>\1</code>', html)
    
    # Convert bullet lists - handle nested indentation
    # First convert double-indented bullets (sub-items with 2+ spaces)
    html = re.sub(r'^  - (.*?)$', r'<li class="indent2">\1</li>', html, flags=re.MULTILINE)
    # Then convert single-level bullets
    html = re.sub(r'^- (.*?)$', r'<li>\1</li>', html, flags=re.MULTILINE)
    
    # Wrap consecutive <li> items in <ul> - handle both regular and indented
    def wrap_list_items(match):
        content = match.group(0)
        # Check if this is an indented list
        if '<li class="indent2">' in content:
            return '<ul class="nested">\n' + content + '</ul>\n'
        return '<ul>\n' + content + '</ul>\n'
    
    # Wrap list items that are grouped together
    html = re.sub(r'(?:<li[^>]*>.*?</li>\n)+', wrap_list_items, html, flags=re.DOTALL)
    
    # Handle paragraphs - but don't wrap headers or lists
    lines = html.split('\n')
    processed_lines = []
    in_paragraph = False
    
    for line in lines:
        stripped = line.strip()
        # Skip empty lines, headers, and list items
        if not stripped or stripped.startswith('<h') or stripped.startswith('<ul') or stripped.startswith('</ul') or stripped.startswith('<li'):
            if in_paragraph:
                processed_lines.append('</p>')
                in_paragraph = False
            processed_lines.append(line)
        else:
            if not in_paragraph:
                processed_lines.append('<p>')
                in_paragraph = True
            processed_lines.append(line + '<br/>')
    
    if in_paragraph:
        processed_lines.append('</p>')
    
    html = '\n'.join(processed_lines)
    
    # Create full HTML document with professional styling
    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
    company_line = f"<p><strong>Company:</strong> {company_name}</p>" if company_name else ""
    
    full_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>DFIR Investigation Report - {case_name}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            max-width: 8.5in;
            margin: 0 auto;
            padding: 1in;
            color: #333;
            background: white;
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
            font-size: 28pt;
        }}
        h2 {{
            color: #2980b9;
            border-bottom: 2px solid #bdc3c7;
            padding-bottom: 8px;
            margin-top: 30px;
            font-size: 20pt;
        }}
        h3 {{
            color: #34495e;
            margin-top: 20px;
            font-size: 16pt;
        }}
        h4 {{
            color: #7f8c8d;
            margin-top: 15px;
            font-size: 14pt;
        }}
        p {{
            margin: 10px 0;
            text-align: justify;
        }}
        code {{
            background-color: #f4f4f4;
            border: 1px solid #ddd;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            font-size: 9pt;
        }}
        strong {{
            color: #c0392b;
            font-weight: bold;
        }}
        ul {{
            margin: 10px 0;
            padding-left: 30px;
            list-style-type: disc;
        }}
        ul.nested {{
            margin: 5px 0;
            padding-left: 40px;
            list-style-type: circle;
        }}
        li {{
            margin: 5px 0;
            line-height: 1.4;
        }}
        li.indent2 {{
            margin-left: 20px;
        }}
        .header {{
            background-color: #ecf0f1;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0;
            border: none;
        }}
        .metadata {{
            color: #7f8c8d;
            font-size: 10pt;
        }}
        @media print {{
            body {{
                margin: 0;
                padding: 0.5in;
            }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>DFIR Investigation Report</h1>
        <p class="metadata"><strong>Case:</strong> {case_name}</p>
        {company_line}
        <p class="metadata"><strong>Generated:</strong> {timestamp}</p>
    </div>
    
    {html}
    
    <hr style="margin-top: 40px; border: none; border-top: 2px solid #bdc3c7;">
    <p class="metadata" style="text-align: center; font-size: 9pt;">
        Report generated by CaseScope DFIR Platform
    </p>
</body>
</html>"""
    
    return full_html


def refine_report_with_chat(user_request, current_report, case, iocs, tagged_events, chat_history=None, model='llama3.1:8b-instruct-q4_K_M'):
    """
    Refine an existing report based on user's chat request
    
    Args:
        user_request (str): User's refinement request
        current_report (str): The current HTML report content
        case: Case object
        iocs: List of IOC objects
        tagged_events: List of tagged event dictionaries
        chat_history (list): Previous chat messages [{'role': 'user'|'assistant', 'message': '...'}]
        model (str): Ollama model to use
    
    Returns:
        Generator yielding chat response chunks
    """
    from bs4 import BeautifulSoup
    
    # Convert HTML report back to text for context
    soup = BeautifulSoup(current_report, 'html.parser')
    report_text = soup.get_text()
    
    # Build context-aware prompt
    prompt = f"""You are a DFIR report refinement assistant. A security analyst is reviewing a DFIR report and wants to make changes.

**YOUR TASK**: Respond to the analyst's request by providing ONLY the refined/new content they asked for.

**CRITICAL RULES**:
1. ⚠️ **USE ONLY DATA PROVIDED** - Do NOT invent, assume, or fabricate ANY details
2. ⚠️ **RESPOND DIRECTLY** - Provide the actual content they requested, not explanations about what you'll do
3. ⚠️ **MATCH EXISTING FORMAT** - Use the same HTML formatting style as the current report
4. ⚠️ **BE SPECIFIC** - Reference exact timestamps, IPs, hostnames, usernames from the events
5. ⚠️ **STAY FOCUSED** - Only address what they asked for, don't rewrite the entire report

**CURRENT REPORT EXCERPT** (first 2000 chars for context):
```
{report_text[:2000]}
```

**AVAILABLE CASE DATA**:
"""
    
    # Add event summary
    if tagged_events:
        prompt += f"\n**Tagged Events**: {len(tagged_events)} events available\n"
        prompt += "**Sample Event Data** (first 3 events):\n"
        for i, evt in enumerate(tagged_events[:3]):
            evt_data = evt.get('_source', {})
            timestamp = evt_data.get('@timestamp', evt_data.get('timestamp', 'N/A'))
            computer = evt_data.get('Computer', evt_data.get('computer', evt_data.get('host', {}).get('name', 'N/A')))
            prompt += f"\n{i+1}. Time: {timestamp}, System: {computer}\n"
            # Add key fields
            for key in ['Event_ID', 'event_id', 'Target_User_Name', 'target_user', 'Source_Network_Address', 'source_ip', 'CommandLine', 'command_line']:
                if key in evt_data and evt_data[key]:
                    prompt += f"   - {key}: {evt_data[key]}\n"
    
    # Add IOC summary
    if iocs:
        prompt += f"\n**IOCs**: {len(iocs)} indicators available\n"
        for ioc in iocs[:5]:
            prompt += f"- {ioc.ioc_value} ({ioc.ioc_type})\n"
    
    # Add chat history for context
    if chat_history:
        prompt += "\n**PREVIOUS CONVERSATION**:\n"
        for msg in chat_history[-5:]:  # Last 5 messages for context
            role_label = "Analyst" if msg['role'] == 'user' else "You"
            prompt += f"{role_label}: {msg['message']}\n"
    
    # Add current user request
    prompt += f"\n**ANALYST'S REQUEST**:\n{user_request}\n\n"
    
    prompt += """
**YOUR RESPONSE**:
Provide ONLY the refined content requested. Format it in HTML suitable for the report.
If they asked to:
- "Add more detail" → Provide the expanded section with the additional details
- "Rewrite for executives" → Provide the rewritten text in simpler language
- "Expand timeline" → Provide additional timeline entries in the same format
- "Add a section" → Provide the complete new section with proper HTML headers

DO NOT:
- Say "I'll do this" or "Here's how I'll change it"
- Provide explanations of what you're doing
- Repeat their request back to them
- Offer to do it - JUST DO IT and provide the content

BEGIN YOUR RESPONSE:
"""
    
    # Call Ollama with streaming
    ollama_url = "http://localhost:11434/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": True,
        "options": {
            "temperature": 0.3,  # Lower temperature for more focused refinements
            "num_ctx": 8192,  # Larger context for full report
            "num_thread": 16
        }
    }
    
    try:
        response = requests.post(ollama_url, json=payload, stream=True, timeout=300)
        response.raise_for_status()
        
        for line in response.iter_lines():
            if line:
                try:
                    chunk = json.loads(line.decode('utf-8'))
                    if 'response' in chunk:
                        yield chunk['response']
                    if chunk.get('done', False):
                        break
                except json.JSONDecodeError:
                    continue
                    
    except Exception as e:
        logger.error(f"[AI Chat] Error during refinement: {str(e)}")
        yield f"\n\n❌ Error: {str(e)}"


# Export functions
__all__ = [
    'check_ollama_status',
    'generate_case_report_prompt',
    'generate_report_with_ollama',
    'format_report_title',
    'markdown_to_html',
    'refine_report_with_chat'
]

